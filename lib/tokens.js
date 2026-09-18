/**
 * Shared Graph / portal token pool (JWT decode + scope scoring).
 */
function decodeJwt(token) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) return null;
  try {
    return JSON.parse(
      Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString()
    );
  } catch {
    return null;
  }
}

function scopeSet(payload) {
  const scp = String(payload.scp || "")
    .split(/\s+/)
    .filter(Boolean);
  const roles = Array.isArray(payload.roles) ? payload.roles : [];
  return new Set([...scp, ...roles]);
}

function hasPolicyRead(payload) {
  const s = scopeSet(payload);
  return (
    s.has("Policy.Read.All") ||
    s.has("Policy.ReadWrite.All") ||
    s.has("Policy.ReadWrite.ConditionalAccess") ||
    s.has("Policy.Read.ConditionalAccess")
  );
}

function scoreToken(payload) {
  let score = 0;
  const s = scopeSet(payload);
  const aud = String(payload.aud || "");
  if (hasPolicyRead(payload)) score += 100;
  if (s.has("Policy.Read.All")) score += 20;
  if (s.has("Directory.Read.All") || s.has("Directory.ReadWrite.All")) score += 30;
  if (s.has("SecurityEvents.Read.All") || s.has("SecurityEvents.ReadWrite.All"))
    score += 20;
  if (s.has("ThreatHunting.Read.All")) score += 25;
  if (s.has("Vulnerability.Read.All")) score += 25;
  if (s.has("Application.Read.All")) score += 10;
  if (s.has("User.Read.All") || s.has("User.ReadWrite.All")) score += 5;
  if (Array.isArray(payload.wids) && payload.wids.length) score += 15;
  if (s.has("User.Read") && s.size <= 6 && !hasPolicyRead(payload)) score -= 50;
  // Portal MTP tokens (security.microsoft.com hunting UI)
  if (
    /api\.security\.microsoft\.com|api\.securitycenter\.microsoft\.com|api-[a-z]{2}\.security\.microsoft\.com/i.test(
      aud
    )
  ) {
    score += 90;
  }
  return score;
}

/** Hostname of an audience claim; "" when it is an app id or malformed. */
function audHost(aud) {
  const a = String(aud || "").trim().toLowerCase();
  if (!a) return "";
  try {
    return new URL(/^https?:\/\//.test(a) ? a : `https://${a}`).hostname;
  } catch {
    return "";
  }
}

const GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000";
const GRAPH_HOSTS = new Set(["graph.microsoft.com"]);
const EXCHANGE_HOSTS = new Set(["outlook.office365.com", "outlook.office.com", "manage.office.com"]);

function isMtpAud(aud) {
  const h = audHost(aud);
  return (
    h === "api.security.microsoft.com" ||
    h === "api.securitycenter.microsoft.com" ||
    /^api-[a-z]{2}\.security\.microsoft\.com$/.test(h)
  );
}

function isGraphAud(aud) {
  return String(aud || "").trim().toLowerCase() === GRAPH_APP_ID || GRAPH_HOSTS.has(audHost(aud));
}

function describeToken(payload) {
  const scp = payload.scp || "(none)";
  const short = String(scp).length > 100 ? String(scp).slice(0, 100) + "…" : scp;
  const aud = String(payload.aud || "").slice(0, 40);
  const tid = payload.tid ? String(payload.tid).slice(0, 8) + "…" : "?";
  return `score=${scoreToken(payload)} tid=${tid} policyRead=${hasPolicyRead(payload)} aud=${aud} scp=${short}`;
}

function normalizeTid(tid) {
  if (tid == null || tid === "") return null;
  return String(tid).trim().toLowerCase();
}

/** Treat a token as dead slightly before `exp` so in-flight calls still land. */
const EXPIRY_SKEW_SEC = 120;

function tokenExpiresAt(payload) {
  const exp = Number(payload && payload.exp);
  return Number.isFinite(exp) ? exp : null;
}

function isTokenExpired(payload, skewSec = EXPIRY_SKEW_SEC) {
  const exp = tokenExpiresAt(payload);
  if (exp == null) return false;
  return exp - skewSec <= Math.floor(Date.now() / 1000);
}

function secondsUntilExpiry(payload) {
  const exp = tokenExpiresAt(payload);
  if (exp == null) return null;
  return exp - Math.floor(Date.now() / 1000);
}

class TokenPool {
  constructor() {
    this.byHash = new Map();
    /** Async callbacks that push fresh tokens into the pool when it runs dry. */
    this.refreshers = [];
    this.refreshing = null;
    this.lastRefreshAt = 0;
    /** Locked tenant GUID (lowercase). Set by --tenant or first accepted token. */
    this.expectedTid = null;
    this.expectedTidSource = null;
    /** Tokens rejected because tid ≠ expectedTid (diagnostic only). */
    this.rejectedMixed = [];
    this._mixedWarnAt = 0;
  }

  /**
   * Pin the pool to one tenant. Further tokens with a different `tid` are refused.
   * Calling again with the same tid is a no-op; a different tid throws.
   */
  lockTenant(tid, source = "lock") {
    const n = normalizeTid(tid);
    if (!n) {
      throw new Error("lockTenant: empty tenant id");
    }
    if (this.expectedTid && this.expectedTid !== n) {
      throw new Error(
        `Tenant lock conflict: pool is locked to ${this.expectedTid} (${this.expectedTidSource}), ` +
          `refusing to switch to ${n} (${source}). Start a fresh collect for the other tenant.`
      );
    }
    if (!this.expectedTid) {
      this.expectedTid = n;
      this.expectedTidSource = source;
      console.log(`  🔒 tenant locked: ${n} (via ${source})`);
    }
    return this.expectedTid;
  }

  tenantId() {
    return this.expectedTid;
  }

  /**
   * Register a source able to mint a new token mid-run (CLI re-probe, browser
   * re-capture). Called when every pooled token has expired or returned 401.
   */
  onRefresh(fn, label) {
    if (typeof fn === "function") this.refreshers.push({ fn, label: label || "refresh" });
  }

  /**
   * Ask every registered source for a fresh token. Concurrent callers share the
   * same in-flight attempt, and attempts are throttled so a burst of 401s does
   * not trigger a burst of CLI spawns.
   */
  async refresh({ minIntervalMs = 20000 } = {}) {
    if (!this.refreshers.length) return false;
    if (this.refreshing) return this.refreshing;
    if (Date.now() - this.lastRefreshAt < minIntervalMs) return false;

    this.refreshing = (async () => {
      this.lastRefreshAt = Date.now();
      let added = false;
      for (const { fn, label } of this.refreshers) {
        try {
          const token = await fn();
          if (token && this.add(token, { source: `${label}:refresh` })) {
            console.log(`  ↻ token renewed via ${label}`);
            added = true;
          }
        } catch (e) {
          console.warn(`  ⚠ token refresh (${label}): ${String(e.message || e).slice(0, 120)}`);
        }
      }
      return added;
    })();

    try {
      return await this.refreshing;
    } finally {
      this.refreshing = null;
    }
  }

  /** Drop entries past their `exp`; returns how many were evicted. */
  pruneExpired() {
    let n = 0;
    for (const [key, entry] of this.byHash) {
      if (isTokenExpired(entry.payload)) {
        this.byHash.delete(key);
        n++;
      }
    }
    return n;
  }

  _rejectMixed(payload, meta, tid) {
    const rec = {
      tid,
      expectedTid: this.expectedTid,
      aud: String(payload.aud || "").slice(0, 80),
      appid: payload.appid || payload.azp || null,
      upn: payload.upn || payload.unique_name || payload.preferred_username || null,
      source: meta.source || "unknown",
      at: new Date().toISOString(),
    };
    this.rejectedMixed.push(rec);
    // Rate-limit console noise (browser can spam many foreign-tenant tokens).
    if (Date.now() - this._mixedWarnAt > 5000) {
      this._mixedWarnAt = Date.now();
      console.warn(
        `  ⚠ rejected token from other tenant tid=${tid} (locked=${this.expectedTid})` +
          `${rec.upn ? ` upn=${rec.upn}` : ""} via ${rec.source} — keeping pool single-tenant`
      );
    }
    return null;
  }

  add(token, meta = {}) {
    const payload = decodeJwt(token);
    if (!payload) return null;
    const aud = String(payload.aud || "");
    const okAud = isGraphAud(aud) || EXCHANGE_HOSTS.has(audHost(aud)) || isMtpAud(aud);
    if (!okAud) return null;
    if (isTokenExpired(payload)) return null;

    const tid = normalizeTid(payload.tid);
    if (tid) {
      if (!this.expectedTid) {
        this.lockTenant(tid, meta.source || "first-token");
      } else if (tid !== this.expectedTid) {
        return this._rejectMixed(payload, meta, tid);
      }
    } else if (this.expectedTid) {
      // Rare: accept tokens without tid only if we already locked (can't verify).
      // Still log once in a while.
      if (Date.now() - this._mixedWarnAt > 15000) {
        this._mixedWarnAt = Date.now();
        console.warn(
          `  ⚠ token without tid claim accepted into locked pool (${this.expectedTid}) via ${meta.source || "unknown"}`
        );
      }
    }

    const key = `${payload.appid || payload.azp}|${aud}|${payload.scp}|${payload.exp}|${(payload.roles || []).join(",")}|${tid || ""}`;
    if (this.byHash.has(key)) return this.byHash.get(key);
    const entry = {
      token,
      payload,
      score: scoreToken(payload),
      aud,
      tid: tid || null,
      source: meta.source || "unknown",
      kind: isMtpAud(aud) ? "mtp" : "graph",
    };
    this.byHash.set(key, entry);
    const src = entry.source !== "unknown" ? ` via ${entry.source}` : "";
    console.log(
      `  · captured token aud=${aud.slice(0, 50)}${src} (${describeToken(payload)})`
    );
    return entry;
  }

  list() {
    return this.listAll().filter((e) => isGraphAud(e.aud));
  }

  listMtp() {
    return this.listAll().filter((e) => isMtpAud(e.aud));
  }

  /** Live tokens only — expired entries are evicted rather than re-served. */
  listAll() {
    this.pruneExpired();
    return [...this.byHash.values()].sort((a, b) => b.score - a.score);
  }

  /** Diagnostics: everything, including entries that have just expired. */
  listRaw() {
    return [...this.byHash.values()].sort((a, b) => b.score - a.score);
  }

  best() {
    return this.list()[0] || null;
  }

  bestPolicy() {
    return this.list().find((e) => hasPolicyRead(e.payload)) || null;
  }

  bestMtp() {
    return this.listMtp()[0] || null;
  }

  bestForAudience(substr) {
    return (
      this.listAll().find((e) =>
        String(e.aud || "").toLowerCase().includes(String(substr).toLowerCase())
      ) || null
    );
  }

  hasMtp() {
    return this.listMtp().length > 0;
  }

  /** Distinct tenant IDs currently in the pool (should be 0 or 1 after locking). */
  distinctTids() {
    const set = new Set();
    for (const e of this.listAll()) {
      const t = normalizeTid(e.payload && e.payload.tid);
      if (t) set.add(t);
    }
    return [...set];
  }

  /**
   * Hard check: pool must contain tokens for at most one tenant, matching lock.
   * @returns {{ ok: true, tid: string } | { ok: false, error: string, tids: string[] }}
   */
  assertSingleTenant() {
    const tids = this.distinctTids();
    if (tids.length > 1) {
      return {
        ok: false,
        tids,
        error:
          `Mixed-tenant token pool: found ${tids.length} tenant IDs (${tids.join(", ")}). ` +
          `Close other tenant tabs / use a dedicated browser profile, then re-run.`,
      };
    }
    if (this.expectedTid && tids.length === 1 && tids[0] !== this.expectedTid) {
      return {
        ok: false,
        tids,
        error:
          `Token tenant ${tids[0]} does not match locked tenant ${this.expectedTid} (${this.expectedTidSource}).`,
      };
    }
    if (!this.expectedTid && tids.length === 1) {
      this.lockTenant(tids[0], "assertSingleTenant");
    }
    if (!this.expectedTid && tids.length === 0) {
      return {
        ok: false,
        tids: [],
        error: "No tenant id (tid) found on any pooled token — cannot guarantee single-tenant collection.",
      };
    }
    return { ok: true, tid: this.expectedTid, rejectedMixed: this.rejectedMixed.length };
  }

  tenantReport() {
    return {
      lockedTid: this.expectedTid,
      lockedVia: this.expectedTidSource,
      pooledTids: this.distinctTids(),
      rejectedMixedCount: this.rejectedMixed.length,
      rejectedMixedSample: this.rejectedMixed.slice(-5),
    };
  }
}

module.exports = {
  TokenPool,
  decodeJwt,
  scopeSet,
  hasPolicyRead,
  scoreToken,
  describeToken,
  normalizeTid,
  isMtpAud,
  isGraphAud,
  audHost,
  isTokenExpired,
  secondsUntilExpiry,
  tokenExpiresAt,
  EXPIRY_SKEW_SEC,
};
