/**
 * Advanced Hunting runner:
 *  1) Portal apiproxy (security.microsoft.com) — Security Reader via Playwright page
 *  2) Graph ThreatHunting.Read.All
 *  3) Legacy MTP Bearer (api.security.microsoft.com) — rare on current portal
 */
const { scopeSet } = require("./tokens");
const { fetchResilient, sleep } = require("./net");

/** Hunting queries scan large tables; give them more room than plain Graph. */
const HUNT_TIMEOUT_MS = 180000;

const MTP_HUNT_PATHS = [
  "/api/advancedhunting/run",
  "/api/advancedqueries/run",
];

/** Proven UI executor path (returns Results for arbitrary KQL). */
const PORTAL_QUERY_PATH =
  "/apiproxy/hunting/huntingService/queryExecutor/disruptionSummaryQuery";
const PORTAL_SCHEMA_PATH = "/apiproxy/hunting/huntingService/schema";
const PORTAL_HUNTING_URL =
  "https://security.microsoft.com/v2/advanced-hunting";

const HEADER_KEYS = [
  "x-xsrf-token",
  "x-tid",
  "tenant-id",
  "x-clientpage",
  "x-clientpkgversion",
  "x-accepted-statuscode",
  "x-hunting-execution-context",
  "m-package",
  "m-name",
  "m-type",
  "m-componentname",
  "m-connection",
  "m-viewid",
];

/** Hostname of an audience claim (`https://host/`, `host`, or an app id). */
function audHost(aud) {
  const a = String(aud || "").trim().toLowerCase();
  if (!a) return "";
  try {
    return new URL(/^https?:\/\//.test(a) ? a : `https://${a}`).hostname;
  } catch {
    return "";
  }
}

/** Exact hosts a Defender token may be posted to — never a substring match. */
const MTP_HOSTS = new Set([
  "api.security.microsoft.com",
  "api.securitycenter.microsoft.com",
  "api-eu.security.microsoft.com",
  "api-uk.security.microsoft.com",
  "api-us.security.microsoft.com",
  "api-au.security.microsoft.com",
  "api-in.security.microsoft.com",
]);

function isMtpAudience(aud) {
  return MTP_HOSTS.has(audHost(aud));
}

/** Base URL for a Defender token; null when the audience is not an allowed host. */
function mtpBaseFromAud(aud) {
  const host = audHost(aud);
  return MTP_HOSTS.has(host) ? `https://${host}` : null;
}

function hasThreatHuntingScope(payload) {
  const s = scopeSet(payload || {});
  return s.has("ThreatHunting.Read.All");
}

function normalizeHuntResponse(data) {
  if (!data || typeof data !== "object") return { results: [], raw: data };
  const results =
    data.results ||
    data.Results ||
    data.Rows ||
    data.rows ||
    (Array.isArray(data.value) ? data.value : null) ||
    [];
  return {
    results: Array.isArray(results) ? results : [],
    schema: data.schema || data.Schema || null,
    stats: data.stats || data.Stats || data.EnhancedQueryStats || null,
    backend: data._backend || null,
    raw: data,
  };
}

async function fetchJson(token, url, body) {
  const res = await fetchResilient(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(body),
    timeoutMs: HUNT_TIMEOUT_MS,
    onRetry: (attempt, reason, waitMs) => {
      console.warn(
        `  ↻ hunt retry ${attempt} in ${Math.round(waitMs / 1000)}s (${String(reason).slice(0, 80)})`
      );
    },
  });
  const text = await res.text();
  try {
    return text ? JSON.parse(text) : null;
  } catch {
    return null;
  }
}

function pickSpaHeaders(h) {
  const out = {};
  for (const k of HEADER_KEYS) {
    if (h[k]) out[k] = h[k];
  }
  if (!out["x-accepted-statuscode"]) {
    out["x-accepted-statuscode"] = "OK|Aborted|Unauthorized|Forbidden";
  }
  if (!out["x-clientpage"]) out["x-clientpage"] = "/v2/advanced-hunting";
  out.accept = "application/json";
  out["content-type"] = "application/json";
  return out["x-xsrf-token"] && out["x-tid"] ? out : null;
}

/**
 * Playwright-backed portal hunting (cookie + XSRF via apiproxy).
 */
class PortalHuntSession {
  constructor() {
    this.page = null;
    this.headers = null;
    this.headersAt = 0;
    this._queue = Promise.resolve();
    this._listening = false;
    /** Tenant the Graph pool is locked to; portal headers for another tid are refused. */
    this.expectedTid = null;
    this.rejectedTids = new Set();
  }

  get ready() {
    return !!(this.page && this.headers && this.headers["x-xsrf-token"]);
  }

  lockTenant(tid) {
    const n = tid ? String(tid).trim().toLowerCase() : null;
    if (n && this.expectedTid !== n) {
      this.expectedTid = n;
      // Headers captured before the lock may belong to another tenant.
      if (this.headers && !this._tidMatches(this.headers)) {
        this.invalidateHeaders(`portal tenant ${this.headers["x-tid"]} ≠ locked ${n}`);
      }
    }
  }

  /**
   * The security portal can sit on a different tenant than the Graph tokens
   * (MSSP multi-tenant view, partner home tenant). Hunting there would mix two
   * tenants' data into one output folder.
   */
  _tidMatches(headers) {
    if (!this.expectedTid) return true;
    const tid = String((headers && (headers["x-tid"] || headers["tenant-id"])) || "")
      .trim()
      .toLowerCase();
    if (!tid) return true; // cannot verify — let the Graph guard decide
    if (tid === this.expectedTid) return true;
    if (!this.rejectedTids.has(tid)) {
      this.rejectedTids.add(tid);
      console.warn(
        `  ⚠ Portal hunting headers for tenant ${tid} ignored — pool is locked to ${this.expectedTid}. ` +
          "Switch the security.microsoft.com tab to the target tenant."
      );
    }
    return false;
  }

  /** Drop cached XSRF so ready=false until a fresh capture. */
  invalidateHeaders(reason) {
    if (reason) {
      console.warn(`  ⚠ Portal hunting headers invalidated: ${reason}`);
    }
    this.headers = null;
    this.headersAt = 0;
  }

  _onRequest(req) {
    try {
      const url = req.url();
      if (!/security\.microsoft\.com\/apiproxy\/hunting\//i.test(url)) return;
      const picked = pickSpaHeaders(req.headers());
      if (picked && this._tidMatches(picked)) {
        this.headers = picked;
        this.headersAt = Date.now();
      }
    } catch {
      /* ignore */
    }
  }

  async attach(page) {
    if (!page) return false;
    // Prefer an already-open Advanced Hunting tab in the same context
    let huntPage = page;
    try {
      const pages = page.context().pages();
      const found = pages.find(
        (p) =>
          /security\.microsoft\.com/i.test(p.url()) &&
          /hunting/i.test(p.url())
      );
      if (found) huntPage = found;
    } catch {
      /* ignore */
    }

    if (this.page && this.page !== huntPage && this._listening) {
      try {
        this.page.off("request", this._boundOnRequest);
      } catch {
        /* ignore */
      }
    }

    this.page = huntPage;
    this._boundOnRequest = this._onRequest.bind(this);
    this.page.on("request", this._boundOnRequest);
    this._listening = true;

    await this.ensureHuntingSurface();
    // Prefer capturing headers from live SPA traffic without an extra reload
    const deadline = Date.now() + 8000;
    while (Date.now() < deadline) {
      if (this.headers && this.headers["x-xsrf-token"]) break;
      await sleep(400);
    }
    if (!this.ready) await this.refreshHeaders({ force: true });
    return this.ready;
  }

  async ensureHuntingSurface() {
    if (!this.page) throw new Error("No portal page attached");
    const url = this.page.url() || "";
    if (/security\.microsoft\.com/i.test(url) && /hunting/i.test(url)) {
      return;
    }
    console.log("  · Opening Advanced Hunting portal for apiproxy session…");
    await this.page.goto(PORTAL_HUNTING_URL, {
      waitUntil: "domcontentloaded",
      timeout: 120000,
    });
    await sleep(10000);
  }

  async refreshHeaders({ force = false } = {}) {
    if (!this.page) return false;
    if (
      !force &&
      this.headers &&
      Date.now() - this.headersAt < 4 * 60 * 1000
    ) {
      return true;
    }

    // Critical: drop stale XSRF before reload. Otherwise the wait loop
    // returns immediately with an expired token while Edge still looks fine.
    if (force) {
      this.headers = null;
      this.headersAt = 0;
    }

    // Soft navigation / reload to generate SPA apiproxy traffic with XSRF
    const url = this.page.url() || "";
    try {
      if (/security\.microsoft\.com/i.test(url) && /hunting/i.test(url)) {
        await this.page.reload({
          waitUntil: "domcontentloaded",
          timeout: 90000,
        });
      } else {
        await this.page.goto(PORTAL_HUNTING_URL, {
          waitUntil: "domcontentloaded",
          timeout: 120000,
        });
      }
    } catch (e) {
      console.warn(
        `  ⚠ portal hunting reload: ${String(e.message || e).split("\n")[0]}`
      );
    }

    const deadline = Date.now() + 20000;
    while (Date.now() < deadline) {
      if (this.headers && this.headers["x-xsrf-token"]) return true;
      await sleep(500);
    }

    // Cookie / tid fallback if network capture missed
    try {
      const fallback = await this.page.evaluate(() => {
        const cookie = document.cookie || "";
        const xsrf =
          (cookie.match(/(?:^|; )XSRF-TOKEN=([^;]*)/) ||
            cookie.match(/(?:^|; )xsrf-token=([^;]*)/) ||
            [])[1] || null;
        const tid =
          (location.href.match(/[?&]tid=([0-9a-f-]{36})/i) || [])[1] || null;
        return {
          xsrf: xsrf ? decodeURIComponent(xsrf) : null,
          tid,
        };
      });
      if (fallback.xsrf && fallback.tid) {
        const picked = pickSpaHeaders({
          "x-xsrf-token": fallback.xsrf,
          "x-tid": fallback.tid,
          "tenant-id": fallback.tid,
          "x-clientpage": "/v2/advanced-hunting",
        });
        if (picked && this._tidMatches(picked)) {
          this.headers = picked;
          this.headersAt = Date.now();
          return true;
        }
        return false;
      }
    } catch {
      /* ignore */
    }
    return this.ready;
  }

  async _portalFetch(queryText) {
    return this.page.evaluate(
      async ({ path, headers, queryText: qt }) => {
        const res = await fetch(path, {
          method: "POST",
          credentials: "include",
          headers,
          body: JSON.stringify({ QueryText: qt }),
        });
        const text = await res.text();
        return { status: res.status, text };
      },
      {
        path: PORTAL_QUERY_PATH,
        headers: this.headers,
        queryText,
      }
    );
  }

  /**
   * Serialize portal queries (single page + hunting quota).
   */
  runQuery(query) {
    const job = this._queue.then(() => this._runQueryOnce(query));
    this._queue = job.catch(() => {});
    return job;
  }

  async _runQueryOnce(query) {
    const q = String(query || "").trim();
    if (!q) throw new Error("Empty hunting query");
    if (!this.page) throw new Error("Portal hunting page not attached");

    if (!this.ready) await this.refreshHeaders({ force: true });
    if (!this.ready) {
      const err = new Error(
        "Portal hunting session not ready (missing XSRF / hunting page)"
      );
      err.status = 401;
      throw err;
    }

    // Proactive refresh: XSRF often dies ~10–15m while Edge UI still looks signed-in
    if (Date.now() - this.headersAt > 4 * 60 * 1000) {
      await this.refreshHeaders({ force: true });
      if (!this.ready) {
        const err = new Error(
          "Portal hunting XSRF refresh failed (session stale)"
        );
        err.status = 401;
        throw err;
      }
    }

    let payload = await this._portalFetch(q);

    const authFail =
      payload.status === 401 ||
      payload.status === 403 ||
      payload.status === 500;
    if (authFail) {
      this.invalidateHeaders(`HTTP ${payload.status} on apiproxy`);
      await this.ensureHuntingSurface();
      await this.refreshHeaders({ force: true });
      if (!this.ready) {
        const err = new Error(
          `HTTP ${payload.status} portal:${PORTAL_QUERY_PATH} (XSRF refresh failed)\n${String(payload.text || "").slice(0, 300)}`
        );
        err.status = payload.status;
        throw err;
      }
      payload = await this._portalFetch(q);
      if (payload.status < 200 || payload.status >= 300) {
        this.invalidateHeaders(`retry still HTTP ${payload.status}`);
        const err = new Error(
          `HTTP ${payload.status} portal:${PORTAL_QUERY_PATH}\n${String(payload.text || "").slice(0, 400)}`
        );
        err.status = payload.status;
        throw err;
      }
    } else if (payload.status < 200 || payload.status >= 300) {
      const err = new Error(
        `HTTP ${payload.status} portal:${PORTAL_QUERY_PATH}\n${String(payload.text || "").slice(0, 400)}`
      );
      err.status = payload.status;
      throw err;
    }

    let json = null;
    try {
      json = payload.text ? JSON.parse(payload.text) : null;
    } catch {
      json = null;
    }
    const norm = normalizeHuntResponse(json);
    norm.backend = "portal:apiproxy/hunting";
    return norm;
  }

  async fetchSchemaTables() {
    if (!this.ready) await this.refreshHeaders({ force: true });
    if (!this.ready || !this.page) return null;
    const payload = await this.page.evaluate(
      async ({ path, headers }) => {
        const res = await fetch(path, {
          method: "GET",
          credentials: "include",
          headers,
        });
        const text = await res.text();
        return { status: res.status, text };
      },
      { path: PORTAL_SCHEMA_PATH, headers: this.headers }
    );
    if (payload.status !== 200) return null;
    try {
      const json = JSON.parse(payload.text);
      const tables = Array.isArray(json.Tables) ? json.Tables : [];
      const names = tables
        .map((t) => t.Name || t.name || t.TableName)
        .filter(Boolean)
        .map(String);
      return { names, raw: json };
    } catch {
      return null;
    }
  }
}

const portalSession = new PortalHuntSession();

async function attachPortalHunt(page, expectedTid = null) {
  if (expectedTid) portalSession.lockTenant(expectedTid);
  const ok = await portalSession.attach(page);
  if (ok) {
    console.log(
      "  ✓ Portal Advanced Hunting session ready (apiproxy + XSRF)"
    );
  } else {
    console.warn(
      "  ⚠ Portal hunting attach incomplete — will still try Graph/MTP tokens"
    );
  }
  return ok;
}

function portalHuntReady() {
  return portalSession.ready;
}

/**
 * Run a KQL hunting query.
 * @returns {Promise<{results: object[], backend: string, schema?: any}>}
 */
async function runHuntingQuery(pool, query, opts = {}) {
  const q = String(query || "").trim();
  if (!q) throw new Error("Empty hunting query");
  const timespan = opts.timespan || null;
  const errors = [];
  if (pool && pool.tenantId && pool.tenantId()) {
    portalSession.lockTenant(pool.tenantId());
  }

  async function tryPortal(label) {
    if (!(portalSession.page || portalSession.ready)) return null;
    try {
      if (!portalSession.ready) {
        await portalSession.refreshHeaders({ force: true });
      }
      if (!portalSession.ready) {
        errors.push(`portal:${label} not-ready (no XSRF)`);
        return null;
      }
      return await portalSession.runQuery(q);
    } catch (e) {
      const msg = String(e.message || e).split("\n")[0];
      errors.push(`portal:${label}:${e.status || "?"} ${msg}`);
      console.warn(`  ⚠ Hunting portal ${label} failed: ${msg}`);
      // Semantic KQL errors should not fall through to Graph
      if (e.status === 400) throw e;
      return null;
    }
  }

  // 1) Portal apiproxy (Security Reader UI session — preferred for browser collect)
  let portalHit = await tryPortal("attempt1");
  if (portalHit) return portalHit;

  // Stale XSRF / mid-run session death: force reload hunting + one more try
  if (portalSession.page) {
    portalSession.invalidateHeaders("retry before Graph fallback");
    try {
      await portalSession.ensureHuntingSurface();
      await portalSession.refreshHeaders({ force: true });
    } catch (e) {
      errors.push(
        `portal:refresh:${String(e.message || e).split("\n")[0]}`
      );
    }
    portalHit = await tryPortal("attempt2-after-xsrf-refresh");
    if (portalHit) return portalHit;
  }

  // 2) Microsoft Graph (needs ThreatHunting.Read.All on token)
  const graphTokens = (pool && pool.list && pool.list()) || [];
  const graphPrefer = [
    ...graphTokens.filter((e) => hasThreatHuntingScope(e.payload)),
    ...graphTokens,
  ];
  const seenG = new Set();
  for (const entry of graphPrefer) {
    if (seenG.has(entry.token)) continue;
    seenG.add(entry.token);
    try {
      const body = timespan ? { Query: q, Timespan: timespan } : { Query: q };
      const data = await fetchJson(
        entry.token,
        "https://graph.microsoft.com/v1.0/security/runHuntingQuery",
        body
      );
      const norm = normalizeHuntResponse(data);
      norm.backend = "graph";
      return norm;
    } catch (e) {
      errors.push(
        `graph:${e.status || "?"} ${String(e.message || e).split("\n")[0]}`
      );
      if (e.status && e.status !== 401 && e.status !== 403) throw e;
    }
  }

  // 3) Legacy MTP Bearer (rarely present on current portal)
  const mtpTokens =
    (pool && pool.listMtp && pool.listMtp()) ||
    ((pool && pool.listAll && pool.listAll()) || []).filter((e) =>
      isMtpAudience(e.aud)
    );
  for (const entry of mtpTokens) {
    const base = mtpBaseFromAud(entry.aud);
    if (!base) continue;
    for (const path of MTP_HUNT_PATHS) {
      try {
        const data = await fetchJson(entry.token, `${base}${path}`, {
          Query: q,
        });
        const norm = normalizeHuntResponse(data);
        norm.backend = `mtp:${base}${path}`;
        return norm;
      } catch (e) {
        errors.push(
          `mtp:${path}:${e.status || "?"} ${String(e.message || e).split("\n")[0]}`
        );
        if (
          e.status &&
          e.status !== 401 &&
          e.status !== 403 &&
          e.status !== 404
        ) {
          if (e.status !== 404) throw e;
        }
      }
    }
  }

  const portalErrs = errors.filter((e) => e.startsWith("portal:"));
  const otherErrs = errors.filter((e) => !e.startsWith("portal:"));
  const summaryBits = [
    ...portalErrs.slice(0, 3),
    ...otherErrs.slice(-2),
  ].filter(Boolean);

  const err = new Error(
    `Hunting failed (portal apiproxy + Graph + MTP). ` +
      `Portal=${portalSession.ready ? "ready" : "not-ready"}; ` +
      `Graph tokens=${seenG.size}; MTP tokens=${mtpTokens.length}. ` +
      `Attempts: ${summaryBits.join(" | ") || "no attempts"}`
  );
  err.status = 403;
  err.details = errors;
  throw err;
}

module.exports = {
  runHuntingQuery,
  normalizeHuntResponse,
  isMtpAudience,
  hasThreatHuntingScope,
  mtpBaseFromAud,
  attachPortalHunt,
  portalHuntReady,
  portalSession,
  PORTAL_QUERY_PATH,
  PORTAL_SCHEMA_PATH,
};
