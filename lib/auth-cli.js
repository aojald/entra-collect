/**
 * Probe local Graph CLI / Azure CLI / Microsoft Graph PowerShell for a bearer token.
 * Fail-fast: hard timeouts + SIGKILL so --auth auto never stalls before browser.
 *
 * Order: az → Mg PowerShell → mgc
 */
const { spawn } = require("child_process");
const { decodeJwt, hasPolicyRead, scoreToken, scopeSet } = require("./tokens");
const { fetchJsonResilient } = require("./net");

const isWin = process.platform === "win32";

/** Default per-command budget (ms). Keep low so browser fallback is snappy. */
const DEFAULT_TIMEOUT_MS = 12000;

/**
 * Windows: `az` / `mgc` are `.cmd` shims, which `spawn` can only start through
 * cmd.exe. `shell:true` would make cmd.exe resolve the name against the current
 * directory first (an `az.cmd` dropped into an engagement folder would run as
 * the operator), so resolve the absolute path with `where` once and spawn that
 * without a shell.
 */
const resolvedBins = new Map();

async function resolveBin(bin) {
  if (!isWin) return bin;
  if (resolvedBins.has(bin)) return resolvedBins.get(bin);
  const r = await run("where.exe", [bin], { timeout: 4000, shell: false });
  const candidates = r.ok
    ? r.stdout.split(/\r?\n/).map((l) => l.trim()).filter(Boolean)
    : [];
  // Prefer an explicit .cmd/.exe over an extension-less shim.
  const pick =
    candidates.find((p) => /\.(cmd|bat|exe)$/i.test(p)) || candidates[0] || null;
  resolvedBins.set(bin, pick);
  return pick;
}

function run(cmd, args, opts = {}) {
  const timeout = opts.timeout != null ? opts.timeout : DEFAULT_TIMEOUT_MS;
  // `.cmd` / `.bat` shims need cmd.exe; anything else runs without a shell.
  const useShell =
    opts.shell != null ? opts.shell : isWin && /\.(cmd|bat)$/i.test(String(cmd));

  return new Promise((resolve) => {
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    let child;
    try {
      child = spawn(cmd, args, {
        shell: useShell,
        windowsHide: true,
        env: { ...process.env, ...(opts.env || {}) },
        // Own process group on Unix so we can kill az→python children
        detached: !isWin && !useShell,
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (e) {
      finish({
        ok: false,
        status: null,
        stdout: "",
        stderr: "",
        error: String(e.message || e),
        timedOut: false,
      });
      return;
    }

    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => {
      stdout += d.toString();
    });
    child.stderr.on("data", (d) => {
      stderr += d.toString();
    });

    const killTree = () => {
      try {
        if (!isWin && child.pid) {
          try {
            process.kill(-child.pid, "SIGKILL");
          } catch {
            child.kill("SIGKILL");
          }
        } else if (child.pid) {
          child.kill("SIGKILL");
        }
      } catch {
        /* ignore */
      }
    };

    const timer = setTimeout(() => {
      killTree();
      finish({
        ok: false,
        status: null,
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        error: `timed out after ${timeout}ms`,
        timedOut: true,
      });
    }, timeout);

    child.on("error", (e) => {
      finish({
        ok: false,
        status: null,
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        error: String(e.message || e),
        timedOut: false,
      });
    });

    child.on("close", (status) => {
      finish({
        ok: status === 0,
        status,
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        error: status === 0 ? null : stderr.trim().slice(0, 240) || `exit ${status}`,
        timedOut: false,
      });
    });
  });
}

async function which(bin) {
  if (isWin) return resolveBin(bin);
  const r = await run("which", [bin], { timeout: 4000, shell: false });
  if (!r.ok || !r.stdout) return null;
  return r.stdout.split(/\r?\n/).map((l) => l.trim()).filter(Boolean)[0] || null;
}

function looksLikeJwt(s) {
  return typeof s === "string" && s.split(".").length === 3 && s.length > 40;
}

function summarizeToken(token, source) {
  const payload = decodeJwt(token);
  if (!payload) return { ok: false, source, error: "invalid JWT" };
  return {
    ok: true,
    source,
    token,
    payload,
    score: scoreToken(payload),
    policyRead: hasPolicyRead(payload),
    upn:
      payload.upn ||
      payload.unique_name ||
      payload.preferred_username ||
      null,
    tid: payload.tid || null,
    scp: payload.scp || null,
    exp: payload.exp || null,
  };
}

async function tryAzureCli() {
  console.log("  · az: probing (max ~12s)…");
  const az = await which("az");
  if (!az) {
    return { ok: false, source: "az", error: "az not found on PATH" };
  }

  // Quick session check — fail fast if az is broken / locked
  const show = await run(az, ["account", "show", "-o", "none"], {
    timeout: 8000,
  });
  if (!show.ok) {
    return {
      ok: false,
      source: "az",
      error:
        show.timedOut
          ? "az account show timed out (session lock?) — use --auth browser or az login"
          : show.stderr.slice(0, 200) ||
            show.error ||
            "az not logged in (run: az login)",
    };
  }

  let r = await run(
    az,
    [
      "account",
      "get-access-token",
      "--resource-type",
      "ms-graph",
      "--query",
      "accessToken",
      "-o",
      "tsv",
    ],
    { timeout: 12000 }
  );
  if (!r.ok || !looksLikeJwt(r.stdout)) {
    r = await run(
      az,
      [
        "account",
        "get-access-token",
        "--resource",
        "https://graph.microsoft.com",
        "--query",
        "accessToken",
        "-o",
        "tsv",
      ],
      { timeout: 12000 }
    );
  }
  if (!r.ok || !looksLikeJwt(r.stdout)) {
    return {
      ok: false,
      source: "az",
      error:
        r.timedOut
          ? "az get-access-token timed out"
          : r.stderr.slice(0, 240) ||
            r.error ||
            "az returned no Graph access token (run: az login)",
    };
  }
  return summarizeToken(r.stdout, "az");
}

async function tryMgGraphPowerShell() {
  console.log("  · mg-powershell: probing (max ~10s)…");
  const shell =
    (await which("pwsh")) ||
    (await which("powershell")) ||
    (await which("powershell.exe"));
  if (!shell) {
    return {
      ok: false,
      source: "mg-powershell",
      error: "pwsh/powershell not found",
    };
  }

  // Microsoft.Graph.Authentication exposes no Get-MgAccessToken cmdlet, so the
  // token is read back off the Authorization header of a real request. That
  // works across module versions; the GraphSession fallback covers older ones.
  const ps = `
$ErrorActionPreference = 'Stop'
try { Import-Module Microsoft.Graph.Authentication -ErrorAction Stop } catch { exit 2 }
try {
  $ctx = Get-MgContext
  if (-not $ctx) { exit 3 }
} catch { exit 3 }

function Get-TokenFromRequest {
  try {
    $r = Invoke-MgGraphRequest -Method GET \`
      -Uri 'https://graph.microsoft.com/v1.0/$metadata#organization' \`
      -OutputType HttpResponseMessage -ErrorAction Stop
    $p = $r.RequestMessage.Headers.Authorization.Parameter
    if ($p -and $p.Length -gt 40) { return [string]$p }
  } catch {}
  return $null
}

function Get-TokenFromSession {
  try {
    $s = [Microsoft.Graph.PowerShell.Authentication.GraphSession]::Instance
    foreach ($prop in 'AuthContext','InMemoryTokenCache') {
      $v = $s.$prop
      if (-not $v) { continue }
      foreach ($name in 'AccessToken','Token') {
        $t = $v.$name
        if ($t -and ([string]$t).Length -gt 40) { return [string]$t }
      }
    }
  } catch {}
  return $null
}

$tok = Get-TokenFromRequest
if (-not $tok) { $tok = Get-TokenFromSession }
if ($tok) { Write-Output $tok; exit 0 }
exit 4
`.trim();

  const r = await run(shell, ["-NoProfile", "-NonInteractive", "-Command", ps], {
    timeout: 25000,
    shell: false,
  });
  const jwt = r.stdout.split(/\r?\n/).filter(looksLikeJwt).pop();
  if (!jwt) {
    return {
      ok: false,
      source: "mg-powershell",
      error: r.timedOut
        ? "PowerShell probe timed out"
        : r.status === 2
          ? "Microsoft.Graph.Authentication module not installed (Install-Module Microsoft.Graph.Authentication)"
          : r.status === 3
            ? "No Connect-MgGraph session (run Connect-MgGraph -Scopes … first)"
            : r.stderr.slice(0, 240) ||
              r.error ||
              "Could not extract Graph token from the Connect-MgGraph session",
    };
  }
  return summarizeToken(jwt, "mg-powershell");
}

/**
 * Microsoft Graph CLI (`mgc`) has no command that prints an access token, so it
 * can only be reported — never used as a token source. Detecting it is still
 * worth it: it tells the operator their session exists but is unusable here.
 */
async function tryMgc() {
  console.log("  · mgc: probing…");
  const mgc = await which("mgc");
  if (!mgc) {
    return { ok: false, source: "mgc", error: "mgc not found on PATH" };
  }
  const r = await run(mgc, ["login", "status"], { timeout: 8000 });
  const loggedIn = r.ok && !/not logged in|no.*session/i.test(r.stdout + r.stderr);
  return {
    ok: false,
    source: "mgc",
    error: loggedIn
      ? "mgc session found but the Graph CLI cannot export a bearer token — use Connect-MgGraph or az instead"
      : r.timedOut
        ? "mgc timed out"
        : r.stderr.slice(0, 200) || "mgc not logged in",
  };
}

/**
 * App-only token via client credentials.
 *
 * This is the deployment mode that makes the collector reproducible outside a
 * workstation: scopes are whatever the app registration was granted, so
 * ThreatHunting.Read.All and friends are actually available, unlike the fixed
 * scope set an `az` user token carries.
 */
async function appOnlyToken({ tenantId, clientId, clientSecret, certPath, certKeyPath }) {
  if (!tenantId || !clientId) {
    return { ok: false, source: "app", error: "tenant id and client id required" };
  }

  const body = new URLSearchParams({
    client_id: clientId,
    scope: "https://graph.microsoft.com/.default",
    grant_type: "client_credentials",
  });

  if (clientSecret) {
    body.set("client_secret", clientSecret);
  } else if (certPath && certKeyPath) {
    const assertion = buildClientAssertion({
      tenantId,
      clientId,
      certPath,
      certKeyPath,
    });
    body.set(
      "client_assertion_type",
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    );
    body.set("client_assertion", assertion);
  } else {
    return { ok: false, source: "app", error: "client secret or certificate required" };
  }

  const url = `https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/oauth2/v2.0/token`;
  let json;
  try {
    json = await fetchJsonResilient(url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
      timeoutMs: 30000,
    });
  } catch (e) {
    return {
      ok: false,
      source: "app",
      error: String(e.message || e).slice(0, 300),
    };
  }

  if (!json || !json.access_token) {
    return { ok: false, source: "app", error: "no access_token in response" };
  }
  return summarizeToken(json.access_token, "app");
}

/** RS256 JWT signed with the app's private key, per the AAD certificate flow. */
function buildClientAssertion({ tenantId, clientId, certPath, certKeyPath }) {
  const fs = require("fs");
  const crypto = require("crypto");

  const certPem = fs.readFileSync(certPath, "utf8");
  const keyPem = fs.readFileSync(certKeyPath, "utf8");
  const der = Buffer.from(
    certPem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""),
    "base64"
  );
  const thumbprint = crypto.createHash("sha1").update(der).digest("base64url");

  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT", x5t: thumbprint };
  const payload = {
    aud: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
    iss: clientId,
    sub: clientId,
    jti: crypto.randomUUID(),
    nbf: now - 60,
    exp: now + 600,
  };
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const signingInput = `${b64(header)}.${b64(payload)}`;
  const signature = crypto
    .createSign("RSA-SHA256")
    .update(signingInput)
    .sign(keyPem)
    .toString("base64url");
  return `${signingInput}.${signature}`;
}

async function probeCliGraphAuth() {
  const attempts = [];
  const providers = [tryAzureCli, tryMgGraphPowerShell, tryMgc];
  let best = null;

  for (const fn of providers) {
    let res;
    try {
      res = await fn();
    } catch (e) {
      res = {
        ok: false,
        source: fn.name || "cli",
        error: String(e.message || e),
      };
    }
    attempts.push({
      source: res.source,
      ok: !!res.ok,
      error: res.error || null,
      policyRead: res.policyRead || false,
      score: res.score || 0,
      upn: res.upn || null,
    });
    if (res.ok && (!best || res.score > best.score)) {
      best = res;
    }
    // Early exit on first strong Policy.Read token
    if (res.ok && res.policyRead) break;
  }

  return {
    ok: !!best,
    best,
    attempts,
    platform: process.platform,
  };
}

async function enrichPoolFromCli(pool) {
  console.log(
    "▶ Probing Graph CLI / Azure CLI / Mg PowerShell (fail-fast, then browser if needed)…"
  );
  const probe = await probeCliGraphAuth();
  for (const a of probe.attempts) {
    if (a.ok) {
      console.log(
        `  ✓ ${a.source}: token ok (score=${a.score} policyRead=${a.policyRead}` +
          (a.upn ? ` upn=${a.upn}` : "") +
          ")"
      );
    } else {
      const err = (a.error || "failed").replace(/\s+/g, " ").slice(0, 120);
      console.log(`  · ${a.source}: ${err}`);
    }
  }
  if (probe.best && probe.best.token) {
    pool.add(probe.best.token, { source: probe.best.source });
  } else {
    console.log("  → No CLI token — will use browser fallback.\n");
  }
  return probe;
}

/**
 * What each collection area needs, so operators learn about a missing scope in
 * seconds rather than after a two-hour run that quietly produced empty CSVs.
 */
const REQUIRED_SCOPES = [
  {
    area: "Conditional Access",
    any: ["Policy.Read.All", "Policy.ReadWrite.ConditionalAccess", "Policy.Read.ConditionalAccess"],
    impact: "CA export, coverage checks and most attack-path checks",
  },
  {
    area: "Directory / users / devices",
    any: ["Directory.Read.All", "Directory.ReadWrite.All"],
    impact: "users, guests, devices, named locations, role assignments",
  },
  {
    area: "Applications",
    any: ["Application.Read.All", "Directory.Read.All"],
    impact: "app permissions, secret expiry, path-to-GA",
  },
  {
    area: "Sign-in / audit logs",
    any: ["AuditLog.Read.All"],
    impact: "device-code and legacy sign-ins, SPN sign-ins, risky users",
  },
  {
    area: "MFA registration report",
    any: ["Reports.Read.All", "AuditLog.Read.All"],
    impact: "MFA gaps, passkeys, weak-MFA narratives",
  },
  {
    area: "Secure Score / security posture",
    any: ["SecurityEvents.Read.All", "SecurityEvents.ReadWrite.All"],
    impact: "Secure Score and high-value control checks",
  },
  {
    area: "Defender Advanced Hunting",
    any: ["ThreatHunting.Read.All"],
    impact: "RMM, Shadow AI, GenAI, file-share and patch-lag hunts",
    portalAlternative: true,
  },
  {
    area: "Defender vulnerability data",
    any: ["Vulnerability.Read.All", "ThreatHunting.Read.All"],
    impact: "TVM / CVE exposure tables",
    portalAlternative: true,
  },
  {
    area: "Intune configuration",
    any: ["DeviceManagementConfiguration.Read.All", "DeviceManagementManagedDevices.Read.All"],
    impact: "Windows Update rings, compliance policies",
  },
];

/**
 * Compare granted scopes against REQUIRED_SCOPES.
 *
 * @param {object|object[]} payloads one JWT payload, or all of them. A browser
 *   session yields several complementary tokens (Entra, Intune, Defender), and
 *   the Graph client will happily use whichever one covers a given call — so
 *   judging coverage on the single highest-scored token under-reports it.
 * @param {boolean} hasPortalSession true when a browser session can cover the
 *   hunting areas that Graph scopes alone would miss
 */
function evaluatePermissions(payloads, { hasPortalSession = false } = {}) {
  const list = Array.isArray(payloads) ? payloads : [payloads];
  const granted = new Set();
  for (const p of list) {
    for (const s of scopeSet(p || {})) granted.add(s);
  }
  const rows = REQUIRED_SCOPES.map((req) => {
    const matched = req.any.filter((s) => granted.has(s));
    const covered = matched.length > 0;
    const viaPortal = !covered && req.portalAlternative && hasPortalSession;
    return {
      area: req.area,
      status: covered ? "ok" : viaPortal ? "portal" : "missing",
      matched,
      needed: req.any,
      impact: req.impact,
    };
  });
  return {
    rows,
    missing: rows.filter((r) => r.status === "missing"),
    viaPortal: rows.filter((r) => r.status === "portal"),
    grantedCount: granted.size,
  };
}

function printPermissionMatrix(payloads, opts = {}) {
  const { rows, missing, viaPortal } = evaluatePermissions(payloads, opts);
  const count = Array.isArray(payloads) ? payloads.length : 1;
  const icon = { ok: "✓", portal: "◐", missing: "✗" };
  console.log(
    `\n▶ Permission coverage for this session (${count} token${count > 1 ? "s" : ""} in pool)\n`
  );
  for (const r of rows) {
    const detail =
      r.status === "ok"
        ? r.matched.join(", ")
        : r.status === "portal"
          ? "via browser portal session"
          : `needs one of: ${r.needed.join(" | ")}`;
    console.log(`  ${icon[r.status]} ${r.area.padEnd(32)} ${detail}`);
  }
  if (missing.length) {
    console.log(`\n  ${missing.length} area(s) will be missing from the report:`);
    for (const r of missing) console.log(`    · ${r.area} → ${r.impact}`);
  }
  if (viaPortal.length) {
    console.log(
      `\n  ${viaPortal.length} area(s) rely on the browser portal session staying open for the whole run.`
    );
  }
  console.log("");
  return { rows, missing, viaPortal };
}

/**
 * Interactive Azure CLI device-code login.
 * Open microsoft.com/devicelogin ON THE PHONE where the Authenticator passkey lives.
 */
async function azLoginDeviceCode(opts = {}) {
  const timeoutMs = opts.timeoutMs != null ? opts.timeoutMs : 15 * 60 * 1000;
  const az = await which("az");
  if (!az) {
    return { ok: false, error: "az not found on PATH — brew install azure-cli" };
  }
  if (opts.tenant && !/^[A-Za-z0-9.-]+$/.test(String(opts.tenant))) {
    return { ok: false, error: "--tenant must be a GUID or a domain name" };
  }

  console.log("\n╔══════════════════════════════════════════════════════════════╗");
  console.log("║  DEVICE CODE — complete login ON YOUR PHONE                  ║");
  console.log("║                                                              ║");
  console.log("║  1. az will show a code + https://microsoft.com/devicelogin  ║");
  console.log("║  2. Open that URL in Safari/Chrome ON THE PHONE              ║");
  console.log("║  3. Sign in with Authenticator passkey (native on phone)     ║");
  console.log("║  Do NOT use the Mac security-key dialog.                     ║");
  console.log("╚══════════════════════════════════════════════════════════════╝\n");

  const loginArgs = ["login", "--use-device-code"];
  if (opts.tenant) {
    loginArgs.push("--tenant", String(opts.tenant));
  }

  const login = await new Promise((resolve) => {
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    const child = spawn(az, loginArgs, {
      shell: isWin && /\.(cmd|bat)$/i.test(az),
      windowsHide: false,
      stdio: "inherit",
      env: process.env,
    });

    const timer = setTimeout(() => {
      try {
        child.kill("SIGTERM");
      } catch {
        /* ignore */
      }
      finish({ ok: false, error: `az login timed out after ${timeoutMs}ms` });
    }, timeoutMs);

    child.on("error", (e) => {
      finish({ ok: false, error: String(e.message || e) });
    });
    child.on("close", (status) => {
      finish(
        status === 0
          ? { ok: true }
          : { ok: false, error: `az login exited ${status}` }
      );
    });
  });

  if (!login.ok) return login;

  const token = await tryAzureCli();
  if (!token.ok) {
    return {
      ok: false,
      error:
        token.error ||
        "Logged in but could not get Graph token (az account get-access-token)",
    };
  }
  return { ok: true, token };
}

module.exports = {
  probeCliGraphAuth,
  enrichPoolFromCli,
  azLoginDeviceCode,
  appOnlyToken,
  tryAzureCli,
  tryMgGraphPowerShell,
  tryMgc,
  evaluatePermissions,
  printPermissionMatrix,
  REQUIRED_SCOPES,
  which,
  isWin,
};
