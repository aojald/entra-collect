#!/usr/bin/env node
/**
 * Entra Collect — read-only Entra ID / M365 attack-path assessment collector.
 *
 * Auth (--auth):
 *   auto    — probe Azure CLI / Mg PowerShell / mgc; if CA-capable token OK, skip browser
 *   cli     — CLI only
 *   browser — portal login via CDP or Playwright (captures Graph tokens from blades)
 *   device  — az login --use-device-code (often CA-blocked)
 *   app     — client credentials (CI / scheduled)
 *
 * Usage:
 *   node collect.js --help
 *   node collect.js --auth browser --cdp http://127.0.0.1:9222
 *   node collect.js --auth auto --inactive-days 90 --device-stale-months 3
 *   login-edge.cmd                 (Windows CDP)
 *   ./login-browser.sh             (macOS / Linux CDP)
 */

const { chromium } = require("playwright");
const fs = require("fs");
const path = require("path");
const os = require("os");
const readline = require("readline");
const { runCollection } = require("./lib/collection");
const {
  TokenPool,
  hasPolicyRead,
  describeToken,
  normalizeTid,
} = require("./lib/tokens");
const {
  enrichPoolFromCli,
  azLoginDeviceCode,
  appOnlyToken,
  tryAzureCli,
  tryMgGraphPowerShell,
  printPermissionMatrix,
} = require("./lib/auth-cli");
const { createGraph } = require("./lib/graph");

const args = process.argv.slice(2);
if (args.includes("--help") || args.includes("-h")) {
  console.log(`Entra Collect — identity & M365 attack-path assessment

Collect read-only artifacts from Entra / Defender / M365 via your portal or CLI session,
then build expert findings + HTML / Excel remediation workbook.

Usage:
  node collect.js [options]

Recommended (interactive portal + MFA / passkeys):
  macOS/Linux:  ./login-browser.sh
  Windows:      login-edge.cmd
  then:         node collect.js --auth browser --cdp http://127.0.0.1:9222

Auth:
  --auth auto|cli|browser|device|app
                        auto    = CLI Graph first, else browser (default)
                        cli     = Azure CLI / Graph PowerShell / mgc only
                        browser = Edge/Brave/Chrome portal session (CDP or Playwright)
                        device  = az device-code (often blocked by CA)
                        app     = client credentials (see below)

App-only (no interactive session — CI / scheduled):
  --client-id UUID --tenant TENANT_ID  + ENTRA_CLIENT_SECRET env or --client-secret-file FILE
  --client-id UUID --client-cert path.pem --client-cert-key key.pem --tenant TENANT_ID
                        implies --auth app
  --client-secret SECRET  deprecated (visible in ps / shell history) — prefer the env var or file

Common:
  --portal entra|azure
  --tenant TENANT_ID    pin collection to this tenant GUID (abort if tokens/org differ)
  --yes                 skip the interactive tenant confirmation when --tenant is not given
  --out DIR             output root (default: current directory)
  --no-cache            do not keep raw Graph responses in output_*/.cache (disables --resume)
  --resume DIR          retry failed steps in an existing output_* folder
  --intel-only          with --resume: re-run alerts/exposure/identity/GraphAPI hunts only
  --check-permissions   show scopes present vs required, then exit
  --inactive-days N     default 90
  --device-stale-months N  default 3
  --signin-days 30,90
  --no-capanalyzer-offline
                        skip CapAnalyzer What-If extras (principals / memberships / raw signIns)
  --capanalyzer-memberships N
                        optional cap on transitiveMemberOf users (default: no cap / all CA+priv users)
  --capanalyzer-signin-pages N
                        max Graph pages for raw signIns sample (default 3, ×200)
  --rmm-legit-threshold 0.7
  --timeout SEC         browser login timeout (default 900)
  --mfa-wait SEC        auto-continue after MFA without pressing Enter
  --no-wait-enter       do not wait for Enter after MFA
  --headless            Playwright headless (not for interactive MFA)
  --browser auto|brave|msedge|chrome|chromium
                        default auto (Edge preferred on Windows, Edge/Brave on macOS)
  --cdp http://127.0.0.1:9222
                        attach to browser started by login-browser.sh / login-edge.cmd
  --cdp-port N          debugging port when this tool launches the browser (default 9222)
  --keep-browser        leave the launched browser (and its debugging port) open at the end
  --no-passkeys         disable WebAuthn (password / push MFA only)

After collect (also runs automatically at the end of a successful collect):
  node report.js output_YYYY-MM-DD_HHMM     rebuild HTML + Excel
  node analyze.js output_YYYY-MM-DD_HHMM    expert narratives only

Docs: README.md · docs/WINDOWS.md · docs/GUIDE.md
`);
  process.exit(0);
}
const portal = argValue("--portal", "entra");
const timeoutSec = Number(argValue("--timeout", "900"));
const mfaWaitSec = Number(argValue("--mfa-wait", "0"));
const inactiveDays = Number(argValue("--inactive-days", "90"));
const deviceStaleMonths = Number(argValue("--device-stale-months", "3"));
const signInDaysRaw = argValue("--signin-days", "30,90");
const signInDays = signInDaysRaw
  .split(",")
  .map((x) => Number(x.trim()))
  .filter((n) => n > 0);
const capAnalyzerOffline = !args.includes("--no-capanalyzer-offline");
const capAnalyzerMembershipsRaw = argValue("--capanalyzer-memberships", "");
const capAnalyzerMaxMemberships =
  capAnalyzerMembershipsRaw === "" ||
  capAnalyzerMembershipsRaw.toLowerCase() === "all" ||
  capAnalyzerMembershipsRaw === "0"
    ? null
    : Number(capAnalyzerMembershipsRaw);
const capAnalyzerSignInPages = Number(argValue("--capanalyzer-signin-pages", "3"));
const rmmLegitThreshold = Number(argValue("--rmm-legit-threshold", "0.7"));
const waitEnter = !args.includes("--no-wait-enter") && mfaWaitSec <= 0;
const headed = !args.includes("--headless");
/** Brave/Edge show Authenticator phone QR; Playwright Chromium often only USB key */
const browserChannel = resolveBrowserChannel(
  String(argValue("--browser", "auto")).toLowerCase()
);
/** Passkeys on by default; --no-passkeys for password + push MFA only */
const allowPasskeys = !args.includes("--no-passkeys");
const tenantId = argValue("--tenant", "") || null;
const cdpEndpoint = argValue("--cdp", "") || null;
const cdpPort = Number(argValue("--cdp-port", "9222")) || 9222;
const keepBrowser = args.includes("--keep-browser");
const assumeYes = args.includes("--yes") || args.includes("-y");
const noCache = args.includes("--no-cache");
const clientId = argValue("--client-id", "") || null;
const clientSecret = resolveClientSecret();
const clientCert = argValue("--client-cert", "") || null;
const clientCertKey = argValue("--client-cert-key", "") || null;
const checkPermissionsOnly = args.includes("--check-permissions");
const intelOnly = args.includes("--intel-only");
const resumeDir = argValue("--resume", "") || null;
/**
 * Default to the caller's working directory, not the tool folder: an `npm -g`
 * install would otherwise write tenant data next to global node_modules.
 */
const outRoot = argValue("--out", "") || process.cwd();

/**
 * Secret precedence: --client-secret-file, ENTRA_CLIENT_SECRET, then the
 * deprecated --client-secret flag (visible in `ps` and shell history).
 */
function resolveClientSecret() {
  const file = argValue("--client-secret-file", "");
  if (file) {
    try {
      return fs.readFileSync(file, "utf8").trim() || null;
    } catch (e) {
      console.error(`--client-secret-file: ${e.message}`);
      process.exit(1);
    }
  }
  if (process.env.ENTRA_CLIENT_SECRET) return process.env.ENTRA_CLIENT_SECRET;
  const inline = argValue("--client-secret", "");
  if (inline) {
    console.warn(
      "⚠ --client-secret is deprecated: the value is visible in the process list and shell history. Use ENTRA_CLIENT_SECRET or --client-secret-file."
    );
    return inline;
  }
  return null;
}
/** auto = CLI first then browser if needed; cli = CLI only; browser = Playwright only; device = az device-code; app = client credentials */
const authMode = String(
  argValue("--auth", clientId ? "app" : "auto")
).toLowerCase();
if (!["auto", "cli", "browser", "device", "app"].includes(authMode)) {
  console.error(`Invalid --auth ${authMode} (use auto|cli|browser|device|app)`);
  process.exit(1);
}
if (authMode === "app" && (!clientId || !tenantId || !(clientSecret || clientCert))) {
  console.error(
    "--auth app requires --client-id, --tenant and one of --client-secret / --client-cert"
  );
  process.exit(1);
}

function argValue(flag, fallback) {
  const i = args.indexOf(flag);
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback;
}

/**
 * `auto` picks the first browser actually installed, preferring the ones that
 * render the Authenticator QR in-page. Defaulting to Brave was a macOS-centric
 * choice that fails on the Windows and Linux boxes where only Edge exists.
 */
function resolveBrowserChannel(requested) {
  if (requested !== "auto") {
    if (!["brave", "msedge", "chrome", "chromium"].includes(requested)) {
      console.error(
        `Invalid --browser ${requested} (use auto|brave|msedge|chrome|chromium)`
      );
      process.exit(1);
    }
    return requested;
  }
  const order =
    process.platform === "darwin"
      ? ["brave", "msedge", "chrome"]
      : ["msedge", "chrome", "brave"];
  for (const name of order) {
    if (resolveBrowserExecutable(name)) return name;
  }
  return "chromium";
}

const HOME_URL =
  portal === "azure" ? "https://portal.azure.com/" : "https://entra.microsoft.com/";

const CA_URLS =
  portal === "azure"
    ? [
        "https://portal.azure.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies",
        "https://portal.azure.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/NamedLocations",
        "https://portal.azure.com/#view/Microsoft_AAD_IAM/RolesManagementMenuBlade/~/AllRoles",
        "https://security.microsoft.com/securescore",
        "https://security.microsoft.com/hunting",
        "https://security.microsoft.com/tvm_software_inventory",
        "https://security.microsoft.com/machines",
        "https://security.microsoft.com/antispam",
        "https://security.microsoft.com/outboundspam",
        "https://admin.microsoft.com/Adminportal/Home#/Settings/Services/:/Settings/L1/ModernCommunicationPreferences",
        "https://admin.exchange.microsoft.com/#/homepage",
        "https://admin.exchange.microsoft.com/#/mailflowrules",
        "https://admin.exchange.microsoft.com/#/connecteddomains",
        "https://admin.microsoft.com/sharepoint",
      ]
    : [
        "https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies",
        "https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/NamedLocations",
        "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/RolesManagementMenuBlade/~/AllRoles",
        "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods",
        "https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/SignIns",
        "https://security.microsoft.com/securescore",
        "https://security.microsoft.com/hunting",
        "https://security.microsoft.com/tvm_software_inventory",
        "https://security.microsoft.com/machines",
        "https://security.microsoft.com/antispam",
        "https://security.microsoft.com/outboundspam",
        "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesWindowsMenu/~/windowsUpdate",
        "https://admin.exchange.microsoft.com/#/homepage",
        "https://admin.exchange.microsoft.com/#/mailflowrules",
        "https://admin.exchange.microsoft.com/#/connecteddomains",
        "https://admin.microsoft.com/sharepoint",
        "https://entra.microsoft.com/",
      ];

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/** Yes/no question on the terminal; anything but y/yes is "no". */
function confirm(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    rl.question(question, (answer) => {
      rl.close();
      resolve(/^y(es)?$/i.test(String(answer || "").trim()));
    });
  });
}

function isLoginHost(url) {
  try {
    const h = new URL(url).hostname.toLowerCase();
    return (
      h.includes("login.microsoftonline.com") ||
      h.includes("login.windows.net") ||
      h.includes("login.live.com") ||
      h.includes("device.login.microsoftonline.com")
    );
  } catch {
    return false;
  }
}

function isPortalHost(url) {
  try {
    const h = new URL(url).hostname.toLowerCase();
    return (
      h === "entra.microsoft.com" ||
      h === "portal.azure.com" ||
      h === "security.microsoft.com" ||
      h === "admin.microsoft.com" ||
      h === "admin.exchange.microsoft.com" ||
      h.endsWith(".portal.azure.com")
    );
  } catch {
    return false;
  }
}

async function waitForLoginComplete(page) {
  console.log("\n╔════════════════════════════════════════════════════════════╗");
  console.log("║  Sign in in the browser window (Edge / Brave / Chrome).    ║");
  console.log("║  MFA / passkey QR / Authenticator push — your usual flow.  ║");
  console.log("║  Collection waits until the portal is loaded.              ║");
  if (!allowPasskeys) {
    console.log("║  Passkeys off — use password / Authenticator push only.    ║");
  }
  console.log("╚════════════════════════════════════════════════════════════╝\n");

  const deadline = Date.now() + timeoutSec * 1000;
  while (Date.now() < deadline) {
    const url = page.url();
    if (isPortalHost(url) && !isLoginHost(url)) {
      console.log("  ✓ Portal loaded (login host left).");
      break;
    }
    await sleep(1000);
  }

  if (!isPortalHost(page.url()) || isLoginHost(page.url())) {
    throw new Error(`Login/MFA not finished in time.\nCurrent URL: ${page.url()}`);
  }

  while (isLoginHost(page.url()) && Date.now() < deadline) {
    console.log("  · MFA challenge still showing — waiting…");
    await sleep(1000);
  }

  if (waitEnter) {
    console.log("");
    console.log("  When QR / MFA is done and you see the Entra/Azure portal,");
    await new Promise((resolve) => {
      const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
      });
      rl.question("  → press Enter here to continue… ", () => {
        rl.close();
        resolve();
      });
    });
    console.log("  ✓ Continuing.\n");
  } else {
    console.log(`  ✓ Waiting extra ${mfaWaitSec}s for MFA (--mfa-wait)…`);
    const end = Date.now() + mfaWaitSec * 1000;
    while (Date.now() < end) {
      if (isLoginHost(page.url())) {
        while (isLoginHost(page.url()) && Date.now() < deadline) await sleep(1000);
      }
      await sleep(1000);
    }
    console.log("  ✓ MFA wait done.\n");
  }
}

const ts = new Date()
  .toISOString()
  .replace(/[:.]/g, "")
  .slice(0, 15)
  .replace("T", "_");
const outDir = resumeDir
  ? path.resolve(path.isAbsolute(resumeDir) ? resumeDir : path.join(outRoot, resumeDir))
  : path.join(path.resolve(outRoot), `output_${ts}`);

/**
 * Created only once a collection actually starts. Doing it at module load meant
 * importing this file — or aborting during login — left behind an empty
 * output_* folder, which then became the "latest run" that analyze.js and
 * report.js default to.
 */
function ensureOutDir() {
  if (resumeDir && !fs.existsSync(outDir)) {
    console.error(`--resume: ${outDir} does not exist`);
    process.exit(1);
  }
  fs.mkdirSync(outDir, { recursive: true });
}

/**
 * Only 401/403 is a real answer of "this token cannot read that".
 *
 * A 429 or a network hiccup means the call was authenticated and merely
 * throttled — treating it as a denial makes the collector wait forever for a
 * token it already holds.
 */
async function probeGraph(pool, url, label) {
  try {
    const g = createGraph(pool);
    await g.get(url);
    return true;
  } catch (e) {
    if (e.status === 401 || e.status === 403) return false;
    console.warn(
      `  · ${label} probe inconclusive (${e.status || "network"}) — token scopes look right, continuing`
    );
    return true;
  }
}

/** Memoised: the blade tour would otherwise re-probe on every URL and self-throttle. */
let caAccessConfirmed = false;
async function probeCaAccess(pool) {
  if (caAccessConfirmed) return true;
  const g = createGraph(pool);
  const ok = await probeGraph(
    pool,
    `${g.GRAPH}/identity/conditionalAccess/policies?$top=1`,
    "CA"
  );
  if (ok) caAccessConfirmed = true;
  return ok;
}

async function probeGraphOrg(pool) {
  const g = createGraph(pool);
  return probeGraph(pool, `${g.GRAPH}/organization?$select=id,displayName`, "Graph org");
}

async function captureTokens(page, pool, timeoutMs) {
  console.log("▶ Collecting Graph tokens (CA + Security portal)…\n");

  let settled = false;
  let resolveReady;
  let rejectReady;
  const ready = new Promise((resolve, reject) => {
    resolveReady = (v) => {
      if (settled) return;
      settled = true;
      resolve(v);
    };
    rejectReady = (e) => {
      if (settled) return;
      settled = true;
      reject(e);
    };
  });

  const timer = setTimeout(() => {
    rejectReady(
      new Error(
        "Timed out waiting for a Policy-capable Graph token.\n" +
          "Open Conditional Access manually if needed."
      )
    );
  }, timeoutMs);

  const onRequest = (req) => {
    try {
      if (isLoginHost(page.url())) return;
      const url = req.url();
      const auth = req.headers()["authorization"] || req.headers()["Authorization"];
      if (!auth || !auth.toLowerCase().startsWith("bearer ")) return;
      // Graph + Exchange + Microsoft Threat Protection (Advanced Hunting UI)
      if (
        url.includes("graph.microsoft.com") ||
        url.includes("outlook.office365.com") ||
        url.includes("outlook.office.com") ||
        /api([.-][a-z]{2})?\.security\.microsoft\.com/i.test(url) ||
        url.includes("api.securitycenter.microsoft.com")
      ) {
        pool.add(auth.slice(7).trim(), { source: "browser" });
      }
    } catch {
      /* ignore */
    }
  };

  page.on("request", onRequest);

  console.log("▶ Opening Conditional Access + Secure Score / Hunting blades…\n");
  let visitedHunting = false;
  for (const url of CA_URLS) {
    if (isLoginHost(page.url())) {
      console.warn("  ⚠ Login/MFA reappeared — pausing.");
      while (isLoginHost(page.url())) await sleep(1000);
    }
    try {
      console.log(`  → ${url.replace(/^https?:\/\//, "").slice(0, 90)}`);
      await page.goto(url, { waitUntil: "domcontentloaded", timeout: 120000 });
      // Hunting UI issues MTP tokens after scripts load — wait a bit longer
      const isHunt = /\/hunting|tvm_|\/machines/i.test(url);
      await sleep(isHunt ? 15000 : 8000);
      if (isHunt) visitedHunting = true;
      if (pool.hasMtp && pool.hasMtp()) {
        console.log("  ✓ MTP / Defender hunting token captured");
      }
      // Stop the login timeout as soon as CA + hunting are covered, but keep
      // touring: the remaining blades are what mint the Intune, Exchange and
      // SharePoint tokens that later collection steps depend on.
      // `visitedHunting` is tested first so the Graph probe does not run — and
      // self-throttle into a 429 — on every blade.
      if (
        !settled &&
        visitedHunting &&
        pool.bestPolicy() &&
        (await probeCaAccess(pool))
      ) {
        clearTimeout(timer);
        console.log("  ✓ Policy + hunting tokens captured — finishing the blade tour");
        resolveReady(pool.bestPolicy() || pool.best());
      }
    } catch (e) {
      console.warn(`  ⚠ navigation: ${e.message.split("\n")[0]}`);
    }
  }

  if (!settled) {
      if (pool.bestPolicy() && (await probeCaAccess(pool))) {
        clearTimeout(timer);
        if (!pool.hasMtp || !pool.hasMtp()) {
          console.log(
            "  · MTP Bearer not seen (normal) — hunting will use portal apiproxy when page stays open"
          );
        }
        console.log("  ✓ CA API probe succeeded");
        resolveReady(pool.bestPolicy() || pool.best());
      } else {
      console.log(
        "\n  Still waiting for Policy.Read token — stay on Conditional Access / Secure Score.\n"
      );
    }
  }

  try {
    return await ready;
  } finally {
    clearTimeout(timer);
    page.off("request", onRequest);
  }
}

async function writeTokenInfo(pool, authMeta) {
  const best = pool.bestPolicy() || pool.best();
  if (!best) return;
  const tenant = pool.tenantReport();
  fs.writeFileSync(
    path.join(outDir, "00_token_info.json"),
    JSON.stringify(
      {
        authMode,
        authMeta,
        aud: best.payload.aud,
        appid: best.payload.appid || best.payload.azp,
        upn:
          best.payload.upn ||
          best.payload.unique_name ||
          best.payload.preferred_username,
        tid: best.payload.tid,
        lockedTid: tenant.lockedTid,
        lockedVia: tenant.lockedVia,
        pooledTids: tenant.pooledTids,
        rejectedMixedCount: tenant.rejectedMixedCount,
        rejectedMixedSample: tenant.rejectedMixedSample,
        scp: best.payload.scp,
        roles: best.payload.roles,
        wids: best.payload.wids,
        score: best.score,
        policyRead: hasPolicyRead(best.payload),
        source: best.source || null,
        poolSize: pool.list().length,
        allTokens: pool.list().map((t) => ({
          score: t.score,
          tid: t.payload.tid || null,
          policyRead: hasPolicyRead(t.payload),
          scp: t.payload.scp,
          appid: t.payload.appid || t.payload.azp,
          source: t.source || null,
        })),
        note: "Raw tokens not saved. Mixed-tenant tokens are rejected at capture time.",
      },
      null,
      2
    ),
    "utf8"
  );
  console.log("  ✓ 00_token_info.json");
}

/**
 * Ensure every pooled token (and live /organization) belongs to one tenant.
 * Aborts the process on mismatch so tokens from different tenants never mix.
 */
async function assertTenantGuard(pool, { expectedTid = null } = {}) {
  if (expectedTid) {
    try {
      pool.lockTenant(expectedTid, "--tenant");
    } catch (e) {
      console.error(`\n❌ ${e.message}\n`);
      process.exit(1);
    }
  }

  const check = pool.assertSingleTenant();
  if (!check.ok) {
    console.error(`\n❌ Tenant guard: ${check.error}`);
    if (pool.rejectedMixed.length) {
      console.error(
        `   Also rejected ${pool.rejectedMixed.length} token(s) from other tenant(s) during capture.`
      );
    }
    console.error(
      "\n   Fix: use one browser profile / one az account for the target tenant," +
        " close other Entra tabs, pass --tenant <guid>, then re-run.\n"
    );
    process.exit(1);
  }

  // Live Graph check — org id must match JWT tid
  const g = createGraph(pool);
  let orgId = null;
  let orgName = null;
  try {
    const data = await g.get(
      `${g.GRAPH}/organization?$select=id,displayName`
    );
    const org = Array.isArray(data.value) ? data.value[0] : data;
    orgId = normalizeTid(org && org.id);
    orgName = (org && org.displayName) || null;
  } catch (e) {
    console.error(
      `\n❌ Tenant guard: could not read /organization to verify tenant (${String(e.message || e).slice(0, 160)}).\n`
    );
    process.exit(1);
  }

  if (!orgId) {
    console.error("\n❌ Tenant guard: /organization returned no id.\n");
    process.exit(1);
  }

  if (orgId !== check.tid) {
    console.error(
      `\n❌ Tenant guard: Graph organization id (${orgId}` +
        `${orgName ? ` — ${orgName}` : ""}) does not match token tid (${check.tid}).`
    );
    console.error(
      "   You are likely signed into a different tenant than the tokens suggest. Aborting.\n"
    );
    process.exit(1);
  }

  console.log(
    `  ✓ tenant guard OK — ${check.tid}` +
      `${orgName ? ` (${orgName})` : ""}` +
      `${pool.rejectedMixed.length ? ` · dropped ${pool.rejectedMixed.length} foreign-tenant token(s)` : ""}`
  );
  return { tid: check.tid, displayName: orgName };
}

/**
 * Resolve system browser binary (Brave/Edge/Chrome). Playwright has no channel:"brave".
 */
function resolveBrowserExecutable(name) {
  const candidates =
    process.platform === "darwin"
      ? {
          brave: [
            "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
          ],
          msedge: [
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
          ],
          chrome: [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
          ],
        }
      : process.platform === "win32"
        ? {
            brave: [
              `${process.env.LOCALAPPDATA}\\BraveSoftware\\Brave-Browser\\Application\\brave.exe`,
              `${process.env.PROGRAMFILES}\\BraveSoftware\\Brave-Browser\\Application\\brave.exe`,
              `${process.env["PROGRAMFILES(X86)"]}\\BraveSoftware\\Brave-Browser\\Application\\brave.exe`,
            ],
            msedge: [
              `${process.env.PROGRAMFILES}\\Microsoft\\Edge\\Application\\msedge.exe`,
              `${process.env["PROGRAMFILES(X86)"]}\\Microsoft\\Edge\\Application\\msedge.exe`,
            ],
            chrome: [
              `${process.env.PROGRAMFILES}\\Google\\Chrome\\Application\\chrome.exe`,
              `${process.env["PROGRAMFILES(X86)"]}\\Google\\Chrome\\Application\\chrome.exe`,
              `${process.env.LOCALAPPDATA}\\Google\\Chrome\\Application\\chrome.exe`,
            ],
          }
        : {
            brave: ["/usr/bin/brave-browser", "/usr/bin/brave"],
            msedge: ["/usr/bin/microsoft-edge", "/usr/bin/msedge"],
            chrome: ["/usr/bin/google-chrome", "/usr/bin/google-chrome-stable"],
          };

  const list = candidates[name] || [];
  for (const p of list) {
    if (p && fs.existsSync(p)) return p;
  }
  return null;
}

/** macOS .app name for `open -a` (required for Bluetooth / hybrid passkey QR). */
function resolveMacAppName(name) {
  return (
    {
      brave: "Brave Browser",
      msedge: "Microsoft Edge",
      chrome: "Google Chrome",
    }[name] || null
  );
}

/**
 * Where throw-away browser profiles live.
 *
 * Kept OUT of the tool directory on purpose: these profiles hold the customer's
 * portal session cookies, and a profile sitting next to the code ends up in
 * every zip, clone and backup of the engagement folder. Chrome/Edge 136+ also
 * ignore --remote-debugging-port on the *default* profile path, so this must
 * not be the user's normal profile either.
 */
function resolveProfileRoot() {
  if (process.env.ENTRA_COLLECT_PROFILE_DIR) {
    return process.env.ENTRA_COLLECT_PROFILE_DIR;
  }
  const base =
    process.platform === "win32"
      ? process.env.LOCALAPPDATA || os.tmpdir()
      : process.platform === "darwin"
        ? path.join(os.homedir(), "Library", "Application Support")
        : process.env.XDG_STATE_HOME || path.join(os.homedir(), ".local", "state");
  return path.join(base, "entra-collect", "profiles");
}

function resolveUserDataDir(name) {
  return path.join(resolveProfileRoot(), name);
}

/** Chromium flags so Brave/Edge keep in-browser hybrid QR (not macOS USB-only dialog). */
function passkeyLaunchArgs() {
  if (!allowPasskeys) {
    return [
      "--disable-features=WebAuthentication,WebAuthenticationConditionalUI,WebAuthenticationHybridTransports",
    ];
  }
  // Disable iCloud Keychain defaults (they surface macOS ASAuthorization USB/Touch ID UI).
  // Enable hybrid caBLE so the browser shows the QR you scan in Authenticator.
  // No --remote-allow-origins: Playwright's CDP client sends no Origin header,
  // and the flag would let any web page reach the debugging socket of the
  // admin session for the whole run.
  return [
    "--disable-blink-features=AutomationControlled",
    "--disable-features=WebAuthenticationICloudKeychainForGoogle,WebAuthenticationICloudKeychainForActiveWithDrive,WebAuthenticationICloudKeychainForActiveWithoutDrive,WebAuthenticationICloudKeychainForInactiveWithDrive,WebAuthenticationICloudKeychainForInactiveWithoutDrive",
    "--enable-features=WebAuthenticationHybridTransports,WebAuthnHybridLinking,WebAuthnSecurityKeyAndQrCodeUiRefresh",
  ];
}

async function waitForCdp(endpoint, timeoutMs = 90000) {
  const deadline = Date.now() + timeoutMs;
  let lastErr = null;
  let ticks = 0;
  while (Date.now() < deadline) {
    try {
      return await chromium.connectOverCDP(endpoint);
    } catch (e) {
      lastErr = e;
      ticks += 1;
      if (ticks === 1 || ticks % 10 === 0) {
        process.stdout.write(
          `  · waiting for CDP ${endpoint} (${Math.round((deadline - Date.now()) / 1000)}s left)…\n`
        );
      }
      await sleep(500);
    }
  }
  throw new Error(
    `CDP not ready at ${endpoint} (${lastErr?.message || "timeout"}).\n` +
      "  Edge 136+ ignores --remote-debugging-port on the DEFAULT profile.\n" +
      "  Fix: ./login-browser.sh or ./login-edge.sh / login-edge.cmd\n" +
      "       (dedicated entra-collect profile outside the repo), wait for « CDP OK », then retry --cdp.\n" +
      "  Or in your logged-in Edge: edge://inspect/#remote-debugging → enable Remote debugging."
  );
}

/**
 * macOS: launch browser via `open -a` so Info.plist Bluetooth works (hybrid QR).
 * Direct Playwright executablePath / binary launch → FIDO: Cannot use Bluetooth.
 * Must use NON-default user-data-dir or CDP port is silently ignored (Chrome/Edge 136+).
 */
async function launchMacAppViaOpenAndConnect(name, port = cdpPort) {
  const { spawn } = require("child_process");
  const appName = resolveMacAppName(name);
  const userDataDir = resolveUserDataDir(`${name}-cdp`);
  if (!appName || !userDataDir) {
    throw new Error(`No macOS app mapping for ${name}`);
  }
  fs.mkdirSync(userDataDir, { recursive: true });
  const endpoint = `http://127.0.0.1:${port}`;
  const args = [
    "-na",
    appName,
    "--args",
    `--remote-debugging-port=${port}`,
    `--user-data-dir=${userDataDir}`,
    "--no-first-run",
    "--no-default-browser-check",
    ...passkeyLaunchArgs(),
    HOME_URL,
  ];
  console.log(`▶ Opening ${appName} via macOS open -a (Bluetooth / QR + CDP)…`);
  console.log(`  CDP:     ${endpoint}`);
  console.log(`  profile: ${userDataDir}  (non-default — required for CDP on Edge 136+)`);
  console.log("  Sign in again in this window with Authenticator QR.\n");

  spawn("open", args, { detached: true, stdio: "ignore" }).unref();
  return waitForCdp(endpoint);
}

/**
 * Launch Playwright, login, capture portal Graph tokens into pool.
 * Returns { browser, page } so caller can keep enriching / close.
 */
async function acquireBrowserTokens(pool) {
  let browser;
  let context;
  let page;
  let ownsBrowser = true;
  let launchedViaOpen = false;

  if (cdpEndpoint) {
    console.log(`▶ Attaching to existing browser via CDP: ${cdpEndpoint}\n`);
    console.log(
      "  Use the same Brave/Edge window where the Authenticator QR appears.\n"
    );
    browser = await waitForCdp(cdpEndpoint, 15000);
    ownsBrowser = false;
    context =
      browser.contexts()[0] ||
      (await browser.newContext({
        viewport: { width: 1400, height: 900 },
        locale: "en-US",
      }));
    page = context.pages().find((p) => !p.url().startsWith("chrome")) || context.pages()[0];
    if (!page) page = await context.newPage();
  } else if (
    process.platform === "darwin" &&
    ["brave", "msedge", "chrome"].includes(browserChannel)
  ) {
    // Never launch Edge/Brave binary directly on macOS — breaks Bluetooth → no QR.
    browser = await launchMacAppViaOpenAndConnect(browserChannel, cdpPort);
    // We started it, so we close it at the end (the debugging port stays open
    // otherwise) unless the operator asked to keep the window.
    ownsBrowser = !keepBrowser;
    launchedViaOpen = true;
    context =
      browser.contexts()[0] ||
      (await browser.newContext({
        viewport: { width: 1400, height: 900 },
        locale: "en-US",
      }));
    page = context.pages().find((p) => !p.url().startsWith("chrome")) || context.pages()[0];
    if (!page) page = await context.newPage();
  } else {
    const profileDir = resolveUserDataDir(browserChannel);
    fs.mkdirSync(profileDir, { recursive: true });

    const launchArgs = passkeyLaunchArgs();
    const common = {
      headless: !headed,
      args: launchArgs,
      ignoreDefaultArgs: ["--enable-automation"],
      viewport: { width: 1400, height: 900 },
      locale: "en-US",
    };

    if (browserChannel === "chromium") {
      console.log("▶ Launching Playwright Chromium…\n");
      console.log(
        "  ⚠ On macOS prefer --browser msedge|brave (open -a + Bluetooth for QR).\n"
      );
      context = await chromium.launchPersistentContext(profileDir, common);
    } else {
      const exe = resolveBrowserExecutable(browserChannel);
      if (!exe && browserChannel !== "msedge" && browserChannel !== "chrome") {
        console.error(
          `\n❌ ${browserChannel} not found. Install it, or use --browser msedge|chrome.\n`
        );
        throw new Error(`${browserChannel} executable not found`);
      }
      console.log(
        `▶ Launching ${browserChannel}${exe ? ` (${exe})` : ""} for portal login…\n`
      );
      try {
        const opts = { ...common };
        if (exe) {
          opts.executablePath = exe;
        } else {
          opts.channel = browserChannel;
        }
        context = await chromium.launchPersistentContext(profileDir, opts);
      } catch (e) {
        console.error(`\n❌ Could not launch ${browserChannel}: ${e.message}`);
        throw e;
      }
    }
    browser = context.browser() || context;
    page = context.pages()[0] || (await context.newPage());
  }

  if (!page.url() || page.url() === "about:blank" || !isPortalHost(page.url())) {
    await page.goto(HOME_URL, { waitUntil: "domcontentloaded", timeout: 120000 });
  } else {
    console.log(`  Already on: ${page.url()}`);
  }

  try {
    await waitForLoginComplete(page);
    await captureTokens(page, pool, timeoutSec * 1000);
  } catch (e) {
    console.error(`\n❌ ${e.message}`);
    console.error("\nTips:");
    console.error("  • Finish MFA / passkey in the browser, then press Enter here");
    console.error(
      "  • macOS Bluetooth / hybrid QR? Use ./login-browser.sh (or login-edge.sh) + --cdp — not a raw browser binary"
    );
    console.error("  • Confirm Conditional Access + Secure Score blades open for this account");
    console.error("  • Help: node collect.js --help");
    if (pool.list().length) {
      console.error("\n  Tokens seen:");
      for (const t of pool.list()) console.error(`    - ${describeToken(t.payload)}`);
    }
    if (ownsBrowser) {
      try {
        await context.close();
      } catch {
        /* ignore */
      }
    }
    throw e;
  }

  // Keep enriching pool while collection runs
  page.on("request", (req) => {
    try {
      const url = req.url();
      const auth = req.headers()["authorization"] || req.headers()["Authorization"];
      if (!auth || !auth.toLowerCase().startsWith("bearer ")) return;
      if (
        url.includes("graph.microsoft.com") ||
        url.includes("outlook.office365.com") ||
        url.includes("outlook.office.com") ||
        /api([.-][a-z]{2})?\.security\.microsoft\.com/i.test(url) ||
        url.includes("api.securitycenter.microsoft.com")
      ) {
        pool.add(auth.slice(7).trim(), { source: "browser" });
      }
    } catch {
      /* ignore */
    }
  });

  // Prefer closing the context (persistent); browser may be null for persistent.
  return {
    browser: {
      close: async () => {
        if (!ownsBrowser) {
          try {
            // Disconnect CDP only — do not quit Edge/Brave (user may still need it)
            await browser.close();
          } catch {
            /* ignore */
          }
          if (cdpEndpoint || launchedViaOpen) {
            console.log(
              "  ⚠ The browser keeps its debugging port open — close that window when the engagement step is done."
            );
          }
          return;
        }
        if (launchedViaOpen) {
          // `open -a` launched a real app: closing the CDP connection does not
          // quit it, so ask the browser to shut down through CDP first.
          try {
            const ctx = browser.contexts()[0];
            const anyPage = ctx && ctx.pages()[0];
            if (anyPage) {
              const session = await ctx.newCDPSession(anyPage);
              await session.send("Browser.close").catch(() => {});
            }
          } catch {
            /* ignore */
          }
          try {
            await browser.close();
          } catch {
            /* ignore */
          }
          return;
        }
        try {
          await context.close();
        } catch {
          /* ignore */
        }
      },
    },
    page,
    context,
  };
}

/**
 * Let the pool re-mint a Graph token from the still-open portal tab.
 *
 * The portal silently renews its own tokens; reloading a blade makes it emit a
 * fresh Bearer that the existing request listener picks up. Without this, every
 * step past the first hour of a browser-mode run fails on an expired token.
 */
function registerBrowserRefresh(pool, page) {
  if (!page) return;
  pool.onRefresh(async () => {
    let captured = null;
    const onRequest = (req) => {
      try {
        const auth = req.headers()["authorization"] || "";
        if (!auth.toLowerCase().startsWith("bearer ")) return;
        if (!req.url().includes("graph.microsoft.com")) return;
        captured = auth.slice(7).trim();
      } catch {
        /* ignore */
      }
    };
    page.on("request", onRequest);
    try {
      await page.reload({ waitUntil: "domcontentloaded", timeout: 60000 });
      const deadline = Date.now() + 20000;
      while (!captured && Date.now() < deadline) await sleep(500);
    } finally {
      page.off("request", onRequest);
    }
    return captured;
  }, "portal");
}

async function main() {
  // Fail before authentication rather than after it.
  if (resumeDir && !fs.existsSync(outDir)) {
    console.error(`--resume: ${outDir} does not exist`);
    process.exit(1);
  }
  if (intelOnly && !resumeDir) {
    console.error("--intel-only requires --resume DIR (existing output folder)");
    process.exit(1);
  }
  console.log("Entra Collect — attack-path assessment");
  console.log(`Output: ${outDir}`);
  console.log(`Platform: ${process.platform} | auth: ${authMode}`);
  console.log(`Start URL (browser fallback): ${HOME_URL}`);
  console.log(
    `Flags: inactiveDays=${inactiveDays} deviceStaleMonths=${deviceStaleMonths} signInDays=${signInDays.join(",")} rmmLegitThreshold=${rmmLegitThreshold}${intelOnly ? " intelOnly=true" : ""}`
  );
  if (authMode !== "cli" && authMode !== "app") {
    console.log(
      waitEnter
        ? "Browser MFA: press Enter after MFA when the portal is visible (default)"
        : `Browser MFA: auto-continue after --mfa-wait ${mfaWaitSec}s`
    );
  }
  console.log("");

  const pool = new TokenPool();
  let browser = null;
  let portalPage = null;
  const authMeta = { cli: null, browserUsed: false, reason: null };

  // Pin early when --tenant is set so foreign browser/CLI tokens never enter the pool.
  if (tenantId) {
    try {
      pool.lockTenant(tenantId, "--tenant");
    } catch (e) {
      console.error(`\n❌ ${e.message}\n`);
      process.exit(1);
    }
  }

  // ── 0) App-only (client credentials) — no interactive session needed
  if (authMode === "app") {
    const res = await appOnlyToken({
      tenantId,
      clientId,
      clientSecret,
      certPath: clientCert,
      certKeyPath: clientCertKey,
    });
    if (!res.ok) {
      console.error(`\n❌ App-only login failed: ${res.error}\n`);
      process.exit(1);
    }
    pool.add(res.token, { source: "app" });
    // App tokens are short-lived and cheap to re-mint; no user interaction.
    pool.onRefresh(async () => {
      const again = await appOnlyToken({
        tenantId,
        clientId,
        clientSecret,
        certPath: clientCert,
        certKeyPath: clientCertKey,
      });
      return again.ok ? again.token : null;
    }, "app");
    authMeta.cli = {
      ok: true,
      attempts: [{ source: "app", ok: true }],
      source: "app",
      policyRead: res.policyRead,
      score: res.score,
    };
    authMeta.reason = "client-credentials";
    console.log(
      `  ✓ App-only Graph token (score=${res.score} policyRead=${res.policyRead} appid=${clientId})`
    );
  }

  // ── 1) Device-code login (passkey lives on phone → auth ON phone)
  if (authMode === "device") {
    const login = await azLoginDeviceCode({
      tenant: tenantId,
      timeoutMs: Math.max(timeoutSec, 900) * 1000,
    });
    if (!login.ok) {
      console.error(`\n❌ Device-code login failed: ${login.error}\n`);
      process.exit(1);
    }
    pool.add(login.token.token, { source: "az-device" });
    console.log(
      `  ✓ Device-code Graph token (score=${login.token.score} policyRead=${login.token.policyRead}` +
        (login.token.upn ? ` upn=${login.token.upn}` : "") +
        ")"
    );
    authMeta.cli = {
      ok: true,
      attempts: [{ source: "az-device", ok: true }],
      source: "az-device",
      policyRead: login.token.policyRead,
      score: login.token.score,
    };
    authMeta.reason = "device-code";
    if (!(await probeGraphOrg(pool))) {
      console.error("\n❌ Graph /organization failed with device-code token.\n");
      process.exit(1);
    }
    if (!(await probeCaAccess(pool))) {
      console.warn(
        "  ⚠ Token cannot read Conditional Access — CA sections may be empty."
      );
      console.warn(
        "     After login, ensure Azure CLI can get Graph with Policy.Read, or use portal browser if consented.\n"
      );
    }
  }

  // ── 2) CLI Graph (az / MgGraph / mgc)
  if (authMode === "auto" || authMode === "cli") {
    const probe = await enrichPoolFromCli(pool);
    authMeta.cli = {
      ok: probe.ok,
      attempts: probe.attempts,
      source: probe.best?.source || null,
      policyRead: probe.best?.policyRead || false,
      score: probe.best?.score || 0,
    };

    if (authMode === "cli") {
      if (!pool.best()) {
        console.error(
          "\n❌ --auth cli: no Graph token from Azure CLI / Mg PowerShell / mgc."
        );
        console.error("   Prefer:  ./login-browser.sh   (or login-edge.cmd on Windows)");
        console.error("            node collect.js --auth browser --cdp http://127.0.0.1:9222");
        console.error("   Or:      node collect.js --auth browser\n");
        process.exit(1);
      }
      const orgOk = await probeGraphOrg(pool);
      if (!orgOk) {
        console.error("\n❌ CLI token present but Graph /organization failed.");
        process.exit(1);
      }
      const caOk = await probeCaAccess(pool);
      if (!caOk) {
        console.warn(
          "  ⚠ CLI token cannot read Conditional Access — collection will soft-fail CA sections."
        );
        console.warn(
          "     Prefer Connect-MgGraph / az with Policy.Read.All, or --auth auto|browser.\n"
        );
      }
      authMeta.reason = "cli-only";
    }

    // CLI sources can mint a new token on demand — essential past the ~60 min
    // lifetime of the first one on a multi-hour collection.
    const cliSource = probe.best && probe.best.source;
    if (cliSource === "az") {
      pool.onRefresh(async () => {
        const t = await tryAzureCli();
        return t.ok ? t.token : null;
      }, "az");
    } else if (cliSource === "mg-powershell") {
      pool.onRefresh(async () => {
        const t = await tryMgGraphPowerShell();
        return t.ok ? t.token : null;
      }, "mg-powershell");
    }
  }

  // ── 3) Browser if needed
  const needBrowser =
    authMode === "browser" ||
    (authMode === "auto" &&
      (!pool.best() ||
        !pool.bestPolicy() ||
        !(await probeCaAccess(pool))));

  if (needBrowser) {
    if (authMode === "auto" && pool.list().length) {
      console.log(
        "\n  CLI token insufficient for CA (missing Policy.Read or probe failed)."
      );
      console.log("  Falling back to browser portal session (Edge/Brave/Chrome)…\n");
      authMeta.reason = "cli-weak-fallback-browser";
    } else if (authMode === "auto" && !pool.best()) {
      console.log("  Launching browser for portal login…\n");
      authMeta.reason = "cli-missing-fallback-browser";
    } else {
      authMeta.reason = "browser-forced";
    }
    authMeta.browserUsed = true;
    try {
      const session = await acquireBrowserTokens(pool);
      browser = session.browser;
      portalPage = session.page;
      registerBrowserRefresh(pool, portalPage);
    } catch {
      process.exit(1);
    }
  } else if (authMode === "auto" || authMode === "device") {
    console.log("\n  ✓ Using CLI Graph token (browser not required).\n");
    if (!authMeta.reason) authMeta.reason = "cli-sufficient";
  }

  if (!pool.best()) {
    console.error("\n❌ No Graph token available after auth.\n");
    process.exit(1);
  }

  const tenantGuard = await assertTenantGuard(pool, { expectedTid: tenantId });
  authMeta.tenantGuard = tenantGuard;

  // Without --tenant the lock came from whichever token arrived first. On a
  // partner / multi-tenant browser session that can be the home tenant rather
  // than the customer, so make the operator read the name before anything is
  // written.
  if (!tenantId && !checkPermissionsOnly) {
    const label = `${tenantGuard.displayName || "(no display name)"} — ${tenantGuard.tid}`;
    if (assumeYes) {
      console.log(`  · tenant confirmed by --yes: ${label}`);
    } else if (!process.stdin.isTTY) {
      console.error(
        `\n❌ Tenant not confirmed: ${label}\n   Non-interactive run — pass --tenant ${tenantGuard.tid} (or --yes) to proceed.\n`
      );
      if (browser) await browser.close();
      process.exit(1);
    } else {
      const ok = await confirm(
        `  → Collect from tenant "${label}"? [y/N] `
      );
      if (!ok) {
        console.error("\n  Aborted — re-run with --tenant <guid> for the tenant you meant.\n");
        if (browser) await browser.close();
        process.exit(1);
      }
    }
  }

  const coverage = printPermissionMatrix(
    pool.list().map((t) => t.payload),
    { hasPortalSession: !!portalPage }
  );
  authMeta.coverage = coverage.rows;

  if (checkPermissionsOnly) {
    if (browser) await browser.close();
    console.log("--check-permissions: nothing collected.\n");
    return;
  }

  ensureOutDir();
  await writeTokenInfo(pool, authMeta);

  await runCollection(pool, outDir, {
    inactiveDays,
    deviceStaleMonths,
    signInDays,
    rmmLegitThreshold,
    capAnalyzerOffline,
    capAnalyzerMaxMemberships,
    capAnalyzerSignInPages,
    portalPage,
    resume: !!resumeDir,
    intelOnly,
    cache: !noCache,
    expectedTenantId: tenantGuard.tid,
  });

  if (browser) await browser.close();
  console.log(`\n✅ Done. Artifacts in:\n   ${outDir}\n`);
  console.log("Open:");
  console.log("  · 00_REPORT.html           — dashboard + findings (PDF/Excel buttons inside)");
  console.log("  · 00_Remediation_Plan.xlsx — This Week / Remediation Plan steering workbook");
  console.log("  · 00_SUMMARY.md            — text overview");
  console.log("");
  console.log(`Rebuild later:  node report.js ${path.basename(outDir)}\n`);
}

// Only launch when executed directly (not when required accidentally)
if (require.main === module) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}

module.exports = { main, probeCaAccess, probeGraphOrg };
