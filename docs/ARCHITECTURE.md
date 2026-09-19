# Architecture

## High-level flow

```
--auth auto|cli|browser|device|app
        │
        ├─ CLI Graph (az → Mg PowerShell → mgc) ──┐
        ├─ az device-code (often CA-blocked)      ├─▶ TokenPool
        ├─ app client credentials                 │
        └─ browser / CDP attach + portal blade tour ┘
                    │
                    ▼
         lib/collection.js
                    │
         schema → Graph modules → attackpath → m365 → logs → endpoints → intel
                    │
         (browser) attachPortalHunt → Advanced Hunting via portal apiproxy
                    │
         analyze (NARR.*) → report.js → 00_REPORT.html + 00_Remediation_Plan.xlsx
```

## Entry points

| File | Role |
|---|---|
| `collect.js` | CLI / browser / CDP auth, TokenPool, calls `runCollection` |
| `login-browser.sh` | macOS/Linux CDP launcher (Edge/Brave/Chrome) |
| `login-edge.sh` / `login-edge.cmd` | Edge-only CDP profile + remote debugging |
| `collect.cmd` | Windows launcher (`--auth auto`) |
| `analyze.js` | Re-run expert narratives on an `output_*` folder |
| `report.js` | HTML + Excel report (re-runs analyze; PDF via in-page button) |
| `lib/collection.js` | Main collection pipeline + `00_SUMMARY.*` + auto-report |
| `lib/hunt.js` | Advanced Hunting: **portal apiproxy → Graph → legacy MTP** |
| `lib/analyze.js` | Static correlation → `NARR.*` + posture score |
| `lib/attackpath.js` | Consent / CA coverage / priv hygiene → `40_*` |
| `lib/tenantFacts.js` | Licences (`subscribedSkus`), Security Defaults, auth-method migration state → NotApplicable scoring |
| `lib/roles.js` | Directory roles by effective principal: schedule instances, group expansion, scope |
| `lib/apps.js` | App roles on Graph / EXO / SPO / AAD Graph, delegated AllPrincipals grants, SP credentials |
| `lib/caScope.js` | Effective scope of each CA policy + full / partial / none coverage verdicts |
| `lib/findings.js` | Output contract v2: Status / Confidence / LicenceRequired / Rationale |
| `lib/endpoints.js` | RMM / AI / patch / TVM / GenAI / file-share / Intune |
| `lib/intel.js` | Adaptive intel: alerts / Exposure Graph / IdentityLogon (MDE-optional) |
| `lib/xlsxReport.js` | Remediation workbook builder |

## Auth modes

| Mode | Behavior |
|---|---|
| `auto` (default) | CLI Graph first; if Policy.Read / CA probe OK → skip browser; else browser |
| `cli` | CLI only (`az` or `Connect-MgGraph`) |
| `browser` | Playwright portal (or `--cdp` attach) |
| `device` | `az login --use-device-code` (often blocked by CA) |
| `app` | Client credentials (secret or certificate) — no interactive session |

`lib/auth-cli.js` reads a Connect-MgGraph token off the Authorization header of a
real `Invoke-MgGraphRequest`, because `Microsoft.Graph.Authentication` exposes no
cmdlet that returns one. `mgc` is detected but unusable as a token source.

`--check-permissions` prints, per collection area, which granted scope satisfies
it and what will be missing — including the areas that only work while a browser
portal session stays open.

### Browser / CDP (macOS, Linux, Windows)

- macOS/Linux: `./login-browser.sh` then `node collect.js --auth browser --cdp http://127.0.0.1:9222`.
  On macOS it launches via `open -a` so Bluetooth hybrid QR works; on Linux it execs the binary directly.
  `login-edge.sh` is a thin wrapper kept for muscle memory.
- Windows: `login-edge.cmd` then the same `--cdp` flag.
- A **dedicated, non-default** profile is required so Edge/Chrome 136+ honor
  `--remote-debugging-port`. It lives outside the tool folder
  (`%LOCALAPPDATA%` / `~/Library/Application Support` / `$XDG_STATE_HOME`,
  overridable with `ENTRA_COLLECT_PROFILE_DIR`) because it stores live portal
  session cookies for the target tenant.
- `--browser auto` detects the first installed Chromium-family browser, preferring
  Brave on macOS and Edge elsewhere.

## Token capture (`TokenPool`)

1. Playwright intercepts bearer tokens from portal traffic (and storage where possible).
2. JWTs scored by scopes (`Policy.Read.All`, `Directory.Read.All`, …).
3. Graph client tries higher-scored tokens first; failover on 401/403.
4. Expired entries are evicted rather than re-served, and when the pool runs dry
   a registered refresher mints a new token — `az` re-probe, portal tab reload,
   or a fresh client-credentials call. Runs outlive the ~60-75 min token lifetime,
   so without this everything after the first hour fails.
5. Soft errors → `ERROR_*.json` (collection continues).

## Resilience (`lib/net.js`, `lib/io.js`, `lib/cache.js`)

| Concern | Where | Behaviour |
|---|---|---|
| Transient failures | `lib/net.js` | Hard timeout per request; retry with exponential backoff on network errors, 408, 429, 5xx. Deterministic 4xx fail immediately. |
| Step failures | `io.soft()` | One whole-step retry when the cause looks transient, then `ERROR_*.json` + a manifest entry. Single definition, shared by all modules. |
| Failure vs empty | `00_MANIFEST.json` | Every artifact records `ok` / `empty` / `failed` / `partial` / `skipped`, so an outage is never rendered as a clean zero. |
| False positives | `ctx.sources` in `attackpath.js` | Checks whose input was not collected become `NotEvaluated` + a `Coverage` finding, instead of `Fail`; checks the tenant cannot satisfy (licence / Security Defaults, `lib/tenantFacts.js`) become `NotApplicable`. |
| Resume | `lib/cache.js` | Responses are cached by URL/query. `--resume DIR` replays the pipeline while serving successful calls from `.cache/`, so only failed steps hit the network. Caching at the transport layer keeps every downstream side effect intact. |

## Hunting (`lib/hunt.js`)

Order for each KQL query:

1. **Portal apiproxy** on `security.microsoft.com` (`/apiproxy/hunting/huntingService/...`) with SPA cookies + XSRF — works with Security Reader UI session.
2. **Graph** `POST /v1.0/security/runHuntingQuery` — needs `ThreatHunting.Read.All`.
3. **Legacy MTP** Bearer (rare).

Portal KQL dialect tips: prefer `sort|take` over `top by`; keep `summarize … by` on **one line**; bound `make_set(col, N)`; avoid missing columns (`IsExploitAvailable`); avoid `coalesce` on optional CloudApp columns when possible.

**XSRF / mid-run session:** portal apiproxy tokens expire (~10–15m) while Edge can still look signed-in. `lib/hunt.js` now invalidates stale headers, refreshes proactively every ~4m, retries once after reload on 401/403/500, and surfaces portal errors (not only Graph 403) in `ERROR_hunt_*.json`.

Directory settings: use Graph `GET /v1.0/groupSettings` (not `/v1.0/settings`).

SPN credential use: `27_SPN_SignIns_*` from Graph service-principal sign-in events (Critical/High SPNs focused).

EXO tour: collector opens Exchange homepage + mail-flow rules + connected domains + Defender outbound spam (for AutoForwardingMode token capture).

## Collection artifact prefixes

See [OUTPUTS.md](OUTPUTS.md). Highlights: `00_` summary/report, `02_` CA, `03_` privileged, `07_` MFA, `19_` hunting schema, `30–35_` endpoints, `36–39_` adaptive intel, `40_` attack-path.

## With vs without MDE

`lib/schema.js` probes the hunting catalog (including Exposure Graph + IdentityInfo) and sets capability flags. Collectors branch on those flags rather than assuming Device* tables exist.

| Surface | Needs | Module |
|---|---|---|
| RMM / AI agents / patch lag / TVM CVEs | `DeviceInfo` / process / TVM tables | `endpoints.js` — skipped cleanly if missing |
| GenAI / file-share | `CloudAppEvents` **or** `DeviceNetworkEvents` | `endpoints.js` |
| Failed logons / admin tooling (partial) | `EntraIdSignInEvents` / `AADSignInEventsBeta` / `SigninLogs` / `IdentityLogonEvents` | `logs.js` + `schema.js` KQL dialects |
| Defender alerts, exposure-critical assets, privileged IdentityLogon activity | `AlertInfo`, `ExposureGraph*`, `IdentityLogonEvents` | `lib/intel.js` — **runs with or without MDE** |

On an MDE-light tenant (Identity + CloudApp + Alerts + Exposure Graph, no Device* tables), endpoint CSVs stay empty by design and adaptive intel (`36_`–`39_`) carries the hunting signal — including IdentityInfo/AccountInfo inventory and Exposure Graph paths when event tables are empty. Graph digests (`21_LegacyAuth_ByAccount`, `24_RiskDetections`, `27_SPN_SignIns_Digest`, `28_Privileged_SignIns`) fill the same gap from auditLogs. On a full MDE tenant both paths run.

## Analyzer + report

- `lib/analyze.js` emits expert narratives (`NARR.*`) into `00_Expert_Findings.*` and refreshes the Findings section of `00_SUMMARY.md`.
- Catalogue: [ANALYZER.md](ANALYZER.md). False positives: [FALSE_POSITIVES.md](FALSE_POSITIVES.md).
- `report.js` builds `00_REPORT.html` and `00_Remediation_Plan.xlsx` (PDF via the in-page Download PDF button). Endpoints tab includes TVM / KQL checklist.

## Graph client (`lib/graph.js`)

- v1.0 + beta, pagination, token pool failover.
- All I/O goes through `lib/net.js` (timeouts + retries); the client adds token
  rotation on 401/403 and a pool refresh when every token is stale.
- Read-through cache when resuming; write-through always, so any run can be resumed later.
- Hunting POSTs are routed through `lib/hunt.js`.
- Capped pagination marks the result `truncated`, which the manifest records as
  `partial` rather than a confident count.

## Report hardening (`report.js`)

- Tenant data is embedded as inert `<script type="application/json">`, not as
  executable JavaScript. The report stays a single shareable file without putting
  customer strings in script context.
- jsPDF is inlined from `node_modules` instead of a CDN, so export works on
  air-gapped and proxy-filtered networks; failures fall back to browser print
  with an explicit message.
- A failed `analyzeOutputDir` degrades the report instead of preventing it.
- The dashboard splits failed steps into permission-denied (401/403, needs a
  role) and possibly-transient (worth `--resume`), since only the latter can be
  fixed by re-running.

## Permission coverage

`--check-permissions` unions the scopes of **every Graph token in the pool**, not
just the highest-scored one. A browser session yields several complementary
tokens (Entra, Intune, Defender) and the Graph client uses whichever one covers
a given call, so judging coverage on a single token under-reports it.

## CSV

`lib/csv.js` is the single reader/writer for every CSV in the pipeline. The
parser is a character-level state machine over the whole document, not a
per-line split: quoted fields legitimately contain newlines and delimiters
(Secure Score ships multi-line HTML remediation), and splitting on `\n` first
shifts later columns onto the wrong header — corrupting data silently instead
of failing.

## Tests

`npm test` (node:test, no network) covers the retry classifier and backoff,
token expiry/renewal/throttling, manifest status semantics, the resume cache,
and CSV round-tripping of multi-line/quoted fields.

`npm run test:render -- <output_dir>` loads `00_REPORT.html` in a real browser
and asserts the dashboard built without JavaScript errors. The report is almost
entirely client-side, so a broken script yields a blank page that no
server-side test would catch.
