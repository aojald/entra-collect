# Usage guide

## Install

```bash
cd entra-collect
npm install

# Only needed for --browser chromium; skip it if you use Edge/Brave/Chrome or --cdp
npm run setup:browser
```

`npm install` no longer downloads Chromium automatically — that failed behind
corporate proxies and is useless in `--cdp` and `--auth cli|app` modes.

## Collect

```bash
node collect.js [options]
# or
npm run collect
npm run collect:azure   # --portal azure
```

### CLI flags

| Flag | Default | Meaning |
|---|---|---|
| `--portal entra\|azure` | `entra` | Home portal + blade tour |
| `--out DIR` | current directory | Where `output_*` directories are created |
| `--no-cache` | off | Do not keep raw Graph responses in `output_*/.cache` (disables `--resume` for that run) |
| `--yes` | off | Skip the interactive tenant confirmation when `--tenant` is not given (scripted runs) |
| `--resume DIR` | off | Re-run into an existing output dir, retrying only failed steps |
| `--intel-only` | off | With `--resume`: skip Graph inventory, re-run adaptive intel hunts (alerts / exposure / IdentityInfo / GraphAPI writes) |
| `--check-permissions` | off | Print the scope-coverage matrix and exit without collecting |
| `--tenant TENANT_ID` | — | Tenant id. Required for `--auth app`; otherwise the resolved organisation must be confirmed interactively (or `--yes`). Tokens, portal hunting headers and `--resume` folders from another tenant are refused |
| `--inactive-days N` | `90` | Enabled accounts with no sign-in since N days |
| `--device-stale-months N` | `3` | Joined/hybrid devices not seen since N months |
| `--signin-days A,B,…` | `30,90` | Device-code (and related) sign-in windows |
| `--rmm-legit-threshold F` | `0.7` | RMM on ≥ F of Windows devices → assumed corporate |
| `--timeout SEC` | `900` | Max wait for login to reach a portal host |
| `--mfa-wait SEC` | `0` | Auto-continue after N seconds (0 = press Enter) |
| `--no-wait-enter` | off | Do not wait for Enter (pair with `--mfa-wait`) |
| `--headless` | off | Headless Chromium (login usually needs headed) |
| `--browser auto\|brave\|msedge\|chrome\|chromium` | `auto` | Platform preference order (Brave→Edge→Chrome on macOS; Edge first on Windows) |
| `--cdp URL` | off | Attach to a browser started via `./login-browser.sh` / `login-edge.cmd` |
| `--cdp-port N` | `9222` | Debugging port when the tool launches the browser itself |
| `--keep-browser` | off | Leave a browser the tool launched (and its debugging port) open at the end |
| `--no-passkeys` | off | Disable WebAuthn (password / Authenticator push only) |
| `--auth auto\|cli\|browser\|device\|app` | `auto` | See below |
| `--client-id` / `--client-secret-file` / `--client-cert` / `--client-cert-key` | — | App-only credentials (implies `--auth app`). Secret via `ENTRA_CLIENT_SECRET` or `--client-secret-file FILE`; `--client-secret VALUE` is deprecated (visible in `ps` / shell history) |

### Auth modes

- **`auto`** — probe local CLI for a Graph token; if Policy.Read / CA probe OK, skip browser; else spawn a browser.
- **`cli`** — CLI only (fail if no token). Use after `az login` or `Connect-MgGraph -Scopes …`.
- **`browser`** — portal session via Playwright **or** `--cdp` attach to `login-browser.sh` / `login-edge.cmd`.
- **`device`** — `az login --use-device-code`, for passkeys that live on a phone (often CA-blocked).
- **`app`** — client credentials. No interactive session, so this is the mode for Linux, CI and scheduled runs.

#### What each mode can actually collect

Run `node collect.js --check-permissions` to see the real coverage for *your*
session. In general:

| Source | Graph scopes you get | Consequence |
|---|---|---|
| Browser portal | Portal first-party scopes + apiproxy hunting | Widest coverage; Advanced Hunting works without `ThreatHunting.Read.All` |
| `Connect-MgGraph -Scopes …` | Exactly what you requested and consented | Good, but you must ask for `ThreatHunting.Read.All` to get endpoint hunts |
| `az login` | Azure CLI's fixed first-party scope set | **No `ThreatHunting.Read.All`** — RMM / Shadow AI / GenAI / TVM hunts are unavailable |
| App registration (`--auth app`) | Whatever the app was granted | Fully reproducible; grant the scopes listed by `--check-permissions` |

`mgc` (Microsoft Graph CLI) is detected but cannot be used: it has no command
that exports a bearer token. Use `Connect-MgGraph` or `az` instead.

#### App-only example

```bash
node collect.js --auth app \
  --tenant 00000000-0000-0000-0000-000000000000 \
  --client-id 11111111-1111-1111-1111-111111111111
# secret read from ENTRA_CLIENT_SECRET (or --client-secret-file ./secret.txt)

# or with a certificate
node collect.js --auth app --tenant … --client-id … \
  --client-cert ./app.pem --client-cert-key ./app.key
```

The secret can also come from the `ENTRA_CLIENT_SECRET` environment variable so
it never appears in shell history or process listings.

Windows native notes: [WINDOWS.md](WINDOWS.md).

```bash
node collect.js \
  --inactive-days 90 \
  --device-stale-months 3 \
  --signin-days 30,90 \
  --rmm-legit-threshold 0.7
```

### Login flow

1. Chromium opens Entra (or Azure) portal login.
2. Complete MFA (number matching). The script **does not** navigate away while you are on `login.microsoftonline.com`.
3. When you see the portal UI, focus the terminal and press **Enter**.
4. The tool tours CA / Secure Score / Hunting / Intune / EXO / SharePoint blades to mint useful tokens, then runs Graph collection.

Tokens are kept **in memory** for the run only (not written to disk as raw JWTs by default; `00_token_info.json` may hold metadata).

---

## Recommended Entra roles

| Role | Unlocks |
|---|---|
| Global Reader | Most Entra / CA / users / apps / roles |
| Security Reader | Secure Score, many security APIs, alerts |
| Reports Reader | MFA registration report (often overlapping) |
| Intune Reader (or Endpoint roles) | Update rings / device configs |
| Exchange Viewer / Recipient roles | Auto-forward mode via EXO admin session |
| Threat Hunting / appropriate Defender role | `runHuntingQuery` (ThreatHunting.Read.All on token) |

Without hunting rights, identity still works via **Graph sign-in logs**; RMM/AI/patch hunts are skipped cleanly (see `19_Hunting_Schema.json`).

---

## Report

Generated automatically at the end of a successful collection (HTML + Excel). Rebuild anytime with:

```bash
node report.js                     # latest output_* (runs analyze + HTML + Excel)
node report.js output_YYYY-MM-DD_HHMM
node analyze.js                    # expert narratives only → 00_Expert_Findings.*
```

| Artifact | Purpose |
|---|---|
| `00_REPORT.html` | Interactive dashboard + findings |
| `00_Remediation_Plan.xlsx` | Steering workbook (This Week / Remediation Plan / Owner · Status · Due) |

Open `00_REPORT.html` in a browser:

- **Dashboard** — expert posture score, top correlated findings, coverage  
- **Expert findings** — Critical/High/Medium narratives with evidence + remediation  
- **Inventory findings** — raw collector rows (includes Info / skips)  
- **Attack path / CA / Identity / Privileged / Apps / Schema** — detail views  
- **Export Excel** / **Download PDF** — remediation workbook and executive brief

---

## CAPAnalyzer

Upload `02_ca_policies_capanalyzer.json` into CAPAnalyzer. Graph IDs stay in standard fields; human names live under `_resolved` / `resolutions` (ignored by CAPAnalyzer’s normalizer).

By default the collector also writes an **offline What-If pack**:

| File | Purpose |
|---|---|
| `02_directory_principals_capanalyzer.json` | Users/groups/apps/roles **referenced by Conditional Access** (plus resolver cache) — not the full tenant directory |
| `02_user_memberships_capanalyzer.json` | `transitiveMemberOf` for **all** CA-referenced + privileged users (optional cap via `--capanalyzer-memberships N`). Role IDs are stored as **role template** IDs for CapAnalyzer What-If. |
| `20_signIns_raw_capanalyzer.json` | Raw Graph signIns sample (≤ ~600 interactive events) for Sign-in Replay |

Skip with `--no-capanalyzer-offline`. Bound membership count with `--capanalyzer-memberships N` (default: no cap). Bound raw sign-in pages with `--capanalyzer-signin-pages N` (default: 3).

> Upload the CapAnalyzer JSON files together in CAPAnalyzer (policies + principals + memberships; optional raw signIns) for offline What-If.

---

## Troubleshooting

| Symptom | Likely cause | What to do |
|---|---|---|
| Empty CA / 403 on policies | Token lacks Policy.Read | Complete Entra CA blade tour; use Global Reader |
| Many `ERROR_hunt_*.json` with 403 | No ThreatHunting scope **and** portal XSRF died mid-run | Keep Edge on Advanced Hunting; collector now auto-refreshes XSRF (~4m) + retries. Check `Attempts:` in ERROR for `portal:` lines |
| `Portal=ready` but hunts empty | Stale XSRF cached while Edge UI still open | Fixed in `lib/hunt.js` (invalidate + force reload); re-collect |
| `DeviceInfo` / `EntraIdSignInEvents` / `AADSignInEventsBeta` missing | No MDE / identity hunting stream | Not Log Analytics by default — see [HUNTING_KQL.md](HUNTING_KQL.md) |
| No device-code rows | Filter unsupported or no events | Check Graph sample / Entra Sign-in logs portal |
| EXO forwarding n/a | No Exchange admin token | Open `admin.exchange.microsoft.com` during collection |
| Intune rings empty | No Intune read | Grant Intune Reader and re-run |
| MFA wait forever | Still on login host | Finish MFA; ensure URL is entra/portal/security |
| Many `fetch failed` errors | Transient network / laptop sleep | Requests now retry 3× with backoff; if they still fail, `--resume` the run |
| 401s after ~1 h of collection | Graph token expired mid-run | Tokens are now renewed automatically (CLI re-probe / portal reload / app re-mint) |
| Report says "Incomplete collection" | Some steps failed | `node collect.js --resume output_YYYY-MM-DD_HHMM` |

Soft failures write `ERROR_<label>.json` in the output folder without aborting the run.

---

## Reliability and resume

Collection runs for one to three hours, so failures are treated as expected
rather than exceptional:

- **Retries** — every request has a hard timeout and retries transient network
  errors, 408, 429 and 5xx with exponential backoff. Deterministic 4xx (403 on a
  missing scope) fail immediately instead of wasting the budget.
- **Token renewal** — Graph tokens live ~60-75 minutes. Expired entries are
  evicted from the pool and a fresh one is minted from whichever source you
  authenticated with.
- **`00_MANIFEST.json`** — records, per artifact, whether it is `ok`, `empty`,
  `failed`, `partial` or `skipped`. This is what lets the report say
  "not collected" instead of showing a failed export as a clean zero.
- **`--resume`** — replays the run into the same folder. Calls that already
  succeeded are served from `.cache/`, so only the failed steps hit the network.

```bash
node collect.js --auth browser --cdp http://127.0.0.1:9222
# a few steps failed near the end
node collect.js --auth browser --cdp http://127.0.0.1:9222 --resume output_YYYY-MM-DD_HHMM

# Re-run only adaptive intel hunts (GraphAPI writes, alerts, IdentityInfo, …)
node collect.js --auth browser --cdp http://127.0.0.1:9222 --resume output_YYYY-MM-DD_HHMM --intel-only
```

### Checks that are NotEvaluated / NotApplicable rather than failed

When a source cannot be collected, the checks derived from it are marked `NotEvaluated`
instead of `Fail`, and a `Coverage` finding is raised. When the tenant cannot be in the
tested state (no Entra ID P2, Security Defaults on) the check is `NotApplicable` with the
licence it would need. The report opens with a coverage banner listing both. A failed Conditional
Access export used to produce High findings such as "no legacy-auth block" —
which described the outage, not the tenant.

---

## Ethics

Use only on tenants you are **authorized** to assess. The collector is designed as **read-only**.
