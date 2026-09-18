# Entra Collect — Guide

English product guide for operators and reviewers. For a visual walkthrough, open [`index.html`](index.html) in a browser.

---

## What it does

Entra Collect is a **read-only security assessment pipeline** for Microsoft Entra ID and Microsoft 365. It is designed for authorized pentests and baseline reviews where:

1. You already have a portal session (or CLI / app credentials), and  
2. You need **attack-path evidence**, not only compliance scores.

### Pipeline

```
┌─────────────┐     ┌──────────────┐     ┌────────────────┐     ┌──────────────────┐
│  Authenticate│ ──▶ │   Collect    │ ──▶ │ Expert analyzer│ ──▶ │ HTML + Excel     │
│ browser/CLI │     │ Graph+Hunt   │     │   NARR.*       │     │ (+ PDF in page)  │
│ /app/device │     │              │     │                │     │                  │
└─────────────┘     └──────────────┘     └────────────────┘     └──────────────────┘
                           │
                           ▼
                    output_YYYY-MM-DD_HHMM/
                    ├── 00_REPORT.html
                    ├── 00_Remediation_Plan.xlsx
                    ├── 00_Expert_Findings.*
                    ├── 00_SUMMARY.*
                    ├── 00_MANIFEST.json
                    └── 01_… 40_… CSVs / JSON
```

| Stage | Entry | Output |
|---|---|---|
| Collect | `node collect.js` | Artifacts + findings + summary + **HTML/Excel report** (auto) |
| Analyze | `node analyze.js <dir>` | `00_Expert_Findings.csv` / `.json` + posture score |
| Report | `node report.js <dir>` | Rebuild `00_REPORT.html` + `00_Remediation_Plan.xlsx` (re-runs analyze) |

---

## Platforms (Windows, macOS, Linux)

Requires **Node.js 18+** on all platforms.

### Shared concepts

| Topic | Detail |
|---|---|
| CDP attach | Preferred for passkeys / Authenticator QR: start a browser with remote debugging, then `--cdp http://127.0.0.1:9222` |
| Dedicated profile | Chrome/Edge 136+ ignore debugging on the **default** profile — the login scripts use a dedicated `entra-collect` profile |
| Profile location | Outside the git repo (cookies for the target tenant). Override with `ENTRA_COLLECT_PROFILE_DIR` |
| Auth modes | `auto` · `browser` · `cli` · `app` · `device` |

### macOS

```bash
npm install
./login-browser.sh                    # Edge by default; optional: brave|chrome
# Complete MFA / passkey QR in the window
node collect.js --auth browser --cdp http://127.0.0.1:9222
```

`login-browser.sh` uses `open -a` so **Bluetooth hybrid passkey** transport works.

### Linux

```bash
npm install
./login-browser.sh 9222 https://entra.microsoft.com msedge
node collect.js --auth browser --cdp http://127.0.0.1:9222
```

Headless CI is better served by `--auth app` (client credentials) than by headed CDP.

### Windows

```bat
npm install
login-edge.cmd
node collect.js --auth browser --cdp http://127.0.0.1:9222
```

Or `collect.cmd` / `--auth auto` after `az login` or `Connect-MgGraph`.  
See [WINDOWS.md](WINDOWS.md) for Edge paths, scheduled tasks, and CLI Graph tips.

### Auth mode cheat sheet

| Mode | When to use |
|---|---|
| `browser` + `--cdp` | Pentest laptop, passkeys, richest portal hunting session |
| `auto` | Jump host with Azure CLI already consented |
| `cli` | Strict: fail if no CLI Graph token |
| `app` | Linux/CI/scheduled — app registration with Graph (+ hunting if granted) |
| `device` | Rarely useful — often blocked by Conditional Access |

Preview coverage before a long run:

```bash
node collect.js --check-permissions --auth browser --cdp http://127.0.0.1:9222
```

---

## What is collected

Collection is **schema-aware** and **permission-aware**. Missing roles produce `ERROR_*.json` and Limitations in the report — not silent green zeros.

### Identity & Conditional Access

| Area | Examples |
|---|---|
| Tenant / auth | Organization, security defaults, auth methods, MFA registration campaign, auth strengths |
| CA | Full policies (CAPAnalyzer JSON), named locations, audit CSV, device-code CAPs, offline What-If pack (principals / memberships / raw signIns) |
| Users | No MFA, passkeys, inactive accounts, guests, SSPR sample |
| Devices | Stale joined, registered-only, per-user inventory, device registration policy |
| Risk | Risky users, risk detections |
| Sign-in digests | Device code, legacy auth, failed sign-ins by IP, privileged Graph sign-ins, SPN sign-ins |

### Privileged access & apps

| Area | Examples |
|---|---|
| Roles | High-value Entra roles **and** the full directory assignment inventory (Global Reader, Security Reader, …) |
| Attack path | Consent policy, CA coverage matrix, exclusion groups, path-to-GA, high-priv owners |
| Apps | Dangerous Graph permissions, wildcard reply URLs, secret expiry |

### Microsoft Secure Score

| Artifact | Meaning |
|---|---|
| `10_secure_score_latest.json` | Live tenant score + `controlScores` |
| `10_SecureScore_ByCategory.csv` | **In-scope** controls only (Identity / Apps / Data / Device…) |
| `10_SecureScore_Controls_ByValue.csv` | Full profile catalog (reference — do not use alone for gaps) |

Empty `CurrentScore` rows in the full catalog would invent hundreds of false MDE points. The report and analyzer prefer the in-scope set.

### Defender / M365 (adaptive)

After probing Advanced Hunting (`19_Hunting_Schema.json`):

| If available | Collected |
|---|---|
| `Device*` / TVM | RMM, AI agents, patch lag, Windows 10, TVM CVEs |
| `Email*` | Delivery samples, outbound domains |
| `CloudAppEvents` | GenAI / file-share usage, admin ops |
| `Alert*` / Exposure Graph | Alerts, critical assets & paths |
| `IdentityInfo` / `IdentityLogonEvents` | Critical identities, failed/privileged logons |

Without MDE device tables, endpoint RMM/TVM are **not assessed** (zeros mean unavailable). Identity and app narratives still run.

### Typical roles

| Role | Unlocks |
|---|---|
| Global Reader + Security Reader | Core Entra + Secure Score + many hunting views |
| Intune Reader / related | Update rings, some device inventory |
| Exchange / SharePoint admin APIs | Often still 403 for Reader — shown as Limitations |

Full artifact list: [OUTPUTS.md](OUTPUTS.md).

---

## Expert analyzer

The analyzer (`lib/analyze.js`) is a **static expert system**: deterministic correlation rules over collected files — not an LLM call at runtime.

### Goals

1. Turn inventory rows into **attack narratives** a pentester can brief.  
2. Prioritize **Now → Next → Later**.  
3. Produce a **posture score** (0–100) calibrated so expected patterns (backup apps, license-gated MFA inventory) do not alone collapse the gauge.  
4. Prefer **activity ∩ configuration** (e.g. dangerous SPN that actually signs in) over configuration alone.

### How a narrative is built

```
Load CSVs/JSON from output_*/
        │
        ▼
Build indexes (privileged UPNs, risky users, CA coverage, …)
        │
        ▼
Run rule blocks → pushNarrative({ id, severity, priority, title, narrative, evidence, remediation })
        │
        ▼
Sort by Priority then Severity
        │
        ▼
scoreFromNarratives() → expertScore + sevCount
        │
        ▼
00_Expert_Findings.csv / .json (+ summary refresh)
```

Each narrative has:

| Field | Role |
|---|---|
| `Id` | Stable id, e.g. `NARR.App.RoleManagement` |
| `Severity` | Critical → Info |
| `Priority` | Now / Next / Later (remediation order) |
| `Narrative` | Human-readable story |
| `Evidence` | Concrete UPNs, apps, counts |
| `Remediation` | Actionable next steps |
| `RelatedFiles` | Which CSVs to open |

### Context-aware severity (examples)

| Signal | Naive reading | Expert framing |
|---|---|---|
| 500 users without MFA methods | Critical gap | Medium if enforced MFA CA already exists — inventory ≠ open path; focus exclusion groups |
| Privileged user `risk=low` | Critical compromise | Medium when user-risk CA remediates high risk |
| TeamViewer on 5 IT laptops | Shadow RMM foothold | Medium — confirm allow-list before treating as attacker tool |
| Failed logons burst | External spray | Often **office / site egress** + shared mailboxes — confirm IPs with IT |
| `Microsoft 365 Backup` Directory.ReadWrite | Third-party GA path | Filtered as first-party; third-party Cove/Synology/SkyKick remain |
| Device MFA `notRequired` | (bug) “MFA required” | High — password-only join/register path |

### Score

Rough calibration (see `scoreFromNarratives`):

- Start at 100  
- Subtract for Critical / High / Medium / Low counts (capped)  
- Rebates when related narratives would double-count (e.g. RoleManagement + PathToGA)  
- Rebate when MFA inventory is compensated by enforced MFA CA  

**Expert posture ≠ Microsoft Secure Score.** The report shows both side by side.

Catalogue of all `NARR.*` ids: [ANALYZER.md](ANALYZER.md).  
False-positive notes: [FALSE_POSITIVES.md](FALSE_POSITIVES.md).

---

## HTML report & Excel workbook

### Generation

A successful collect already writes the report. Rebuild after code/UI changes:

```bash
node report.js                     # latest non-empty output_*
node report.js output_YYYY-MM-DD_HHMM
```

`report.js` always re-runs the analyzer so narratives stay in sync with code changes.
It writes **`00_REPORT.html`** and **`00_Remediation_Plan.xlsx`**.

### What you see

| Section / file | Content |
|---|---|
| **Dashboard** | Posture gauge, severity counts, Now/Next/Later roadmap, incomplete-collection banner |
| **Expert findings** | Filterable narratives (priority + severity) |
| **Inventory** | Raw `00_Findings.csv` by area |
| **Limitations** | `ERROR_*`, hunting schema gaps, skipped checks |
| **Attack path** | Checklist fails/partials first |
| **Deep dives** | CA, users/MFA, sign-ins, devices, endpoints, mail, privileged, apps |
| **Secure Score** | In-scope score, category cards, searchable roadmap (Identity / Apps / Data / Device) |
| **Hunting schema** | Tables probed this run |
| **`00_Remediation_Plan.xlsx`** | This Week + Remediation Plan (Owner / Status / Due) for steering |

### Design principles in the UI

- **Expert findings drive the story**; inventory Pass checks stay secondary.  
- **403 ≠ retry** — banner splits permission failures from transient errors (`--resume`).  
- **No MDE** — endpoint cards show `n/a` / “not assessed”, not green zeros.  
- **Secure Score** uses in-scope controls; category chips filter the backlog.  
- **Export Excel** / **Download PDF** for remediation steering and executive export.

### Offline use

`00_REPORT.html` embeds JSON data — open the file locally; no server required (except some browsers restricting `file://` for PDF helpers; then serve the folder with any static server).

---

## Reliability & resume

| Mechanism | Behaviour |
|---|---|
| Retries | Transient network / 429 / 5xx with backoff |
| Token refresh | Mid-run renewal via portal reload or CLI |
| Manifest | Every artifact: `ok` / `empty` / `failed` / `partial` / `skipped` |
| Cache + `--resume` | Successful Graph/hunt responses replayed from `.cache/` |

```bash
node collect.js --resume output_YYYY-MM-DD_HHMM
```

---

## Suggested operator workflow

1. Confirm authorization and target tenant.  
2. `login-browser.sh` / `login-edge.cmd` → sign in.  
3. `node collect.js --check-permissions …`  
4. Full collect (1–3 hours typical).  
5. Open `00_REPORT.html` → read **Expert findings (Now)** first; use `00_Remediation_Plan.xlsx` to assign owners.  
6. Use Limitations for gaps; do not treat skipped endpoint hunts as clean.  
7. After analyzer code updates: `node report.js <dir>` only — no re-collect needed.

---

## Related docs

- [ARCHITECTURE.md](ARCHITECTURE.md) — modules & hunting apiproxy  
- [USAGE.md](USAGE.md) — CLI flags  
- [OUTPUTS.md](OUTPUTS.md) — file catalog  
- [CHECKS.md](CHECKS.md) — attack-path check ids  
- [ANALYZER.md](ANALYZER.md) — narrative catalogue  
