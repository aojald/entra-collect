# Entra Collect

**Read-only Entra ID / Microsoft 365 attack-path assessment** for authorized pentests and baseline reviews.

It reuses your interactive **portal login** (Entra, Azure, Defender, Intune, Exchange) so you do **not** need admin consent for *Microsoft Graph Command Line Tools*. Tokens are captured from the browser session and used against Microsoft Graph and Defender Advanced Hunting.

```
Login (browser / CLI / app)
        │
        ▼
   Collect artifacts          →  CSV / JSON in output_*/
        │
        ▼
   Expert analyzer (NARR.*)   →  prioritized attack narratives + posture score
        │
        ▼
   HTML + Excel (+ PDF)       →  00_REPORT.html · 00_Remediation_Plan.xlsx
```

> **Visual docs:** open [`docs/index.html`](docs/index.html) in a browser (or enable GitHub Pages on `/docs`).  
> **Full guide:** [`docs/GUIDE.md`](docs/GUIDE.md)

---

## Why this tool

| Problem | Approach |
|---|---|
| Graph PowerShell / CLI apps blocked by admin consent | Capture tokens from already-consented **first-party portals** |
| Compliance checklists that ignore real attack paths | Expert narratives focused on GA paths, CA bypass, live SPN activity |
| “0 findings” when Hunting/API failed | Manifest + Limitations: **unknown ≠ clean** |
| Long runs (1–3 h) | Retries, token refresh, `--resume` with response cache |
| Tenants without MDE | Adaptive schema: skip `Device*`, still collect identity / apps / Exposure Graph |

Inspired by Maester / EIDSCA / CISA attack-path thinking — not Secure Score theatre. Microsoft Secure Score is included as a **separate** adoption backlog (in-scope controls only).

---

## Quick start

```bash
git clone https://github.com/aojald/entra-collect.git
cd entra-collect
npm install
```

### macOS / Linux (recommended: CDP + passkeys)

```bash
./login-browser.sh
# Sign in to the target tenant in the Edge/Brave window (QR / MFA)

node collect.js --auth browser --cdp http://127.0.0.1:9222 --tenant <customer-tenant-guid> \
  --inactive-days 90 --device-stale-months 3 --signin-days 30,90
```

### Windows

```bat
login-edge.cmd
node collect.js --auth browser --cdp http://127.0.0.1:9222 --tenant <customer-tenant-guid>
```

Or use `collect.cmd` / `--auth auto` (tries Azure CLI / Graph PowerShell first).

### Tenant, output and secrets

- **Tenant**: pass `--tenant <guid>`. Without it the tool resolves the tenant from the first token it sees and asks you to confirm the organisation name before writing anything (`--yes` skips the prompt for scripted runs). Tokens, portal hunting headers and `--resume` folders from another tenant are refused.
- **Output**: `output_YYYY-MM-DD_HHMM/` is created in the **current directory** (override with `--out DIR`). `output_*/.cache/` keeps raw Graph responses for `--resume`; add `--no-cache` if you do not need it — it is as sensitive as the CSVs.
- **App-only**: give the client secret via `ENTRA_CLIENT_SECRET` or `--client-secret-file FILE`. `--client-secret` on the command line still works but is deprecated (visible in `ps` / shell history).
- **Browser**: the launched browser is closed at the end of the run (its debugging port would otherwise stay open on an admin session); `--keep-browser` keeps it. With `--cdp` you started the browser yourself — close it when done.

### After collection

A successful collect already writes the report artifacts. Open them directly:

```bash
open output_*/00_REPORT.html              # macOS
start output_*\00_REPORT.html             # Windows
# also: output_*/00_Remediation_Plan.xlsx
```

Rebuild after analyzer/UI changes (no new collection):

```bash
node report.js output_YYYY-MM-DD_HHMM
```

| Command | Purpose |
|---|---|
| `node collect.js --check-permissions` | Preview what this session can collect |
| `node collect.js --resume output_…` | Retry failed steps only (cache hits for the rest) |
| `node analyze.js output_…` | Re-run expert narratives only |
| `node report.js output_…` | Rebuild HTML + Excel (+ re-analyze) |

---

## Platforms

| OS | Browser attach | Notes |
|---|---|---|
| **macOS** | `./login-browser.sh` | Uses `open -a` so Bluetooth hybrid passkey QR works |
| **Linux** | `./login-browser.sh` | Launches browser binary with CDP |
| **Windows** | `login-edge.cmd` | Native Node — no WSL required |

Requires **Node.js ≥ 18**. Browser profiles live **outside** the repo (`~/Library/Application Support/entra-collect`, `%LOCALAPPDATA%\entra-collect`, `$XDG_STATE_HOME/entra-collect`) because they hold live tenant cookies.

Auth modes: `auto` · `browser` · `cli` · `app` (client credentials for CI) · `device`.

Details: [docs/GUIDE.md#platforms](docs/GUIDE.md#platforms-windows-macos-linux) · [docs/WINDOWS.md](docs/WINDOWS.md)

---

## What gets collected

Hundreds of artifacts under `output_*/`, grouped roughly as:

- **Identity & CA** — policies, named locations, MFA registration, guests, inactive accounts, risk
- **Privileged access** — role assignments, hybrid GAs, PIM signals, privileged hygiene
- **Applications** — dangerous Graph grants, path-to-GA, secrets, SPN sign-ins
- **Secure Score** — **in-scope** live controls by category (not the inflated full catalog)
- **Defender hunting** — schema discovery, then RMM / TVM / GenAI / mail / alerts / Exposure Graph when tables exist
- **M365 collab** — cross-tenant, Teams guest samples, anti-spam checklists, outbound mail digests

Adaptive hunting probes `19_Hunting_Schema.json` and **skips** queries that cannot run (e.g. no `Device*` without MDE).

Catalog: [docs/OUTPUTS.md](docs/OUTPUTS.md) · Overview: [docs/GUIDE.md#what-is-collected](docs/GUIDE.md#what-is-collected)

---

## Expert analyzer

`lib/analyze.js` correlates CSVs into **`NARR.*` narratives** (Now / Next / Later) and a posture score (0–100).

Examples:

- Apps with `RoleManagement.ReadWrite.Directory` → Critical GA-equivalent path  
- Standing / hybrid Global Administrators  
- CA exclusion groups that are not role-assignable  
- Live high-privilege SPN sign-ins vs dormant grants  
- MFA registration gaps **downgraded** only when All-users MFA *and* a protected security-info registration exist (an account with no method is otherwise one password away from an attacker enrolling their own)  
- Failed logons framed as office-egress noise vs external spray  
- Credentials on Microsoft first-party service principals, broad delegated grants, federated-IdP MFA trust

Every check and narrative carries a **Status** (`Pass` / `Fail` / `Partial` / `NotEvaluated` / `NotApplicable`), a **Confidence** and the **licence** it depends on. A check whose input could not be collected is *NotEvaluated*, never *Pass*; a control the tenant cannot have (no P2, Security Defaults on) is *NotApplicable*, never *Fail*. Conditional Access is scored on each policy's **effective scope** (all users, all apps, exclusions), not on its display name.

Re-run anytime: `node analyze.js <output_dir>`.

Catalogue: [docs/ANALYZER.md](docs/ANALYZER.md) · How it works: [docs/GUIDE.md#expert-analyzer](docs/GUIDE.md#expert-analyzer)

---

## HTML report & Excel workbook

A successful collect (and `node report.js`) write:

| File | Purpose |
|---|---|
| `00_REPORT.html` | Interactive dashboard + findings (self-contained) |
| `00_Remediation_Plan.xlsx` | Steering workbook — **This Week**, Remediation Plan, Owner / Status / Due |

In the HTML:

- Dashboard with posture gauge and **Now / Next / Later** roadmap  
- Expert findings (filterable) vs raw inventory  
- Deep dives: CA, users, privileged, apps, endpoints, Secure Score by category  
- Limitations banner: 403 vs transient failures  
- **Export Excel** / **Download PDF** buttons

```bash
node report.js                  # latest output_* (rebuild)
node report.js output_YYYY-MM-DD_HHMM
```

---

## Documentation map

| Doc | Content |
|---|---|
| **[docs/index.html](docs/index.html)** | Visual overview (open in browser / GitHub Pages) |
| **[docs/GUIDE.md](docs/GUIDE.md)** | Full English guide (platforms, collect, analyzer, report) |
| [docs/USAGE.md](docs/USAGE.md) | CLI flags & troubleshooting |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Modules, CDP, hunting apiproxy |
| [docs/WINDOWS.md](docs/WINDOWS.md) | Windows-specific setup |
| [docs/OUTPUTS.md](docs/OUTPUTS.md) | Artifact catalog |
| [docs/CHECKS.md](docs/CHECKS.md) | Attack-path checklist IDs |
| [docs/ANALYZER.md](docs/ANALYZER.md) | `NARR.*` catalogue |
| [docs/FALSE_POSITIVES.md](docs/FALSE_POSITIVES.md) | Known noise / dismissal rules |
| [docs/HUNTING_KQL.md](docs/HUNTING_KQL.md) | Manual KQL companions |
| [SECURITY.md](SECURITY.md) | Token / output handling & vulnerability reporting |

---

## Requirements & ethics

- Node.js **≥ 18**
- Signed-in account with at least **Global Reader** + **Security Reader** (more roles unlock Intune / EXO / hunting)
- **Authorized** engagement on the target tenant only
- Read-only Graph / hunting calls — no tenant configuration changes
- Keep `output_*` and browser profiles **out of git** — they contain customer identity data

---

## License

[MIT](LICENSE) © 2026 Aojald
