# Running natively on Windows

The collector is **already Node.js + Playwright** — it runs on Windows without Wine/WSL. Collection logic (`lib/*`) is path-safe (`path.join`). What matters is the environment and auth mode.

## Prerequisites (Windows)

| Component | Why |
|---|---|
| **Node.js 18+** (LTS) | Runtime |
| **Git** (optional) | Clone / updates |
| `npm install` in `entra-collect` | Dependencies |
| **Microsoft Edge** | Recommended CDP path (`login-edge.cmd`) |
| `npm run setup:browser` | Only for `--browser chromium`; Edge needs nothing extra |
| Desktop session | Headed browsers need an interactive Windows session (RDP OK) |

## Recommended: CDP + Edge (MFA / passkeys)

Same idea as macOS/Linux `./login-browser.sh`: a **dedicated** Edge profile so `--remote-debugging-port` works on Edge 136+.

```bat
cd entra-collect
npm install
login-edge.cmd
REM optional: login-edge.cmd 9223 https://security.microsoft.com

REM After sign-in in that Edge window (Authenticator / Windows Hello / QR):
node collect.js --auth browser --cdp http://127.0.0.1:9222
```

| Topic | Detail |
|---|---|
| Profile | `%LOCALAPPDATA%\entra-collect\profiles\msedge-cdp` — deliberately **outside** the tool folder (live tenant cookies). Override with `ENTRA_COLLECT_PROFILE_DIR`. |
| MFA | Windows Hello, Authenticator push, or QR |
| Portal hunting | Attach keeps Security portal session → Advanced Hunting apiproxy |
| Antivirus | May prompt on Edge flags — allowlist if needed |

Without CDP, `node collect.js --auth browser` still works via Playwright-launched Edge (`--browser msedge`).

## Alternative: CLI-first (`--auth auto`)

When Azure CLI / Graph PowerShell already have Graph consent:

```bat
collect.cmd
REM or:
node collect.js --check-permissions
node collect.js --auth auto --inactive-days 90 --device-stale-months 3
```

`--browser` defaults to `auto`, which picks Edge on Windows.

## Auth modes (`--auth`)

| Mode | Behavior |
|---|---|
| **`auto` (default)** | Probe CLI Graph tokens first (`az` → Microsoft Graph PowerShell). If a usable token with **Policy.Read** / CA probe OK → **no browser**. Otherwise spawn a portal login. |
| **`cli`** | CLI only — fail if no token (no browser). |
| **`browser`** | Portal session via Playwright **or** `--cdp` attach (recommended with `login-edge.cmd`). |
| **`device`** | `az login --use-device-code` (often blocked by CA). |
| **`app`** | Client credentials — no interactive session, suitable for scheduled tasks. |

```bat
REM Prefer Azure CLI / MgGraph when consented; else browser
node collect.js --auth auto

REM Strict CLI (after az login or Connect-MgGraph)
node collect.js --auth cli

REM CDP attach (recommended for MFA / hunting)
login-edge.cmd
node collect.js --auth browser --cdp http://127.0.0.1:9222

REM Always Playwright browser (no CDP)
node collect.js --auth browser
```

### Preparing CLI Graph access

When admin consent is available for one of:

1. **Azure CLI** (recommended on Windows jump hosts)
   ```bat
   az login
   az account get-access-token --resource-type ms-graph --query accessToken -o tsv
   ```
2. **Microsoft Graph PowerShell**
   ```powershell
   Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
   Connect-MgGraph -Scopes "Directory.Read.All","Policy.Read.All","User.Read.All","AuditLog.Read.All","IdentityRiskEvent.Read.All","SecurityEvents.Read.All","ThreatHunting.Read.All"
   ```
3. **App registration** (best for scheduled or unattended runs)
   ```bat
   set ENTRA_CLIENT_SECRET=...   (or --client-secret-file secret.txt)
   node collect.js --auth app --tenant TENANT --client-id APP
   ```

`mgc` (Microsoft Graph CLI) is detected but **cannot be used as a token source** —
it has no command that exports a bearer token.

Note on `az`: its Graph token carries the Azure CLI first-party scope set, which
does **not** include `ThreatHunting.Read.All`. All Defender hunts (RMM, Shadow AI,
GenAI, TVM, patch lag) are unavailable in that mode. Use `Connect-MgGraph` with
the scopes above, an app registration, or the browser/CDP path.

If the CLI token lacks `Policy.Read.*`, `--auth auto` falls back to the browser so
CA collection still works. Run `node collect.js --check-permissions` first to see
exactly which areas your session covers.

## Windows-specific notes

| Topic | Detail |
|---|---|
| Paths with spaces | Supported (`path.join`); quote paths in `.cmd` |
| Press Enter after MFA | Works in `cmd.exe` and PowerShell |
| Headless | `--headless` possible but MFA usually needs headed |
| Antivirus | May quarantine Playwright Chromium — allowlist if install fails |
| Corporate proxy | Set `HTTPS_PROXY` / `HTTP_PROXY` for Node + Playwright |
| Execution policy | `collect.cmd` uses `node` only — no PowerShell script signing required |
| Line endings | Prefer LF in git; Node tolerates CRLF |

## What is *not* required for Windows

- WSL / Docker
- Graph PowerShell for the **browser / CDP** path (portal tokens)
- Admin rights on the workstation (Node user install / zip is enough)

## After collection

Open `output_*\00_REPORT.html` and `output_*\00_Remediation_Plan.xlsx`.
Rebuild with `node report.js output_YYYY-MM-DD_HHMM` if you change analyzer rules.

## Smoke-test `login-edge.cmd` (CDP)

On a Windows desktop with Edge installed:

```bat
login-edge.cmd
curl -s http://127.0.0.1:9222/json/version
node collect.js --auth browser --cdp http://127.0.0.1:9222 --no-wait-enter
```

If port 9222 already answers CDP, `login-edge.cmd` exits 0 and prints the collect command (does not start a second Edge). Profile dir: `%LOCALAPPDATA%\entra-collect\profiles\msedge-cdp`.

## Diagram

```
Windows jump host
    ├─ login-edge.cmd --cdp ──▶ TokenPool + portal hunting ──▶ runCollection
    ├─ collect.cmd / --auth auto ──▶ CLI Graph (az / Mg) ──▶ (fallback browser)
    └─ --auth app ──▶ client credentials ──▶ runCollection
```

See also: [GUIDE.md](GUIDE.md) · [USAGE.md](USAGE.md) · [SECURITY.md](../SECURITY.md)
