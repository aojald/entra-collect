# Security Policy

## Authorized use only

Entra Collect is intended for **authorized** security assessments of Microsoft Entra ID / Microsoft 365 tenants you own or have written permission to test. Misuse against third-party tenants is prohibited.

## Handling of secrets and session data

- Collection may capture **portal session tokens** in memory and write **tenant inventory** under `output_*/`.
- Treat every `output_*` folder as **highly confidential** customer data (UPNs, role assignments, CA policies, hunting evidence).
- Browser CDP profiles (`%LOCALAPPDATA%\entra-collect`, `~/Library/Application Support/entra-collect`, etc.) hold **live cookies** — keep them outside engagement archives and never commit them.
- Do not commit `.env`, certificates, or `*.local.json`.
- Raw bearer tokens are not written to `00_token_info.json` by design; still protect the machine running the tool.
- `output_*/.cache/` holds every raw Graph response (so `--resume` can replay a run). It is as sensitive as the CSVs; use `--no-cache` when you do not need resume, and delete the folder before archiving.
- App-only runs: pass the client secret through `ENTRA_CLIENT_SECRET` or `--client-secret-file`. `--client-secret` on the command line is deprecated because the value shows in `ps` and shell history.
- CSV cells that start with `=`, `+`, `-`, `@` or a tab are prefixed with `'` so tenant-controlled names cannot become spreadsheet formulas when the files are opened in Excel.

## Browser session exposure during a run

Browser mode drives a real Edge / Brave / Chrome window through the Chrome DevTools Protocol. While the collection runs (1–3 h) that browser has a **debugging port open on 127.0.0.1** and holds an **authenticated admin session**.

- Any local process running as the same user can attach to that port and act as the signed-in administrator. Run collections from a workstation you trust, not a shared jump host, and do not leave the session unattended.
- The launchers never pass `--remote-allow-origins`; Playwright attaches without an `Origin` header, and enabling it would let web pages talk to the debugging socket.
- When the tool launched the browser itself it closes it at the end. With `--cdp` (you started the browser) or `--keep-browser`, close the window yourself once the run is done.
- The tool refuses to proceed without an explicit tenant: pass `--tenant <guid>` or confirm the tenant name it resolved. Tokens, portal hunting headers and `--resume` folders from another tenant are rejected.

## Reporting vulnerabilities

If you find a security issue in Entra Collect itself (token handling, unsafe defaults, injection in report generation, etc.), please open a **private** GitHub security advisory on the repository, or contact the maintainer via GitHub.

Please do **not** open a public issue that includes customer tenant data, tokens, or cookies.
