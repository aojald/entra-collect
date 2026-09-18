# Hunting / logs — adaptive collector + manual KQL

> App docs: see [README.md](../README.md) and the rest of [docs/](./).

The collector **auto-discovers** schema on each run (`lib/schema.js` → `19_Hunting_Schema.json`) and only runs hunts for tables that exist. Re-run `node collect.js` after granting hunting rights to pick up new tables.


---

## Why portal queries failed earlier

| Query table | Error | Meaning |
|---|---|---|
| `AADSignInEventsBeta` | table not resolved | Legacy XDR identity table — current tenants often have `EntraIdSignInEvents` instead |
| `EntraIdSignInEvents` | table not resolved | Entra identity stream not in Defender Hunting (needs Entra ID P2 + XDR identity) |
| `DeviceInfo` | table not resolved | No MDE Advanced Hunting device tables (or wrong workspace) |

Those tables are **not** default Log Analytics. They only appear in Defender XDR Advanced Hunting when the product streams data.

---

## Where logs live by default

1. **Entra** → Monitoring → Sign-in logs (Graph `auditLogs/signIns`) — default, no LAW required  
2. **Log Analytics / Sentinel** — only if Entra Diagnostic settings → workspace (`SigninLogs`, `AuditLogs`)  
3. **Defender Hunting** — `DeviceInfo` plus `EntraIdSignInEvents` (legacy `AADSignInEventsBeta`) with MDE / XDR streams  

---

## Manual discovery (optional)

Prefer re-running the collector. Or in Hunting:

```kusto
search *
| distinct $table
| sort by $table asc
```

Probes: `DeviceInfo | take 1`, `EntraIdSignInEvents | take 1`, `AADSignInEventsBeta | take 1`, `EmailEvents | take 1`, `SigninLogs | take 1`, … The collector prefers the table that exists and has rows (new XDR name, then legacy XDR, then Sentinel, then Defender for Identity).

---

## Identity KQL if LAW has `SigninLogs`

```kusto
SigninLogs
| where TimeGenerated > ago(90d)
| where AuthenticationProtocol =~ "deviceCode"
    or AuthenticationProtocol has "deviceCode"
    or ClientAppUsed has "Device Code"
| summarize Events=count(), Apps=make_set(AppDisplayName, 10), Ips=make_set(IPAddress, 10)
    by UserPrincipalName
| sort by Events desc
```

Device/RMM/patch KQL only if `DeviceInfo` exists — or just re-run the collector once hunting is enabled; it adapts automatically.

### GraphAPIAuditEvents (CA / role / consent writes)

This table has **no** `AccountDisplayName`. Group by `AccountObjectId` (plus `ApplicationId` / `ServicePrincipalId`). The collector does that automatically (`39_GraphAPI_Write_Audit_30d.csv`). To refresh only this family of hunts:

```bash
node collect.js --auth browser --cdp http://127.0.0.1:9222 --resume output_YYYY-MM-DD_HHMM --intel-only
```
