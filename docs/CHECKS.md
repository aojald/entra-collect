# Security checks reference

This tool mixes **inventory** (facts for the report) and **attack-path checks** (Pass/Fail that map to abuse). Attack-path logic lives in `lib/attackpath.js` and is inspired by Maester / EIDSCA / CISA — selected for **attacker usefulness**, not audit checkbox coverage.

---

## Attack-path checklist (`40_AttackPath_Checklist.csv`)

| CheckId | Title | Why it matters |
|---|---|---|
| `AP.Consent.User` | User OAuth consent limited | Consent phishing without password theft |
| `AP.Consent.Risky` | Block consent for risky apps | Microsoft-flagged apps |
| `AP.Consent.AdminWorkflow` | Admin consent request workflow | Safe path vs shadow IT |
| `AP.Apps.Create` | Users cannot register apps | Phishing app + redirect URI |
| `AP.Guest.Role` | Guest ≠ member-equivalent | Directory enumeration by guests |
| `AP.MFA.SMS` | SMS not usable for MFA | SIM swap / OTP phishing |
| `AP.MFA.Voice` | Voice MFA disabled | Phone-based bypass |
| `AP.MFA.EmailOTP` | Email OTP disabled | Mailbox → MFA bypass |
| `AP.MFA.TAP` | TAP one-time & short-lived | Standing password equivalent |
| `AP.MFA.NumberMatch` | Authenticator number matching (Info only — platform-enforced since May 2023) | MFA fatigue / push bombing |
| `AP.CA.DeviceCode` | CA blocks device code / auth transfer for all users | Device-code phishing → PRT without a password |
| `AP.CA.LegacyBlock` | CA blocks legacy auth | Password spray without MFA |
| `AP.CA.AzureMgmt` | MFA for Azure / admin portals | Control-plane after password theft |
| `AP.CA.SignInRisk` | Sign-in risk MFA/block (P2) | Impossible travel / unfamiliar sign-in |
| `AP.CA.UserRisk` | User risk block / password change (P2) | At-risk users keep working |
| `AP.CA.GuestMfa` | MFA for guests | Invited guest foothold |
| `AP.CA.AllUsersMfa` | MFA for all users on all cloud apps | Password-only sign-in anywhere in the population |
| `AP.CA.AdminPhishingResistant` | Phishing-resistant strength for Global Administrators | AitM / token replay against admins |
| `AP.CA.ExclRoles` | All-users policies do not exclude GA / PRA / PAA | Administrators carved out of every control |
| `AP.CA.SecInfoReg` | Protect Register security info | MFA method takeover |
| `AP.CA.SessionControls` | Sign-in frequency + never-persistent browser on population policies | Stolen sessions stay valid for weeks |
| `AP.CA.GrantOR` | Device + MFA use AND | MFA alone bypasses compliance |
| `AP.CA.ExclGroups` | CA exclude groups role-assignable, static, small | Add-self → bypass all CA |
| `AP.CA.SecurityDefaults` | Info row when Security Defaults are on | Design state — CA controls NotApplicable |
| `AP.Priv.HybridGA` | GAs not on-prem synced | AD compromise → cloud GA |
| `AP.Priv.GaMfa` | Every GA has MFA registered | Password-only GA |
| `AP.App.PathToGA` | No apps with GA-path Graph perms | App secret → Global Admin |
| `AP.App.FirstPartyCreds` | No credentials on Microsoft first-party service principals | Persistence backdoor after compromise |
| `AP.App.DelegatedGrants` | No broad AllPrincipals delegated grants to third-party apps | Every user's token → mailbox / directory write |
| `AP.App.Management` | App management policies enabled | Unrestricted secrets / URIs |
| `AP.CA.DirSync` | Sync accounts CA hygiene | Break sync or leave sync unprotected |

Statuses: **Pass** · **Fail** · **Partial** · **Info** · **NotEvaluated** (input not collected) · **NotApplicable** (licence / Security Defaults). Every row also carries `Confidence`, `LicenceRequired` and `Rationale`.

### Effective scope, not policy names

Every CA verdict is computed on the *effective scope* of each policy (`lib/caScope.js`): a policy counts as coverage only when it is **enforced**, targets **all users** and **all cloud apps** (or the roles the control is about) and is not hollowed out by exclusions — Global / Privileged Role Administrator excluded, ≥3 excluded roles or groups, ≥10 excluded users, or excluded groups holding ≥25 members in total. Anything else is **Partial** with the reason (`not all users`, `not all apps`, `excludes Global Administrator`, `broad exclusions`) in the Evidence column. Display names are never used.

---

## CA coverage matrix (`40_CA_AttackPath_Coverage.csv`)

For each attacker-relevant control, the tool records whether an **enforced, population-wide** CA policy covers it (`Covered` = `true` / `partial` / `false` / `unknown` / `n/a`), which policy names matched and, for `partial`, why:

- Device code / auth transfer  
- Legacy authentication block  
- Azure management / Microsoft Admin Portals MFA  
- Sign-in risk  
- User risk  
- Guest MFA  
- MFA for all users on all cloud apps  
- Phishing-resistant MFA for Global Administrators  
- Security-info registration  

Also flags:

- Enforced **OR(mfa, compliantDevice|domainJoinedDevice)** grants  
- **Report-only** device-compliance policies (still not blocking unmanaged devices)

---

## Always-on inventory findings (`00_Findings.csv`)

Examples of findings emitted from the main collector (not only attack-path):

| Area | Signal |
|---|---|
| SecurityDefaults | Off → CA must cover MFA/legacy |
| Tenants | Users can create tenants |
| Guests | Invites from everyone |
| CA | Report-only policies; no device-code CA |
| Privileged | Standing (permanent, tenant-wide) GA count — PIM activations live at collection time and AU/app-scoped assignments are listed but not counted; role-assignable group members are expanded |
| MFA | Users without MFA registered |
| InactiveAccounts | Enabled idle accounts |
| DeviceJoin | Join/register = All users |
| DeviceCode / LegacyAuth | Observed usage in logs |
| IdentityProtection | At-risk / compromised users |
| AppPrivEsc / Consent / WeakMFA | From attack-path module |
| HuntingSchema | API unavailable or tables missing |
| RMM / AI / PatchTuesday | Endpoint hunts when schema allows |

Severity guide used in practice:

- **High** — direct attacker path or standing privilege abuse  
- **Medium** — important hardening / likely abuse assist  
- **Info** — context, coverage notes, successful controls  

---

## What is intentionally *not* cloned from Maester

Skipped as low signal for a pentest deliverable (ops/compliance noise):

- Intune certificate / APNS / VPP expiry grids  
- Branding / cosmetic Intune settings  
- Broad CIS “P1 licensed user” inventory  
- Full Defender ASR checkbox matrices  
- Copilot Studio AI-agent governance suites  

Those can still be reviewed manually with your own baseline / CIS / Intune checklists outside this tool.

---

## Interpreting “clean” vs “skipped”

| Result | Meaning |
|---|---|
| Checklist **Pass** | Control observed as present/enforced |
| Checklist **Fail** | Gap confirmed from Graph/CA data |
| Finding “Skipped — hunting unavailable” | No data plane — **not** a clean bill of health |
| Empty `30_RMM_*` + schema missing `DeviceInfo` | Could not hunt endpoints |
| Device code **0** events | No observed use in window (still check CA coverage) |

---

## Expert narratives (`00_Expert_Findings.csv`)

Second-pass **static correlation** (`lib/analyze.js` / `node analyze.js`). Joins inventory CSVs into attack stories used for the report score:

| Id | Joins | Why |
|---|---|---|
| `NARR.DeviceCode.Privileged` | Device-code users ∩ privileged / GA (± Identity Protection) | Live admin token path |
| `NARR.DeviceCode.NoCA` | Device-code usage or gap × CA coverage | Exploitability of the flow |
| `NARR.Priv.HybridGA` | Hygiene OnPremSynced GAs (aggregated) | AD → cloud GA |
| `NARR.Priv.StandingGA` | Permanent GA count | Blast radius |
| `NARR.Priv.ExternalGA` | GA UPNs matching `.ext` / vendor patterns | Supply-chain standing admin |
| `NARR.App.RoleManagement` | `RoleManagement.ReadWrite.Directory` | Direct role assignment → GA |
| `NARR.App.PathToGA` | Other GA-path Graph app roles | App secret → directory write |
| `NARR.Risk.PrivilegedAtRisk` | Risky users ∩ privileged | Compromised admin still active |
| `NARR.Risk.NoUserRiskCA` | Risky user count × no user-risk CA | No automated containment |
| `NARR.Legacy.Observed` / `.NoCA` | Legacy success × CA legacy block | Spray without MFA |
| `NARR.Consent.User` | Consent checklist × dangerous apps | Consent phishing |
| `NARR.CA.GuestMfa` / `SecInfoReg` / `ReportOnlyCompliance` | CA coverage + related inventory | Classic CA holes |
| `NARR.MFA.MassGap` | Users without MFA (+ admins) | Registration debt |
| `NARR.CA.AzureMgmt` | Partial Azure Management MFA | CLI/ARM bypass of portal MFA |

Severity: **Critical** (correlated standing privilege abuse) · **High** · **Medium**. Inventory `Info` / skip rows stay out of this score.
