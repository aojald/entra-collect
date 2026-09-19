# Expert analyzer (`NARR.*`)

`lib/analyze.js` correlates CSV/JSON artifacts into prioritized narratives and a posture score (`00_Expert_Findings.*`).

Re-run:

```bash
node analyze.js output_YYYY-MM-DD_HHMM
# or via report (also rebuilds HTML)
node report.js output_YYYY-MM-DD_HHMM
```

## Narratives (current)

| ID | Typical severity | Primary sources |
|---|---|---|
| `NARR.DeviceCode.Privileged` | Critical/High | `20_DeviceCode_*`, privileged accounts |
| `NARR.DeviceCode.NoCA` | High | `40_CA_AttackPath_Coverage`, checklist |
| `NARR.Priv.HybridGA` | High | `40_Privileged_Identity_Hygiene` |
| `NARR.Priv.StandingGA` | High | Permanent GA count |
| `NARR.Priv.MspStandingGA` | High | MSP/partner-style enabled GA (vendor naming / `.ext@`) |
| `NARR.Priv.ExternalGA` | Critical | External-looking GA UPNs |
| `NARR.App.RoleManagement` | High | `RoleManagement.ReadWrite.Directory` |
| `NARR.App.PathToGA` | High | `40_Apps_Path_To_GA` |
| `NARR.App.TapAutomation` | High | Auth Admin SP / `logic-generateTAP*` |
| `NARR.App.CaPolicyWrite` | High | `Policy.ReadWrite.ConditionalAccess` on apps |
| `NARR.App.SpnActive` | High/Med | `04_SPN_DangerousPerms` ∩ `27_SPN_SignIns_*` / digest — join on AppId / SP id, not display name |
| `NARR.App.SpnDormant` | Med/Low | Same join, inverted — dangerous grants with no sign-in (removal candidates) |
| `NARR.App.ExpiredSecrets` | Med/Low | `04_App_SecretsExpiry` |
| `NARR.App.FirstPartyCredential` | Critical/High | `04_SPN_Credentials` — secret / cert on a Microsoft first-party SP (persistence backdoor) |
| `NARR.App.DelegatedBroadGrants` | High/Med | `04_Delegated_Grants_AllPrincipals` — admin-consented delegated write / mailbox scopes for all users |
| `NARR.Priv.DormantAdmin` | Critical/High | `08_Accounts_Inactive_*` ∩ privileged roles, minus accounts matching the break-glass pattern |
| `NARR.Priv.BreakGlass` | Info/Medium | Dormant GAs excluded from most enforced CA in `02_CA_Audit` — the designed emergency accounts, judged on their controls rather than on dormancy |
| `NARR.Identity.InactiveNoMfa` | High/Med/Low | Inactive **member** accounts ∩ `07_Users_Without_MFA` (guests excluded), split into humans vs rooms/shared/service, downgraded when CA already gates the population |
| `NARR.Guest.Stale` | Med/Low | `05_guests` ∩ inactivity + `ExternalUserState=PendingAcceptance` |
| `NARR.Risk.PrivilegedAtRisk` | High | `24_RiskyUsers` ∩ privileged |
| `NARR.Risk.NoUserRiskCA` | High | Risk users + CA coverage |
| `NARR.Legacy.Observed` / `NoCA` | High | Legacy auth + CA |
| `NARR.Consent.User` | High | Authorization policy |
| `NARR.CA.GuestMfa` | High | Guest MFA CA (**Fail** only; Pass when `includeGuestsOrExternalUsers`) |
| `NARR.CA.BreakGlassExclusions` | High | Same user excluded from ≥8 enforced CA (`02_CA_Audit`) |
| `NARR.CA.SecInfoReg` | High | Register security info coverage |
| `NARR.CA.ExclGroups` | High | Non–role-assignable exclusion groups |
| `NARR.CA.ReportOnlyCompliance` | High | Device compliance report-only (not MAM `compliantApplication`) |
| `NARR.CA.ReportOnlyHardening` | High | Token Protection / phishing-resistant report-only |
| `NARR.CA.TrustedIpHygiene` | High | Public DNS (e.g. `1.1.1.1`) in trusted named locations |
| `NARR.CA.AzureMgmt` | Medium | Azure Management Partial |
| `NARR.MFA.MassGap` | Low→High | `07_Users_Without_MFA` + All-users / license-gate CA (role-only and risk MFA do not count as coverage) |
| `NARR.Endpoint.RmmSuspicious` | High/Med | Desktop RMM *agents* after noise filter (`30_RMM_*`) |
| `NARR.Endpoint.RmmInventoryNoise` | Info | Mobile/viewer/QuickSupport-only inventory |
| `NARR.Endpoint.TvmCves` | High | Unpatched Critical/High CVEs — `11_*` + `32_TVM_Windows_*` |
| `NARR.Endpoint.PatchLag` | High | `32_Behind_PatchTuesday` |
| `NARR.Endpoint.Windows10` | Low/Med | `32_Windows10_Devices` |
| `NARR.Cloud.FileSharing` | Medium/Low | `35_*` — network reachability, not upload volume; sustained traffic flagged as a sync-client pattern |
| `NARR.Cloud.GenAiUsage` | Medium/Low | `34_*` — sanctioned tenant apps vs third-party services by reach; **no byte volume**, see below |
| `NARR.Cloud.ShadowAi` | Med/Low | `31_AI_Agents_*` (excludes Copilot / OtherAI noise) |
| `NARR.Mail.SetMailboxBurst` | Med/Low | `25_HighValue_CloudAppEvents_*` Set-Mailbox, broken down by day and by attributed account |
| `NARR.Mail.ConsumerOutbound` | Med/Low | `18_Outbound_Email_Domains_30d` + `18_Consumer_Outbound_BySender_30d` — ranked by bytes and attachment count |
| `NARR.Devices.MultiEndpoint` | Info/Med | `09_Devices_Per_User_Multi` — flags shared enrollment/admin identities with mass device ownership |
| `NARR.Alert.HighSeverity` | High/Med/Info | `36_Security_Alerts_30d` — High/Critical XDR; MDCA/IRM storms are not treated as endpoint compromise |
| `NARR.Exposure.CriticalAssets` | Med/Info | `37_Exposure_Critical_Assets` — Exposure Manager critical/internet-facing nodes |
| `NARR.Exposure.Paths` | Med | `37_Exposure_Critical_Paths` — edges touching critical nodes |
| `NARR.Identity.DefenderCritical` | High/Med | `38_IdentityInfo_Critical` — UEBA inventory when Logon tables are empty |
| `NARR.Identity.FailedLogonBurst` | High/Med | `38_Identity_Failed_Logons_30d` — works when AADSignInEventsBeta is missing |
| `NARR.Identity.PrivilegedActivity` | Info | `38_Identity_Privileged_Logons_30d` ∩ privileged inventory |
| `NARR.Identity.PrivilegedGraphSignIns` | Info | `28_Privileged_SignIns_30d` — Graph activity baseline for admins |
| `NARR.App.DangerousSpnActivity` | High | `27_SPN_SignIns_Digest_*` — high-priv apps actively signing in |
| `NARR.Legacy.Observed` | High | Prefer `21_LegacyAuth_ByAccount_*` when traffic concentrates (e.g. SMTP) |
| `NARR.SecureScore.Roadmap` | Info | `10_SecureScore_Controls_ByValue` — costed backlog, deliberately score-neutral |

## Configuration vs activity

Most narratives read configuration: what an attacker *could* do. A second group
joins configuration with activity logs to say what is actually live, which is
usually what decides remediation order:

- an over-privileged app that authenticates daily is hardened; one that never
  authenticates is deleted (`SpnActive` / `SpnDormant`);
- a privileged account with no sign-in has full blast radius and no baseline
  for an intrusion to stand out against (`DormantAdmin`);
- dormant single-factor accounts are the password-spray surface
  (`InactiveNoMfa`), counted on members only — a guest authenticates against
  its home tenant, so "no MFA registered here" would be misleading.

## Output contract (schema version 2)

`00_Expert_Findings.csv` / `.json` (`schemaVersion: 2`) and `00_Findings.csv` share four columns beyond severity:

| Column | Values | Meaning |
|---|---|---|
| `Status` | `Fail` · `Info` · `NotEvaluated` · `NotApplicable` (checklist adds `Pass` / `Partial`) | `NotEvaluated` = the input was not collected — unknown, never a pass. `NotApplicable` = the tenant cannot be in the tested state (no P2, Security Defaults on). |
| `Confidence` | `High` · `Medium` · `Low` | `Medium` when the verdict rests on a partial / sampled pull or an All-users fallback; `Low` for name heuristics (break-glass, service-account naming). |
| `LicenceRequired` | `""` · `P1` · `P2` · `Governance` | Licence the control depends on. |
| `Rationale` | free text | One line on why this status. |

Severity vocabulary is the same everywhere: `Critical` · `High` · `Medium` · `Low` · `Info`. Inventory findings (`00_Findings.csv`) use `High` / `Medium` / `Info` (plus `Critical` for the first-party credential backdoor); narratives use the full range.

## Scoring

`scoreFromNarratives` starts from a base and subtracts by severity (Critical/High heavier). Clamped ~20–100. Report dashboard uses this score (not raw inventory finding counts). Only a **real** MFA compensation (`compensated=true` in the MassGap evidence: All-users MFA on all apps, protected security-info registration, no broad exclusions) softens the gauge — a policy name mentioning licences does not.

## Design notes

- Prefer **attack-path language** (what an attacker does next) over compliance checklists.
- Downgrade only for *verified* compensating controls, evaluated on raw policy JSON (`lib/caScope.js`) — never on display names.
- A password-only account that meets an MFA grant is sent to **registration**, not denied; All-users MFA therefore only compensates a registration gap when *Register security info* is itself protected by CA.
- Do not narrate Fail for Guest MFA when checklist is **Pass** / **Partial**.
- Counts derived from a failed export are `null` in `00_SUMMARY.json` and narrated as *unknown* — never as zero.
- See [FALSE_POSITIVES.md](FALSE_POSITIVES.md) for dismissal rules that feed analyzer inputs.

## What the hunting tables cannot tell you

Two questions come up on every report, and the honest answer to both is that
Defender Advanced Hunting does not carry the data:

- **Data volume to GenAI or file-sharing services.** Neither `CloudAppEvents`
  nor `DeviceNetworkEvents` has a byte counter. The only size-like column in the
  schema is `InitiatingProcessFileSize`, which is the size of the executable
  that opened the connection. Earlier versions of the analyzer summed it and
  reported "~0 MB transferred", which read as "nobody uses AI" — the opposite of
  the truth. Both narratives now report reach (events, distinct users, distinct
  devices) and say explicitly that volume requires a CASB or proxy in line.
- **What a `Set-Mailbox` call actually changed.** `CloudAppEvents` records that
  the cmdlet ran, not its parameters. Distinguishing an audit-setting update
  from a forwarding rule requires the Exchange admin audit log.

Outbound *mail* volume is the exception: `EmailEvents` does expose `EmailSize`
and `AttachmentCount`, which is why `NARR.Mail.ConsumerOutbound` can rank
senders by megabytes and by attachment count.

## Configuration that is intentional

Some configurations look like findings in isolation and are the correct design
in context. The analyzer detects these rather than reporting them as gaps:

- **Break-glass accounts** — a dormant Global Administrator excluded from most
  enforced CA policies is the designed emergency account. `classifyBreakGlass()`
  identifies it from the exclusion breadth in `02_CA_Audit.csv`, moves it out of
  `NARR.Priv.DormantAdmin` and out of `NARR.CA.BreakGlassExclusions`, and
  reports it once under `NARR.Priv.BreakGlass` with the controls that actually
  need verifying.
- **License-gated MFA** — where CA requires MFA of a licensed group *and* blocks
  unlicensed or unmanaged sign-in, a large "users without MFA" count is
  inventory rather than exposure. `detectLicenseGatedAccess()` recognises the
  pair and `NARR.MFA.MassGap` states that the compensating control is already
  deployed instead of recommending it. Role-only MFA, Identity Protection
  risk MFA, and admin-portal MFA are not treated as population coverage;
  group-scoped MFA is recorded as scoped, not covered.
- **Rooms and shared mailboxes** — these will never register an MFA method. The
  correct control is blocking interactive sign-in, so they are counted and
  advised separately from human accounts. `admin.` / `adm.` prefixes are
  bucketed as service accounts, not humans.
