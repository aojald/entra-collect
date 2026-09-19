# Output file catalog

All paths are relative to `output_YYYY-MM-DD_HHMM/`.

## Start here

| File | Description |
|---|---|
| `00_REPORT.html` | Interactive findings viewer + **Export Excel** / **Download PDF** |
| `00_Remediation_Plan.xlsx` | Steering workbook (This Week / Remediation Plan / Owner · Status · Due) |
| `00_SUMMARY.md` | Human executive summary |
| `00_SUMMARY.json` | Machine-readable summary + KPIs |
| `00_MANIFEST.json` | Per-step collection status (ok / failed / empty) |
| `00_Expert_Findings.csv` / `.json` | Correlated attack narratives (drives posture score) |
| `00_Findings.csv` | Inventory findings Severity; Area; Detail |
| `00_REPORT_DATA.json` | Compact report metadata (score, counts) |
| `.cache/` | Raw Graph responses keyed by URL, used by `--resume`. Same sensitivity as the CSVs; skip with `--no-cache`, delete before archiving |

## Tenant & authentication

| File | Description |
|---|---|
| `01_organization.json` | Tenant org object |
| `01_security_defaults.json` | Security Defaults on/off |
| `01_authorization_policy.json` | Invites, consent policies, create apps/tenants, guest role |
| `01_auth_methods_policy.json` | Auth methods config (SMS, Voice, FIDO, Authenticator, …) |
| `01_auth_methods.csv` | Method × state |

## Conditional Access

| File | Description |
|---|---|
| `02_ca_policies_raw.json` | Graph policies (IDs) |
| `02_ca_policies_capanalyzer.json` | CAPAnalyzer upload (IDs + `_resolved` names) |
| `02_directory_principals_capanalyzer.json` | Users/groups/apps/roles referenced by CA (offline What-If) |
| `02_user_memberships_capanalyzer.json` | Bounded `transitiveMemberOf` for CA + privileged users |
| `02_CA_Audit.csv` | Flattened policy audit with resolved names |
| `02_DeviceCode_CAPs.csv` | Policies targeting auth flows / device code |
| `02_named_locations.json` | Named locations (JSON) |
| `02_NamedLocations.csv` | Named locations (CSV) |
| `02_named_locations_capanalyzer.json` | Optional CAPAnalyzer locations upload |

## Privileged access

| File | Description |
|---|---|
| `03_role_definitions.json` | Role catalog (beta, with `isPrivileged` when readable) |
| `03_PrivilegedRoles_Audit.csv` | One row per *effective* principal: `AssignmentType` = `Permanent` / `PIM — Active (activated)` / `PIM — Eligible`; `Scope` = `Tenant` / `AU` / `App` (+ `ScopeName`); `ViaGroup` when inherited from a role-assignable group (the group shell is kept as its own row); `IsPrivilegedRole` from Graph `isPrivileged` or the built-in high-value list. Source: `roleAssignmentScheduleInstances` (P2/Governance) or `roleAssignments` |
| `03_PrivilegedAccounts_HighValue.csv` | Privileged roles on effective principals (group members expanded, shells excluded). Only `Permanent` + `Tenant` rows count as standing GA |

## Apps & guests

| File | Description |
|---|---|
| `04_SPN_DangerousPerms.csv` | High-risk application permissions on Microsoft Graph, Exchange Online (`full_access_as_app`, `Exchange.ManageAsApp`), SharePoint Online and legacy Azure AD Graph (`ResourceAppId` column) |
| `04_Delegated_Grants_AllPrincipals.csv` | Admin-consented delegated grants for all users, scored on the worst scope (`MaxSeverity`) |
| `04_SPN_Credentials.csv` | Every secret / certificate on a service-principal object; `MicrosoftOwned=true` rows are the first-party backdoor pattern (Critical), `LongLived` = secret > 2 years |
| `04_SPN_WildcardReplyUrls.csv` | Wildcard redirect URIs |
| `04_App_SecretsExpiry.csv` | Secrets expiring / expired (<30d) |
| `04_App_LongLived_Secrets.csv` | App-registration secrets valid > 2 years |
| `05_guests.csv` | Guest inventory |

## MFA, inactive users, devices

| File | Description |
|---|---|
| `07_user_registration_details.json` | Full registration report |
| `07_Users_Without_MFA.csv` | `isMfaRegistered=false` on *enabled* accounts (joined with the users export; `AccountEnabled`, `UserType` columns) |
| `07_Users_Without_MFA_Disabled.csv` | Same for disabled accounts — inventory, not a live path |
| `07_Users_PhishingResistant_or_Passkey.csv` | Strictly phishing-resistant methods: passkey / FIDO2 / WHfB / secure-enclave key / CBA |
| `07_Users_AuthenticatorPasswordless.csv` | Authenticator phone sign-in only (strong, not phishing-resistant) |
| `08_Accounts_Inactive_Nd.csv` | Enabled, no interactive, non-interactive or successful sign-in since N days (`LastAny`, `DaysSinceAny`); accounts created in the last 14 days are skipped |
| `06_device_registration_policy.json` | Who can join/register + MFA |
| `09_Devices_Stale_Joined_Nm.csv` | Stale Entra/hybrid joined |
| `09_Devices_Registered_Only.csv` | Workplace / registered only |
| `09_Devices_Per_User.csv` | Device counts per user |
| `09_Devices_Per_User_Multi.csv` | Users with many registered devices |

## Secure Score, vulns, password, SSPR, logs

| File | Description |
|---|---|
| `10_secure_score_*.json` | Raw Secure Score |
| `10_SecureScore_Controls_ByValue.csv` | Controls sorted by max score |
| `10_SecureScore_Top15_HighValue.csv` | Top remediation candidates |
| `10_SecureScore_ByCategory.csv` | In-scope controls by category |
| `10_SecureScore_Category_Rollup.csv` | Category point rollup |
| `11_Defender_Exploitable_Vulns.csv` | TVM hunting (if schema allows) |
| `11_security_alerts_sample.json` | Fallback alerts sample |
| `12_*` | Directory / password settings |
| `12_Federation.csv` | Federated domains: issuer, `federatedIdpMfaBehavior`, signed-request requirement, signing-cert state |
| `13_*` | SSPR registration signals |
| `14_Log_Retention_Notes.csv` | Where logs live by default |

## M365 collaboration & mail

| File | Description |
|---|---|
| `15_*` | SharePoint / cross-tenant access |
| `15_CrossTenant_Trust.csv` | Default + per-partner inbound trust (MFA / compliant / hybrid device claims), B2B direct connect, automatic redemption |
| `16_*` | Teams / group guest settings |
| `17_*` | Anti-spam checklist (+ EmailEvents sample if available) |
| `18_*` | Mailbox forwarding checks / outbound domains |

## Hunting schema

| File | Description |
|---|---|
| `19_Hunting_Schema.json` | Full discovery report + capabilities |
| `19_Hunting_Schema_Tables.csv` | Per-table probe results |

## Sign-in / audit insights

| File | Description |
|---|---|
| `20_DeviceCode_SignIns_*.csv` | Device code events |
| `20_signIns_raw_capanalyzer.json` | Bounded raw Graph signIns for CapAnalyzer Sign-in Replay |
| `20_DeviceCode_Users_*.csv` | Rollup by user |
| `20_DeviceCode_Blocked_*.csv` | Failed device-code (CA effectiveness) |
| `21_LegacyAuth_Success_*.csv` | Legacy client successes |
| `22_FailedSignIns_ByIP_*.csv` | Failure clusters (if hunting identity) |
| `23_SingleFactor_Success_*.csv` | Non-MFA successes (if hunting) |
| `24_RiskyUsers.csv` | Identity Protection at-risk |
| `25_HighValue_CloudAppEvents_*.csv` | Role/consent/app events (if table exists) |
| `26_AdminTooling_SignIns_*.csv` | Azure CLI / Graph CLI / AAD PowerShell |
| `27_SPN_SignIns_*.csv` | Service-principal sign-ins (focus Critical/High SPNs) |

## Endpoints

| File | Description |
|---|---|
| `30_patch_tuesday_reference.json` | Live CU / Patch Tuesday map (Microsoft Learn; fallback if fetch fails) |
| `30_RMM_*.csv` | RMM detections + family prevalence |
| `30_RMM_Dismissed_Artefacts.csv` | Noise dismissed as collaboration viewers (not desktop agents) |
| `31_AI_Agents_*.csv` | AI agent process/software signals |
| `32_*` | OS builds, Win10, behind Patch Tuesday, TVM OS CVEs |
| `33_Intune_UpdateRings*.csv/json` | WUfB / feature / quality profiles |
| `34_GenAI_Usage_*.csv` | GenAI CloudApp / network reach |
| `35_FileShare_Usage_*.csv` | Consumer file-share reach |

## Adaptive intel (`36_`–`39_`) — with or without MDE

Collected by `lib/intel.js` whenever Alert / Exposure Graph / IdentityLogon /
CloudApp tables exist. On tenants without Device* hunting tables these are the
primary hunting-backed artifacts.

| File | Description |
|---|---|
| `36_Security_Alerts_30d.csv` | Defender XDR AlertInfo grouped by severity |
| `36_Security_Alert_Evidence_30d.csv` | AlertEvidence rollup (users / devices) |
| `37_Exposure_Critical_Assets.csv` | Exposure Graph high-crit / high-risk / internet-facing nodes |
| `37_Exposure_Edge_Types.csv` | Edge-label frequency in the exposure graph |
| `37_Exposure_Critical_Paths.csv` | Edges touching Very High/High nodes (neighbours) |
| `38_IdentityInfo_Critical.csv` | IdentityInfo UEBA inventory (crit / risk / roles) |
| `38_IdentityAccountInfo_Privileged.csv` | IdentityAccountInfo roles / MFA / eligible |
| `38_Identity_Failed_Logons_30d.csv` | Failed IdentityLogonEvents by account/app |
| `38_Identity_Logons_ByApp_30d.csv` | Logon volume by application / protocol |
| `38_Identity_Privileged_Logons_30d.csv` | Activity for high-value privileged UPNs |
| `39_CloudApp_Admin_Operations_30d.csv` | Admin-like CloudAppEvents action types |

Related Graph digests (same “no MDE” path, from `lib/logs.js`):

| File | Description |
|---|---|
| `21_LegacyAuth_ByAccount_*.csv` | Legacy auth concentrated per account (e.g. shared SMTP) |
| `24_RiskDetections_90d.csv` | Identity Protection risk detections |
| `27_SPN_SignIns_Digest_*.csv` | Volume rollup for high-priv / top SPNs |
| `28_Privileged_SignIns_30d.csv` | Graph sign-ins for privileged UPNs |
| `01_MFA_Registration_Campaign.csv` | Authenticator registration campaign state |
| `01_Authentication_Strengths.csv` | Auth strength policies catalog |
| `10_IdentitySecureScore_Controls.csv` | AzureAD slice of Microsoft Secure Score |
| `15_Partner_Contracts.csv` | CSP `/contracts` (if permitted) |
| `15_GDAP_Relationships.csv` | Delegated admin / GDAP (often needs GA) |
| `13_Registration_And_Reset_Logs_*.csv` | Registration/SSPR activities from directoryAudits |

## Attack-path pack (`40_*`)

| File | Description |
|---|---|
| `40_AttackPath_Checklist.csv` | Pass / Fail / Partial checks |
| `40_CA_AttackPath_Coverage.csv` | Control × covered × policies |
| `40_CA_Exclusion_Groups.csv` | Exclusion group hardening |
| `40_Privileged_Identity_Hygiene.csv` | Hybrid / MFA / mailbox hints on priv users |
| `40_Privileged_SPN_Credentials.csv` | Privileged SPs + secrets/certs |
| `40_Apps_Path_To_GA.csv` | Apps with GA-path Graph permissions |
| `40_HighPriv_App_Owners.csv` | Owners on GA-path SPs |
| `40_admin_consent_request_policy.json` | Admin consent workflow |
| `40_app_management_policies.json` | App lockdown policies (if readable) |

## Diagnostics

| File | Description |
|---|---|
| `ERROR_<label>.json` | Soft-failed API call (status + message snippet) |
| `00_token_info.json` | Captured token metadata (scopes / app), not full secrets |

CSV delimiter is **semicolon** (`;`) for Excel-friendly EU locales.
