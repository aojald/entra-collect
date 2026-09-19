# False positives & dismissal rules

Lessons from real tenant collections (Advanced Hunting / TVM / process telemetry).

## LogMeIn / GoTo Meeting (not RMM)

**Symptom:** TVM vendor `logmein` + software `live` or `gotomeeting_v9` on Macs → early High “RMM” findings.

**Reality:** LogMeIn rebranded to GoTo. Meeting / Live collaboration apps still appear under vendor `logmein`. They are **not** LogMeIn Rescue / Central / Pro.

**Collector behaviour (`lib/endpoints.js`):**

- RMM family `LogMeIn` matches only Rescue / Central / Pro / GoToAssist / GoToMyPC / Hamachi / Resolve / Ignition.
- `isRmmMeetingFalsePositive()` dismisses `live` / `gotomeeting_*` under vendor logmein.
- Dismissed rows → `30_RMM_Dismissed_Artefacts.csv` (Info finding), **not** High RMM prevalence.

**Extra validation used in investigations:**

- No Rescue/Central process events over 30d.
- No RMM C2 network to logmein/gotoassist.
- Optional: old `LogMeIn Installer` only under personal Google Drive sync paths = archive artefact.

## TeamViewer QuickSupport (iOS)

May be a support app, not a full RMM host. Still surfaces as low-prevalence RMM — review context (owner, process, prevalence) before treating as foothold.

## AI agent noise

Broad patterns (e.g. `copilot`, Edge WebView helpers) can inflate `31_AI_Agents_*`. Prefer family summaries over raw process rows; enterprise Copilot ≠ shadow Claude/Perplexity/LM Studio.

## Guest MFA detection (fixed)

**Bug:** Graph CA policies for guests often use `conditions.users.includeGuestsOrExternalUsers` (object), **not** `includeUsers: ["Guests"]`.

**Effect:** False High “No guest MFA CA” while `[CA20] … Guests … Require MFA` existed.

**Fix:** `lib/attackpath.js` `includesGuestsExplicit()` reads `includeGuestsOrExternalUsers.guestOrExternalUserTypes`.

## Failed export reported as "no policy" (fixed)

**Bug:** when the Conditional Access export returned 403, `40_CA_AttackPath_Coverage.csv` was written *before* the rows were marked unknown, so the analyzer produced High "No CA blocks legacy auth / device code / guest MFA" narratives on a tenant it had never read.

**Fix:** the coverage CSV is written after the not-evaluated pass; `caCovered()` returns unknown whenever `caPoliciesCollected=false`; `AP.Priv.GaMfa` and `AP.App.PathToGA` are `NotEvaluated` when their own input failed. General rule now: a check whose input was not collected is **NotEvaluated**, never Pass or Fail.

## Licence / Security Defaults scored as Fail (fixed)

Sign-in-risk / user-risk CA needs Entra ID P2; a tenant on Security Defaults cannot have CA at all. Both used to Fail High. `lib/tenantFacts.js` reads `subscribedSkus` and the Security Defaults policy; the affected checks are **NotApplicable** with the reason and `LicenceRequired`.

## Number matching (fixed)

Microsoft enforces Authenticator number matching for every push since May 2023; the `numberMatchingRequiredState` setting is ignored by the platform. The check is Info only.

## Policy exists ≠ control covered (fixed)

A legacy-auth block scoped to one pilot group, an MFA policy that excludes Global Administrators, or a report-only device-code policy used to count as coverage. Every CA verdict is now computed on the policy's **effective scope** (`lib/caScope.js`) and is **Partial** with the reason when the policy is enforced but scoped, carved out or report-only. Policy display names are never used for verdicts.

## PIM activation counted as permanent GA (fixed)

`roleAssignments` returns eligible assignments that were *activated* at collection time. `lib/roles.js` prefers `roleAssignmentScheduleInstances` (Assigned vs Activated); activations are listed as `PIM — Active (activated)` and excluded from the standing-GA count. AU- and app-scoped assignments are listed with their scope and excluded too; role-assignable group members are expanded.

## Recency sample reported as "no legacy auth in 90 days" (fixed)

The legacy-auth and failed-sign-in extractions read the 1–2k most recent sign-ins and filtered locally — minutes of logs on a busy tenant. They now filter server-side (`clientAppUsed`, `status/errorCode`) over the full window; a hit page budget is recorded as **Partial**, and when the source is unreadable the count is `null` and narrated as *unknown*.

## Disabled leavers in "users without MFA" (fixed)

The registration report has no `accountEnabled`. Rows are joined with the users export; disabled accounts go to `07_Users_Without_MFA_Disabled.csv` and no longer inflate the gap. Inactivity uses the newest of interactive / non-interactive / last-successful sign-in and skips accounts created in the last 14 days.

## Hardware OATH / Authenticator passwordless as phishing-resistant (fixed)

Neither is phishing-resistant. `07_Users_PhishingResistant_or_Passkey.csv` now holds passkey / FIDO2 / WHfB / secure-enclave / CBA only; Authenticator phone sign-in is reported separately.

## Stale SUMMARY.md

Post-process (dismiss RMM, backfill TVM, re-analyze) can leave `00_SUMMARY.md` Findings out of date. `analyzeOutputDir` now refreshes the Findings + Expert posture section from current CSVs. Prefer `00_Expert_Findings.json` / `00_REPORT.html` as source of truth.

## General rule

Elevate endpoint findings only when **inventory + process/network** (or high prevalence corporate RMM) agree. Vendor string alone is insufficient.
