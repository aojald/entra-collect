/**
 * Attack-story narratives added after the first live runs of the scoped
 * checks. Each one joins several artifacts into a single "what an attacker
 * does with this, and what closes it" story, so the report reads as a
 * remediation plan rather than a compliance list.
 *
 * Pure functions over the analyzer context; no Graph, no filesystem.
 */
const {
  classifyAccountKind,
  buildSpnActivityIndex,
  spnIsActive,
  spnIdentityKeys,
} = require("./posture");

const truthy = (v) => /^(true|1|yes)$/i.test(String(v ?? "").trim());
const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);
const names = (rows, key = "SPNDisplayName", n = 6) =>
  [...new Set(rows.map((r) => r[key]).filter(Boolean))].slice(0, n);

/** methodsRegistered values that are phishable telephony / mail factors. */
const WEAK_METHOD_RE = /^(mobilePhone|alternateMobilePhone|officePhone|email|securityQuestion)$/i;
/** Anything that counts as a real second factor beyond the weak set. */
const STRONG_METHOD_RE =
  /^(microsoftAuthenticator.*|softwareOneTimePasscode|softwareOath|hardwareOneTimePasscode|hardwareOath|windowsHelloForBusiness|fido2.*|passKey.*|macOsSecureEnclaveKey|x509Certificate.*|temporaryAccessPass|externalAuthMethod)$/i;

/** Users whose only registered factors are SMS / voice / e-mail. */
function weakOnlyUsers(regDetails) {
  const out = [];
  for (const u of regDetails || []) {
    if (u.isMfaRegistered !== true) continue;
    const methods = (u.methodsRegistered || []).map(String);
    const weak = methods.filter((m) => WEAK_METHOD_RE.test(m));
    const strong = methods.filter((m) => STRONG_METHOD_RE.test(m));
    if (weak.length && !strong.length) out.push(u);
  }
  return out;
}

function checklistStatus(checklist, id) {
  const row = (checklist || []).find(
    (r) => String(r.CheckId || "").toUpperCase() === id.toUpperCase()
  );
  return row ? String(row.Status || "") : "";
}
function checklistEvidence(checklist, id) {
  const row = (checklist || []).find(
    (r) => String(r.CheckId || "").toUpperCase() === id.toUpperCase()
  );
  return row ? String(row.Evidence || "") : "";
}

/**
 * @param {object} ctx analyzer context (loadContext)
 * @param {object[]} narratives array being built
 * @param {(out: object[], n: object) => void} pushNarrative
 */
function runExtraRules(ctx, narratives, pushNarrative) {
  const summary = ctx.summary || {};
  const checklist = ctx.checklist || [];

  // ── NARR.MFA.WeakMethods — SMS / voice / e-mail still valid factors ─────
  {
    const methods = ctx.authMethodsCsv || [];
    const enabled = (id) =>
      methods.some((m) => String(m.Method).toLowerCase() === id && /^enabled$/i.test(m.State || ""));
    const weakEnabled = ["sms", "voice", "email"].filter(enabled);
    if (weakEnabled.length) {
      const weakOnly = weakOnlyUsers(ctx.regDetailsRaw);
      const weakAdmins = weakOnly.filter((u) => u.isAdmin === true);
      const secInfo = checklistStatus(checklist, "AP.CA.SecInfoReg");
      const secInfoOpen = !/^pass$/i.test(secInfo);
      const noMethod = num(summary.usersWithoutMfa);
      const severity =
        weakAdmins.length && secInfoOpen
          ? "Critical"
          : weakOnly.length || (secInfoOpen && noMethod)
            ? "High"
            : "Medium";
      const label = weakEnabled.map((m) => ({ sms: "SMS", voice: "voice call", email: "e-mail OTP" })[m]).join(", ");
      pushNarrative(narratives, {
        id: "NARR.MFA.WeakMethods",
        severity,
        priority: severity === "Medium" ? "Next" : "Now",
        title: weakOnly.length
          ? `${label} still count as MFA — ${weakOnly.length} account(s) rely on them alone${weakAdmins.length ? ` (${weakAdmins.length} admin)` : ""}`
          : `${label} still count as MFA — phishable factors an attacker can enrol`,
        impact:
          "A phishing kit or SIM-swap captures the second factor; if registration is unprotected, a stolen password is enough to enrol the attacker's own number.",
        narrative:
          `The authentication methods policy leaves ${label} enabled as second factors. ` +
          "These are the factors real-time phishing kits and SIM-swap relay without effort, and — more important here — they are what an attacker registers on a victim's account once they hold the password. " +
          (weakOnly.length
            ? `${weakOnly.length} account(s) currently have no factor other than a phone number or mailbox${weakAdmins.length ? `, including ${weakAdmins.length} with a directory role` : ""}. `
            : "No account relies on them exclusively today, but they remain enrollable. ") +
          (secInfoOpen
            ? `Security-info registration is ${/partial/i.test(secInfo) ? "only report-only protected" : "not protected"} by Conditional Access, so the enrolment can happen from anywhere` +
              (noMethod ? ` — and ${noMethod} enabled account(s) have no method at all, i.e. the first MFA prompt they meet becomes the attacker's enrolment.` : ".")
            : "Registration is protected by CA, which limits where an attacker can add a number, but the factor itself stays phishable."),
        evidence:
          `enabled weak methods=${weakEnabled.join(",")}; weakOnlyUsers=${weakOnly.length}; weakOnlyAdmins=${weakAdmins.length}` +
          (weakAdmins.length ? ` [${weakAdmins.map((u) => u.userPrincipalName).slice(0, 5).join(", ")}]` : "") +
          `; usersWithoutAnyMethod=${noMethod}; AP.CA.SecInfoReg=${secInfo || "n/a"} — 01_auth_methods.csv, 07_user_registration_details.json`,
        remediation:
          "1) Authentication methods policy: set SMS and Voice to disabled (or restrict their includeTargets to a time-boxed migration group), keep e-mail OTP for guests only. " +
          "2) Register-security-info CA: require a compliant device or a trusted location (helpdesk hands out a Temporary Access Pass for everything else). " +
          "3) Registration campaign targeting the weak-only population toward Authenticator / passkeys; admins first, with a phishing-resistant authentication strength on their CA. " +
          "4) Watch 13_Registration_And_Reset_Logs for method additions on privileged accounts while the migration runs.",
        relatedFiles: [
          "01_auth_methods.csv",
          "07_user_registration_details.json",
          "07_Users_Without_MFA.csv",
          "40_AttackPath_Checklist.csv",
        ],
        relatedChecks: ["AP.MFA.SMS", "AP.MFA.Voice", "AP.MFA.EmailOTP", "AP.CA.SecInfoReg"],
      });
    }
  }

  // ── NARR.App.MailboxAccess — apps that can read every mailbox ───────────
  {
    const MAIL_PERMS = /^(full_access_as_app|Exchange\.ManageAsApp|Mail\.ReadWrite|Mail\.Read|Mail\.Send|MailboxSettings\.ReadWrite|EWS\.AccessAsApp)$/i;
    const rows = (ctx.dangerous || []).filter((r) => MAIL_PERMS.test(String(r.Permission || "")));
    if (rows.length) {
      const activity = buildSpnActivityIndex(ctx.spnSignIns, ctx.spnSignInDigest);
      const bySp = new Map();
      for (const r of rows) {
        const key = r.PrincipalId || r.SPNDisplayName;
        if (!bySp.has(key)) {
          bySp.set(key, {
            name: r.SPNDisplayName || key,
            ids: spnIdentityKeys(r),
            perms: new Set(),
            resources: new Set(),
          });
        }
        bySp.get(key).perms.add(r.Permission);
        bySp.get(key).resources.add(r.ResourceApp || "");
      }
      const apps = [...bySp.values()].map((a) => ({
        ...a,
        full: [...a.perms].some((p) => /^(full_access_as_app|Exchange\.ManageAsApp)$/i.test(p)),
        active: activity.size ? spnIsActive(a, activity) : null,
      }));
      const fullAccess = apps.filter((a) => a.full);
      const activeFull = fullAccess.filter((a) => a.active === true);
      const dormant = apps.filter((a) => a.active === false);
      pushNarrative(narratives, {
        id: "NARR.App.MailboxAccess",
        severity: activeFull.length ? "Critical" : fullAccess.length ? "High" : "Medium",
        priority: fullAccess.length ? "Now" : "Next",
        title: `${apps.length} application(s) can read or send mail for every mailbox${fullAccess.length ? ` — ${fullAccess.length} with full Exchange access` : ""}`,
        impact:
          "Anyone holding the app's secret reads the CEO inbox — and every other mailbox — with no user sign-in and no MFA.",
        narrative:
          `${apps.length} service principal(s) hold application permissions on mail: ${apps.slice(0, 5).map((a) => `${a.name} [${[...a.perms].join(", ")}]`).join("; ")}${apps.length > 5 ? "; …" : ""}. ` +
          "Application permissions are tenant-wide by default — the app, or anyone holding its secret, reads the CEO's inbox as easily as the test mailbox, with no user sign-in and no MFA. " +
          (fullAccess.length
            ? `${fullAccess.length} of them have ${fullAccess.some((a) => [...a.perms].some((p) => /ManageAsApp/i.test(p))) ? "full_access_as_app / Exchange.ManageAsApp" : "full_access_as_app"}, which is every mailbox plus (for ManageAsApp) Exchange administration itself: mail-flow rules, forwarding, RBAC. `
            : "") +
          (activity.size
            ? `${apps.filter((a) => a.active === true).length} of them authenticated in the sign-in window${dormant.length ? `; ${dormant.length} did not — those are removals, not hardening work` : ""}. `
            : "Service-principal sign-ins were not available to tell active integrations from forgotten ones. ") +
          "Whether each app is limited to the mailboxes it needs (Exchange ApplicationAccessPolicy) cannot be read through Graph and must be checked in Exchange Online PowerShell.",
        evidence: apps
          .slice(0, 10)
          .map(
            (a) =>
              `${a.name}: ${[...a.perms].join(", ")} @ ${[...a.resources].filter(Boolean).join("/")}` +
              (a.active === true ? " (active)" : a.active === false ? " (no sign-in)" : "")
          )
          .join(" | "),
        remediation:
          "Per app: (a) if it never authenticates, delete the assignment; (b) if it needs one or a few mailboxes, run New-ApplicationAccessPolicy -AppId <appId> -PolicyScopeGroupId <mail-enabled group> -AccessRight RestrictAccess, then Test-ApplicationAccessPolicy; (c) replace full_access_as_app / EWS with the narrowest Graph Mail.* application permission the vendor supports; (d) Exchange.ManageAsApp only for genuine Exchange automation, under an Exchange RBAC-for-Applications role, never alongside a client secret. Alert on 'Add app role assignment' for the Exchange Online resource.",
        relatedFiles: ["04_SPN_DangerousPerms.csv", "27_SPN_SignIns_Digest_90d.csv", "04_SPN_Credentials.csv"],
        relatedChecks: ["AP.App.PathToGA"],
      });
    }
  }

  // ── NARR.App.SecretLifecycle — long-lived, expired, unbounded secrets ────
  {
    const spLong = (ctx.spCredentials || []).filter(
      (r) => truthy(r.LongLived) && /secret/i.test(r.CredentialType || "") && !truthy(r.Expired) && !truthy(r.MicrosoftOwned)
    );
    const appLong = ctx.appLongLived || [];
    const expired = (ctx.secretsExpiry || []).filter(
      (r) => /expired/i.test(r.Status || "") || num(r.DaysLeft) < 0
    );
    const soon = (ctx.secretsExpiry || []).filter((r) => {
      const d = Number(r.DaysLeft);
      return Number.isFinite(d) && d >= 0 && d <= 30;
    });
    const appMgmt = checklistStatus(checklist, "AP.App.Management");
    const noPolicy = /fail/i.test(appMgmt);
    const dangerousNames = new Set((ctx.dangerous || []).map((r) => String(r.SPNDisplayName || "").toLowerCase()));
    const longOnDangerous = spLong.filter((r) => dangerousNames.has(String(r.SPNDisplayName || "").toLowerCase()));
    if (spLong.length || appLong.length || expired.length >= 1 || soon.length >= 3) {
      const total = spLong.length + appLong.length;
      pushNarrative(narratives, {
        id: "NARR.App.SecretLifecycle",
        severity: longOnDangerous.length ? "High" : total ? "Medium" : "Low",
        priority: longOnDangerous.length ? "Now" : total ? "Next" : "Later",
        title: total
          ? `${total} client secret(s) valid for more than two years${longOnDangerous.length ? ` — ${longOnDangerous.length} on apps with dangerous permissions` : ""}${noPolicy ? "; nothing caps secret lifetime" : ""}`
          : `${expired.length} expired client secret(s) still attached to applications`,
        impact:
          "A secret leaked in a repo or CI log keeps working for years; on a high-privilege app that is standing tenant-wide access.",
        narrative:
          (total
            ? `${spLong.length} secret(s) on service-principal objects and ${appLong.length} on app registrations were issued for more than 730 days. A leaked long-lived secret (repo, CI log, laptop) works for years and nobody rotates it because nothing forces them to. `
            : "") +
          (longOnDangerous.length
            ? `${longOnDangerous.length} of them belong to apps that already hold directory-, mail- or SharePoint-write permissions (${names(longOnDangerous).join(", ")}) — that is standing tenant-level access behind a string. `
            : "") +
          (expired.length
            ? `${expired.length} secret(s) are expired but still listed${soon.length ? ` and ${soon.length} expire within 30 days` : ""}: either the integration is broken and nobody noticed, or a rotation left the old material behind. `
            : soon.length
              ? `${soon.length} secret(s) expire within 30 days. `
              : "") +
          (noPolicy
            ? "No app management policy is enabled, so new secrets can again be minted for any duration."
            : "An app management policy is enabled; make sure it caps passwordCredentials lifetime and applies to existing apps."),
        evidence:
          [
            ...spLong.slice(0, 6).map((r) => `${r.SPNDisplayName}: secret ${r.LifetimeDays}d (SP object)`),
            ...appLong.slice(0, 4).map((r) => `${r.AppName}: secret ${r.LifetimeDays}d (app registration)`),
            ...expired.slice(0, 4).map((r) => `${r.AppName || r.DisplayName}: expired ${r.DaysLeft}d`),
          ].join(" | ") + ` — AP.App.Management=${appMgmt || "n/a"}`,
        remediation:
          "Enable a tenant app management policy (passwordCredentials maxLifetime ≤ 180 days, keyCredentials ≤ 2 years, block passwordAddition on high-value apps and prefer certificates or federated credentials / managed identities). Rotate every secret older than a year starting with the apps listed as dangerous, remove expired material, and alert on 'Add service principal credentials' / 'Update application – Certificates and secrets management'.",
        relatedFiles: ["04_SPN_Credentials.csv", "04_App_LongLived_Secrets.csv", "04_App_SecretsExpiry.csv", "40_app_management_policies.json"],
        relatedChecks: ["AP.App.Management", "AP.App.PathToGA"],
      });
    }
  }

  // ── NARR.CA.SessionControls — stolen sessions live until token expiry ────
  {
    const st = checklistStatus(checklist, "AP.CA.SessionControls");
    if (/fail|partial/i.test(st)) {
      const evidence = checklistEvidence(checklist, "AP.CA.SessionControls");
      const tokenAlerts = (ctx.securityAlerts || []).filter((a) =>
        /token|session cookie|adversary.in.the.middle|aitm|stolen session|anomalous token|infostealer/i.test(
          `${a.Title || ""} ${a.Category || ""}`
        )
      );
      const hardeningReportOnly = narratives.some((n) => n.Id === "NARR.CA.ReportOnlyHardening");
      pushNarrative(narratives, {
        id: "NARR.CA.SessionControls",
        severity: tokenAlerts.length ? "High" : "Medium",
        priority: tokenAlerts.length ? "Now" : "Next",
        title: /fail/i.test(st)
          ? "A stolen browser session stays valid for weeks — no session controls on population policies"
          : "Session controls only partially applied — stolen sessions outlive the incident",
        impact:
          "Infostealer / AiTM kits reuse the cookie after MFA. Password reset does not kill the session.",
        licence: "P1",
        narrative:
          "Modern account takeover rarely phishes a password: infostealers and adversary-in-the-middle kits take the browser cookie or the refresh token after the user has done MFA. " +
          (/fail/i.test(st)
            ? "No enforced all-users policy sets a sign-in frequency or forbids persistent browser sessions, so such a token keeps working — including for a user whose password has since been reset — until its natural expiry (up to 90 days of refresh). "
            : `Some controls exist but not on the whole population (${evidence}). `) +
          (tokenAlerts.length
            ? `Defender raised ${tokenAlerts.length} alert(s) in the last 30 days that match this pattern (${[...new Set(tokenAlerts.map((a) => a.Title))].slice(0, 3).join("; ")}) — the gap is being exercised, not theoretical. `
            : "") +
          (hardeningReportOnly
            ? "Token Protection / phishing-resistant policies exist only in report-only mode, so the binding that would make a stolen token useless is also not enforced."
            : ""),
        evidence: `AP.CA.SessionControls=${st}: ${evidence}` + (tokenAlerts.length ? `; tokenTheftAlerts30d=${tokenAlerts.length}` : ""),
        remediation:
          "Add session controls to the population MFA policy: sign-in frequency 24 h (12 h or 'every time' for admin roles and unmanaged devices), persistent browser session = never for unmanaged / non-compliant devices, and enable Token Protection (secureSignInSession) for Exchange / SharePoint on Windows clients after the report-only trial. Keep Continuous Access Evaluation in strict mode so revocations propagate in minutes. Pair with 'Revoke sessions' in the compromise playbook.",
        relatedFiles: ["40_AttackPath_Checklist.csv", "02_CA_Audit.csv", "36_Security_Alerts_30d.csv"],
        relatedChecks: ["AP.CA.SessionControls", "AP.CA.AdminPhishingResistant"],
      });
    }
  }

  // ── NARR.External.InboundTrust — guest security = their employer's security ─
  {
    const def = (ctx.crossTenantTrust || []).find((r) => /^default$/i.test(r.Scope || ""));
    if (def && (truthy(def.TrustMfa) || truthy(def.TrustCompliantDevice) || truthy(def.TrustHybridJoined))) {
      const guests = ctx.guests || [];
      const enabledGuests = guests.filter((g) => !/^false$/i.test(String(g.AccountEnabled || "")));
      const partners = (ctx.crossTenantTrust || []).filter((r) => /^partner$/i.test(r.Scope || ""));
      const privilegedGuests = (ctx.privHygiene || []).filter(
        (r) => /guest/i.test(r.UserType || "") || /#EXT#/i.test(r.UPN || "")
      );
      const trusted = [
        truthy(def.TrustMfa) ? "MFA" : "",
        truthy(def.TrustCompliantDevice) ? "compliant device" : "",
        truthy(def.TrustHybridJoined) ? "hybrid-joined device" : "",
      ].filter(Boolean);
      pushNarrative(narratives, {
        id: "NARR.External.InboundTrust",
        severity: privilegedGuests.length ? "High" : "Medium",
        priority: privilegedGuests.length ? "Now" : "Next",
        title: `Every external tenant's ${trusted.join(" / ")} claim is trusted — ${enabledGuests.length} guest(s) are only as safe as their home tenant`,
        impact:
          "A guest from a weak or attacker-created home tenant satisfies your MFA / device grant. You never see their factor.",
        narrative:
          `Cross-tenant access defaults accept ${trusted.join(", ")} claims from any Entra tenant, not just named partners${partners.length ? ` (${partners.length} partner override(s) exist but the default still applies to everyone else)` : ""}. ` +
          `For the ${enabledGuests.length} enabled guest account(s) this means the "require MFA" grant in your Conditional Access is satisfied by whatever their own organisation — or a throw-away tenant an attacker created — calls MFA; you never see or control that factor. ` +
          (privilegedGuests.length
            ? `${privilegedGuests.length} guest account(s) hold directory roles here (${privilegedGuests.map((r) => r.UPN).slice(0, 3).join(", ")}), so a partner-side compromise lands directly on your control plane. `
            : "") +
          "Combined with stale or unaccepted invitations this is the quiet way into SharePoint and Teams data.",
        evidence:
          `default inboundTrust: isMfaAccepted=${def.TrustMfa}, isCompliantDeviceAccepted=${def.TrustCompliantDevice}, isHybridAzureADJoinedDeviceAccepted=${def.TrustHybridJoined}; guests=${guests.length} (${enabledGuests.length} enabled); partnerOverrides=${partners.length}; privilegedGuests=${privilegedGuests.length} — 15_CrossTenant_Trust.csv`,
        remediation:
          "Set the default inbound trust to not accept MFA / device claims, then enable trust per named partner tenant only (Cross-tenant access settings → Organizational settings). Guests from everyone else will then complete MFA in your tenant, which also makes 'Register security info' and the guest MFA policy meaningful. Review guests holding directory roles and move them to PIM-eligible or remove them.",
        relatedFiles: ["15_CrossTenant_Trust.csv", "05_guests.csv", "40_Privileged_Identity_Hygiene.csv"],
        relatedChecks: ["AP.CA.GuestMfa", "AP.Guest.Role"],
      });
    }
  }

  // ── NARR.CA.OrphanReferences — deleted users still in policy scopes ──────
  {
    const refs = ctx.caOrphanRefs || [];
    const orphans = num(summary.caOrphanUserReferences);
    if (refs.length && orphans) {
      const excl = refs.reduce((n, r) => n + num(r.OrphanExcludeUsers), 0);
      const perUser = refs.filter((r) => /per-user/i.test(r.PolicyName || ""));
      const reportOnly = refs.filter((r) => /report/i.test(r.State || ""));
      pushNarrative(narratives, {
        id: "NARR.CA.OrphanReferences",
        severity: excl ? "Medium" : "Low",
        priority: "Later",
        title: `${orphans} deleted account(s) still referenced by ${refs.length} Conditional Access polic${refs.length > 1 ? "ies" : "y"}`,
        impact:
          "Not a live bypass (deleted ids do not come back), but leftover scopes mean the policy set is not being maintained — the next exception is added without review.",
        narrative:
          `Conditional Access still lists ${orphans} user id(s) that no longer exist in the directory. ` +
          (perUser.length
            ? `${perUser.reduce((n, r) => n + num(r.OrphanIncludeUsers), 0)} of them sit in "${perUser[0].PolicyName}"${reportOnly.some((r) => r === perUser[0]) ? " (report-only)" : ""}: the migration from per-user MFA to Conditional Access was started and never finished — the policy meant to replace legacy per-user MFA targets people who have left. `
            : "") +
          (excl
            ? `${excl} orphan(s) are in exclude lists. A deleted object cannot come back with the same id, so this is not a live bypass, but exclusion lists nobody prunes are how the next exception is added without review. `
            : "") +
          "It also says the policy set is not being maintained: scopes written once and left.",
        evidence: refs
          .map((r) => `${r.PolicyName} [${r.State}]: include=${r.OrphanIncludeUsers}, exclude=${r.OrphanExcludeUsers}`)
          .join(" | "),
        remediation:
          "Remove the orphaned ids from each policy scope; where a per-user-MFA migration policy is involved, finish it (enable the policy on the intended group or delete it and disable legacy per-user MFA). Add a quarterly review of CA include/exclude lists to the identity runbook.",
        relatedFiles: ["02_CA_Orphan_References.csv", "02_CA_Audit.csv"],
        relatedChecks: ["AP.CA.ExclGroups"],
      });
    }
  }

  // ── NARR.Devices.LocalAdmin — identity compromise becomes endpoint admin ─
  {
    if (summary.deviceJoinGlobalAdminsLocalAdmin === true) {
      const ga = num(summary.globalAdminPermanent);
      const regAll = /all registering users/i.test(String(summary.deviceJoinRegisteringUsersLocalAdmin || ""));
      const rmm = (ctx.rmmFamily || []).filter((r) => num(r.Hosts || r.Devices || r.Count) > 0);
      const joined = num(summary.devicesEntraJoined);
      const laps = summary.deviceLapsEnabled;
      pushNarrative(narratives, {
        id: "NARR.Devices.LocalAdmin",
        severity: rmm.length || ga >= 3 ? "High" : "Medium",
        priority: "Next",
        title: `Global Administrators are local admins on ${joined || "every"} Entra-joined device${joined === 1 ? "" : "s"}${regAll ? "; so is whoever joins one" : ""}`,
        impact:
          "A stolen GA token or primary refresh token is administrator on the Windows fleet — identity compromise becomes endpoint compromise.",
        narrative:
          `The device registration policy keeps the default that puts the Global Administrator role in the local Administrators group of every Entra-joined Windows device${joined ? ` (${joined} today)` : ""}. ` +
          `That turns any GA compromise — phished token, stolen primary refresh token, malicious app with the role — into administrator on ${joined || "all"} endpoints, and any GA laptop into a lateral-movement hub. ${ga ? `${ga} permanent GA account(s) carry that reach. ` : ""}` +
          (regAll ? "Every user who joins a device also becomes its local administrator, so standard users run as admin on their own machines. " : "") +
          (rmm.length
            ? `Remote-access tooling is already present on the fleet (${rmm.slice(0, 4).map((r) => r.Family || r.Name).join(", ")}), which is exactly what an attacker with local admin uses to stay. `
            : "") +
          (laps === false ? "Windows LAPS is disabled, so local admin passwords are not rotated or escrowed either." : laps === true ? "Windows LAPS is enabled, which limits reuse of local admin passwords but not this role mapping." : ""),
        evidence: `azureADJoin.localAdmins.enableGlobalAdmins=true; registeringUsers=${summary.deviceJoinRegisteringUsersLocalAdmin || "?"}; permanentGA=${ga}; entraJoined=${joined}; laps=${laps}` + (rmm.length ? `; rmmFamilies=${rmm.length}` : ""),
        remediation:
          "Device settings → 'Global administrator role is added as local administrator on the device' = No; 'Registering user is added as local administrator' = None (or a named group). Grant local admin through the Azure AD Joined Device Local Administrator role or Intune Endpoint Privilege Management / LAPS with just-in-time elevation, never through Global Administrator. Then remove standing GA where PIM-eligible suffices.",
        relatedFiles: ["06_device_registration_policy.json", "03_PrivilegedAccounts_HighValue.csv", "30_RMM_Family_Summary.csv"],
        relatedChecks: ["AP.Priv.GaMfa"],
      });
    }
  }
}

/**
 * Stages of a compromise, each with the narrative ids that prove it is open.
 * Order inside a stage = preference for the headline step.
 */
const CHAIN_STAGES = [
  {
    key: "access",
    label: "Initial access",
    ids: [
      "NARR.MFA.WeakMethods",
      "NARR.Legacy.Observed",
      "NARR.Legacy.NoCA",
      "NARR.MFA.MassGap",
      "NARR.Auth.SingleFactor",
      "NARR.DeviceCode.NoCA",
      "NARR.Identity.InactiveNoMfa",
      "NARR.External.InboundTrust",
    ],
  },
  {
    key: "foothold",
    label: "Foothold & persistence",
    ids: ["NARR.CA.SecInfoReg", "NARR.CA.SessionControls", "NARR.CA.ExclGroups", "NARR.App.DelegatedBroadGrants"],
  },
  {
    key: "privilege",
    label: "Privilege escalation",
    ids: [
      "NARR.App.FirstPartyCredential",
      "NARR.App.RoleManagement",
      "NARR.App.PathToGA",
      "NARR.App.CaPolicyWrite",
      "NARR.Priv.HybridGA",
      "NARR.Priv.DormantAdmin",
      "NARR.Priv.StandingGA",
      "NARR.CA.AzureMgmt",
      "NARR.App.SecretLifecycle",
    ],
  },
  {
    key: "impact",
    label: "Data & lateral movement",
    ids: ["NARR.App.MailboxAccess", "NARR.Devices.LocalAdmin", "NARR.Endpoint.RmmSuspicious", "NARR.Mail.SetMailboxBurst", "NARR.Mail.ConsumerOutbound"],
  },
];

/** MassGap only opens a door when it is not compensated. */
function stageQualifies(n) {
  if (!n) return false;
  if (n.Id === "NARR.MFA.MassGap" && /compensated=true/i.test(n.Evidence || "")) return false;
  return !/^info$/i.test(n.Severity || "");
}

function firstSentence(s) {
  const m = String(s || "").match(/^(.{20,220}?[.;])(\s|$)/);
  return m ? m[1] : String(s || "").slice(0, 200);
}

/**
 * Synthesis narrative: the shortest path from outside to tenant control that
 * the other narratives already prove step by step. Emitted only when at least
 * three stages are open, so it never invents a chain.
 */
function buildAttackChain(narratives, pushNarrative) {
  const byId = new Map(narratives.map((n) => [n.Id, n]));
  const stages = CHAIN_STAGES.map((st) => {
    const hits = st.ids.map((id) => byId.get(id)).filter(stageQualifies);
    return { ...st, hits, head: hits[0] || null };
  });
  const open = stages.filter((s) => s.head);
  if (open.length < 3) return null;

  const hasAccess = open.some((s) => s.key === "access");
  const hasPriv = open.some((s) => s.key === "privilege");
  const severity = hasAccess && hasPriv ? "Critical" : "High";
  const steps = open.map((s, i) => `${i + 1}. ${s.label}: ${s.head.Title} (${s.head.Id})`);
  const fixes = open.map((s, i) => `${i + 1}. ${firstSentence(s.head.Remediation)} [${s.head.Id}]`);
  const alsoOpen = open
    .flatMap((s) => s.hits.slice(1))
    .map((n) => n.Id);

  pushNarrative(narratives, {
    id: "NARR.Chain.ShortestPath",
    severity,
    priority: "Now",
    title: `Shortest path to tenant compromise: ${open.length} of 4 stages are open`,
    impact:
      "An attacker can go from outside the tenant to control plane or data without hitting a closed door. Closing any one stage below breaks the chain.",
    narrative:
      "Read this first. Each step is a finding proven elsewhere in this report; together they are the route an attacker would take, in order. " +
      steps.join(" → ") +
      ". Closing the first two stages removes the attacker before privilege is in play." +
      (alsoOpen.length ? ` Other findings that widen the same stages: ${alsoOpen.slice(0, 8).join(", ")}.` : ""),
    evidence: open.map((s) => `${s.label}: ${s.hits.map((n) => n.Id).join(", ")}`).join(" | "),
    remediation: fixes.map((f, i) => `${i + 1}) ${f.replace(/^\d+\.\s*/, "")}`).join(" "),
    relatedFiles: ["00_Expert_Findings.csv", "40_AttackPath_Checklist.csv"],
    relatedChecks: open.map((s) => s.head.Id),
    confidence: "High",
    rationale: "Synthesis of narratives already emitted; no additional data",
  });
  return true;
}

module.exports = {
  runExtraRules,
  buildAttackChain,
  weakOnlyUsers,
  CHAIN_STAGES,
  WEAK_METHOD_RE,
  STRONG_METHOD_RE,
};
