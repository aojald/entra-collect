/**
 * Attack-path checks inspired by Maester / EIDSCA / CISA — focused on
 * real protection gaps and misconfigs threat actors abuse (not compliance ticks).
 */
const { soft, STATUS } = require("./io");
const {
  secInfoPolicyState,
  isFleetDeviceCompliancePolicy,
  GA_EQUIV_DIRECTORY_ROLES,
} = require("./posture");

function push(findings, severity, area, detail) {
  findings.push({ Severity: severity, Area: area, Detail: detail });
}

/** Well-known app / role IDs */
const APP = {
  AZURE_MANAGEMENT: "797f4846-ba00-4fd7-ba43-dac1f8f63013",
  MICROSOFT_ADMIN_PORTALS: "MicrosoftAdminPortals",
  OFFICE365: "Office365",
  ALL: "All",
};

const GUEST_ROLE = {
  // Most permissive (same directory rights as member)
  USER: "a0b1b346-4d3e-4e8b-98f8-753987be4970",
  GUEST: "10dae51f-b6af-4016-8d66-8c2a99b928b2",
  RESTRICTED: "2af84b1e-32c8-42b7-82bc-daa82404023b",
};

const HIGH_PRIV_ROLES = new Set([
  "Global Administrator",
  "Privileged Role Administrator",
  "Privileged Authentication Administrator",
  "Security Administrator",
  "Application Administrator",
  "Cloud Application Administrator",
  "Authentication Administrator",
  "Conditional Access Administrator",
  "User Administrator",
  "Exchange Administrator",
  "SharePoint Administrator",
  "Intune Administrator",
  "Hybrid Identity Administrator",
]);

const GA_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10";

const PRIV_TO_GA_PERMS = new Set([
  "RoleManagement.ReadWrite.Directory",
  "AppRoleAssignment.ReadWrite.All",
  "Application.ReadWrite.All",
  "Directory.ReadWrite.All",
]);

function enforcedPolicies(policies) {
  return (policies || []).filter((p) => p.state === "enabled");
}

function usersCond(p) {
  return (p.conditions && p.conditions.users) || {};
}
function appsCond(p) {
  return (p.conditions && p.conditions.applications) || {};
}
function grant(p) {
  return p.grantControls || {};
}
function builtIn(p) {
  return (grant(p).builtInControls || []).map((x) => String(x).toLowerCase());
}
function clients(p) {
  return ((p.conditions && p.conditions.clientAppTypes) || []).map((x) =>
    String(x).toLowerCase()
  );
}

function includesAllUsers(u) {
  const inc = u.includeUsers || [];
  return inc.some((x) => String(x).toLowerCase() === "all");
}

/**
 * Guests may be targeted via includeUsers tokens OR includeGuestsOrExternalUsers
 * (Graph object with guestOrExternalUserTypes) — CA20-style policies use the latter.
 */
function includesGuestsExplicit(u) {
  const inc = (u.includeUsers || []).map((x) => String(x).toLowerCase());
  const roles = (u.includeRoles || []).map((x) => String(x).toLowerCase());
  if (
    inc.includes("guests") ||
    inc.includes("guestsorexternalusers") ||
    roles.includes("guests")
  ) {
    return true;
  }
  const g = u.includeGuestsOrExternalUsers;
  if (g == null || g === false) return false;
  if (typeof g === "object") {
    const types = String(g.guestOrExternalUserTypes || "").trim();
    return types.length > 0;
  }
  return true;
}

function includesGuestsOrAll(u) {
  return includesAllUsers(u) || includesGuestsExplicit(u);
}

function includesPrivilegedRoles(u) {
  const roles = u.includeRoles || [];
  // Any directory role include, or All users (covers admins)
  return roles.length > 0 || includesAllUsers(u);
}

function appsInclude(p, appIdOrToken) {
  const inc = (appsCond(p).includeApplications || []).map(String);
  const needle = String(appIdOrToken);
  return (
    inc.some((x) => x.toLowerCase() === needle.toLowerCase()) ||
    inc.includes(APP.ALL) ||
    inc.includes("All")
  );
}

function hasUserAction(p, action) {
  const actions = (appsCond(p).includeUserActions || []).map(String);
  return actions.some((a) => a.toLowerCase().includes(String(action).toLowerCase()));
}

function isBlock(p) {
  return builtIn(p).includes("block");
}

function requiresMfa(p) {
  const g = builtIn(p);
  return (
    g.includes("mfa") ||
    !!(grant(p).authenticationStrength) ||
    g.includes("passwordchange")
  );
}

function checklistRow(id, title, status, severity, evidence, why) {
  return {
    CheckId: id,
    Title: title,
    Status: status, // Pass | Fail | Partial | Info | Skip
    Severity: severity,
    Evidence: evidence,
    WhyItMatters: why,
  };
}

/**
 * @param {object} ctx
 * @param {object[]} [ctx.policies]
 * @param {object} [ctx.authz]
 * @param {object} [ctx.authMethods]
 * @param {object[]} [ctx.privRows]
 * @param {object[]} [ctx.roleRows]
 * @param {object[]} [ctx.dangerousSpnRows]
 * @param {object[]} [ctx.regDetails]
 * @param {object} [ctx.roleDefMap]
 * @param {Object<string,boolean>} [ctx.sources] which inputs were really collected
 */
async function collectAttackPathChecks(graph, io, findings, summary, ctx = {}) {
  console.log("── Attack-path checks (consent / CA gaps / weak MFA / priv hygiene)");

  const policies = ctx.policies || [];
  const enforced = enforcedPolicies(policies);
  const authzRaw = ctx.authz;
  const authz = authzRaw && authzRaw.value ? authzRaw.value[0] : authzRaw;
  const authMethods = ctx.authMethods;
  const privRows = ctx.privRows || [];
  const dangerousSpnRows = ctx.dangerousSpnRows || [];
  const regDetails = ctx.regDetails || [];
  const checklist = [];

  const sources = ctx.sources || {};
  /** Absent key = assume collected (older callers); explicit false = failed. */
  const missing = (key) => sources[key] === false;

  /**
   * Neutralise everything produced since the given marks: the checks ran, but
   * on data that was never collected, so a "Fail" here would be an artefact of
   * the outage rather than a tenant weakness.
   */
  function markNotEvaluated(mark, reason) {
    for (let i = mark.checklist; i < checklist.length; i++) {
      const row = checklist[i];
      if (row.Status === "Skip") continue;
      row.Status = "Skip";
      row.Severity = "Info";
      row.Evidence = `Not evaluated — ${reason}`;
    }
    findings.splice(mark.findings, findings.length - mark.findings);
    push(
      findings,
      "High",
      "Coverage",
      `${reason} — the related attack-path checks are inconclusive for this run, not passing. Re-run the collection before drawing conclusions.`
    );
    console.warn(`  ⚠ ${reason} — related checks marked Skip`);
  }

  const mark = () => ({ checklist: checklist.length, findings: findings.length });

  // ── 1) Consent / app registration (consent phishing) ──────────────────
  console.log("  · Consent & app registration");
  const consentMark = mark();
  const dup = (authz && authz.defaultUserRolePermissions) || {};
  const grantPolicies = dup.permissionGrantPoliciesAssigned || [];
  const userConsentLow = grantPolicies.some((p) =>
    /ManagePermissionGrantsForSelf\.microsoft-user-default-low/i.test(p)
  );
  const userConsentLegacy = grantPolicies.some((p) =>
    /ManagePermissionGrantsForSelf\.microsoft-user-default-legacy/i.test(p)
  );
  const userConsentDisabled = !grantPolicies.some((p) =>
    /ManagePermissionGrantsForSelf/i.test(p)
  );
  const usersCanCreateApps = dup.allowedToCreateApps === true;
  const allowRiskyConsent = authz && authz.allowUserConsentForRiskyApps === true;

  if (userConsentLegacy || (userConsentLow && !userConsentDisabled)) {
    checklist.push(
      checklistRow(
        "AP.Consent.User",
        "User OAuth consent should be disabled or tightly limited",
        "Fail",
        "High",
        `permissionGrantPoliciesAssigned=${grantPolicies.join(" | ") || "(none)"}`,
        "Consent phishing: attacker app gets Mail/Files/Directory without stealing a password"
      )
    );
    push(
      findings,
      "High",
      "Consent",
      `User consent enabled (${userConsentLegacy ? "legacy/broad" : "default-low"}) — consent phishing risk. Policies: ${grantPolicies.join(", ") || "n/a"} — 40_AttackPath_Checklist.csv`
    );
  } else {
    checklist.push(
      checklistRow(
        "AP.Consent.User",
        "User OAuth consent should be disabled or tightly limited",
        "Pass",
        "High",
        `permissionGrantPoliciesAssigned=${grantPolicies.join(" | ") || "(none)"}`,
        "Consent phishing"
      )
    );
  }

  if (allowRiskyConsent) {
    checklist.push(
      checklistRow(
        "AP.Consent.Risky",
        "Block user consent for risky apps",
        "Fail",
        "High",
        "allowUserConsentForRiskyApps=true",
        "Allows consent to apps Microsoft flags as risky"
      )
    );
    push(findings, "High", "Consent", "allowUserConsentForRiskyApps=true");
  }

  if (usersCanCreateApps) {
    checklist.push(
      checklistRow(
        "AP.Apps.Create",
        "Non-admins must not register applications",
        "Fail",
        "High",
        "allowedToCreateApps=true",
        "Any user can create an app + redirect URI for phishing / token theft"
      )
    );
    push(
      findings,
      "High",
      "AppRegistration",
      "Users can register applications (allowedToCreateApps=true)"
    );
  } else {
    checklist.push(
      checklistRow(
        "AP.Apps.Create",
        "Non-admins must not register applications",
        "Pass",
        "High",
        "allowedToCreateApps=false",
        "App registration phishing"
      )
    );
  }

  // Guest directory role
  const guestRole = authz && authz.guestUserRoleId;
  if (guestRole === GUEST_ROLE.USER) {
    checklist.push(
      checklistRow(
        "AP.Guest.Role",
        "Guest users should not have member-equivalent directory access",
        "Fail",
        "High",
        `guestUserRoleId=${guestRole} (User)`,
        "Guests can enumerate users/groups/apps like members"
      )
    );
    push(findings, "High", "Guests", "Guest role = User (member-equivalent) — overly permissive");
  } else if (guestRole === GUEST_ROLE.GUEST) {
    checklist.push(
      checklistRow(
        "AP.Guest.Role",
        "Guest users should not have member-equivalent directory access",
        "Partial",
        "Medium",
        `guestUserRoleId=${guestRole} (Guest)`,
        "Prefer Restricted Guest for least privilege"
      )
    );
  } else if (guestRole === GUEST_ROLE.RESTRICTED) {
    checklist.push(
      checklistRow(
        "AP.Guest.Role",
        "Guest users should not have member-equivalent directory access",
        "Pass",
        "Medium",
        `guestUserRoleId=${guestRole} (Restricted)`,
        "Guest enumeration"
      )
    );
  }

  // Admin consent workflow
  const adminConsent = await soft(
    "adminConsentRequestPolicy",
    () => graph.get(`${graph.GRAPH}/policies/adminConsentRequestPolicy`),
    io
  );
  if (adminConsent) {
    io.saveJson("40_admin_consent_request_policy.json", adminConsent);
    if (adminConsent.isEnabled !== true) {
      checklist.push(
        checklistRow(
          "AP.Consent.AdminWorkflow",
          "Admin consent request workflow should be enabled",
          "Fail",
          "Medium",
          "isEnabled=false",
          "Without workflow, users have no safe path → shadow IT / informal admin consent"
        )
      );
      push(
        findings,
        "Medium",
        "Consent",
        "Admin consent request workflow disabled — 40_admin_consent_request_policy.json"
      );
    } else {
      checklist.push(
        checklistRow(
          "AP.Consent.AdminWorkflow",
          "Admin consent request workflow should be enabled",
          "Pass",
          "Medium",
          "isEnabled=true",
          "Consent governance"
        )
      );
    }
  }

  // Group owner consent for apps (directory settings / permission grant)
  const groupOwnerConsent = grantPolicies.some((p) =>
    /ManagePermissionGrantsForOwnedResource/i.test(p)
  );
  if (groupOwnerConsent) {
    // Owned resource consent for chat/team is common; flag only if self.legacy or broad
    const broadOwned = grantPolicies.some((p) =>
      /ManagePermissionGrantsForOwnedResource\.microsoft-user-default/i.test(p)
    );
    if (broadOwned) {
      push(
        findings,
        "Medium",
        "Consent",
        "Group/resource owner consent policies assigned — review 01_authorization_policy.json"
      );
    }
  }

  if (missing("authz")) {
    markNotEvaluated(consentMark, "Authorization policy could not be collected");
  }

  // ── 2) Auth methods: SMS/Voice + Authenticator hardening ──────────────
  console.log("  · Weak MFA / Authenticator settings");
  const authMethodsMark = mark();
  const methodConfigs =
    (authMethods && authMethods.authenticationMethodConfigurations) || [];
  const byId = Object.fromEntries(methodConfigs.map((c) => [c.id, c]));

  const sms = byId.Sms;
  const voice = byId.Voice;
  const email = byId.Email;
  const tap = byId.TemporaryAccessPass;
  const msAuth = byId.MicrosoftAuthenticator;

  if (sms && sms.state === "enabled") {
    const usable =
      (sms.includeTargets || []).some((t) => t.isUsableForSignIn !== false);
    checklist.push(
      checklistRow(
        "AP.MFA.SMS",
        "SMS must not be usable for MFA/sign-in",
        "Fail",
        "High",
        `Sms state=enabled; usableForSignIn≈${usable}`,
        "SIM swap / SS7 / phishing OTP interception"
      )
    );
    push(
      findings,
      "High",
      "WeakMFA",
      "SMS authentication method enabled (SIM-swap / OTP phishing) — disable or restrict — 01_auth_methods.csv"
    );
  } else {
    checklist.push(
      checklistRow(
        "AP.MFA.SMS",
        "SMS must not be usable for MFA/sign-in",
        "Pass",
        "High",
        `Sms=${sms ? sms.state : "n/a"}`,
        "SIM swap"
      )
    );
  }

  if (voice && voice.state === "enabled") {
    checklist.push(
      checklistRow(
        "AP.MFA.Voice",
        "Voice call MFA should be disabled",
        "Fail",
        "High",
        "Voice state=enabled",
        "Phone-based MFA bypass / social engineering"
      )
    );
    push(findings, "High", "WeakMFA", "Voice call MFA enabled — 01_auth_methods.csv");
  }

  if (email && email.state === "enabled") {
    checklist.push(
      checklistRow(
        "AP.MFA.EmailOTP",
        "Email OTP should be disabled for MFA",
        "Fail",
        "Medium",
        "Email state=enabled",
        "Mailbox compromise → MFA bypass"
      )
    );
    push(findings, "Medium", "WeakMFA", "Email OTP authentication method enabled");
  }

  if (tap && tap.state === "enabled") {
    const once = tap.isUsableOnce === true;
    const maxMin = tap.maximumLifetimeInMinutes || 0;
    if (!once || maxMin > 480) {
      checklist.push(
        checklistRow(
          "AP.MFA.TAP",
          "Temporary Access Pass should be one-time and short-lived",
          "Fail",
          "Medium",
          `TAP enabled; isUsableOnce=${tap.isUsableOnce}; maxMinutes=${maxMin}`,
          "Long-lived TAP = standing password equivalent"
        )
      );
      push(
        findings,
        "Medium",
        "WeakMFA",
        `Temporary Access Pass enabled (once=${tap.isUsableOnce}, maxMin=${maxMin}) — tighten`
      );
    } else {
      checklist.push(
        checklistRow(
          "AP.MFA.TAP",
          "Temporary Access Pass should be one-time and short-lived",
          "Pass",
          "Medium",
          `once=${once}; maxMinutes=${maxMin}`,
          "TAP abuse"
        )
      );
    }
  }

  if (msAuth && msAuth.state === "enabled") {
    const fs = msAuth.featureSettings || {};
    const numMatch = fs.numberMatchingRequiredState && fs.numberMatchingRequiredState.state;
    const showApp = fs.displayAppInformationRequiredState && fs.displayAppInformationRequiredState.state;
    const showLoc = fs.displayLocationInformationRequiredState && fs.displayLocationInformationRequiredState.state;
    // "enabled" = enforced; "default" often means tenant default (usually on for number matching in modern tenants)
    // Flag only when explicitly disabled
    if (numMatch === "disabled") {
      checklist.push(
        checklistRow(
          "AP.MFA.NumberMatch",
          "Authenticator number matching must be enforced",
          "Fail",
          "High",
          "numberMatchingRequiredState=disabled",
          "MFA fatigue / push bombing succeeds without number matching"
        )
      );
      push(findings, "High", "WeakMFA", "Authenticator number matching explicitly disabled");
    } else {
      checklist.push(
        checklistRow(
          "AP.MFA.NumberMatch",
          "Authenticator number matching must be enforced",
          numMatch === "enabled" ? "Pass" : "Partial",
          "High",
          `numberMatchingRequiredState=${numMatch || "not set (check portal)"}`,
          "MFA fatigue"
        )
      );
      if (!numMatch) {
        push(
          findings,
          "Info",
          "WeakMFA",
          "Authenticator numberMatchingRequiredState not present in policy JSON — confirm number matching in Entra portal"
        );
      }
    }
    if (showApp === "disabled" || showLoc === "disabled") {
      push(
        findings,
        "Medium",
        "WeakMFA",
        `Authenticator context prompts weakened (app=${showApp || "n/a"}, location=${showLoc || "n/a"})`
      );
    }
  }

  if (missing("authMethods")) {
    markNotEvaluated(
      authMethodsMark,
      "Authentication method policies could not be collected"
    );
  }

  // ── 3) CA attack-path coverage ─────────────────────────────────────────
  console.log("  · Conditional Access attack-path coverage");
  const caMark = mark();
  const caCoverage = [];

  function matchPolicies(pred) {
    return enforced.filter(pred);
  }

  // Device code / auth transfer
  const deviceCodePols = matchPolicies((p) => {
    const flows =
      p.conditions &&
      p.conditions.authenticationFlows &&
      p.conditions.authenticationFlows.transferMethods;
    return !!flows;
  });
  caCoverage.push({
    Control: "Block or MFA device code / auth transfer",
    Covered: deviceCodePols.length > 0,
    Policies: deviceCodePols.map((p) => p.displayName).join(" | "),
    Severity: "High",
    Why: "Device code phishing / Graph CLI abuse (AitM-adjacent)",
  });
  // Already reported in main CA section if missing

  // Legacy auth block
  const legacyBlock = matchPolicies((p) => {
    const c = clients(p);
    const targetsLegacy =
      c.includes("exchangeactivesync") ||
      c.includes("other") ||
      (c.includes("exchangeActiveSync".toLowerCase()) && true);
    // Also: include only legacy client types
    const legacyOnly =
      c.length > 0 &&
      c.every((x) =>
        ["exchangeactivesync", "other", "imap", "pop", "authenticatedsmtp"].includes(x)
      );
    return (targetsLegacy || legacyOnly) && isBlock(p);
  });
  // Broader: policy that includes exchangeActiveSync/other among clientAppTypes and blocks
  const legacyBlockBroad = matchPolicies((p) => {
    const c = clients(p);
    return (
      (c.includes("exchangeactivesync") || c.includes("other")) &&
      isBlock(p)
    );
  });
  const legacyOk = legacyBlock.length + legacyBlockBroad.length > 0;
  caCoverage.push({
    Control: "Block legacy authentication (EAS / Other clients)",
    Covered: legacyOk,
    Policies: [...legacyBlock, ...legacyBlockBroad]
      .map((p) => p.displayName)
      .filter((v, i, a) => a.indexOf(v) === i)
      .join(" | "),
    Severity: "High",
    Why: "Password spray / basic auth bypasses modern MFA",
  });
  if (!legacyOk) {
    checklist.push(
      checklistRow(
        "AP.CA.LegacyBlock",
        "CA must block legacy authentication",
        "Fail",
        "High",
        "No enforced CA with clientAppTypes legacy + grant block",
        "Password spray without MFA"
      )
    );
    push(
      findings,
      "High",
      "CA",
      "No enforced CA policy blocks legacy auth (Exchange ActiveSync / Other clients) — spray/basic-auth path open"
    );
  } else {
    checklist.push(
      checklistRow(
        "AP.CA.LegacyBlock",
        "CA must block legacy authentication",
        "Pass",
        "High",
        caCoverage[caCoverage.length - 1].Policies,
        "Password spray"
      )
    );
  }

  // Azure management MFA
  const azureMgmt = matchPolicies(
    (p) =>
      appsInclude(p, APP.AZURE_MANAGEMENT) &&
      requiresMfa(p) &&
      includesPrivilegedRoles(usersCond(p))
  );
  const adminPortals = matchPolicies(
    (p) =>
      appsInclude(p, APP.MICROSOFT_ADMIN_PORTALS) &&
      requiresMfa(p)
  );
  const azureCovered = azureMgmt.length > 0 || adminPortals.length > 0;
  caCoverage.push({
    Control: "MFA for Azure management / Admin portals",
    Covered: azureCovered,
    Policies: [...azureMgmt, ...adminPortals]
      .map((p) => p.displayName)
      .filter((v, i, a) => a.indexOf(v) === i)
      .join(" | "),
    Severity: "High",
    Why: "Stolen password/session → Azure + often Entra control plane",
  });
  if (!azureCovered) {
    checklist.push(
      checklistRow(
        "AP.CA.AzureMgmt",
        "CA must require MFA for Azure management / admin portals",
        "Fail",
        "High",
        "No match on Azure Management app or MicrosoftAdminPortals + MFA",
        "Cloud control-plane takeover"
      )
    );
    push(
      findings,
      "High",
      "CA",
      "No clear enforced MFA CA for Azure Management (797f4846-…) / Admin Portals"
    );
  } else if (azureMgmt.length === 0 && adminPortals.length > 0) {
    checklist.push(
      checklistRow(
        "AP.CA.AzureMgmt",
        "CA must require MFA for Azure management / admin portals",
        "Partial",
        "High",
        `Admin portals only: ${adminPortals.map((p) => p.displayName).join(" | ")} — Azure Service Management API app may still be uncovered`,
        "ARM/CLI may not be covered by Admin Portals alone"
      )
    );
    push(
      findings,
      "Medium",
      "CA",
      "MFA covers Microsoft Admin Portals but not explicitly Azure Management API (797f4846-…) — verify CLI/PowerShell/ARM"
    );
  } else {
    checklist.push(
      checklistRow(
        "AP.CA.AzureMgmt",
        "CA must require MFA for Azure management / admin portals",
        "Pass",
        "High",
        caCoverage[caCoverage.length - 1].Policies,
        "Azure control plane"
      )
    );
  }

  // Sign-in risk / user risk
  const signInRisk = matchPolicies(
    (p) =>
      ((p.conditions && p.conditions.signInRiskLevels) || []).length > 0 &&
      (requiresMfa(p) || isBlock(p))
  );
  const userRisk = matchPolicies(
    (p) =>
      ((p.conditions && p.conditions.userRiskLevels) || []).length > 0 &&
      (requiresMfa(p) || isBlock(p) || builtIn(p).includes("passwordchange"))
  );
  caCoverage.push({
    Control: "Sign-in risk → MFA or block",
    Covered: signInRisk.length > 0,
    Policies: signInRisk.map((p) => p.displayName).join(" | "),
    Severity: "High",
    Why: "Stops impossible travel / unfamiliar token use mid-attack",
  });
  caCoverage.push({
    Control: "User risk high → block or password change",
    Covered: userRisk.length > 0,
    Policies: userRisk.map((p) => p.displayName).join(" | "),
    Severity: "High",
    Why: "Identity Protection at-risk users keep accessing if no user-risk CA",
  });
  if (!signInRisk.length) {
    push(findings, "High", "CA", "No enforced CA for sign-in risk (MFA/block)");
    checklist.push(
      checklistRow(
        "AP.CA.SignInRisk",
        "CA for sign-in risk",
        "Fail",
        "High",
        "none",
        "Risky sign-ins"
      )
    );
  } else {
    checklist.push(
      checklistRow(
        "AP.CA.SignInRisk",
        "CA for sign-in risk",
        "Pass",
        "High",
        signInRisk.map((p) => p.displayName).join(" | "),
        "Risky sign-ins"
      )
    );
  }
  if (!userRisk.length) {
    push(
      findings,
      "High",
      "CA",
      "No enforced CA for user risk (block / force password change) — at-risk users can keep signing in"
    );
    checklist.push(
      checklistRow(
        "AP.CA.UserRisk",
        "CA for user risk",
        "Fail",
        "High",
        "none",
        "Compromised accounts stay active"
      )
    );
  } else {
    checklist.push(
      checklistRow(
        "AP.CA.UserRisk",
        "CA for user risk",
        "Pass",
        "High",
        userRisk.map((p) => p.displayName).join(" | "),
        "Compromised accounts"
      )
    );
  }

  // MFA for guests
  const guestMfa = matchPolicies(
    (p) => includesGuestsOrAll(usersCond(p)) && requiresMfa(p) && appsInclude(p, APP.ALL)
  );
  // Precise: guests/external via includeGuestsOrExternalUsers (or includeUsers guests token)
  // Prefer All-cloud-apps (or guest-named) MFA — skip enrollment-only side policies.
  const guestMfaStrict = matchPolicies((p) => {
    const u = usersCond(p);
    if (!includesGuestsExplicit(u) || !requiresMfa(p)) return false;
    if (appsInclude(p, APP.ALL)) return true;
    return /\[?\s*guests?\s*\]?/i.test(p.displayName || "");
  });
  const guestCovered = guestMfaStrict.length > 0 || guestMfa.length > 0;
  caCoverage.push({
    Control: "MFA for guest / external users",
    Covered: guestMfaStrict.length > 0,
    Policies: (guestMfaStrict.length ? guestMfaStrict : guestMfa)
      .map((p) => p.displayName)
      .join(" | "),
    Severity: "High",
    Why: "Invited guest with password-only access to SPO/Teams",
  });
  if (!guestMfaStrict.length) {
    checklist.push(
      checklistRow(
        "AP.CA.GuestMfa",
        "CA must require MFA for guests",
        guestCovered ? "Partial" : "Fail",
        "High",
        guestCovered
          ? "Only covered via All users MFA (verify guests not excluded)"
          : "No guest-targeted MFA CA",
        "Guest foothold after invite"
      )
    );
    push(
      findings,
      guestCovered ? "Medium" : "High",
      "CA",
      guestCovered
        ? "No guest-specific MFA CA — relying on All-users policies (verify guest exclusions)"
        : "No enforced MFA CA targeting guests/external users"
    );
  } else {
    checklist.push(
      checklistRow(
        "AP.CA.GuestMfa",
        "CA must require MFA for guests",
        "Pass",
        "High",
        guestMfaStrict.map((p) => p.displayName).join(" | "),
        "Guest foothold"
      )
    );
  }

  // Security info registration — report-only is Partial, not "no policy".
  const secInfoState = secInfoPolicyState(policies);
  caCoverage.push({
    Control: "Protect security-info registration (trusted location / compliant)",
    Covered: secInfoState.status === "Pass",
    Policies: secInfoState.match.map((p) => p.displayName).join(" | "),
    Severity: "High",
    Why: "Attacker registers MFA method after password spray / helpdesk social engineering",
  });
  if (secInfoState.status === "Fail") {
    checklist.push(
      checklistRow(
        "AP.CA.SecInfoReg",
        "CA must protect Register security info",
        "Fail",
        "High",
        "No policy with includeUserActions registersecurityinfo",
        "MFA method takeover"
      )
    );
    push(
      findings,
      "High",
      "CA",
      "No CA protecting 'Register security info' — MFA methods can be added from anywhere"
    );
  } else if (secInfoState.status === "Partial") {
    checklist.push(
      checklistRow(
        "AP.CA.SecInfoReg",
        "CA must protect Register security info",
        "Partial",
        "High",
        `Report-only only: ${secInfoState.reportOnly.map((p) => p.displayName).join(" | ")}`,
        "MFA takeover — policy exists but does not block"
      )
    );
    push(
      findings,
      "Medium",
      "CA",
      `Register security info CA is report-only (not enforced): ${secInfoState.reportOnly.map((p) => p.displayName).join(" | ")} — MFA methods can still be added from anywhere until it is On`
    );
  } else {
    checklist.push(
      checklistRow(
        "AP.CA.SecInfoReg",
        "CA must protect Register security info",
        "Pass",
        "High",
        secInfoState.enforced.map((p) => p.displayName).join(" | "),
        "MFA takeover"
      )
    );
  }

  // OR grant MFA|compliant
  const orBypass = enforced.filter((p) => {
    const g = builtIn(p);
    return (
      grant(p).operator === "OR" &&
      g.includes("mfa") &&
      (g.includes("compliantdevice") || g.includes("domainjoineddevice"))
    );
  });
  if (orBypass.length) {
    checklist.push(
      checklistRow(
        "AP.CA.GrantOR",
        "Device compliance + MFA must use AND not OR",
        "Fail",
        "High",
        orBypass.map((p) => p.displayName).join(" | "),
        "MFA alone bypasses device compliance requirement"
      )
    );
    push(
      findings,
      "High",
      "CA",
      `${orBypass.length} enforced CA use OR(mfa, compliant/domainJoined) — MFA bypasses device control: ${orBypass.map((p) => p.displayName).join(" | ")}`
    );
  } else {
    checklist.push(
      checklistRow(
        "AP.CA.GrantOR",
        "Device compliance + MFA must use AND not OR",
        "Pass",
        "High",
        "No enforced OR(mfa, device) grants",
        "Device bypass"
      )
    );
  }

  // Report-only device compliance that gates *cloud apps* (not SecInfo / enrollment).
  const reportOnlyDevice = policies.filter(
    (p) =>
      p.state === "enabledForReportingButNotEnforced" &&
      isFleetDeviceCompliancePolicy(p)
  );
  if (reportOnlyDevice.length) {
    push(
      findings,
      "High",
      "CA",
      `${reportOnlyDevice.length} device-compliance CA still report-only — unmanaged devices not blocked: ${reportOnlyDevice.map((p) => p.displayName).join(" | ")}`
    );
  }

  io.saveCsv("40_CA_AttackPath_Coverage.csv", caCoverage);

  // CA exclusion groups — role-assignable / RMAU
  console.log("  · CA exclusion group hardening");
  const excludeGroupIds = new Set();
  for (const p of enforced) {
    for (const g of usersCond(p).excludeGroups || []) {
      if (g && g !== "All") excludeGroupIds.add(g);
    }
  }
  const exclGroupRows = [];
  for (const gid of excludeGroupIds) {
    const g = await soft(
      `caExcludeGroup_${gid}`,
      () =>
        graph.get(
          `${graph.GRAPH}/groups/${gid}?$select=id,displayName,isAssignableToRole,securityEnabled,membershipRule,groupTypes,visibility`
        ),
      io
    );
    if (!g) continue;
    const protected_ = g.isAssignableToRole === true;
    exclGroupRows.push({
      GroupId: g.id,
      DisplayName: g.displayName,
      IsAssignableToRole: g.isAssignableToRole,
      SecurityEnabled: g.securityEnabled,
      Dynamic: !!(g.membershipRule || (g.groupTypes || []).includes("DynamicMembership")),
      Hardened: protected_,
      Risk: protected_
        ? "OK — role-assignable (harder to join)"
        : "Weak — any User Admin can add members → CA bypass",
    });
  }
  io.saveCsv("40_CA_Exclusion_Groups.csv", exclGroupRows);

  // One finding for the whole set. Emitting one per group buried every other
  // High finding under twenty identical lines saying the same thing.
  const weakExclGroups = exclGroupRows.filter((r) => !r.Hardened);
  if (weakExclGroups.length) {
    const names = weakExclGroups.map((r) => r.DisplayName);
    const shown = names.slice(0, 5).map((n) => `"${n}"`).join(", ");
    push(
      findings,
      "High",
      "CA",
      `${weakExclGroups.length}/${exclGroupRows.length} CA exclusion groups are not role-assignable — ` +
        "any User Administrator can add members and bypass Conditional Access: " +
        shown +
        (names.length > 5 ? ` and ${names.length - 5} more` : "") +
        " — 40_CA_Exclusion_Groups.csv"
    );
  }
  if (excludeGroupIds.size === 0) {
    checklist.push(
      checklistRow(
        "AP.CA.ExclGroups",
        "CA exclusion groups should be role-assignable",
        "Info",
        "High",
        "No excludeGroups on enforced policies",
        "CA bypass via group membership"
      )
    );
  } else {
    const weak = exclGroupRows.filter((r) => !r.Hardened).length;
    checklist.push(
      checklistRow(
        "AP.CA.ExclGroups",
        "CA exclusion groups should be role-assignable",
        weak ? "Fail" : "Pass",
        "High",
        `${weak}/${exclGroupRows.length} exclusion groups not role-assignable`,
        "CA bypass via group membership"
      )
    );
  }

  if (missing("caPolicies")) {
    markNotEvaluated(caMark, "Conditional Access policies could not be collected");
    for (const row of caCoverage) {
      row.Covered = "unknown";
      row.Evidence = "Not evaluated — CA policies could not be collected";
    }
  }

  // ── 4) Privileged identity hygiene ────────────────────────────────────
  console.log("  · Privileged identity hygiene");
  const privMark = mark();
  const privHygiene = [];

  // Enrich privileged users with sync + mail
  const userPriv = privRows.filter(
    (r) => (r.PrincipalType || "").toLowerCase() === "user"
  );
  const uniqueUserIds = [...new Set(userPriv.map((r) => r.PrincipalId).filter(Boolean))];

  for (const uid of uniqueUserIds.slice(0, 80)) {
    const u = await soft(
      `privUser_${uid}`,
      () =>
        graph.get(
          `${graph.GRAPH}/users/${uid}?$select=id,displayName,userPrincipalName,accountEnabled,onPremisesSyncEnabled,onPremisesUserPrincipalName,mail,otherMails,userType,createdDateTime`
        ),
      io
    );
    if (!u) continue;
    const roles = userPriv
      .filter((r) => r.PrincipalId === uid)
      .map((r) => r.RoleName);
    const isGa = roles.includes("Global Administrator");
    const synced = u.onPremisesSyncEnabled === true;
    const hasMail = !!(u.mail || (u.otherMails && u.otherMails.length));
    const reg = regDetails.find(
      (x) => x.id === uid || x.userPrincipalName === u.userPrincipalName
    );
    const mfa = reg ? reg.isMfaRegistered : null;

    privHygiene.push({
      DisplayName: u.displayName,
      UPN: u.userPrincipalName,
      Roles: roles.join(" | "),
      IsGlobalAdmin: isGa,
      OnPremSynced: synced,
      HasMailboxHint: hasMail,
      Mail: u.mail || "",
      MfaRegistered: mfa,
      AccountEnabled: u.accountEnabled,
      UserType: u.userType,
    });

    // Disabled privileged accounts stay in the hygiene CSV for inventory only —
    // do not raise High/Medium live-path alerts for them.
    if (u.accountEnabled === false) {
      if (isGa || roles.some((r) => HIGH_PRIV_ROLES.has(r))) {
        push(
          findings,
          "Info",
          "Privileged",
          `Disabled privileged account ${u.userPrincipalName} roles=[${roles.join(", ")}] — inventory only; not an active path`
        );
      }
      continue;
    }

    if (synced && (isGa || roles.some((r) => HIGH_PRIV_ROLES.has(r)))) {
      push(
        findings,
        isGa ? "High" : "Medium",
        "Privileged",
        `Synced (hybrid) privileged account ${u.userPrincipalName} roles=[${roles.join(", ")}] — on-prem compromise → cloud`
      );
    }
    if (isGa && hasMail) {
      // Info/Medium — almost all GAs have mail; flag cloud-only break-glass without mail as good signal later
    }
    if (isGa && mfa === false) {
      push(
        findings,
        "High",
        "Privileged",
        `Global Admin ${u.userPrincipalName} has no MFA registered — break-glass or backdoor`
      );
    }
  }
  io.saveCsv("40_Privileged_Identity_Hygiene.csv", privHygiene);

  const hybridGa = privHygiene.filter(
    (r) => r.IsGlobalAdmin && r.OnPremSynced && r.AccountEnabled !== false
  );
  const hybridGaDisabled = privHygiene.filter(
    (r) => r.IsGlobalAdmin && r.OnPremSynced && r.AccountEnabled === false
  );
  const gaNoMfa = privHygiene.filter(
    (r) =>
      r.IsGlobalAdmin &&
      r.AccountEnabled !== false &&
      r.MfaRegistered === false
  );
  checklist.push(
    checklistRow(
      "AP.Priv.HybridGA",
      "Global Admins should be cloud-only (not synced)",
      hybridGa.length ? "Fail" : "Pass",
      "High",
      hybridGa.length
        ? hybridGa.map((r) => r.UPN).join(" | ") +
          (hybridGaDisabled.length
            ? ` (disabled, not alerted: ${hybridGaDisabled.map((r) => r.UPN).join(" | ")})`
            : "")
        : hybridGaDisabled.length
          ? `No enabled hybrid GAs (disabled retained: ${hybridGaDisabled.map((r) => r.UPN).join(" | ")})`
          : "No synced GAs in sampled set",
      "AD DS compromise → Entra GA"
    )
  );
  checklist.push(
    checklistRow(
      "AP.Priv.GaMfa",
      "Every Global Admin must have MFA registered",
      gaNoMfa.length ? "Fail" : "Pass",
      "High",
      gaNoMfa.length ? gaNoMfa.map((r) => r.UPN).join(" | ") : "All sampled GAs have MFA",
      "Password-only GA"
    )
  );

  // Break-glass heuristic: permanent GA, excluded from many CA, no MFA — or named *break*/*emergency*
  const bgNamed = privHygiene.filter(
    (r) =>
      r.IsGlobalAdmin &&
      r.AccountEnabled !== false &&
      /break|emergency|bg-|breakglass|break-glass/i.test(
        `${r.DisplayName} ${r.UPN}`
      )
  );
  if (bgNamed.length) {
    for (const b of bgNamed) {
      if (b.MfaRegistered === false) {
        push(
          findings,
          "High",
          "BreakGlass",
          `Likely break-glass ${b.UPN} has no MFA — if CA-excluded, this is a standing backdoor`
        );
      } else {
        push(
          findings,
          "Info",
          "BreakGlass",
          `Likely break-glass account ${b.UPN} (MFA=${b.MfaRegistered}) — verify CA exclusions + monitoring`
        );
      }
    }
  }

  // SPN with privileged directory role + client secrets
  console.log("  · Privileged apps / GA paths");
  const spPriv = privRows.filter((r) =>
    /serviceprincipal|service principal/i.test(r.PrincipalType || "")
  );
  const spSecretPriv = [];
  for (const row of spPriv.slice(0, 40)) {
    const sp = await soft(
      `privSp_${row.PrincipalId}`,
      () =>
        graph.get(
          `${graph.GRAPH}/servicePrincipals/${row.PrincipalId}?$select=id,appId,displayName,passwordCredentials,keyCredentials,servicePrincipalType,accountEnabled`
        ),
      io
    );
    if (!sp) continue;
    let secrets = (sp.passwordCredentials || []).length;
    let keys = (sp.keyCredentials || []).length;
    let credSource = "servicePrincipal";
    if (secrets === 0 && keys === 0 && sp.appId) {
      const apps = await soft(
        `privAppCreds_${sp.appId}`,
        () =>
          graph.getAll(
            `${graph.GRAPH}/applications?$filter=appId eq '${sp.appId}'&$select=id,appId,displayName,passwordCredentials,keyCredentials`
          ),
        io
      );
      const app = Array.isArray(apps) ? apps[0] : null;
      if (app) {
        secrets = (app.passwordCredentials || []).length;
        keys = (app.keyCredentials || []).length;
        credSource = "application";
      }
    }
    spSecretPriv.push({
      DisplayName: sp.displayName,
      AppId: sp.appId,
      Role: row.RoleName,
      ClientSecrets: secrets,
      Certificates: keys,
      CredSource: credSource,
      Risk:
        secrets > 0
          ? "High — client secret + privileged role (secret leak = standing admin)"
          : keys > 0
            ? "Review — cert-based privileged SP"
            : "Info — no creds listed on SP or app registration",
    });
    if (secrets > 0) {
      push(
        findings,
        "High",
        "Privileged",
        `Service principal "${sp.displayName}" has ${secrets} client secret(s) + role ${row.RoleName}`
      );
    }
  }
  io.saveCsv("40_Privileged_SPN_Credentials.csv", spSecretPriv);

  // Apps with GA-path Graph permissions + SPs holding GA-equivalent Entra roles
  const gaPath = dangerousSpnRows.filter((r) => PRIV_TO_GA_PERMS.has(r.Permission));
  const gaRoleSps = (privRows || []).filter(
    (r) =>
      /serviceprincipal|service principal/i.test(r.PrincipalType || "") &&
      GA_EQUIV_DIRECTORY_ROLES.test(r.RoleName || "")
  );
  io.saveCsv(
    "40_Apps_Path_To_GA.csv",
    [
      ...gaPath.map((r) => ({
        ...r,
        AttackNote:
          r.Permission === "RoleManagement.ReadWrite.Directory"
            ? "Can assign Global Admin to any principal"
            : r.Permission === "AppRoleAssignment.ReadWrite.All"
              ? "Can escalate via app role grants"
              : "Broad directory/app write — often convertible to GA",
      })),
      ...gaRoleSps.map((r) => ({
        SPNDisplayName: r.PrincipalName,
        PrincipalId: r.PrincipalId,
        PrincipalType: r.PrincipalType,
        Permission: r.RoleName,
        Severity: "Critical",
        ResourceApp: "Entra directory role",
        AttackNote: `${r.RoleName} on a service principal is equivalent to a Graph GA path`,
      })),
    ]
  );
  if (gaPath.length || gaRoleSps.length) {
    const uniq = [
      ...new Set([
        ...gaPath.map((r) => r.SPNDisplayName),
        ...gaRoleSps.map((r) => r.PrincipalName),
      ]),
    ].filter(Boolean);
    const roleBit = gaRoleSps.length
      ? `; directory roles on SPs: ${[...new Set(gaRoleSps.map((r) => `${r.PrincipalName} [${r.RoleName}]`))].join(" | ")}`
      : "";
    checklist.push(
      checklistRow(
        "AP.App.PathToGA",
        "No non-MS apps with direct path to Global Admin privileges",
        "Fail",
        "High",
        `${gaPath.length} Graph assignments / ${uniq.length} apps${roleBit}`,
        "App credential theft → GA"
      )
    );
    push(
      findings,
      "High",
      "AppPrivEsc",
      `${uniq.length} apps with GA-path Graph permissions or GA-equivalent directory roles (${[...PRIV_TO_GA_PERMS].join(", ")}; Privileged Role / Privileged Authentication / Global Administrator on SPs) — 40_Apps_Path_To_GA.csv`
    );
  } else {
    checklist.push(
      checklistRow(
        "AP.App.PathToGA",
        "No non-MS apps with direct path to Global Admin privileges",
        "Pass",
        "High",
        "No RoleManagement/AppRoleAssignment/Application.ReadWrite.All/Directory.ReadWrite.All on SPNs",
        "App → GA"
      )
    );
  }

  // App owners on high-priv apps (sample)
  const ownerRisk = [];
  for (const name of [...new Set(gaPath.map((r) => r.PrincipalId))].slice(0, 25)) {
    const owners = await soft(
      `appOwners_${name}`,
      () => graph.getAll(`${graph.GRAPH}/servicePrincipals/${name}/owners`),
      io
    );
    if (!owners || !owners.length) continue;
    for (const o of owners) {
      ownerRisk.push({
        SpPrincipalId: name,
        OwnerName: o.displayName,
        OwnerUPN: o.userPrincipalName || o.appId || o.id,
        OwnerType: ((o["@odata.type"] || "").split(".").pop() || "").replace(/^#/, ""),
      });
    }
  }
  if (ownerRisk.length) {
    io.saveCsv("40_HighPriv_App_Owners.csv", ownerRisk);
    push(
      findings,
      "Medium",
      "AppPrivEsc",
      `${ownerRisk.length} owner links on GA-path service principals — owners can often add credentials — 40_HighPriv_App_Owners.csv`
    );
  }

  // Directory sync accounts in CA
  const syncAccounts = privRows.filter(
    (r) => r.RoleName === "Directory Synchronization Accounts"
  );
  if (syncAccounts.length) {
    checklist.push(
      checklistRow(
        "AP.CA.DirSync",
        "Directory sync accounts should be excluded from blocking CA (or dedicated)",
        "Info",
        "Medium",
        syncAccounts.map((r) => r.UPNOrAppId || r.PrincipalName).join(" | "),
        "Mis-scoped CA can break sync OR leave sync account unprotected"
      )
    );
    push(
      findings,
      "Info",
      "Hybrid",
      `${syncAccounts.length} Directory Synchronization Accounts — verify CA exclusions (MT.1020) and credential hygiene — 03_PrivilegedAccounts_HighValue.csv`
    );
  }

  // App management / lockdown (best-effort)
  const appMgmt = await soft(
    "appManagementPolicy",
    () =>
      graph.getAll(
        `${graph.GRAPH_BETA}/policies/appManagementPolicies`
      ),
    io
  );
  if (appMgmt) {
    io.saveJson("40_app_management_policies.json", appMgmt);
    const enabled = (appMgmt || []).filter((p) => p.isEnabled);
    if (!enabled.length) {
      push(
        findings,
        "Medium",
        "AppLockdown",
        "No enabled app management policies — consider restricting secret/cert lifetimes & identifier URIs (MT.1002)"
      );
      checklist.push(
        checklistRow(
          "AP.App.Management",
          "App management restrictions should be enabled",
          "Fail",
          "Medium",
          "No enabled appManagementPolicies",
          "Unrestricted app secrets / URIs"
        )
      );
    } else {
      checklist.push(
        checklistRow(
          "AP.App.Management",
          "App management restrictions should be enabled",
          "Pass",
          "Medium",
          `${enabled.length} enabled policies`,
          "App secret abuse"
        )
      );
    }
  }

  if (missing("privRoles")) {
    markNotEvaluated(privMark, "Role assignments could not be collected");
  }

  io.saveCsv("40_AttackPath_Checklist.csv", checklist);

  const failHigh = checklist.filter(
    (c) => c.Status === "Fail" && c.Severity === "High"
  ).length;
  const skipped = checklist.filter((c) => c.Status === "Skip").length;
  summary.attackPathChecks = checklist.length;
  summary.attackPathHighFails = failHigh;
  summary.attackPathSkipped = skipped;
  summary.attackPathCollected = true;
  summary.attackPathMissingSources = Object.entries(sources)
    .filter(([, ok]) => ok === false)
    .map(([k]) => k);

  push(
    findings,
    failHigh ? "High" : "Info",
    "AttackPath",
    `${checklist.length} attack-path checks; ${failHigh} High failures` +
      (skipped ? `; ${skipped} not evaluated (source unavailable)` : "") +
      " — see 40_AttackPath_Checklist.csv + 40_CA_AttackPath_Coverage.csv"
  );

  return { checklist, caCoverage };
}

module.exports = {
  collectAttackPathChecks,
  APP,
  GUEST_ROLE,
  PRIV_TO_GA_PERMS,
  GA_ROLE_ID,
  includesGuestsExplicit,
  includesGuestsOrAll,
  requiresMfa,
};
