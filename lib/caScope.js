/**
 * Effective scope of a Conditional Access policy.
 *
 * "A policy exists that blocks legacy auth" is not coverage if it targets one
 * pilot user, one app, or excludes every administrator. Every coverage check
 * therefore reasons over this normalised view instead of the raw Graph object
 * or the policy's display name.
 */

const APP = {
  ALL: "All",
  OFFICE365: "Office365",
  AZURE_MANAGEMENT: "797f4846-ba00-4fd7-ba43-dac1f8f63013",
  MICROSOFT_ADMIN_PORTALS: "MicrosoftAdminPortals",
};

const GA_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10";
const PRA_TEMPLATE = "e8611ab8-c189-46e8-94e1-60213ab1f814";
const PAA_TEMPLATE = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13";

/** Built-in authentication strength ids. */
const AUTH_STRENGTH = {
  MFA: "00000000-0000-0000-0000-000000000002",
  PASSWORDLESS: "00000000-0000-0000-0000-000000000003",
  PHISHING_RESISTANT: "00000000-0000-0000-0000-000000000004",
};

/** allowedCombinations that are phishing-resistant on their own. */
const PHISHING_RESISTANT_COMBOS = new Set([
  "fido2",
  "windowsHelloForBusiness",
  "x509CertificateMultiFactor",
  "x509CertificateSingleFactor",
]);

/** Legacy client app types (CA condition values). */
const LEGACY_CLIENT_TYPES = new Set(["exchangeactivesync", "other"]);

const lower = (x) => String(x == null ? "" : x).toLowerCase();

function list(x) {
  return Array.isArray(x) ? x : x == null ? [] : [x];
}

/**
 * Is a custom / built-in authentication strength phishing-resistant?
 * @param {object} ref grantControls.authenticationStrength
 * @param {object[]} [catalog] authenticationStrengthPolicies (for custom ones)
 */
function strengthIsPhishingResistant(ref, catalog = []) {
  if (!ref) return false;
  if (ref.id === AUTH_STRENGTH.PHISHING_RESISTANT) return true;
  const full =
    (catalog || []).find((s) => s.id === ref.id) ||
    (Array.isArray(ref.allowedCombinations) ? ref : null);
  const combos = list(full && full.allowedCombinations).map(String);
  if (!combos.length) return false;
  return combos.every((c) => PHISHING_RESISTANT_COMBOS.has(c));
}

/**
 * @param {object} p Graph conditionalAccessPolicy
 * @param {object} [opts]
 * @param {Object<string,string>} [opts.roleDefMap] role template id → name
 * @param {object[]} [opts.authStrengths] authenticationStrengthPolicies catalog
 * @param {Object<string,{memberCount?:number,ownerCount?:number,dynamic?:boolean,isAssignableToRole?:boolean,displayName?:string}>} [opts.groupMeta]
 */
function effectiveScope(p, { roleDefMap = {}, authStrengths = [], groupMeta = {} } = {}) {
  const c = (p && p.conditions) || {};
  const u = c.users || {};
  const a = c.applications || {};
  const g = (p && p.grantControls) || {};
  const s = (p && p.sessionControls) || {};

  const includeUsers = list(u.includeUsers).map(String);
  const excludeUsers = list(u.excludeUsers).map(String);
  const includeGroups = list(u.includeGroups).map(String);
  const excludeGroups = list(u.excludeGroups).map(String);
  const includeRoles = list(u.includeRoles).map(String);
  const excludeRoles = list(u.excludeRoles).map(String);

  const allUsers = includeUsers.some((x) => lower(x) === "all");
  const guestsObj = u.includeGuestsOrExternalUsers;
  const includesGuests =
    includeUsers.some((x) => ["guests", "guestsorexternalusers"].includes(lower(x))) ||
    includeRoles.some((x) => lower(x) === "guests") ||
    (guestsObj && typeof guestsObj === "object"
      ? String(guestsObj.guestOrExternalUserTypes || "").trim().length > 0
      : !!guestsObj);
  const excludesGuests =
    excludeUsers.some((x) => ["guests", "guestsorexternalusers"].includes(lower(x))) ||
    !!(u.excludeGuestsOrExternalUsers &&
      String(u.excludeGuestsOrExternalUsers.guestOrExternalUserTypes || "").trim());

  const includeApps = list(a.includeApplications).map(String);
  const excludeApps = list(a.excludeApplications).map(String);
  const userActions = list(a.includeUserActions).map(String);
  const allApps = includeApps.some((x) => lower(x) === "all");
  const office365 = includeApps.some((x) => lower(x) === lower(APP.OFFICE365));

  const controls = list(g.builtInControls).map(lower);
  const strengthRef = g.authenticationStrength || null;
  const phishingResistant = strengthIsPhishingResistant(strengthRef, authStrengths);
  const isBlock = controls.includes("block");
  const requiresMfa = !isBlock && (controls.includes("mfa") || !!strengthRef);

  const roleName = (id) => roleDefMap[id] || roleDefMap[lower(id)] || id;
  const gaLike = (id) => [GA_TEMPLATE, PRA_TEMPLATE, PAA_TEMPLATE].includes(lower(id));
  const excludedGaRoles = excludeRoles.filter(gaLike);

  const excludedGroupMeta = excludeGroups.map((id) => ({ id, ...(groupMeta[id] || {}) }));
  const excludedGroupMembers = excludedGroupMeta.reduce(
    (n, m) => n + (Number.isFinite(Number(m.memberCount)) ? Number(m.memberCount) : 0),
    0
  );
  const excludedMembersKnown = excludedGroupMeta.some((m) => Number.isFinite(Number(m.memberCount)));

  // "Broad" = enough carve-outs that the policy no longer describes the
  // population. Thresholds are deliberately loose: two break-glass users and
  // one hardened exclusion group are normal.
  const broadExclusions =
    excludedGaRoles.length > 0 ||
    excludeRoles.length >= 3 ||
    excludeUsers.length >= 10 ||
    excludeGroups.length >= 3 ||
    (excludedMembersKnown && excludedGroupMembers >= 25);

  const sif = s.signInFrequency || null;
  const pb = s.persistentBrowser || null;
  const session = {
    signInFrequency:
      sif && sif.isEnabled
        ? sif.frequencyInterval === "everyTime"
          ? "everyTime"
          : `${sif.value}${String(sif.type || "").charAt(0)}`
        : "",
    persistentBrowser: pb && pb.isEnabled ? pb.mode || "configured" : "",
    tokenProtection: !!(s.secureSignInSession && s.secureSignInSession.isEnabled),
    cae:
      s.continuousAccessEvaluation && s.continuousAccessEvaluation.mode
        ? s.continuousAccessEvaluation.mode
        : "",
    appEnforced: !!(s.applicationEnforcedRestrictions && s.applicationEnforcedRestrictions.isEnabled),
    cloudAppSecurity: !!(s.cloudAppSecurity && s.cloudAppSecurity.isEnabled),
    disableResilienceDefaults: s.disableResilienceDefaults === true,
  };

  const state = String((p && p.state) || "");
  return {
    id: p && p.id,
    name: (p && p.displayName) || "",
    state,
    enforced: state === "enabled",
    reportOnly: state === "enabledForReportingButNotEnforced",

    allUsers,
    includesGuests,
    excludesGuests,
    includedUsers: includeUsers,
    includedGroups: includeGroups,
    includedRoles: includeRoles,
    includedRoleNames: includeRoles.map(roleName),
    excludedUsers: excludeUsers,
    excludedUserCount: excludeUsers.length,
    excludedGroups: excludeGroups,
    excludedGroupMeta,
    excludedGroupMembers: excludedMembersKnown ? excludedGroupMembers : null,
    excludedRoles: excludeRoles,
    excludedRoleNames: excludeRoles.map(roleName),
    excludedGaRoles: excludedGaRoles.map(roleName),
    broadExclusions,

    allApps,
    office365,
    includedApps: includeApps,
    excludedApps: excludeApps,
    userActions,
    userActionOnly: userActions.length > 0 && !allApps && !office365 && includeApps.length === 0,

    clientAppTypes: list(c.clientAppTypes).map(lower),
    platforms: list(c.platforms && c.platforms.includePlatforms).map(String),
    locations: {
      include: list(c.locations && c.locations.includeLocations).map(String),
      exclude: list(c.locations && c.locations.excludeLocations).map(String),
    },
    signInRisk: list(c.signInRiskLevels).map(lower).filter((x) => x && x !== "none"),
    userRisk: list(c.userRiskLevels).map(lower).filter((x) => x && x !== "none"),
    authFlows: list(
      c.authenticationFlows && String(c.authenticationFlows.transferMethods || "").split(",")
    )
      .map((x) => lower(x).trim())
      .filter(Boolean),

    grants: {
      operator: g.operator || "",
      controls,
      isBlock,
      requiresMfa,
      requiresCompliantDevice:
        controls.includes("compliantdevice") || controls.includes("domainjoineddevice"),
      passwordChange: controls.includes("passwordchange"),
      authStrength: strengthRef
        ? { id: strengthRef.id, displayName: strengthRef.displayName || "" }
        : null,
      phishingResistant,
    },
    session,
  };
}

/** Population-wide: everyone, every app, no broad carve-outs. */
function coversPopulation(s) {
  return s.enforced && s.allUsers && s.allApps && !s.broadExclusions;
}

/** Targets at least one directory role (admin-focused policy) or everyone. */
function targetsAdmins(s, roleDefMap = {}) {
  if (s.allUsers && !s.excludedGaRoles.length) return true;
  return s.includedRoles.length > 0;
}

function targetsGlobalAdmin(s) {
  if (s.allUsers && !s.excludedGaRoles.length) return true;
  return s.includedRoles.some((id) => lower(id) === GA_TEMPLATE);
}

function includesApp(s, appIdOrToken) {
  if (s.allApps) return true;
  const needle = lower(appIdOrToken);
  return s.includedApps.some((x) => lower(x) === needle);
}

function targetsLegacyClients(s) {
  return s.clientAppTypes.some((x) => LEGACY_CLIENT_TYPES.has(x));
}

/**
 * Coverage verdict for a control from the policies that match `pred`:
 *  full    → at least one enforced, population-wide match
 *  partial → matches exist but every one is scoped / carved out / report-only
 *  none    → nothing
 */
function coverageVerdict(scopes, pred, { population = coversPopulation } = {}) {
  const matches = scopes.filter((s) => pred(s));
  const enforced = matches.filter((s) => s.enforced);
  const full = enforced.filter((s) => population(s));
  const reportOnly = matches.filter((s) => s.reportOnly);
  const reasons = [];
  for (const s of enforced.filter((x) => !population(x))) {
    const why = [];
    if (!s.allUsers) why.push("not all users");
    if (!s.allApps && !s.userActions.length) why.push("not all apps");
    if (s.excludedGaRoles.length) why.push(`excludes ${s.excludedGaRoles.join("/")}`);
    else if (s.broadExclusions) why.push("broad exclusions");
    reasons.push(`${s.name} (${why.join(", ") || "scoped"})`);
  }
  return {
    status: full.length ? "full" : enforced.length || reportOnly.length ? "partial" : "none",
    full,
    partial: enforced.filter((x) => !population(x)),
    reportOnly,
    matches,
    reasons,
    names: (full.length ? full : enforced.length ? enforced : reportOnly).map((s) => s.name),
  };
}

/**
 * Population MFA coverage from raw policies — replaces the name-based
 * `detectEnforcedMfaCoverage` when 02_ca_policies_raw.json is available.
 */
function detectMfaCoverageFromPolicies(policies, opts = {}) {
  const scopes = (policies || []).map((p) => effectiveScope(p, opts));
  const isPopMfa = (s) =>
    s.grants.requiresMfa &&
    !s.signInRisk.length &&
    !s.userRisk.length &&
    !s.userActionOnly &&
    (s.allApps || s.office365);
  const v = coverageVerdict(scopes, isPopMfa);
  const scoped = v.partial.filter((s) => !s.allUsers && (s.includedGroups.length || s.includedUsers.length));
  return {
    covered: v.status === "full",
    scoped: scoped.length > 0,
    partial: v.status === "partial",
    broadExclusions: v.status !== "full" && v.partial.some((s) => s.allUsers && s.broadExclusions),
    evidence: v.names.slice(0, 6),
    allUsersEvidence: v.full.map((s) => s.name).slice(0, 6),
    scopedEvidence: scoped.map((s) => s.name).slice(0, 6),
    reasons: v.reasons.slice(0, 6),
    phishingResistantAllUsers: v.full.some((s) => s.grants.phishingResistant),
  };
}

module.exports = {
  APP,
  AUTH_STRENGTH,
  GA_TEMPLATE,
  PRA_TEMPLATE,
  PAA_TEMPLATE,
  PHISHING_RESISTANT_COMBOS,
  effectiveScope,
  coversPopulation,
  coverageVerdict,
  targetsAdmins,
  targetsGlobalAdmin,
  includesApp,
  targetsLegacyClients,
  strengthIsPhishingResistant,
  detectMfaCoverageFromPolicies,
};
