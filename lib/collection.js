/**
 * Full Entra / security collection (read-only) using portal Graph token pool.
 */
const fs = require("fs");
const path = require("path");
const { createIo, readManifest, soft, STATUS } = require("./io");
const { createCache } = require("./cache");
const { createGraph } = require("./graph");
const { createResolver } = require("./resolve");
const { collectM365CollabAndMail } = require("./m365");
const { collectSignInAndAuditInsights } = require("./logs");
const { collectEndpointHunts } = require("./endpoints");
const { collectAdaptiveIntel } = require("./intel");
const { discoverHuntingSchema } = require("./schema");
const { collectAttackPathChecks } = require("./attackpath");
const { attachPortalHunt, portalHuntReady } = require("./hunt");
const { writeReport } = require("../report");
const { collectCapAnalyzerOfflinePack } = require("./capanalyzer");
const { isCopilotOrAgentUpn } = require("./posture");
const { parseCsv } = require("./csv");
const { collectTenantFacts } = require("./tenantFacts");
const { ERROR_KIND } = require("./io");
const {
  fetchRoleDefinitions,
  collectRoleAssignments,
  highValueRows,
  summarizeRoles,
} = require("./roles");
const { collectAppSurface } = require("./apps");

const PHISHING_RESISTANT = new Set([
  "passKeyDeviceBoundAuthenticator",
  "passKeyDeviceBound",
  "passKeyDeviceUnbound",
  "passkey",
  "fido2",
  "windowsHelloForBusiness",
  "hardwareOath",
  "microsoftAuthenticatorPush", // not phishing-resistant alone — exclude
]);

// Methods considered phishing-resistant in Entra registration report
const PHISHING_RESISTANT_METHODS = [
  "passKeyDeviceBoundAuthenticator",
  "passKeyDeviceUnboundAuthenticator",
  "windowsHelloForBusiness",
  "fido2",
  "hardwareOath",
];

function daysAgo(n) {
  return Date.now() - n * 86400000;
}

function monthsAgo(n) {
  const d = new Date();
  d.setMonth(d.getMonth() - n);
  return d.getTime();
}

function parseDate(v) {
  if (!v) return null;
  const t = Date.parse(v);
  return Number.isNaN(t) ? null : t;
}

/** Classify Entra device into PC / Smartphone / Tablet / Other for inventory stats. */
function classifyDeviceForm(d) {
  const os = String(d.operatingSystem || "").toLowerCase();
  const model = String(d.model || "").toLowerCase();
  const name = String(d.displayName || "").toLowerCase();
  const blob = `${os} ${model} ${name}`;
  if (
    /ipad|ipados|tablet|sm-t\d|lenovo tb|galaxy tab|surface go/i.test(blob)
  ) {
    return "Tablet";
  }
  if (
    os === "iphone" ||
    os === "android" ||
    os === "androidforwork" ||
    os === "androidenterprise" ||
    /iphone|windowsmobile|windowsphone|pixel\s?\d|galaxy s\d|galaxy a\d/i.test(
      blob
    )
  ) {
    if (/android/i.test(os) && /tab|pad|sm-t/i.test(blob)) return "Tablet";
    return "Smartphone";
  }
  if (
    /windows|mac|macos|macmdm|linux|chromeos|ubuntu|debian/i.test(os) ||
    /macbook|imac|surface (pro|laptop|book)|thinkpad|latitude|xps/i.test(blob)
  ) {
    return "PC";
  }
  return "Other";
}

async function runCollection(pool, outDir, opts = {}) {
  const inactiveDays = opts.inactiveDays ?? 90;
  const deviceStaleMonths = opts.deviceStaleMonths ?? 3;
  const signInDays = opts.signInDays ?? [30, 90];
  const rmmLegitThreshold = opts.rmmLegitThreshold ?? 0.7;
  const capAnalyzerOffline = opts.capAnalyzerOffline !== false;
  const capAnalyzerMaxMemberships =
    opts.capAnalyzerMaxMemberships === undefined
      ? null
      : opts.capAnalyzerMaxMemberships;
  const capAnalyzerSignInPages = opts.capAnalyzerSignInPages ?? 3;
  const previousManifest = opts.resume ? readManifest(outDir) : null;
  if (opts.resume) {
    // The folder already holds one tenant's data; refuse to merge another into it.
    const lockedTid = String(
      opts.expectedTenantId || (pool.tenantId && pool.tenantId()) || ""
    ).toLowerCase();
    const prevTid = readPreviousTenantId(outDir);
    if (lockedTid && prevTid && prevTid !== lockedTid) {
      throw new Error(
        `--resume refused: ${path.basename(outDir)} was collected from tenant ${prevTid} ` +
          `but the current session is tenant ${lockedTid}. Start a new output folder.`
      );
    }
  }
  const io = createIo(outDir, { previousManifest });
  const cache = createCache(outDir, { read: !!opts.resume, write: opts.cache !== false });
  const graph = createGraph(pool, { cache });
  if (opts.resume) {
    const failed = previousManifest
      ? Object.entries(previousManifest.steps || {}).filter(
          ([, s]) => s.status === STATUS.FAILED
        ).length
      : 0;
    console.log(
      `▶ Resume mode — replaying into ${path.basename(outDir)}; ` +
        `${failed} previously failed step(s) will be retried, the rest served from cache.`
    );
  }
  const findings = [];
  const summary = {
    collectedAt: new Date().toISOString(),
    inactiveDays,
    deviceStaleMonths,
    signInDays,
    rmmLegitThreshold,
  };

  console.log("\n▶ Collecting Entra + Security data...\n");
  console.log(
    `  inactiveDays=${inactiveDays} deviceStaleMonths=${deviceStaleMonths}\n`
  );

  // Portal Advanced Hunting (apiproxy) — Security Reader path via browser page
  if (opts.portalPage) {
    const lockedForHunt =
      opts.expectedTenantId || (pool.tenantId && pool.tenantId()) || null;
    await soft(
      "portal_hunt_attach",
      () => attachPortalHunt(opts.portalPage, lockedForHunt),
      io
    );
    summary.huntingPortalReady = portalHuntReady();
  } else {
    summary.huntingPortalReady = false;
  }

  // ── Discover hunting / log schema first (adapt later checks) ───────────
  const schema = await discoverHuntingSchema(graph, io, findings);
  summary.huntingCanHunt = schema.canHunt;
  summary.huntingApiStatus = schema.huntApiStatus;
  summary.huntingIdentitySource = schema.identitySource;
  summary.huntingAvailableTables = schema.availableTables;
  summary.huntingCapabilities = schema.capabilities;
  summary.graphSignInsAvailable = !!(
    schema.graphSignIns && schema.graphSignIns.available
  );

  if (opts.intelOnly) {
    mergePreviousCollection(outDir, summary, findings);
    console.log("── Adaptive intel only (--intel-only) — Graph inventory skipped\n");
    await collectAdaptiveIntel(graph, io, findings, summary, {
      schema,
      privilegedAccounts: [],
    });
  } else {

  // ── Role definitions (needed for CA + privileged) ─────────────────────
  const { roleDefMap, roleDefById } = await fetchRoleDefinitions(graph, io);
  const resolver = createResolver(graph, roleDefMap);

  // ── Tenant / auth policy ──────────────────────────────────────────────
  console.log("── Tenant / auth policy");
  const org = await soft(
    "organization",
    () => graph.getAll(`${graph.GRAPH}/organization`),
    io
  );
  if (org) {
    io.saveJson("01_organization.json", org);
    const orgObj = Array.isArray(org) ? org[0] : org;
    const orgTid = orgObj && orgObj.id ? String(orgObj.id).toLowerCase() : null;
    const lockedTid = pool.tenantId && pool.tenantId();
    if (orgTid) {
      summary.tenantId = orgTid;
      summary.tenantDisplayName = orgObj.displayName || null;
    }
    if (lockedTid && orgTid && lockedTid !== orgTid) {
      throw new Error(
        `Tenant mismatch mid-collection: token pool locked to ${lockedTid} but /organization is ${orgTid}` +
          `${orgObj.displayName ? ` (${orgObj.displayName})` : ""}. Aborting to avoid mixed-tenant artifacts.`
      );
    }
  }

  const secDefaults = await soft(
    "securityDefaults",
    () =>
      graph.get(
        `${graph.GRAPH}/policies/identitySecurityDefaultsEnforcementPolicy`
      ),
    io
  );
  if (secDefaults) {
    io.saveJson("01_security_defaults.json", secDefaults);
    summary.securityDefaultsEnabled = secDefaults.isEnabled;
    if (secDefaults.isEnabled === false) {
      findings.push({
        Severity: "Info",
        Area: "SecurityDefaults",
        Detail: "OFF — CA must cover MFA / legacy auth",
      });
    }
  }

  const authz = await soft(
    "authorizationPolicy",
    () => graph.get(`${graph.GRAPH}/policies/authorizationPolicy`),
    io
  );
  let authzPol = null;
  if (authz) {
    io.saveJson("01_authorization_policy.json", authz);
    const pol = authz.value ? authz.value[0] : authz;
    authzPol = pol;
    const dup = pol.defaultUserRolePermissions || {};
    summary.allowInvitesFrom = pol.allowInvitesFrom;
    summary.guestUserRoleId = pol.guestUserRoleId;
    summary.allowedToUseSSPR = pol.allowedToUseSSPR;
    summary.usersCanCreateApps = dup.allowedToCreateApps;
    summary.usersCanCreateTenants = dup.allowedToCreateTenants;
    if (dup.allowedToCreateTenants === true) {
      findings.push({
        Severity: "Medium",
        Area: "Tenants",
        Detail: "Users can create tenants",
      });
    }
    if (pol.allowInvitesFrom === "everyone") {
      findings.push({
        Severity: "Medium",
        Area: "Guests",
        Detail: "Guest invites allowed from everyone",
      });
    }
  }

  const authMethods = await soft(
    "authMethodsPolicy",
    () => graph.get(`${graph.GRAPH}/policies/authenticationMethodsPolicy`),
    io
  );
  if (authMethods) {
    io.saveJson("01_auth_methods_policy.json", authMethods);
    io.saveCsv(
      "01_auth_methods.csv",
      (authMethods.authenticationMethodConfigurations || []).map((c) => ({
        Method: c.id,
        State: c.state,
      }))
    );
    // MFA registration campaign (Authenticator nudge) — often left on "default".
    const camp =
      (authMethods.registrationEnforcement &&
        authMethods.registrationEnforcement
          .authenticationMethodsRegistrationCampaign) ||
      null;
    if (camp) {
      const targets = camp.includeTargets || [];
      io.saveCsv(
        "01_MFA_Registration_Campaign.csv",
        [
          {
            State: camp.state || "",
            SnoozeDays: camp.snoozeDurationInDays ?? "",
            IncludeTargets: targets
              .map(
                (t) =>
                  `${t.id || t.targetType || "?"}:${t.targetedAuthenticationMethod || ""}`
              )
              .join(" | "),
            ExcludeTargets: (camp.excludeTargets || [])
              .map((t) => t.id || t.targetType || "?")
              .join(" | "),
          },
        ]
      );
      summary.mfaRegistrationCampaignState = camp.state || "";
      summary.mfaRegistrationCampaignSnoozeDays = camp.snoozeDurationInDays;
      findings.push({
        Severity: camp.state === "enabled" ? "Info" : "Medium",
        Area: "MfaCampaign",
        Detail: `MFA registration campaign state=${camp.state || "?"} snoozeDays=${camp.snoozeDurationInDays ?? "?"} targets=${targets.length} — 01_MFA_Registration_Campaign.csv`,
      });
    }
  }

  // Licences / Security Defaults / auth-method migration state — decide which
  // checks are NotApplicable rather than Fail on this tenant.
  const facts = await collectTenantFacts(graph, io, {
    securityDefaults: secDefaults,
    authMethods,
  });
  summary.tenantFacts = {
    securityDefaultsEnabled: facts.securityDefaultsEnabled,
    policyMigrationState: facts.policyMigrationState,
    licencesCollected: facts.licencesCollected,
    p1: facts.licences ? facts.licences.p1 : null,
    p2: facts.licences ? facts.licences.p2 : null,
    governance: facts.licences ? facts.licences.governance : null,
  };
  if (facts.licences && !facts.licences.p1) {
    findings.push({
      Severity: "Info",
      Area: "Licensing",
      Detail:
        "No Entra ID P1/P2 service plan detected — Conditional Access and sign-in activity checks are scored NotApplicable, not Fail (01_Licences.csv)",
    });
  } else if (facts.licences && !facts.licences.p2) {
    findings.push({
      Severity: "Info",
      Area: "Licensing",
      Detail:
        "No Entra ID P2 service plan detected — Identity Protection / PIM checks are scored NotApplicable, not Fail (01_Licences.csv)",
    });
  }

  // Authentication strengths catalog (built-in + custom).
  const authStrengths = await soft(
    "authenticationStrengthPolicies",
    () =>
      graph.getAll(`${graph.GRAPH}/policies/authenticationStrengthPolicies`),
    io
  );
  if (authStrengths) {
    io.saveJson("01_authentication_strengths.json", authStrengths);
    io.saveCsv(
      "01_Authentication_Strengths.csv",
      authStrengths.map((s) => ({
        Id: s.id,
        DisplayName: s.displayName,
        PolicyType: s.policyType || "",
        RequirementsSatisfied: s.requirementsSatisfied || "",
        AllowedCombinations: Array.isArray(s.allowedCombinations)
          ? s.allowedCombinations.join(" | ")
          : s.allowedCombinations || "",
        Description: (s.description || "").slice(0, 200),
      }))
    );
    summary.authStrengthCount = authStrengths.length;
    summary.authStrengthCustom = authStrengths.filter(
      (s) => /custom/i.test(String(s.policyType || ""))
    ).length;
  }

  // ── Named locations (before CA for name map) ──────────────────────────
  console.log("── Named locations");
  const namedLocs = await soft(
    "namedLocations",
    () =>
      graph.getAll(`${graph.GRAPH}/identity/conditionalAccess/namedLocations`),
    io
  );
  const locMap = {};
  if (namedLocs) {
    io.saveJson("02_named_locations.json", namedLocs);
    for (const l of namedLocs) {
      locMap[l.id] = l.displayName;
    }
    resolver.setLocationMap(locMap);
    io.saveCsv(
      "02_NamedLocations.csv",
      namedLocs.map((l) => ({
        Id: l.id,
        Name: l.displayName,
        Type: (l["@odata.type"] || "").split(".").pop(),
        IsTrusted: l.isTrusted,
        IpRanges: ((l.ipRanges || []).map((x) => x.cidrAddress) || []).join(", "),
        Countries: (l.countriesAndRegions || []).join(", "),
      }))
    );
    summary.namedLocationsCount = namedLocs.length;
  } else {
    // Leave undefined ("n/a") rather than 0 — 0 would read as "none defined".
    summary.namedLocationsCollected = false;
  }

  // ── Conditional Access (with name resolution) ─────────────────────────
  console.log("── Conditional Access (resolving object names…)");
  const policies = await soft(
    "caPolicies",
    () => graph.getAll(`${graph.GRAPH}/identity/conditionalAccess/policies`),
    io
  );
  if (policies) {
    // Pure Graph array (IDs only) — also CAPAnalyzer-compatible
    io.saveJson("02_ca_policies_raw.json", policies);

    const annotated = [];
    const rows = [];
    for (const p of policies) {
      const u = (p.conditions && p.conditions.users) || {};
      const a = (p.conditions && p.conditions.applications) || {};
      const loc = (p.conditions && p.conditions.locations) || {};
      const grant = (p.grantControls && p.grantControls.builtInControls) || [];
      const clients = (p.conditions && p.conditions.clientAppTypes) || [];
      const authFlows =
        p.conditions &&
        p.conditions.authenticationFlows &&
        p.conditions.authenticationFlows.transferMethods;

      const isEnforced = p.state === "enabled";
      const isReportOnly = p.state === "enabledForReportingButNotEnforced";
      const riskFlags = [];
      if (isReportOnly) riskFlags.push("NOT ENFORCED (report-only)");
      if (
        p.grantControls &&
        p.grantControls.operator === "OR" &&
        grant.includes("compliantDevice") &&
        grant.includes("mfa")
      ) {
        riskFlags.push("OR grant: MFA alone can bypass compliant device");
      }

      const includeLocations = loc.includeLocations || [];
      const excludeLocations = loc.excludeLocations || [];

      const resolved = {
        includeUsers: await resolver.resolveList(u.includeUsers || []),
        excludeUsers: await resolver.resolveList(u.excludeUsers || []),
        includeGroups: await resolver.resolveList(u.includeGroups || []),
        excludeGroups: await resolver.resolveList(u.excludeGroups || []),
        includeRoles: await resolver.resolveList(u.includeRoles || []),
        excludeRoles: await resolver.resolveList(u.excludeRoles || []),
        includeApplications: await resolver.resolveList(
          a.includeApplications || []
        ),
        excludeApplications: await resolver.resolveList(
          a.excludeApplications || []
        ),
        includeLocations: await resolver.resolveList(includeLocations),
        excludeLocations: await resolver.resolveList(excludeLocations),
      };

      // Deep clone policy; keep all Graph ID fields intact for CAPAnalyzer.
      // Human names live only under `_resolved` (ignored by CAPAnalyzer normalizePolicy).
      const clone = JSON.parse(JSON.stringify(p));
      clone._resolved = resolved;
      annotated.push(clone);

      rows.push({
        PolicyName: p.displayName,
        State: p.state,
        IsEnforced: isEnforced ? "Yes" : isReportOnly ? "Report-only" : "Disabled",
        GrantControls: grant.join(", "),
        GrantOperator: (p.grantControls && p.grantControls.operator) || "",
        AuthStrength:
          (p.grantControls &&
            p.grantControls.authenticationStrength &&
            p.grantControls.authenticationStrength.displayName) ||
          "",
        IncludeUsers: resolved.includeUsers.join(" | "),
        IncludeUsersRaw: (u.includeUsers || []).join(", "),
        ExcludeUsers: resolved.excludeUsers.join(" | "),
        ExcludeUsersRaw: (u.excludeUsers || []).join(", "),
        IncludeGroups: resolved.includeGroups.join(" | "),
        IncludeGroupsRaw: (u.includeGroups || []).join(", "),
        ExcludeGroups: resolved.excludeGroups.join(" | "),
        ExcludeGroupsRaw: (u.excludeGroups || []).join(", "),
        IncludeRoles: resolved.includeRoles.join(" | "),
        IncludeRolesRaw: (u.includeRoles || []).join(", "),
        ExcludeRoles: resolved.excludeRoles.join(" | "),
        ExcludeRolesRaw: (u.excludeRoles || []).join(", "),
        IncludeApps: resolved.includeApplications.join(" | "),
        IncludeAppsRaw: (a.includeApplications || []).join(", "),
        ExcludeApps: resolved.excludeApplications.join(" | "),
        ExcludeAppsRaw: (a.excludeApplications || []).join(", "),
        IncludeLocations: resolved.includeLocations.join(" | "),
        IncludeLocationsRaw: includeLocations.join(", "),
        ExcludeLocations: resolved.excludeLocations.join(" | "),
        ExcludeLocationsRaw: excludeLocations.join(", "),
        ClientAppTypes: clients.join(", "),
        AuthFlows: authFlows || "",
        SignInRisk: ((p.conditions && p.conditions.signInRiskLevels) || []).join(
          ", "
        ),
        UserRisk: ((p.conditions && p.conditions.userRiskLevels) || []).join(", "),
        Platforms: (
          (p.conditions.platforms && p.conditions.platforms.includePlatforms) ||
          []
        ).join(", "),
        RiskFlags: riskFlags.join(" | "),
      });
    }

    // CAPAnalyzer-oriented bundle:
    // - `value` = policies with original GUIDs/IDs (required for analysis)
    // - `_resolved` on each policy = human labels (safe; CAPAnalyzer strips unknown fields)
    // - `namedLocations` + `resolutions` for optional upload / readability
    const capAnalyzerBundle = {
      "@odata.context":
        "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies (enriched for CAPAnalyzer)",
      value: annotated,
      namedLocations: namedLocs || [],
      resolutions: resolver.getResolutions(),
      _meta: {
        note: "Graph ID fields are unchanged for CAPAnalyzer compatibility. Human-readable names are in each policy._resolved and in resolutions{id→label}.",
        policyCount: annotated.length,
        namedLocationCount: (namedLocs || []).length,
        resolutionCount: Object.keys(resolver.getResolutions()).length,
      },
    };
    io.saveJson("02_ca_policies_capanalyzer.json", capAnalyzerBundle);
    // Convenience: named locations in the shape CAPAnalyzer optional upload accepts
    if (namedLocs && namedLocs.length) {
      io.saveJson("02_named_locations_capanalyzer.json", {
        namedLocations: namedLocs,
      });
    }

    io.saveCsv("02_CA_Audit.csv", rows);
    const deviceCode = rows.filter((r) => r.AuthFlows);
    io.saveCsv("02_DeviceCode_CAPs.csv", deviceCode);

    summary.caTotal = policies.length;
    summary.caEnforced = rows.filter((r) => r.IsEnforced === "Yes").length;
    summary.caReportOnly = rows.filter((r) => r.IsEnforced === "Report-only").length;
    summary.caDeviceCodePolicies = deviceCode.length;

    const reportOnly = rows.filter((r) => r.IsEnforced === "Report-only");
    if (reportOnly.length) {
      findings.push({
        Severity: "Medium",
        Area: "CA",
        Detail: `${reportOnly.length} report-only policies`,
      });
    }
    if (!deviceCode.length) {
      findings.push({
        Severity: "High",
        Area: "CA",
        Detail: "No policy targets device code / auth transfer flows",
      });
    }
  } else {
    summary.caPoliciesCollected = false;
    findings.push({
      Severity: "High",
      Area: "Coverage",
      Detail:
        "Conditional Access policies could not be collected — CA coverage is unknown for this run, not absent (see ERROR_caPolicies.json)",
    });
  }

  // ── Privileged roles ──────────────────────────────────────────────────
  console.log("── Privileged roles (schedule instances, group expansion, scope)");
  const roleModel = await collectRoleAssignments(graph, io, { roleDefById, facts });
  const roleRows = roleModel.rows;
  const rolesCollected = roleModel.collected;
  // High-value = privileged role on an effective principal (group members are
  // expanded; the group shell itself stays in the audit CSV only).
  let privRows = highValueRows(roleRows);
  const roleStatus = rolesCollected ? undefined : STATUS.FAILED;
  io.saveCsv("03_PrivilegedRoles_Audit.csv", roleRows, { status: roleStatus });
  io.saveCsv("03_PrivilegedAccounts_HighValue.csv", privRows, { status: roleStatus });

  if (!rolesCollected) {
    // Reporting "0 Global Admins" after a failed export reads as good hygiene.
    findings.push({
      Severity: "High",
      Area: "Coverage",
      Detail:
        "Role assignments could not be collected — privileged-access figures are unknown for this run, not zero (see ERROR_roleAssignments.json)",
    });
  } else {
    const kpi = summarizeRoles(roleRows);
    summary.privilegedAssignmentsTotal = kpi.assignmentsTotal;
    summary.privilegedHighValueAssignments = privRows.length;
    summary.globalAdminPermanent = kpi.globalAdminPermanent;
    summary.globalAdminActivated = kpi.globalAdminActivated;
    summary.globalAdminEligible = kpi.globalAdminEligible;
    summary.pimEligibleCount = kpi.pimEligibleCount;
    summary.roleAssignmentSource = roleModel.source;
    summary.roleEligibilityCollected = roleModel.eligibilityCollected;
    summary.roleViaGroupRows = kpi.viaGroupRows;
    summary.roleScopedRows = kpi.scopedRows;

    const scopedNote = kpi.scopedRows
      ? `; ${kpi.scopedRows} AU/app-scoped assignment(s) listed but not counted as tenant-wide`
      : "";
    const groupNote = kpi.viaGroupRows
      ? `; ${kpi.viaGroupRows} inherited through role-assignable groups`
      : "";
    findings.push({
      Severity: summary.globalAdminPermanent > 5 ? "High" : summary.globalAdminPermanent > 2 ? "Medium" : "Info",
      Area: "Privileged",
      Detail:
        `${summary.globalAdminPermanent} permanent Global Administrators` +
        (kpi.globalAdminActivated ? ` (+${kpi.globalAdminActivated} PIM-activated at collection time)` : "") +
        `; ${privRows.length} high-value role assignments${groupNote}${scopedNote}` +
        ` — source ${roleModel.source} (see 03_PrivilegedAccounts_HighValue.csv)`,
    });
    if (roleModel.groupExpansion.truncated) {
      findings.push({
        Severity: "Info",
        Area: "Coverage",
        Detail: `Role-assignable group expansion capped: ${roleModel.groupExpansion.expanded}/${roleModel.groupExpansion.requested} groups expanded — privileged inventory is partial`,
      });
    }
    if (!roleModel.eligibilityCollected) {
      findings.push({
        Severity: "Info",
        Area: "Privileged",
        Detail: "PIM eligibility not readable (no P2/Governance licence or no permission) — eligible assignments are unknown, not zero",
      });
    }
  }

  // ── CapAnalyzer offline What-If pack (principals + memberships + raw signIns)
  if (capAnalyzerOffline && policies) {
    const primarySignInDays =
      Array.isArray(signInDays) && signInDays.length
        ? Math.min(
            ...signInDays
              .map(Number)
              .filter((n) => Number.isFinite(n) && n > 0)
          ) || 30
        : 30;
    const pack = await collectCapAnalyzerOfflinePack(graph, io, {
      policies,
      resolver,
      roleDefMap,
      privilegedRows: privRows || [],
      maxMembershipUsers: capAnalyzerMaxMemberships,
      signInDays: primarySignInDays,
      signInMaxPages: capAnalyzerSignInPages,
      signInTop: 200,
      includeSignIns: true,
    });
    if (pack?.catalog) {
      summary.capAnalyzerPrincipals =
        (pack.catalog._meta.userCount || 0) +
        (pack.catalog._meta.groupCount || 0) +
        (pack.catalog._meta.applicationCount || 0);
    }
    if (pack?.membershipPack) {
      summary.capAnalyzerMembershipUsers = pack.membershipPack._meta.resolved;
    }
    if (pack?.signInPack) {
      summary.capAnalyzerRawSignIns = pack.signInPack._meta.count;
    }
  } else if (!capAnalyzerOffline) {
    console.log("── CapAnalyzer offline pack skipped (--no-capanalyzer-offline)");
  }

  // ── MFA / passkeys / inactive users (registration report + sign-in) ───
  console.log("── MFA registration / phishing-resistant / inactive users");
  let regDetails = await soft(
    "userRegistrationDetails",
    () =>
      graph.getAll(
        `${graph.GRAPH}/reports/authenticationMethods/userRegistrationDetails`
      ),
    io
  );

  if (regDetails) {
    io.saveJson("07_user_registration_details.json", regDetails);

    const noMfa = regDetails.filter((u) => u.isMfaRegistered === false);
    const withMfa = regDetails.filter((u) => u.isMfaRegistered === true);
    const phishing = regDetails.filter((u) => {
      const methods = u.methodsRegistered || [];
      return methods.some((m) =>
        PHISHING_RESISTANT_METHODS.some(
          (p) => m.toLowerCase().includes(p.toLowerCase()) || m === p
        )
      );
    });
    // Broader: isPasswordlessCapable or systemPreferredAuthenticationMethods
    const passkeyLike = regDetails.filter((u) => {
      const methods = (u.methodsRegistered || []).map((m) => m.toLowerCase());
      return methods.some(
        (m) =>
          m.includes("passkey") ||
          m.includes("fido2") ||
          m.includes("windowshello") ||
          m.includes("passwordless")
      );
    });

    io.saveCsv(
      "07_Users_Without_MFA.csv",
      noMfa.map((u) => ({
        UPN: u.userPrincipalName,
        DisplayName: u.userDisplayName,
        IsAdmin: u.isAdmin,
        IsSsprRegistered: u.isSsprRegistered,
        MethodsRegistered: (u.methodsRegistered || []).join(", "),
        LastUpdated: u.lastUpdatedDateTime,
      }))
    );
    io.saveCsv(
      "07_Users_PhishingResistant_or_Passkey.csv",
      passkeyLike.map((u) => ({
        UPN: u.userPrincipalName,
        DisplayName: u.userDisplayName,
        IsAdmin: u.isAdmin,
        MethodsRegistered: (u.methodsRegistered || []).join(", "),
        IsMfaRegistered: u.isMfaRegistered,
      }))
    );

    summary.usersInRegistrationReport = regDetails.length;
    summary.usersWithoutMfa = noMfa.length;
    summary.usersWithMfa = withMfa.length;
    summary.usersWithPasskeyOrPhishingResistant = passkeyLike.length;
    summary.adminsWithoutMfa = noMfa.filter((u) => u.isAdmin).length;

    if (noMfa.length) {
      const adminRows = noMfa.filter((u) => u.isAdmin);
      const humanAdmins = adminRows.filter(
        (u) =>
          !isCopilotOrAgentUpn(u.userPrincipalName) &&
          !/^(svc[-._]|service[-._]|sync_)/i.test(
            String(u.userPrincipalName || "").split("@")[0]
          )
      );
      findings.push({
        Severity: humanAdmins.length ? "High" : "Medium",
        Area: "MFA",
        Detail: `${noMfa.length} users without MFA registered (${adminRows.length} admins` +
          (humanAdmins.length !== adminRows.length
            ? `, ${humanAdmins.length} human`
            : "") +
          `) — 07_Users_Without_MFA.csv`,
      });
    }
    findings.push({
      Severity: "Info",
      Area: "Passkey",
      Detail: `${passkeyLike.length} users with passkey/WHfB/FIDO-like methods — 07_Users_PhishingResistant_or_Passkey.csv`,
    });
  }

  // Inactive users via beta signInActivity
  const usersSignIn = await soft(
    "usersSignInActivity",
    () =>
      graph.getAll(
        `${graph.GRAPH_BETA}/users?$select=id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime,signInActivity&$top=999`
      ),
    io
  );
  if (usersSignIn) {
    const cutoff = daysAgo(inactiveDays);
    const inactive = [];
    for (const u of usersSignIn) {
      if (u.accountEnabled === false) continue;
      const last =
        parseDate(u.signInActivity && u.signInActivity.lastSignInDateTime) ||
        parseDate(
          u.signInActivity && u.signInActivity.lastNonInteractiveSignInDateTime
        );
      if (last === null || last < cutoff) {
        inactive.push({
          DisplayName: u.displayName,
          UPN: u.userPrincipalName,
          UserType: u.userType,
          AccountEnabled: u.accountEnabled,
          LastInteractive:
            (u.signInActivity && u.signInActivity.lastSignInDateTime) || "Never",
          LastNonInteractive:
            (u.signInActivity &&
              u.signInActivity.lastNonInteractiveSignInDateTime) ||
            "Never",
          Created: u.createdDateTime,
          DaysSinceInteractive: last
            ? Math.floor((Date.now() - last) / 86400000)
            : "Never",
        });
      }
    }
    io.saveCsv(`08_Accounts_Inactive_${inactiveDays}d.csv`, inactive);
    summary.inactiveAccounts = inactive.length;
    findings.push({
      Severity: inactive.length > 50 ? "Medium" : "Info",
      Area: "InactiveAccounts",
      Detail: `${inactive.length} enabled accounts with no sign-in since ${inactiveDays} days — 08_Accounts_Inactive_${inactiveDays}d.csv`,
    });
  }

  // ── Devices ───────────────────────────────────────────────────────────
  console.log("── Devices (joined / registered / stale / per-user)");
  let devices = await soft(
    "devices",
    () =>
      graph.getAll(
        `${graph.GRAPH}/devices?$select=id,displayName,deviceId,accountEnabled,operatingSystem,operatingSystemVersion,trustType,profileType,approximateLastSignInDateTime,registrationDateTime,isManaged,isCompliant,manufacturer,model&$expand=registeredOwners($select=id,displayName,userPrincipalName,userType)`
      ),
    io
  );
  if (!devices) {
    devices = await soft(
      "devices_no_owners",
      () =>
        graph.getAll(
          `${graph.GRAPH}/devices?$select=id,displayName,deviceId,accountEnabled,operatingSystem,operatingSystemVersion,trustType,profileType,approximateLastSignInDateTime,registrationDateTime,isManaged,isCompliant,manufacturer,model`
        ),
      io
    );
  }

  const deviceReg = await soft(
    "deviceRegistrationPolicy",
    () => graph.get(`${graph.GRAPH}/policies/deviceRegistrationPolicy`),
    io
  );
  if (deviceReg) {
    io.saveJson("06_device_registration_policy.json", deviceReg);
    const joinType =
      (deviceReg.azureADJoin &&
        deviceReg.azureADJoin.allowedToJoin &&
        deviceReg.azureADJoin.allowedToJoin["@odata.type"]) ||
      "";
    const regType =
      (deviceReg.azureADRegistration &&
        deviceReg.azureADRegistration.allowedToRegister &&
        deviceReg.azureADRegistration.allowedToRegister["@odata.type"]) ||
      "";
    summary.deviceJoinAllowed = joinType.includes("allDeviceRegistrationMembership")
      ? "All users"
      : joinType.includes("noDeviceRegistrationMembership")
        ? "None"
        : joinType || "Selected/unknown";
    summary.deviceRegisterAllowed = regType.includes(
      "allDeviceRegistrationMembership"
    )
      ? "All users"
      : regType.includes("noDeviceRegistrationMembership")
        ? "None"
        : regType || "Selected/unknown";
    summary.deviceJoinOrRegisterMfa =
      deviceReg.multiFactorAuthConfiguration || "unknown";
    summary.userDeviceQuota = deviceReg.userDeviceQuota;
    const joinUsers =
      (deviceReg.azureADJoin &&
        deviceReg.azureADJoin.allowedToJoin &&
        deviceReg.azureADJoin.allowedToJoin.users) ||
      [];
    const joinGroups =
      (deviceReg.azureADJoin &&
        deviceReg.azureADJoin.allowedToJoin &&
        deviceReg.azureADJoin.allowedToJoin.groups) ||
      [];
    summary.deviceJoinEnumeratedUsers = joinUsers.length;
    summary.deviceJoinEnumeratedGroups = joinGroups.length;
    const mfaOff = /notRequired|disabled|none|^false$/i.test(
      String(summary.deviceJoinOrRegisterMfa)
    );
    findings.push({
      Severity: mfaOff
        ? "High"
        : summary.deviceJoinAllowed === "All users" ||
            summary.deviceRegisterAllowed === "All users"
          ? "Medium"
          : "Info",
      Area: "DeviceJoin",
      Detail:
        `Join=${summary.deviceJoinAllowed}` +
        (joinUsers.length || joinGroups.length
          ? ` (users=${joinUsers.length}, groups=${joinGroups.length})`
          : "") +
        `; Register=${summary.deviceRegisterAllowed}; MFA=${summary.deviceJoinOrRegisterMfa}` +
        (mfaOff
          ? " — users can join/register devices WITHOUT MFA at the device-registration policy"
          : " — MFA required by deviceRegistrationPolicy") +
        `; quota=${summary.userDeviceQuota}`,
    });
  }

  if (devices) {
    const staleCut = monthsAgo(deviceStaleMonths);
    // trustType: AzureAd = Entra joined, ServerAd = hybrid, Workplace = registered
    const entraJoined = devices.filter(
      (d) => (d.trustType || "").toLowerCase() === "azuread"
    );
    const hybridJoined = devices.filter(
      (d) => (d.trustType || "").toLowerCase() === "serverad"
    );
    const registered = devices.filter(
      (d) => (d.trustType || "").toLowerCase() === "workplace"
    );
    const joinedOrHybrid = [...entraJoined, ...hybridJoined];
    const staleJoined = joinedOrHybrid.filter((d) => {
      const last = parseDate(d.approximateLastSignInDateTime);
      return last === null || last < staleCut;
    });

    io.saveCsv(
      `09_Devices_Stale_Joined_${deviceStaleMonths}m.csv`,
      staleJoined.map((d) => ({
        DisplayName: d.displayName,
        TrustType: d.trustType,
        OS: d.operatingSystem,
        LastSeen: d.approximateLastSignInDateTime || "Never",
        Enabled: d.accountEnabled,
        Compliant: d.isCompliant,
        Managed: d.isManaged,
        Manufacturer: d.manufacturer,
        Model: d.model,
      }))
    );
    io.saveCsv(
      "09_Devices_Registered_Only.csv",
      registered.map((d) => ({
        DisplayName: d.displayName,
        TrustType: d.trustType,
        OS: d.operatingSystem,
        LastSeen: d.approximateLastSignInDateTime || "Never",
        Enabled: d.accountEnabled,
        Compliant: d.isCompliant,
        Managed: d.isManaged,
      }))
    );

    // Per-user device inventory (PC / smartphone / tablet) — stats, not a finding by default
    const byUser = new Map();
    let devicesWithOwner = 0;
    for (const d of devices) {
      const form = classifyDeviceForm(d);
      const owners = Array.isArray(d.registeredOwners) ? d.registeredOwners : [];
      const userOwners = owners.filter(
        (o) =>
          o &&
          ((o["@odata.type"] || "").toLowerCase().includes("user") ||
            !!o.userPrincipalName)
      );
      if (!userOwners.length) continue;
      devicesWithOwner++;
      for (const o of userOwners) {
        const upn = o.userPrincipalName || o.displayName || o.id;
        if (!byUser.has(upn)) {
          byUser.set(upn, {
            UPN: upn,
            DisplayName: o.displayName || "",
            PC: 0,
            Smartphone: 0,
            Tablet: 0,
            Other: 0,
            Total: 0,
            Devices: [],
          });
        }
        const row = byUser.get(upn);
        row[form] = (row[form] || 0) + 1;
        row.Total++;
        if (row.Devices.length < 12) {
          row.Devices.push(
            `${form}:${d.displayName || d.deviceId || "?"}(${d.operatingSystem || "?"})`
          );
        }
      }
    }

    const perUserRows = [...byUser.values()]
      .map((r) => ({
        UPN: r.UPN,
        DisplayName: r.DisplayName,
        PC: r.PC,
        Smartphone: r.Smartphone,
        Tablet: r.Tablet,
        Other: r.Other,
        Total: r.Total,
        HasPcPhoneTablet: r.PC >= 1 && r.Smartphone >= 1 && r.Tablet >= 1,
        MultiPC: r.PC > 1,
        MultiPhone: r.Smartphone > 1,
        MultiTablet: r.Tablet > 1,
        OverQuota:
          summary.userDeviceQuota != null &&
          Number(summary.userDeviceQuota) > 0 &&
          r.Total > Number(summary.userDeviceQuota),
        SampleDevices: r.Devices.join(" | "),
      }))
      .sort((a, b) => b.Total - a.Total || b.PC - a.PC);

    io.saveCsv("09_Devices_Per_User.csv", perUserRows);
    io.saveCsv(
      "09_Devices_Per_User_Multi.csv",
      perUserRows.filter(
        (r) =>
          r.MultiPC ||
          r.MultiPhone ||
          r.MultiTablet ||
          r.HasPcPhoneTablet ||
          r.OverQuota
      )
    );

    const formCounts = { PC: 0, Smartphone: 0, Tablet: 0, Other: 0 };
    for (const d of devices) formCounts[classifyDeviceForm(d)]++;

    summary.devicesWithOwner = devicesWithOwner;
    summary.devicesFormPC = formCounts.PC;
    summary.devicesFormSmartphone = formCounts.Smartphone;
    summary.devicesFormTablet = formCounts.Tablet;
    summary.devicesFormOther = formCounts.Other;
    summary.usersWithDevices = perUserRows.length;
    summary.usersMultiPC = perUserRows.filter((r) => r.MultiPC).length;
    summary.usersMultiPhone = perUserRows.filter((r) => r.MultiPhone).length;
    summary.usersMultiTablet = perUserRows.filter((r) => r.MultiTablet).length;
    summary.usersPcPhoneTablet = perUserRows.filter(
      (r) => r.HasPcPhoneTablet
    ).length;
    summary.usersOverDeviceQuota = perUserRows.filter((r) => r.OverQuota).length;

    findings.push({
      Severity: "Info",
      Area: "DevicesPerUser",
      Detail:
        `Form factors PC=${formCounts.PC}, Phone=${formCounts.Smartphone}, Tablet=${formCounts.Tablet}, Other=${formCounts.Other}; ` +
        `users with devices=${perUserRows.length}; multi-PC=${summary.usersMultiPC}, multi-phone=${summary.usersMultiPhone}, multi-tablet=${summary.usersMultiTablet}; ` +
        `PC+phone+tablet=${summary.usersPcPhoneTablet}` +
        (summary.userDeviceQuota != null
          ? `; over quota>${summary.userDeviceQuota}=${summary.usersOverDeviceQuota}`
          : "") +
        ` — 09_Devices_Per_User.csv`,
    });

    summary.devicesTotal = devices.length;
    summary.devicesEntraJoined = entraJoined.length;
    summary.devicesHybridJoined = hybridJoined.length;
    summary.devicesRegisteredOnly = registered.length;
    summary.devicesStaleJoinedOrHybrid = staleJoined.length;

    findings.push({
      Severity: "Info",
      Area: "Devices",
      Detail: `Joined=${entraJoined.length}, Hybrid=${hybridJoined.length}, RegisteredOnly=${registered.length}, StaleJoined>${deviceStaleMonths}m=${staleJoined.length}`,
    });
  }

  // ── Apps / service principals ─────────────────────────────────────────
  const appSurface = await collectAppSurface(graph, io, findings, summary);
  const dangerousSpnRows = appSurface.dangerousSpnRows;

  const apps = await soft(
    "applications",
    () =>
      graph.getAll(
        `${graph.GRAPH}/applications?$select=id,appId,displayName,web,spa,passwordCredentials,keyCredentials,signInAudience,createdDateTime&$top=999`
      ),
    io
  );
  if (apps) {
    const wild = [];
    const secrets = [];
    const longLived = [];
    const now = Date.now();
    for (const app of apps) {
      const uris = [
        ...((app.web && app.web.redirectUris) || []),
        ...((app.spa && app.spa.redirectUris) || []),
      ];
      if (uris.some((u) => u.includes("*"))) {
        wild.push({
          DisplayName: app.displayName,
          AppId: app.appId,
          WildcardUris: uris.join(", "),
        });
      }
      for (const s of app.passwordCredentials || []) {
        const end = new Date(s.endDateTime).getTime();
        const start = new Date(s.startDateTime).getTime();
        const daysLeft = Math.floor((end - now) / 86400000);
        const lifetimeDays =
          Number.isFinite(start) && Number.isFinite(end)
            ? Math.round((end - start) / 86400000)
            : null;
        if (daysLeft < 30) {
          secrets.push({
            AppName: app.displayName,
            AppId: app.appId,
            SecretName: s.displayName || "(unnamed)",
            Expiry: s.endDateTime,
            DaysLeft: daysLeft,
            Status: daysLeft < 0 ? "EXPIRED" : "Expiring soon",
          });
        }
        if (lifetimeDays != null && lifetimeDays > 730 && daysLeft >= 0) {
          longLived.push({
            AppName: app.displayName,
            AppId: app.appId,
            SignInAudience: app.signInAudience || "",
            SecretName: s.displayName || "(unnamed)",
            Start: s.startDateTime,
            Expiry: s.endDateTime,
            LifetimeDays: lifetimeDays,
            DaysLeft: daysLeft,
          });
        }
      }
    }
    io.saveCsv("04_SPN_WildcardReplyUrls.csv", wild);
    io.saveCsv("04_App_SecretsExpiry.csv", secrets);
    io.saveCsv("04_App_LongLived_Secrets.csv", longLived);
    summary.appSecretsLongLived = longLived.length;
    if (longLived.length) {
      findings.push({
        Severity: "Medium",
        Area: "AppCredentials",
        Detail: `${longLived.length} app-registration client secret(s) valid for more than 2 years — enable an app management policy to cap secret lifetime — 04_App_LongLived_Secrets.csv`,
      });
    }
  }

  const guests = await soft(
    "guests",
    () =>
      graph.getAll(
        `${graph.GRAPH}/users?$filter=userType eq 'Guest'&$select=id,displayName,userPrincipalName,accountEnabled,createdDateTime,externalUserState,mail`
      ),
    io
  );
  if (guests) {
    io.saveCsv(
      "05_guests.csv",
      guests.map((g) => ({
        DisplayName: g.displayName,
        UPN: g.userPrincipalName,
        AccountEnabled: g.accountEnabled,
        Created: g.createdDateTime,
        ExternalUserState: g.externalUserState,
        Mail: g.mail,
      }))
    );
    summary.guestCount = guests.length;
    summary.guestEnabled = guests.filter((g) => g.accountEnabled).length;
  }

  // ── Attack-path checks (Maester-inspired, threat-actor focused) ────────
  // `sources` tells the checker which inputs are real. An empty array from a
  // failed export must not be read as "the tenant has none of these".
  await collectAttackPathChecks(graph, io, findings, summary, {
    policies: policies || [],
    authz: authzPol,
    authMethods: authMethods || null,
    privRows,
    roleRows,
    dangerousSpnRows,
    regDetails: regDetails || [],
    roleDefMap,
    facts,
    sources: {
      caPolicies: policies != null,
      authz: authzPol != null,
      authMethods: authMethods != null,
      privRoles: rolesCollected,
      regDetails: regDetails != null,
      servicePrincipals: appSurface.sources.servicePrincipals,
      servicePrincipalInventory: appSurface.sources.servicePrincipalInventory,
      delegatedGrants: appSurface.sources.delegatedGrants,
    },
  });

  // ── Secure Score + high-value controls ────────────────────────────────
  console.log("── Microsoft Secure Score");
  const scores = await soft(
    "secureScores",
    () =>
      graph.getAll(
        `${graph.GRAPH}/security/secureScores?$top=1`
      ),
    io
  );
  // secureScores returns array — take newest
  let latestScore = null;
  if (scores) {
    const arr = Array.isArray(scores) ? scores : scores.value || [];
    latestScore = arr[0] || scores;
    io.saveJson("10_secure_score_latest.json", latestScore);
    summary.secureScoreCurrent =
      latestScore.currentScore ?? latestScore.scorePercentage;
    summary.secureScoreMax = latestScore.maxScore;
    summary.secureScoreEnabledServices = (
      latestScore.enabledServices || []
    ).join(", ");
  }

  const scoreProfiles = await soft(
    "secureScoreControlProfiles",
    () =>
      graph.getAll(`${graph.GRAPH}/security/secureScoreControlProfiles`),
    io
  );
  if (scoreProfiles || latestScore) {
    if (scoreProfiles) {
      io.saveJson("10_secure_score_control_profiles.json", scoreProfiles);
    }
    const {
      buildInScopeControls,
      buildCategoryRollup,
    } = require("./securescore");

    // Catalog of all profiles (reference) — CurrentScore only when in live score.
    const actionable = (scoreProfiles || [])
      .map((c) => {
        const max = c.maxScore || 0;
        let current = null;
        if (latestScore && latestScore.controlScores) {
          const hit = latestScore.controlScores.find(
            (x) => x.controlName === c.id || x.controlName === c.title
          );
          if (hit) current = hit.score;
        }
        return {
          Id: c.id,
          Title: c.title,
          MaxScore: max,
          CurrentScore: current,
          InLiveScore: current != null ? "yes" : "no",
          Rank: c.rank,
          Service: c.service,
          ImplementationStatus: c.implementationStatus,
          Remediation: (c.remediation || "").slice(0, 300),
          RemediationImpact: c.remediationImpact,
          Threats: (c.threats || []).join(", "),
          Tier: c.tier,
          UserImpact: c.userImpact,
          ActionType: c.actionType,
          Deprecated: c.deprecated,
        };
      })
      .filter((c) => !c.Deprecated && (c.MaxScore || 0) > 0)
      .sort((a, b) => (b.MaxScore || 0) - (a.MaxScore || 0));

    if (actionable.length) {
      io.saveCsv("10_SecureScore_Controls_ByValue.csv", actionable);
    }

    // Controls that actually count toward this tenant's Secure Score.
    const inScope = buildInScopeControls(latestScore, scoreProfiles || []);
    if (inScope.length) {
      io.saveCsv("10_SecureScore_ByCategory.csv", inScope);
      io.saveCsv(
        "10_SecureScore_Category_Rollup.csv",
        buildCategoryRollup(inScope)
      );
      const open = inScope
        .filter((c) => c.Status !== "Complete" && c.GapPoints > 0.05)
        .sort((a, b) => b.GapPoints - a.GapPoints);
      io.saveCsv("10_SecureScore_Top15_HighValue.csv", open.slice(0, 15));
      summary.secureScoreControls = inScope.length;
      summary.secureScoreOpenControls = open.length;
      summary.secureScoreOpenPoints = Math.round(
        open.reduce((s, c) => s + c.GapPoints, 0) * 100
      ) / 100;
      const roll = buildCategoryRollup(inScope);
      summary.secureScoreCategories = roll
        .map((r) => `${r.Category}:${r.Score}/${r.Max}(gap ${r.Gap})`)
        .join("; ");
      findings.push({
        Severity: "Info",
        Area: "SecureScore",
        Detail:
          `Score=${summary.secureScoreCurrent}/${summary.secureScoreMax}; ` +
          `${inScope.length} in-scope controls (${open.length} open, ${summary.secureScoreOpenPoints} pts); ` +
          `by category: ${summary.secureScoreCategories} — 10_SecureScore_ByCategory.csv`,
      });
    } else if (actionable.length) {
      const top = actionable.slice(0, 15);
      io.saveCsv("10_SecureScore_Top15_HighValue.csv", top);
      summary.secureScoreControls = actionable.length;
      findings.push({
        Severity: "Info",
        Area: "SecureScore",
        Detail: `Score=${summary.secureScoreCurrent}/${summary.secureScoreMax}; top controls in 10_SecureScore_Top15_HighValue.csv`,
      });
    }
  }

  // ── Defender exploitable vulnerabilities (schema-aware) ───────────────
  console.log("── Defender vulnerability / hunting (schema-aware)");
  let vulnRows = [];

  if (schema.canHunt && schema.has("DeviceTvmSoftwareVulnerabilities")) {
    const hunt = await soft(
      "defenderHuntingVulns",
      () =>
        graph.post(`${graph.GRAPH}/security/runHuntingQuery`, {
          Query: `
DeviceTvmSoftwareVulnerabilities
| where VulnerabilitySeverityLevel in ("Critical","High")
| summarize Devices=dcount(DeviceId) by CveId, VulnerabilitySeverityLevel, SoftwareName, SoftwareVersion
| top 200 by Devices desc
`.trim(),
        }),
      io
    );
    if (hunt && hunt.results) {
      vulnRows = hunt.results.map((r) => ({
        CveId: r.CveId,
        Severity: r.VulnerabilitySeverityLevel,
        Software: r.SoftwareName,
        Version: r.SoftwareVersion,
        Devices: r.Devices,
        ExploitAvailable: "",
      }));
      io.saveCsv("11_Defender_Exploitable_Vulns.csv", vulnRows);
      io.saveJson("11_defender_hunting_raw.json", hunt);
      summary.defenderExploitableVulnRows = vulnRows.length;
      findings.push({
        Severity: vulnRows.length ? "High" : "Info",
        Area: "DefenderVulns",
        Detail: `${vulnRows.length} CVE rows from TVM hunting (exploitable/critical) — 11_Defender_Exploitable_Vulns.csv`,
      });
    }
  } else {
    const alerts = await soft(
      "securityAlerts",
      () =>
        graph.getAll(
          `${graph.GRAPH}/security/alerts_v2?$top=50&$orderby=createdDateTime desc`
        ),
      io
    );
    if (alerts) {
      io.saveJson("11_security_alerts_sample.json", alerts);
      summary.securityAlertsSample = alerts.length;
    }
    const why = !schema.canHunt
      ? `Hunting API ${schema.huntApiStatus}`
      : "DeviceTvmSoftwareVulnerabilities not in schema";
    findings.push({
      Severity: "Info",
      Area: "DefenderVulns",
      Detail: `Skipped TVM hunting (${why}). Check Defender Vulnerability Management portal manually. See 19_Hunting_Schema.json.`,
    });
  }

  // ── Password policy / banned passwords ────────────────────────────────
  console.log("── Password protection / banned words");
  // Directory / password rule settings live under groupSettings (not /v1.0/settings)
  const dirSettings = await soft(
    "directorySettings",
    async () => {
      try {
        return await graph.getAll(`${graph.GRAPH}/groupSettings`);
      } catch (e) {
        if (e && e.status === 404) {
          return graph.getAll(`${graph.GRAPH_BETA}/groupSettings`);
        }
        throw e;
      }
    },
    io
  );
  if (dirSettings) {
    io.saveJson("12_directory_settings.json", dirSettings);
    const pwdRows = [];
    for (const s of dirSettings) {
      const values = s.values || [];
      const asObj = {};
      for (const v of values) asObj[v.name] = v.value;
      pwdRows.push({
        DisplayName: s.displayName,
        TemplateId: s.templateId,
        ...asObj,
      });
      // Classic banned password list length indicator
      if (
        asObj.BannedPasswordCheckOnPremisesMode ||
        asObj.EnableBannedPasswordCheck ||
        asObj.BannedPasswordList
      ) {
        summary.passwordBannedCheck = asObj.EnableBannedPasswordCheck;
        summary.passwordBannedOnPremMode =
          asObj.BannedPasswordCheckOnPremisesMode;
        summary.customBannedPasswordListConfigured = !!(
          asObj.BannedPasswordList && String(asObj.BannedPasswordList).length > 0
        );
        summary.customBannedPasswordCount = asObj.BannedPasswordList
          ? String(asObj.BannedPasswordList).split(/\t|\n|;|,/).filter(Boolean)
              .length
          : 0;
        summary.passwordLockoutThreshold = asObj.LockoutThreshold;
        summary.passwordLockoutDurationSeconds = asObj.LockoutDurationInSeconds;
        summary.passwordBannedOnPremEnabled =
          asObj.EnableBannedPasswordCheckOnPremises;
      }
    }
    if (pwdRows.length) io.saveCsv("12_DirectorySettings_Password.csv", pwdRows);
    // Surface Password Protection blade fields explicitly (same Graph source).
    if (summary.passwordLockoutThreshold != null) {
      const bannedOff = /false|0/i.test(String(summary.passwordBannedCheck));
      findings.push({
        Severity: bannedOff ? "Medium" : "Info",
        Area: "PasswordProtection",
        Detail:
          `Smart lockout threshold=${summary.passwordLockoutThreshold}; durationSec=${summary.passwordLockoutDurationSeconds}; ` +
          `customBannedCloud=${summary.passwordBannedCheck}; customListEntries=${summary.customBannedPasswordCount ?? 0}; ` +
          `onPremPasswordProtection=${summary.passwordBannedOnPremEnabled} mode=${summary.passwordBannedOnPremMode || "?"} — 12_DirectorySettings_Password.csv`,
      });
    }
  }

  // Identity Secure Score slice = Identity category from in-scope controls.
  try {
    const byCatPath = path.join(outDir, "10_SecureScore_ByCategory.csv");
    if (fs.existsSync(byCatPath)) {
      const { parseCsv } = require("./csv");
      const all = parseCsv(fs.readFileSync(byCatPath, "utf8"));
      const identity = all.filter((r) =>
        /^Identity$/i.test(String(r.Category || r.Service || ""))
      );
      if (identity.length) {
        io.saveCsv("10_IdentitySecureScore_Controls.csv", identity);
        const max = identity.reduce((n, r) => n + (Number(r.MaxScore) || 0), 0);
        const cur = identity.reduce(
          (n, r) => n + (Number(r.CurrentScore) || 0),
          0
        );
        summary.identitySecureScoreCurrent = Math.round(cur * 100) / 100;
        summary.identitySecureScoreMax = Math.round(max * 100) / 100;
        findings.push({
          Severity: "Info",
          Area: "IdentitySecureScore",
          Detail: `Identity Secure Score (in-scope): ${cur.toFixed(1)}/${max.toFixed(1)} across ${identity.length} controls — 10_IdentitySecureScore_Controls.csv`,
        });
      }
    }
  } catch {
    /* non-fatal */
  }

  // Auth methods password config (complexity is mostly cloud defaults)
  const domains = await soft(
    "domains",
    () => graph.getAll(`${graph.GRAPH}/domains`),
    io
  );
  if (domains) {
    io.saveCsv(
      "12_Domains.csv",
      domains.map((d) => ({
        Id: d.id,
        IsDefault: d.isDefault,
        IsVerified: d.isVerified,
        PasswordValidityPeriodInDays: d.passwordValidityPeriodInDays,
        PasswordNotificationWindowInDays: d.passwordNotificationWindowInDays,
        AuthenticationType: d.authenticationType,
      }))
    );
    const def = domains.find((d) => d.isDefault) || domains[0];
    if (def) {
      summary.passwordValidityPeriodInDays = def.passwordValidityPeriodInDays;
      summary.passwordNotificationWindowInDays =
        def.passwordNotificationWindowInDays;
    }
  }

  findings.push({
    Severity: "Info",
    Area: "PasswordPolicy",
    Detail: `ValidityDays=${summary.passwordValidityPeriodInDays ?? "n/a"}; BannedPasswordCheck=${summary.passwordBannedCheck ?? "n/a"}; CustomBannedList=${summary.customBannedPasswordListConfigured ?? "n/a"} (${summary.customBannedPasswordCount ?? 0} entries) — see 12_*`,
  });

  // ── SSPR ──────────────────────────────────────────────────────────────
  console.log("── SSPR");
  // Authentication methods policy registration + authorizationPolicy.allowedToUseSSPR
  // Detailed SSPR methods often in directory settings "Password Reset*" or portal-only
  let ssprMethods = null;
  if (dirSettings) {
    const sspr = dirSettings.find(
      (s) =>
        (s.displayName || "").toLowerCase().includes("password reset") ||
        (s.displayName || "").toLowerCase().includes("sspr")
    );
    if (sspr) {
      ssprMethods = sspr;
      io.saveJson("13_sspr_directory_setting.json", sspr);
    }
  }

  // From registration report
  if (regDetails) {
    const ssprReg = regDetails.filter((u) => u.isSsprRegistered === true);
    const ssprCapable = regDetails.filter((u) => u.isSsprCapable === true);
    summary.ssprRegisteredUsers = ssprReg.length;
    summary.ssprCapableUsers = ssprCapable.length;
    io.saveCsv(
      "13_SSPR_Registered_Users.csv",
      ssprReg.map((u) => ({
        UPN: u.userPrincipalName,
        DisplayName: u.userDisplayName,
        IsAdmin: u.isAdmin,
        MethodsRegistered: (u.methodsRegistered || []).join(", "),
        IsSsprEnabled: u.isSsprEnabled,
        IsSsprCapable: u.isSsprCapable,
      }))
    );
  }

  // Try beta authenticationMethodsPolicy for SSPR-related registration campain
  summary.ssprAllowedToUse = authz
    ? (authz.value ? authz.value[0] : authz).allowedToUseSSPR
    : undefined;

  // Number of verification methods: from auth methods enabled count + SSPR policy if present
  let ssprVerificationCount = null;
  if (ssprMethods && ssprMethods.values) {
    const map = Object.fromEntries(
      ssprMethods.values.map((v) => [v.name, v.value])
    );
    // Common keys: Version, RegistrationEnabled, EnablementType, etc.
    io.saveJson("13_sspr_policy_values.json", map);
    // Count enabled methods if listed
    const methodKeys = Object.keys(map).filter((k) =>
      /MobilePhone|OfficePhone|Email|SecurityQuestions|AlternateMobilePhone|Fido|App/i.test(
        k
      )
    );
    ssprVerificationCount = methodKeys.length || null;
    summary.ssprPolicyRawKeys = Object.keys(map).join(", ");
  }
  if (authMethods) {
    const enabledMethods = (
      authMethods.authenticationMethodConfigurations || []
    ).filter((c) => c.state === "enabled");
    summary.authMethodsEnabledCount = enabledMethods.length;
    summary.authMethodsEnabled = enabledMethods.map((c) => c.id).join(", ");
    // SSPR typically requires 1 or 2 methods — Entra default documented as policy
    ssprVerificationCount =
      ssprVerificationCount ?? summary.authMethodsEnabledCount;
  }
  summary.ssprVerificationMethodsEstimate = ssprVerificationCount;

  findings.push({
    Severity: "Info",
    Area: "SSPR",
    Detail: `allowedToUseSSPR=${summary.ssprAllowedToUse}; registered=${summary.ssprRegisteredUsers ?? "n/a"}; capable=${summary.ssprCapableUsers ?? "n/a"}; enabledAuthMethods=${summary.authMethodsEnabledCount ?? "n/a"} (${summary.authMethodsEnabled || ""})`,
  });

  // ── Log retention (best-effort) ───────────────────────────────────────
  console.log("── Log retention (best-effort)");
  /**
   * Entra audit/sign-in default retention is license-based (often 7–30 days in portal,
   * longer with Log Analytics diagnostic settings). Full M365 audit retention is Purview.
   * We capture what Graph exposes and note defaults.
   */
  const retentionNotes = [
    {
      LogType: "Entra sign-in logs (interactive)",
      Retention: "License-default (typically 7 days free / 30 days P1+ in Entra; extend via Diagnostic settings → Log Analytics)",
      Source: "Documentation / tenant license — confirm in Entra > Monitoring > Diagnostic settings",
    },
    {
      LogType: "Entra audit logs",
      Retention: "License-default (typically 7–30 days in Entra; extend via Diagnostic settings)",
      Source: "Documentation — confirm Diagnostic settings on Entra",
    },
    {
      LogType: "Microsoft 365 Unified Audit Log",
      Retention: "Default 180 days (E3/E5 often 1 year with Audit (Premium)); configurable in Purview",
      Source: "Microsoft Purview audit — not fully readable via Graph with Reader alone",
    },
    {
      LogType: "Microsoft Defender / Security alerts",
      Retention: "Product-default (often 180 days for alerts; advanced hunting 30 days unless longer retention add-on)",
      Source: "Defender portal settings",
    },
  ];

  io.saveCsv("14_Log_Retention_Notes.csv", retentionNotes);
  summary.logRetentionSeeFile = "14_Log_Retention_Notes.csv";
  findings.push({
    Severity: "Info",
    Area: "LogRetention",
    Detail:
      "Defaults documented in 14_Log_Retention_Notes.csv — confirm Diagnostic settings + Purview audit retention in portals (ARM/Purview often needed for exact values)",
  });

  // ── SharePoint / Teams / anti-spam / forwarding ────────────────────────
  await collectM365CollabAndMail(graph, pool, io, findings, summary, {
    schema,
  });

  // ── Sign-in / audit log insights ──────────────────────────────────────
  await collectSignInAndAuditInsights(graph, io, findings, summary, {
    windows: signInDays,
    schema,
    dangerousSpns: dangerousSpnRows || [],
    privilegedAccounts: typeof privRows !== "undefined" ? privRows : [],
  });

  // ── Endpoint hunts: RMM / AI / patch / update rings ───────────────────
  await collectEndpointHunts(graph, io, findings, summary, {
    rmmLegitThreshold,
    schema,
    devices: devices || [],
  });

  // ── Adaptive intel: alerts / exposure / IdentityLogon (with or without MDE)
  await collectAdaptiveIntel(graph, io, findings, summary, {
    schema,
    privilegedAccounts: typeof privRows !== "undefined" ? privRows : [],
  });

  } // !intelOnly

  // ── Write summary ─────────────────────────────────────────────────────
  io.saveJson("00_SUMMARY.json", summary);
  io.saveCsv("00_Findings.csv", findings);

  // Human-readable markdown summary
  const md = [];
  md.push(`# Entra / Security collection summary`);
  md.push(`- Collected: ${summary.collectedAt}`);
  md.push(`- Inactive threshold: ${inactiveDays} days`);
  md.push(`- Device stale threshold: ${deviceStaleMonths} months`);
  md.push("");
  md.push(`## Hunting / log schema`);
  md.push(
    `- Advanced Hunting API: **${summary.huntingCanHunt ? "OK" : "unavailable"}** (${summary.huntingApiStatus || "n/a"})`
  );
  md.push(`- Graph Entra sign-ins: **${summary.graphSignInsAvailable ? "OK" : "unavailable"}**`);
  md.push(`- Identity hunt source: **${summary.huntingIdentitySource || "n/a"}**`);
  md.push(
    `- Tables available: ${(summary.huntingAvailableTables || []).join(", ") || "(none)"}`
  );
  md.push(`- Details: \`19_Hunting_Schema.json\``);
  md.push("");
  md.push(`## Identity`);
  md.push(`- Users without MFA: **${summary.usersWithoutMfa ?? "n/a"}** (admins: ${summary.adminsWithoutMfa ?? "n/a"})`);
  md.push(`- Users with passkey/phishing-resistant-like methods: **${summary.usersWithPasskeyOrPhishingResistant ?? "n/a"}**`);
  md.push(`- Inactive enabled accounts (>${inactiveDays}d): **${summary.inactiveAccounts ?? "n/a"}**`);
  md.push(`- Guests: **${summary.guestCount ?? "n/a"}** (enabled: ${summary.guestEnabled ?? "n/a"})`);
  md.push("");
  md.push(`## Privileged`);
  md.push(`- High-value role assignments: **${summary.privilegedHighValueAssignments ?? "n/a"}**`);
  md.push(`- Permanent Global Admins: **${summary.globalAdminPermanent ?? "n/a"}**`);
  md.push(`- PIM eligible rows: **${summary.pimEligibleCount ?? "n/a"}**`);
  md.push("");
  md.push(`## Attack-path checks`);
  md.push(
    `- Checks: **${summary.attackPathChecks ?? "n/a"}** | High failures: **${summary.attackPathHighFails ?? "n/a"}**`
  );
  md.push(`- Details: \`40_AttackPath_Checklist.csv\`, \`40_CA_AttackPath_Coverage.csv\``);
  md.push("");
  md.push(`## Devices`);
  md.push(`- Entra joined: **${summary.devicesEntraJoined ?? "n/a"}** | Hybrid: **${summary.devicesHybridJoined ?? "n/a"}** | Registered only: **${summary.devicesRegisteredOnly ?? "n/a"}**`);
  md.push(`- Stale joined/hybrid (>${deviceStaleMonths}m): **${summary.devicesStaleJoinedOrHybrid ?? "n/a"}**`);
  md.push(`- Form factors PC / Phone / Tablet / Other: **${summary.devicesFormPC ?? "n/a"}** / **${summary.devicesFormSmartphone ?? "n/a"}** / **${summary.devicesFormTablet ?? "n/a"}** / **${summary.devicesFormOther ?? "n/a"}**`);
  md.push(`- Users with devices: **${summary.usersWithDevices ?? "n/a"}** · multi-PC **${summary.usersMultiPC ?? "n/a"}** · multi-phone **${summary.usersMultiPhone ?? "n/a"}** · multi-tablet **${summary.usersMultiTablet ?? "n/a"}** · PC+phone+tablet **${summary.usersPcPhoneTablet ?? "n/a"}**`);
  md.push(`- Join allowed: **${summary.deviceJoinAllowed ?? "n/a"}** | Register: **${summary.deviceRegisterAllowed ?? "n/a"}** | MFA: **${summary.deviceJoinOrRegisterMfa ?? "n/a"}** | quota: **${summary.userDeviceQuota ?? "n/a"}**`);
  md.push("");
  md.push(`## Conditional Access`);
  md.push(`- Policies: ${summary.caTotal ?? "n/a"} (enforced ${summary.caEnforced ?? "n/a"}, report-only ${summary.caReportOnly ?? "n/a"})`);
  md.push(`- Device-code / auth-flow policies: **${summary.caDeviceCodePolicies ?? "n/a"}**`);
  md.push(`- Named locations: **${summary.namedLocationsCount ?? "n/a"}**`);
  md.push("");
  md.push(`## SharePoint / Teams / Mail`);
  md.push(`- SPO sharing: **${summary.spoSharingLabel ?? summary.spoSharingCapability ?? "n/a"}**`);
  md.push(`- Reshare by externals: ${summary.spoResharingByExternal ?? "n/a"} | Legacy auth: ${summary.spoLegacyAuth ?? "n/a"}`);
  md.push(`- Groups AllowToAddGuests: ${summary.groupsAllowToAddGuests ?? "n/a"}`);
  md.push(`- Cross-tenant B2B inbound/outbound: ${summary.ctaB2bCollaborationInbound ?? "n/a"} / ${summary.ctaB2bCollaborationOutbound ?? "n/a"}`);
  md.push(`- AutoForwardingMode (EXO): ${summary.autoForwardingMode ?? "n/a — see 18_* manual checks"}`);
  md.push("");
  md.push(`## Sign-in log insights`);
  for (const d of signInDays) {
    md.push(
      `- Device code (${d}d): **${summary[`deviceCodeSignIns${d}d`] ?? "n/a"}** events / **${summary[`deviceCodeUsers${d}d`] ?? "n/a"}** users`
    );
  }
  md.push(`- Legacy auth users: ${summary[`legacyAuthUsers${primaryDaysHint(signInDays)}d`] ?? summary.legacyAuthEvents90d ?? "n/a"}`);
  md.push(`- Single-factor success users: ${summary.singleFactorUsers90d ?? summary[`singleFactorUsers${primaryDaysHint(signInDays)}d`] ?? "n/a"}`);
  md.push(`- Risky users: ${summary.riskyUsersAtRisk ?? "n/a"}`);
  md.push(`- Failed sign-in IP clusters: ${summary[`failedSignInIpClusters${primaryDaysHint(signInDays)}d`] ?? "n/a"}`);
  md.push(`- Admin tooling apps: ${summary[`adminToolingApps${primaryDaysHint(signInDays)}d`] ?? "n/a"}`);
  md.push("");
  md.push(`## Endpoints (Defender / Intune)`);
  md.push(`- Windows devices (hunt): **${summary.windowsDeviceCount ?? "n/a"}**`);
  md.push(`- Windows 10: **${summary.windows10Count ?? "n/a"}** | Windows 11: **${summary.windows11Count ?? "n/a"}**`);
  md.push(`- Behind Patch Tuesday (${summary.patchTuesdayAsOf ?? "?"}): **${summary.behindPatchTuesdayCount ?? "n/a"}**`);
  md.push(`- RMM families: ${summary.rmmFamilies ?? "n/a"} (suspicious <${Math.round((summary.rmmLegitThreshold ?? 0.7) * 100)}%: **${summary.rmmSuspiciousFamilies ?? "n/a"}**)`);
  md.push(`- AI agent families / device rows: ${summary.aiAgentFamilies ?? "n/a"} / ${summary.aiAgentDeviceRows ?? "n/a"}`);
  md.push(`- GenAI cloud/network usage rows: **${summary.genAiUsageRows ?? "n/a"}** (~${summary.genAiBytesUploaded != null ? Math.round(summary.genAiBytesUploaded / 1048576) : "n/a"} MB)`);
  md.push(`- File-sharing (WeTransfer/Dropbox/…) rows: **${summary.fileShareUsageRows ?? "n/a"}**`);
  md.push(`- Intune update-ring policies: **${summary.updateRingPolicies ?? "n/a"}**`);
  md.push("");
  md.push(`## Secure Score / Defender`);
  md.push(`- Secure Score: **${summary.secureScoreCurrent ?? "n/a"} / ${summary.secureScoreMax ?? "n/a"}**`);
  md.push(`- Defender exploitable/critical CVE rows: **${summary.defenderExploitableVulnRows ?? "n/a"}**`);
  md.push("");
  md.push(`## Password / SSPR / Logs`);
  md.push(`- Password validity days: ${summary.passwordValidityPeriodInDays ?? "n/a"}`);
  md.push(`- Banned password check: ${summary.passwordBannedCheck ?? "n/a"}; custom list entries: ${summary.customBannedPasswordCount ?? "n/a"}`);
  md.push(`- SSPR allowed: ${summary.ssprAllowedToUse ?? "n/a"}; registered users: ${summary.ssprRegisteredUsers ?? "n/a"}`);
  md.push(`- Auth methods enabled: ${summary.authMethodsEnabled ?? "n/a"}`);
  md.push(`- Log retention: see 14_Log_Retention_Notes.csv`);
  md.push("");
  md.push(`## Findings`);
  for (const f of findings) {
    md.push(`- **[${f.Severity}]** ${f.Area}: ${f.Detail}`);
  }
  fs.writeFileSync(path.join(outDir, "00_SUMMARY.md"), md.join("\n"), "utf8");
  console.log("  ✓ 00_SUMMARY.md");

  console.log("\n── FINDINGS ──");
  for (const f of findings) {
    console.log(`  [${f.Severity}] ${f.Area}: ${f.Detail}`);
  }
  console.log("\n── KEY COUNTS ──");
  console.log(
    `  No MFA: ${summary.usersWithoutMfa ?? "n/a"} | Passkey-like: ${summary.usersWithPasskeyOrPhishingResistant ?? "n/a"} | Inactive>${inactiveDays}d: ${summary.inactiveAccounts ?? "n/a"}`
  );
  console.log(
    `  GA permanent: ${summary.globalAdminPermanent ?? "n/a"} | Stale devices: ${summary.devicesStaleJoinedOrHybrid ?? "n/a"} | Registered-only: ${summary.devicesRegisteredOnly ?? "n/a"}`
  );
  console.log(
    `  Secure Score: ${summary.secureScoreCurrent ?? "n/a"}/${summary.secureScoreMax ?? "n/a"} | Vuln rows: ${summary.defenderExploitableVulnRows ?? "n/a"}`
  );
  console.log(
    `  SPO sharing: ${summary.spoSharingLabel ?? "n/a"} | AutoForward: ${summary.autoForwardingMode ?? "n/a"}`
  );
  console.log(
    `  DeviceCode 30d: ${summary.deviceCodeSignIns30d ?? "n/a"} evt / ${summary.deviceCodeUsers30d ?? "n/a"} users | 90d: ${summary.deviceCodeSignIns90d ?? "n/a"} / ${summary.deviceCodeUsers90d ?? "n/a"}`
  );
  console.log(
    `  Win10: ${summary.windows10Count ?? "n/a"} | Behind PT: ${summary.behindPatchTuesdayCount ?? "n/a"} | RMM suspicious: ${summary.rmmSuspiciousFamilies ?? "n/a"} | AI rows: ${summary.aiAgentDeviceRows ?? "n/a"} | Rings: ${summary.updateRingPolicies ?? "n/a"}`
  );
  console.log(
    `  Attack-path checks: ${summary.attackPathChecks ?? "n/a"} | High fails: ${summary.attackPathHighFails ?? "n/a"}`
  );

  const manifest = io.finish({
    summary: { findings: findings.length },
    cache: cache.summarize(),
  });
  const failedSteps = Object.entries(manifest.steps).filter(
    ([, s]) => s.status === STATUS.FAILED
  );
  if (failedSteps.length) {
    // A 401/403 or a licence error will fail identically on every re-run —
    // telling the operator to resume would waste their time. Only transient
    // causes are worth retrying.
    const kindOf = (s) =>
      s.kind ||
      (s.httpStatus === 401 || s.httpStatus === 403
        ? ERROR_KIND.DENIED
        : s.transient
          ? ERROR_KIND.TRANSIENT
          : ERROR_KIND.ERROR);
    const denied = failedSteps.filter(([, s]) => kindOf(s) === ERROR_KIND.DENIED);
    const licence = failedSteps.filter(([, s]) => kindOf(s) === ERROR_KIND.LICENCE);
    const unsupported = failedSteps.filter(
      ([, s]) => kindOf(s) === ERROR_KIND.UNSUPPORTED
    );
    const retryable = failedSteps.filter(([, s]) =>
      [ERROR_KIND.TRANSIENT, ERROR_KIND.ERROR].includes(kindOf(s))
    );

    console.log(`\n  ⚠ ${failedSteps.length} step(s) failed — data below is incomplete.`);

    if (denied.length) {
      console.log(
        `\n    ${denied.length} blocked by permissions (a re-run will not help — grant the role):`
      );
      for (const [label, s] of denied) {
        console.log(`      · ${label}: HTTP ${s.httpStatus}${s.code ? ` ${s.code}` : ""}`);
      }
      console.log("      → check the roles listed by: node collect.js --check-permissions");
    }
    if (licence.length) {
      console.log(
        `\n    ${licence.length} require a licence the tenant does not have (scored NotApplicable):`
      );
      for (const [label, s] of licence) {
        console.log(`      · ${label}: ${s.code || `HTTP ${s.httpStatus}`}`);
      }
    }
    if (unsupported.length) {
      console.log(
        `\n    ${unsupported.length} rejected by the API (query shape / endpoint — a re-run will not help):`
      );
      for (const [label, s] of unsupported.slice(0, 12)) {
        console.log(`      · ${label}: ${String(s.error).slice(0, 110)}`);
      }
    }

    if (retryable.length) {
      console.log(`\n    ${retryable.length} possibly transient — worth retrying:`);
      for (const [label, s] of retryable.slice(0, 12)) {
        console.log(`      · ${label}: ${String(s.error).slice(0, 110)}`);
      }
      console.log(
        `      → node collect.js --resume ${path.basename(outDir)}   (cached calls are not re-fetched)`
      );
    }
  }

  // ── HTML / Excel report ────────────────────────────────────────────────
  try {
    const reportPath = await writeReport(outDir);
    summary.reportHtml = path.basename(reportPath);
    console.log(`\n  ▶ Open report: ${reportPath}`);
    console.log(
      `    → In the browser: Download PDF · Download Excel (This Week / Remediation Plan)`
    );
  } catch (e) {
    console.warn(`  ⚠ report: ${e.message}`);
  }

  return summary;
}

/** Tenant id recorded by a previous run in this folder, if any. */
function readPreviousTenantId(outDir) {
  // 00_token_info.json is rewritten by the current run before we get here, so
  // only the previous run's summary is authoritative.
  try {
    const j = JSON.parse(fs.readFileSync(path.join(outDir, "00_SUMMARY.json"), "utf8"));
    return j.tenantId ? String(j.tenantId).toLowerCase() : null;
  } catch {
    return null;
  }
}

function primaryDaysHint(windows) {
  if (windows.includes(90)) return 90;
  return windows[windows.length - 1] || 90;
}

const INTEL_FINDING_AREAS = new Set([
  "Alerts",
  "ExposureGraph",
  "IdentityInfo",
  "IdentityAccountInfo",
  "IdentityLogon",
  "CloudApp",
  "GraphAudit",
  "AdaptiveIntel",
]);

function mergePreviousCollection(outDir, summary, findings) {
  const keep = {
    collectedAt: summary.collectedAt,
    huntingPortalReady: summary.huntingPortalReady,
    huntingCanHunt: summary.huntingCanHunt,
    huntingApiStatus: summary.huntingApiStatus,
    huntingIdentitySource: summary.huntingIdentitySource,
    huntingAvailableTables: summary.huntingAvailableTables,
    huntingCapabilities: summary.huntingCapabilities,
    graphSignInsAvailable: summary.graphSignInsAvailable,
  };
  try {
    const prev = JSON.parse(
      fs.readFileSync(path.join(outDir, "00_SUMMARY.json"), "utf8")
    );
    if (prev && typeof prev === "object") Object.assign(summary, prev, keep);
  } catch {
    /* first run into this folder should use --resume with existing artifacts */
  }
  try {
    const prevFindings = parseCsv(
      fs.readFileSync(path.join(outDir, "00_Findings.csv"), "utf8")
    );
    for (const f of prevFindings) {
      if (!INTEL_FINDING_AREAS.has(f.Area)) findings.push(f);
    }
  } catch {
    /* optional */
  }
}

module.exports = { runCollection };
