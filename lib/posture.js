/**
 * Tenant-agnostic posture helpers shared by collect + analyzer.
 *
 * Pure functions over already-collected rows. No Graph, no filesystem.
 * Keep attack stories stable across tenants: same object ≠ four Highs;
 * report-only user-action CA ≠ fleet device-compliance gap; TVM openssl
 * ≠ unpatched Windows CU.
 */

const { parseOsBuild } = require("./patchTuesday");

const GA_PATH_PERMS = new Set([
  "RoleManagement.ReadWrite.Directory",
  "AppRoleAssignment.ReadWrite.All",
  "Application.ReadWrite.All",
  "Directory.ReadWrite.All",
]);

const GA_EQUIV_DIRECTORY_ROLES =
  /^(Global Administrator|Privileged Role Administrator|Privileged Authentication Administrator)$/i;

const CA_WRITE_PERM = /Policy\.ReadWrite\.ConditionalAccess/i;

const OS_SOFTWARE_RE =
  /^(windows_1[01]|windows_server|windows\s*1[01]|windows$)/i;

const RUNTIME_SOFTWARE_RE =
  /^(openssl|7-zip|7zip|\.net|dotnet|python|java|nodejs|chrome|edge|firefox|adobe|citrix|vmware|sql_server)/i;

const COPILOT_AGENT_RE =
  /^securitycopilotagentuser[-_]|copilotagentuser[-_]|#ext#.*agent/i;

function normName(s) {
  return String(s || "")
    .replace(/\u202f/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

function isUserActionOnlyPolicy(p) {
  const apps = ((p.conditions && p.conditions.applications) || {});
  const actions = apps.includeUserActions || [];
  const inc = apps.includeApplications || [];
  if (!actions.length) return false;
  if (!inc.length) return true;
  return !inc.some((x) => /^(all|office365)$/i.test(String(x)));
}

function hasUserAction(p, action) {
  const actions = (
    ((p.conditions && p.conditions.applications) || {}).includeUserActions || []
  ).map(String);
  return actions.some((a) =>
    a.toLowerCase().includes(String(action).toLowerCase())
  );
}

function builtInControls(p) {
  return ((p.grantControls && p.grantControls.builtInControls) || []).map((x) =>
    String(x).toLowerCase()
  );
}

/** Device-compliance CA that actually gates cloud apps — not SecInfo / enrollment. */
function isFleetDeviceCompliancePolicy(p) {
  const g = builtInControls(p);
  if (!g.includes("compliantdevice") && !g.includes("domainjoineddevice")) {
    return false;
  }
  if (hasUserAction(p, "registersecurityinfo") || hasUserAction(p, "registerdevice")) {
    return false;
  }
  if (isUserActionOnlyPolicy(p)) return false;
  return true;
}

function secInfoPolicyState(policies) {
  const all = policies || [];
  const match = all.filter((p) => hasUserAction(p, "registersecurityinfo"));
  const enforced = match.filter((p) => p.state === "enabled");
  const reportOnly = match.filter(
    (p) => p.state === "enabledForReportingButNotEnforced"
  );
  if (enforced.length) {
    return { status: "Pass", enforced, reportOnly, match };
  }
  if (reportOnly.length) {
    return { status: "Partial", enforced, reportOnly, match };
  }
  return { status: "Fail", enforced, reportOnly, match };
}

function isOsSoftware(name) {
  return OS_SOFTWARE_RE.test(String(name || "").trim());
}

function isRuntimeSoftware(name) {
  return RUNTIME_SOFTWARE_RE.test(String(name || "").trim());
}

function splitTvmVulns(rows) {
  const os = [];
  const runtime = [];
  const other = [];
  for (const r of rows || []) {
    const name = r.Software || r.SoftwareName || "";
    if (isOsSoftware(name)) os.push(r);
    else if (isRuntimeSoftware(name)) runtime.push(r);
    else other.push(r);
  }
  return { os, runtime, other };
}

function tvmSeverity(rows) {
  const crit = (rows || []).filter((r) =>
    /critical/i.test(String(r.VulnerabilitySeverityLevel || r.Severity || ""))
  ).length;
  const high = (rows || []).filter((r) =>
    /high/i.test(String(r.VulnerabilitySeverityLevel || r.Severity || ""))
  ).length;
  return { crit, high };
}

/**
 * Patch lag from TVM / CVE inventory when DeviceInfo has no UBR.
 * baseline.builds keyed by OS major ("26100").
 */
function patchLagFromSoftwareVersions(rows, baseline) {
  const builds = (baseline && baseline.builds) || {};
  const byDevice = new Map();
  for (const r of rows || []) {
    const ver = r.Version || r.SoftwareVersion || r.OSVersion || "";
    const parsed = parseOsBuild(ver);
    if (!parsed || parsed.ubr == null) continue;
    if (!isOsSoftware(r.Software || r.SoftwareName || "windows")) {
      if (!/^10\.0\.\d{5}\.\d+/.test(String(ver))) continue;
    }
    const id = String(r.DeviceId || r.DeviceName || ver);
    const prev = byDevice.get(id);
    if (!prev || parsed.ubr > prev.ubr) byDevice.set(id, parsed);
  }
  let behind = 0;
  let known = 0;
  for (const b of byDevice.values()) {
    const ref = builds[b.major];
    if (!ref || ref.minUbr == null) continue;
    known++;
    if (b.ubr < ref.minUbr) behind++;
  }
  return { behind, known, devices: byDevice.size };
}

function aggregateFailuresByIp(rows) {
  const byIp = new Map();
  for (const r of rows || []) {
    const ip = String(r.IP || r.IPAddress || "").trim() || "(none)";
    let e = byIp.get(ip);
    if (!e) {
      e = {
        IP: ip,
        Country: r.Country || "",
        Failures: 0,
        Users: 0,
        ErrorCodes: new Set(),
        SampleUsers: new Set(),
        Source: r.Source || "",
      };
      byIp.set(ip, e);
    }
    e.Failures += Number(r.Failures || 0);
    e.Users = Math.max(e.Users, Number(r.Users || 0));
    if (r.ErrorCode != null && String(r.ErrorCode).trim() !== "") {
      e.ErrorCodes.add(String(r.ErrorCode));
    }
    for (const u of String(r.SampleUsers || "").split(/\s*\|\s*/)) {
      if (u) e.SampleUsers.add(u);
    }
    if (r.Country && !e.Country) e.Country = r.Country;
  }
  return [...byIp.values()]
    .map((e) => ({
      IP: e.IP,
      Country: e.Country,
      Failures: e.Failures,
      Users: e.Users,
      ErrorCode: [...e.ErrorCodes].join(" | "),
      SampleUsers: [...e.SampleUsers].slice(0, 8).join(" | "),
      Source: e.Source,
    }))
    .sort((a, b) => b.Failures - a.Failures);
}

function isCopilotOrAgentUpn(upn) {
  return COPILOT_AGENT_RE.test(String(upn || "").split("@")[0] || "") ||
    /^securitycopilotagentuser-/i.test(String(upn || ""));
}

function identityInfoActionable(rows) {
  const withRoles = [];
  const atRisk = [];
  const taggedCritical = [];
  for (const r of rows || []) {
    const roles = String(r.AssignedRoles || r.PrivilegedEntraPimRoles || "").trim();
    const risk = String(r.RiskLevel || "").trim();
    const crit = Number(r.CriticalityLevel);
    if (roles) withRoles.push(r);
    if (/^(high|medium|atRisk|confirmedcompromised)$/i.test(risk)) atRisk.push(r);
    if (Number.isFinite(crit) && crit >= 3) taggedCritical.push(r);
  }
  return { withRoles, atRisk, taggedCritical };
}

/** Built-in role template IDs Graph sometimes omits from roleDefinitions. */
const ROLE_ID_FALLBACK = {
  "eb1d8c34-acf5-460d-8424-c1f1a6fbdb85": "AdHoc License Administrator",
  "d24aef57-1500-4070-84db-2666f29cf966": "Modern Commerce Administrator",
};

function looksLikeGuid(s) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
    String(s || "").trim()
  );
}

function resolveDirectoryRoleName(nameOrId, roleDefById = {}) {
  const raw = String(nameOrId || "").trim();
  if (!raw) return raw;
  if (!looksLikeGuid(raw)) return raw;
  const key = raw.toLowerCase();
  return (
    roleDefById[raw] ||
    roleDefById[key] ||
    ROLE_ID_FALLBACK[key] ||
    raw
  );
}

/**
 * Entra directory-role blast-radius bucket for the Privileged report.
 * High-value = identity control-plane (GA / app / CA / mailbox admins).
 * Data-plane = Purview content purge mapped into Entra (not isPrivileged).
 */
function directoryRoleTier(roleName, highValueNames) {
  const n = String(roleName || "");
  if (highValueNames && highValueNames.has(n)) return "High-value";
  if (/purview workload content (administrator|writer)/i.test(n)) return "Data-plane";
  if (/\breaders?\b/i.test(n)) return "Reader";
  return "Other";
}

function enrichDirectoryRoleRows(rows, { roleDefById = {}, highValueNames = new Set() } = {}) {
  return (rows || []).map((r) => {
    const roleName = resolveDirectoryRoleName(r.RoleName, roleDefById);
    return {
      ...r,
      RoleName: roleName,
      Tier: directoryRoleTier(roleName, highValueNames),
    };
  });
}

function rollupDirectoryRoles(rows) {
  const by = new Map();
  for (const r of rows || []) {
    const name = r.RoleName || "?";
    if (!by.has(name)) {
      by.set(name, {
        RoleName: name,
        Tier: r.Tier || "Other",
        Assignments: 0,
        Permanent: 0,
        Eligible: 0,
        Users: 0,
        ServicePrincipals: 0,
      });
    }
    const e = by.get(name);
    e.Assignments++;
    if (/permanent/i.test(String(r.AssignmentType || ""))) e.Permanent++;
    if (/eligible/i.test(String(r.AssignmentType || ""))) e.Eligible++;
    if (/^user$/i.test(String(r.PrincipalType || ""))) e.Users++;
    if (/serviceprincipal/i.test(String(r.PrincipalType || ""))) e.ServicePrincipals++;
  }
  return [...by.values()].sort(
    (a, b) => b.Assignments - a.Assignments || a.RoleName.localeCompare(b.RoleName)
  );
}

/** PIM / portal probes are POST under /roleManagement but are not mutations. */
function isGraphApiProbeUri(uri) {
  return /checkaccess|estimateaccess/i.test(String(uri || ""));
}

function graphApiWriteHits(rows) {
  return (rows || []).filter((r) => {
    const u = `${r.SampleUris || ""} ${r.RequestUri || ""}`;
    if (isGraphApiProbeUri(u)) return false;
    return /conditionalaccess\/policies|roleassignments|roleassignmentschedule|roleeligibilityschedule|roleassignmentapprovals|oauth2permissiongrants|approleassignedto|authenticationmethods|updateallowedcombinations/i.test(
      u
    );
  });
}

function clusterAppControlPlane({
  gaPath = [],
  dangerous = [],
  priv = [],
  cloudAppAdminOps = [],
  graphApiAudit = [],
} = {}) {
  const apps = new Map();
  const touch = (name, field, value) => {
    const key = normName(name);
    if (!key || key === "?") return;
    if (!apps.has(key)) {
      apps.set(key, {
        name: String(name).replace(/\u202f/g, " ").trim(),
        perms: new Set(),
        entraRoles: new Set(),
        caWrite: false,
      });
    }
    const e = apps.get(key);
    if (field === "perm" && value) e.perms.add(value);
    if (field === "role" && value) e.entraRoles.add(value);
    if (field === "caWrite") e.caWrite = true;
  };

  for (const r of gaPath) {
    if (!GA_PATH_PERMS.has(r.Permission)) continue;
    touch(r.SPNDisplayName || r.DisplayName || r.PrincipalId, "perm", r.Permission);
  }
  for (const r of dangerous) {
    const perm = r.Permission || "";
    if (CA_WRITE_PERM.test(perm)) {
      touch(r.SPNDisplayName || r.DisplayName || r.AppName, "caWrite");
      touch(r.SPNDisplayName || r.DisplayName || r.AppName, "perm", perm);
    }
  }
  for (const r of priv) {
    if (!/serviceprincipal|service principal/i.test(r.PrincipalType || "")) continue;
    if (!GA_EQUIV_DIRECTORY_ROLES.test(r.RoleName || "")) continue;
    touch(r.PrincipalName || r.DisplayName || r.UPNOrAppId, "role", r.RoleName);
  }

  const caWriteOps = (cloudAppAdminOps || []).filter((r) =>
    /Set-ConditionalAccessPolicy|Update-.*ConditionalAccess|conditionalaccesspolicy/i.test(
      `${r.ActionType || ""} ${r.Application || ""}`
    )
  );
  const caWriteEvents = caWriteOps.reduce(
    (n, r) => n + Number(r.Events || 0),
    0
  );
  const graphHits = graphApiWriteHits(graphApiAudit);
  const graphApiWriteEvents = graphHits.reduce(
    (n, r) => n + Number(r.Events || 0),
    0
  );

  const list = [...apps.values()];
  const pathToGa = list.filter(
    (a) =>
      [...a.perms].some((p) => GA_PATH_PERMS.has(p)) || a.entraRoles.size > 0
  );
  const roleMgmt = list.filter((a) => a.perms.has("RoleManagement.ReadWrite.Directory"));
  const caWrite = list.filter((a) => a.caWrite);
  const names = (arr) => arr.map((a) => a.name);

  return {
    list,
    pathToGa,
    roleMgmt,
    caWrite,
    names,
    caWriteEvents,
    graphApiWriteEvents,
    roleMgmtCoveredByPathToGa:
      roleMgmt.length > 0 &&
      roleMgmt.every((a) => pathToGa.some((p) => normName(p.name) === normName(a.name))),
    caWriteCoveredByPathToGa:
      caWrite.length > 0 &&
      caWrite.every((a) => pathToGa.some((p) => normName(p.name) === normName(a.name))),
  };
}

function clusterAlertsBySource(rows) {
  const bySource = new Map();
  const byTitle = new Map();
  let high = 0;
  for (const r of rows || []) {
    const src = String(r.ServiceSource || "Unknown").trim() || "Unknown";
    bySource.set(src, (bySource.get(src) || 0) + 1);
    if (/high|critical/i.test(String(r.Severity || ""))) high++;
  }
  const highRows = (rows || []).filter((r) =>
    /high|critical/i.test(String(r.Severity || ""))
  );
  for (const r of highRows) {
    const t = String(r.Title || "?").replace(/\s+/g, " ").trim() || "?";
    const prev = byTitle.get(t) || {
      title: t,
      n: 0,
      source: r.ServiceSource || r.DetectionSource || "",
      last: r.LastSeen || "",
    };
    prev.n += Number(r.Count || 1) || 1;
    if (r.LastSeen && (!prev.last || String(r.LastSeen) > String(prev.last))) {
      prev.last = r.LastSeen;
    }
    byTitle.set(t, prev);
  }
  const irmHigh = highRows.filter((r) =>
    /insider risk|purview irm/i.test(
      `${r.ServiceSource || ""} ${r.Title || ""}`
    )
  ).length;
  const endpointHigh = highRows.filter((r) =>
    /defender for endpoint/i.test(String(r.ServiceSource || ""))
  ).length;
  const identityHigh = highRows.filter((r) =>
    /defender for identity/i.test(String(r.ServiceSource || ""))
  ).length;
  const mdcaHigh = highRows.filter((r) =>
    /cloud apps|mcas|defender for cloud/i.test(String(r.ServiceSource || ""))
  ).length;
  return {
    total: (rows || []).length,
    high,
    irmHigh,
    endpointHigh,
    identityHigh,
    mdcaHigh,
    titles: [...byTitle.values()].sort((a, b) => b.n - a.n),
    bySource: [...bySource.entries()].sort((a, b) => b[1] - a[1]),
  };
}

function caIsEnforced(r) {
  const st = String(r.State || "");
  return /^enabled$/i.test(st) || String(r.IsEnforced || "").toLowerCase() === "yes";
}

function includeAllUsersText(s) {
  return /all users|tous les utilisateurs|todos los usuarios|^all$/i.test(
    String(s || "").trim()
  );
}

/** Report-only CA that gates cloud apps on device compliance — not MAM / SecInfo. */
function isReportOnlyFleetComplianceRow(r) {
  const state = `${r.State || ""} ${r.IsEnforced || ""} ${r.RiskFlags || ""} ${r.Detail || ""}`;
  if (!/report.?only|enabledForReportingButNotEnforced/i.test(state)) return false;
  const blob = `${r.PolicyName || r.DisplayName || r.Name || ""} ${r.GrantControls || ""} ${r.RiskFlags || ""}`.toLowerCase();
  if (/security.?info|registersecurityinfo|enrollment/.test(blob)) return false;
  const mamOnly =
    /compliantapplication|requireappprotection|app protection|\bmam\b/.test(blob) &&
    !/compliantdevice|device.?compliance|domainjoineddevice/.test(blob);
  if (mamOnly) return false;
  return /compliantdevice|device.?compliance|domainjoineddevice|marked as compliant/.test(
    blob
  );
}

/** Sign-in / user-risk MFA is not daily population MFA. */
function caIsRiskGated(r) {
  const name = String(r.PolicyName || "");
  const grant = String(r.GrantControls || "");
  if (
    /identity protection|sign-?in risk|user risk|usuarios con riesgo|riesgo (alto|inicio)|risky sign-?ins?/i.test(
      name
    )
  ) {
    return true;
  }
  if (String(r.SignInRisk || "").trim() || String(r.UserRisk || "").trim()) {
    return true;
  }
  if (/passwordChange/i.test(grant)) return true;
  return false;
}

/**
 * Population MFA coverage: All-users MFA grant, not admin-portal / role-only /
 * Identity Protection risk policies. Group-scoped MFA is `scoped`, not `covered`.
 */
function detectEnforcedMfaCoverage(caAudit) {
  const allUsers = [];
  const scoped = [];
  for (const r of caAudit || []) {
    if (!caIsEnforced(r)) continue;
    const name = String(r.PolicyName || "");
    const grant = `${r.GrantControls || ""} ${r.AuthStrength || ""}`;
    const isMfa =
      /mfa|multifactor|authentication strength/i.test(`${name} ${grant}`) &&
      !/\bblock\b/i.test(String(r.GrantControls || ""));
    if (!isMfa) continue;
    if (caIsRiskGated(r)) continue;
    if (/admin portals?/i.test(name)) continue;

    const includeAllUsers =
      includeAllUsersText(r.IncludeUsers) || includeAllUsersText(r.IncludeUsersRaw);
    const inclGroups = String(r.IncludeGroups || "").trim();
    const inclRoles = String(r.IncludeRoles || "").trim();
    // Role-only MFA (Directory roles / admin portals) is not population coverage.
    // Empty users+groups with roles used to be treated as "All" — that was wrong.
    if (inclRoles && !includeAllUsers && !inclGroups) continue;

    if (includeAllUsers) {
      allUsers.push(name);
      continue;
    }
    if (inclGroups) scoped.push(name);
  }
  return {
    covered: allUsers.length > 0,
    scoped: scoped.length > 0,
    evidence: (allUsers.length ? allUsers : scoped).slice(0, 6),
    allUsersEvidence: allUsers.slice(0, 6),
    scopedEvidence: scoped.slice(0, 6),
  };
}

function spnIdentityKeys(r) {
  const keys = [];
  for (const v of [
    r.AppId,
    r.ServicePrincipalId,
    r.PrincipalId,
    r.App,
    r.AppDisplayName,
    r.SPNDisplayName,
    r.DisplayName,
    r.AppName,
  ]) {
    const s = String(v || "").trim().toLowerCase();
    if (s) keys.push(s);
  }
  return keys;
}

function buildSpnActivityIndex(signIns, digest) {
  const keys = new Set();
  for (const r of [...(signIns || []), ...(digest || [])]) {
    for (const k of spnIdentityKeys(r)) keys.add(k);
  }
  return keys;
}

function spnIsActive(entry, activityKeys) {
  if (!activityKeys || !activityKeys.size) return false;
  if (activityKeys.has(normName(entry.name))) return true;
  for (const id of entry.ids || []) {
    if (activityKeys.has(String(id).toLowerCase())) return true;
  }
  return false;
}

module.exports = {
  GA_PATH_PERMS,
  GA_EQUIV_DIRECTORY_ROLES,
  isUserActionOnlyPolicy,
  hasUserAction,
  isFleetDeviceCompliancePolicy,
  secInfoPolicyState,
  isOsSoftware,
  isRuntimeSoftware,
  splitTvmVulns,
  tvmSeverity,
  patchLagFromSoftwareVersions,
  aggregateFailuresByIp,
  isCopilotOrAgentUpn,
  identityInfoActionable,
  resolveDirectoryRoleName,
  directoryRoleTier,
  enrichDirectoryRoleRows,
  rollupDirectoryRoles,
  clusterAppControlPlane,
  graphApiWriteHits,
  isGraphApiProbeUri,
  clusterAlertsBySource,
  detectEnforcedMfaCoverage,
  caIsRiskGated,
  isReportOnlyFleetComplianceRow,
  buildSpnActivityIndex,
  spnIdentityKeys,
  spnIsActive,
  normName,
};
