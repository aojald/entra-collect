/**
 * Directory role model.
 *
 * `/roleManagement/directory/roleAssignments` alone gets three things wrong
 * for an assessment: a PIM activation looks permanent, a role-assignable group
 * hides its members, and an assignment scoped to one Administrative Unit or one
 * app counts like a tenant-wide one. This module returns one row per
 * *effective* principal with its assignment type and scope, so the checks can
 * score standing, tenant-wide access and nothing else.
 */
const { soft, STATUS, classifyStepError, ERROR_KIND } = require("./io");

/**
 * Roles treated as high-value even when Graph does not expose `isPrivileged`
 * (v1.0 role definitions omit it). Identity control plane + roles with a known
 * path to Global Administrator.
 */
const BASELINE_HIGH_PRIV = new Set([
  "Global Administrator",
  "Privileged Role Administrator",
  "Privileged Authentication Administrator",
  "Security Administrator",
  "Application Administrator",
  "Cloud Application Administrator",
  "User Administrator",
  "Authentication Administrator",
  "Authentication Policy Administrator",
  "Exchange Administrator",
  "SharePoint Administrator",
  "Intune Administrator",
  "Helpdesk Administrator",
  "Password Administrator",
  "Billing Administrator",
  "Conditional Access Administrator",
  "Directory Synchronization Accounts",
  "Hybrid Identity Administrator",
  "Domain Name Administrator",
  "External Identity Provider Administrator",
  "Directory Writers",
  "Application Developer",
  "Cloud Device Administrator",
  "Partner Tier1 Support",
  "Partner Tier2 Support",
  "Global Reader",
  "Security Operator",
  "Groups Administrator",
  "Identity Governance Administrator",
  "Lifecycle Workflows Administrator",
  "Attribute Assignment Administrator",
  "Attribute Definition Administrator",
]);

const ASSIGNMENT = {
  PERMANENT: "Permanent",
  ACTIVATED: "PIM — Active (activated)",
  ELIGIBLE: "PIM — Eligible",
};

const ROLE_TIER_ORDER = { Tenant: 0, AU: 1, App: 2, Other: 3 };

/** Parse `directoryScopeId` into a scope kind + raw id. */
function parseScope(directoryScopeId) {
  const s = String(directoryScopeId || "/").trim();
  if (!s || s === "/") return { kind: "Tenant", id: "" };
  const au = s.match(/^\/administrativeUnits\/([^/]+)$/i);
  if (au) return { kind: "AU", id: au[1] };
  const app = s.match(/^\/([0-9a-f-]{36})$/i);
  if (app) return { kind: "App", id: app[1] };
  return { kind: "Other", id: s };
}

/** Principal object → normalised label fields. */
function describePrincipal(p, fallbackId) {
  const raw = (p && p["@odata.type"]) || "";
  const type = (raw.split(".").pop() || "").replace(/^#/, "") || "unknown";
  return {
    id: (p && p.id) || fallbackId || "",
    type,
    displayName: (p && p.displayName) || "",
    upnOrAppId:
      (p && p.userPrincipalName) ||
      (p && p.appId ? `appId: ${p.appId}` : "") ||
      (p && p.mail) ||
      "",
    accountEnabled: p && typeof p.accountEnabled === "boolean" ? p.accountEnabled : null,
    userType: (p && p.userType) || "",
  };
}

/**
 * Pure: build the assignment rows from Graph payloads.
 *
 * @param {object} input
 * @param {object[]} [input.scheduleInstances] roleAssignmentScheduleInstances (P2)
 * @param {object[]} [input.assignments] roleAssignments (fallback)
 * @param {object[]} [input.eligibility] roleEligibilityScheduleInstances or Schedules
 * @param {Object<string,object>} input.roleDefById id → { displayName, isPrivileged }
 * @param {Object<string,object[]>} [input.groupMembers] groupId → transitiveMembers
 * @param {Object<string,string>} [input.scopeNames] scope id → display name
 */
function buildRoleRows({
  scheduleInstances = null,
  assignments = null,
  eligibility = [],
  roleDefById = {},
  groupMembers = {},
  scopeNames = {},
}) {
  const rows = [];
  const roleName = (id) => (roleDefById[id] && roleDefById[id].displayName) || id;
  const isPriv = (id) => {
    const d = roleDefById[id];
    const name = roleName(id);
    return !!((d && d.isPrivileged) || BASELINE_HIGH_PRIV.has(name));
  };

  function emit(a, assignmentType, principal) {
    const scope = parseScope(a.directoryScopeId || a.appScopeId);
    const p = describePrincipal(principal, a.principalId);
    const base = {
      RoleName: roleName(a.roleDefinitionId),
      RoleId: a.roleDefinitionId || "",
      IsPrivilegedRole: isPriv(a.roleDefinitionId),
      PrincipalName: p.displayName,
      PrincipalType: p.type,
      UPNOrAppId: p.upnOrAppId,
      AccountEnabled: p.accountEnabled,
      UserType: p.userType,
      AssignmentType: assignmentType,
      PIMEnabled: assignmentType === ASSIGNMENT.PERMANENT ? "No" : "Yes",
      EndDateTime: a.endDateTime || "",
      Scope: scope.kind,
      ScopeId: scope.id,
      ScopeName: scope.id ? scopeNames[scope.id] || "" : "",
      PrincipalId: p.id,
      ViaGroup: "",
      ViaGroupId: "",
    };
    rows.push(base);

    if (p.type === "group") {
      const members = groupMembers[p.id];
      if (Array.isArray(members)) {
        for (const m of members) {
          const mp = describePrincipal(m, m && m.id);
          if (mp.type === "group") continue; // transitive already flattened
          rows.push({
            ...base,
            PrincipalName: mp.displayName,
            PrincipalType: mp.type,
            UPNOrAppId: mp.upnOrAppId,
            AccountEnabled: mp.accountEnabled,
            UserType: mp.userType,
            PrincipalId: mp.id,
            ViaGroup: p.displayName || p.id,
            ViaGroupId: p.id,
          });
        }
      }
    }
  }

  if (Array.isArray(scheduleInstances)) {
    for (const a of scheduleInstances) {
      const activated = /activated/i.test(String(a.assignmentType || ""));
      emit(a, activated ? ASSIGNMENT.ACTIVATED : ASSIGNMENT.PERMANENT, a.principal);
    }
  } else if (Array.isArray(assignments)) {
    for (const a of assignments) emit(a, ASSIGNMENT.PERMANENT, a.principal);
  }
  for (const e of eligibility || []) emit(e, ASSIGNMENT.ELIGIBLE, e.principal);

  return rows;
}

/** Rows that count as standing, tenant-wide privileged access. */
function isStandingTenantWide(r) {
  return r.AssignmentType === ASSIGNMENT.PERMANENT && r.Scope === "Tenant";
}

/**
 * Pure: KPIs over the effective rows (group rows themselves excluded because
 * their members are expanded).
 */
function summarizeRoles(rows) {
  const effective = rows.filter((r) => r.PrincipalType !== "group");
  const gaPerm = new Set();
  const gaActivated = new Set();
  const gaEligible = new Set();
  for (const r of effective) {
    if (r.RoleName !== "Global Administrator") continue;
    const key = r.PrincipalId || r.UPNOrAppId;
    if (r.AssignmentType === ASSIGNMENT.PERMANENT) gaPerm.add(key);
    else if (r.AssignmentType === ASSIGNMENT.ACTIVATED) gaActivated.add(key);
    else gaEligible.add(key);
  }
  return {
    assignmentsTotal: rows.length,
    effectivePrincipals: effective.length,
    globalAdminPermanent: gaPerm.size,
    globalAdminActivated: gaActivated.size,
    globalAdminEligible: gaEligible.size,
    pimEligibleCount: rows.filter((r) => r.AssignmentType === ASSIGNMENT.ELIGIBLE).length,
    viaGroupRows: rows.filter((r) => r.ViaGroup).length,
    scopedRows: rows.filter((r) => r.Scope !== "Tenant").length,
  };
}

async function fetchRoleDefinitions(graph, io) {
  // beta carries isPrivileged; v1.0 does not. Try beta, fall back silently.
  let defs = null;
  let source = "beta";
  try {
    defs = await graph.getAll(
      `${graph.GRAPH_BETA}/roleManagement/directory/roleDefinitions?$select=id,displayName,templateId,isPrivileged,isBuiltIn`
    );
  } catch {
    defs = null;
  }
  if (!Array.isArray(defs)) {
    source = "v1.0";
    defs = await soft(
      "roleDefinitions",
      () => graph.getAll(`${graph.GRAPH}/roleManagement/directory/roleDefinitions`),
      io
    );
  } else {
    io.recordStep("roleDefinitions", STATUS.OK, { source });
    io.clearError("roleDefinitions");
  }
  const roleDefMap = {};
  const roleDefById = {};
  if (Array.isArray(defs)) {
    for (const d of defs) {
      roleDefMap[d.id] = d.displayName;
      roleDefById[d.id] = {
        displayName: d.displayName,
        isPrivileged: d.isPrivileged === true,
        templateId: d.templateId,
      };
    }
    io.saveJson("03_role_definitions.json", defs);
  }
  return { defs, roleDefMap, roleDefById, source };
}

/**
 * Collect assignments + eligibility, expand groups, resolve scopes.
 * Returns null-safe structures; `collected` is false when no assignment
 * source could be read (callers must then score NotEvaluated).
 */
async function collectRoleAssignments(graph, io, { roleDefById = {}, facts = null, maxGroupExpansions = 50 } = {}) {
  // 1) Active assignments: schedule instances distinguish Assigned vs Activated.
  let scheduleInstances = null;
  let assignments = null;
  let licenceBlocked = false;
  try {
    scheduleInstances = await graph.getAll(
      `${graph.GRAPH}/roleManagement/directory/roleAssignmentScheduleInstances?$expand=principal`
    );
    io.recordStep("roleAssignmentScheduleInstances", STATUS.OK);
    io.clearError("roleAssignmentScheduleInstances");
  } catch (e) {
    const kind = classifyStepError(e);
    licenceBlocked = kind === ERROR_KIND.LICENCE;
    io.recordStep("roleAssignmentScheduleInstances", STATUS.SKIPPED, {
      reason: licenceBlocked ? "no PIM licence" : String(e.message || e).split("\n")[0].slice(0, 200),
      kind,
    });
    scheduleInstances = null;
  }
  if (!Array.isArray(scheduleInstances)) {
    assignments = await soft(
      "roleAssignments",
      async () => {
        try {
          return await graph.getAll(
            `${graph.GRAPH}/roleManagement/directory/roleAssignments?$expand=principal`
          );
        } catch (e) {
          if (e && e.status === 400) {
            return graph.getAll(`${graph.GRAPH}/roleManagement/directory/roleAssignments`);
          }
          throw e;
        }
      },
      io
    );
  }

  // 2) Eligibility (P2 / Governance only).
  let eligibility = null;
  if (!licenceBlocked || (facts && facts.licences && facts.licences.pim)) {
    eligibility = await soft(
      "roleEligibility",
      () =>
        graph.getAll(
          `${graph.GRAPH}/roleManagement/directory/roleEligibilityScheduleInstances?$expand=principal`
        ),
      io
    );
  } else {
    io.skip("roleEligibility", "no PIM licence (roleAssignmentScheduleInstances refused)");
  }

  const collected = Array.isArray(scheduleInstances) || Array.isArray(assignments);
  if (!collected) {
    return {
      collected: false,
      rows: [],
      source: null,
      eligibilityCollected: Array.isArray(eligibility),
      groupExpansion: { requested: 0, expanded: 0, truncated: false },
    };
  }

  // 3) Principals without an expanded object (fallback path) → resolve.
  const all = [...(scheduleInstances || assignments || []), ...(eligibility || [])];
  const principalCache = new Map();
  for (const a of all) {
    if (a.principal || !a.principalId) continue;
    if (!principalCache.has(a.principalId)) {
      let obj = null;
      try {
        obj = await graph.get(`${graph.GRAPH}/directoryObjects/${a.principalId}`);
      } catch {
        obj = { id: a.principalId };
      }
      principalCache.set(a.principalId, obj);
    }
    a.principal = principalCache.get(a.principalId);
  }

  // 4) Expand group principals (role-assignable groups, PIM for Groups).
  const groupIds = [
    ...new Set(
      all
        .filter((a) => /group$/i.test(String((a.principal && a.principal["@odata.type"]) || "")))
        .map((a) => a.principalId)
        .filter(Boolean)
    ),
  ];
  const groupMembers = {};
  const toExpand = groupIds.slice(0, maxGroupExpansions);
  for (const gid of toExpand) {
    const members = await soft(
      `roleGroupMembers_${gid}`,
      () =>
        graph.getAll(
          `${graph.GRAPH}/groups/${gid}/transitiveMembers?$select=id,displayName,userPrincipalName,accountEnabled,userType,appId&$top=999`
        ),
      io
    );
    if (Array.isArray(members)) groupMembers[gid] = members;
  }

  // 5) Scope names (AUs) — best effort, capped.
  const scopeNames = {};
  const auIds = [
    ...new Set(
      all
        .map((a) => parseScope(a.directoryScopeId))
        .filter((s) => s.kind === "AU")
        .map((s) => s.id)
    ),
  ].slice(0, 40);
  for (const id of auIds) {
    try {
      const au = await graph.get(
        `${graph.GRAPH}/directory/administrativeUnits/${id}?$select=id,displayName,isMemberManagementRestricted`
      );
      scopeNames[id] = au.displayName
        ? `${au.displayName}${au.isMemberManagementRestricted ? " (restricted AU)" : ""}`
        : id;
    } catch {
      scopeNames[id] = id;
    }
  }

  const rows = buildRoleRows({
    scheduleInstances,
    assignments,
    eligibility: eligibility || [],
    roleDefById,
    groupMembers,
    scopeNames,
  });

  return {
    collected: true,
    rows,
    source: Array.isArray(scheduleInstances) ? "roleAssignmentScheduleInstances" : "roleAssignments",
    eligibilityCollected: Array.isArray(eligibility),
    groupExpansion: {
      requested: groupIds.length,
      expanded: Object.keys(groupMembers).length,
      truncated: groupIds.length > toExpand.length,
    },
  };
}

/** High-value slice: privileged role, effective principal (not the group shell). */
function highValueRows(rows) {
  return rows.filter((r) => r.IsPrivilegedRole && r.PrincipalType !== "group");
}

module.exports = {
  BASELINE_HIGH_PRIV,
  ASSIGNMENT,
  ROLE_TIER_ORDER,
  parseScope,
  describePrincipal,
  buildRoleRows,
  summarizeRoles,
  isStandingTenantWide,
  highValueRows,
  fetchRoleDefinitions,
  collectRoleAssignments,
};
