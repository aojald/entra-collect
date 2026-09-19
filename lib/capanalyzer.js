/**
 * CapAnalyzer offline What-If extras (bounded by default).
 *
 * Emits:
 *   02_directory_principals_capanalyzer.json  — users/groups/apps/roles from CA
 *   02_user_memberships_capanalyzer.json      — transitiveMemberOf for a capped user set
 *   20_signIns_raw_capanalyzer.json           — raw Graph signIns sample for Sign-in Replay
 *
 * Cost (defaults): principals ≈ free (reuse resolver cache);
 * memberships ≈ 1 Graph call per user (capped); raw sign-ins ≈ 2–3 pages.
 */
const { soft } = require("./io");
const { GUID_RE } = require("./resolve");

function isGuid(id) {
  return GUID_RE.test(String(id || ""));
}

function pushUnique(set, values) {
  if (!values) return;
  for (const v of values) {
    if (v != null && String(v).trim() !== "") set.add(String(v));
  }
}

/** Collect every directory GUID referenced by CA include/exclude fields. */
function extractCaPrincipalIds(policies = []) {
  const users = new Set();
  const groups = new Set();
  const roles = new Set();
  const apps = new Set();

  for (const p of policies) {
    const u = (p.conditions && p.conditions.users) || {};
    const a = (p.conditions && p.conditions.applications) || {};
    pushUnique(users, u.includeUsers);
    pushUnique(users, u.excludeUsers);
    pushUnique(groups, u.includeGroups);
    pushUnique(groups, u.excludeGroups);
    pushUnique(roles, u.includeRoles);
    pushUnique(roles, u.excludeRoles);
    pushUnique(apps, a.includeApplications);
    pushUnique(apps, a.excludeApplications);
  }

  const stripTokens = (set) =>
    [...set].filter(
      (id) =>
        isGuid(id) &&
        !["all", "none", "guestsorexternalusers"].includes(id.toLowerCase())
    );

  return {
    users: stripTokens(users),
    groups: stripTokens(groups),
    roles: stripTokens(roles),
    apps: stripTokens(apps),
  };
}

function buildPrincipalCatalog(resolver, policies, roleDefMap = {}) {
  const ids = extractCaPrincipalIds(policies);
  const records = resolver.getPrincipalRecords
    ? resolver.getPrincipalRecords()
    : {};

  const users = [];
  const groups = [];
  const applications = [];
  const roles = [];
  const seen = new Set();

  function take(id, fallbackType) {
    if (!id || seen.has(id)) return;
    seen.add(id);
    const rec = records[id];
    if (rec) {
      if (rec.type === "user") users.push(rec);
      else if (rec.type === "group") groups.push(rec);
      else if (rec.type === "application") applications.push(rec);
      else if (rec.type === "role") roles.push(rec);
      else if (fallbackType === "user") {
        users.push({
          id,
          type: "user",
          displayName: rec.displayName || id,
          userPrincipalName: rec.userPrincipalName || "",
        });
      } else if (fallbackType === "group") {
        groups.push({
          id,
          type: "group",
          displayName: rec.displayName || id,
        });
      } else if (fallbackType === "application") {
        applications.push({
          id,
          type: "application",
          displayName: rec.displayName || id,
          appId: rec.appId || id,
        });
      } else if (fallbackType === "role") {
        roles.push({
          id,
          type: "role",
          displayName: rec.displayName || roleDefMap[id] || id,
        });
      }
      return;
    }
    if (fallbackType === "user") {
      users.push({ id, type: "user", displayName: id, userPrincipalName: "" });
    } else if (fallbackType === "group") {
      groups.push({ id, type: "group", displayName: id });
    } else if (fallbackType === "application") {
      applications.push({ id, type: "application", displayName: id, appId: id });
    } else if (fallbackType === "role") {
      roles.push({
        id,
        type: "role",
        displayName: roleDefMap[id] || id,
      });
    }
  }

  for (const id of ids.users) take(id, "user");
  for (const id of ids.groups) take(id, "group");
  for (const id of ids.apps) take(id, "application");
  for (const id of ids.roles) take(id, "role");

  // Also include any typed records already resolved (locations skipped)
  for (const rec of Object.values(records)) {
    if (!rec || !rec.id || seen.has(rec.id)) continue;
    if (rec.type === "user") {
      seen.add(rec.id);
      users.push(rec);
    } else if (rec.type === "group") {
      seen.add(rec.id);
      groups.push(rec);
    } else if (rec.type === "application") {
      seen.add(rec.id);
      applications.push(rec);
    } else if (rec.type === "role") {
      seen.add(rec.id);
      roles.push(rec);
    }
  }

  return {
    users,
    groups,
    applications,
    roles,
    _meta: {
      note: "Principals referenced by Conditional Access (plus resolver cache). For CapAnalyzer offline What-If.",
      userCount: users.length,
      groupCount: groups.length,
      applicationCount: applications.length,
      roleCount: roles.length,
    },
  };
}

/**
 * Pick user IDs for transitiveMemberOf.
 * Prefer CA-referenced users, then privileged principals.
 * @param {number|null} maxUsers  null / <=0 = no cap (all selected users)
 */
function selectMembershipUserIds({
  caUserIds = [],
  privilegedRows = [],
  maxUsers = null,
}) {
  const cap =
    maxUsers == null || !Number.isFinite(maxUsers) || maxUsers <= 0
      ? Infinity
      : maxUsers;
  const out = [];
  const seen = new Set();
  const add = (id) => {
    if (!id || !isGuid(id) || seen.has(id) || out.length >= cap) return;
    seen.add(id);
    out.push(id);
  };

  for (const id of caUserIds) add(id);
  for (const r of privilegedRows) {
    if ((r.PrincipalType || "").toLowerCase() === "user") add(r.PrincipalId);
  }
  return out;
}

async function fetchMembership(graph, userId) {
  const groupIds = [];
  const roleIds = [];
  const groupNames = [];
  const roleNames = [];

  let url =
    `${graph.GRAPH}/users/${encodeURIComponent(userId)}/transitiveMemberOf` +
    `?$select=id,displayName,roleTemplateId&$top=100`;
  let pages = 0;
  const maxPages = 3;

  while (url && pages < maxPages) {
    pages++;
    const data = await graph.get(url);
    const values = Array.isArray(data.value) ? data.value : [];
    for (const obj of values) {
      const type = (obj["@odata.type"] || "").split(".").pop();
      const id = obj.id;
      if (!id) continue;
      if (type === "group") {
        groupIds.push(id);
        if (obj.displayName) groupNames.push(obj.displayName);
      } else if (type === "directoryRole" || type === "directoryRoleTemplate") {
        // CA includeRoles uses role template IDs, not directoryRole instance IDs.
        roleIds.push(obj.roleTemplateId || id);
        if (obj.displayName) roleNames.push(obj.displayName);
      } else {
        // transitiveMemberOf returns #microsoft.graph.group and directoryRole;
        // some tenants omit type — treat unknown GUID as group for What-If.
        groupIds.push(id);
        if (obj.displayName) groupNames.push(obj.displayName);
      }
    }
    url = data["@odata.nextLink"] || null;
  }

  return { groupIds, roleIds, groupNames, roleNames };
}

async function collectMemberships(graph, io, userIds, { maxUsers = null } = {}) {
  const cap =
    maxUsers == null || !Number.isFinite(maxUsers) || maxUsers <= 0
      ? userIds.length
      : maxUsers;
  const limited = userIds.slice(0, cap);
  const memberships = {};
  let ok = 0;
  let failed = 0;
  /** CA policies still reference these ids, but the objects no longer exist. */
  const orphans = [];

  for (let i = 0; i < limited.length; i++) {
    const userId = limited[i];
    const label = `capanalyzer_memberOf_${userId}`;
    const result = await soft(
      label,
      async () => {
        try {
          return await fetchMembership(graph, userId);
        } catch (e) {
          // A deleted user is a finding about the policy, not a collection
          // error — record it instead of writing an ERROR_* file.
          if (e && e.status === 404) return { orphan: true };
          throw e;
        }
      },
      io
    );
    if (result && result.orphan) {
      orphans.push(userId);
    } else if (result) {
      memberships[userId] = result;
      ok++;
    } else {
      failed++;
    }
    if ((i + 1) % 10 === 0 || i === limited.length - 1) {
      console.log(
        `  CapAnalyzer memberships ${i + 1}/${limited.length} (ok=${ok} fail=${failed})`
      );
    }
  }

  return {
    memberships,
    orphans,
    _meta: {
      note: "transitiveMemberOf for CapAnalyzer offline What-If (CA-referenced + privileged users).",
      requested: limited.length,
      resolved: ok,
      failed,
      orphaned: orphans.length,
      maxUsers: maxUsers == null || maxUsers <= 0 ? null : maxUsers,
    },
  };
}

/**
 * Raw Graph sign-ins sample (not CSV-mapped) for CapAnalyzer Sign-in Replay.
 * Caps pages so this stays a few Graph calls, not a full tenant dump.
 */
async function collectRawSignIns(
  graph,
  io,
  { days = 30, maxPages = 3, top = 200 } = {}
) {
  const since = new Date(Date.now() - days * 86400000).toISOString();
  // Prefer interactive user sign-ins — SPN noise is less useful for CA What-If.
  const filter = `createdDateTime ge ${since} and signInEventTypes/any(t: t eq 'interactiveUser')`;
  const fallbackFilter = `createdDateTime ge ${since}`;

  const items = await soft(
    "capanalyzer_rawSignIns",
    async () => {
      const { getSignIns } = require("./logs");
      try {
        const interactive = await getSignIns(graph, filter, { maxPages, top });
        if (interactive && interactive.length) return interactive;
      } catch {
        /* older tenants may reject signInEventTypes filter */
      }
      return getSignIns(graph, fallbackFilter, { maxPages, top });
    },
    io
  );

  if (!items) return null;

  return {
    "@odata.context":
      "https://graph.microsoft.com/v1.0/$metadata#auditLogs/signIns (sample for CAPAnalyzer)",
    value: items,
    _meta: {
      note: "Bounded raw Graph signIns for CapAnalyzer Sign-in Replay → What-If. Not a full export.",
      days,
      maxPages,
      top,
      count: items.length,
    },
  };
}

/**
 * Main entry — call after CA resolution (+ privileged rows when available).
 */
async function collectCapAnalyzerOfflinePack(
  graph,
  io,
  {
    policies = [],
    resolver,
    roleDefMap = {},
    privilegedRows = [],
    maxMembershipUsers = null,
    signInDays = 30,
    signInMaxPages = 3,
    signInTop = 200,
    includeSignIns = true,
    includeMemberships = true,
    includePrincipals = true,
  } = {}
) {
  if (!policies.length) {
    console.log("  CapAnalyzer offline pack skipped (no CA policies)");
    return null;
  }

  console.log("── CapAnalyzer offline What-If pack");

  let catalog = null;
  if (includePrincipals) {
    catalog = buildPrincipalCatalog(resolver, policies, roleDefMap);
    io.saveJson("02_directory_principals_capanalyzer.json", catalog);
    console.log(
      `  Principals: ${catalog._meta.userCount} users, ${catalog._meta.groupCount} groups, ${catalog._meta.applicationCount} apps, ${catalog._meta.roleCount} roles`
    );
  }

  const caIds = extractCaPrincipalIds(policies);
  const membershipUserIds = selectMembershipUserIds({
    caUserIds: caIds.users,
    privilegedRows,
    maxUsers: maxMembershipUsers,
  });

  let membershipPack = null;
  if (includeMemberships) {
    if (membershipUserIds.length) {
      const capLabel =
        maxMembershipUsers == null || maxMembershipUsers <= 0
          ? "no cap"
          : `cap ${maxMembershipUsers}`;
      console.log(
        `  Memberships: expanding transitiveMemberOf for ${membershipUserIds.length} user(s) (${capLabel})…`
      );
      membershipPack = await collectMemberships(graph, io, membershipUserIds, {
        maxUsers: maxMembershipUsers,
      });
      io.saveJson("02_user_memberships_capanalyzer.json", membershipPack);
    } else {
      console.log("  Memberships: no CA/privileged user IDs to expand");
    }
  }

  let signInPack = null;
  if (includeSignIns) {
    console.log(
      `  Raw sign-ins: sampling up to ${signInMaxPages * signInTop} interactive events / ${signInDays}d…`
    );
    signInPack = await collectRawSignIns(graph, io, {
      days: signInDays,
      maxPages: signInMaxPages,
      top: signInTop,
    });
    if (signInPack) {
      io.saveJson("20_signIns_raw_capanalyzer.json", signInPack);
      console.log(`  Raw sign-ins: saved ${signInPack._meta.count} events`);
    } else {
      console.log("  Raw sign-ins: skipped (no AuditLog permission or empty)");
    }
  }

  return {
    catalog,
    membershipPack,
    signInPack,
  };
}

module.exports = {
  collectCapAnalyzerOfflinePack,
  buildPrincipalCatalog,
  extractCaPrincipalIds,
  selectMembershipUserIds,
  collectMemberships,
  collectRawSignIns,
};
