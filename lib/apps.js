/**
 * Application / service-principal attack surface.
 *
 * Three things the Graph-only view missed:
 *  1. App roles on resources other than Microsoft Graph — `full_access_as_app`
 *     and `Exchange.ManageAsApp` live on the Exchange Online service
 *     principal, SharePoint has its own `Sites.FullControl.All`, and the legacy
 *     Azure AD Graph still grants `Directory.ReadWrite.All`.
 *  2. Delegated grants consented for every user (`consentType=AllPrincipals`).
 *  3. Credentials added to a service principal — in particular to a Microsoft
 *     first-party one, which is the classic persistence backdoor.
 */
const { soft } = require("./io");

/** Resource service principals whose app roles matter. */
const RESOURCES = {
  graph: { appId: "00000003-0000-0000-c000-000000000000", label: "Microsoft Graph" },
  exo: { appId: "00000002-0000-0ff1-ce00-000000000000", label: "Office 365 Exchange Online" },
  spo: { appId: "00000003-0000-0ff1-ce00-000000000000", label: "Office 365 SharePoint Online" },
  aadGraph: { appId: "00000002-0000-0000-c000-000000000000", label: "Windows Azure Active Directory" },
};

/** Tenant ids Microsoft publishes first-party apps from. */
const MICROSOFT_OWNER_TENANTS = new Set([
  "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
  "72f988bf-86f1-41af-91ab-2d7cd011db47",
]);

/** Application permissions (app roles) by resource → permission → severity. */
const DANGEROUS_APP_ROLES = {
  [RESOURCES.graph.appId]: {
    "RoleManagement.ReadWrite.Directory": "Critical",
    "AppRoleAssignment.ReadWrite.All": "Critical",
    "Application.ReadWrite.All": "Critical",
    "Directory.ReadWrite.All": "Critical",
    "PrivilegedAccess.ReadWrite.AzureAD": "Critical",
    "Policy.ReadWrite.ConditionalAccess": "Critical",
    "Policy.ReadWrite.AuthenticationMethod": "Critical",
    "Policy.ReadWrite.PermissionGrant": "Critical",
    "DelegatedPermissionGrant.ReadWrite.All": "Critical",
    "UserAuthenticationMethod.ReadWrite.All": "Critical",
    "User-PasswordProfile.ReadWrite.All": "Critical",
    "Domain.ReadWrite.All": "Critical",
    "User.ReadWrite.All": "Critical",
    "Mail.ReadWrite": "Critical",
    "Files.ReadWrite.All": "Critical",
    "Sites.FullControl.All": "Critical",
    "DeviceManagementManagedDevices.PrivilegedOperations.All": "Critical",
    "Application.ReadWrite.OwnedBy": "High",
    "Group.ReadWrite.All": "High",
    "GroupMember.ReadWrite.All": "High",
    "User.EnableDisableAccount.All": "High",
    "User.ManageIdentities.All": "High",
    "Mail.Read": "High",
    "Mail.Send": "High",
    "Calendars.ReadWrite": "High",
    "Chat.ReadWrite.All": "High",
    "Sites.ReadWrite.All": "High",
    "Organization.ReadWrite.All": "High",
    "EntitlementManagement.ReadWrite.All": "High",
    "DeviceManagementConfiguration.ReadWrite.All": "High",
    "DeviceManagementRBAC.ReadWrite.All": "High",
    "Directory.Read.All": "Medium",
    "User.Read.All": "Medium",
    "Files.Read.All": "Medium",
    "Sites.Read.All": "Medium",
    "AuditLog.Read.All": "Medium",
  },
  [RESOURCES.exo.appId]: {
    full_access_as_app: "Critical",
    "Exchange.ManageAsApp": "Critical",
    "Mail.ReadWrite": "Critical",
    "Mail.Read": "High",
    "Mail.Send": "High",
    "MailboxSettings.ReadWrite": "High",
    "Calendars.ReadWrite.All": "High",
    "Contacts.ReadWrite": "Medium",
  },
  [RESOURCES.spo.appId]: {
    "Sites.FullControl.All": "Critical",
    "User.ReadWrite.All": "Critical",
    "Sites.ReadWrite.All": "High",
    "Sites.Manage.All": "High",
    "TermStore.ReadWrite.All": "Medium",
    "Sites.Read.All": "Medium",
  },
  [RESOURCES.aadGraph.appId]: {
    "Directory.ReadWrite.All": "Critical",
    "Application.ReadWrite.All": "Critical",
    "Application.ReadWrite.OwnedBy": "High",
    "Device.ReadWrite.All": "High",
    "Directory.Read.All": "Medium",
    "Member.Read.Hidden": "Medium",
  },
};

/** Delegated scopes that are worth a finding when consented for all users. */
const DANGEROUS_DELEGATED = {
  "Directory.AccessAsUser.All": "Critical",
  "RoleManagement.ReadWrite.Directory": "Critical",
  "Application.ReadWrite.All": "Critical",
  "Directory.ReadWrite.All": "Critical",
  "Policy.ReadWrite.ConditionalAccess": "Critical",
  "UserAuthenticationMethod.ReadWrite.All": "Critical",
  "AppRoleAssignment.ReadWrite.All": "Critical",
  "Mail.ReadWrite": "High",
  "Mail.ReadWrite.Shared": "High",
  "Mail.Send": "High",
  "Mail.Send.Shared": "High",
  "Files.ReadWrite.All": "High",
  "Sites.ReadWrite.All": "High",
  "Sites.FullControl.All": "Critical",
  "User.ReadWrite.All": "High",
  "Group.ReadWrite.All": "High",
  "Mail.Read": "Medium",
  "Files.Read.All": "Medium",
  "Directory.Read.All": "Medium",
  "EWS.AccessAsUser.All": "High",
  full_access_as_user: "High",
  "user_impersonation": "Medium",
  offline_access: "",
};

const SEV_RANK = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

function isMicrosoftOwned(sp) {
  const owner = String((sp && sp.appOwnerOrganizationId) || "").toLowerCase();
  return MICROSOFT_OWNER_TENANTS.has(owner);
}

/** Severity of an application permission on a given resource, or null. */
function classifyAppRole(resourceAppId, permission) {
  const map = DANGEROUS_APP_ROLES[String(resourceAppId || "").toLowerCase()];
  return (map && map[permission]) || null;
}

/**
 * Pure: rows for `04_SPN_DangerousPerms.csv`.
 * @param {Array<{resource: object, sp: object, assignments: object[]}>} perResource
 *   resource = RESOURCES entry, sp = resource service principal (with appRoles),
 *   assignments = appRoleAssignedTo rows.
 */
function buildDangerousRows(perResource) {
  const rows = [];
  for (const { resource, sp, assignments } of perResource) {
    const permMap = {};
    for (const r of (sp && sp.appRoles) || []) permMap[r.id] = r.value;
    for (const a of assignments || []) {
      const perm = permMap[a.appRoleId];
      if (!perm) continue;
      const sev = classifyAppRole(resource.appId, perm);
      if (!sev) continue;
      rows.push({
        SPNDisplayName: a.principalDisplayName,
        PrincipalId: a.principalId,
        PrincipalType: a.principalType,
        Permission: perm,
        Severity: sev,
        ResourceApp: a.resourceDisplayName || resource.label,
        ResourceAppId: resource.appId,
        CreatedDateTime: a.createdDateTime,
      });
    }
  }
  return rows.sort((a, b) => SEV_RANK[a.Severity] - SEV_RANK[b.Severity]);
}

/**
 * Pure: rows for `04_Delegated_Grants_AllPrincipals.csv`.
 * @param {object[]} grants oauth2PermissionGrants (consentType AllPrincipals)
 * @param {Map<string, object>} spById service principal object id → sp
 */
function buildDelegatedGrantRows(grants, spById) {
  const rows = [];
  for (const g of grants || []) {
    const client = spById.get(g.clientId) || {};
    const resource = spById.get(g.resourceId) || {};
    const scopes = String(g.scope || "")
      .split(/\s+/)
      .filter(Boolean);
    const scored = scopes
      .map((s) => ({ scope: s, sev: DANGEROUS_DELEGATED[s] || "" }))
      .filter((x) => x.sev);
    const worst = scored.map((x) => x.sev).sort((a, b) => SEV_RANK[a] - SEV_RANK[b])[0] || "";
    rows.push({
      ClientDisplayName: client.displayName || g.clientId,
      ClientId: g.clientId,
      ClientAppId: client.appId || "",
      MicrosoftOwned: isMicrosoftOwned(client),
      ResourceDisplayName: resource.displayName || g.resourceId,
      ResourceAppId: resource.appId || "",
      Scopes: scopes.join(" "),
      DangerousScopes: scored.map((x) => x.scope).join(" "),
      MaxSeverity: worst,
      ConsentType: g.consentType,
      GrantId: g.id,
    });
  }
  return rows.sort((a, b) => (SEV_RANK[a.MaxSeverity] ?? 9) - (SEV_RANK[b.MaxSeverity] ?? 9));
}

const TWO_YEARS_DAYS = 730;

/**
 * Pure: one row per credential on a service principal object.
 * Credentials on the *service principal* (not the app registration) are
 * exactly where a backdoor lands when someone adds a secret to a first-party
 * or gallery app.
 */
function buildSpCredentialRows(sps, now = Date.now()) {
  const rows = [];
  for (const sp of sps || []) {
    const creds = [
      ...((sp.passwordCredentials || []).map((c) => ({ ...c, _kind: "secret" }))),
      ...((sp.keyCredentials || []).map((c) => ({ ...c, _kind: "certificate" }))),
    ];
    for (const c of creds) {
      const start = Date.parse(c.startDateTime || "");
      const end = Date.parse(c.endDateTime || "");
      const lifetimeDays =
        Number.isFinite(start) && Number.isFinite(end)
          ? Math.round((end - start) / 86400000)
          : null;
      const daysLeft = Number.isFinite(end) ? Math.floor((end - now) / 86400000) : null;
      const msOwned = isMicrosoftOwned(sp);
      rows.push({
        SPNDisplayName: sp.displayName || "",
        ServicePrincipalId: sp.id,
        AppId: sp.appId || "",
        ServicePrincipalType: sp.servicePrincipalType || "",
        AccountEnabled: sp.accountEnabled,
        MicrosoftOwned: msOwned,
        AppOwnerTenant: sp.appOwnerOrganizationId || "",
        CredentialType: c._kind,
        CredentialName: c.displayName || "",
        KeyId: c.keyId || "",
        Start: c.startDateTime || "",
        End: c.endDateTime || "",
        LifetimeDays: lifetimeDays,
        DaysLeft: daysLeft,
        Expired: daysLeft != null && daysLeft < 0,
        LongLived: lifetimeDays != null && lifetimeDays > TWO_YEARS_DAYS,
        Risk: msOwned
          ? "Critical — credential on a Microsoft first-party service principal (persistence backdoor pattern)"
          : lifetimeDays != null && lifetimeDays > TWO_YEARS_DAYS && c._kind === "secret"
            ? "High — client secret valid > 2 years"
            : daysLeft != null && daysLeft < 0
              ? "Info — expired"
              : "",
      });
    }
  }
  return rows;
}

/**
 * Collect everything. `sources` tells the checker which parts actually came back.
 */
async function collectAppSurface(graph, io, findings, summary) {
  console.log("── Apps / service principals (multi-resource roles, delegated grants, credentials)");

  // All service principals: one pass feeds the credential check and the
  // id → name index for delegated grants.
  const sps = await soft(
    "servicePrincipals",
    () =>
      graph.getAll(
        `${graph.GRAPH}/servicePrincipals?$select=id,appId,displayName,appOwnerOrganizationId,servicePrincipalType,accountEnabled,passwordCredentials,keyCredentials,createdDateTime,appRoles&$top=999`,
        400
      ),
    io
  );
  const spById = new Map();
  const spByAppId = new Map();
  if (Array.isArray(sps)) {
    for (const sp of sps) {
      spById.set(sp.id, sp);
      if (sp.appId) spByAppId.set(String(sp.appId).toLowerCase(), sp);
    }
    summary.servicePrincipalCount = sps.length;
    if (sps.truncated) {
      findings.push({
        Severity: "Info",
        Area: "Coverage",
        Detail: `Service-principal inventory capped at ${sps.length} objects — credential and delegated-grant checks are partial`,
      });
    }
  }

  // App-role assignments per resource.
  const perResource = [];
  let graphAssignmentsOk = false;
  for (const [key, res] of Object.entries(RESOURCES)) {
    let sp = spByAppId.get(res.appId);
    if (!sp || !Array.isArray(sp.appRoles)) {
      const fetched = await soft(
        `resourceSP_${key}`,
        () => graph.getAll(`${graph.GRAPH}/servicePrincipals?$filter=appId eq '${res.appId}'`),
        io
      );
      sp = Array.isArray(fetched) ? fetched[0] : null;
    }
    if (!sp) {
      if (key !== "graph") io.skip(`appRoleAssignedTo_${key}`, "resource service principal not present in tenant");
      continue;
    }
    const assignments = await soft(
      key === "graph" ? "graphAppRoleAssignedTo" : `appRoleAssignedTo_${key}`,
      () => graph.getAll(`${graph.GRAPH}/servicePrincipals/${sp.id}/appRoleAssignedTo`),
      io
    );
    if (Array.isArray(assignments)) {
      perResource.push({ resource: res, sp, assignments });
      if (key === "graph") graphAssignmentsOk = true;
    }
  }
  const dangerousSpnRows = buildDangerousRows(perResource);
  if (perResource.length) {
    io.saveCsv("04_SPN_DangerousPerms.csv", dangerousSpnRows);
    summary.dangerousSpnPermissions = dangerousSpnRows.length;
    summary.dangerousSpnResources = perResource.map((p) => p.resource.label).join(" | ");
    const nonGraph = dangerousSpnRows.filter((r) => r.ResourceAppId !== RESOURCES.graph.appId);
    if (nonGraph.length) {
      const crit = nonGraph.filter((r) => r.Severity === "Critical");
      findings.push({
        Severity: crit.length ? "High" : "Medium",
        Area: "AppPermissions",
        Detail:
          `${nonGraph.length} application permission(s) on Exchange / SharePoint / legacy AAD Graph resources` +
          (crit.length
            ? ` (${crit.length} Critical, e.g. ${[...new Set(crit.map((r) => `${r.SPNDisplayName}:${r.Permission}`))].slice(0, 3).join(", ")})`
            : "") +
          " — 04_SPN_DangerousPerms.csv",
      });
    }
  }

  // Delegated grants consented for every user.
  const grants = await soft(
    "oauth2PermissionGrants",
    () =>
      graph.getAll(`${graph.GRAPH}/oauth2PermissionGrants?$filter=consentType eq 'AllPrincipals'`),
    io
  );
  let delegatedRows = [];
  if (Array.isArray(grants)) {
    delegatedRows = buildDelegatedGrantRows(grants, spById);
    io.saveCsv("04_Delegated_Grants_AllPrincipals.csv", delegatedRows);
    summary.delegatedGrantsAllPrincipals = delegatedRows.length;
    const risky = delegatedRows.filter(
      (r) => /Critical|High/.test(r.MaxSeverity) && !r.MicrosoftOwned
    );
    summary.delegatedGrantsRisky = risky.length;
    if (risky.length) {
      findings.push({
        Severity: risky.some((r) => r.MaxSeverity === "Critical") ? "High" : "Medium",
        Area: "AppPermissions",
        Detail:
          `${risky.length} third-party app(s) hold admin-consented delegated grants for all users with write / mailbox / directory scopes: ` +
          risky.slice(0, 4).map((r) => `${r.ClientDisplayName} [${r.DangerousScopes}]`).join("; ") +
          (risky.length > 4 ? ` and ${risky.length - 4} more` : "") +
          " — 04_Delegated_Grants_AllPrincipals.csv",
      });
    }
  }

  // Credentials on service principal objects.
  let spCredRows = [];
  if (Array.isArray(sps)) {
    spCredRows = buildSpCredentialRows(sps);
    io.saveCsv("04_SPN_Credentials.csv", spCredRows);
    const firstParty = spCredRows.filter((r) => r.MicrosoftOwned);
    const longLived = spCredRows.filter(
      (r) => !r.MicrosoftOwned && r.LongLived && r.CredentialType === "secret" && !r.Expired
    );
    summary.spCredentialsTotal = spCredRows.length;
    summary.spCredentialsOnFirstParty = firstParty.length;
    summary.spSecretsLongLived = longLived.length;
    if (firstParty.length) {
      const names = [...new Set(firstParty.map((r) => r.SPNDisplayName))];
      findings.push({
        Severity: "Critical",
        Area: "AppBackdoor",
        Detail:
          `${firstParty.length} credential(s) present on ${names.length} Microsoft first-party service principal(s): ${names.slice(0, 5).join(", ")}` +
          (names.length > 5 ? ` and ${names.length - 5} more` : "") +
          " — first-party apps never need tenant-added secrets; this is the persistence pattern used after tenant compromise. Investigate the audit log for 'Add service principal credentials' and remove — 04_SPN_Credentials.csv",
      });
    }
    if (longLived.length) {
      findings.push({
        Severity: "High",
        Area: "AppCredentials",
        Detail: `${longLived.length} service-principal client secret(s) valid for more than 2 years — 04_SPN_Credentials.csv`,
      });
    }
  }

  return {
    dangerousSpnRows,
    delegatedRows,
    spCredRows,
    sources: {
      servicePrincipals: graphAssignmentsOk,
      servicePrincipalInventory: Array.isArray(sps),
      delegatedGrants: Array.isArray(grants),
    },
  };
}

module.exports = {
  RESOURCES,
  DANGEROUS_APP_ROLES,
  DANGEROUS_DELEGATED,
  MICROSOFT_OWNER_TENANTS,
  TWO_YEARS_DAYS,
  isMicrosoftOwned,
  classifyAppRole,
  buildDangerousRows,
  buildDelegatedGrantRows,
  buildSpCredentialRows,
  collectAppSurface,
};
