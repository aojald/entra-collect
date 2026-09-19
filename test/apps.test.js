const test = require("node:test");
const assert = require("node:assert");
const {
  RESOURCES,
  classifyAppRole,
  buildDangerousRows,
  buildDelegatedGrantRows,
  buildSpCredentialRows,
  isMicrosoftOwned,
} = require("../lib/apps");

test("app roles are classified per resource, not by name alone", () => {
  assert.equal(classifyAppRole(RESOURCES.exo.appId, "full_access_as_app"), "Critical");
  assert.equal(classifyAppRole(RESOURCES.exo.appId, "Exchange.ManageAsApp"), "Critical");
  assert.equal(classifyAppRole(RESOURCES.graph.appId, "full_access_as_app"), null, "not a Graph role");
  assert.equal(classifyAppRole(RESOURCES.graph.appId, "UserAuthenticationMethod.ReadWrite.All"), "Critical");
  assert.equal(classifyAppRole(RESOURCES.aadGraph.appId, "Directory.ReadWrite.All"), "Critical");
  assert.equal(classifyAppRole(RESOURCES.spo.appId, "Sites.FullControl.All"), "Critical");
  assert.equal(classifyAppRole(RESOURCES.graph.appId, "User.Read"), null);
});

test("buildDangerousRows covers Exchange full_access_as_app that the Graph-only view missed", () => {
  const rows = buildDangerousRows([
    {
      resource: RESOURCES.graph,
      sp: { appRoles: [{ id: "r1", value: "Directory.Read.All" }, { id: "r2", value: "User.Read" }] },
      assignments: [
        { appRoleId: "r1", principalDisplayName: "SOC", principalId: "p1", principalType: "ServicePrincipal", resourceDisplayName: "Microsoft Graph" },
        { appRoleId: "r2", principalDisplayName: "Harmless", principalId: "p2", principalType: "ServicePrincipal" },
      ],
    },
    {
      resource: RESOURCES.exo,
      sp: { appRoles: [{ id: "e1", value: "full_access_as_app" }] },
      assignments: [
        { appRoleId: "e1", principalDisplayName: "Mail archiver", principalId: "p3", principalType: "ServicePrincipal" },
      ],
    },
  ]);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].Permission, "full_access_as_app", "Critical sorts first");
  assert.equal(rows[0].ResourceAppId, RESOURCES.exo.appId);
  assert.equal(rows[0].ResourceApp, "Office 365 Exchange Online");
  assert.equal(rows[1].Severity, "Medium");
});

test("delegated AllPrincipals grants are scored on their worst scope and name-resolved", () => {
  const spById = new Map([
    ["c1", { id: "c1", displayName: "Vendor CRM", appId: "app-c1", appOwnerOrganizationId: "11111111-1111-1111-1111-111111111111" }],
    ["c2", { id: "c2", displayName: "Office", appId: "app-c2", appOwnerOrganizationId: "f8cdef31-a31e-4b4a-93e4-5f571e91255a" }],
    ["r1", { id: "r1", displayName: "Microsoft Graph", appId: RESOURCES.graph.appId }],
  ]);
  const rows = buildDelegatedGrantRows(
    [
      { id: "g1", clientId: "c1", resourceId: "r1", consentType: "AllPrincipals", scope: "openid profile Mail.ReadWrite Directory.AccessAsUser.All" },
      { id: "g2", clientId: "c2", resourceId: "r1", consentType: "AllPrincipals", scope: "User.Read offline_access" },
    ],
    spById
  );
  assert.equal(rows.length, 2);
  assert.equal(rows[0].ClientDisplayName, "Vendor CRM");
  assert.equal(rows[0].MaxSeverity, "Critical");
  assert.equal(rows[0].DangerousScopes, "Mail.ReadWrite Directory.AccessAsUser.All");
  assert.equal(rows[0].MicrosoftOwned, false);
  assert.equal(rows[1].MaxSeverity, "");
  assert.equal(rows[1].MicrosoftOwned, true);
});

test("credentials on first-party SPs are Critical; long secrets High; app-owned SPs unflagged", () => {
  const now = Date.parse("2026-09-19T00:00:00Z");
  const rows = buildSpCredentialRows(
    [
      {
        id: "sp1",
        appId: "00000003-0000-0000-c000-000000000000",
        displayName: "Microsoft Graph",
        appOwnerOrganizationId: "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
        passwordCredentials: [{ keyId: "k1", displayName: "backdoor", startDateTime: "2026-01-01T00:00:00Z", endDateTime: "2028-01-01T00:00:00Z" }],
        keyCredentials: [],
      },
      {
        id: "sp2",
        appId: "app-2",
        displayName: "Line of business",
        appOwnerOrganizationId: "22222222-2222-2222-2222-222222222222",
        passwordCredentials: [{ keyId: "k2", startDateTime: "2024-01-01T00:00:00Z", endDateTime: "2030-01-01T00:00:00Z" }],
        keyCredentials: [{ keyId: "k3", startDateTime: "2026-01-01T00:00:00Z", endDateTime: "2027-01-01T00:00:00Z" }],
      },
      { id: "sp3", appId: "app-3", displayName: "No creds", passwordCredentials: [], keyCredentials: [] },
    ],
    now
  );
  assert.equal(rows.length, 3);
  assert.equal(rows[0].MicrosoftOwned, true);
  assert.match(rows[0].Risk, /^Critical/);
  assert.equal(rows[1].LongLived, true);
  assert.match(rows[1].Risk, /^High/);
  assert.equal(rows[2].CredentialType, "certificate");
  assert.equal(rows[2].Risk, "");
  assert.equal(isMicrosoftOwned({ appOwnerOrganizationId: "72f988bf-86f1-41af-91ab-2d7cd011db47" }), true);
  assert.equal(isMicrosoftOwned({}), false);
});
