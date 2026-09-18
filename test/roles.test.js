const test = require("node:test");
const assert = require("node:assert");
const {
  parseScope,
  buildRoleRows,
  summarizeRoles,
  highValueRows,
  ASSIGNMENT,
  BASELINE_HIGH_PRIV,
} = require("../lib/roles");

const GA = "62e90394-69f5-4237-9190-012177145e10";
const HELPDESK = "729827e3-9c14-49f7-bb1b-9608f156bbb8";
const APPADMIN = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3";
const roleDefById = {
  [GA]: { displayName: "Global Administrator", isPrivileged: true },
  [HELPDESK]: { displayName: "Helpdesk Administrator", isPrivileged: true },
  [APPADMIN]: { displayName: "Application Administrator", isPrivileged: true },
  "custom-1": { displayName: "Custom Reader", isPrivileged: false },
};

const user = (id, upn, extra = {}) => ({
  "@odata.type": "#microsoft.graph.user",
  id,
  displayName: upn.split("@")[0],
  userPrincipalName: upn,
  accountEnabled: true,
  ...extra,
});

test("directoryScopeId parses into tenant / AU / app scope", () => {
  assert.deepEqual(parseScope("/"), { kind: "Tenant", id: "" });
  assert.deepEqual(parseScope(undefined), { kind: "Tenant", id: "" });
  assert.deepEqual(parseScope("/administrativeUnits/abc"), { kind: "AU", id: "abc" });
  assert.deepEqual(parseScope("/11111111-1111-1111-1111-111111111111"), {
    kind: "App",
    id: "11111111-1111-1111-1111-111111111111",
  });
});

test("PIM activations are not permanent; eligibility is separate", () => {
  const rows = buildRoleRows({
    scheduleInstances: [
      { roleDefinitionId: GA, principalId: "u1", directoryScopeId: "/", assignmentType: "Assigned", principal: user("u1", "perm@x.com") },
      { roleDefinitionId: GA, principalId: "u2", directoryScopeId: "/", assignmentType: "Activated", endDateTime: "2026-09-18T20:00:00Z", principal: user("u2", "act@x.com") },
    ],
    eligibility: [
      { roleDefinitionId: GA, principalId: "u3", directoryScopeId: "/", principal: user("u3", "elig@x.com") },
    ],
    roleDefById,
  });
  assert.equal(rows.length, 3);
  assert.equal(rows[0].AssignmentType, ASSIGNMENT.PERMANENT);
  assert.equal(rows[1].AssignmentType, ASSIGNMENT.ACTIVATED);
  assert.equal(rows[2].AssignmentType, ASSIGNMENT.ELIGIBLE);
  const k = summarizeRoles(rows);
  assert.equal(k.globalAdminPermanent, 1);
  assert.equal(k.globalAdminActivated, 1);
  assert.equal(k.globalAdminEligible, 1);
  assert.equal(k.pimEligibleCount, 1);
});

test("role-assignable group members become effective rows with ViaGroup", () => {
  const rows = buildRoleRows({
    assignments: [
      {
        roleDefinitionId: GA,
        principalId: "g1",
        directoryScopeId: "/",
        principal: { "@odata.type": "#microsoft.graph.group", id: "g1", displayName: "GA-Group" },
      },
    ],
    roleDefById,
    groupMembers: {
      g1: [
        user("m1", "alice@x.com"),
        user("m2", "bob@x.com", { accountEnabled: false }),
        { "@odata.type": "#microsoft.graph.group", id: "nested", displayName: "Nested" },
        { "@odata.type": "#microsoft.graph.servicePrincipal", id: "sp1", displayName: "Automation", appId: "app-1" },
      ],
    },
  });
  const shell = rows.find((r) => r.PrincipalType === "group");
  assert.ok(shell, "group shell kept for the audit CSV");
  const members = rows.filter((r) => r.ViaGroup === "GA-Group");
  assert.equal(members.length, 3, "nested group not emitted, users + SP are");
  assert.equal(members[0].UPNOrAppId, "alice@x.com");
  assert.equal(members[2].UPNOrAppId, "appId: app-1");
  const k = summarizeRoles(rows);
  assert.equal(k.globalAdminPermanent, 3, "shell excluded, members counted");
  assert.equal(highValueRows(rows).length, 3);
});

test("AU / app scope is recorded and kept out of the tenant-wide GA count", () => {
  const rows = buildRoleRows({
    assignments: [
      { roleDefinitionId: HELPDESK, principalId: "u1", directoryScopeId: "/administrativeUnits/au-1", principal: user("u1", "hd@x.com") },
      { roleDefinitionId: APPADMIN, principalId: "u2", directoryScopeId: "/22222222-2222-2222-2222-222222222222", principal: user("u2", "appowner@x.com") },
      { roleDefinitionId: GA, principalId: "u3", directoryScopeId: "/", principal: user("u3", "ga@x.com") },
    ],
    roleDefById,
    scopeNames: { "au-1": "Paris (restricted AU)" },
  });
  assert.equal(rows[0].Scope, "AU");
  assert.equal(rows[0].ScopeName, "Paris (restricted AU)");
  assert.equal(rows[1].Scope, "App");
  assert.equal(rows[2].Scope, "Tenant");
  assert.equal(summarizeRoles(rows).scopedRows, 2);
  assert.equal(summarizeRoles(rows).globalAdminPermanent, 1);
});

test("isPrivileged from Graph and the baseline list both mark high-value roles", () => {
  const rows = buildRoleRows({
    assignments: [
      { roleDefinitionId: "custom-1", principalId: "u1", principal: user("u1", "a@x.com") },
      { roleDefinitionId: "unknown-id", principalId: "u2", principal: user("u2", "b@x.com") },
      { roleDefinitionId: GA, principalId: "u3", principal: user("u3", "c@x.com") },
    ],
    roleDefById: { ...roleDefById, "unknown-id": { displayName: "Hybrid Identity Administrator" } },
  });
  assert.equal(rows[0].IsPrivilegedRole, false);
  assert.equal(rows[1].IsPrivilegedRole, true, "baseline list catches Hybrid Identity Administrator");
  assert.equal(rows[2].IsPrivilegedRole, true);
  assert.ok(BASELINE_HIGH_PRIV.has("Partner Tier2 Support"));
  assert.ok(BASELINE_HIGH_PRIV.has("Authentication Policy Administrator"));
});
