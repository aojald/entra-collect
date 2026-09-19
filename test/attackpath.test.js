const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { createIo, classifyStepError, ERROR_KIND } = require("../lib/io");
const { collectAttackPathChecks, CHECK } = require("../lib/attackpath");
const { deriveLicences } = require("../lib/tenantFacts");
const { parseCsv } = require("../lib/csv");

function tmpOut() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "entra-collect-ap-"));
}

/** Minimal Graph stub: every object lookup returns an empty-but-valid shape. */
function stubGraph(overrides = {}) {
  return {
    GRAPH: "https://graph.microsoft.com/v1.0",
    GRAPH_BETA: "https://graph.microsoft.com/beta",
    get: async (url) => {
      if (overrides.get) {
        const v = await overrides.get(url);
        if (v !== undefined) return v;
      }
      if (/adminConsentRequestPolicy/.test(url)) return { isEnabled: true };
      if (/\/users\//.test(url)) {
        const id = url.match(/users\/([^?]+)/)[1];
        return {
          id,
          displayName: `User ${id}`,
          userPrincipalName: `${id}@contoso.onmicrosoft.com`,
          accountEnabled: true,
          onPremisesSyncEnabled: false,
        };
      }
      if (/\/groups\//.test(url)) return { id: "g1", displayName: "Excl", isAssignableToRole: false };
      return {};
    },
    getAll: async (url) => {
      if (overrides.getAll) {
        const v = await overrides.getAll(url);
        if (v !== undefined) return v;
      }
      return [];
    },
  };
}

const ENFORCED_LEGACY_BLOCK = {
  id: "p1",
  displayName: "Block legacy",
  state: "enabled",
  conditions: {
    users: { includeUsers: ["All"] },
    applications: { includeApplications: ["All"] },
    clientAppTypes: ["exchangeActiveSync", "other"],
  },
  grantControls: { operator: "OR", builtInControls: ["block"] },
};

function readChecklist(outDir) {
  return parseCsv(fs.readFileSync(path.join(outDir, "40_AttackPath_Checklist.csv"), "utf8"));
}
function readCoverage(outDir) {
  return parseCsv(fs.readFileSync(path.join(outDir, "40_CA_AttackPath_Coverage.csv"), "utf8"));
}
function row(list, id) {
  return list.find((r) => r.CheckId === id);
}

test("CA coverage CSV records unknown (not false) when CA export failed", async () => {
  const outDir = tmpOut();
  const io = createIo(outDir, { manifest: false });
  const findings = [];
  const summary = {};
  await collectAttackPathChecks(stubGraph(), io, findings, summary, {
    policies: [],
    authz: { defaultUserRolePermissions: {} },
    authMethods: { authenticationMethodConfigurations: [] },
    privRows: [],
    roleRows: [],
    dangerousSpnRows: [],
    regDetails: [],
    sources: { caPolicies: false },
  });
  const cov = readCoverage(outDir);
  assert.ok(cov.length > 0);
  for (const r of cov) {
    assert.equal(r.Covered, "unknown", `${r.Control} should be unknown`);
  }
  const cl = readChecklist(outDir);
  for (const r of cl.filter((x) => /^AP\.CA\./.test(x.CheckId))) {
    assert.equal(r.Status, CHECK.NOT_EVALUATED, `${r.CheckId}`);
  }
  assert.ok(
    !findings.some((f) => f.Area === "CA" && /No enforced CA/i.test(f.Detail)),
    "no CA Fail findings when CA export failed"
  );
});

test("GA MFA check is NotEvaluated when registration report failed, Partial when a GA is missing from it", async () => {
  const privRows = [
    {
      RoleName: "Global Administrator",
      PrincipalType: "user",
      PrincipalId: "ga1",
      UPNOrAppId: "ga1@contoso.onmicrosoft.com",
      AssignmentType: "Permanent (direct)",
    },
  ];
  const base = {
    policies: [ENFORCED_LEGACY_BLOCK],
    authz: { defaultUserRolePermissions: {} },
    authMethods: { authenticationMethodConfigurations: [] },
    privRows,
    roleRows: privRows,
    dangerousSpnRows: [],
  };

  let outDir = tmpOut();
  await collectAttackPathChecks(stubGraph(), createIo(outDir, { manifest: false }), [], {}, {
    ...base,
    regDetails: [],
    sources: { regDetails: false },
  });
  assert.equal(row(readChecklist(outDir), "AP.Priv.GaMfa").Status, CHECK.NOT_EVALUATED);

  outDir = tmpOut();
  await collectAttackPathChecks(stubGraph(), createIo(outDir, { manifest: false }), [], {}, {
    ...base,
    regDetails: [],
    sources: { regDetails: true },
  });
  assert.equal(row(readChecklist(outDir), "AP.Priv.GaMfa").Status, CHECK.PARTIAL);

  outDir = tmpOut();
  await collectAttackPathChecks(stubGraph(), createIo(outDir, { manifest: false }), [], {}, {
    ...base,
    regDetails: [{ id: "ga1", userPrincipalName: "ga1@contoso.onmicrosoft.com", isMfaRegistered: false }],
    sources: { regDetails: true },
  });
  assert.equal(row(readChecklist(outDir), "AP.Priv.GaMfa").Status, CHECK.FAIL);
});

test("PathToGA is NotEvaluated when the Graph app-role export failed", async () => {
  const outDir = tmpOut();
  await collectAttackPathChecks(stubGraph(), createIo(outDir, { manifest: false }), [], {}, {
    policies: [ENFORCED_LEGACY_BLOCK],
    authz: { defaultUserRolePermissions: {} },
    authMethods: { authenticationMethodConfigurations: [] },
    privRows: [],
    roleRows: [],
    dangerousSpnRows: [],
    regDetails: [],
    sources: { servicePrincipals: false },
  });
  assert.equal(row(readChecklist(outDir), "AP.App.PathToGA").Status, CHECK.NOT_EVALUATED);
});

test("risk checks are NotApplicable without P2; legacy is Pass under Security Defaults", async () => {
  let outDir = tmpOut();
  let findings = [];
  await collectAttackPathChecks(stubGraph(), createIo(outDir, { manifest: false }), findings, {}, {
    policies: [ENFORCED_LEGACY_BLOCK],
    authz: { defaultUserRolePermissions: {} },
    authMethods: { authenticationMethodConfigurations: [] },
    privRows: [],
    roleRows: [],
    dangerousSpnRows: [],
    regDetails: [],
    facts: { licences: { p1: true, p2: false } },
  });
  let cl = readChecklist(outDir);
  assert.equal(row(cl, "AP.CA.SignInRisk").Status, CHECK.NOT_APPLICABLE);
  assert.equal(row(cl, "AP.CA.UserRisk").Status, CHECK.NOT_APPLICABLE);
  assert.equal(row(cl, "AP.CA.SignInRisk").LicenceRequired, "P2");
  assert.equal(row(cl, "AP.CA.LegacyBlock").Status, CHECK.PASS);
  assert.ok(!findings.some((f) => /user risk|sign-in risk/i.test(f.Detail) && f.Severity === "High"));
  const cov = readCoverage(outDir);
  assert.equal(cov.find((r) => /user risk/i.test(r.Control)).Covered, "n/a");

  outDir = tmpOut();
  findings = [];
  await collectAttackPathChecks(stubGraph(), createIo(outDir, { manifest: false }), findings, {}, {
    policies: [],
    authz: { defaultUserRolePermissions: {} },
    authMethods: { authenticationMethodConfigurations: [] },
    privRows: [],
    roleRows: [],
    dangerousSpnRows: [],
    regDetails: [],
    facts: { securityDefaultsEnabled: true, licences: null },
  });
  cl = readChecklist(outDir);
  assert.equal(row(cl, "AP.CA.LegacyBlock").Status, CHECK.PASS);
  assert.equal(row(cl, "AP.CA.AzureMgmt").Status, CHECK.PASS);
  assert.equal(row(cl, "AP.CA.GuestMfa").Status, CHECK.NOT_APPLICABLE);
  assert.equal(row(cl, "AP.CA.SecInfoReg").Status, CHECK.NOT_APPLICABLE);
  assert.ok(row(cl, "AP.CA.SecurityDefaults"));
  assert.ok(!findings.some((f) => f.Area === "CA" && f.Severity === "High"));
});

test("number matching is informational only", async () => {
  const outDir = tmpOut();
  const findings = [];
  await collectAttackPathChecks(stubGraph(), createIo(outDir, { manifest: false }), findings, {}, {
    policies: [ENFORCED_LEGACY_BLOCK],
    authz: { defaultUserRolePermissions: {} },
    authMethods: {
      authenticationMethodConfigurations: [
        {
          id: "MicrosoftAuthenticator",
          state: "enabled",
          featureSettings: { numberMatchingRequiredState: { state: "disabled" } },
        },
      ],
    },
    privRows: [],
    roleRows: [],
    dangerousSpnRows: [],
    regDetails: [],
  });
  const r = row(readChecklist(outDir), "AP.MFA.NumberMatch");
  assert.equal(r.Status, CHECK.INFO);
  assert.ok(!findings.some((f) => /number matching/i.test(f.Detail) && f.Severity === "High"));
});

test("checklist rows carry Confidence / LicenceRequired columns", async () => {
  const outDir = tmpOut();
  await collectAttackPathChecks(stubGraph(), createIo(outDir, { manifest: false }), [], {}, {
    policies: [ENFORCED_LEGACY_BLOCK],
    authz: { defaultUserRolePermissions: {} },
    authMethods: { authenticationMethodConfigurations: [] },
    privRows: [],
    roleRows: [],
    dangerousSpnRows: [],
    regDetails: [],
  });
  const r = row(readChecklist(outDir), "AP.CA.LegacyBlock");
  assert.equal(r.Status, CHECK.PASS);
  assert.equal(r.Confidence, "High");
  assert.ok("LicenceRequired" in r);
});

test("deriveLicences reads P1/P2 from provisioned service plans only", () => {
  const lic = deriveLicences([
    {
      skuPartNumber: "SPE_E3",
      capabilityStatus: "Enabled",
      prepaidUnits: { enabled: 100 },
      servicePlans: [{ servicePlanName: "AAD_PREMIUM", provisioningStatus: "Success" }],
    },
    {
      skuPartNumber: "AAD_PREMIUM_P2",
      capabilityStatus: "Suspended",
      prepaidUnits: { enabled: 0 },
      servicePlans: [{ servicePlanName: "AAD_PREMIUM_P2", provisioningStatus: "Success" }],
    },
  ]);
  assert.equal(lic.p1, true);
  assert.equal(lic.p2, false);
  assert.equal(lic.conditionalAccess, true);
  assert.equal(lic.identityProtection, false);
  assert.equal(lic.skus.length, 2);

  const p2 = deriveLicences([
    {
      skuPartNumber: "SPE_E5",
      capabilityStatus: "Enabled",
      prepaidUnits: { enabled: 5 },
      servicePlans: [{ servicePlanName: "AAD_PREMIUM_P2", provisioningStatus: "Success" }],
    },
  ]);
  assert.equal(p2.p1, true);
  assert.equal(p2.p2, true);
});

test("step errors: licence and denied are not transient; invalid filter is unsupported", () => {
  const lic = new Error("HTTP 400 x");
  lic.status = 400;
  lic.body = JSON.stringify({ error: { code: "AadPremiumLicenseRequired", message: "P2" } });
  assert.equal(classifyStepError(lic), ERROR_KIND.LICENCE);

  const denied = new Error("HTTP 403 x");
  denied.status = 403;
  denied.body = JSON.stringify({ error: { code: "Authorization_RequestDenied" } });
  assert.equal(classifyStepError(denied), ERROR_KIND.DENIED);

  const bad = new Error("HTTP 400 x");
  bad.status = 400;
  bad.body = JSON.stringify({
    error: { code: "BadRequest", message: "Invalid filter clause: Could not find a property named 'authenticationProtocol'" },
  });
  assert.equal(classifyStepError(bad), ERROR_KIND.UNSUPPORTED);

  const throttled = new Error("HTTP 429 x");
  throttled.status = 429;
  assert.equal(classifyStepError(throttled), ERROR_KIND.TRANSIENT);
});

test("auth-method verdicts are Partial while the legacy MFA policy migration is incomplete", async () => {
  const outDir = tmpOut();
  const findings = [];
  await collectAttackPathChecks(stubGraph(), createIo(outDir, { manifest: false }), findings, {}, {
    policies: [ENFORCED_LEGACY_BLOCK],
    authz: { defaultUserRolePermissions: {} },
    authMethods: {
      policyMigrationState: "preMigration",
      authenticationMethodConfigurations: [{ id: "Sms", state: "disabled" }],
    },
    privRows: [],
    roleRows: [],
    dangerousSpnRows: [],
    regDetails: [],
  });
  const cl = readChecklist(outDir);
  assert.equal(row(cl, "AP.MFA.SMS").Status, CHECK.PARTIAL, "disabled in the new policy is not authoritative");
  assert.equal(row(cl, "AP.MFA.Migration").Status, CHECK.FAIL);
  assert.ok(findings.some((f) => /migration is "preMigration"/.test(f.Detail)));

  const outDir2 = tmpOut();
  await collectAttackPathChecks(stubGraph(), createIo(outDir2, { manifest: false }), [], {}, {
    policies: [ENFORCED_LEGACY_BLOCK],
    authz: { defaultUserRolePermissions: {} },
    authMethods: {
      policyMigrationState: "migrationComplete",
      authenticationMethodConfigurations: [{ id: "Sms", state: "disabled" }],
    },
    privRows: [],
    roleRows: [],
    dangerousSpnRows: [],
    regDetails: [],
  });
  const cl2 = readChecklist(outDir2);
  assert.equal(row(cl2, "AP.MFA.SMS").Status, CHECK.PASS);
  assert.equal(row(cl2, "AP.MFA.Migration").Status, CHECK.PASS);
});

test("authorization-policy extras: self-service sign-up and group creation", async () => {
  const outDir = tmpOut();
  const findings = [];
  await collectAttackPathChecks(stubGraph(), createIo(outDir, { manifest: false }), findings, {}, {
    policies: [ENFORCED_LEGACY_BLOCK],
    authz: {
      allowEmailVerifiedUsersToJoinOrganization: true,
      defaultUserRolePermissions: { allowedToCreateSecurityGroups: true, allowedToReadOtherUsers: true },
    },
    authMethods: { authenticationMethodConfigurations: [] },
    privRows: [],
    roleRows: [],
    dangerousSpnRows: [],
    regDetails: [],
  });
  const cl = readChecklist(outDir);
  assert.equal(row(cl, "AP.Guest.SelfServiceSignup").Status, CHECK.FAIL);
  assert.equal(row(cl, "AP.Users.CreateSecurityGroups").Status, CHECK.FAIL);
  assert.ok(findings.some((f) => /Self-service sign-up/.test(f.Detail)));
});

test("new CA scope checks appear with expected verdicts on a hollow all-users policy", async () => {
  const GA = "62e90394-69f5-4237-9190-012177145e10";
  const hollowMfa = {
    id: "p2",
    displayName: "Require MFA for all",
    state: "enabled",
    conditions: {
      users: { includeUsers: ["All"], excludeRoles: [GA] },
      applications: { includeApplications: ["All"] },
      clientAppTypes: ["all"],
    },
    grantControls: { operator: "OR", builtInControls: ["mfa"] },
  };
  const outDir = tmpOut();
  const findings = [];
  await collectAttackPathChecks(stubGraph(), createIo(outDir, { manifest: false }), findings, {}, {
    policies: [ENFORCED_LEGACY_BLOCK, hollowMfa],
    authz: { defaultUserRolePermissions: {} },
    authMethods: { authenticationMethodConfigurations: [] },
    privRows: [],
    roleRows: [],
    dangerousSpnRows: [],
    regDetails: [],
    roleDefMap: { [GA]: "Global Administrator" },
  });
  const cl = readChecklist(outDir);
  assert.equal(row(cl, "AP.CA.AllUsersMfa").Status, CHECK.PARTIAL);
  assert.match(row(cl, "AP.CA.AllUsersMfa").Evidence, /excludes Global Administrator/);
  assert.equal(row(cl, "AP.CA.ExclRoles").Status, CHECK.FAIL);
  assert.equal(row(cl, "AP.CA.AdminPhishingResistant").Status, CHECK.FAIL);
  assert.equal(row(cl, "AP.CA.DeviceCode").Status, CHECK.FAIL);
  assert.equal(row(cl, "AP.CA.SessionControls").Status, CHECK.FAIL);
  const cov = readCoverage(outDir);
  assert.equal(cov.find((r) => /all users on all cloud apps/i.test(r.Control)).Covered, "partial");
});
