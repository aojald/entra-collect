const test = require("node:test");
const assert = require("node:assert");
const {
  secInfoPolicyState,
  isFleetDeviceCompliancePolicy,
  splitTvmVulns,
  aggregateFailuresByIp,
  identityInfoActionable,
  clusterAppControlPlane,
  graphApiWriteHits,
  clusterAlertsBySource,
  isCopilotOrAgentUpn,
  patchLagFromSoftwareVersions,
  detectEnforcedMfaCoverage,
  isReportOnlyFleetComplianceRow,
  buildSpnActivityIndex,
  spnIsActive,
} = require("../lib/posture");

test("SecInfo report-only is Partial, not Fail", () => {
  const policies = [
    {
      displayName: "CA35 SecInfo",
      state: "enabledForReportingButNotEnforced",
      conditions: {
        applications: { includeUserActions: ["urn:user:registersecurityinfo"] },
      },
      grantControls: { builtInControls: ["compliantDevice"] },
    },
  ];
  const st = secInfoPolicyState(policies);
  assert.equal(st.status, "Partial");
  assert.equal(isFleetDeviceCompliancePolicy(policies[0]), false);
});

test("enforced All-apps compliantDevice is fleet coverage", () => {
  const p = {
    state: "enabled",
    conditions: { applications: { includeApplications: ["All"] } },
    grantControls: { builtInControls: ["compliantDevice"] },
  };
  assert.equal(isFleetDeviceCompliancePolicy(p), true);
});

test("TVM splits Windows OS from openssl", () => {
  const { os, runtime } = splitTvmVulns([
    { Software: "openssl", Severity: "Critical", Devices: 124 },
    { Software: "windows_11", Severity: "High", Devices: 77 },
  ]);
  assert.equal(os.length, 1);
  assert.equal(runtime.length, 1);
});

test("failed sign-ins collapse IP × errorCode into one IP", () => {
  const rows = aggregateFailuresByIp([
    { IP: "83.167.32.73", ErrorCode: "50011", Failures: 100, Users: 10, SampleUsers: "a@x" },
    { IP: "83.167.32.73", ErrorCode: "53000", Failures: 50, Users: 5, SampleUsers: "b@x" },
    { IP: "1.2.3.4", ErrorCode: "50126", Failures: 80, Users: 1, SampleUsers: "c@x" },
  ]);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].IP, "83.167.32.73");
  assert.equal(rows[0].Failures, 150);
  assert.ok(String(rows[0].ErrorCode).includes("50011"));
});

test("IdentityInfo ignores RiskLevel None and crit=0 dump", () => {
  const { withRoles, atRisk, taggedCritical } = identityInfoActionable([
    { AccountUpn: "ga@t", CriticalityLevel: 0, RiskLevel: "None", AssignedRoles: "Global Administrator" },
    { AccountUpn: "x@t", CriticalityLevel: 4, RiskLevel: "", AssignedRoles: "" },
    { AccountUpn: "y@t", CriticalityLevel: 4, RiskLevel: "Low", AssignedRoles: "" },
    { AccountUpn: "z@t", CriticalityLevel: 3, RiskLevel: "High", AssignedRoles: "" },
  ]);
  assert.equal(withRoles.length, 1);
  assert.equal(atRisk.length, 1);
  assert.equal(atRisk[0].AccountUpn, "z@t");
  assert.equal(taggedCritical.length, 3);
});

test("app control-plane cluster treats Entra PRA as GA path and dedupes CA-write", () => {
  const c = clusterAppControlPlane({
    gaPath: [
      { SPNDisplayName: "SOC", Permission: "RoleManagement.ReadWrite.Directory" },
      { SPNDisplayName: "SOC", Permission: "Application.ReadWrite.All" },
    ],
    dangerous: [
      { SPNDisplayName: "SOC", Permission: "Policy.ReadWrite.ConditionalAccess" },
    ],
    priv: [
      {
        PrincipalType: "servicePrincipal",
        PrincipalName: "Varonis_AAD",
        RoleName: "Privileged Role Administrator",
      },
    ],
  });
  assert.equal(c.pathToGa.length, 2);
  assert.equal(c.roleMgmtCoveredByPathToGa, true);
  assert.equal(c.caWriteCoveredByPathToGa, true);
  assert.ok(c.pathToGa.some((a) => /varonis/i.test(a.name)));
});

test("Graph API audit writes count CA/role PATCH clusters", () => {
  const hits = graphApiWriteHits([
    { SampleUris: "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies", Events: 4 },
    { SampleUris: "https://graph.microsoft.com/v1.0/users", Events: 9 },
    { SampleUris: "https://graph.microsoft.com/beta/roleManagement/directory/estimateAccess", Events: 3715 },
    { SampleUris: "https://graph.microsoft.com/beta/roleManagement/directory/checkAccess", Events: 14 },
  ]);
  assert.equal(hits.length, 1);
  const c = clusterAppControlPlane({
    graphApiAudit: hits,
  });
  assert.equal(c.graphApiWriteEvents, 4);
});

test("alert cluster separates IRM, endpoint, and Cloud Apps High", () => {
  const c = clusterAlertsBySource([
    { Severity: "High", ServiceSource: "Microsoft Insider Risk Management", Title: "Purview IRM" },
    { Severity: "High", ServiceSource: "Microsoft Defender for Endpoint", Title: "Malware" },
    { Severity: "High", ServiceSource: "Microsoft Defender for Cloud Apps", Title: "Mass download" },
    { Severity: "High", ServiceSource: "Microsoft Defender for Cloud Apps", Title: "Mass download" },
    { Severity: "Informational", ServiceSource: "Microsoft Defender for Office 365", Title: "ZAP" },
  ]);
  assert.equal(c.high, 4);
  assert.equal(c.irmHigh, 1);
  assert.equal(c.endpointHigh, 1);
  assert.equal(c.mdcaHigh, 2);
  assert.equal(c.titles[0].title, "Mass download");
  assert.equal(c.titles[0].n, 2);
});

test("Copilot agent UPNs are not human single-factor", () => {
  assert.equal(
    isCopilotOrAgentUpn("SecurityCopilotAgentUser-b1d1bac2-5336-4db0-bfb4-3f7cb8303f3a@contoso.com"),
    true
  );
  assert.equal(isCopilotOrAgentUpn("jane@contoso.com"), false);
});

test("TVM software versions can show Patch Tuesday lag when DeviceInfo has no UBR", () => {
  const lag = patchLagFromSoftwareVersions(
    [{ Software: "windows_11", Version: "10.0.26100.9106", DeviceId: "d1" }],
    { builds: { 26100: { minUbr: 9445 } } }
  );
  assert.equal(lag.behind, 1);
  assert.equal(lag.known, 1);
});

test("population MFA coverage ignores role-only, risk-gated, and admin-portal policies", () => {
  const mfa = detectEnforcedMfaCoverage([
    {
      PolicyName: "MFA for admin portals",
      State: "enabled",
      GrantControls: "mfa",
      IncludeUsers: "",
      IncludeGroups: "",
      IncludeRoles: "Global Administrator",
    },
    {
      PolicyName: "Identity Protection risky sign-ins",
      State: "enabled",
      GrantControls: "mfa",
      IncludeUsers: "All",
      IncludeUsersRaw: "All",
      SignInRisk: "high",
    },
    {
      PolicyName: "MFA for licensed staff",
      State: "enabled",
      GrantControls: "mfa",
      IncludeUsers: "",
      IncludeGroups: "Group: MFA licensed",
    },
  ]);
  assert.equal(mfa.covered, false);
  assert.equal(mfa.scoped, true);
  assert.ok(mfa.scopedEvidence.some((n) => /licensed staff/i.test(n)));

  const allUsers = detectEnforcedMfaCoverage([
    {
      PolicyName: "Require MFA for all users",
      State: "enabled",
      IsEnforced: "Yes",
      GrantControls: "mfa",
      IncludeUsers: "All",
      IncludeUsersRaw: "All",
    },
  ]);
  assert.equal(allUsers.covered, true);
});

test("report-only MAM is not fleet device compliance", () => {
  assert.equal(
    isReportOnlyFleetComplianceRow({
      PolicyName: "CA-05 Mobile Approved Apps + MAM",
      State: "enabledForReportingButNotEnforced",
      GrantControls: "compliantApplication",
    }),
    false
  );
  assert.equal(
    isReportOnlyFleetComplianceRow({
      PolicyName: "CA-04 Require Compliant Device",
      State: "enabledForReportingButNotEnforced",
      GrantControls: "compliantDevice",
    }),
    true
  );
});

test("directory role GUIDs resolve and Purview is data-plane not high-value", () => {
  const { resolveDirectoryRoleName, directoryRoleTier, enrichDirectoryRoleRows, rollupDirectoryRoles } = require("../lib/posture");
  assert.equal(
    resolveDirectoryRoleName("eb1d8c34-acf5-460d-8424-c1f1a6fbdb85"),
    "AdHoc License Administrator"
  );
  assert.equal(
    resolveDirectoryRoleName("d24aef57-1500-4070-84db-2666f29cf966"),
    "Modern Commerce Administrator"
  );
  assert.equal(resolveDirectoryRoleName("Global Reader"), "Global Reader");
  const high = new Set(["Global Administrator", "Security Administrator"]);
  assert.equal(directoryRoleTier("Global Administrator", high), "High-value");
  assert.equal(directoryRoleTier("Global Reader", high), "Reader");
  assert.equal(directoryRoleTier("Security Reader", high), "Reader");
  assert.equal(
    directoryRoleTier("Purview Workload Content Administrator", high),
    "Data-plane"
  );
  const rows = enrichDirectoryRoleRows(
    [
      { RoleName: "Global Reader", PrincipalType: "user", AssignmentType: "Permanent (direct)" },
      { RoleName: "3f04f91a-4ad7-4bd3-bcfa-49882ea1a88a", PrincipalType: "user", AssignmentType: "Permanent (direct)" },
    ],
    {
      roleDefById: { "3f04f91a-4ad7-4bd3-bcfa-49882ea1a88a": "Purview Workload Content Administrator" },
      highValueNames: high,
    }
  );
  assert.equal(rows[1].RoleName, "Purview Workload Content Administrator");
  assert.equal(rows[1].Tier, "Data-plane");
  const roll = rollupDirectoryRoles(rows);
  assert.equal(roll.length, 2);
});

test("SPN activity matches AppId / service-principal id when display names diverge", () => {
  const keys = buildSpnActivityIndex(
    [],
    [
      {
        App: "Vendor integration (prod)",
        AppId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        ServicePrincipalId: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        Events: 30,
      },
    ]
  );
  assert.equal(
    spnIsActive(
      {
        name: "Vendor integration",
        ids: ["bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"],
      },
      keys
    ),
    true
  );
  assert.equal(
    spnIsActive({ name: "Unused connector", ids: ["cccccccccccccccccccccccccccccccccccc"] }, keys),
    false
  );
});
