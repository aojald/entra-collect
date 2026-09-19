const test = require("node:test");
const assert = require("node:assert");
const {
  effectiveScope,
  coverageVerdict,
  coversPopulation,
  targetsLegacyClients,
  strengthIsPhishingResistant,
  detectMfaCoverageFromPolicies,
  GA_TEMPLATE,
  AUTH_STRENGTH,
} = require("../lib/caScope");

function policy(over = {}) {
  return {
    id: over.id || "p",
    displayName: over.displayName || "Policy",
    state: over.state || "enabled",
    conditions: {
      users: { includeUsers: ["All"], ...(over.users || {}) },
      applications: { includeApplications: ["All"], ...(over.applications || {}) },
      clientAppTypes: over.clientAppTypes || ["all"],
      signInRiskLevels: over.signInRiskLevels || [],
      userRiskLevels: over.userRiskLevels || [],
      authenticationFlows: over.authenticationFlows,
    },
    grantControls: over.grantControls || { operator: "OR", builtInControls: ["mfa"] },
    sessionControls: over.sessionControls || null,
  };
}

test("all users / all apps MFA is population coverage; a pilot group is not", () => {
  const all = effectiveScope(policy());
  assert.equal(all.allUsers, true);
  assert.equal(all.allApps, true);
  assert.equal(all.grants.requiresMfa, true);
  assert.equal(coversPopulation(all), true);

  const pilot = effectiveScope(policy({ users: { includeUsers: [], includeGroups: ["g-pilot"] } }));
  assert.equal(pilot.allUsers, false);
  assert.equal(coversPopulation(pilot), false);

  const oneApp = effectiveScope(policy({ applications: { includeApplications: ["some-app-id"] } }));
  assert.equal(oneApp.allApps, false);
  assert.equal(coversPopulation(oneApp), false);
});

test("excluding Global Administrator or many groups makes the policy hollow", () => {
  const exclGa = effectiveScope(
    policy({ users: { includeUsers: ["All"], excludeRoles: [GA_TEMPLATE] } }),
    { roleDefMap: { [GA_TEMPLATE]: "Global Administrator" } }
  );
  assert.deepEqual(exclGa.excludedGaRoles, ["Global Administrator"]);
  assert.equal(exclGa.broadExclusions, true);
  assert.equal(coversPopulation(exclGa), false);

  const bigGroup = effectiveScope(
    policy({ users: { includeUsers: ["All"], excludeGroups: ["g1"] } }),
    { groupMeta: { g1: { memberCount: 300 } } }
  );
  assert.equal(bigGroup.excludedGroupMembers, 300);
  assert.equal(bigGroup.broadExclusions, true);

  const breakGlass = effectiveScope(
    policy({ users: { includeUsers: ["All"], excludeUsers: ["bg1", "bg2"], excludeGroups: ["g1"] } }),
    { groupMeta: { g1: { memberCount: 2 } } }
  );
  assert.equal(breakGlass.broadExclusions, false, "two break-glass users + one small group is normal");
});

test("coverageVerdict: full / partial / none and human-readable reasons", () => {
  const scopes = [
    effectiveScope(policy({ id: "a", displayName: "Legacy pilot", users: { includeUsers: [], includeGroups: ["g"] }, clientAppTypes: ["exchangeActiveSync", "other"], grantControls: { builtInControls: ["block"] } })),
    effectiveScope(policy({ id: "b", displayName: "Legacy report-only", state: "enabledForReportingButNotEnforced", clientAppTypes: ["exchangeActiveSync", "other"], grantControls: { builtInControls: ["block"] } })),
  ];
  const pred = (s) => targetsLegacyClients(s) && s.grants.isBlock;
  let v = coverageVerdict(scopes, pred);
  assert.equal(v.status, "partial");
  assert.match(v.reasons[0], /Legacy pilot \(not all users\)/);
  assert.equal(v.reportOnly.length, 1);

  scopes.push(effectiveScope(policy({ id: "c", displayName: "Block legacy", clientAppTypes: ["exchangeActiveSync", "other"], grantControls: { builtInControls: ["block"] } })));
  v = coverageVerdict(scopes, pred);
  assert.equal(v.status, "full");
  assert.deepEqual(v.names, ["Block legacy"]);

  assert.equal(coverageVerdict([], pred).status, "none");
});

test("authentication strengths: built-in phishing-resistant and all-PR custom combos", () => {
  assert.equal(strengthIsPhishingResistant({ id: AUTH_STRENGTH.PHISHING_RESISTANT }), true);
  assert.equal(strengthIsPhishingResistant({ id: AUTH_STRENGTH.MFA }), false);
  const catalog = [
    { id: "custom-pr", allowedCombinations: ["fido2", "windowsHelloForBusiness"] },
    { id: "custom-mixed", allowedCombinations: ["fido2", "password,microsoftAuthenticatorPush"] },
  ];
  assert.equal(strengthIsPhishingResistant({ id: "custom-pr" }, catalog), true);
  assert.equal(strengthIsPhishingResistant({ id: "custom-mixed" }, catalog), false);

  const s = effectiveScope(
    policy({ users: { includeUsers: [], includeRoles: [GA_TEMPLATE] }, grantControls: { operator: "OR", authenticationStrength: { id: AUTH_STRENGTH.PHISHING_RESISTANT } } })
  );
  assert.equal(s.grants.phishingResistant, true);
  assert.equal(s.grants.requiresMfa, true);
});

test("session controls and auth flows are normalised", () => {
  const s = effectiveScope(
    policy({
      authenticationFlows: { transferMethods: "deviceCodeFlow,authenticationTransfer" },
      grantControls: { builtInControls: ["block"] },
      sessionControls: {
        signInFrequency: { isEnabled: true, type: "hours", value: 12 },
        persistentBrowser: { isEnabled: true, mode: "never" },
        secureSignInSession: { isEnabled: true },
        disableResilienceDefaults: true,
      },
    })
  );
  assert.deepEqual(s.authFlows, ["devicecodeflow", "authenticationtransfer"]);
  assert.equal(s.session.signInFrequency, "12h");
  assert.equal(s.session.persistentBrowser, "never");
  assert.equal(s.session.tokenProtection, true);
  assert.equal(s.session.disableResilienceDefaults, true);
  assert.equal(s.grants.isBlock, true);
});

test("detectMfaCoverageFromPolicies ignores names and risk-gated / user-action policies", () => {
  const policies = [
    policy({ displayName: "Whatever the admin called it" }),
    policy({ displayName: "Require MFA (risky)", signInRiskLevels: ["high"] }),
    policy({ displayName: "Register security info", applications: { includeApplications: [], includeUserActions: ["urn:user:registersecurityinfo"] } }),
  ];
  const r = detectMfaCoverageFromPolicies(policies);
  assert.equal(r.covered, true);
  assert.deepEqual(r.allUsersEvidence, ["Whatever the admin called it"]);

  const hollow = detectMfaCoverageFromPolicies(
    [policy({ displayName: "Require MFA for all", users: { includeUsers: ["All"], excludeRoles: [GA_TEMPLATE] } })],
    { roleDefMap: { [GA_TEMPLATE]: "Global Administrator" } }
  );
  assert.equal(hollow.covered, false);
  assert.equal(hollow.partial, true);
  assert.equal(hollow.broadExclusions, true);
  assert.match(hollow.reasons[0], /excludes Global Administrator/);
});
