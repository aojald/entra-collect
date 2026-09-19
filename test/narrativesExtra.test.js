const test = require("node:test");
const assert = require("node:assert");
const {
  runExtraRules,
  buildAttackChain,
  weakOnlyUsers,
} = require("../lib/narrativesExtra");
const {
  runRules,
  scoreFromNarratives,
  summarizeNoMfaBreakdown,
  isGuestAccount,
} = require("../lib/analyze");

function push(out, n) {
  out.push({
    Id: n.id,
    Severity: n.severity,
    Priority: n.priority || "Next",
    Title: n.title,
    Impact: n.impact || "",
    Narrative: n.narrative,
    Evidence: n.evidence || "",
    Remediation: n.remediation || "",
    Status: /^info$/i.test(n.severity) ? "Info" : "Fail",
    Confidence: n.confidence || "High",
  });
}

function extras(ctx) {
  const out = [];
  runExtraRules(ctx, out, push);
  return out;
}

function base(extra = {}) {
  return {
    summary: {},
    checklist: [],
    caCoverage: [],
    caAudit: [],
    caPoliciesRaw: null,
    gaPath: [],
    dangerous: [],
    priv: [],
    privHygiene: [],
    noMfa: [],
    legacy: [],
    exclGroups: [],
    rawFindings: [],
    cloudAppAdminOps: [],
    graphApiAudit: [],
    adminTooling: [],
    crossTenantTrust: [],
    deviceCodeUsers: [],
    risky: [],
    secretsExpiry: [],
    spCredentials: [],
    delegatedGrants: [],
    appLongLived: [],
    guests: [],
    inactiveAccounts: [],
    rmmFamily: [],
    rmmAssets: [],
    securityAlerts: [],
    ...extra,
    summary: { ...(extra.summary || {}) },
  };
}

test("weakOnlyUsers keeps accounts whose only factors are SMS / voice / email", () => {
  const rows = weakOnlyUsers([
    {
      isMfaRegistered: true,
      methodsRegistered: ["mobilePhone"],
      userPrincipalName: "sms@t",
    },
    {
      isMfaRegistered: true,
      methodsRegistered: ["mobilePhone", "microsoftAuthenticatorPush"],
      userPrincipalName: "both@t",
    },
    {
      isMfaRegistered: false,
      methodsRegistered: [],
      userPrincipalName: "none@t",
    },
  ]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].userPrincipalName, "sms@t");
});

test("seven extra narratives fire from tenant-agnostic signals", () => {
  const out = extras({
    summary: {
      usersWithoutMfa: 12,
      deviceJoinGlobalAdminsLocalAdmin: true,
      globalAdminPermanent: 4,
      devicesEntraJoined: 80,
      deviceLapsEnabled: false,
      caOrphanUserReferences: 3,
    },
    authMethodsCsv: [
      { Method: "Sms", State: "enabled" },
      { Method: "Voice", State: "enabled" },
      { Method: "Email", State: "disabled" },
    ],
    regDetailsRaw: [
      {
        isMfaRegistered: true,
        isAdmin: true,
        methodsRegistered: ["mobilePhone"],
        userPrincipalName: "ga@contoso.com",
      },
    ],
    checklist: [
      { CheckId: "AP.CA.SecInfoReg", Status: "Fail", Evidence: "none" },
      {
        CheckId: "AP.CA.SessionControls",
        Status: "Fail",
        Evidence: "signInFrequency: none",
      },
      { CheckId: "AP.App.Management", Status: "Fail", Evidence: "none" },
    ],
    dangerous: [
      {
        SPNDisplayName: "MailBackup",
        PrincipalId: "sp-1",
        Permission: "full_access_as_app",
        ResourceApp: "Office 365 Exchange Online",
      },
    ],
    spCredentials: [
      {
        SPNDisplayName: "MailBackup",
        CredentialType: "secret",
        LongLived: "true",
        Expired: "false",
        MicrosoftOwned: "false",
        LifetimeDays: 900,
      },
    ],
    appLongLived: [],
    secretsExpiry: [],
    crossTenantTrust: [
      {
        Scope: "default",
        TrustMfa: "true",
        TrustCompliantDevice: "false",
        TrustHybridJoined: "false",
      },
    ],
    guests: [{ AccountEnabled: "true" }, { AccountEnabled: "true" }],
    caOrphanRefs: [
      {
        PolicyName: "Microsoft-managed: per-user MFA",
        State: "enabledForReportingButNotEnforced",
        OrphanIncludeUsers: 3,
        OrphanExcludeUsers: 0,
      },
    ],
    securityAlerts: [],
    rmmFamily: [],
    privHygiene: [],
  });
  const ids = out.map((n) => n.Id);
  for (const id of [
    "NARR.MFA.WeakMethods",
    "NARR.App.MailboxAccess",
    "NARR.App.SecretLifecycle",
    "NARR.CA.SessionControls",
    "NARR.External.InboundTrust",
    "NARR.CA.OrphanReferences",
    "NARR.Devices.LocalAdmin",
  ]) {
    assert.ok(ids.includes(id), `missing ${id}: ${ids.join(",")}`);
  }
  assert.ok(out.every((n) => n.Impact), "every extra narrative needs an Impact line");
});

test("attack chain emits only when three stages are open and is score-neutral", () => {
  const seed = [
    {
      Id: "NARR.MFA.WeakMethods",
      Severity: "High",
      Title: "SMS still counts",
      Remediation: "Disable SMS.",
    },
    {
      Id: "NARR.CA.SecInfoReg",
      Severity: "High",
      Title: "Registration unprotected",
      Remediation: "Protect register security info.",
    },
    {
      Id: "NARR.App.PathToGA",
      Severity: "Critical",
      Title: "App can grant GA",
      Remediation: "Remove RoleManagement.",
    },
    {
      Id: "NARR.App.MailboxAccess",
      Severity: "High",
      Title: "Mailbox apps",
      Remediation: "Restrict ApplicationAccessPolicy.",
    },
  ];
  const out = seed.slice();
  buildAttackChain(out, push);
  const chain = out.find((n) => n.Id === "NARR.Chain.ShortestPath");
  assert.ok(chain);
  assert.match(chain.Title, /4 of 4|3 of 4|stages are open/i);
  const scored = scoreFromNarratives(out);
  const without = scoreFromNarratives(seed);
  assert.equal(scored.score, without.score);
  assert.equal(scored.sevCount.Critical, without.sevCount.Critical);
});

test("MassGap titles members, not the raw guest-heavy count", () => {
  const noMfa = [
    ...Array.from({ length: 40 }, (_, i) => ({
      UPN: `g${i}_ext.com#EXT#@tenant.onmicrosoft.com`,
      DisplayName: `Guest ${i}`,
      UserType: "Guest",
      IsAdmin: "false",
      AccountEnabled: "true",
    })),
    ...Array.from({ length: 25 }, (_, i) => ({
      UPN: `user${i}@tenant.com`,
      DisplayName: `User ${i}`,
      UserType: "Member",
      IsAdmin: "false",
      AccountEnabled: "true",
    })),
  ];
  const narr = runRules(base({
    summary: { usersWithoutMfa: 65, adminsWithoutMfa: 0 },
    noMfa,
    caAudit: [],
    checklist: [],
    caCoverage: [],
    crossTenantTrust: [
      { Scope: "default", TrustMfa: "true", TrustCompliantDevice: "false", TrustHybridJoined: "false" },
    ],
  }));
  const gap = narr.find((n) => n.Id === "NARR.MFA.MassGap");
  assert.ok(gap, "MassGap should fire for 25 unregistered members");
  assert.match(gap.Title, /25 member/i);
  assert.doesNotMatch(gap.Title, /65/);
  assert.match(gap.Evidence, /guestHeavy=true/);
  assert.match(gap.Narrative, /40 guest/i);
});

test("ExclGroups ignores complementary groups and counts only real bypasses", () => {
  const narr = runRules(base({
    checklist: [{ CheckId: "AP.CA.ExclGroups", Status: "Fail", Evidence: "5/7 weak" }],
    exclGroups: [
      {
        DisplayName: "Guests (covered elsewhere)",
        Complementary: "true",
        Hardened: "true",
        Risk: "Complementary — include target of guest MFA",
        MemberCount: 300,
      },
      {
        DisplayName: "Travel exceptions",
        Complementary: "false",
        Hardened: "false",
        Risk: "Weak — any User Administrator can add members",
        MemberCount: 3,
        Dynamic: "false",
      },
      {
        DisplayName: "Field techs",
        Complementary: "false",
        Hardened: "false",
        Risk: "Weak — any User Administrator can add members",
        MemberCount: 21,
        Dynamic: "false",
      },
    ],
  }));
  const row = narr.find((n) => n.Id === "NARR.CA.ExclGroups");
  assert.ok(row);
  assert.match(row.Title, /2 CA exclusion/i);
  assert.match(row.Narrative, /complementary/i);
  assert.doesNotMatch(row.Title, /300/);
});

test("Legacy.NoCA says report-only policies do not block", () => {
  const narr = runRules(base({
    summary: { legacyAuth90d: 0 },
    checklist: [
      {
        CheckId: "AP.CA.LegacyBlock",
        Status: "Partial",
        Evidence:
          "Report-only only — not enforced: Microsoft-managed: Block legacy authentication | Baseline Security Mode: Block legacy authentication",
      },
    ],
    caCoverage: [{ Control: "Legacy auth block", Covered: "partial" }],
    legacy: [],
  }));
  const row = narr.find((n) => n.Id === "NARR.Legacy.NoCA");
  assert.ok(row);
  assert.match(row.Title, /report-only/i);
  assert.match(row.Narrative, /do not deny|stops nothing|Turning the existing/i);
});

test("AzureMgmt rises when Azure PowerShell sign-ins are observed", () => {
  const narr = runRules(base({
    checklist: [
      {
        CheckId: "AP.CA.AzureMgmt",
        Status: "Partial",
        Evidence: "Admin portals only",
      },
    ],
    adminTooling: [
      {
        Application: "Microsoft Azure PowerShell",
        SignIns: 11,
        Users: "admin@tenant.com",
      },
    ],
    caAudit: [],
  }));
  const row = narr.find((n) => n.Id === "NARR.CA.AzureMgmt");
  assert.ok(row);
  assert.equal(row.Severity, "High");
  assert.equal(row.Priority, "Now");
  assert.match(row.Narrative, /Azure PowerShell/i);
  assert.match(row.Narrative, /admin@tenant.com/);
});

test("summarizeNoMfaBreakdown does not count guests as humans", () => {
  assert.equal(isGuestAccount({ UserType: "Guest", UPN: "a@t" }), true);
  assert.equal(isGuestAccount({ UserType: "Member", UPN: "x_ext.com#EXT#@t" }), false);
  const b = summarizeNoMfaBreakdown([
    { UPN: "g_x.com#EXT#@t", DisplayName: "G", UserType: "Guest" },
    { UPN: "jane@t.com", DisplayName: "Jane Doe", UserType: "Member" },
    { UPN: "room@t.com", DisplayName: "Conf Room", UserType: "Member" },
  ]);
  assert.equal(b.guest, 1);
  assert.equal(b.human, 1);
  assert.equal(b.room, 1);
  assert.equal(b.total, 3);
});
