/**
 * Expert / narrative analyzer — second pass over collector CSVs.
 *
 * Unlike inventory findings (one check → one row), this joins signals across
 * files into attack narratives (Critical / High / Medium) for the report.
 *
 * Purely static rules — no LLM. Safe to re-run on any output_* folder.
 */
const fs = require("fs");
const path = require("path");
const { createIo } = require("./io");
const { parseCsv } = require("./csv");
const {
  enrichRmmAssets,
  summarizeRmmByFamily,
  formatAssetLine,
} = require("./rmmClassify");
const {
  clusterAppControlPlane,
  clusterAlertsBySource,
  splitTvmVulns,
  tvmSeverity,
  patchLagFromSoftwareVersions,
  aggregateFailuresByIp,
  identityInfoActionable,
  isCopilotOrAgentUpn,
  detectEnforcedMfaCoverage,
  buildSpnActivityIndex,
  spnIdentityKeys,
  spnIsActive,
  isReportOnlyFleetComplianceRow,
  normName,
} = require("./posture");

const ROLE_MGMT_PERM = "RoleManagement.ReadWrite.Directory";
const GA_PATH_PERMS = new Set([
  "RoleManagement.ReadWrite.Directory",
  "AppRoleAssignment.ReadWrite.All",
  "Application.ReadWrite.All",
  "Directory.ReadWrite.All",
]);

const HIGH_PRIV_ROLE_RE =
  /Global Administrator|Privileged Role Administrator|Privileged Authentication Administrator|Security Administrator|Application Administrator|Cloud Application Administrator|Authentication Administrator|Conditional Access Administrator|User Administrator|Exchange Administrator|SharePoint Administrator|Intune Administrator|Hybrid Identity Administrator/i;

function readJson(p) {
  try {
    return JSON.parse(fs.readFileSync(p, "utf8"));
  } catch {
    return null;
  }
}

function readCsv(p) {
  try {
    return parseCsv(fs.readFileSync(p, "utf8"));
  } catch {
    return [];
  }
}

function truthy(v) {
  const s = String(v ?? "").toLowerCase();
  return s === "true" || s === "1" || s === "yes";
}

function normUpn(u) {
  return String(u || "")
    .trim()
    .toLowerCase();
}

function caCovered(caCoverage, controlRe) {
  const row = (caCoverage || []).find((r) =>
    controlRe.test(String(r.Control || r.control || ""))
  );
  if (!row) return null;
  const v = String(row.Covered || row.covered || "").toLowerCase();
  if (v === "true" || v === "yes" || v === "1") return true;
  if (v === "false" || v === "no" || v === "0") return false;
  return null;
}

function checklistStatus(checklist, id) {
  const row = (checklist || []).find(
    (r) => String(r.CheckId || "").toUpperCase() === id.toUpperCase()
  );
  return row ? String(row.Status || "") : "";
}

function sevRank(s) {
  return { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 }[s] ?? 9;
}

/**
 * How broadly each account is excluded from *enforced* Conditional Access.
 *
 * This is what separates a designed break-glass account from a forgotten admin:
 * break-glass is deliberately carved out of nearly every policy so it still
 * works when CA itself is the outage, whereas a forgotten admin is excluded
 * from nothing. Both look identical in an inactivity report, and calling the
 * first one Critical burns the reader's trust in the rest of the findings.
 *
 * Only user-level exclusions are counted. Group-level exclusions are resolved
 * by name elsewhere and are far less reliable to attribute to one account.
 */
function buildCaExclusionIndex(caAudit) {
  const enforced = (caAudit || []).filter((r) => {
    const st = String(r.State || "");
    return /^enabled$/i.test(st) || String(r.IsEnforced || "").toLowerCase() === "yes";
  });
  // The column is a display list: "Jane Doe <jane.doe@tenant> | Svc <…>".
  const byUpn = new Map();
  for (const r of enforced) {
    const raw = String(r.ExcludeUsers || "");
    if (!raw.trim()) continue;
    const seen = new Set();
    for (const m of raw.matchAll(/<([^>]+@[^>]+)>/g)) {
      const upn = m[1].trim().toLowerCase();
      if (seen.has(upn)) continue;
      seen.add(upn);
      if (!byUpn.has(upn)) byUpn.set(upn, []);
      byUpn.get(upn).push(String(r.PolicyName || "").trim());
    }
  }
  return { enforcedCount: enforced.length, byUpn };
}

/**
 * Break-glass signature: excluded from most enforced CA policies, holding GA,
 * and ideally cloud-only on the tenant's .onmicrosoft.com domain. Dormancy is
 * expected for these — an emergency account that gets used routinely is not an
 * emergency account — so it is not part of the test.
 */
function classifyBreakGlass(upn, caIndex, { isGa = false } = {}) {
  const policies = caIndex.byUpn.get(String(upn || "").toLowerCase()) || [];
  const total = caIndex.enforcedCount || 0;
  const ratio = total ? policies.length / total : 0;
  const cloudOnly = /\.onmicrosoft\.com$/i.test(upn || "");
  const broad = policies.length >= 8 || (total >= 4 && ratio >= 0.6);
  return {
    isBreakGlass: broad && isGa,
    excludedFrom: policies.length,
    enforcedTotal: total,
    ratio,
    cloudOnly,
    policies,
  };
}

/** Enforced CA suggests unlicensed / unmanaged users are blocked or MFA is license-scoped. */
function detectLicenseGatedAccess(caAudit) {
  const enforced = (caAudit || []).filter((r) => {
    const st = String(r.State || "");
    return /^enabled$/i.test(st) || String(r.IsEnforced || "").toLowerCase() === "yes";
  });
  const hasBlockExcludingLicenses = enforced.some((r) => {
    const grant = String(r.GrantControls || "").toLowerCase();
    const excl = String(r.ExcludeGroups || "");
    const name = String(r.PolicyName || "");
    return (
      grant.includes("block") &&
      (/licen/i.test(excl) || /unmanaged|unlicensed|sans licence/i.test(name))
    );
  });
  const hasMfaForLicenseGroup = enforced.some((r) => {
    const blob = `${r.PolicyName || ""} ${r.GrantControls || ""} ${r.AuthStrength || ""}`;
    const incl = String(r.IncludeGroups || "");
    return /mfa|multifactor|authentication strength|require mfa/i.test(blob) && /licen/i.test(incl);
  });
  const evidence = [];
  for (const r of enforced) {
    const name = r.PolicyName || "";
    if (
      (/block/i.test(r.GrantControls || "") && /licen|unmanaged/i.test(`${name} ${r.ExcludeGroups || ""}`)) ||
      (/mfa|require mfa/i.test(`${name} ${r.GrantControls || ""}`) && /licen/i.test(r.IncludeGroups || ""))
    ) {
      evidence.push(name);
    }
  }
  return {
    gated: hasBlockExcludingLicenses || hasMfaForLicenseGroup,
    evidence: evidence.slice(0, 6),
  };
}

/**
/** Microsoft first-party apps that often hold Directory.ReadWrite.All for backup/platform. */
function isMicrosoftFirstPartyApp(name) {
  const n = String(name || "");
  return (
    /^(Microsoft |Office 365|Azure |Windows Azure|Dynamics |SharePoint |OneDrive |Teams |Power BI|Power Apps|Power Automate|Intune |Defender |Microsoft365|Microsoft 365)/i.test(
      n
    ) || /Microsoft 365 Backup/i.test(n)
  );
}

/** Device-registration MFA: "notRequired" must NOT match /required/. */
function isDeviceRegMfaOff(mfa) {
  return /notRequired|disabled|none|^false$/i.test(String(mfa || ""));
}
function isDeviceRegMfaRequired(mfa) {
  const s = String(mfa || "");
  return !isDeviceRegMfaOff(s) && /^required$/i.test(s);
}

function looksLikeBackupOrSocApp(name) {
  return /avepoint|backup|veeam|commvault|rubrik|druva|cloudiway|metalogix|sharegate|quest|skykick|barracuda|soc\b|sentinel|defender/i.test(
    String(name || "")
  );
}

/**
 * What a third-party app of this class actually needs, so the finding can say
 * "replace X with Y" instead of "confirm business need".
 *
 * The distinction that matters is whether the vendor's function genuinely
 * requires write access. A SOC reads and responds — it never needs to grant
 * directory roles. A backup product does need write, but only to restore, and
 * only to the object types it backs up; role assignment is a separate decision
 * that is almost always left switched on by default.
 */
const VENDOR_PROFILES = [
  {
    re: /soc\b|sentinel|devensys|arctic|expel|mdr\b|siem/i,
    kind: "SOC / MDR",
    keep: [
      "Policy.Read.All",
      "Directory.Read.All",
      "AuditLog.Read.All",
      "SecurityEvents.Read.All",
      "SecurityIncident.Read.All",
      "IdentityRiskEvent.Read.All",
    ],
    response: [
      "SecurityIncident.ReadWrite.All",
      "SecurityAlert.ReadWrite.All",
      "User.RevokeSessions.All",
    ],
    note:
      "A SOC needs to see the configuration and the logs, and at most to contain an account. Reading Conditional Access is Policy.Read.All; revoking a compromised user's sessions is User.RevokeSessions.All, not User.ReadWrite.All. RoleManagement.ReadWrite.Directory has no detection or response use at all — it is the permission that lets the app make itself Global Administrator, so a SOC holding it means a breach at the provider is a breach of your tenant. If the provider genuinely needs to change your CA policies, do it as named human engineers with a PIM-eligible Conditional Access Administrator role requiring approval and justification: you keep per-person attribution in the audit log, which an app-only token destroys.",
  },
  {
    re: /avepoint|veeam|commvault|rubrik|druva|keepit|backup|afi\.ai|skykick/i,
    kind: "Backup / restore",
    keep: [
      "Directory.Read.All",
      "Policy.Read.All",
      "Sites.Read.All",
      "Files.Read.All",
      "Mail.Read",
    ],
    response: ["Directory.ReadWrite.All", "Policy.ReadWrite.ConditionalAccess"],
    note:
      "Backup only needs read; the write grants exist for restore. That asymmetry is the lever: split the vendor into two app registrations, one read-only that runs daily, and one write-capable used only during an actual restore, kept credential-disabled the rest of the time. RoleManagement.ReadWrite.Directory and AppRoleAssignment.ReadWrite.All are only required if you restore role assignments and app grants — decide that explicitly rather than accepting the vendor's default consent screen, because those two are what turn a backup product into a Global Admin path.",
  },
  {
    re: /varonis|netwrix|dspm|purview|data risk|scanning/i,
    kind: "Data security / DSPM",
    keep: [
      "Directory.Read.All",
      "User.Read.All",
      "Group.Read.All",
      "Sites.Read.All",
      "AuditLog.Read.All",
    ],
    response: [],
    note:
      "Classification and access analytics are read-only workloads. User.ReadWrite.All / Group.ReadWrite.All are only needed if the product remediates permissions for you; if you do not use that feature, the grant is pure attack surface.",
  },
  {
    re: /pnp|community|script|powershell|automation|logic-/i,
    kind: "Internal automation / community tool",
    keep: ["User.Read.All", "Group.Read.All", "Directory.Read.All"],
    response: [],
    note:
      "Prefer a managed identity over an app registration with a secret, and scope write access to the specific objects the job touches — for mail-sending automation, an ApplicationAccessPolicy limits Mail.Send to a single mailbox instead of the whole tenant.",
  },
];

function vendorProfile(name) {
  return VENDOR_PROFILES.find((p) => p.re.test(String(name || ""))) || null;
}

/** Per-app "replace these grants with these" lines, for narrative remediation. */
function leastPrivilegeAdvice(appNames) {
  const out = [];
  for (const name of appNames) {
    const p = vendorProfile(name);
    if (!p) continue;
    out.push(
      `${name} (${p.kind}): read-only equivalent is ${p.keep.slice(0, 4).join(", ")}` +
        (p.response.length
          ? `; if it must act, ${p.response.join(", ")} are the narrow write grants`
          : "") +
        `. ${p.note}`
    );
  }
  return out;
}

function looksLikeServiceAccount(upn, displayName) {
  const local = String(upn || "").split("@")[0] || "";
  const blob = `${upn || ""} ${displayName || ""}`.toLowerCase();
  return (
    /^(svc[-._]|sa[-._]|service[-._]|spn[-._]|sync_|adm[-._]|admin[-._])/i.test(local) ||
    /^(powerbi|noreply|no-reply|saas_|svc)/i.test(local) ||
    /\bservice\b|\bsvc\b|backup|avepoint|sync|provision|automation|break.?glass|power\s*bi/i.test(
      blob
    )
  );
}

/** Heuristic bucket for MFA / inactive inventory rows (human vs room/shared/svc). */
function classifyAccountKind(upn, displayName) {
  if (isCopilotOrAgentUpn(upn)) return "service";
  const blob = `${upn || ""} ${displayName || ""}`;
  if (/\b(salle|salon|room|meeting|boardroom)\b/i.test(blob)) return "room";
  if (
    looksLikeServiceAccount(upn, displayName) ||
    /^(svc|sa|service|adm|admin)[-_.]|\bservice\b|\bsvc\b/i.test(blob)
  ) {
    return "service";
  }
  const local = String(upn || "").split("@")[0];
  if (
    /(no-?reply|contact|info|accueil|communication|event|compta|facturation|standard|scan|print|booking|subscription|newsletter|mailing|distribution|shared|internship|compliance|support|helpdesk|fundmgnt|payroll|recrut)/i.test(
      local
    ) ||
    /\b(shared|mailbox|distribution list|liste|training room)\b/i.test(
      String(displayName || "")
    )
  ) {
    return "shared";
  }
  return "human";
}

function summarizeNoMfaBreakdown(noMfaRows) {
  const buckets = { human: 0, room: 0, service: 0, shared: 0 };
  for (const r of noMfaRows || []) {
    const k = classifyAccountKind(
      r.UPN || r.UserPrincipalName,
      r.DisplayName
    );
    buckets[k] = (buckets[k] || 0) + 1;
  }
  const nonHuman = buckets.room + buckets.service + buckets.shared;
  return { ...buckets, nonHuman, total: (noMfaRows || []).length };
}

function pushNarrative(out, n) {
  const severity = n.severity;
  const id = n.id;
  const priority =
    n.priority ||
    (severity === "Critical" ||
    /RoleManagement|ExternalGA|PathToGA|DeviceCode\.Privileged|StandingGA|Risk\.Privileged|BreakGlass|MspStanding|TapAutomation|CaPolicyWrite|TrustedIp/i.test(
      id
    )
      ? "Now"
      : severity === "High"
        ? "Next"
        : "Later");
  out.push({
    Id: id,
    Severity: severity,
    Priority: priority,
    Title: n.title,
    Narrative: n.narrative,
    Evidence: n.evidence || "",
    Remediation: n.remediation || "",
    RelatedFiles: (n.relatedFiles || []).join(" | "),
    RelatedChecks: (n.relatedChecks || []).join(" | "),
  });
}

/**
 * Load all inputs needed for correlation from an output directory.
 */
function loadContext(outDir) {
  const summary = readJson(path.join(outDir, "00_SUMMARY.json")) || {};
  const rawFindings = readCsv(path.join(outDir, "00_Findings.csv"));
  const checklist = readCsv(path.join(outDir, "40_AttackPath_Checklist.csv"));
  const caCoverage = readCsv(path.join(outDir, "40_CA_AttackPath_Coverage.csv"));
  const priv = readCsv(path.join(outDir, "03_PrivilegedAccounts_HighValue.csv"));
  const privHygiene = readCsv(
    path.join(outDir, "40_Privileged_Identity_Hygiene.csv")
  );
  const privSpnCreds = readCsv(
    path.join(outDir, "40_Privileged_SPN_Credentials.csv")
  );
  const gaPath = readCsv(path.join(outDir, "40_Apps_Path_To_GA.csv"));
  const dangerous = readCsv(path.join(outDir, "04_SPN_DangerousPerms.csv"));
  const deviceCodeUsers =
    readCsv(path.join(outDir, "20_DeviceCode_Users_90d.csv")).length
      ? readCsv(path.join(outDir, "20_DeviceCode_Users_90d.csv"))
      : readCsv(path.join(outDir, "20_DeviceCode_Users_30d.csv"));
  const legacy = readCsv(path.join(outDir, "21_LegacyAuth_Success_90d.csv"));
  const legacyByAccount = pickNonEmpty(outDir, [
    "21_LegacyAuth_ByAccount_90d.csv",
    "21_LegacyAuth_ByAccount_30d.csv",
  ]);
  const risky = readCsv(path.join(outDir, "24_RiskyUsers.csv"));
  const riskDetections = readCsv(path.join(outDir, "24_RiskDetections_90d.csv"));
  const caAudit = readCsv(path.join(outDir, "02_CA_Audit.csv"));
  const exclGroups = readCsv(path.join(outDir, "40_CA_Exclusion_Groups.csv"));
  const rmmFamily = readCsv(path.join(outDir, "30_RMM_Family_Summary.csv"));
  const rmmAssets = readCsv(path.join(outDir, "30_RMM_Affected_Assets.csv"));
  const rmmDetections = readCsv(path.join(outDir, "30_RMM_Detections.csv"));
  const defenderVulns = readCsv(
    path.join(outDir, "11_Defender_Exploitable_Vulns.csv")
  );
  const tvmWin = readCsv(path.join(outDir, "32_TVM_Windows_HighCritical.csv"));
  const patchBehind = readCsv(path.join(outDir, "32_Behind_PatchTuesday.csv"));
  const osPatchStatus = readCsv(
    path.join(outDir, "32_Endpoints_OS_PatchStatus.csv")
  );
  const patchTuesdayRef = readJson(
    path.join(outDir, "30_patch_tuesday_reference.json")
  );
  const win10 = readCsv(path.join(outDir, "32_Windows10_Devices.csv"));
  const genAiUsers = readCsv(path.join(outDir, "34_GenAI_Usage_ByUser.csv"));
  const genAiApps = readCsv(path.join(outDir, "34_GenAI_Usage_ByApp.csv"));
  const fileShareUsers = readCsv(
    path.join(outDir, "35_FileShare_Usage_ByUser.csv")
  );
  const fileShareApps = readCsv(
    path.join(outDir, "35_FileShare_Usage_ByApp.csv")
  );
  const devicesPerUserMulti = readCsv(
    path.join(outDir, "09_Devices_Per_User_Multi.csv")
  );
  const secretsExpiry = readCsv(path.join(outDir, "04_App_SecretsExpiry.csv"));
  const aiAgents = readCsv(path.join(outDir, "31_AI_Agents_Summary.csv"));
  const cloudApp90 = readCsv(
    path.join(outDir, "25_HighValue_CloudAppEvents_90d.csv")
  );
  const cloudAppHigh = cloudApp90.length
    ? cloudApp90
    : readCsv(path.join(outDir, "25_HighValue_CloudAppEvents_30d.csv"));
  const outboundMail = readCsv(
    path.join(outDir, "18_Outbound_Email_Domains_30d.csv")
  );
  const consumerOutbound = readCsv(
    path.join(outDir, "18_Consumer_Outbound_BySender_30d.csv")
  );
  const namedLocations = readCsv(path.join(outDir, "02_NamedLocations.csv"));

  // Activity data. Configuration tells you what *could* happen; these tell you
  // what actually did, which is what separates a theoretical finding from a
  // demonstrated one.
  const spnSignIns = pickNonEmpty(outDir, [
    "27_SPN_SignIns_90d.csv",
    "27_SPN_SignIns_30d.csv",
  ]);
  const inactiveAccounts = pickNonEmpty(outDir, [
    "08_Accounts_Inactive_90d.csv",
    "08_Accounts_Inactive_30d.csv",
  ]);
  const guests = readCsv(path.join(outDir, "05_guests.csv"));
  const noMfa = readCsv(path.join(outDir, "07_Users_Without_MFA.csv"));
  // Prefer in-scope ByCategory; never fall back to the full profile catalog
  // (empty CurrentScore rows inflate gaps). Rebuild from live JSON if needed.
  let secureScoreControls = readCsv(
    path.join(outDir, "10_SecureScore_ByCategory.csv")
  );
  if (!secureScoreControls.length) {
    try {
      const {
        buildInScopeControls,
      } = require("./securescore");
      const latest = readJson(
        path.join(outDir, "10_secure_score_latest.json")
      );
      const profiles = readJson(
        path.join(outDir, "10_secure_score_control_profiles.json")
      );
      secureScoreControls = buildInScopeControls(latest, profiles);
    } catch {
      secureScoreControls = [];
    }
  }
  const secureScoreRollup = readCsv(
    path.join(outDir, "10_SecureScore_Category_Rollup.csv")
  );

  // Adaptive intel (works with or without MDE Device* tables)
  const securityAlerts = readCsv(path.join(outDir, "36_Security_Alerts_30d.csv"));
  const exposureAssets = readCsv(
    path.join(outDir, "37_Exposure_Critical_Assets.csv")
  );
  const exposurePaths = readCsv(
    path.join(outDir, "37_Exposure_Critical_Paths.csv")
  );
  const failedLogons = readCsv(
    path.join(outDir, "38_Identity_Failed_Logons_30d.csv")
  );
  const privilegedLogons = readCsv(
    path.join(outDir, "38_Identity_Privileged_Logons_30d.csv")
  );
  const identityInfoCritical = readCsv(
    path.join(outDir, "38_IdentityInfo_Critical.csv")
  );
  const identityAccountInfo = readCsv(
    path.join(outDir, "38_IdentityAccountInfo_Privileged.csv")
  );
  const cloudAppAdminOps = readCsv(
    path.join(outDir, "39_CloudApp_Admin_Operations_30d.csv")
  );
  const privilegedSignIns = readCsv(
    path.join(outDir, "28_Privileged_SignIns_30d.csv")
  );
  const spnSignInDigest = pickNonEmpty(outDir, [
    "27_SPN_SignIns_Digest_90d.csv",
    "27_SPN_SignIns_Digest_30d.csv",
  ]);
  const failedSignInsByIp = pickNonEmpty(outDir, [
    "22_FailedSignIns_ByIP_90d.csv",
    "22_FailedSignIns_ByIP_30d.csv",
  ]);
  const singleFactor = pickNonEmpty(outDir, [
    "23_SingleFactor_Success_90d.csv",
    "23_SingleFactor_Success_30d.csv",
  ]);
  const graphApiAudit = readCsv(
    path.join(outDir, "39_GraphAPI_Write_Audit_30d.csv")
  );
  const passwordSettings = readCsv(
    path.join(outDir, "12_DirectorySettings_Password.csv")
  );
  const authStrengths = readCsv(
    path.join(outDir, "01_Authentication_Strengths.csv")
  );
  const mfaCampaign = readCsv(
    path.join(outDir, "01_MFA_Registration_Campaign.csv")
  );
  const identitySecureScore = readCsv(
    path.join(outDir, "10_IdentitySecureScore_Controls.csv")
  );
  const gdapRelationships = readCsv(
    path.join(outDir, "15_GDAP_Relationships.csv")
  );
  const partnerContracts = readCsv(path.join(outDir, "15_Partner_Contracts.csv"));
  const deviceRegPolicy = readJson(
    path.join(outDir, "06_device_registration_policy.json")
  );

  return {
    outDir,
    summary,
    rawFindings,
    checklist,
    caCoverage,
    priv,
    privHygiene,
    privSpnCreds,
    gaPath,
    dangerous,
    deviceCodeUsers,
    legacy,
    legacyByAccount,
    risky,
    riskDetections,
    caAudit,
    exclGroups,
    rmmFamily,
    rmmAssets,
    rmmDetections,
    defenderVulns,
    tvmWin,
    patchBehind,
    osPatchStatus,
    patchTuesdayRef,
    win10,
    genAiUsers,
    genAiApps,
    fileShareUsers,
    fileShareApps,
    devicesPerUserMulti,
    secretsExpiry,
    aiAgents,
    cloudAppHigh,
    outboundMail,
    consumerOutbound,
    namedLocations,
    spnSignIns,
    spnSignInDigest,
    privilegedSignIns,
    failedSignInsByIp,
    singleFactor,
    graphApiAudit,
    passwordSettings,
    authStrengths,
    mfaCampaign,
    identitySecureScore,
    gdapRelationships,
    partnerContracts,
    deviceRegPolicy,
    inactiveAccounts,
    guests,
    noMfa,
    secureScoreControls,
    secureScoreRollup,
    securityAlerts,
    exposureAssets,
    exposurePaths,
    failedLogons,
    privilegedLogons,
    identityInfoCritical,
    identityAccountInfo,
    cloudAppAdminOps,
  };
}

/** First candidate file that actually has rows (windows shrink per tenant). */
function pickNonEmpty(outDir, names) {
  for (const n of names) {
    const rows = readCsv(path.join(outDir, n));
    if (rows.length) return rows;
  }
  return [];
}

function buildPrivIndex(priv, privHygiene) {
  /** @type {Map<string, { upn: string, roles: Set<string>, isGa: boolean, synced: boolean|null, enabled: boolean|null, mfa: boolean|null }>} */
  const byUpn = new Map();

  const ensure = (upn) => {
    const k = normUpn(upn);
    if (!k) return null;
    if (!byUpn.has(k)) {
      byUpn.set(k, {
        upn: k,
        roles: new Set(),
        isGa: false,
        synced: null,
        enabled: null,
        mfa: null,
      });
    }
    return byUpn.get(k);
  };

  for (const r of priv || []) {
    const upn = r.UPNOrAppId || r.UPN || "";
    if (!/@/.test(upn)) continue;
    const e = ensure(upn);
    if (!e) continue;
    const role = r.RoleName || "";
    if (role) e.roles.add(role);
    if (/^Global Administrator$/i.test(role)) e.isGa = true;
  }

  for (const r of privHygiene || []) {
    const e = ensure(r.UPN);
    if (!e) continue;
    const roles = String(r.Roles || "")
      .split("|")
      .map((x) => x.trim())
      .filter(Boolean);
    for (const role of roles) e.roles.add(role);
    if (truthy(r.IsGlobalAdmin) || roles.some((x) => /^Global Administrator$/i.test(x))) {
      e.isGa = true;
    }
    if (r.OnPremSynced !== "" && r.OnPremSynced != null) {
      e.synced = truthy(r.OnPremSynced);
    }
    if (r.AccountEnabled !== "" && r.AccountEnabled != null) {
      e.enabled = truthy(r.AccountEnabled);
    }
    if (r.MfaRegistered !== "" && r.MfaRegistered != null) {
      e.mfa = truthy(r.MfaRegistered);
    }
  }

  return byUpn;
}

function isHighPriv(entry) {
  if (!entry) return false;
  if (entry.isGa) return true;
  for (const role of entry.roles) {
    if (HIGH_PRIV_ROLE_RE.test(role)) return true;
  }
  return false;
}

/**
 * Run static correlation rules → expert narratives.
 */
function runRules(ctx) {
  const narratives = [];
  const privIndex = buildPrivIndex(ctx.priv, ctx.privHygiene);
  const riskyByUpn = new Map();
  for (const r of ctx.risky || []) {
    const u = normUpn(r.UPN || r.UserPrincipalName);
    if (u) riskyByUpn.set(u, r);
  }

  const deviceCodeBlocked = caCovered(
    ctx.caCoverage,
    /device.?code|auth.?transfer/i
  );
  const legacyBlocked = caCovered(ctx.caCoverage, /legacy/i);
  const userRiskCa = caCovered(
    ctx.caCoverage,
    /user.?risk|high.?risk.?user|password change for high risk/i
  );
  const guestMfaCa = caCovered(ctx.caCoverage, /guest/i);
  const secInfoCa = caCovered(ctx.caCoverage, /security.?info|register/i);

  // ── NARR.DeviceCode.Privileged — Critical when priv account uses device code ─
  {
    const hits = [];
    for (const u of ctx.deviceCodeUsers || []) {
      const upn = normUpn(u.UPN);
      const priv = privIndex.get(upn);
      if (!priv || !isHighPriv(priv)) continue;
      if (priv.enabled === false) continue; // disabled → no live-path alert
      const risk = riskyByUpn.get(upn);
      hits.push({
        upn,
        events: u.Events || "",
        apps: u.Apps || "",
        ips: u.Ips || "",
        isGa: priv.isGa,
        roles: [...priv.roles].join(" | "),
        riskLevel: risk ? risk.RiskLevel || risk.riskLevel || "" : "",
        riskState: risk ? risk.RiskState || risk.riskState || "" : "",
        enabled: priv.enabled,
      });
    }
    if (hits.length) {
      const anyGa = hits.some((h) => h.isGa);
      const anyRisk = hits.some((h) => h.riskLevel || h.riskState);
      const sev =
        anyGa || anyRisk
          ? "Critical"
          : deviceCodeBlocked === false
            ? "Critical"
            : "High";
      const lines = hits.map(
        (h) =>
          `${h.upn} (events=${h.events}; apps=${h.apps}; GA=${h.isGa}; roles=${h.roles}` +
          (h.riskLevel || h.riskState
            ? `; risk=${h.riskLevel || "?"} / ${h.riskState || "?"}`
            : "") +
          (h.ips ? `; ips=${h.ips}` : "") +
          ")"
      );
      pushNarrative(narratives, {
        id: "NARR.DeviceCode.Privileged",
        severity: sev,
        title: "Privileged accounts used device-code authentication",
        narrative:
          `${hits.length} privileged account(s) completed device-code sign-ins. ` +
          (deviceCodeBlocked === false
            ? "No Conditional Access policy blocks device code / auth transfer — this is a live privilege path (e.g. Graph CLI / Azure CLI)."
            : deviceCodeBlocked === true
              ? "Device-code CA appears present; still investigate whether these sessions predated enforcement or bypassed via exclusions."
              : "Device-code CA coverage unknown; treat observed privileged use as active risk."),
        evidence: lines.join(" · "),
        remediation:
          "Investigate/disable unnecessary privileged device-code use; enforce CA block on deviceCodeFlow + authenticationTransfer; prefer interactive + phishing-resistant MFA for admins; remove standing GA from vendor/external accounts.",
        relatedFiles: [
          "20_DeviceCode_Users_90d.csv",
          "20_DeviceCode_SignIns_90d.csv",
          "40_Privileged_Identity_Hygiene.csv",
          "40_CA_AttackPath_Coverage.csv",
          "24_RiskyUsers.csv",
        ],
        relatedChecks: ["AP.CA.* device code", "NARR.DeviceCode.Observed"],
      });
    }
  }

  // ── NARR.DeviceCode.Observed — High if usage + no CA (and not already covered only by priv) ─
  {
    const users = ctx.deviceCodeUsers || [];
    const events = Number(ctx.summary.deviceCodeSignIns90d ?? users.reduce((a, u) => a + Number(u.Events || 0), 0));
    if (users.length && deviceCodeBlocked === false) {
      const alreadyPriv = narratives.some(
        (n) => n.Id === "NARR.DeviceCode.Privileged"
      );
      // Still emit gap finding, but Medium if Critical priv narrative exists (avoid triple-count)
      pushNarrative(narratives, {
        id: "NARR.DeviceCode.NoCA",
        severity: alreadyPriv ? "High" : "High",
        title: "Device-code / auth-transfer not blocked by Conditional Access",
        narrative: `Observed ${events || "?"} device-code events across ${users.length} user(s), and no enforced CA targets device code / auth transfer. Attackers and automation (Graph CLI) can obtain tokens via device code phishing or headless flows.`,
        evidence: users
          .slice(0, 12)
          .map((u) => `${u.UPN} (${u.Events}×; ${u.Apps})`)
          .join(" · "),
        remediation:
          "Create enforced CA: block deviceCodeFlow and authenticationTransfer for all users (exclude break-glass only, tightly monitored).",
        relatedFiles: [
          "20_DeviceCode_Users_90d.csv",
          "40_CA_AttackPath_Coverage.csv",
          "02_CA_Audit.csv",
        ],
        relatedChecks: ["AP.CA device code coverage"],
      });
    } else if (!users.length && deviceCodeBlocked === false) {
      pushNarrative(narratives, {
        id: "NARR.DeviceCode.NoCA",
        severity: "High",
        title: "No CA blocking device-code (no usage observed in window)",
        narrative:
          "No device-code sign-ins were found in the sampled window, but Conditional Access still does not block device code / auth transfer — the gap remains exploitable.",
        evidence: "Covered=false on device-code / auth-transfer control",
        remediation:
          "Enforce CA block on deviceCodeFlow + authenticationTransfer before the flow is abused.",
        relatedFiles: ["40_CA_AttackPath_Coverage.csv"],
        relatedChecks: ["AP.CA device code coverage"],
      });
    }
  }

  // ── NARR.Priv.HybridGA — one aggregated Critical/High ─
  {
    const hybridGas = [...privIndex.values()].filter(
      (e) => e.isGa && e.synced === true && e.enabled !== false
    );
    const disabledHybrid = [...privIndex.values()].filter(
      (e) => e.isGa && e.synced === true && e.enabled === false
    );
    if (hybridGas.length) {
      pushNarrative(narratives, {
        id: "NARR.Priv.HybridGA",
        severity: hybridGas.length >= 3 ? "Critical" : "High",
        title: "Enabled Global Admins synced from on-premises AD",
        narrative: `${hybridGas.length} enabled Global Administrator account(s) are on-premises synced. Compromise of AD DS / sync credentials can elevate directly to Entra GA. Prefer cloud-only GAs + PIM.`,
        evidence:
          hybridGas.map((e) => e.upn).join(" | ") +
          (disabledHybrid.length
            ? ` · (also disabled hybrid GA: ${disabledHybrid.map((e) => e.upn).join(" | ")})`
            : ""),
        remediation:
          "Convert remaining GAs to cloud-only; disable unused hybrid admin accounts; use PIM eligible GA; harden sync accounts (MT.1020).",
        relatedFiles: [
          "40_Privileged_Identity_Hygiene.csv",
          "03_PrivilegedAccounts_HighValue.csv",
          "40_AttackPath_Checklist.csv",
        ],
        relatedChecks: ["AP.Priv.HybridGA"],
      });
    }
  }

  // ── NARR.Priv.StandingGA — too many permanent GAs ─
  //
  // Count every permanent GA assignment from the privileged export, not only
  // the enabled human accounts that made it into privIndex. Apps and disabled
  // users were previously dropped from the evidence list, so "11 GAs" showed
  // only 7 UPNs and looked like a counting bug.
  {
    const gaRows = (ctx.priv || []).filter((r) =>
      /^Global Administrator$/i.test(r.RoleName || "")
    );
    const byPrincipal = new Map();
    for (const r of gaRows) {
      const key = normUpn(r.UPNOrAppId || r.PrincipalName || r.PrincipalId);
      if (!key) continue;
      if (!byPrincipal.has(key)) {
        const idx = privIndex.get(key);
        const isApp =
          /^appid:/i.test(key) ||
          /serviceprincipal|application/i.test(r.PrincipalType || "");
        byPrincipal.set(key, {
          id: key,
          label: r.PrincipalName || r.UPNOrAppId || key,
          assignment: r.AssignmentType || "Permanent",
          isApp,
          enabled: idx ? idx.enabled : null,
          synced: idx ? idx.synced : null,
        });
      }
    }
    const all = [...byPrincipal.values()];
    const enabledUsers = all.filter((g) => !g.isApp && g.enabled !== false);
    const disabledUsers = all.filter((g) => !g.isApp && g.enabled === false);
    const apps = all.filter((g) => g.isApp);
    const permanent = Number(ctx.summary.globalAdminPermanent ?? all.length);
    const live = enabledUsers.length + apps.length;

    if (permanent >= 5 || live >= 5) {
      const evidence = [];
      evidence.push(
        `Total permanent GA assignments: ${permanent || all.length} — ${enabledUsers.length} enabled user(s), ${disabledUsers.length} disabled user(s), ${apps.length} service principal(s); PIM eligible rows: ${ctx.summary.pimEligibleCount ?? "n/a"}`
      );
      for (const g of enabledUsers.slice(0, 15)) {
        const who =
          g.label && g.label.toLowerCase() !== g.id ? `${g.label} <${g.id}>` : g.id;
        evidence.push(
          `enabled user — ${who}${g.synced ? " (hybrid-synced)" : ""} [${g.assignment}]`
        );
      }
      for (const g of apps.slice(0, 8)) {
        evidence.push(`service principal — ${g.label || g.id} [${g.assignment}]`);
      }
      for (const g of disabledUsers.slice(0, 6)) {
        const who =
          g.label && g.label.toLowerCase() !== g.id ? `${g.label} <${g.id}>` : g.id;
        evidence.push(
          `disabled user — ${who} (still holds the role assignment until removed)`
        );
      }

      pushNarrative(narratives, {
        id: "NARR.Priv.StandingGA",
        severity: live >= 8 || permanent >= 8 ? "Critical" : "High",
        title: "Excessive permanent Global Administrators",
        narrative:
          `${permanent || all.length} permanent Global Administrator assignment(s) detected` +
          ` (${enabledUsers.length} enabled users, ${apps.length} apps/service principals, ${disabledUsers.length} disabled users still carrying the role; PIM eligible rows: ${ctx.summary.pimEligibleCount ?? "n/a"}). ` +
          "A large standing GA set expands blast radius and makes monitoring noisy: every one of these identities can rewrite Conditional Access, grant roles, and read every mailbox. " +
          (disabledUsers.length
            ? `The ${disabledUsers.length} disabled account(s) still count — disable blocks sign-in, but the role assignment remains until it is removed, so re-enabling the account restores GA immediately. `
            : "") +
          (apps.length
            ? `${apps.length} of the assignments are service principals: compromise of their secret/certificate is equivalent to a human GA with no interactive MFA. `
            : ""),
        evidence: evidence.join(" | "),
        remediation:
          "Target ≤2 cloud-only break-glass GAs (documented, monitored, excluded from CA deliberately). Move day-to-day admin to PIM-eligible least-privilege roles. Remove the role from disabled accounts rather than leaving the assignment in place. For any GA service principal: confirm business need, prefer a narrower Graph role, rotate credentials, and alert on its sign-ins.",
        relatedFiles: [
          "03_PrivilegedAccounts_HighValue.csv",
          "03_PrivilegedRoles_Audit.csv",
          "40_Apps_Path_To_GA.csv",
        ],
        relatedChecks: ["AP.Priv.GaMfa"],
      });
    }
  }

  // ── NARR.Priv.DormantAdmin — privileged accounts nobody is watching ─
  //
  // A privileged account that has not signed in for months is the ideal target:
  // full blast radius, and no legitimate baseline to make an intrusion stand
  // out. Neither 03_Privileged* nor 08_Accounts_Inactive shows this alone.
  {
    const inactive = ctx.inactiveAccounts || [];
    const roleHolders = new Map();
    for (const r of ctx.priv || []) {
      const upn = normUpn(r.UPNOrAppId || r.UPN || r.UserPrincipalName);
      if (!upn) continue;
      if (!roleHolders.has(upn)) roleHolders.set(upn, new Set());
      if (r.RoleName) roleHolders.get(upn).add(r.RoleName);
    }

    const dormant = inactive
      .filter((r) => roleHolders.has(normUpn(r.UPN || r.UserPrincipalName)))
      .filter((r) => String(r.AccountEnabled).toLowerCase() !== "false")
      .map((r) => {
        const upn = normUpn(r.UPN || r.UserPrincipalName);
        const roles = [...roleHolders.get(upn)];
        const raw = String(r.DaysSinceInteractive || "").trim();
        const days = Number(raw);
        return {
          upn,
          roles,
          // "Never" is worse than a number, so it sorts to the top.
          never: !Number.isFinite(days),
          days: Number.isFinite(days) ? days : Infinity,
          isGa: roles.some((x) => /global administrator/i.test(x)),
        };
      })
      .sort((a, b) => b.days - a.days);

    // Split the population before scoring it: a designed break-glass account
    // and a forgotten admin are the same row in an inactivity report but
    // opposite findings.
    const caIndex = buildCaExclusionIndex(ctx.caAudit);
    for (const d of dormant) {
      d.bg = classifyBreakGlass(d.upn, caIndex, { isGa: d.isGa });
    }
    const breakGlass = dormant.filter((d) => d.bg.isBreakGlass);
    const forgotten = dormant.filter((d) => !d.bg.isBreakGlass);

    if (forgotten.length) {
      const gas = forgotten.filter((d) => d.isGa);
      const never = forgotten.filter((d) => d.never);
      pushNarrative(narratives, {
        id: "NARR.Priv.DormantAdmin",
        severity: gas.length ? "Critical" : "High",
        priority: "Now",
        title: gas.length
          ? "Dormant Global Administrator account still enabled"
          : "Dormant privileged accounts still enabled",
        narrative:
          `${forgotten.length} enabled account(s) holding privileged roles have not signed in during the inactivity window` +
          (gas.length
            ? `, including ${gas.length} Global Administrator. A GA nobody uses is a GA nobody monitors: there is no normal activity for an intrusion to stand out against.`
            : ".") +
          (never.length
            ? ` ${never.length} have never signed in at all, which suggests role assignments that were provisioned and forgotten.`
            : "") +
          (breakGlass.length
            ? ` ${breakGlass.length} further dormant admin account(s) match the break-glass pattern and are reported separately under NARR.Priv.BreakGlass — they are not counted here.`
            : "") +
          " None of the accounts below carry broad Conditional Access exclusions, so there is no sign they were meant to be emergency accounts.",
        evidence: forgotten
          .slice(0, 10)
          .map(
            (d) =>
              `${d.upn} — ${d.never ? "never signed in" : `${d.days}d idle`} — excluded from ${d.bg.excludedFrom}/${d.bg.enforcedTotal} enforced CA policies [${d.roles.join(", ")}]`
          )
          .join(" | "),
        remediation:
          "Confirm each account is still needed. Remove the role assignment (or disable the account) where it is not. If one of these is in fact an undocumented break-glass account, make it explicit: cloud-only UPN, excluded from every enforced CA policy, credentials split and sealed, and a high-severity alert on any sign-in.",
        relatedFiles: [
          "08_Accounts_Inactive_90d.csv",
          "03_PrivilegedAccounts_HighValue.csv",
          "02_CA_Audit.csv",
        ],
        relatedChecks: ["AP.Priv.GaMfa"],
      });
    }

    // ── NARR.Priv.BreakGlass — the emergency accounts, judged on their own terms
    if (breakGlass.length) {
      const tooMany = breakGlass.length > 2;
      pushNarrative(narratives, {
        id: "NARR.Priv.BreakGlass",
        severity: tooMany ? "Medium" : "Info",
        priority: "Later",
        title: `${breakGlass.length} account(s) match the break-glass pattern — verify the controls around them`,
        narrative:
          `These Global Administrator accounts are dormant *and* carved out of nearly every enforced Conditional Access policy, which is the designed break-glass configuration rather than a gap: the point is that they keep working when CA, MFA or the identity provider is the outage. Dormancy is therefore expected and is not itself a finding. ` +
          (breakGlass.some((d) => d.bg.cloudOnly)
            ? "They are cloud-only accounts on the tenant's .onmicrosoft.com domain, which is correct — it keeps them independent of on-premises AD and of any federated domain. "
            : "Note they are not on the tenant's .onmicrosoft.com domain; break-glass accounts should be cloud-only so they survive an on-premises or federation outage. ") +
          (tooMany
            ? `${breakGlass.length} is more than the two accounts Microsoft recommends — each additional one is standing GA with no monitoring baseline. `
            : "") +
          "What this collection cannot verify, and what actually determines whether the design holds, is listed below.",
        evidence: breakGlass
          .map(
            (d) =>
              `${d.upn} — ${d.never ? "never signed in" : `${d.days}d idle`} — excluded from ${d.bg.excludedFrom}/${d.bg.enforcedTotal} enforced CA policies${d.bg.cloudOnly ? ", cloud-only" : ", NOT cloud-only"} [${d.roles.join(", ")}]`
          )
          .join(" | "),
        remediation:
          "Verify by hand: credentials stored offline and split between two holders (no password manager that depends on this tenant); a phishing-resistant FIDO2 key registered rather than a password alone, kept in a safe; a high-severity alert on any sign-in or any change to these accounts, routed to someone who is not a holder; the exclusions reviewed whenever a new CA policy is added, since a policy created later will cover them by default; and a documented restore test at least annually. Keep the count at two, on separate credentials.",
        relatedFiles: [
          "02_CA_Audit.csv",
          "03_PrivilegedAccounts_HighValue.csv",
          "40_CA_Exclusion_Groups.csv",
        ],
      });
    }
  }

  // ── NARR.Identity.InactiveNoMfa — dormant member accounts without MFA ─
  //
  // Guests are deliberately excluded: a guest authenticates against its home
  // tenant, so "no MFA registered here" says nothing about how it is actually
  // protected. Counting them would inflate the number and overlap with
  // NARR.Guest.Stale, which covers the same population for the right reason.
  {
    const inactive = (ctx.inactiveAccounts || []).filter(
      (r) =>
        String(r.AccountEnabled).toLowerCase() !== "false" &&
        !/guest/i.test(r.UserType || "") &&
        !/#EXT#/i.test(r.UPN || "")
    );
    const noMfaSet = new Set(
      (ctx.noMfa || []).map((r) => normUpn(r.UPN || r.UserPrincipalName)).filter(Boolean)
    );
    const exposed = inactive.filter((r) =>
      noMfaSet.has(normUpn(r.UPN || r.UserPrincipalName))
    );
    if (exposed.length >= 10 && noMfaSet.size) {
      // "Enforce MFA" is the wrong instruction for a meeting room or a shared
      // mailbox — nobody will ever stand in front of one to register a factor.
      // The correct control is to block interactive sign-in entirely, so the
      // two populations need separate counts and separate advice.
      const classify = (r) =>
        classifyAccountKind(r.UPN || r.UserPrincipalName, r.DisplayName);
      const buckets = { human: [], room: [], service: [], shared: [] };
      for (const r of exposed) buckets[classify(r)].push(r);
      const nonHuman = [...buckets.room, ...buckets.service, ...buckets.shared];

      // Does an enforced CA policy actually stand in front of these accounts?
      // All-users MFA, or the pair of MFA scoped to licensed users + block on unlicensed.
      const gate = detectLicenseGatedAccess(ctx.caAudit);
      const mfaCa = detectEnforcedMfaCoverage(ctx.caAudit);
      const enforcedCa = (ctx.caAudit || []).filter((r) => {
        const st = String(r.State || "");
        return /^enabled$/i.test(st) || String(r.IsEnforced || "").toLowerCase() === "yes";
      });
      const isMfaPolicy = (r) =>
        /mfa|multifactor|authentication strength/i.test(
          `${r.PolicyName || ""} ${r.GrantControls || ""} ${r.AuthStrength || ""}`
        );
      const licensedMfa = enforcedCa
        .filter((r) => isMfaPolicy(r) && /licen/i.test(String(r.IncludeGroups || "")))
        .sort(
          (a, b) =>
            (/mfa/i.test(b.PolicyName || "") ? 1 : 0) -
            (/mfa/i.test(a.PolicyName || "") ? 1 : 0)
        );
      const unlicensedBlock = enforcedCa.filter(
        (r) =>
          /block/i.test(`${r.PolicyName || ""} ${r.GrantControls || ""}`) &&
          /unmanaged|unlicensed|sans licence/i.test(String(r.PolicyName || ""))
      );
      const mfaCovered = mfaCa.covered;
      const pairCovered = licensedMfa.length > 0 && unlicensedBlock.length > 0;

      const majorityLabel = (() => {
        const ranked = [
          ["users", buckets.human.length],
          ["rooms", buckets.room.length],
          ["shared mailboxes", buckets.shared.length],
          ["service accounts", buckets.service.length],
        ].sort((a, b) => b[1] - a[1]);
        return ranked[0][0];
      })();
      const inactiveTitle =
        buckets.human.length > nonHuman.length
          ? `Dormant accounts with no MFA — ${buckets.human.length} look like users`
          : `Dormant accounts with no MFA — mostly ${majorityLabel}, not users`;

      const evidence = [];
      evidence.push(
        `Breakdown: ${buckets.human.length} apparent user account(s), ${buckets.room.length} meeting room(s), ${buckets.shared.length} shared/functional mailbox(es), ${buckets.service.length} service account(s)`
      );
      if (mfaCovered) {
        evidence.push(
          `Enforced all-users MFA policy in place: ${mfaCa.allUsersEvidence.slice(0, 2).join(" ; ") || mfaCa.evidence.slice(0, 2).join(" ; ")} — interactive sign-in on these accounts would be challenged and fail`
        );
      }
      if (licensedMfa.length) {
        evidence.push(
          `MFA enforced on the licensed population: ${licensedMfa.slice(0, 2).map((r) => r.PolicyName).join(" ; ")}`
        );
      }
      if (unlicensedBlock.length) {
        evidence.push(
          `Unlicensed / unmanaged sign-in blocked: ${unlicensedBlock.slice(0, 2).map((r) => r.PolicyName).join(" ; ")}`
        );
      }
      if (gate.gated && !licensedMfa.length && !unlicensedBlock.length) {
        evidence.push(`License/unmanaged gate active: ${gate.evidence.slice(0, 2).join(" ; ")}`);
      }
      for (const r of buckets.human.slice(0, 6)) {
        evidence.push(
          `user — ${r.UPN} (${r.DaysSinceInteractive || "never"})${r.DisplayName ? ` · ${r.DisplayName}` : ""}`
        );
      }
      for (const r of nonHuman.slice(0, 6)) {
        evidence.push(
          `${classify(r)} — ${r.UPN}${r.DisplayName ? ` · ${r.DisplayName}` : ""} — should have sign-in disabled, not MFA`
        );
      }

      pushNarrative(narratives, {
        id: "NARR.Identity.InactiveNoMfa",
        severity:
          buckets.human.length >= 100 ? "High" : mfaCovered || pairCovered ? "Low" : "Medium",
        priority: "Next",
        title: inactiveTitle,
        narrative:
          `${exposed.length} enabled member accounts (guests excluded) are dormant with no MFA method registered, but they are not one population. ` +
          `${nonHuman.length} are meeting rooms, shared mailboxes or service accounts: nobody will ever register a factor on those, so an MFA campaign cannot close them — the right control is to block interactive sign-in, after which the absence of MFA stops mattering. ` +
          `${buckets.human.length} look like real user accounts, and those are the genuine password-spray surface: single-factor, with no baseline activity to make a successful compromise visible. ` +
          (mfaCovered
            ? "Note the residual risk is narrower than the raw count suggests: an enforced all-users MFA policy already covers interactive sign-in, so these accounts would be challenged and fail rather than let an attacker in. "
            : pairCovered
              ? "The residual risk is narrower than the raw count suggests, because the tenant already implements the two-policy design that covers exactly this population: MFA is required of the licensed group, and every unlicensed or unmanaged sign-in is blocked outright. A dormant account therefore either holds a license and gets challenged for a factor it does not have, or holds none and is blocked before the password is even evaluated. "
              : "No enforced policy requiring MFA of the whole population was found, and no block on unlicensed sign-in, so nothing currently stands between a guessed password and a session on these accounts. ") +
          (mfaCovered || pairCovered
            ? "What remains genuinely exposed is any path those policies do not reach: legacy/basic authentication, non-interactive token refresh on a session issued before the policy, and membership in one of the CA exclusion groups — which is where this should be verified rather than in the MFA registration report."
            : ""),
        evidence: evidence.join(" | "),
        remediation:
          "Handle the two groups differently. Rooms and shared mailboxes: set the underlying user object to sign-in blocked (accountEnabled = false) — a room mailbox is booked through Exchange and a shared mailbox is opened with delegated access, neither needs its own sign-in, and blocking it removes the credential entirely. Service accounts: move them to certificate or workload-identity authentication and exclude them from interactive MFA deliberately rather than by omission. The remaining user accounts: disable the ones no longer needed (faster than any MFA campaign), and for the rest require MFA registration through a CA policy that blocks sign-in until registration completes. Verify none of them sit in a CA exclusion group, since that is what would turn a theoretical gap into a real one.",
        relatedFiles: [
          "08_Accounts_Inactive_90d.csv",
          "07_Users_Without_MFA.csv",
          "02_CA_Audit.csv",
        ],
        relatedChecks: ["AP.MFA.Coverage"],
      });
    }
  }

  // ── NARR.Guest.Stale — external identities that outlived their purpose ─
  {
    const guests = ctx.guests || [];
    const inactiveUpns = new Set(
      (ctx.inactiveAccounts || [])
        .map((r) => normUpn(r.UPN || r.UserPrincipalName))
        .filter(Boolean)
    );
    const enabled = guests.filter(
      (g) => String(g.AccountEnabled).toLowerCase() !== "false"
    );
    const dormant = enabled.filter((g) => inactiveUpns.has(normUpn(g.UPN)));
    const pending = enabled.filter((g) =>
      /pending/i.test(g.ExternalUserState || "")
    );

    if (enabled.length && (dormant.length >= 10 || pending.length >= 10)) {
      const pct = Math.round((dormant.length / enabled.length) * 100);
      pushNarrative(narratives, {
        id: "NARR.Guest.Stale",
        severity: dormant.length >= 50 || pct >= 60 ? "Medium" : "Low",
        priority: "Next",
        title: "Stale guest accounts and unaccepted invitations",
        narrative:
          `${enabled.length} enabled guest accounts, of which ${dormant.length} (${pct}%) show no recent sign-in` +
          (pending.length
            ? ` and ${pending.length} never accepted their invitation`
            : "") +
          ". Guests inherit whatever sharing and group membership they were given; the ones nobody uses keep that access indefinitely while no owner is reviewing it. Unaccepted invitations are live redeemable links.",
        evidence: [
          ...dormant.slice(0, 6).map((g) => `${g.UPN} (dormant)`),
          ...pending.slice(0, 4).map((g) => `${g.UPN} (invite pending)`),
        ].join(" | "),
        remediation:
          "Enable Entra access reviews for guests with a recurring cadence and auto-removal on no response. Expire invitations that were never redeemed, and set a guest inactivity lifecycle policy.",
        relatedFiles: ["05_guests.csv", "08_Accounts_Inactive_90d.csv"],
        relatedChecks: ["AP.CA.GuestMfa"],
      });
    }
  }

  const appPlane = clusterAppControlPlane({
    gaPath: ctx.gaPath,
    dangerous: ctx.dangerous,
    priv: ctx.priv,
    cloudAppAdminOps: ctx.cloudAppAdminOps,
    graphApiAudit: ctx.graphApiAudit,
  });

  // ── NARR.App.RoleManagement — skipped when PathToGA already covers the same apps ─
  {
    const rows = (ctx.gaPath.length ? ctx.gaPath : ctx.dangerous).filter(
      (r) => r.Permission === ROLE_MGMT_PERM
    );
    if (rows.length && !appPlane.roleMgmtCoveredByPathToGa) {
      const apps = [...new Set(rows.map((r) => r.SPNDisplayName || r.DisplayName))];
      const allBackupLike = apps.every(looksLikeBackupOrSocApp);
      pushNarrative(narratives, {
        id: "NARR.App.RoleManagement",
        severity: allBackupLike && apps.length <= 3 ? "High" : "Critical",
        priority: "Now",
        title: "Apps can assign directory roles (RoleManagement.ReadWrite.Directory)",
        narrative:
          `${apps.length} application(s) hold RoleManagement.ReadWrite.Directory — credential theft on these apps can grant directory roles (including GA).` +
          (allBackupLike
            ? " Names look like backup/SOC products (often intentionally privileged) — still treat secrets, owners, and sign-in logs as high-value."
            : ""),
        evidence: apps.join(" | "),
        remediation:
          "Treat this grant as equivalent to a standing Global Administrator, because that is what it can produce in one API call. Very few products need it: it is only required to *assign* directory roles, so a SOC, a monitoring tool or a reporting product never does. Backup products need it only if you restore role assignments — confirm you actually do before leaving it in place. Remove it where the answer is no; where the answer is yes, isolate the app: certificate credentials, a workload-identity CA policy limiting it to the vendor's egress addresses, and a high-severity alert on every role-assignment audit event it generates." +
          (leastPrivilegeAdvice(apps).length
            ? " " + leastPrivilegeAdvice(apps).join(" ")
            : ""),
        relatedFiles: ["40_Apps_Path_To_GA.csv", "04_SPN_DangerousPerms.csv"],
        relatedChecks: ["AP.App.PathToGA"],
      });
    }
  }

  // ── NARR.App.PathToGA — Graph GA-path + Entra directory roles on SPs ─
  {
    if (appPlane.pathToGa.length) {
      const byApp = appPlane.pathToGa;
      const entraOnly = byApp.filter((a) => !a.perms.size && a.entraRoles.size);
      pushNarrative(narratives, {
        id: "NARR.App.PathToGA",
        severity: "High",
        title: "Non-Microsoft apps with a path to Global Admin",
        narrative:
          `${byApp.length} third-party app(s) can reach Global Admin: Graph directory-write grants and/or standing Privileged Role / Privileged Authentication / Global Administrator directory roles on the service principal.` +
          (entraOnly.length
            ? ` ${entraOnly.length} hold a GA-equivalent Entra role without those Graph app roles.`
            : "") +
          (byApp.filter((a) => a.caWrite).length
            ? ` ${byApp.filter((a) => a.caWrite).length} of those also hold Policy.ReadWrite.ConditionalAccess.`
            : "") +
          (appPlane.caWriteEvents
            ? ` CloudAppEvents recorded ${appPlane.caWriteEvents} Set-ConditionalAccessPolicy operation(s) in the window — often unattributed app-only writes.`
            : "") +
          (appPlane.graphApiWriteEvents
            ? ` GraphAPIAuditEvents recorded ${appPlane.graphApiWriteEvents} CA / role / consent write call(s) in 30d.`
            : "") +
          " Microsoft first-party Graph grants are excluded; directory roles on third-party SPs are not.",
        evidence: byApp
          .map((a) => {
            const bits = [...a.perms, ...a.entraRoles];
            if (a.caWrite && !bits.some((b) => /ConditionalAccess/i.test(b))) {
              bits.push("Policy.ReadWrite.ConditionalAccess");
            }
            return `${a.name} [${bits.join(", ")}]`;
          })
          .join(" | "),
        remediation:
          "Work grant by grant rather than app by app. Read-only replacements exist for most of these and cost nothing to try: swap the write grant for its .Read equivalent and see whether the vendor's daily job still succeeds — that alone removes the GA path for monitoring and reporting products. Where write is genuinely needed only during an occasional operation such as a restore, split it into a second app registration whose credentials stay disabled between uses. For everything that remains: certificate credentials instead of secrets, a workload-identity Conditional Access policy pinning the service principal to the vendor's published egress addresses, named owners, and a high-severity alert on any AppRoleAssignment or RoleManagement write performed by these identities." +
          (leastPrivilegeAdvice(byApp.map((a) => a.name)).length
            ? " " + leastPrivilegeAdvice(byApp.map((a) => a.name)).join(" ")
            : ""),
        relatedFiles: [
          "40_Apps_Path_To_GA.csv",
          "04_SPN_DangerousPerms.csv",
          "03_PrivilegedAccounts_HighValue.csv",
          "39_CloudApp_Admin_Operations_30d.csv",
          "39_GraphAPI_Write_Audit_30d.csv",
        ],
        relatedChecks: ["AP.App.PathToGA", "AP.App.Management"],
      });
    }
  }

  // ── NARR.Risk.PrivilegedAtRisk ─
  {
    const hits = [];
    for (const [upn, risk] of riskyByUpn) {
      const priv = privIndex.get(upn);
      if (!priv || !isHighPriv(priv)) continue;
      if (priv.enabled === false) continue;
      hits.push({
        upn,
        riskLevel: risk.RiskLevel || "",
        riskState: risk.RiskState || "",
        isGa: priv.isGa,
        roles: [...priv.roles].join(" | "),
      });
    }
    if (hits.length) {
      const hitUpns = new Set(hits.map((h) => h.upn));
      const dets = (ctx.riskDetections || []).filter((d) =>
        hitUpns.has(String(d.UPN || "").toLowerCase())
      );
      const confirmed = hits.filter((h) =>
        /confirmedcompromised/i.test(h.riskState)
      );
      const highRisk = hits.filter((h) => /^high$/i.test(h.riskLevel));
      const onlyLow = hits.every(
        (h) => /^low$/i.test(h.riskLevel) || !String(h.riskLevel || "").trim()
      );
      let severity = "High";
      let priority = "Now";
      if (confirmed.length || highRisk.some((h) => h.isGa)) {
        severity = "Critical";
      } else if (onlyLow) {
        // Low/atRisk on admins is common (travel, anonymized IP) — not Critical
        // when Identity Protection CA already remediates high user risk.
        severity = userRiskCa ? "Medium" : "High";
        priority = userRiskCa ? "Next" : "Now";
      } else if (!hits.some((h) => h.isGa)) {
        severity = "Medium";
        priority = "Next";
      }
      const detNote = dets.length
        ? ` Identity Protection logged ${dets.length} underlying risk detection(s) for these accounts in 90d (see 24_RiskDetections_90d.csv) — use the event type/IP even when RiskLevel shows as hidden.`
        : "";
      const caNote = userRiskCa
        ? " An enforced user-risk / high-risk remediation CA is present — confirm it covers these UPNs (not only a licensed subset) and investigate the detections, but this is not an unguarded confirmed-compromise path."
        : " No enforced user-risk CA was detected — they can keep signing in until remediated.";
      pushNarrative(narratives, {
        id: "NARR.Risk.PrivilegedAtRisk",
        severity,
        priority,
        title: onlyLow
          ? "Privileged accounts with low Identity Protection risk"
          : "Privileged accounts flagged by Identity Protection",
        narrative: `${hits.length} privileged account(s) are ${confirmed.length ? "confirmedCompromised / " : ""}atRisk while retaining high-value roles (${confirmed.length} confirmed, ${highRisk.length} high, ${hits.filter((h) => /^low$/i.test(h.riskLevel)).length} low).${caNote}${detNote}`,
        evidence:
          hits
            .map(
              (h) =>
                `${h.upn} (risk=${h.riskLevel}/${h.riskState}; GA=${h.isGa}; ${h.roles})`
            )
            .join(" · ") +
          (dets.length
            ? " | detections: " +
              dets
                .slice(0, 8)
                .map(
                  (d) =>
                    `${d.UPN} ${d.RiskEventType || "?"} @ ${d.Detected || "?"} ip=${d.Ip || "?"}`
                )
                .join(" · ")
            : ""),
        remediation: confirmed.length || highRisk.length
          ? "Immediately investigate and remediate; enforce user-risk CA (high → block / force password change); revoke sessions; review MFA methods."
          : "Triage the risk detections (travel / anonymized IP / unfamiliar features). Keep high-risk → password change / block CA enforced for all users; confirm privileged UPNs are not in exclusion groups.",
        relatedFiles: [
          "24_RiskyUsers.csv",
          "24_RiskDetections_90d.csv",
          "40_Privileged_Identity_Hygiene.csv",
          "40_CA_AttackPath_Coverage.csv",
        ],
        relatedChecks: ["AP.CA.UserRisk"],
      });
    }
  }

  // ── NARR.Risk.NoUserRiskCA ─
  {
    const count = Number(ctx.summary.riskyUsersAtRisk ?? (ctx.risky || []).length);
    if (count > 0 && userRiskCa === false) {
      const high = (ctx.risky || []).filter((r) =>
        /^high$/i.test(r.RiskLevel || "")
      );
      pushNarrative(narratives, {
        id: "NARR.Risk.NoUserRiskCA",
        severity: high.length ? "Critical" : "High",
        title: "At-risk users present with no enforced user-risk Conditional Access",
        narrative: `${count} Identity Protection user(s) are at risk (${high.length} high), but no enforced CA reacts to user risk (block / require password change). Compromised accounts can continue to work.`,
        evidence: (ctx.risky || [])
          .slice(0, 15)
          .map((r) => `${r.UPN} (${r.RiskLevel}/${r.RiskState})`)
          .join(" · "),
        remediation:
          "Enforce CA for user risk high → block or require password change; remediate backlog in Identity Protection.",
        relatedFiles: ["24_RiskyUsers.csv", "40_CA_AttackPath_Coverage.csv"],
        relatedChecks: ["AP.CA.UserRisk"],
      });
    }
  }

  // ── NARR.Legacy.Observed+NoCA ─
  {
    const legacyFail =
      /fail/i.test(checklistStatus(ctx.checklist, "AP.CA.LegacyBlock")) ||
      legacyBlocked === false;
    const legacyRows = ctx.legacy || [];
    if (legacyFail && legacyRows.length) {
      const byAcct = ctx.legacyByAccount || [];
      const top = byAcct[0];
      const totalEvt = byAcct.reduce((n, r) => n + (Number(r.Events) || 0), 0);
      const concentrated =
        top &&
        totalEvt > 0 &&
        Number(top.Events) / totalEvt >= 0.7 &&
        Number(top.Events) >= 5;
      const smtpLike =
        concentrated &&
        /smtp|mail\.|relay|noreply|no-reply/i.test(String(top.UPN || ""));
      pushNarrative(narratives, {
        id: "NARR.Legacy.Observed",
        severity: "High",
        title: concentrated
          ? smtpLike
            ? `Legacy auth concentrated on shared SMTP account ${top.UPN}`
            : `Legacy auth concentrated on ${top.UPN}`
          : "Legacy authentication succeeded and is not blocked by CA",
        narrative: concentrated
          ? `${legacyRows.length} successful legacy-auth sample(s) while CA does not block legacy clients — and ${top.Events}/${totalEvt || "?"} of those events belong to ${top.UPN}` +
            (smtpLike
              ? " (shared/service SMTP identity). Authenticated SMTP with password + CA notApplied is a spray/credential-stuffing path that never prompts MFA."
              : ". A single account carrying most legacy traffic is the practical remediation target (disable the protocol or move that workload to modern auth) while the CA block closes the rest of the tenant.")
          : `${legacyRows.length} successful legacy-auth sign-in sample(s) observed while Conditional Access does not enforce a legacy client block — password spray / basic auth remains viable.`,
        evidence: concentrated
          ? `${top.UPN}: ${top.Events} events · clients=${top.ClientApps || "?"} · ips=${top.DistinctIps || "?"} · ca=${top.ConditionalAccess || "?"} · ${top.SampleIps || ""}`
          : legacyRows
              .slice(0, 12)
              .map(
                (r) =>
                  `${r.UPN || r.UserPrincipalName || "?"} (${r.ClientApp || r.ClientAppUsed || "?"}; ${r.App || ""})`
              )
              .join(" · "),
        remediation: concentrated
          ? `For ${top.UPN}: confirm which printer/app/relay still uses Authenticated SMTP, migrate it to modern auth or a connector, then disable SMTP AUTH on that mailbox. In parallel enforce CA blocking Exchange ActiveSync + Other clients / legacy auth for all users.`
          : "Enforce CA block for Exchange ActiveSync + Other clients; disable Authenticated SMTP where unused; migrate clients to modern auth.",
        relatedFiles: [
          "21_LegacyAuth_Success_90d.csv",
          "21_LegacyAuth_ByAccount_90d.csv",
          "40_CA_AttackPath_Coverage.csv",
        ],
        relatedChecks: ["AP.CA.LegacyBlock"],
      });
    } else if (legacyFail && !legacyRows.length) {
      pushNarrative(narratives, {
        id: "NARR.Legacy.NoCA",
        severity: "High",
        title: "Legacy authentication not blocked by Conditional Access",
        narrative:
          "No legacy successes were sampled in logs, but CA still does not block legacy clients — the spray path remains open.",
        evidence: "AP.CA.LegacyBlock = Fail / Covered=false",
        remediation:
          "Enforce CA policy blocking legacy authentication for all users.",
        relatedFiles: ["40_AttackPath_Checklist.csv"],
        relatedChecks: ["AP.CA.LegacyBlock"],
      });
    }
  }

  // ── NARR.Consent.UserDefaultLow ─
  {
    if (/fail/i.test(checklistStatus(ctx.checklist, "AP.Consent.User"))) {
      const hasDangerous = (ctx.dangerous || []).length > 0;
      pushNarrative(narratives, {
        id: "NARR.Consent.User",
        severity: hasDangerous ? "Critical" : "High",
        title: "User OAuth consent still allowed (default-low)",
        narrative:
          "Users can consent to apps under the default-low permission grant policy — classic consent-phishing path (Mail/Files/Directory scopes without stealing a password)." +
          (hasDangerous
            ? " Tenant already has high-privilege third-party apps, increasing blast radius of additional consent."
            : ""),
        evidence:
          checklistStatus(ctx.checklist, "AP.Consent.User") +
          " — see 40_AttackPath_Checklist.csv AP.Consent.User",
        remediation:
          "Disable user consent or restrict to verified publishers + low-risk permissions; require admin consent workflow.",
        relatedFiles: [
          "40_AttackPath_Checklist.csv",
          "01_authorization_policy.json",
        ],
        relatedChecks: ["AP.Consent.User"],
      });
    }
  }

  // ── NARR.CA.Guest + invites ─
  {
    const guestStatus = checklistStatus(ctx.checklist, "AP.CA.GuestMfa");
    const guestInviteOpen = (ctx.rawFindings || []).some(
      (f) =>
        /guest/i.test(f.Area || "") &&
        /invite|everyone/i.test(f.Detail || "") &&
        /medium|high/i.test(f.Severity || "")
    );
    // Fail only — Partial (All-users MFA) stays inventory; Pass = guest-targeted CA exists
    if (/fail/i.test(guestStatus) || (guestMfaCa === false && !/pass|partial/i.test(guestStatus))) {
      pushNarrative(narratives, {
        id: "NARR.CA.GuestMfa",
        severity: guestInviteOpen ? "High" : "High",
        title: "No MFA Conditional Access for guests / external users",
        narrative:
          "Guests are not covered by an enforced MFA CA policy." +
          (guestInviteOpen
            ? " Combined with open guest invitations, an invited guest foothold is easier to establish and abuse."
            : ""),
        evidence: `CA guest MFA Covered=${guestMfaCa}; AP.CA.GuestMfa ${guestStatus || "Fail"}`,
        remediation:
          "Enforce MFA CA for All guest users (includeGuestsOrExternalUsers); restrict who can invite guests to admins / specific roles.",
        relatedFiles: ["40_CA_AttackPath_Coverage.csv", "05_guests.csv"],
        relatedChecks: ["AP.CA.GuestMfa"],
      });
    }
  }

  // ── NARR.CA.BreakGlassExclusions — same principal carved out of many CA ─
  {
    const caAudit = ctx.caAudit || [];
    const byUser = new Map(); // name -> { count, policies: [] }
    for (const r of caAudit) {
      if (!truthy(r.IsEnforced) && String(r.State || "").toLowerCase() !== "enabled") {
        // still count enabled policies even if IsEnforced column quirky
      }
      const enforced =
        truthy(r.IsEnforced) ||
        String(r.State || "").toLowerCase() === "enabled";
      if (!enforced) continue;
      const ex = String(r.ExcludeUsers || "");
      if (!ex.trim()) continue;
      // ExcludeUsers is "Name (upn) | Name2" style
      for (const part of ex.split("|").map((x) => x.trim()).filter(Boolean)) {
        const key = part.toLowerCase();
        if (!byUser.has(key)) byUser.set(key, { label: part, policies: [] });
        const row = byUser.get(key);
        if (row.policies.length < 40) row.policies.push(r.PolicyName || "?");
      }
    }
    const heavyAll = [...byUser.values()]
      .map((x) => ({ ...x, count: x.policies.length }))
      .filter((x) => x.count >= 8)
      .sort((a, b) => b.count - a.count);

    // A Global Administrator carved out of nearly everything is the intended
    // break-glass design and is reported as such by NARR.Priv.BreakGlass.
    // Flagging it High here as well contradicts that finding and buries the
    // exclusions that genuinely are unexplained.
    const designedUpns = new Set(
      narratives
        .filter((n) => n.Id === "NARR.Priv.BreakGlass")
        .flatMap((n) =>
          [...String(n.Evidence || "").matchAll(/([\w.+-]+@[\w.-]+)/g)].map((m) =>
            m[1].toLowerCase()
          )
        )
    );
    const upnOf = (label) => {
      const m = String(label).match(/<([^>]+@[^>]+)>|([\w.+-]+@[\w.-]+)/);
      return (m ? m[1] || m[2] : "").toLowerCase();
    };
    const heavy = heavyAll.filter((x) => !designedUpns.has(upnOf(x.label)));
    const designed = heavyAll.filter((x) => designedUpns.has(upnOf(x.label)));

    if (heavy.length) {
      const top = heavy.slice(0, 6);
      pushNarrative(narratives, {
        id: "NARR.CA.BreakGlassExclusions",
        severity: "High",
        priority: "Now",
        title: "Accounts broadly excluded from Conditional Access without a break-glass rationale",
        narrative:
          `${heavy.length} principal(s) are excluded from 8 or more enforced CA policies. A broad exclusion is a standing bypass of MFA, device compliance, risk and location controls for that account, so it only makes sense where the account exists precisely to survive a CA outage. ` +
          (designed.length
            ? `${designed.length} further account(s) with the same exclusion breadth do match the break-glass pattern and are covered separately by NARR.Priv.BreakGlass — they are excluded from this count. `
            : "") +
          "The accounts below do not: they are not dormant Global Administrators kept for emergency access, so the exclusion is more likely accumulated convenience — an app that broke, a VIP who complained — than a deliberate design.",
        evidence: top
          .map(
            (x) =>
              `${x.label} — excluded from ${x.count} policies: ${x.policies.slice(0, 5).join("; ")}${x.count > 5 ? "; …" : ""}`
          )
          .join(" | "),
        remediation:
          "For each account, find the policy that originally prompted the exclusion and fix that instead — usually a single app or platform gap that a targeted exclusion, or a change to the policy condition, resolves without a tenant-wide carve-out. Blanket exclusions should be reserved for the two documented break-glass accounts. Where an exclusion has to stay, scope it to the specific policy and add an alert on sign-in for that principal, so a bypass at least produces a signal.",
        relatedFiles: ["02_CA_Audit.csv", "40_Privileged_Identity_Hygiene.csv"],
        relatedChecks: ["AP.CA.ExclGroups"],
      });
    }
  }

  // ── NARR.CA.SecInfoReg ─
  {
    const st = checklistStatus(ctx.checklist, "AP.CA.SecInfoReg");
    const secInfoAudit = (ctx.caAudit || []).filter((r) =>
      /security.?info|registersecurityinfo/i.test(
        `${r.PolicyName || ""} ${r.IncludeApps || ""} ${r.RiskFlags || ""}`
      )
    );
    const secInfoEnforced = secInfoAudit.filter((r) =>
      /^enabled$/i.test(String(r.State || "")) ||
      String(r.IsEnforced || "").toLowerCase() === "yes"
    );
    const secInfoReportOnly = secInfoAudit.filter((r) =>
      /report.?only|enabledForReportingButNotEnforced/i.test(
        `${r.State || ""} ${r.IsEnforced || ""}`
      )
    );
    const missing =
      /fail/i.test(st) && !secInfoAudit.length && secInfoCa === false;
    const reportOnlyGap =
      !secInfoEnforced.length && (secInfoReportOnly.length || /partial/i.test(st));

    if (missing) {
      pushNarrative(narratives, {
        id: "NARR.CA.SecInfoReg",
        severity: "High",
        title: "Register security info not protected by Conditional Access",
        narrative:
          "Users can register MFA methods without a CA requiring trusted location / compliant device — after password theft, attackers can enroll their own MFA.",
        evidence: "AP.CA.SecInfoReg Fail / Covered=false",
        remediation:
          "CA: require compliant device or trusted named location for Register security info user action.",
        relatedFiles: ["40_CA_AttackPath_Coverage.csv", "02_CA_Audit.csv"],
        relatedChecks: ["AP.CA.SecInfoReg"],
      });
    } else if (reportOnlyGap) {
      pushNarrative(narratives, {
        id: "NARR.CA.SecInfoReg",
        severity: "Medium",
        priority: "Next",
        title: "Register security info Conditional Access is report-only",
        narrative:
          "A CA policy targets Register security info but is still report-only — MFA methods can be added from anywhere until it is enforced. This is not a missing policy, and it is not a fleet device-compliance gap.",
        evidence: secInfoReportOnly
          .map((r) => r.PolicyName)
          .filter(Boolean)
          .join(" | ") || "AP.CA.SecInfoReg Partial",
        remediation:
          "Validate impact, then switch the Register security info policy from report-only to On (compliant device and/or trusted location).",
        relatedFiles: ["40_CA_AttackPath_Coverage.csv", "02_CA_Audit.csv"],
        relatedChecks: ["AP.CA.SecInfoReg"],
      });
    }
  }

  // ── NARR.CA.ExclGroups — aggregate (avoids 20× identical inventory Highs) ─
  {
    const exclRows = ctx.exclGroups || [];
    const weak = exclRows.filter(
      (r) =>
        String(r.Hardened || "").toLowerCase() === "false" ||
        String(r.IsAssignableToRole || "").toLowerCase() === "false" ||
        /fail|weak|bypass/i.test(r.Risk || "")
    );
    const exclFail = /fail/i.test(
      checklistStatus(ctx.checklist, "AP.CA.ExclGroups")
    );
    const inventoryExcl = (ctx.rawFindings || []).filter((f) =>
      /exclusion group.*not role-assignable|CA exclusion group/i.test(
        f.Detail || ""
      )
    );
    const weakCount = Math.max(weak.length, inventoryExcl.length);
    if (exclFail || weakCount >= 2) {
      const names = (weak.length ? weak : inventoryExcl)
        .slice(0, 8)
        .map(
          (r) =>
            r.DisplayName ||
            r.displayName ||
            String(r.Detail || "").replace(/^CA exclusion group "([^"]+)".*/i, "$1")
        )
        .filter(Boolean);
      pushNarrative(narratives, {
        id: "NARR.CA.ExclGroups",
        severity: "High",
        priority: weakCount >= 10 ? "Now" : "Next",
        title: "CA exclusion groups are not role-assignable (bypass path)",
        narrative: `${weakCount} Conditional Access exclusion group(s) are not role-assignable. Anyone who can add members to these groups can carve themselves out of MFA / device / location CA — a standing privilege-escalation path.`,
        evidence:
          (names.length
            ? names.join(" | ") +
              (weakCount > names.length ? ` (+${weakCount - names.length} more)` : "")
            : `${weakCount} groups`) + " — 40_CA_Exclusion_Groups.csv",
        remediation:
          "Convert exclusion groups to role-assignable (RMAU); restrict who can manage membership; prefer break-glass accounts over broad exclusion groups; monitor membership changes.",
        relatedFiles: [
          "40_CA_Exclusion_Groups.csv",
          "40_AttackPath_Checklist.csv",
        ],
        relatedChecks: ["AP.CA.ExclGroups"],
      });
    }
  }

  // ── NARR.CA.ReportOnlyCompliance ─
  {
    const reportOnly = (ctx.caAudit || []).filter((r) =>
      /report.?only|enabledForReportingButNotEnforced/i.test(
        `${r.State || ""} ${r.IsEnforced || ""} ${r.RiskFlags || ""} ${r.Detail || ""}`
      )
    );
    const policyLabel = (r) =>
      r.PolicyName || r.DisplayName || r.Name || "";
    const deviceComplianceReport = (ctx.caAudit || []).filter(
      isReportOnlyFleetComplianceRow
    );
    const findingHint = (ctx.rawFindings || []).find((f) =>
      /device-compliance CA still report-only/i.test(f.Detail || "") &&
      !/security info registration/i.test(f.Detail || "")
    );
    if (deviceComplianceReport.length || findingHint) {
      pushNarrative(narratives, {
        id: "NARR.CA.ReportOnlyCompliance",
        severity: "High",
        title: "Device compliance Conditional Access still report-only",
        narrative:
          "Device-compliance CA is not enforced — unmanaged / non-compliant devices are not blocked from cloud resources.",
        evidence:
          (deviceComplianceReport.map(policyLabel).filter(Boolean).join(" | ") ||
            findingHint?.Detail ||
            "report-only device compliance"),
        remediation:
          "Move device-compliance CA from report-only to On after validating impact.",
        relatedFiles: ["02_CA_Audit.csv", "00_Findings.csv"],
        relatedChecks: ["AP.CA.GrantOR"],
      });
    }

    const hardeningReport = reportOnly.filter((r) => {
      const blob = `${policyLabel(r)} ${r.GrantControls || ""} ${r.AuthStrength || ""} ${r.RiskFlags || ""}`;
      return /token.?protection|phishing.?resistant/i.test(blob);
    });
    if (hardeningReport.length) {
      pushNarrative(narratives, {
        id: "NARR.CA.ReportOnlyHardening",
        severity: "High",
        priority: "Next",
        title:
          "Token Protection / phishing-resistant MFA still report-only",
        narrative: `${hardeningReport.length} hardening Conditional Access policy(ies) (Token Protection and/or phishing-resistant MFA for standard users) remain report-only — session-theft and MFA-fatigue paths stay open until enforced.`,
        evidence: hardeningReport.map(policyLabel).filter(Boolean).join(" | "),
        remediation:
          "Validate impact in report-only, then enforce Token Protection on Windows EXO/SPO clients and phishing-resistant MFA for users (admins already covered where an admin phishing-resistant policy is On).",
        relatedFiles: ["02_CA_Audit.csv"],
        relatedChecks: ["AP.CA.GrantOR", "AP.MFA.PhishResistant"],
      });
    }
  }

  // ── NARR.CA.TrustedIpHygiene — public anycast / CDN in trusted named locations ─
  {
    const TRUSTED_IP_REDFLAGS = [
      { re: /\b1\.1\.1\.1\b/, label: "1.1.1.1 (Cloudflare DNS anycast)" },
      { re: /\b1\.0\.0\.1\b/, label: "1.0.0.1 (Cloudflare DNS)" },
      { re: /\b8\.8\.8\.8\b/, label: "8.8.8.8 (Google DNS)" },
      { re: /\b8\.8\.4\.4\b/, label: "8.8.4.4 (Google DNS)" },
      { re: /\b9\.9\.9\.9\b/, label: "9.9.9.9 (Quad9)" },
    ];
    const hits = [];
    for (const loc of ctx.namedLocations || []) {
      const trusted =
        String(loc.IsTrusted || "").toLowerCase() === "true" ||
        String(loc.IsTrusted || "") === "1";
      if (!trusted) continue;
      const ips = String(loc.IpRanges || loc.ipRanges || "");
      const flags = TRUSTED_IP_REDFLAGS.filter((f) => f.re.test(ips)).map(
        (f) => f.label
      );
      if (flags.length) {
        hits.push(
          `${loc.Name || loc.DisplayName || loc.Id}: ${flags.join(", ")} (${ips})`
        );
      }
    }
    if (hits.length) {
      pushNarrative(narratives, {
        id: "NARR.CA.TrustedIpHygiene",
        severity: "High",
        priority: "Now",
        title: "Trusted named location includes public DNS / anycast IPs",
        narrative:
          "A Conditional Access trusted named location includes well-known public resolver IPs (e.g. 1.1.1.1). Those are not corp egress — marking them trusted can weaken location-based MFA / block policies for anyone whose traffic appears from that anycast address.",
        evidence: hits.join(" | "),
        remediation:
          "Remove public DNS/CDN anycast from trusted named locations; keep only verified corp / partner egress CIDRs; re-test CA that use trusted locations.",
        relatedFiles: ["02_NamedLocations.csv", "02_CA_Audit.csv"],
        relatedChecks: ["AP.CA.NamedLocations"],
      });
    }
  }

  // ── NARR.MFA.MassGap — context-aware when CA blocks unlicensed / scopes MFA to licenses ─
  {
    const n = Number(ctx.summary.usersWithoutMfa ?? 0);
    const adminsReported = Number(ctx.summary.adminsWithoutMfa ?? 0);
    const noMfaRows = ctx.noMfa || [];
    const adminRows = (noMfaRows || []).filter(
      (r) => String(r.IsAdmin || "").toLowerCase() === "true"
    );
    const humanAdmins = adminRows.filter(
      (r) => !looksLikeServiceAccount(r.UPN || r.UserPrincipalName, r.DisplayName)
    );
    const serviceAdmins = adminRows.filter((r) =>
      looksLikeServiceAccount(r.UPN || r.UserPrincipalName, r.DisplayName)
    );
    const humanAdminCount = humanAdmins.length;
    const gate = detectLicenseGatedAccess(ctx.caAudit);
    const mfaCa = detectEnforcedMfaCoverage(ctx.caAudit);
    const compensated = gate.gated || mfaCa.covered;
    if (n >= 50 || adminsReported >= 1 || humanAdminCount >= 1) {
      let severity = "Medium";
      let priority = "Later";
      let narrative = "";
      if (humanAdminCount >= 1 && !compensated) {
        severity = "Critical";
        priority = "Now";
        narrative = `${n} users have no MFA methods registered (including ${humanAdminCount} human admin(s)). Without an enforced MFA CA covering interactive users, these accounts remain high-value spray targets.`;
      } else if (humanAdminCount >= 1 && compensated) {
        severity = "High";
        priority = "Now";
        narrative = `${humanAdminCount} human admin account(s) lack MFA registration. Broader tenant gap is ${n} users without MFA methods, but Conditional Access already requires MFA for the interactive population (${(mfaCa.evidence.length ? mfaCa.evidence : gate.evidence).slice(0, 2).join(", ") || "see 02_CA_Audit.csv"}) — prioritize closing the admin registration gap and reviewing MFA exclusion groups.`;
      } else if (compensated) {
        severity = "Medium";
        priority = "Next";
        narrative =
          `${n} users have no MFA methods registered, but this is largely a registration-inventory number rather than an open password-only path. ` +
          `Enforced MFA Conditional Access is present: ${(mfaCa.evidence.length ? mfaCa.evidence : gate.evidence).slice(0, 3).join(", ") || "see 02_CA_Audit.csv"}. ` +
          "Accounts without methods are challenged and fail interactive MFA, unless they sit in an MFA exclusion group, travel exemption, or use legacy/basic auth. " +
          "Track the exclusion-group population and remaining licensed interactive humans — not the raw 07_Users_Without_MFA count.";
        if (serviceAdmins.length) {
          narrative += ` Admin-flagged row(s) without strong MFA look like service/sync accounts (${serviceAdmins
            .map((r) => r.UPN)
            .join(", ")}) — expected for directory sync / automation; protect their credentials separately.`;
        }
      } else if (n >= 200) {
        severity = "High";
        priority = "Next";
        narrative = `${n} users have no MFA methods registered and no clear enforced MFA / license-gate CA was detected — treat as a meaningful registration + enforcement gap.`;
        if (mfaCa.scoped) {
          narrative +=
            ` Group-scoped MFA exists (${mfaCa.scopedEvidence.slice(0, 2).join(", ")}) — confirm membership covers the interactive population; this is not the same as All-users MFA.`;
        }
      } else {
        severity = "Medium";
        priority = "Next";
        narrative = `${n} users have no MFA methods registered. Confirm CA actually requires MFA for interactive users who can sign in.`;
      }
      pushNarrative(narratives, {
        id: "NARR.MFA.MassGap",
        severity,
        priority,
        title: compensated
          ? "MFA registration inventory gap (CA MFA already enforced)"
          : "Large MFA registration gap",
        narrative,
        evidence:
          `usersWithoutMfa=${n}; adminsWithoutMfa=${adminsReported}; humanAdminsWithoutMfa=${humanAdminCount}; serviceAdminsWithoutMfa=${serviceAdmins.length}` +
          (serviceAdmins.length
            ? ` [${serviceAdmins.map((r) => r.UPN).join(", ")}]`
            : "") +
          (humanAdmins.length
            ? `; humanAdminUpns=${humanAdmins.map((r) => r.UPN).slice(0, 5).join(",")}`
            : "") +
          (gate.gated
            ? `; licenseGatedCA=true (${gate.evidence.join(" | ") || "see 02_CA_Audit.csv"})`
            : "; licenseGatedCA=false") +
          (mfaCa.covered
            ? `; allUsersMfaCA=true (${mfaCa.allUsersEvidence.join(" | ")})`
            : "; allUsersMfaCA=false") +
          (mfaCa.scoped
            ? `; groupScopedMfaCA=true (${mfaCa.scopedEvidence.join(" | ")})`
            : "; groupScopedMfaCA=false") +
          " — 07_Users_Without_MFA.csv",
        remediation: compensated
          ? "Do not run a blanket MFA campaign on the raw count. Audit MFA / travel exclusion group membership (make those groups role-assignable), confirm legacy auth is blocked, register MFA for any remaining licensed interactive humans, and treat shared/service objects as sign-in-blocked rather than MFA targets."
          : "Enforce registration campaign + CA requiring MFA; prioritize human admins and privileged roles first.",
        relatedFiles: [
          "07_Users_Without_MFA.csv",
          "02_CA_Audit.csv",
          "40_CA_Exclusion_Groups.csv",
        ],
        relatedChecks: [],
      });
    }
  }

  // ── NARR.Priv.DisabledGA / vendor GA / MSP standing GA ─
  {
    const vendorish = [...privIndex.values()].filter(
      (e) =>
        e.isGa &&
        e.enabled !== false &&
        /(\.ext@|solutio|softwareone|partner|external|msp\b)/i.test(
          e.upn
        )
    );
    // Also catch MSP/vendor naming on hygiene display names (known MSP brands, .ext@, partner, …)
    const mspFromHygiene = (ctx.privHygiene || []).filter((r) => {
      if (!truthy(r.IsGlobalAdmin) && !/Global Administrator/i.test(r.Roles || "")) {
        return false;
      }
      if (r.AccountEnabled === false || String(r.AccountEnabled).toLowerCase() === "false") {
        return false;
      }
      return /msp\b|partner|softwareone|solutio|external/i.test(
        `${r.DisplayName || ""} ${r.UPN || ""} ${r.Mail || ""}`
      );
    });
    const mspUpns = new Set(
      mspFromHygiene.map((r) => normUpn(r.UPN)).filter(Boolean)
    );
    for (const u of vendorish) mspUpns.add(u.upn);

    if (mspUpns.size) {
      const labels = mspFromHygiene.length
        ? mspFromHygiene
            .slice(0, 10)
            .map((r) => `${r.DisplayName || r.UPN} <${r.UPN}>`)
        : [...mspUpns];
      pushNarrative(narratives, {
        id: "NARR.Priv.MspStandingGA",
        severity: "High",
        priority: "Now",
        title: "MSP / partner-style accounts hold Global Administrator",
        narrative: `${mspUpns.size} enabled Global Administrator account(s) look MSP/partner-operated (vendor/partner naming, .ext@ UPN, or similar). Standing partner GA is a supply-chain and shared-credential risk even when PIM-eligible on other roles.`,
        evidence: labels.join(" | "),
        remediation:
          "Prefer GDAP / least-privilege PIM-eligible roles under the partner tenant; remove permanent GA; monitor partner admin sign-ins; time-box access.",
        relatedFiles: [
          "40_Privileged_Identity_Hygiene.csv",
          "03_PrivilegedAccounts_HighValue.csv",
        ],
        relatedChecks: ["NARR.Priv.StandingGA"],
      });
    } else if (vendorish.length) {
      pushNarrative(narratives, {
        id: "NARR.Priv.ExternalGA",
        severity: "Critical",
        title: "External / vendor-style accounts hold Global Administrator",
        narrative: `${vendorish.length} enabled GA account(s) look external or vendor-operated. Standing partner GA is a common supply-chain / shared-credential risk.`,
        evidence: vendorish.map((e) => e.upn).join(" | "),
        remediation:
          "Replace with PIM-eligible least privilege (e.g. specific admin roles) under a guest or dedicated MSP tenant model; remove permanent GA.",
        relatedFiles: ["40_Privileged_Identity_Hygiene.csv"],
        relatedChecks: ["NARR.Priv.StandingGA"],
      });
    }
  }

  // ── NARR.App.TapAutomation — Auth Admin SP that issues Temporary Access Pass ─
  {
    const tapSpn = (ctx.privSpnCreds || []).filter((r) =>
      /tap|temporary.?access|generate.?tap/i.test(
        `${r.DisplayName || ""} ${r.AppId || ""} ${r.Role || ""}`
      )
    );
    const tapFromPriv = (ctx.priv || []).filter(
      (r) =>
        /serviceprincipal|service principal/i.test(r.PrincipalType || "") &&
        /Authentication Administrator/i.test(r.RoleName || "") &&
        /tap|generate.?tap/i.test(`${r.DisplayName || ""} ${r.UPNOrAppId || ""}`)
    );
    if (tapSpn.length || tapFromPriv.length) {
      const names = [
        ...tapSpn.map((r) => `${r.DisplayName} (${r.Role}; secrets=${r.ClientSecrets}; certs=${r.Certificates})`),
        ...tapFromPriv.map((r) => `${r.DisplayName || r.UPNOrAppId} [${r.RoleName}]`),
      ];
      const uniq = [...new Set(names)];
      pushNarrative(narratives, {
        id: "NARR.App.TapAutomation",
        severity: "High",
        priority: "Now",
        title: "Service principals can mint Temporary Access Pass (Authentication Administrator)",
        narrative: `${uniq.length} automation app(s) hold Authentication Administrator (or TAP-named privileged SP). Compromising their certificate/secret allows issuing TAPs for any user — a silent MFA bypass / account takeover path.`,
        evidence: uniq.slice(0, 8).join(" | "),
        remediation:
          "Confirm business need; restrict to Logic App / managed identity with locked network; monitor TAP issuance audit; prefer shorter once-only TAP; rotate credentials; remove unused TAP generators.",
        relatedFiles: [
          "40_Privileged_SPN_Credentials.csv",
          "03_PrivilegedAccounts_HighValue.csv",
        ],
        relatedChecks: ["AP.MFA.TAP", "AP.App.PathToGA"],
      });
    }
  }

  // ── NARR.App.CaPolicyWrite — Policy.ReadWrite.ConditionalAccess on apps ─
  {
    const caWrite = (ctx.dangerous || []).filter((r) =>
      /Policy\.ReadWrite\.ConditionalAccess/i.test(r.Permission || "")
    );
    if (caWrite.length && !appPlane.caWriteCoveredByPathToGa) {
      const byApp = new Map();
      for (const r of caWrite) {
        const name = r.SPNDisplayName || r.DisplayName || r.AppName || "?";
        if (!byApp.has(name)) byApp.set(name, new Set());
        byApp.get(name).add(r.Permission || "Policy.ReadWrite.ConditionalAccess");
      }
      const lines = [...byApp.entries()].map(
        ([name, perms]) => `${name} [${[...perms].join(", ")}]`
      );
      pushNarrative(narratives, {
        id: "NARR.App.CaPolicyWrite",
        severity: "High",
        priority: "Now",
        title: "Apps can create/modify Conditional Access policies",
        narrative:
          `${byApp.size} application(s) hold Policy.ReadWrite.ConditionalAccess. Stolen app credentials can weaken or disable MFA / device / location CA — a direct identity-control-plane takeover path. ` +
          "Note that an app-only grant also erases attribution: the audit log records the application name, not which engineer at the provider made the change, so a malicious or mistaken edit cannot be traced to a person.",
        evidence: lines.slice(0, 8).join(" | "),
        remediation:
          "Almost every use of this grant is really a read: monitoring drift, exporting policy, or reporting on coverage — all of which Policy.Read.All covers. Downgrade first and see what actually breaks. Where a provider genuinely needs to change your policies, do it with named human accounts holding a PIM-eligible Conditional Access Administrator role with approval and time limits, which keeps per-person attribution instead of collapsing it into one app identity. Whatever remains: alert on every CA create/update audit event, and restrict the service principal to the vendor's published egress with a workload-identity CA policy." +
          (leastPrivilegeAdvice([...byApp.keys()]).length
            ? " " + leastPrivilegeAdvice([...byApp.keys()]).join(" ")
            : ""),
        relatedFiles: ["04_SPN_DangerousPerms.csv"],
        relatedChecks: ["AP.App.PathToGA", "AP.CA.ExclGroups"],
      });
    }
  }

  // ── NARR.App.SpnActive / SpnDormant — over-privileged apps, by activity ─
  //
  // 04_SPN_DangerousPerms says which apps *could* do damage; 27_SPN_SignIns
  // says which ones are actually authenticating. Splitting the two turns one
  // undifferentiated list into "harden this now" vs "delete these credentials".
  {
    const signIns = ctx.spnSignIns || [];
    const digest = ctx.spnSignInDigest || [];
    const dangerous = ctx.dangerous || [];
    const activityKeys = buildSpnActivityIndex(signIns, digest);
    const observed = signIns.length + digest.length;

    /** @type {Map<string, {name:string, ids:string[], perms:Set<string>, sev:Set<string>}>} */
    const risky = new Map();
    for (const r of dangerous) {
      const name = r.SPNDisplayName || r.DisplayName || r.AppName;
      const id = String(r.PrincipalId || "").trim().toLowerCase();
      const key = id || normName(name);
      if (!key) continue;
      if (!risky.has(key)) {
        risky.set(key, { name: name || key, ids: [], perms: new Set(), sev: new Set() });
      }
      const e = risky.get(key);
      if (id && !e.ids.includes(id)) e.ids.push(id);
      if (r.Permission) e.perms.add(r.Permission);
      if (r.Severity) e.sev.add(r.Severity);
    }

    const activityByKey = new Map();
    const bumpActivity = (r, n = 1) => {
      for (const k of spnIdentityKeys(r)) {
        if (!activityByKey.has(k)) {
          activityByKey.set(k, { n: 0, ips: new Set(), locs: new Set(), failures: 0 });
        }
        const e = activityByKey.get(k);
        e.n += n;
        if (r.IP) e.ips.add(r.IP);
        if (r.Location) e.locs.add(r.Location);
        if (r.Status && String(r.Status).trim() !== "0") e.failures++;
      }
    };
    for (const r of signIns) bumpActivity(r, 1);
    if (!signIns.length) {
      for (const r of digest) bumpActivity(r, Number(r.Events || 0) || 0);
    }

    const statsFor = (entry) => {
      for (const k of [normName(entry.name), ...(entry.ids || [])]) {
        if (activityByKey.has(k)) return activityByKey.get(k);
      }
      return { n: 0, ips: new Set(), locs: new Set(), failures: 0 };
    };

    const active = [...risky.values()]
      .filter((e) => spnIsActive(e, activityKeys))
      .map((e) => ({ ...e, ...statsFor(e) }))
      .sort((a, b) => b.n - a.n);

    // Prefer NARR.App.DangerousSpnActivity (digest ∩ high-priv) when available —
    // SpnActive would tell the same story with thinner evidence.
    const digestHot = digest.some(
      (r) =>
        /yes/i.test(String(r.HighPrivSpn || "")) && Number(r.Events || 0) > 0
    );
    if (observed && active.length && !digestHot) {
      const worst = active.filter((a) => a.sev.has("Critical"));
      const spread = active.filter((a) => a.ips.size >= 5);
      const line = (a) =>
        `${a.name} — ${a.n} sign-in(s), ${a.ips.size} IP, ${[...a.sev].join("/")} [${[...a.perms].slice(0, 3).join(", ")}]`;

      pushNarrative(narratives, {
        id: "NARR.App.SpnActive",
        severity: worst.length ? "High" : "Medium",
        priority: worst.length ? "Now" : "Next",
        title: "Over-privileged service principals are actively authenticating",
        narrative:
          `${active.length} of ${risky.size} service principals holding dangerous Graph permissions actually signed in during the window` +
          (worst.length
            ? `, including ${worst.length} with Critical-severity grants. These are live credentials on a real attack path, not dormant configuration.`
            : ". Their credentials are in active use, so rotation and owner review are operationally relevant.") +
          (spread.length
            ? ` ${spread.length} authenticate from 5+ distinct IPs — confirm this matches the vendor's documented egress, since a stolen secret would look identical.`
            : ""),
        evidence: active.slice(0, 8).map(line).join(" | "),
        remediation:
          "For each app, confirm the business owner and that the granted scope is still required; downgrade write grants to read; rotate secrets; restrict to known egress IPs with a CA policy for workload identities; alert on sign-ins from new IPs.",
        relatedFiles: ["27_SPN_SignIns_90d.csv", "04_SPN_DangerousPerms.csv"],
        relatedChecks: ["AP.App.PathToGA"],
      });
    }

    // Never-seen apps: same blast radius, zero business justification on record.
    // Join on AppId / service-principal id first — display names diverge across Graph vs hunting.
    const dormant = [...risky.values()].filter((e) => !spnIsActive(e, activityKeys));
    if (observed && dormant.length >= 3) {
      const critical = dormant.filter((e) => e.sev.has("Critical"));
      pushNarrative(narratives, {
        id: "NARR.App.SpnDormant",
        severity: critical.length ? "Medium" : "Low",
        priority: "Next",
        title: "Over-privileged service principals with no sign-in activity",
        narrative: `${dormant.length} service principals hold dangerous Graph permissions but never authenticated in the observed window${critical.length ? `, ${critical.length} of them with Critical-severity grants` : ""}. Unused credentials carry the full blast radius with none of the business value, and nobody would notice them being used.`,
        evidence: dormant
          .slice(0, 10)
          .map((e) => `${e.name} [${[...e.perms].slice(0, 2).join(", ")}]`)
          .join(" | "),
        remediation:
          "Confirm each app is genuinely unused, then remove the service principal or its app-role assignments. If it is a break-glass or seasonal integration, document it and shorten the credential lifetime.",
        relatedFiles: ["27_SPN_SignIns_90d.csv", "04_SPN_DangerousPerms.csv"],
        relatedChecks: ["AP.App.PathToGA"],
      });
    }
  }

  // ── NARR.App.ExpiredSecrets — expired client secrets still registered ─
  {
    const secrets = ctx.secretsExpiry || [];
    const expired = secrets.filter(
      (r) => /expired/i.test(r.Status || "") || Number(r.DaysLeft) < 0
    );
    const soon = secrets.filter((r) => {
      const d = Number(r.DaysLeft);
      return !Number.isNaN(d) && d >= 0 && d <= 30;
    });
    if (expired.length || soon.length >= 3) {
      const apps = [
        ...new Set(
          [...expired, ...soon]
            .map((r) => r.AppName || r.DisplayName)
            .filter(Boolean)
        ),
      ];
      pushNarrative(narratives, {
        id: "NARR.App.ExpiredSecrets",
        severity: expired.length >= 3 ? "Medium" : "Low",
        priority: expired.length >= 3 ? "Next" : "Later",
        title: "Application client secrets expired (or near expiry)",
        narrative:
          `${expired.length} secret(s) already expired` +
          (soon.length ? ` and ${soon.length} expiring ≤30d` : "") +
          `. Expired secrets on SSO/automation apps often mean broken auth or forgotten credentials still listed on high-value apps — rotate/remove and prefer certificates / managed identities.`,
        evidence:
          apps.slice(0, 10).join(" | ") +
          ` — expired=${expired.length}, ≤30d=${soon.length} (04_App_SecretsExpiry.csv)`,
        remediation:
          "Remove expired secrets; rotate active ones; enable app management policies for secret lifetime; prefer federated credentials / certs.",
        relatedFiles: ["04_App_SecretsExpiry.csv"],
        relatedChecks: ["AP.App.Management"],
      });
    }
  }

  // ── NARR.CA.AzureMgmt partial ─
  //
  // This is about *which cloud apps* a CA policy targets — not about admins
  // being signed in on many devices. "Microsoft Admin Portals" covers the
  // browser portals (Entra, Azure portal UI, Intune admin, …). A separate
  // first-party app, Azure Service Management (797f4846-…), is what
  // az CLI / Azure PowerShell / Terraform / ARM REST talk to. A policy that
  // only includes Admin Portals does not automatically cover that API.
  {
    const st = checklistStatus(ctx.checklist, "AP.CA.AzureMgmt");
    if (/partial/i.test(st)) {
      const row = (ctx.checklist || []).find(
        (r) => String(r.CheckId || "").toUpperCase() === "AP.CA.AZUREMGMT"
      );
      const adminPortalPolicies = (ctx.caAudit || []).filter((r) => {
        const enforced =
          /^enabled$/i.test(String(r.State || "")) ||
          String(r.IsEnforced || "").toLowerCase() === "yes";
        return (
          enforced &&
          /microsoftadminportals|admin portals/i.test(
            `${r.IncludeApps || ""} ${r.PolicyName || ""}`
          ) &&
          /mfa|multifactor|authentication strength/i.test(
            `${r.GrantControls || ""} ${r.AuthStrength || ""} ${r.PolicyName || ""}`
          )
        );
      });
      pushNarrative(narratives, {
        id: "NARR.CA.AzureMgmt",
        severity: "Medium",
        priority: "Later",
        title: "MFA CA covers admin portals in the browser, but maybe not Azure CLI / PowerShell",
        narrative:
          "Two different Microsoft first-party apps are involved, and Conditional Access treats them separately. " +
          "Policies that target **Microsoft Admin Portals** protect sign-ins to the browser admin UIs (Entra portal, Azure portal, Intune admin centre, …). " +
          "They do **not** automatically protect the **Azure Service Management** app (`797f4846-ba00-4fd7-ba43-dac1f8f63013`), which is what `az`, Azure PowerShell, Terraform and direct ARM REST calls authenticate against. " +
          "So an admin can be forced through MFA when opening portal.azure.com, yet still obtain an Azure management token from the CLI with password-only if no other policy covers that app. " +
          "This finding is unrelated to how many devices an admin is registered on — that is inventory (see NARR.Devices.MultiEndpoint). The question here is only: when an admin runs `az login` / `Connect-AzAccount`, does CA challenge them for MFA?",
        evidence:
          [
            `Checklist AP.CA.AzureMgmt = Partial${
              row?.Evidence
                ? ` — ${String(row.Evidence).replace(/\s*\|\s*/g, "; ")}`
                : ""
            }`,
            adminPortalPolicies.length
              ? `Admin-portal MFA policies seen: ${adminPortalPolicies
                  .slice(0, 4)
                  .map((p) => p.PolicyName)
                  .join("; ")}`
              : "Admin-portal MFA policies matched by name/cloud-app include",
            "Azure Service Management app 797f4846-ba00-4fd7-ba43-dac1f8f63013 not clearly included in an enforced MFA CA",
          ].join(" | "),
        remediation:
          "In the MFA CA that protects admins, add the cloud app **Azure Management** / Azure Service Management (`797f4846-ba00-4fd7-ba43-dac1f8f63013`) alongside Microsoft Admin Portals — or create a dedicated policy for privileged roles targeting that app. Then verify with `az login` from a non-compliant / fresh session that MFA is actually prompted. Prefer phishing-resistant MFA for those roles.",
        relatedFiles: [
          "40_AttackPath_Checklist.csv",
          "40_CA_AttackPath_Coverage.csv",
          "02_CA_Audit.csv",
        ],
        relatedChecks: ["AP.CA.AzureMgmt"],
      });
    }
  }

  // ── NARR.Endpoint.RmmSuspicious — desktop agents vs inventory noise ─
  {
    const rawAssets = (ctx.rmmAssets || []).length
      ? ctx.rmmAssets
      : ctx.rmmDetections || [];
    const enriched = enrichRmmAssets(rawAssets);
    const byFam = summarizeRmmByFamily(enriched);
    const familyRows = [...byFam.values()].filter((f) => f.Devices > 0);
    const agentFamilies = familyRows.filter((f) => f.AgentDevices > 0);
    const noiseOnlyFamilies = familyRows.filter(
      (f) => f.AgentDevices === 0 && f.NoiseDevices > 0
    );
    const agentAssets = enriched.filter((a) => a.Signal);
    const noiseAssets = enriched.filter((a) => !a.Signal);

    const famCsv = ctx.rmmFamily || [];
    const prevalenceKnown = famCsv.some(
      (r) =>
        Number(r.TotalWindows || 0) > 0 &&
        r.PrevalencePct != null &&
        String(r.PrevalencePct).trim() !== ""
    );
    const assumedLegitFamilies = new Set(
      famCsv
        .filter((r) => truthy(r.AssumedLegit))
        .map((r) => String(r.Family || ""))
    );
    // When prevalence is known, drop high-coverage corporate RMM from "suspicious".
    const reviewAgentFamilies = prevalenceKnown
      ? agentFamilies.filter((f) => !assumedLegitFamilies.has(f.Family))
      : agentFamilies;

    const ownerBlob = agentAssets
      .map((a) => `${a.Owners || ""} ${a.OwnersUPN || ""}`)
      .join(" ");
    const itOwned =
      agentAssets.length > 0 &&
      agentAssets.filter((a) =>
        /\badm[._]|it[._]|admin|support|helpdesk/i.test(
          `${a.Owners || ""} ${a.OwnersUPN || ""}`
        )
      ).length >= Math.ceil(agentAssets.length / 2);

    const mildOnly =
      reviewAgentFamilies.length > 0 &&
      reviewAgentFamilies.every((f) =>
        /teamviewer/i.test(String(f.Family || ""))
      );

    // Multi-tool sprawl on the same host is a stronger shadow-IT signal than
    // a single widespread family (which may be sanctioned support).
    const byHost = new Map();
    for (const a of agentAssets) {
      const host = a.DeviceName || a.DeviceId;
      if (!host) continue;
      if (!byHost.has(host)) byHost.set(host, new Set());
      byHost.get(host).add(a.Family);
    }
    const multiToolHosts = [...byHost.entries()].filter(
      ([, fs]) => fs.size >= 2
    ).length;

    const noiseSummary = [
      noiseAssets.filter((a) => a.RiskClass === "mobile").length
        ? `${noiseAssets.filter((a) => a.RiskClass === "mobile").length} mobile/BYOD`
        : null,
      noiseAssets.filter((a) => a.RiskClass === "viewer").length
        ? `${noiseAssets.filter((a) => a.RiskClass === "viewer").length} outbound viewer`
        : null,
      noiseAssets.filter((a) => a.RiskClass === "adhoc").length
        ? `${noiseAssets.filter((a) => a.RiskClass === "adhoc").length} QuickSupport/add-on`
        : null,
    ]
      .filter(Boolean)
      .join(", ");

    if (reviewAgentFamilies.length) {
      const top = reviewAgentFamilies
        .slice()
        .sort((a, b) => b.AgentDevices - a.AgentDevices)
        .slice(0, 8);
      const evidenceFamilies = top
        .map((f) => {
          const bits = [`${f.Family}: ${f.AgentDevices} agent host(s)`];
          if (f.NoiseDevices)
            bits.push(
              `${f.NoiseDevices} noise filtered (mobile=${f.MobileDevices}, viewer=${f.ViewerDevices}, adhoc=${f.AdhocDevices})`
            );
          return bits.join(", ");
        })
        .join(" | ");
      // Prefer agent evidence; put multi-tool hosts first.
      const rankedAgents = agentAssets
        .filter((a) =>
          reviewAgentFamilies.some((f) => f.Family === a.Family)
        )
        .slice()
        .sort((a, b) => {
          const ha = byHost.get(a.DeviceName || a.DeviceId);
          const hb = byHost.get(b.DeviceName || b.DeviceId);
          return (hb?.size || 0) - (ha?.size || 0);
        });
      const assetLines = rankedAgents.slice(0, 18).map(formatAssetLine);

      let severity = "High";
      if (itOwned || mildOnly) severity = "Medium";
      // Widespread single consumer tool without multi-tool sprawl → often
      // cultural/sanctioned support rather than a foothold campaign.
      const totalAgents = reviewAgentFamilies.reduce(
        (n, f) => n + f.AgentDevices,
        0
      );
      if (
        !multiToolHosts &&
        totalAgents >= 50 &&
        reviewAgentFamilies.length === 1 &&
        /teamviewer/i.test(reviewAgentFamilies[0].Family)
      ) {
        severity = "Medium";
      }
      if (multiToolHosts >= 5) severity = "High";

      pushNarrative(narratives, {
        id: "NARR.Endpoint.RmmSuspicious",
        severity,
        priority: severity === "High" ? "Next" : "Later",
        title: itOwned
          ? "Desktop RMM agents on endpoints (likely IT-owned — confirm allow-list)"
          : multiToolHosts
            ? "Desktop RMM / remote-access agents (multi-tool sprawl)"
            : "Desktop RMM / remote-access agents on endpoints",
        narrative:
          `${reviewAgentFamilies.length} remote-access family(ies) show desktop agent/host installs` +
          ` (${totalAgents} agent host(s)` +
          (multiToolHosts
            ? `; ${multiToolHosts} host(s) run 2+ agent families`
            : "") +
          `). ` +
          (noiseSummary
            ? `Filtered as inventory noise (not counted as agent signal): ${noiseSummary}. `
            : "") +
          (prevalenceKnown
            ? itOwned
              ? "Owners look like IT/admin identities — often legitimate support tooling; confirm allow-list before treating as foothold. "
              : "Corporate RMM usually shows high fleet coverage on one approved family; low-prevalence or multi-tool stacks are more often shadow IT. "
            : "Fleet prevalence could not be measured (DeviceInfo missing) — treat this as an allow-list / hygiene review, not proof of compromise. ") +
          "Evidence below lists agent hosts first (mobile viewers / QuickSupport excluded).",
        evidence:
          evidenceFamilies +
          (assetLines.length ? ` || ${assetLines.join(" || ")}` : ""),
        remediation: itOwned
          ? "Confirm the approved remote-support stack with IT; document the allow-list; remove non-approved desktop agents; alert on new RMM families."
          : "Allow-list one corporate RMM if needed; remove unauthorized desktop agents (AnyDesk/Splashtop/UltraVNC/Datto/etc.) from 30_RMM_Affected_Assets.csv where Signal=true; ignore mobile/viewer noise unless policy forbids them; alert on new agent installs.",
        relatedFiles: [
          "30_RMM_Affected_Assets.csv",
          "30_RMM_Family_Summary.csv",
          "30_RMM_Detections.csv",
        ],
      });
    }

    // Noise-only (or leftover noise when agents already narrated) — Info so
    // assessors see we did not ignore the inventory.
    if (noiseOnlyFamilies.length || (noiseAssets.length && !reviewAgentFamilies.length)) {
      const noiseFam = (noiseOnlyFamilies.length
        ? noiseOnlyFamilies
        : familyRows.filter((f) => f.NoiseDevices > 0)
      )
        .slice()
        .sort((a, b) => b.NoiseDevices - a.NoiseDevices)
        .slice(0, 8);
      if (noiseFam.length && !reviewAgentFamilies.length) {
        pushNarrative(narratives, {
          id: "NARR.Endpoint.RmmInventoryNoise",
          severity: "Info",
          priority: "Later",
          title: "RMM inventory is mostly noise (mobile / viewers / ad-hoc)",
          narrative:
            `TVM lists remote-access related software, but after classification there is no desktop agent/host signal worth treating as a foothold. ` +
            `Typical noise: mobile/BYOD clients (*_Android, *_for_android), outbound VNC/RealVNC viewers, and TeamViewer QuickSupport/add-ons. ` +
            (noiseSummary ? `This export: ${noiseSummary}. ` : "") +
            `Re-check if policy bans even viewers/mobile clients.`,
          evidence: noiseFam
            .map(
              (f) =>
                `${f.Family}: ${f.NoiseDevices} noise host(s) (mobile=${f.MobileDevices}, viewer=${f.ViewerDevices}, adhoc=${f.AdhocDevices})`
            )
            .join(" | "),
          remediation:
            "No urgent RMM agent cleanup unless policy forbids these clients. Keep monitoring for new desktop agent families (ScreenConnect, AnyDesk host, Splashtop streamer, DattoRMM, UltraVNC server, etc.).",
          relatedFiles: [
            "30_RMM_Family_Summary.csv",
            "30_RMM_Affected_Assets.csv",
            "30_RMM_Dismissed_Artefacts.csv",
          ],
        });
      }
    }
  }

  // ── NARR.Endpoint.TvmCves — unpatched High/Critical CVEs on devices ─
  {
    const vulns = ctx.defenderVulns || [];
    const tvmWin = ctx.tvmWin || [];
    const { os, runtime } = splitTvmVulns(vulns);
    const osSev = tvmSeverity(os);
    if (vulns.length || tvmWin.length) {
      const devices = new Set(
        [
          ...os.map((r) => r.DeviceId || r.DeviceName).filter(Boolean),
          ...tvmWin.map((r) => r.DeviceId || r.DeviceName).filter(Boolean),
        ]
      ).size;
      const sampleVulns = os
        .concat(runtime)
        .slice(0, 6)
        .map(
          (r) =>
            `${r.CveId || "?"} (${r.Software || "?"}, ${r.Devices || "?"} devices)`
        )
        .join(" | ");
      const sampleWin = tvmWin
        .slice(0, 6)
        .map(
          (r) =>
            `${r.DeviceName || "?"}: ${r.Software || "windows"} crit=${r.Critical || 0}/high=${r.High || 0} (vulns=${r.Vulns || "?"})`
        )
        .join(" | ");
      const hasCritOs =
        osSev.crit > 0 || tvmWin.some((r) => Number(r.Critical) > 0);
      const osSignal = os.length || tvmWin.length;
      pushNarrative(narratives, {
        id: "NARR.Endpoint.TvmCves",
        severity: hasCritOs ? "High" : osSignal ? "Medium" : "Low",
        priority: hasCritOs ? "Now" : "Next",
        title: hasCritOs
          ? "Unpatched Critical Windows / OS CVEs on Defender-managed devices"
          : osSignal
            ? "Unpatched High-severity Windows CVEs on Defender-managed devices"
            : "Unpatched third-party / runtime CVEs (not Windows CU lag)",
        narrative:
          (osSignal
            ? `Defender TVM shows High/Critical *Windows OS* findings on ~${devices || "n/a"} device(s)` +
              (osSev.crit ? ` (${osSev.crit} Critical OS CVE row(s))` : "") +
              (tvmWin.length
                ? ` and ${tvmWin.length} Windows device/software row(s) in 32_*. `
                : ". ")
            : "No Windows OS CVE rows in the TVM sample. ") +
          (runtime.length
            ? `${runtime.length} row(s) are runtime/libraries (openssl, 7-zip, .NET, browsers) — treat separately from Patch Tuesday / WUfB lag, they are not a missing CU. `
            : "") +
          "Unpatched OS CVEs remain a ransomware / lateral-movement path; library CVEs are patch-the-app, not skip-a-Tuesday.",
        evidence:
          [sampleWin, sampleVulns].filter(Boolean).join(" || ") ||
          `${vulns.length} rows in 11_Defender_Exploitable_Vulns.csv`,
        remediation:
          "Prioritize Critical on windows_* in 32_TVM_Windows_HighCritical.csv; enforce update rings; isolate devices that cannot patch. Runtime CVEs (openssl/.NET) go to the owning app owners, not the Windows CU ring.",
        relatedFiles: [
          "32_TVM_Windows_HighCritical.csv",
          "32_TVM_Windows_CVE_Inventory.csv",
          "11_Defender_Exploitable_Vulns.csv",
        ],
      });
    }
  }

  // ── NARR.Endpoint.PatchLag — behind Patch Tuesday ─
  {
    let behind =
      (ctx.patchBehind || []).length ||
      Number(ctx.summary.behindPatchTuesdayCount || 0);
    let derived = false;
    const osRows = ctx.osPatchStatus || [];
    const allUnknown =
      osRows.length > 0 &&
      osRows.every((r) => /unknown/i.test(String(r.PatchStatus || "")));
    if ((!behind || allUnknown) && ctx.patchTuesdayRef && ctx.patchTuesdayRef.builds) {
      const lag = patchLagFromSoftwareVersions(
        [
          ...(ctx.defenderVulns || []),
          ...(ctx.tvmWin || []).map((r) => ({
            Software: r.Software || "windows_11",
            Version: r.Version,
            DeviceId: r.DeviceId,
            DeviceName: r.DeviceName,
          })),
        ],
        ctx.patchTuesdayRef
      );
      if (lag.known && lag.behind > behind) {
        behind = lag.behind;
        derived = true;
      }
    }
    if (behind > 0) {
      pushNarrative(narratives, {
        id: "NARR.Endpoint.PatchLag",
        severity: behind >= 10 ? "High" : "Medium",
        priority: behind >= 10 ? "Now" : "Next",
        title: "Windows devices behind current Patch Tuesday baseline",
        narrative: `${behind} device(s) lag the current Patch Tuesday baseline (${ctx.summary.patchTuesdayAsOf || "see 30_patch_tuesday_reference.json"}${ctx.summary.patchTuesdaySource ? `, source=${ctx.summary.patchTuesdaySource}` : ""}).` +
          (derived
            ? " DeviceInfo had no UBR; lag was derived from TVM software versions against 30_patch_tuesday_reference.json."
            : "") +
          " Delayed cumulative updates leave known CVE windows open.",
        evidence: `behindPatchTuesdayCount=${behind}; sample=${(ctx.patchBehind || [])
          .slice(0, 5)
          .map((r) => r.DeviceName || r.DeviceId)
          .filter(Boolean)
          .join(" | ")}`,
        remediation:
          "Review 32_Behind_PatchTuesday.csv and Intune update rings (33_*); accelerate quality updates; investigate rings with long deferrals.",
        relatedFiles: [
          "32_Behind_PatchTuesday.csv",
          "33_Intune_UpdateRings.csv",
          "30_patch_tuesday_reference.json",
        ],
      });
    }
  }

  // ── NARR.Endpoint.Windows10 — EOS / ESU risk ─
  {
    const n =
      (ctx.win10 || []).length || Number(ctx.summary.windows10Count || 0);
    if (n > 0) {
      pushNarrative(narratives, {
        id: "NARR.Endpoint.Windows10",
        severity: n >= 20 ? "Medium" : "Low",
        priority: "Later",
        title: "Windows 10 devices still active",
        narrative: `${n} Windows 10 endpoint(s) still report into hunting/inventory — post-EOS risk unless covered by ESU and tightly scoped.`,
        evidence: `windows10Count=${n} — 32_Windows10_Devices.csv`,
        remediation:
          "Migrate to Windows 11, or document ESU + compensating controls; remove stale Win10 from Entra/Intune.",
        relatedFiles: ["32_Windows10_Devices.csv"],
      });
    }
  }

  // ── NARR.Cloud.FileSharing — endpoints reaching consumer transfer sites ─
  //
  // This is network *reachability*, not upload volume: Defender exposes no byte
  // counters. A high event count almost always means a sync client is installed
  // and polling, which is a different (and more actionable) problem than a
  // one-off transfer, so the narrative says which is which instead of implying
  // exfiltration was observed.
  {
    const rows = ctx.fileShareUsers || [];
    const apps = ctx.fileShareApps || [];
    if (rows.length || apps.length) {
      const domainOf = (r) => {
        const m = String(r.SampleActions || "").match(
          /(?:https?:\/\/)?(?:[\w-]+\.)*?([\w-]+\.(?:com|net|io|nz|co\.nz|tl|org))/i
        );
        return m ? m[1].toLowerCase() : r.Application || "?";
      };
      const byService = new Map();
      for (const r of rows) {
        const svc = domainOf(r);
        const e = byService.get(svc) || { events: 0, users: new Set(), devices: new Set() };
        e.events += Number(r.Events || 0);
        if (r.Account) e.users.add(r.Account);
        if (r.DeviceName) e.devices.add(r.DeviceName);
        byService.set(svc, e);
      }
      const ranked = [...byService.entries()].sort((a, b) => b[1].events - a[1].events);
      // A sync client chatters continuously; a browser upload does not.
      const syncLike = ranked.filter(([, e]) => e.events >= 100);
      const users = new Set(rows.map((r) => r.Account).filter(Boolean)).size;
      const devices = new Set(rows.map((r) => r.DeviceName).filter(Boolean)).size;

      pushNarrative(narratives, {
        id: "NARR.Cloud.FileSharing",
        severity: syncLike.length ? "Medium" : "Low",
        priority: "Next",
        title: "Managed endpoints reaching consumer file-sharing services",
        narrative:
          `${users} account(s) on ${devices} managed device(s) connected to consumer file-transfer services in the last 30 days ` +
          `(${ranked.slice(0, 4).map(([s]) => s).join(", ")}). ` +
          "Source is DeviceNetworkEvents — this is network connectivity observed by Defender for Endpoint, " +
          "not evidence that files were uploaded: no Defender hunting table exposes transfer volume. " +
          (syncLike.length
            ? `${syncLike.length} service(s) show sustained traffic (100+ connections), which is the signature of an installed sync client rather than an occasional web upload — that is a standing, unmanaged copy of corporate data outside DLP.`
            : "Volumes are low and consistent with occasional browsing rather than an installed client.") +
          " Rank it on whether these services are sanctioned, not on the event counts.",
        evidence: ranked
          .slice(0, 8)
          .map(
            ([svc, e]) =>
              `${svc} — ${e.events} connections, ${e.users.size} user(s), ${e.devices.size} device(s)${e.events >= 100 ? " (sync-client pattern)" : ""}`
          )
          .join(" | "),
        remediation:
          "Decide per service whether it is sanctioned. For the rest: block the domains at the proxy/Defender for Cloud Apps, remove the desktop sync clients (they persist across reboots and re-authenticate silently), and give users a sanctioned alternative — OneDrive/SharePoint sharing links with DLP — otherwise the usage simply moves to an unmonitored service.",
        relatedFiles: [
          "35_FileShare_Usage_ByUser.csv",
          "35_FileShare_Usage_ByApp.csv",
        ],
      });
    }
  }

  // ── NARR.Cloud.GenAiUsage — sanctioned vs unsanctioned AI reach ─
  //
  // Deliberately no "MB transferred": CloudAppEvents and DeviceNetworkEvents
  // have no byte counters (the only size column in the schema is
  // InitiatingProcessFileSize, the executable's size). Claiming ~0 MB told the
  // reader nobody used AI, which was exactly backwards. What these tables do
  // support is reach — who, how often, sanctioned tenant app or open web.
  {
    const rows = ctx.genAiUsers || [];
    const apps = ctx.genAiApps || [];
    if (rows.length || apps.length) {
      const cloudRows = rows.filter((r) => r.Source === "CloudAppEvents");
      const netRows = rows.filter((r) => r.Source === "DeviceNetworkEvents");

      const totalEvents = rows.reduce((s, r) => s + (Number(r.Events) || 0), 0);
      const cloudEvents = cloudRows.reduce((s, r) => s + (Number(r.Events) || 0), 0);
      const netEvents = netRows.reduce((s, r) => s + (Number(r.Events) || 0), 0);
      const netDevices = new Set(netRows.map((r) => r.DeviceName).filter(Boolean));

      // Which third-party AI services the endpoints actually reached. Match on
      // the full known hostnames rather than the second-level domain, so
      // copilot.microsoft.com is not collapsed into a bare "microsoft.com".
      const AI_SERVICES = [
        "chatgpt.com",
        "chat.openai.com",
        "openai.com",
        "claude.ai",
        "anthropic.com",
        "gemini.google.com",
        "bard.google.com",
        "perplexity.ai",
        "copilot.microsoft.com",
        "copilot.cloud.microsoft",
        "midjourney.com",
        "character.ai",
        "poe.com",
        "huggingface.co",
        "grok.x.ai",
        "x.ai",
        "you.com",
      ];
      const svcCount = new Map();
      for (const r of netRows) {
        const sample = String(r.SampleActions || "").toLowerCase();
        const events = Number(r.Events || 0);
        for (const svc of AI_SERVICES) {
          if (sample.includes(svc)) {
            svcCount.set(svc, (svcCount.get(svc) || 0) + events);
          }
        }
      }
      const services = [...svcCount.entries()].sort((a, b) => b[1] - a[1]);
      const sanctioned = cloudRows.length
        ? [...new Set(cloudRows.map((r) => r.Application))]
        : [];

      const evidence = [];
      if (sanctioned.length) {
        evidence.push(
          `Sanctioned (tenant apps, CloudAppEvents): ${sanctioned.join(", ")} — ${cloudEvents} interactions, ${new Set(cloudRows.map((r) => r.Account)).size} users`
        );
      }
      for (const [svc, ev] of services.slice(0, 8)) {
        evidence.push(`${svc} — ${ev} connections (endpoint network)`);
      }
      if (netDevices.size) {
        evidence.push(`${netDevices.size} device(s) reached third-party AI services directly`);
      }

      pushNarrative(narratives, {
        id: "NARR.Cloud.GenAiUsage",
        severity: netRows.length ? "Medium" : "Low",
        priority: "Later",
        title: netRows.length
          ? "Generative AI in use through both sanctioned and unsanctioned paths"
          : "Generative AI usage is confined to sanctioned tenant apps",
        narrative:
          `${totalEvents.toLocaleString("en-US")} AI-related events in the last 30 days. ` +
          (cloudRows.length
            ? `${cloudEvents.toLocaleString("en-US")} are interactions with sanctioned tenant apps (${sanctioned.join(", ")}), which stay inside the Microsoft data boundary and are covered by tenant DLP. `
            : "") +
          (netRows.length
            ? `${netEvents.toLocaleString("en-US")} are direct connections from ${netDevices.size} managed device(s) to third-party AI services — those sessions leave the tenant boundary, so anything pasted into them is outside DLP and outside audit. `
            : "") +
          "Note that Defender exposes no transfer volume for either path: neither CloudAppEvents nor DeviceNetworkEvents carries byte counters, so the exposure has to be judged on reach and on whether the service is sanctioned, not on megabytes. Measuring actual data volume requires a CASB/proxy in line.",
        evidence: evidence.join(" | ") || `genAiUsageRows=${rows.length}`,
        remediation:
          "Treat the sanctioned path as the target state and steer usage to it. For the third-party services: decide which are approved, apply Defender for Cloud Apps session policies (or block) on the rest, and enable endpoint DLP rules for paste/upload to AI domains — that is also the only way to get real volume telemetry. Publish an AI usage policy naming the approved tools, since blocking without an alternative moves usage to personal devices where there is no telemetry at all.",
        relatedFiles: ["34_GenAI_Usage_ByUser.csv", "34_GenAI_Usage_ByApp.csv"],
      });
    }
  }

  // ── NARR.Cloud.ShadowAi — unsanctioned endpoint AI agents (31_*) ─
  {
    const SANCTIONED = new Set([
      "githubcopilot",
      "otherai", // EdgeUpdate / WebView noise
      "microsoftcopilot",
      "m365copilot",
    ]);
    const byFam = new Map();
    for (const r of ctx.aiAgents || []) {
      const fam = String(r.Family || "").trim();
      if (!fam || SANCTIONED.has(fam.toLowerCase())) continue;
      const devices = Number(r.Devices || 0);
      const events = Number(r.Events || 0);
      const prev = byFam.get(fam) || { devices: 0, events: 0 };
      byFam.set(fam, {
        devices: Math.max(prev.devices, devices),
        events: prev.events + events,
      });
    }
    const ranked = [...byFam.entries()]
      .filter(([, s]) => s.devices > 0)
      .sort((a, b) => b[1].devices - a[1].devices);
    const broad = ranked.filter(([, s]) => s.devices >= 10);
    if (ranked.length && (broad.length || ranked.some(([, s]) => s.devices >= 3))) {
      const maxDev = ranked[0]?.[1]?.devices || 0;
      pushNarrative(narratives, {
        id: "NARR.Cloud.ShadowAi",
        severity: maxDev >= 50 ? "Medium" : "Low",
        priority: maxDev >= 50 ? "Next" : "Later",
        title: "Shadow / unsanctioned AI agents on endpoints",
        narrative: `${ranked.length} non-Copilot AI family(ies) observed on endpoints (e.g. Perplexity, Claude, ChatGPT, local LLMs). Unsanctioned AI is a data-exfil and shadow-IT path; Microsoft Copilot signals are excluded as typically enterprise-sanctioned.`,
        evidence: ranked
          .slice(0, 10)
          .map(([f, s]) => `${f}: ${s.devices} devices / ${s.events} events`)
          .join(" | "),
        remediation:
          "Allow-list approved AI only; block Perplexity/Claude desktop + consumer ChatGPT via Defender / network; prefer M365 Copilot with DLP; inventory LM Studio / Ollama hosts.",
        relatedFiles: [
          "31_AI_Agents_Summary.csv",
          "34_GenAI_Usage_ByApp.csv",
        ],
      });
    }
  }

  // ── NARR.Mail.SetMailboxBurst — high volume Set-Mailbox CloudApp events ─
  {
    const events = (ctx.cloudAppHigh || []).filter((r) =>
      /Set-Mailbox/i.test(r.ActionType || "")
    );
    if (events.length >= 50) {
      const byAcct = new Map();
      for (const r of events) {
        const a = String(r.Account || "").trim() || "(empty / system)";
        byAcct.set(a, (byAcct.get(a) || 0) + 1);
      }
      const topAcct = [...byAcct.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 6)
        .map(([a, n]) => `${a}=${n}`)
        .join(" | ");
      const mspHits = [...byAcct.keys()].filter((a) =>
        /msp\b|partner|softwareone|solutio|external/i.test(a)
      );

      // "N events" is not reviewable. Who, when, and whether it arrived in one
      // burst or as a steady trickle is what tells an operator whether to look.
      const byDay = new Map();
      let earliest = null;
      let latest = null;
      for (const r of events) {
        const ts = String(r.Timestamp || "");
        const day = ts.slice(0, 10);
        if (day) byDay.set(day, (byDay.get(day) || 0) + 1);
        if (ts && (!earliest || ts < earliest)) earliest = ts;
        if (ts && (!latest || ts > latest)) latest = ts;
      }
      const busiestDays = [...byDay.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
      const spread = byDay.size;
      const peak = busiestDays[0]?.[1] || 0;
      // A change window looks like one or two dense days; abuse looks like a
      // steady low-rate trickle, or a single account doing everything.
      const bursty = peak >= events.length * 0.5;
      const attributed = [...byAcct.entries()]
        .filter(([a]) => a !== "(empty / system)")
        .sort((a, b) => b[1] - a[1]);
      const systemCount = byAcct.get("(empty / system)") || 0;

      const evidence = [];
      evidence.push(
        `${events.length} events over ${spread} distinct day(s), ${earliest ? earliest.slice(0, 10) : "?"} → ${latest ? latest.slice(0, 10) : "?"}`
      );
      evidence.push(
        bursty
          ? `Concentrated: ${peak} of ${events.length} on a single day — consistent with a bulk change or migration`
          : `Spread out: busiest day is only ${peak} events — a steady trickle rather than one operation`
      );
      for (const [day, n] of busiestDays) evidence.push(`${day} — ${n} events`);
      for (const [acct, n] of attributed.slice(0, 6)) {
        evidence.push(
          `${acct} — ${n} events${/msp\b|partner|softwareone|solutio|external/i.test(acct) ? " (external/MSP admin)" : ""}`
        );
      }
      if (systemCount) {
        evidence.push(
          `${systemCount} events with no account attributed — Microsoft backend automation, normally benign but unverifiable from this table`
        );
      }

      pushNarrative(narratives, {
        id: "NARR.Mail.SetMailboxBurst",
        severity: events.length >= 100 ? "Medium" : "Low",
        priority: "Next",
        title: `${events.length} Set-Mailbox operations across ${spread} day(s)`,
        narrative:
          `Set-Mailbox is the cmdlet behind forwarding addresses, delegate permissions and mailbox-level audit settings, so a run of them is where mailbox-based persistence hides. ` +
          `${events.length} events were recorded${earliest ? ` between ${earliest.slice(0, 10)} and ${latest.slice(0, 10)}` : ""}, ` +
          (bursty
            ? "concentrated into a single day — that shape usually means a planned bulk change or a migration, which is easy to confirm against the change record and then dismiss. "
            : "spread fairly evenly across the window rather than concentrated — that shape is less likely to be a one-off migration and more likely to be routine automation, or something recurring that nobody owns. ") +
          (attributed.length
            ? `${attributed.length} distinct account(s) are attributed${mspHits.length ? `, including external/MSP admin identities` : ""}. `
            : "") +
          (systemCount
            ? `${systemCount} events carry no account, which is normal for Microsoft backend automation but means CloudAppEvents alone cannot tell you what was changed. `
            : "") +
          "This table records that the cmdlet ran, not which parameter it set — the Exchange admin audit log is what distinguishes an audit-setting update from a forwarding rule being added.",
        evidence: evidence.join(" | "),
        remediation:
          "Pull the matching Set-Mailbox entries from the Exchange admin audit log (Purview → Audit, or Search-UnifiedAuditLog) for the busiest days listed above and read the Parameters field — that is the only place the actual change is recorded. Anything that set ForwardingSmtpAddress, DeliverToMailboxAndForward or a mailbox delegate deserves individual confirmation. Challenge the externally-attributed operations against the provider's change record, and add an alert on Set-Mailbox executed outside declared change windows, since that is the condition that separates routine administration from persistence.",
        relatedFiles: [
          "25_HighValue_CloudAppEvents_90d.csv",
          "25_HighValue_CloudAppEvents_30d.csv",
          "18_Mailbox_Forwarding_Manual_Checks.csv",
        ],
      });
    }
  }

  // ── NARR.Mail.ConsumerOutbound — gmail/yahoo/etc outbound volume ─
  {
    const CONSUMER =
      /^(gmail|googlemail|yahoo|hotmail|outlook|live|icloud|me\.com|proton\.me|protonmail|mail\.ru|yandex|aol)\./i;
    const rows = (ctx.outboundMail || []).filter((r) =>
      CONSUMER.test(String(r.DestDomain || r.Domain || ""))
    );
    const total = rows.reduce(
      (s, r) => s + Number(r.OutboundCount || r.Count || 0),
      0
    );
    if (total >= 200 || rows.some((r) => Number(r.OutboundCount || 0) >= 100)) {
      // Message counts alone cannot separate a mailing list from an exfil path.
      // Where the collection captured size and attachment counts, rank by the
      // two signals that actually differ: bytes leaving, and how much of it
      // travelled as attachments.
      const senders = (ctx.consumerOutbound || [])
        .map((r) => ({
          sender: r.Sender || "",
          messages: Number(r.Messages || 0),
          attach: Number(r.WithAttachments || 0),
          mb: Number(r.TotalMB || 0),
          maxMb: Number(r.MaxMB || 0),
          domains: String(r.Domains || ""),
        }))
        .sort((a, b) => b.mb - a.mb || b.attach - a.attach);
      const totalMb = senders.reduce((s, r) => s + r.mb, 0);
      const totalAttach = senders.reduce((s, r) => s + r.attach, 0);
      const heavy = senders.filter((r) => r.attach >= 10 || r.mb >= 50);

      const evidence = [];
      if (senders.length) {
        evidence.push(
          `${senders.length} internal sender(s), ${totalMb} MB total, ${totalAttach} message(s) carrying attachments`
        );
        for (const s of senders.slice(0, 8)) {
          evidence.push(
            `${s.sender} — ${s.messages} msg, ${s.attach} with attachments, ${s.mb} MB total (largest ${s.maxMb} MB) → ${s.domains}`
          );
        }
      }
      for (const r of rows.slice(0, 6)) {
        const mb = Number(r.TotalMB || 0);
        const att = Number(r.WithAttachments || 0);
        evidence.push(
          `${r.DestDomain || r.Domain} — ${r.OutboundCount || r.Count || "?"} messages` +
            (mb ? `, ${mb} MB` : "") +
            (att ? `, ${att} with attachments` : "") +
            (r.Senders ? `, ${r.Senders} sender(s)` : "")
        );
      }

      pushNarrative(narratives, {
        id: "NARR.Mail.ConsumerOutbound",
        severity: heavy.length || total >= 1000 ? "Medium" : "Low",
        priority: "Next",
        title: "Outbound mail to consumer domains, ranked by data volume",
        narrative:
          `${total} outbound message(s) reached consumer mail domains (gmail, yahoo, hotmail and similar) in the last 30 days` +
          (senders.length
            ? `, carrying ${totalMb} MB in total, of which ${totalAttach} message(s) had attachments. Volume is what matters here, not the message count: a long thread of one-line replies and a handful of messages carrying a document set produce similar counts but very different exposure, so the list below is ordered by bytes sent rather than by frequency. `
            : ". Message size and attachment counts were not captured in this run, so the ranking below is by message count only — re-run the collection to pick up the volume and attachment breakdown, which is what distinguishes normal correspondence from a transfer. ") +
          (heavy.length
            ? `${heavy.length} sender(s) stand out on volume or attachment count and are worth confirming individually. `
            : "") +
          "Most of this is usually legitimate — personal addresses of counterparties, contractors working from a consumer account — so treat it as a list to explain rather than a list to block, with the exception of any sender whose own personal address appears as a recipient, which is the classic pre-departure pattern.",
        evidence: evidence.join(" | "),
        remediation:
          "Start with the top senders by volume and confirm the business reason; the shape to look for is an employee mailing documents to an address that resembles their own name. Where the traffic is legitimate B2C correspondence, leave it and instead put a DLP policy on the content: alert (not block) on sensitive-information types leaving to consumer domains, which catches the exfiltration case without breaking the business one. Confirm auto-forwarding to external domains is off in the outbound anti-spam policy, since an automatic rule producing this traffic is a different and more serious finding than a person sending mail." +
          (senders.length
            ? ""
            : " The per-sender volume breakdown appears in 18_Consumer_Outbound_BySender_30d.csv once the collection has been re-run."),
        relatedFiles: [
          "18_Outbound_Email_Domains_30d.csv",
          "18_Consumer_Outbound_BySender_30d.csv",
          "18_Mailbox_Forwarding_Manual_Checks.csv",
        ],
      });
    }
  }

  // ── NARR.SecureScore.Roadmap — in-scope Secure Score only ─
  //
  // Prefer 10_SecureScore_ByCategory.csv (controls that count toward the live
  // tenant score). The full profile catalog overstates gaps for products that
  // are not in enabledServices (e.g. hundreds of MDE points at 0).
  {
    const { buildSecureScoreExplorer } = require("./securescore");
    const explorer = buildSecureScoreExplorer(ctx.secureScoreControls || []);
    const gaps = explorer.openControls;
    const rollup =
      (ctx.secureScoreRollup || []).length
        ? ctx.secureScoreRollup
        : explorer.categories;
    const tenantCur = Number(ctx.summary?.secureScoreCurrent);
    const tenantMax = Number(ctx.summary?.secureScoreMax);

    if (gaps.length >= 3 || (explorer.controlCount > 0 && rollup.length)) {
      const total =
        Number.isFinite(tenantMax) && Number.isFinite(tenantCur)
          ? Math.round((tenantMax - tenantCur) * 10) / 10
          : explorer.openPoints;
      const catBits = rollup
        .filter((r) => Number(r.Gap || r.gap || 0) > 0.05)
        .slice(0, 6)
        .map(
          (r) =>
            `${r.Category || r.category}: ${r.Score ?? r.score}/${r.Max ?? r.max} (gap ${r.Gap ?? r.gap})`
        );
      pushNarrative(narratives, {
        id: "NARR.SecureScore.Roadmap",
        severity: "Info",
        priority: "Later",
        title: `Secure Score roadmap: ${total} points open across ${gaps.length || explorer.openCount} controls`,
        narrative:
          `Microsoft Secure Score for this tenant is ${Number.isFinite(tenantCur) ? tenantCur : "?"} / ${Number.isFinite(tenantMax) ? tenantMax : "?"} based on ${explorer.controlCount} in-scope controls` +
          (catBits.length ? ` — by category: ${catBits.join("; ")}.` : ".") +
          " Only controls that count toward the live score are used (not the full secureScoreControlProfiles catalog, which includes products this tenant is not scored on). " +
          "Treat Secure Score as a feature-adoption backlog ordered by recoverable points — it complements the attack-path findings above, it does not replace them.",
        evidence: gaps
          .slice(0, 12)
          .map(
            (r) =>
              `+${r.GapPoints} pts [${r.Category}] ${r.Title}${r.UserImpact ? ` (impact: ${r.UserImpact})` : ""}`
          )
          .join(" | "),
        remediation:
          "In the report Secure Score section, filter by category (Identity / Apps / Data) and work the highest Gap points first. Prefer Identity gaps that overlap expert findings (MFA, user/sign-in risk CA, legacy auth). Full list: 10_SecureScore_ByCategory.csv.",
        relatedFiles: [
          "10_SecureScore_ByCategory.csv",
          "10_SecureScore_Category_Rollup.csv",
          "10_SecureScore_Top15_HighValue.csv",
          "10_IdentitySecureScore_Controls.csv",
        ],
        relatedChecks: [],
      });
    }
  }

  // ── Adaptive intel narratives (alerts / exposure / IdentityLogon) ─
  //
  // These fire whether or not MDE Device* tables existed. On tenants without
  // MDE they are often the only hunting-backed activity findings.
  {
    const alerts = ctx.securityAlerts || [];
    const clustered = clusterAlertsBySource(alerts);
    const hot = alerts.filter((r) => /high|critical/i.test(r.Severity || ""));
    if (hot.length) {
      const identityOrEndpoint = clustered.endpointHigh + clustered.identityHigh;
      const irmOnly = clustered.irmHigh === clustered.high && identityOrEndpoint === 0;
      const mdcaOnly =
        clustered.mdcaHigh > 0 &&
        identityOrEndpoint === 0 &&
        clustered.high === clustered.mdcaHigh + clustered.irmHigh;
      const titleLine = irmOnly
        ? `${clustered.irmHigh} High Purview IRM alert(s) (not endpoint compromise)`
        : mdcaOnly
          ? `${clustered.mdcaHigh} High Defender for Cloud Apps alert(s) (no endpoint/identity High)`
          : identityOrEndpoint && clustered.mdcaHigh >= 5
            ? `${identityOrEndpoint} Defender for Endpoint/Identity High alert(s) (+ ${clustered.mdcaHigh} Cloud Apps High)`
            : `${hot.length} High/Critical Defender alert(s) in the last 30 days`;
      pushNarrative(narratives, {
        id: "NARR.Alert.HighSeverity",
        severity: identityOrEndpoint
          ? "High"
          : irmOnly
            ? "Info"
            : "Medium",
        priority: identityOrEndpoint ? "Now" : "Later",
        title: titleLine,
        narrative:
          `Defender XDR raised ${hot.length} High/Critical alert group(s) (of ${alerts.length} total) in the last 30 days` +
          (clustered.mdcaHigh
            ? `, including ${clustered.mdcaHigh} from Defender for Cloud Apps`
            : "") +
          (clustered.irmHigh
            ? `, ${clustered.irmHigh} Purview Insider Risk / Adaptive Protection`
            : "") +
          (identityOrEndpoint
            ? ` and ${identityOrEndpoint} from Defender for Endpoint / Identity.`
            : ".") +
          (irmOnly
            ? " IRM data-leak policies fire on DLP matches, not on malware or identity takeover — triage in Purview, not as an incident queue."
            : mdcaOnly
              ? " Cloud Apps Highs are often mass-download / sharing detections, not endpoint compromise — collapse them by title before treating the count as an incident queue."
              : " These are detections the platform already believes matter — treat endpoint/identity Highs as demonstrated activity.") +
          (ctx.summary?.adaptiveIntel &&
          ctx.summary.adaptiveIntel.mdeEndpoint === false
            ? " This tenant has little or no MDE device hunting data, so alert + identity signals carry more of the assessment weight than endpoint process/network hunts."
            : ""),
        evidence: (clustered.titles.length ? clustered.titles : hot)
          .slice(0, 10)
          .map((r) =>
            r.title
              ? `${r.n}× ${r.title} · ${r.source || ""} · last ${r.last || "?"}`
              : `[${r.Severity}] ${r.Title || "?"} — ${r.Count || 1}× · ${r.ServiceSource || r.DetectionSource || ""} · last ${r.LastSeen || "?"}`
          )
          .join(" | "),
        remediation:
          "Triage each High/Critical alert in security.microsoft.com → Incidents & alerts. Confirm status is not left at New; for identity-sourced alerts, revoke sessions and reset credentials on the implicated accounts; for malware/endpoint alerts, isolate the device.",
        relatedFiles: [
          "36_Security_Alerts_30d.csv",
          "36_Security_Alert_Evidence_30d.csv",
        ],
      });
    }
  }

  {
    const assets = ctx.exposureAssets || [];
    // Exposure Manager encodes criticality as 0=Very High … 3=Low (or labels).
    const critical = assets.filter((r) => {
      const n = Number(r.CriticalityLevel);
      if (Number.isFinite(n)) return n <= 1;
      return /critical|very high|^high$/i.test(
        `${r.CriticalityLevel || ""} ${r.CriticalityLabel || ""}`
      );
    });
    const internet = assets.filter((r) =>
      /true|1|yes/i.test(String(r.IsInternetFacing || ""))
    );
    if (assets.length >= 5) {
      pushNarrative(narratives, {
        id: "NARR.Exposure.CriticalAssets",
        severity: critical.length || internet.length >= 5 ? "Medium" : "Info",
        priority: "Next",
        title: `Exposure Graph: ${assets.length} high-risk / critical / internet-facing asset(s)`,
        narrative:
          `Microsoft Exposure Management lists ${assets.length} asset(s) with elevated criticality, sensitive data, or internet-facing exposure` +
          (critical.length ? ` (${critical.length} Very High/High)` : "") +
          (internet.length ? `, ${internet.length} internet-facing` : "") +
          ". This is the attack-path view of the tenant when Defender for Endpoint device tables are thin or absent — it still tells you which identities, apps and resources Microsoft considers valuable and reachable.",
        evidence: assets
          .slice(0, 10)
          .map(
            (r) =>
              `${r.NodeName || r.NodeId || "?"} [${r.NodeLabel || r.Categories || "?"}] crit=${r.CriticalityLabel || r.CriticalityLevel || "?"} internet=${r.IsInternetFacing || "n/a"}`
          )
          .join(" | "),
        remediation:
          "Open Exposure management in security.microsoft.com and work the Critical assets first: reduce internet exposure, remove standing admin paths, and confirm those nodes are covered by CA / MFA / device compliance. Use 37_Exposure_Critical_Paths.csv for neighbour relationships and 37_Exposure_Edge_Types.csv for edge-type frequency.",
        relatedFiles: [
          "37_Exposure_Critical_Assets.csv",
          "37_Exposure_Critical_Paths.csv",
          "37_Exposure_Edge_Types.csv",
        ],
      });
    }
  }

  {
    const paths = ctx.exposurePaths || [];
    if (paths.length >= 10) {
      const byCrit = new Map();
      for (const p of paths) {
        const name = p.CritName || p.SourceNodeName || "?";
        byCrit.set(name, (byCrit.get(name) || 0) + 1);
      }
      const top = [...byCrit.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8);
      pushNarrative(narratives, {
        id: "NARR.Exposure.Paths",
        severity: "Medium",
        priority: "Next",
        title: `Exposure Graph: ${paths.length} edge(s) touching critical assets`,
        narrative:
          `Beyond listing critical nodes, the Exposure Graph shows ${paths.length} relationship edge(s) connecting Very High/High assets to neighbours (groups, apps, other identities). ` +
          "These edges are the practical attack-path view when MDE device tables are missing — they answer which objects sit next to the accounts and apps already flagged as critical.",
        evidence: top
          .map(([n, c]) => `${n} (${c} edges)`)
          .join(" | ") +
          " · sample: " +
          paths
            .slice(0, 8)
            .map(
              (p) =>
                `${p.CritName || p.SourceNodeName || "?"} -[${p.EdgeLabel || "?"}/${p.Direction || ""}]-> ${p.NeighborName || p.TargetNodeName || "?"}`
            )
            .join(" · "),
        remediation:
          "For each critical identity with many edges: confirm group membership is still required, remove standing admin group links, and treat neighbouring service principals as credential-theft targets. Walk the same paths in security.microsoft.com → Exposure management.",
        relatedFiles: [
          "37_Exposure_Critical_Paths.csv",
          "37_Exposure_Critical_Assets.csv",
        ],
      });
    }
  }

  {
    const rows = ctx.identityInfoCritical || [];
    const { withRoles, atRisk, taggedCritical } = identityInfoActionable(rows);
    if (atRisk.length || withRoles.length >= 5 || taggedCritical.length >= 10) {
      pushNarrative(narratives, {
        id: "NARR.Identity.DefenderCritical",
        severity: atRisk.some((r) => /^(high|atRisk|confirmedcompromised)$/i.test(String(r.RiskLevel || "")))
          ? "High"
          : "Medium",
        priority: "Next",
        title: atRisk.length
          ? `Defender IdentityInfo: ${atRisk.length} identity(ies) with High/Medium risk`
          : `Defender IdentityInfo: ${withRoles.length} role-bearing identities`,
        narrative:
          `Advanced Hunting IdentityInfo lists ${withRoles.length} identities with directory / PIM roles` +
          (atRisk.length ? `, ${atRisk.length} with High/Medium RiskLevel` : "") +
          (taggedCritical.length ? `, ${taggedCritical.length} tagged criticality ≥ 3` : "") +
          ". RiskLevel None / empty and a raw take() dump are ignored — those are not at-risk admins.",
        evidence: [...atRisk, ...withRoles]
          .slice(0, 12)
          .map(
            (r) =>
              `${r.AccountUpn || r.AccountDisplayName || "?"} crit=${r.CriticalityLevel ?? "?"} risk=${r.RiskLevel || "n/a"} roles=${(r.AssignedRoles || r.PrivilegedEntraPimRoles || "").toString().slice(0, 80)}`
          )
          .join(" | "),
        remediation:
          "Cross-check against 03_PrivilegedAccounts_HighValue and 24_RiskyUsers. For each IdentityInfo risk hit on an admin: revoke sessions, reset credentials, and confirm user-risk CA. Use BlastRadius / Tags in the portal to prioritise which identities to harden first.",
        relatedFiles: [
          "38_IdentityInfo_Critical.csv",
          "38_IdentityAccountInfo_Privileged.csv",
          "03_PrivilegedAccounts_HighValue.csv",
          "24_RiskyUsers.csv",
        ],
      });
    }
  }

  {
    const digest = ctx.spnSignInDigest || [];
    const hotAll = digest.filter(
      (r) => /yes/i.test(String(r.HighPrivSpn || "")) && Number(r.Events) > 0
    );
    const hot = hotAll.filter(
      (r) => !isMicrosoftFirstPartyApp(r.App || r.ServicePrincipalId)
    );
    const msSkipped = hotAll.length - hot.length;
    if (hot.length) {
      const roleMgmtLive = hot.some((r) =>
        /rolemanagement|avepoint|approleassignment/i.test(
          `${r.App || ""} ${r.Permissions || ""}`
        )
      );
      const spread = hot.filter((r) => Number(r.DistinctIps || 0) >= 5);
      const planeNames = new Set(appPlane.pathToGa.map((a) => a.name.toLowerCase()));
      const extra = hot.filter((r) => {
        const n = String(r.App || r.ServicePrincipalId || "").toLowerCase();
        return ![...planeNames].some(
          (p) => n === p || (p && n.startsWith(p)) || (n && p.startsWith(n))
        );
      });
      const alreadyCovered = extra.length === 0 && appPlane.pathToGa.length > 0;
      pushNarrative(narratives, {
        id: "NARR.App.DangerousSpnActivity",
        severity: alreadyCovered
          ? "Info"
          : roleMgmtLive || spread.length
            ? "High"
            : "Medium",
        priority: alreadyCovered
          ? "Later"
          : roleMgmtLive || spread.length
            ? "Now"
            : "Next",
        title: alreadyCovered
          ? `${hot.length} high-privilege app(s) actively signing in (same control-plane apps)`
          : `${hot.length} high-privilege third-party app(s) actively signing in`,
        narrative:
          `${hot.length} third-party service principal(s) that hold Critical/High Graph permissions produced sign-ins in the collection window` +
          (msSkipped
            ? ` (${msSkipped} Microsoft first-party high-priv apps omitted).`
            : ".") +
          (spread.length
            ? ` ${spread.length} authenticate from 5+ IPs — prioritize those (credential theft would look the same).`
            : " Permission inventory alone is theoretical; active token use means those credentials are in play.") +
          " Cross-check with PathToGA / RoleManagement narratives rather than treating every backup/SOC sign-in as a separate Critical.",
        evidence: hot
          .slice(0, 10)
          .map(
            (r) =>
              `${r.App || r.ServicePrincipalId} — ${r.Events} events · ips=${r.DistinctIps || "?"} · last ${r.LastSeen || "?"}`
          )
          .join(" | "),
        remediation:
          "For each active high-priv SP: confirm the workload still needs the write/role-management grants, rotate credentials, pin egress with workload-identity CA, and alert on RoleManagement / AppRoleAssignment audit events from these app IDs.",
        relatedFiles: [
          "27_SPN_SignIns_Digest_90d.csv",
          "27_SPN_SignIns_90d.csv",
          "40_Apps_Path_To_GA.csv",
        ],
        relatedChecks: ["AP.App.PathToGA"],
      });
    }
  }

  {
    const rows = ctx.privilegedSignIns || [];
    if (rows.length >= 5) {
      const byUser = new Map();
      for (const r of rows) {
        const u = String(r.UPN || "").toLowerCase();
        if (!u) continue;
        if (!byUser.has(u)) byUser.set(u, { n: 0, ips: new Set(), apps: new Set() });
        const x = byUser.get(u);
        x.n++;
        if (r.Ip) x.ips.add(r.Ip);
        if (r.App) x.apps.add(r.App);
      }
      const top = [...byUser.entries()]
        .map(([u, x]) => ({ u, ...x }))
        .sort((a, b) => b.n - a.n)
        .slice(0, 8);
      pushNarrative(narratives, {
        id: "NARR.Identity.PrivilegedGraphSignIns",
        severity: "Info",
        priority: "Later",
        title: `${byUser.size} privileged account(s) with Graph sign-ins in 30d`,
        narrative:
          `Graph sign-in logs show ${rows.length} successful event(s) across ${byUser.size} privileged UPN(s) in 30 days. ` +
          "Useful when IdentityLogonEvents is empty: this is the Entra-side activity baseline for standing admins (IPs, apps, CA status).",
        evidence: top
          .map(
            (t) =>
              `${t.u} — ${t.n} events · ${t.ips.size} ips · apps=${[...t.apps].slice(0, 4).join(", ")}`
          )
          .join(" | "),
        remediation:
          "Compare IPs/apps against expected admin behaviour and PIM activations. Unexpected geography or legacy clients on GA accounts → revoke sessions and investigate.",
        relatedFiles: [
          "28_Privileged_SignIns_30d.csv",
          "03_PrivilegedAccounts_HighValue.csv",
        ],
      });
    }
  }

  {
    const rows = (ctx.failedLogons || []).filter((r) =>
      String(r.AccountUpn || r.AccountDisplayName || "").trim()
    );
    const heavy = rows
      .map((r) => ({ ...r, n: Number(r.Failures || 0) }))
      .filter((r) => r.n >= 50)
      .sort((a, b) => b.n - a.n);
    if (heavy.length || rows.length >= 20) {
      pushNarrative(narratives, {
        id: "NARR.Identity.FailedLogonBurst",
        severity:
          heavy.length >= 10 &&
          !heavy
            .slice(0, 8)
            .every((r) =>
              /info@|sales@|shared|mailbox|operator|noreply/i.test(
                String(r.AccountUpn || "")
              )
            )
            ? "High"
            : heavy.length
              ? "Medium"
              : "Low",
        priority: "Next",
        title: heavy.length
          ? `${heavy.length} account(s) with ≥50 failed logons in 30d`
          : `${rows.length} failed-logon rows in IdentityLogonEvents`,
        narrative:
          `IdentityLogonEvents shows ${rows.length} account/application failure row(s) in 30 days` +
          (heavy.length
            ? `, including ${heavy.length} with 50+ failures. ` +
              "These bursts often come from company office / site egress IPs (shared PCs, kiosks, saved Outlook passwords on plant or warehouse broadband) rather than an external spray — confirm the SampleIps against known bureau ranges before assuming compromise."
            : ".") +
          " This path works even when AADSignInEventsBeta is missing from hunting, which is common on tenants without full Defender identity streaming.",
        evidence: (heavy.length ? heavy : rows)
          .slice(0, 10)
          .map(
            (r) =>
              `${r.AccountUpn || "?"} — ${r.Failures || r.n || "?"} failures · ${r.Application || "?"} · ips=${r.DistinctIps || r.SampleIps || "?"}`
          )
          .join(" | "),
        remediation:
          "1) Ask IT which SampleIps are office / plant / warehouse egress and allow-list that context in the investigation. 2) On those sites, fix or remove saved passwords on shared PCs and rotate the shared mailbox passwords that keep retrying. 3) For accounts that are real users (not shared/service), reset password, revoke sessions, and check risky sign-ins. 4) Alert on ≥50 failures/hour per IP so a real external spray stays visible next to this office noise.",
        relatedFiles: [
          "38_Identity_Failed_Logons_30d.csv",
          "38_Identity_Logons_ByApp_30d.csv",
          "24_RiskyUsers.csv",
        ],
      });
    }
  }

  // Graph sign-in failure clusters (works when IdentityLogonEvents is empty).
  {
    const rows = aggregateFailuresByIp(ctx.failedSignInsByIp || [])
      .map((r) => ({ ...r, n: Number(r.Failures || 0) }))
      .filter((r) => r.n > 0)
      .sort((a, b) => b.n - a.n);
    const hot = rows.filter((r) => r.n >= 50);
    if (hot.length || rows.length >= 30) {
      const totalFails = rows.reduce((n, r) => n + r.n, 0);
      const sampleUsers = hot
        .flatMap((r) => String(r.SampleUsers || "").split(/\s*\|\s*/))
        .filter(Boolean)
        .slice(0, 8);
      // Heuristic: many distinct users per IP + IE/corporate-looking → shared-site noise;
      // few users / many fails → spray or stuck client on one mailbox.
      const multiUserHot = hot.filter((r) => Number(r.Users || 0) >= 5).length;
      const singleAccountHot = hot.filter((r) => Number(r.Users || 0) <= 2).length;
      const likelySharedSites = multiUserHot >= Math.ceil(hot.length / 2);
      const likelyStuckClients =
        singleAccountHot >= Math.ceil(hot.length / 2) ||
        (hot[0] && Number(hot[0].Users || 0) <= 2 && hot[0].n >= 500);
      const severity =
        likelySharedSites || likelyStuckClients
          ? "Medium"
          : hot.length >= 5
            ? "High"
            : "Medium";
      pushNarrative(narratives, {
        id: "NARR.Auth.FailedSignInSpray",
        severity,
        priority: "Next",
        title: hot.length
          ? `${hot.length} IP(s) with ≥50 failed sign-ins (${totalFails} failures sampled)`
          : `${rows.length} IPs with failed sign-ins in the window`,
        narrative: likelyStuckClients
          ? `Top failure sources concentrate on one or two accounts per IP (e.g. a shared mailbox with a stale saved password), not a classic spray across the directory. ` +
            `${hot.length} IP(s) exceeded 50 failures (${totalFails} sampled). Fix the stuck clients / rotate those mailbox passwords, and keep lockout + failure alerting so a real spray is still visible next to this noise.`
          : likelySharedSites
          ? `This is mostly failed password attempts (Entra error 50126 = wrong username/password), not successful breaches and not MFA prompts being ignored. ` +
            `${hot.length} public IP(s) each generated 50+ failures in the sampled window, and most of those IPs hit many different accounts (often shared / site / reception mailboxes). ` +
            `That pattern usually means shared site PCs: a saved password went stale, Outlook/Teams keeps retrying, and every shared mailbox on that broadband line burns failures. ` +
            `Treat it as credential hygiene + monitoring debt until the hottest IPs are confirmed as known office/site egress — not proof that an attacker is inside.`
          : `Entra logged ${totalFails} failed sign-ins across ${rows.length} source IP(s)` +
            (hot.length
              ? `, with ${hot.length} IP(s) above 50 failures.`
              : ".") +
            ` Dominant error 50126 means the password (or UPN) is wrong — someone or something is retrying credentials. ` +
            `That can be an external password spray, a single shared mailbox with a bad saved password, or a misconfigured device. Check whether the top IPs are known site egress before assuming compromise.`,
        evidence: (hot.length ? hot : rows)
          .slice(0, 8)
          .map(
            (r) =>
              `${r.IP} (${r.Country || "?"}): ${r.Failures} failures against ${r.Users || "?"} account(s), error ${r.ErrorCode || "?"} — e.g. ${String(r.SampleUsers || "").split(/\s*\|\s*/).slice(0, 4).join(", ")}`
          )
          .join(" | "),
        remediation:
          "1) Ask IT which of the top IPs are known office / plant / warehouse / site egress. 2) On those sites, fix or remove saved passwords on shared PCs and rotate the shared mailbox passwords. 3) Turn on custom banned-password check + keep smart lockout. 4) Alert on ≥50 failures/hour per IP so a real spray is visible next to this noise. 5) Prefer unique passwords or passwordless for any account that still needs interactive sign-in.",
        relatedFiles: [
          "22_FailedSignIns_ByIP_90d.csv",
          "22_FailedSignIns_ByIP_30d.csv",
          "12_DirectorySettings_Password.csv",
        ],
      });
    }
  }

  // Non-MFA successes: Copilot agents and rooms are not password-only humans.
  {
    const rows = ctx.singleFactor || [];
    const humans = rows.filter((r) => {
      const upn = r.UPN || r.AccountUpn || "";
      const kind = classifyAccountKind(upn, r.DisplayName);
      return kind === "human" && !isCopilotOrAgentUpn(upn);
    });
    if (humans.length >= 15) {
      const mfaCa = detectEnforcedMfaCoverage(ctx.caAudit);
      pushNarrative(narratives, {
        id: "NARR.Auth.SingleFactor",
        severity: mfaCa.covered ? "Low" : "Medium",
        priority: "Later",
        title: `${humans.length} human account(s) with successful non-MFA sign-ins`,
        narrative:
          `Hunting listed ${rows.length} account(s) with AuthenticationRequirement ≠ MFA; ${rows.length - humans.length} are rooms, Copilot/service agents, or shared mailboxes (SSO/PRT is often labelled single-factor). ` +
          `${humans.length} look like people.` +
          (mfaCa.covered
            ? " Enforced MFA CA is present — remaining singles are usually Windows sign-in / broker tokens, not a password-only path."
            : " No clear enforced MFA CA — treat interactive humans on this list as a spray surface."),
        evidence: humans
          .slice(0, 8)
          .map((r) => `${r.UPN || r.AccountUpn} (${r.SignIns} sign-ins)`)
          .join(" | "),
        remediation:
          "Do not run an MFA campaign on the raw 23_* count. Filter out SecurityCopilotAgentUser-* and room mailboxes first; then confirm the remaining humans are covered by MFA CA or register methods.",
        relatedFiles: [
          "23_SingleFactor_Success_90d.csv",
          "07_Users_Without_MFA.csv",
          "02_CA_Audit.csv",
        ],
      });
    }
  }

  // Device join / register MFA (deviceRegistrationPolicy).
  {
    const pol = ctx.deviceRegPolicy || {};
    const mfa = String(
      pol.multiFactorAuthConfiguration ||
        ctx.summary?.deviceJoinOrRegisterMfa ||
        ""
    );
    const regType =
      (pol.azureADRegistration &&
        pol.azureADRegistration.allowedToRegister &&
        pol.azureADRegistration.allowedToRegister["@odata.type"]) ||
      "";
    const joinType =
      (pol.azureADJoin &&
        pol.azureADJoin.allowedToJoin &&
        pol.azureADJoin.allowedToJoin["@odata.type"]) ||
      "";
    const registerAll = /allDeviceRegistrationMembership/i.test(regType);
    const joinAll = /allDeviceRegistrationMembership/i.test(joinType);
    const joinUsers =
      (pol.azureADJoin &&
        pol.azureADJoin.allowedToJoin &&
        pol.azureADJoin.allowedToJoin.users) ||
      [];
    const mfaOff = isDeviceRegMfaOff(mfa);
    const mfaRequired = isDeviceRegMfaRequired(mfa);
    const joinGroups =
      (pol.azureADJoin &&
        pol.azureADJoin.allowedToJoin &&
        pol.azureADJoin.allowedToJoin.groups) ||
      [];
    // Emit when MFA is off (finding), or when MFA is on but Register/Join is All
    // users (scope note). Skip pure pass: MFA required + join/register restricted.
    if (mfaOff || (mfaRequired && (registerAll || joinAll))) {
      pushNarrative(narratives, {
        id: "NARR.Devices.JoinRegisterMfa",
        severity: mfaOff ? "High" : "Info",
        priority: mfaOff ? "Now" : "Later",
        title: mfaOff
          ? "Users can join/register devices without MFA"
          : "Device join/register MFA is required (Register/Join still broad)",
        narrative: mfaOff
          ? `deviceRegistrationPolicy.multiFactorAuthConfiguration=${mfa || "notRequired"} — Entra will not challenge for MFA during Azure AD join / workplace join. Combined with Register=${registerAll ? "All users" : "restricted"} and Join=${joinAll ? "All users" : `selected (${joinUsers.length} user(s)/${joinGroups.length} group(s))`}, an attacker with a password can enrol a rogue device and satisfy device-based CA grants.`
          : `Device registration MFA is "${mfa}" — join/register is not a password-only path at this control. Remaining scope note: Register is ${registerAll ? "open to all users" : "restricted"}; Join is ${joinAll ? "open to all users" : `limited to ${joinUsers.length || "selected"} user(s)/${joinGroups.length} group(s)`}. This Entra device policy is separate from Conditional Access device-registration user actions.`,
        evidence: `MFA=${mfa || "?"}; Register=${registerAll ? "All users" : regType || "?"}; Join=${joinAll ? "All users" : `${joinType || "selected"} users=${joinUsers.length} groups=${joinGroups.length}`}; quota=${pol.userDeviceQuota ?? ctx.summary?.userDeviceQuota ?? "?"}`,
        remediation: mfaOff
          ? "Set deviceRegistrationPolicy.multiFactorAuthConfiguration to required; restrict who can join/register; consider a CA policy for device registration user action where licensed."
          : "Keep MFA required. Prefer restricting Register from All users if BYOD is not intended. Document who may Join.",
        relatedFiles: [
          "06_device_registration_policy.json",
          "09_Devices_Registered_Only.csv",
          "09_Devices_Per_User_Multi.csv",
        ],
      });
    }
  }

  // Password Protection blade (smart lockout + banned passwords).
  //
  // 12_DirectorySettings_Password.csv also contains Group.Unified / Consent
  // rows with empty password columns. Those still parse as "" (not null), so
  // a naive `.find(LockoutThreshold != null)` wrongly picks Group.Unified and
  // reports an empty custom list even when Password Rule Settings has hundreds
  // of entries. Prefer DisplayName, then any row with a real password value.
  {
    const rows = ctx.passwordSettings || [];
    const hasPwdValue = (r) =>
      String(r.LockoutThreshold || "").trim() !== "" ||
      String(r.EnableBannedPasswordCheck || "").trim() !== "" ||
      String(r.BannedPasswordList || "").trim() !== "";
    const row =
      rows.find((r) => /Password Rule/i.test(r.DisplayName || "")) ||
      rows.find(hasPwdValue);
    if (row) {
      const sum = ctx.summary || {};
      const lockout =
        String(row.LockoutThreshold || "").trim() ||
        sum.passwordLockoutThreshold ||
        "?";
      const duration =
        String(row.LockoutDurationInSeconds || "").trim() ||
        sum.passwordLockoutDurationSeconds ||
        "?";
      const enableBanned =
        String(row.EnableBannedPasswordCheck || "").trim() ||
        sum.passwordBannedCheck;
      const bannedOff = /false|0/i.test(String(enableBanned ?? ""));
      const listRaw = String(row.BannedPasswordList || "").trim();
      const listCount =
        sum.customBannedPasswordCount != null
          ? Number(sum.customBannedPasswordCount)
          : listRaw
            ? listRaw.split(/\t|\n|;|,/).map((s) => s.trim()).filter(Boolean)
                .length
            : 0;
      const listEmpty =
        sum.customBannedPasswordListConfigured === true
          ? false
          : listCount === 0;
      const onPremEnabled =
        String(row.EnableBannedPasswordCheckOnPremises || "").trim() ||
        sum.passwordBannedOnPremEnabled ||
        "?";
      const onPremMode =
        String(row.BannedPasswordCheckOnPremisesMode || "").trim() ||
        sum.passwordBannedOnPremMode ||
        "?";
      const onPremAudit = /audit/i.test(String(onPremMode));
      const severity =
        bannedOff || (listEmpty && !bannedOff) ? "Medium" : "Info";
      let remediation;
      if (bannedOff) {
        remediation =
          "Turn on custom banned password check; add org brand terms, site names, and seasonal words. Move on-prem mode from Audit to Enforced once the DC agent is healthy. Keep lockout threshold around 10 / 1200s unless you have a spray problem — then tighten and alert.";
      } else if (listEmpty) {
        remediation =
          "Custom check is ON but the list is empty — add org brand terms, site names, and seasonal words or the control does nothing beyond Microsoft's global list. Move on-prem mode from Audit to Enforced once the DC agent is healthy.";
      } else {
        remediation =
          `Custom banned list is populated (${listCount} entries) — keep brand/product terms and seasons current. ` +
          (onPremAudit
            ? "Move on-prem mode from Audit to Enforced once the DC agent is healthy. "
            : "") +
          "Review smart lockout threshold/duration against spray risk and alert on lockout bursts.";
      }
      pushNarrative(narratives, {
        id: "NARR.Password.Protection",
        severity,
        priority: severity === "Medium" ? "Next" : "Later",
        title: bannedOff
          ? "Custom banned-password check disabled (Password Protection)"
          : listEmpty
            ? "Custom banned-password list empty (Password Protection)"
            : "Password Protection / smart lockout settings",
        narrative:
          `Entra Password Protection (Password Rule Settings) reports smart lockout threshold=${lockout} lasting ${duration}s. ` +
          (bannedOff
            ? "Custom banned password check for cloud is OFF — users can pick org-specific weak passwords (season+year, company name) that the global Microsoft list will not catch. "
            : "Custom banned password check for cloud is ON. ") +
          (!bannedOff && listEmpty
            ? "The custom list is empty — enable alone does nothing without entries. "
            : !bannedOff
              ? `Custom list has ${listCount} entr${listCount === 1 ? "y" : "ies"}. `
              : "") +
          `On-premises password protection is ${onPremEnabled} in mode ${onPremMode} ` +
          (onPremAudit
            ? "(Audit only — DC agent logs but does not block bad passwords on AD DS)."
            : "."),
        evidence: Object.entries({
          LockoutThreshold: lockout,
          LockoutDurationInSeconds: duration,
          EnableBannedPasswordCheck: enableBanned,
          EnableBannedPasswordCheckOnPremises: onPremEnabled,
          BannedPasswordCheckOnPremisesMode: onPremMode,
          CustomListConfigured: listEmpty ? "no" : "yes",
          CustomListEntries: listCount,
        })
          .map(([k, v]) => `${k}=${v}`)
          .join(" · "),
        remediation,
        relatedFiles: ["12_DirectorySettings_Password.csv", "12_Domains.csv"],
      });
    }
  }

  // MFA registration campaign.
  {
    const camp = (ctx.mfaCampaign || [])[0];
    const state =
      (camp && camp.State) || ctx.summary?.mfaRegistrationCampaignState || "";
    if (state) {
      const noMfa = (ctx.noMfa || []).length;
      pushNarrative(narratives, {
        id: "NARR.MFA.RegistrationCampaign",
        // Context for MassGap — not a standalone Medium finding.
        severity: "Info",
        priority: "Later",
        title: `MFA registration campaign is "${state}"`,
        narrative:
          `The Authenticator registration campaign (Authentication methods → Registration campaign) is state=${state}` +
          (camp?.SnoozeDays != null ? `, snoozeDays=${camp.SnoozeDays}` : "") +
          `. With ${noMfa || ctx.summary?.usersWithoutMfa || "?"} users still lacking MFA, ` +
          (state === "enabled"
            ? "the nudge is active — verify it targets the unlicensed/gap population and is not snoozed into irrelevance."
            : `"${state}" means Microsoft’s default/limited prompting only; it will not close a large MFA gap by itself. Pair with an enforced MFA CA (or registration campaign set to enabled) rather than relying on the portal nudge.`),
        evidence: camp
          ? `State=${camp.State}; SnoozeDays=${camp.SnoozeDays}; Include=${camp.IncludeTargets || "?"}; Exclude=${camp.ExcludeTargets || ""}`
          : `state=${state}`,
        remediation:
          'Set registration campaign to enabled for all_users (or the licensed group), keep snooze short, and enforce MFA CA so users who dismiss the nudge still cannot sign in password-only.',
        relatedFiles: [
          "01_MFA_Registration_Campaign.csv",
          "01_auth_methods_policy.json",
          "07_Users_Without_MFA.csv",
        ],
      });
    }
  }

  {
    const rows = ctx.privilegedLogons || [];
    if (rows.length) {
      pushNarrative(narratives, {
        id: "NARR.Identity.PrivilegedActivity",
        severity: "Info",
        priority: "Later",
        title: `${rows.length} privileged account(s) seen authenticating in IdentityLogonEvents`,
        narrative:
          `${rows.length} of the high-value privileged accounts from the role inventory produced IdentityLogonEvents in the last 30 days. ` +
          "Use this as the activity baseline for those admins: dormant privileged accounts that appear here unexpectedly, or privileged accounts authenticating from many IPs, deserve a closer look against 27_SPN_SignIns and Entra sign-in logs.",
        evidence: rows
          .slice(0, 10)
          .map(
            (r) =>
              `${r.AccountUpn} — ${r.Events} events · last ${r.LastSeen || "?"} · ${r.Apps || ""} · ips=${r.Ips || "?"}`
          )
          .join(" | "),
        remediation:
          "Compare against expected admin behaviour and PIM activation history. Unexpected IPs or apps on GA / Exchange Admin accounts → revoke sessions and investigate. Prefer phishing-resistant MFA for every account on this list.",
        relatedFiles: [
          "38_Identity_Privileged_Logons_30d.csv",
          "03_PrivilegedAccounts_HighValue.csv",
        ],
      });
    }
  }

  // ── NARR.Devices.MultiEndpoint — device accumulation per user ─
  //
  // The bare counts said nothing actionable. What makes this worth reading is
  // *which* users accumulated devices and what those devices are: three PCs on
  // one user is usually two stale registrations plus a Cloud PC, and each stale
  // one is a registered device object that can still satisfy a device-based CA
  // grant long after the hardware is gone.
  {
    const multi = ctx.devicesPerUserMulti || [];
    const all3 = multi.filter((r) => truthy(r.HasPcPhoneTablet)).length;
    const multiPc = multi.filter((r) => truthy(r.MultiPC)).length;
    if (multi.length && (all3 || multiPc)) {
      const enriched = multi
        .map((r) => ({
          upn: r.UPN || "",
          name: r.DisplayName || "",
          pc: Number(r.PC || 0),
          phone: Number(r.Smartphone || 0),
          tablet: Number(r.Tablet || 0),
          total: Number(r.Total || 0),
          overQuota: truthy(r.OverQuota),
          sample: String(r.SampleDevices || ""),
        }))
        .sort((a, b) => b.total - a.total || b.pc - a.pc);

      const heaviest = enriched.slice(0, 8);
      const overQuota = enriched.filter((e) => e.overQuota);
      // Cloud PCs are provisioned, not accumulated — worth separating out so
      // the reader does not chase a W365 host as if it were a forgotten laptop.
      const withCloudPc = enriched.filter((e) => /W365|CloudPC/i.test(e.sample));

      // Dozens/hundreds of PCs on one admin UPN is almost never "one person with
      // many laptops" — it is an enrollment / Autopilot / shared-admin identity
      // that every device was joined under. That is a different finding.
      const enrollmentLike = enriched.filter((e) => {
        const adminish =
          /admin|adm[-_.]|autopilot|enrollment|intune|provision/i.test(
            `${e.upn} ${e.name}`
          ) || privIndex.has(normUpn(e.upn));
        return e.pc >= 15 || (adminish && e.total >= 20);
      });

      const evidence = [];
      evidence.push(
        `${multi.length} users with more than one device · ${multiPc} with 2+ PCs · ${all3} with PC + phone + tablet` +
          (overQuota.length ? ` · ${overQuota.length} over the registration quota` : "")
      );
      if (enrollmentLike.length) {
        evidence.push(
          `${enrollmentLike.length} account(s) look like shared enrollment / admin join identities (not personal multi-device users)`
        );
      }
      for (const e of heaviest) {
        const devices = e.sample.split(" | ").slice(0, 6).join(", ");
        const tag = enrollmentLike.includes(e)
          ? " — likely enrollment/shared-admin identity"
          : "";
        evidence.push(
          `${e.upn}${e.name ? ` (${e.name})` : ""} — ${e.total} devices: ${e.pc} PC, ${e.phone} phone, ${e.tablet} tablet${e.overQuota ? " — OVER QUOTA" : ""}${tag} → ${devices}`
        );
      }
      if (withCloudPc.length) {
        evidence.push(
          `${withCloudPc.length} of these include a Windows 365 Cloud PC, which is provisioned rather than accumulated — discount it before treating the PC count as sprawl`
        );
      }

      const worst = enrollmentLike[0];
      pushNarrative(narratives, {
        id: "NARR.Devices.MultiEndpoint",
        severity: enrollmentLike.some((e) => e.pc >= 50) ? "Medium" : "Info",
        priority: enrollmentLike.length ? "Next" : "Later",
        title: worst
          ? `Shared admin / enrollment accounts own mass device registrations (${worst.upn}: ${worst.pc} PCs)`
          : `Device accumulation: ${multiPc} users hold 2+ PCs`,
        narrative: worst
          ? `${worst.upn} is registered as owner/join identity for ${worst.total} devices (${worst.pc} PCs). ` +
            "That is not a person using many laptops — it is the classic pattern of a shared admin or Autopilot/enrollment account used to join every machine. " +
            "Why it matters: (1) a privileged account becomes the common identity behind hundreds of device objects; (2) device ownership and Intune primary-user reporting become useless for investigations; (3) if that account is ever compromised, the blast radius includes every device it enrolled; (4) stale registrations under that account keep satisfying device-based CA until cleaned up. " +
            `Across the tenant, ${multi.length} users have more than one device and ${multiPc} have 2+ PCs — after separating enrollment identities, the residual list is the real personal sprawl to tidy.`
          : `${multi.length} users are registered against more than one device, ${multiPc} of them against two or more PCs and ${all3} against a PC, a phone and a tablet at once. ` +
            "This is inventory rather than a vulnerability, but a device object keeps satisfying device-based Conditional Access grants until it is removed — so a replaced laptop that was never cleaned up is still a compliant identity. " +
            "Cross-check the heaviest users below against 09_Devices_Stale_Joined_3m.csv.",
        evidence: evidence.join(" | "),
        remediation: worst
          ? "Stop joining devices under privileged shared accounts. Use Autopilot / provisioning package / enrollment profiles that assign the real user as primary user. Re-assign primary user on the existing fleet where possible, delete stale device objects under the admin UPNs, and put those admin accounts behind phishing-resistant MFA + CA. Set a realistic device registration quota so this pattern cannot silently rebuild."
          : "Compare the per-user device lists against the stale-device export and delete registrations that no longer correspond to hardware in service. Set a device registration quota in Entra so accumulation does not restart.",
        relatedFiles: [
          "09_Devices_Per_User_Multi.csv",
          "09_Devices_Per_User.csv",
          "09_Devices_Stale_Joined_3m.csv",
          "03_PrivilegedAccounts_HighValue.csv",
        ],
      });
    }
  }

  // Sort Now → Next → Later, then Critical → High → Medium
  const prioRank = (p) => ({ Now: 0, Next: 1, Later: 2 }[p] ?? 3);
  narratives.sort((a, b) => {
    const pd = prioRank(a.Priority) - prioRank(b.Priority);
    if (pd !== 0) return pd;
    const d = sevRank(a.Severity) - sevRank(b.Severity);
    if (d !== 0) return d;
    return String(a.Id).localeCompare(String(b.Id));
  });

  return narratives;
}

function scoreFromNarratives(narratives) {
  // Calibrated for pentest posture (not Microsoft Secure Score).
  // Critical/High are still visible as findings; points are softer so 2–3
  // expected/context findings (backup apps, license-gated MFA inventory) don't
  // collapse the gauge to ~40.
  let score = 100;
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  const ids = new Set();
  for (const n of narratives) {
    counts[n.Severity] = (counts[n.Severity] || 0) + 1;
    ids.add(n.Id);
  }
  score -= Math.min(28, (counts.Critical || 0) * 9);
  score -= Math.min(28, (counts.High || 0) * 3.5);
  score -= Math.min(12, (counts.Medium || 0) * 1.5);
  score -= Math.min(4, (counts.Low || 0) * 0.5);

  // Related app-path narratives shouldn't double-penalize as hard
  if (ids.has("NARR.App.RoleManagement") && ids.has("NARR.App.PathToGA")) {
    score += 3;
  }
  if (
    ids.has("NARR.App.SpnActive") &&
    ids.has("NARR.App.DangerousSpnActivity")
  ) {
    score += 3;
  }
  // MFA inventory compensated by enforced CA should not crush the posture gauge
  const mfa = narratives.find((n) => n.Id === "NARR.MFA.MassGap");
  if (
    mfa &&
    (/licenseGatedCA=true/i.test(mfa.Evidence || "") ||
      /enforcedMfaCA=true/i.test(mfa.Evidence || ""))
  ) {
    score += 6;
  }
  if (
    mfa &&
    /Critical/i.test(mfa.Severity) === false &&
    /enforcedMfaCA=true/i.test(mfa.Evidence || "")
  ) {
    score += 2;
  }

  return {
    score: Math.max(20, Math.min(100, Math.round(score))),
    sevCount: counts,
  };
}

/**
 * Analyze an output directory; write expert finding artifacts.
 * @returns {{ narratives: object[], score: number, sevCount: object }}
 */
function refreshSummaryFindings(outDir, narratives, score) {
  const summaryMd = path.join(outDir, "00_SUMMARY.md");
  if (!fs.existsSync(summaryMd)) return;
  const findings = readCsv(path.join(outDir, "00_Findings.csv"));
  let text = fs.readFileSync(summaryMd, "utf8");
  const findingsBlock =
    "## Findings\n" +
    findings
      .map(
        (f) =>
          `- **[${f.Severity || "Info"}]** ${f.Area || "?"}: ${f.Detail || ""}`
      )
      .join("\n") +
    "\n\n## Expert posture\n" +
    `- Score: **${score}**\n` +
    `- Narratives: **${(narratives || []).length}**\n` +
    (narratives || [])
      .slice(0, 25)
      .map((n) => `- **[${n.Severity}]** ${n.Id}: ${n.Title}`)
      .join("\n") +
    "\n";

  // Replace from ## Findings through EOF (or next top-level section after Findings if any)
  if (/^## Findings\b/m.test(text)) {
    text = text.replace(/^## Findings\b[\s\S]*$/m, findingsBlock.trimEnd() + "\n");
  } else {
    text = text.trimEnd() + "\n\n" + findingsBlock;
  }
  fs.writeFileSync(summaryMd, text, "utf8");
}

function analyzeOutputDir(outDir) {
  const ctx = loadContext(outDir);
  const narratives = runRules(ctx);
  const { score, sevCount } = scoreFromNarratives(narratives);
  const io = createIo(outDir, { manifest: false });

  io.saveCsv("00_Expert_Findings.csv", narratives);
  io.saveJson("00_Expert_Findings.json", {
    generatedAt: new Date().toISOString(),
    score,
    sevCount,
    narratives,
  });

  // Append expert rollup into summary if present
  const summaryPath = path.join(outDir, "00_SUMMARY.json");
  if (fs.existsSync(summaryPath)) {
    const summary = readJson(summaryPath) || {};
    summary.expertScore = score;
    summary.expertSevCount = sevCount;
    summary.expertFindingCount = narratives.length;
    const mfaBreak = summarizeNoMfaBreakdown(ctx.noMfa || []);
    summary.usersWithoutMfaHuman = mfaBreak.human;
    summary.usersWithoutMfaNonHuman = mfaBreak.nonHuman;
    summary.usersWithoutMfaRooms = mfaBreak.room;
    summary.usersWithoutMfaShared = mfaBreak.shared;
    summary.usersWithoutMfaService = mfaBreak.service;
    // Refresh Identity Secure Score from in-scope category when available.
    try {
      const { buildSecureScoreExplorer } = require("./securescore");
      const byCat = readCsv(
        path.join(outDir, "10_SecureScore_ByCategory.csv")
      );
      if (byCat.length) {
        const id = buildSecureScoreExplorer(byCat).categories.find((c) =>
          /^Identity$/i.test(c.Category)
        );
        if (id) {
          summary.identitySecureScoreCurrent = id.Score;
          summary.identitySecureScoreMax = id.Max;
        }
      }
    } catch {
      /* non-fatal */
    }
    fs.writeFileSync(summaryPath, JSON.stringify(summary, null, 2), "utf8");
  }

  try {
    refreshSummaryFindings(outDir, narratives, score);
  } catch (e) {
    console.warn("  ⚠ refresh SUMMARY.md findings:", e.message);
  }

  return { narratives, score, sevCount, summary: ctx.summary };
}

module.exports = {
  analyzeOutputDir,
  runRules,
  loadContext,
  scoreFromNarratives,
  refreshSummaryFindings,
  classifyAccountKind,
  summarizeNoMfaBreakdown,
  GA_PATH_PERMS,
  ROLE_MGMT_PERM,
};
