/**
 * HTML findings viewer + PDF / Excel export from an Entra Collect output directory.
 *
 * Usage:
 *   node report.js [outputDir]
 *   node report.js                    # latest output_* folder
 */
const fs = require("fs");
const path = require("path");
const {
  analyzeOutputDir,
  summarizeNoMfaBreakdown,
} = require("./lib/analyze");
const { readManifest } = require("./lib/io");
const { parseCsv } = require("./lib/csv");
const {
  buildInScopeControls,
  buildSecureScoreExplorer,
  stripHtml,
} = require("./lib/securescore");
const { writeFileNode: writeXlsxReport } = require("./lib/xlsxReport");
const {
  enrichDirectoryRoleRows,
  rollupDirectoryRoles,
} = require("./lib/posture");

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

/**
 * Most recent run that actually produced data.
 *
 * Aborted runs leave behind empty output_* folders; picking one of those by
 * date would render a spotless report for a tenant that was never collected.
 */
function latestOutputDir(base) {
  const dirs = fs
    .readdirSync(base)
    .filter(
      (d) => d.startsWith("output_") && fs.statSync(path.join(base, d)).isDirectory()
    )
    .sort()
    .reverse();
  const hasData = (d) =>
    fs.readdirSync(path.join(base, d)).some((f) => /\.(csv|json)$/i.test(f));
  const chosen = dirs.find(hasData);
  if (chosen && chosen !== dirs[0]) {
    console.warn(
      `  · skipping ${dirs.filter((d) => !hasData(d)).length} empty output folder(s); using ${chosen}`
    );
  }
  return chosen ? path.join(base, chosen) : null;
}

/** Map ERROR_* labels → human collection area */
const ERROR_AREA_HINTS = {
  hunt: "Defender Advanced Hunting",
  tvm: "Defender / TVM",
  defender: "Defender / TVM",
  genai: "GenAI / Cloud Apps hunts",
  fileshare: "File-sharing hunts",
  rmm: "RMM hunts",
  intune: "Intune / Endpoint Manager",
  sharepoint: "SharePoint admin",
  teams: "Teams",
  directory: "Directory settings",
  audit: "Directory audit logs",
  forward: "Mailbox forwarding / EXO",
  antispam: "Anti-spam / Email hunting",
  auth: "Auth / SSPR",
  graph: "Microsoft Graph",
};

/** Aggregate TVM CSV rows for report KPIs / breakdowns. */
const SEV_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3 };

function normUpnKey(v) {
  return String(v || "").trim().toLowerCase();
}

/**
 * Join dangerous Graph grants with actual service-principal sign-ins.
 *
 * The permission list alone cannot distinguish a live integration from an
 * abandoned one; the sign-in log alone has no notion of blast radius. Together
 * they sort the same apps into "harden now" and "delete the credentials".
 */
function buildSpnActivity(dangerous, signIns) {
  if (!dangerous.length) return [];

  const risky = new Map();
  for (const r of dangerous) {
    const name = r.SPNDisplayName || r.DisplayName || r.AppName;
    if (!name) continue;
    if (!risky.has(name)) risky.set(name, { perms: new Set(), sevs: new Set() });
    if (r.Permission) risky.get(name).perms.add(r.Permission);
    if (r.Severity) risky.get(name).sevs.add(r.Severity);
  }

  const activity = new Map();
  for (const r of signIns) {
    const name = r.App || r.AppDisplayName;
    if (!name) continue;
    if (!activity.has(name))
      activity.set(name, { n: 0, ips: new Set(), locs: new Set(), failures: 0, last: "" });
    const e = activity.get(name);
    e.n++;
    if (r.IP) e.ips.add(r.IP);
    if (r.Location) e.locs.add(r.Location);
    if (r.Status && String(r.Status).trim() !== "0") e.failures++;
    if (r.Created && r.Created > e.last) e.last = r.Created;
  }

  const rows = [...risky.entries()].map(([name, meta]) => {
    const a = activity.get(name);
    const sevs = [...meta.sevs].sort(
      (x, y) => (SEV_ORDER[x] ?? 9) - (SEV_ORDER[y] ?? 9)
    );
    return {
      App: name,
      Status: a ? "Active" : "No sign-in",
      SignIns: a ? a.n : 0,
      DistinctIPs: a ? a.ips.size : 0,
      Failures: a ? a.failures : 0,
      LastSeen: a ? a.last : "",
      MaxSeverity: sevs[0] || "",
      Locations: a ? [...a.locs].slice(0, 3).join(", ") : "",
      Permissions: [...meta.perms].join(", "),
    };
  });

  // Active + most dangerous first: that is the triage order.
  rows.sort((a, b) => {
    if ((b.SignIns > 0) !== (a.SignIns > 0)) return b.SignIns > 0 ? 1 : -1;
    const s = (SEV_ORDER[a.MaxSeverity] ?? 9) - (SEV_ORDER[b.MaxSeverity] ?? 9);
    return s !== 0 ? s : b.SignIns - a.SignIns;
  });
  return rows;
}

/** Privileged role holders that show no recent sign-in. */
function buildDormantPrivileged(priv, inactive) {
  if (!priv.length || !inactive.length) return [];
  const roles = new Map();
  for (const r of priv) {
    const upn = normUpnKey(r.UPNOrAppId || r.UPN || r.UserPrincipalName);
    if (!upn) continue;
    if (!roles.has(upn)) roles.set(upn, new Set());
    if (r.RoleName) roles.get(upn).add(r.RoleName);
  }
  return inactive
    .filter((r) => roles.has(normUpnKey(r.UPN || r.UserPrincipalName)))
    .map((r) => {
      const upn = normUpnKey(r.UPN || r.UserPrincipalName);
      const list = [...roles.get(upn)];
      const days = Number(r.DaysSinceInteractive);
      return {
        UPN: r.UPN || r.UserPrincipalName,
        Roles: list.join(", "),
        IsGlobalAdmin: list.some((x) => /global administrator/i.test(x)),
        Idle: Number.isFinite(days) ? `${days}d` : "Never signed in",
        IdleDays: Number.isFinite(days) ? days : Number.MAX_SAFE_INTEGER,
        AccountEnabled: r.AccountEnabled,
        Created: r.Created || "",
      };
    })
    .sort((a, b) => b.IdleDays - a.IdleDays);
}

/** Guest lifecycle: dormant accounts and invitations that were never redeemed. */
function buildGuestHygiene(guests, inactive) {
  if (!guests.length) return { rows: [], total: 0, dormant: 0, pending: 0, disabled: 0 };
  const inactiveUpns = new Set(
    inactive.map((r) => normUpnKey(r.UPN || r.UserPrincipalName)).filter(Boolean)
  );
  const rows = guests.map((g) => {
    const dormant = inactiveUpns.has(normUpnKey(g.UPN));
    const pending = /pending/i.test(g.ExternalUserState || "");
    const enabled = String(g.AccountEnabled).toLowerCase() !== "false";
    return {
      UPN: g.UPN,
      DisplayName: g.DisplayName,
      State: pending ? "Invite pending" : dormant ? "Dormant" : "Active",
      ExternalUserState: g.ExternalUserState || "",
      AccountEnabled: g.AccountEnabled,
      Created: g.Created || "",
      Mail: g.Mail || "",
      _rank: pending ? 0 : dormant ? 1 : 2,
    };
  });
  rows.sort((a, b) => a._rank - b._rank);
  const enabled = rows.filter((r) => String(r.AccountEnabled).toLowerCase() !== "false");
  return {
    rows,
    total: rows.length,
    enabled: enabled.length,
    dormant: enabled.filter((r) => r.State === "Dormant").length,
    pending: enabled.filter((r) => r.State === "Invite pending").length,
    disabled: rows.length - enabled.length,
  };
}

/**
 * Load in-scope Secure Score controls (live controlScores), not the full
 * profile catalog. Prefer CSV from collection; rebuild from JSON if needed.
 */
function loadSecureScoreExplorer(outDir) {
  let controls = readCsvMaybe(outDir, "10_SecureScore_ByCategory.csv");
  // Reject accidental load of the inflated catalog if someone renamed files.
  if (
    controls.length > 200 ||
    (controls.length && !controls.some((r) => r.Category || r.GapPoints != null))
  ) {
    controls = [];
  }
  if (!controls.length) {
    const latest = readJson(path.join(outDir, "10_secure_score_latest.json"));
    const profiles = readJson(
      path.join(outDir, "10_secure_score_control_profiles.json")
    );
    controls = buildInScopeControls(latest, profiles);
  }
  const explorer = buildSecureScoreExplorer(controls);
  const rollup = readCsvMaybe(outDir, "10_SecureScore_Category_Rollup.csv");
  return {
    ...explorer,
    categories: rollup.length ? rollup : explorer.categories,
    gapRows: explorer.openControls.slice(0, 80).map((r) => ({
      Gain: Math.round(r.GapPoints * 10) / 10,
      Category: r.Category,
      Title: r.Title,
      Status: r.Status,
      Current: r.CurrentScore,
      Max: r.MaxScore,
      UserImpact: r.UserImpact,
      Threats: r.Threats,
      Remediation: stripHtml(r.Remediation),
      ControlId: r.ControlId,
    })),
  };
}

function summarizeTvm(defenderVulns, tvmWin, errors) {
  const vulns = defenderVulns || [];
  const winDev = tvmWin || [];
  const bySoft = new Map();
  let critical = 0;
  let high = 0;
  let windowsCveRows = 0;
  for (const r of vulns) {
    const sev = String(r.Severity || r.VulnerabilitySeverityLevel || "");
    if (/critical/i.test(sev)) critical++;
    else if (/high/i.test(sev)) high++;
    const soft = String(r.Software || r.SoftwareName || "?").toLowerCase();
    if (soft.startsWith("windows")) windowsCveRows++;
    const key = soft;
    if (!bySoft.has(key)) {
      bySoft.set(key, {
        Software: r.Software || r.SoftwareName || "?",
        CveRows: 0,
        Critical: 0,
        High: 0,
        MaxDevices: 0,
      });
    }
    const row = bySoft.get(key);
    row.CveRows++;
    if (/critical/i.test(sev)) row.Critical++;
    if (/high/i.test(sev)) row.High++;
    row.MaxDevices = Math.max(row.MaxDevices, Number(r.Devices) || 0);
  }
  const bySoftware = [...bySoft.values()]
    .sort((a, b) => b.CveRows - a.CveRows || b.MaxDevices - a.MaxDevices)
    .slice(0, 40);

  const huntErrs = (errors || []).filter((e) =>
    /hunt_|defenderHunting|tvm|genai|fileshare|rmm/i.test(e.label || "")
  );

  const winDevSorted = [...winDev].sort(
    (a, b) =>
      Number(b.Critical || 0) - Number(a.Critical || 0) ||
      Number(b.High || 0) - Number(a.High || 0) ||
      Number(b.Vulns || 0) - Number(a.Vulns || 0)
  );

  return {
    cveRows: vulns.length,
    critical,
    high,
    windowsCveRows,
    windowsOsDevices: winDev.length,
    windowsOsCriticalSum: winDevSorted.reduce(
      (n, r) => n + (Number(r.Critical) || 0),
      0
    ),
    bySoftware,
    windowsOsDevicesTop: winDevSorted.slice(0, 800),
    huntErrors: huntErrs,
    windowsOsMissing:
      winDev.length === 0 &&
      huntErrs.some((e) => /tvm_os|hunt_tvm/i.test(e.label || "")),
  };
}

function classifyErrorLabel(label) {
  const l = label.toLowerCase();
  for (const [key, area] of Object.entries(ERROR_AREA_HINTS)) {
    if (l.includes(key)) return area;
  }
  return "Other / Graph";
}

function shortError(errObj) {
  const raw = String((errObj && errObj.error) || "");
  const status = errObj && errObj.status;
  let reason = "Unknown";
  if (status === 403 || /Forbidden|not authorized|Missing application scopes/i.test(raw)) {
    reason = "Access denied (403) — missing role or Graph scope";
  } else if (status === 401 || /Unauthorized/i.test(raw)) {
    reason = "Unauthorized (401) — token insufficient";
  } else if (status === 404 || /NotFound/i.test(raw)) {
    reason = "Not found (404)";
  } else if (/Failed to resolve table/i.test(raw)) {
    reason = "Hunting table not in tenant schema";
  } else if (
    status === 400 ||
    /incomplete fragment|syntax errors in your query|ErrorCode.:2/i.test(raw)
  ) {
    reason = "Hunting KQL syntax rejected (400) — query dialect / portal AH incompatibility";
  } else if (status) {
    reason = `HTTP ${status}`;
  }
  // Extract required scopes if present
  let needed = "";
  const scopeMatch = raw.match(
    /must have one of the following scopes:\s*([A-Za-z0-9.,_\s]+)/i
  );
  if (scopeMatch) needed = scopeMatch[1].trim().replace(/\s+/g, " ");
  const huntMatch = raw.match(/API required scopes:\s*([A-Za-z0-9.,_\s]+)/i);
  if (huntMatch) needed = huntMatch[1].trim();
  return { reason, needed, status: status || null, snippet: raw.slice(0, 220) };
}

function loadErrors(outDir) {
  const files = fs
    .readdirSync(outDir)
    .filter((f) => f.startsWith("ERROR_") && f.endsWith(".json"));
  return files.map((f) => {
    const label = f.replace(/^ERROR_/, "").replace(/\.json$/, "");
    const body = readJson(path.join(outDir, f)) || {};
    const parsed = shortError(body);
    return {
      file: f,
      label,
      area: classifyErrorLabel(label),
      ...parsed,
    };
  });
}

/** Expected hunting artifacts — used to show OK/Fail/Empty after KQL fixes. */
const HUNT_KQL_CHECKS = [
  {
    id: "defenderHuntingVulns",
    label: "TVM CVE inventory (High/Critical)",
    artifact: "11_Defender_Exploitable_Vulns.csv",
    error: "ERROR_defenderHuntingVulns.json",
  },
  {
    id: "hunt_tvm_os_vulns",
    label: "Windows OS TVM High/Critical by device",
    artifact: "32_TVM_Windows_HighCritical.csv",
    error: "ERROR_hunt_tvm_os_vulns.json",
  },
  {
    id: "hunt_tvm_os_cves",
    label: "Windows OS CVE inventory",
    artifact: "32_TVM_Windows_CVE_Inventory.csv",
    error: null,
  },
  {
    id: "hunt_rmm_inventory",
    label: "RMM software inventory",
    artifact: "30_RMM_Affected_Assets.csv",
    error: "ERROR_hunt_rmm_inventory.json",
  },
  {
    id: "hunt_genai_cloudapp",
    label: "GenAI CloudApp usage",
    artifact: "34_GenAI_Usage_ByUser.csv",
    error: "ERROR_hunt_genai_cloudapp.json",
  },
  {
    id: "hunt_fileshare_cloudapp",
    label: "File-share CloudApp usage",
    artifact: "35_FileShare_Usage_ByUser.csv",
    error: "ERROR_hunt_fileshare_cloudapp.json",
  },
  {
    id: "hunt_genai_network",
    label: "GenAI network signals",
    artifact: null,
    error: "ERROR_hunt_genai_network.json",
  },
  {
    id: "hunt_fileshare_network",
    label: "File-share network signals",
    artifact: null,
    error: "ERROR_hunt_fileshare_network.json",
  },
];

function csvRowCount(outDir, name) {
  if (!name) return 0;
  const p = path.join(outDir, name);
  if (!fs.existsSync(p)) return -1;
  const text = fs.readFileSync(p, "utf8");
  if (!String(text).trim()) return 0;
  const lines = String(text)
    .replace(/\r\n/g, "\n")
    .split("\n")
    .filter((l) => l.trim());
  return Math.max(0, lines.length - 1);
}

function buildHuntKqlStatus(outDir, errors) {
  const errByLabel = new Map((errors || []).map((e) => [e.label, e]));
  return HUNT_KQL_CHECKS.map((c) => {
    const rows = c.artifact ? csvRowCount(outDir, c.artifact) : -1;
    const err =
      (c.error && fs.existsSync(path.join(outDir, c.error))
        ? errByLabel.get(c.error.replace(/^ERROR_/, "").replace(/\.json$/, "")) ||
          errByLabel.get(c.id)
        : null) ||
      errByLabel.get(c.id) ||
      null;
    let status = "n/a";
    if (rows > 0) status = "OK";
    else if (err) status = "Fail";
    else if (rows === 0) status = "Empty";
    else if (rows < 0 && !err) status = "Missing";
    return {
      Hunt: c.label,
      Id: c.id,
      Status: status,
      Rows: rows < 0 ? "" : String(rows),
      Artifact: c.artifact || "",
      ErrorDetail: err
        ? `${err.reason || "error"}${(err.snippet && ": " + err.snippet.slice(0, 100)) || ""}`
        : "",
    };
  });
}

function groupFindingsByArea(findings) {
  const map = {};
  for (const f of findings) {
    const area = f.Area || "Other";
    if (!map[area]) {
      map[area] = { area, High: 0, Medium: 0, Low: 0, Info: 0, total: 0, items: [] };
    }
    const sev = f.Severity || "Info";
    map[area][sev] = (map[area][sev] || 0) + 1;
    map[area].total++;
    map[area].items.push(f);
  }
  return Object.values(map).sort((a, b) => {
    if (b.High !== a.High) return b.High - a.High;
    if (b.Medium !== a.Medium) return b.Medium - a.Medium;
    return b.total - a.total;
  });
}

function buildCoverage(summary, schema, errors) {
  const caps = (summary && summary.huntingCapabilities) || (schema && schema.capabilities) || {};
  const rows = [
    {
      Domain: "Entra sign-in logs (Graph)",
      Status: summary.graphSignInsAvailable ? "Available" : "Unavailable",
      Impact: summary.graphSignInsAvailable
        ? "Device code / legacy via Graph"
        : "Identity log hunts limited",
    },
    {
      Domain: "Defender Advanced Hunting API",
      Status: summary.huntingCanHunt ? "Available" : summary.huntingApiStatus || "Unavailable",
      Impact: summary.huntingCanHunt
        ? "Endpoint / identity / email hunts possible"
        : "RMM, AI, patch, TVM, EmailEvents, EntraIdSignInEvents skipped",
    },
    {
      Domain: "RMM / process hunts",
      Status: caps.rmm ? "Runnable" : "Skipped",
      Impact: caps.rmm ? "DeviceTvm / ProcessEvents used" : "Needs DeviceInfo / TVM + hunting rights",
    },
    {
      Domain: "AI agent hunts",
      Status: caps.ai ? "Runnable" : "Skipped",
      Impact: caps.ai ? "Process/file/network signals" : "Needs MDE hunting tables",
    },
    {
      Domain: "OS / Patch Tuesday hunts",
      Status: caps.patch || caps.windowsInventory ? "Runnable" : "Skipped",
      Impact: caps.patch ? "DeviceInfo builds" : "Use Intune / Entra devices instead",
    },
    {
      Domain: "TVM vulnerability hunts",
      Status: caps.vulns ? "Runnable" : "Skipped",
      Impact: caps.vulns ? "CVE inventory" : "Needs DeviceTvmSoftwareVulnerabilities",
    },
    {
      Domain: "GenAI cloud usage volume",
      Status: caps.cloudGenAi ? "Runnable" : "Skipped",
      Impact: caps.cloudGenAi
        ? "CloudAppEvents / network GenAI volume"
        : "Needs CloudAppEvents or DeviceNetworkEvents",
    },
    {
      Domain: "File-sharing sites (WeTransfer/Dropbox)",
      Status: caps.fileSharing ? "Runnable" : "Skipped",
      Impact: caps.fileSharing
        ? "Cloud App + network sharing signals"
        : "Needs CloudAppEvents or DeviceNetworkEvents",
    },
    {
      Domain: "Identity hunting tables",
      Status: caps.deviceCodeHunt || caps.legacyHunt ? "Runnable" : "Skipped (Graph fallback)",
      Impact: `Source: ${summary.huntingIdentitySource || schema?.identitySource || "n/a"}`,
    },
    {
      Domain: "Email / MDO hunting",
      Status: caps.antiSpam || caps.forwarding ? "Runnable" : "Skipped",
      Impact: caps.antiSpam ? "EmailEvents" : "Checklist only / EXO portal",
    },
  ];

  const errAreas = {};
  for (const e of errors) {
    errAreas[e.area] = (errAreas[e.area] || 0) + 1;
  }
  for (const [area, n] of Object.entries(errAreas)) {
    rows.push({
      Domain: `API errors — ${area}`,
      Status: `${n} failed call(s)`,
      Impact: "See Limitations tab for scopes / roles",
    });
  }
  return rows;
}

function readCsvMaybe(outDir, name) {
  return readCsv(path.join(outDir, name));
}

/** Prefer newest inactive/stale files by scanning dir for pattern */
function readCsvGlobFirst(outDir, re) {
  try {
    const files = fs
      .readdirSync(outDir)
      .filter((f) => re.test(f))
      .sort();
    if (!files.length) return [];
    return readCsv(path.join(outDir, files[files.length - 1]));
  } catch {
    return [];
  }
}

function isStrongMfaMethod(m) {
  const s = String(m || "").toLowerCase();
  return /authenticator|fido|passkey|hello|hardwareoath|passwordless|windowshello/.test(
    s
  );
}

function isWeakMfaMethod(m) {
  const s = String(m || "").toLowerCase();
  return /phone|sms|voice|email|officephone/.test(s);
}

/** Phone/SMS/email MFA without authenticator / FIDO / WHfB */
function deriveWeakMfaUsers(regDetails) {
  const rows = Array.isArray(regDetails)
    ? regDetails
    : regDetails?.value || [];
  const out = [];
  for (const u of rows) {
    if (!u.isMfaRegistered) continue;
    const methods = u.methodsRegistered || [];
    const hasStrong = methods.some(isStrongMfaMethod);
    const hasWeak = methods.some(isWeakMfaMethod);
    if (hasWeak && !hasStrong) {
      out.push({
        UPN: u.userPrincipalName,
        DisplayName: u.userDisplayName,
        IsAdmin: u.isAdmin,
        MethodsRegistered: methods.join(", "),
        PreferredSecondary: u.userPreferredMethodForSecondaryAuthentication || "",
        LastUpdated: u.lastUpdatedDateTime || "",
      });
    }
  }
  return out;
}

/** Collapse repetitive inventory Highs (e.g. 20× CA exclusion groups) into one rollup. */
function collapseInventoryFindings(findings) {
  const exclRe = /exclusion group.*not role-assignable|CA exclusion group "/i;
  const excl = [];
  const rest = [];
  for (const f of findings || []) {
    if (exclRe.test(f.Detail || "")) excl.push(f);
    else rest.push(f);
  }
  if (excl.length > 1) {
    rest.unshift({
      Severity: "High",
      Area: "CA",
      Detail:
        `${excl.length} CA exclusion groups are not role-assignable (add member = CA bypass) — aggregated; see Expert finding NARR.CA.ExclGroups / 40_CA_Exclusion_Groups.csv`,
      _collapsedFrom: excl.length,
    });
  } else {
    rest.push(...excl);
  }
  return rest;
}

/**
 * Per-artifact collection status, so the report can say "not collected" instead
 * of rendering a failed export as a clean zero.
 */
function loadCollectionStatus(outDir) {
  const manifest = readManifest(outDir);
  if (!manifest) return { available: false, artifacts: {}, failedSteps: [] };
  const failedSteps = Object.entries(manifest.steps || {})
    .filter(([, s]) => s.status === "failed")
    .map(([label, s]) => ({ label, error: s.error, httpStatus: s.httpStatus }));
  return {
    available: true,
    artifacts: manifest.artifacts || {},
    failedSteps,
    startedAt: manifest.startedAt,
    finishedAt: manifest.finishedAt,
  };
}

function buildReportPayload(outDir) {
  // Expert narratives (correlation) — drives score + primary report view.
  // A bad rule must degrade the report, never prevent it from being written.
  let expert;
  try {
    expert = analyzeOutputDir(outDir);
  } catch (e) {
    console.warn(`  ⚠ expert analysis failed: ${e.message}`);
    expert = { narratives: [], score: null, sevCount: {}, error: String(e.message) };
  }
  const collection = loadCollectionStatus(outDir);
  const summary = readJson(path.join(outDir, "00_SUMMARY.json")) || {};
  const findingsRaw = readCsv(path.join(outDir, "00_Findings.csv"));
  const findings = collapseInventoryFindings(findingsRaw);
  const narratives = expert.narratives || [];
  const attackChecklist = readCsv(path.join(outDir, "40_AttackPath_Checklist.csv"));
  const checklistFails = (attackChecklist || []).filter((r) =>
    /fail/i.test(r.Status || "")
  );
  const checklistPartials = (attackChecklist || []).filter((r) =>
    /partial/i.test(r.Status || "")
  );
  const checklistPasses = (attackChecklist || []).filter((r) =>
    /pass/i.test(r.Status || "")
  );
  const checklistNotEvaluated = (attackChecklist || []).filter((r) =>
    /^(skip|notevaluated)$/i.test(String(r.Status || "").trim())
  );
  const checklistNotApplicable = (attackChecklist || []).filter((r) =>
    /^notapplicable$/i.test(String(r.Status || "").trim())
  );
  const caCoverage = readCsv(path.join(outDir, "40_CA_AttackPath_Coverage.csv"));
  const caAudit = readCsv(path.join(outDir, "02_CA_Audit.csv"));
  const priv = readCsv(path.join(outDir, "03_PrivilegedAccounts_HighValue.csv"));
  const privAllRaw = readCsvMaybe(outDir, "03_PrivilegedRoles_Audit.csv");
  const roleDefJson = readJson(path.join(outDir, "03_role_definitions.json"));
  const roleDefById = {};
  for (const d of Array.isArray(roleDefJson) ? roleDefJson : []) {
    if (d && d.id && d.displayName) roleDefById[d.id] = d.displayName;
    if (d && d.templateId && d.displayName) roleDefById[d.templateId] = d.displayName;
  }
  const highValueNames = new Set(
    (priv || []).map((r) => r.RoleName).filter(Boolean)
  );
  const privAll = enrichDirectoryRoleRows(privAllRaw.length ? privAllRaw : priv, {
    roleDefById,
    highValueNames,
  });
  const privByRole = rollupDirectoryRoles(privAll);
  const dangerous = readCsv(path.join(outDir, "04_SPN_DangerousPerms.csv"));
  const gaPath = readCsv(path.join(outDir, "40_Apps_Path_To_GA.csv"));
  const deviceCode = readCsvMaybe(outDir, "20_DeviceCode_Users_90d.csv").length
    ? readCsvMaybe(outDir, "20_DeviceCode_Users_90d.csv")
    : readCsvMaybe(outDir, "20_DeviceCode_Users_30d.csv");
  const deviceCodeSignIns = readCsvMaybe(outDir, "20_DeviceCode_SignIns_90d.csv").length
    ? readCsvMaybe(outDir, "20_DeviceCode_SignIns_90d.csv")
    : readCsvMaybe(outDir, "20_DeviceCode_SignIns_30d.csv");
  const legacy = readCsvMaybe(outDir, "21_LegacyAuth_Success_90d.csv");
  const risky = readCsvMaybe(outDir, "24_RiskyUsers.csv");
  const schema = readJson(path.join(outDir, "19_Hunting_Schema.json"));
  const exclGroups = readCsvMaybe(outDir, "40_CA_Exclusion_Groups.csv");
  const privHygiene = readCsvMaybe(outDir, "40_Privileged_Identity_Hygiene.csv");
  const privSpnCreds = readCsvMaybe(outDir, "40_Privileged_SPN_Credentials.csv");
  const noMfa = readCsvMaybe(outDir, "07_Users_Without_MFA.csv");
  const passkey = readCsvMaybe(outDir, "07_Users_PhishingResistant_or_Passkey.csv");
  const inactive = readCsvGlobFirst(outDir, /^08_Accounts_Inactive_\d+d\.csv$/);
  const staleDevices = readCsvGlobFirst(outDir, /^09_Devices_Stale_Joined_\d+m\.csv$/);
  const registeredOnly = readCsvMaybe(outDir, "09_Devices_Registered_Only.csv");
  const guests = readCsvMaybe(outDir, "05_guests.csv");
  const secretsExpiry = readCsvMaybe(outDir, "04_App_SecretsExpiry.csv");
  const wildcardUrls = readCsvMaybe(outDir, "04_SPN_WildcardReplyUrls.csv");
  const secureScoreTop = readCsvMaybe(outDir, "10_SecureScore_Top15_HighValue.csv");
  const sspr = readCsvMaybe(outDir, "13_SSPR_Registered_Users.csv");
  const domains = readCsvMaybe(outDir, "12_Domains.csv");
  const rmm = readCsvMaybe(outDir, "30_RMM_Detections.csv");
  const rmmDismissed = readCsvMaybe(outDir, "30_RMM_Dismissed_Artefacts.csv");
  const rmmFamilyRaw = readCsvMaybe(outDir, "30_RMM_Family_Summary.csv");
  const rmmAssetsRaw = readCsvMaybe(outDir, "30_RMM_Affected_Assets.csv");
  // Older collects marked AssumedLegit=false when TotalWindows=0 (DeviceInfo
  // missing). Recompute agent/noise splits for the Endpoints tab when needed.
  let rmmFamily = rmmFamilyRaw;
  let rmmAssets = rmmAssetsRaw;
  try {
    const {
      enrichRmmAssets,
      summarizeRmmByFamily,
    } = require("./lib/rmmClassify");
    rmmAssets = enrichRmmAssets(rmmAssetsRaw);
    if (
      !rmmFamilyRaw.some((r) => r.AgentDevices != null && String(r.AgentDevices) !== "")
    ) {
      const byFam = summarizeRmmByFamily(rmmAssets);
      rmmFamily = rmmFamilyRaw.map((r) => {
        const s = byFam.get(r.Family) || {};
        const agent = Number(s.AgentDevices || 0);
        const noise = Number(s.NoiseDevices || 0);
        const totalWin = Number(r.TotalWindows || 0);
        return {
          ...r,
          AgentDevices: agent,
          NoiseDevices: noise,
          MobileDevices: s.MobileDevices || 0,
          ViewerDevices: s.ViewerDevices || 0,
          AdhocDevices: s.AdhocDevices || 0,
          AssumedLegit: r.AssumedLegit,
          Verdict:
            agent === 0 && Number(r.Devices || 0) > 0
              ? "Noise only — mobile/viewer/adhoc inventory (no desktop agent signal)"
              : !totalWin
                ? `Inventory — ${agent} agent / ${noise} noise (DeviceInfo missing, fleet % n/a)`
                : r.Verdict,
        };
      });
    } else if (
      summary &&
      rmmFamily.length &&
      !rmmFamily.some((r) => Number(r.TotalWindows || 0) > 0)
    ) {
      summary.rmmPrevalenceKnown = false;
    }
    if (summary) {
      summary.rmmAgentAssets = rmmAssets.filter((a) => a.Signal).length;
      summary.rmmNoiseAssets = rmmAssets.filter((a) => !a.Signal).length;
      summary.rmmSuspiciousFamilies = rmmFamily.filter(
        (r) => Number(r.AgentDevices || 0) > 0 && !/^(1|true)$/i.test(String(r.AssumedLegit || ""))
      ).length;
    }
  } catch (e) {
    rmmFamily = rmmFamilyRaw.map((r) => {
      if (Number(r.TotalWindows || 0) > 0) return r;
      return {
        ...r,
        PrevalencePct: r.PrevalencePct || "",
        AssumedLegit: false,
        Verdict:
          "Inventory only — DeviceInfo missing, fleet prevalence not measured",
      };
    });
    if (
      summary &&
      rmmFamily.length &&
      !rmmFamily.some((r) => Number(r.TotalWindows || 0) > 0)
    ) {
      summary.rmmPrevalenceKnown = false;
    }
  }
  const aiAgents = readCsvGlobFirst(outDir, /^31_AI_.*\.csv$/);
  const patchBehind = readCsvGlobFirst(outDir, /^32_.*Behind.*\.csv$/);
  // Windows build inventory. The old /^32_Windows_.*\.csv$/ glob matched
  // nothing (the file is 32_OS_Build_Distribution.csv) while also being able to
  // pick up 32_TVM_Windows_* if that ever changed.
  const winInventory = readCsvMaybe(outDir, "32_OS_Build_Distribution.csv");
  const updateRings = readCsvMaybe(outDir, "33_Intune_UpdateRings.csv");
  const genAiUsers = readCsvMaybe(outDir, "34_GenAI_Usage_ByUser.csv");
  const genAiApps = readCsvMaybe(outDir, "34_GenAI_Usage_ByApp.csv");
  const fileShareUsers = readCsvMaybe(outDir, "35_FileShare_Usage_ByUser.csv");
  const fileShareApps = readCsvMaybe(outDir, "35_FileShare_Usage_ByApp.csv");
  const defenderVulns = readCsvMaybe(outDir, "11_Defender_Exploitable_Vulns.csv");
  const devicesPerUser = readCsvMaybe(outDir, "09_Devices_Per_User.csv");
  const devicesPerUserMulti = readCsvMaybe(outDir, "09_Devices_Per_User_Multi.csv");
  const win10Devices = readCsvMaybe(outDir, "32_Windows10_Devices.csv");
  const tvmWin = readCsvMaybe(outDir, "32_TVM_Windows_HighCritical.csv");
  const tvmWinCves = readCsvMaybe(outDir, "32_TVM_Windows_CVE_Inventory.csv");
  const osBuildDist = readCsvMaybe(outDir, "32_OS_Build_Distribution.csv");
  const patchStatusAll = readCsvMaybe(outDir, "32_Endpoints_OS_PatchStatus.csv");
  const highPrivOwners = readCsvMaybe(outDir, "40_HighPriv_App_Owners.csv");
  const antiSpam = readCsvMaybe(outDir, "17_AntiSpam_Manual_Checklist.csv");
  const emailSample = readCsvMaybe(outDir, "17_Email_Delivery_7d_Sample.csv");
  const outboundDomains = readCsvMaybe(outDir, "18_Outbound_Email_Domains_30d.csv");
  const forwardingChecks = readCsvMaybe(outDir, "18_Mailbox_Forwarding_Manual_Checks.csv");
  const teamsGuest = readCsvMaybe(outDir, "16_Teams_Sample_GuestSettings.csv").length
    ? readCsvMaybe(outDir, "16_Teams_Sample_GuestSettings.csv")
    : readCsvMaybe(outDir, "16_Teams_Group_Guest_Settings.csv");
  const logRetention = readCsvMaybe(outDir, "14_Log_Retention_Notes.csv");
  const securityAlerts = (() => {
    const j = readJson(path.join(outDir, "11_security_alerts_sample.json"));
    if (Array.isArray(j)) return j;
    if (j && Array.isArray(j.value)) return j.value;
    return [];
  })().map((a) => ({
    Title: a.title || a.Title || "",
    Severity: a.severity || a.Severity || "",
    Status: a.status || a.Status || "",
    Category: a.category || a.Category || "",
    Created: a.createdDateTime || a.CreatedDateTime || "",
    Product: (a.vendorInformation && a.vendorInformation.provider) || a.serviceSource || "",
  }));
  const spnSignIns = readCsvMaybe(outDir, "27_SPN_SignIns_90d.csv").length
    ? readCsvMaybe(outDir, "27_SPN_SignIns_90d.csv")
    : readCsvMaybe(outDir, "27_SPN_SignIns_30d.csv");
  const spnActivity = buildSpnActivity(dangerous, spnSignIns);
  const dormantPrivileged = buildDormantPrivileged(priv, inactive);
  const guestHygiene = buildGuestHygiene(guests, inactive);
  const secureScoreExplorer = loadSecureScoreExplorer(outDir);
  const secureScoreGaps = {
    rows: secureScoreExplorer.gapRows,
    count: secureScoreExplorer.openCount,
    points: secureScoreExplorer.openPoints,
    categories: secureScoreExplorer.categories,
    controlCount: secureScoreExplorer.controlCount,
    inScope: true,
  };

  const regDetails = readJson(path.join(outDir, "07_user_registration_details.json"));
  const weakMfa = deriveWeakMfaUsers(regDetails);
  const errors = loadErrors(outDir);
  const tvmStats = summarizeTvm(defenderVulns, tvmWin, errors);
  const huntKqlStatus = buildHuntKqlStatus(outDir, errors);
  const byArea = groupFindingsByArea(findings);
  const coverage = buildCoverage(summary, schema, errors);

  const inventorySevCount = { High: 0, Medium: 0, Low: 0, Info: 0, Critical: 0 };
  for (const f of findings) {
    const s = f.Severity || "Info";
    inventorySevCount[s] = (inventorySevCount[s] || 0) + 1;
  }

  const skippedFindings = findings.filter((f) =>
    /skip|unavailable|could not|missing|n\/a —|forbidden|not captured/i.test(
      f.Detail || ""
    )
  );

  const score = expert.score;
  const sevCount = {
    Critical: expert.sevCount.Critical || 0,
    High: expert.sevCount.High || 0,
    Medium: expert.sevCount.Medium || 0,
    Low: expert.sevCount.Low || 0,
    Info: expert.sevCount.Info || 0,
  };

  // Precompute for the HTML client (browser cannot call Node helpers).
  const noMfaBreak = summarizeNoMfaBreakdown(noMfa);
  summary.usersWithoutMfaHuman =
    summary.usersWithoutMfaHuman != null
      ? summary.usersWithoutMfaHuman
      : noMfaBreak.human;
  summary.usersWithoutMfaNonHuman =
    summary.usersWithoutMfaNonHuman != null
      ? summary.usersWithoutMfaNonHuman
      : noMfaBreak.nonHuman;

  const CAP = 800; // keep HTML usable while showing deep inventory

  return {
    meta: {
      generatedAt: new Date().toISOString(),
      outputDir: path.basename(outDir),
      tool: "Entra Collect",
      brand: "Entra Collect",
      tagline: "Identity & M365 attack-path assessment",
      scoring: "expert-narratives",
    },
    summary,
    collection,
    score,
    sevCount,
    inventorySevCount,
    narratives,
    findings,
    byArea,
    skippedFindings,
    errors,
    coverage,
    attackChecklist,
    checklistStats: {
      fail: checklistFails.length,
      partial: checklistPartials.length,
      pass: checklistPasses.length,
      notEvaluated: checklistNotEvaluated.length,
      notApplicable: checklistNotApplicable.length,
      total: (attackChecklist || []).length,
    },
    caCoverage,
    caAudit: caAudit.slice(0, 300),
    priv: priv.slice(0, CAP),
    privTotal: priv.length,
    privAll: privAll.slice(0, CAP),
    privAllTotal: privAll.length,
    privByRole,
    dangerous: dangerous.slice(0, CAP),
    gaPath: gaPath.slice(0, CAP),
    spnActivity,
    dormantPrivileged,
    guestHygiene: { ...guestHygiene, rows: guestHygiene.rows.slice(0, CAP) },
    secureScoreGaps,
    secureScoreExplorer: {
      categories: secureScoreExplorer.categories,
      controls: secureScoreExplorer.controls,
      openCount: secureScoreExplorer.openCount,
      openPoints: secureScoreExplorer.openPoints,
      controlCount: secureScoreExplorer.controlCount,
    },
    deviceCode: deviceCode.slice(0, CAP),
    deviceCodeSignIns: deviceCodeSignIns.slice(0, 200),
    legacy: legacy.slice(0, CAP),
    risky: risky.slice(0, CAP),
    exclGroups,
    privHygiene: privHygiene.slice(0, CAP),
    privSpnCreds: privSpnCreds.slice(0, CAP),
    noMfa: noMfa.slice(0, CAP),
    noMfaTotal: noMfa.length,
    weakMfa: weakMfa.slice(0, CAP),
    weakMfaTotal: weakMfa.length,
    passkey: passkey.slice(0, CAP),
    passkeyTotal: passkey.length,
    inactive: inactive.slice(0, CAP),
    inactiveTotal: inactive.length,
    staleDevices: staleDevices.slice(0, CAP),
    staleDevicesTotal: staleDevices.length,
    registeredOnly: registeredOnly.slice(0, CAP),
    registeredOnlyTotal: registeredOnly.length,
    devicesPerUser: devicesPerUser.slice(0, CAP),
    devicesPerUserTotal: devicesPerUser.length,
    devicesPerUserMulti: devicesPerUserMulti.slice(0, CAP),
    devicesPerUserMultiTotal: devicesPerUserMulti.length,
    guests: guests.slice(0, CAP),
    guestsTotal: guests.length,
    secretsExpiry: secretsExpiry.slice(0, CAP),
    wildcardUrls: wildcardUrls.slice(0, CAP),
    secureScoreTop: secureScoreTop.slice(0, 50),
    sspr: sspr.slice(0, CAP),
    domains: domains.slice(0, 100),
    defenderVulns: defenderVulns.slice(0, CAP),
    defenderVulnsTotal: defenderVulns.length,
    win10Devices: win10Devices.slice(0, CAP),
    win10DevicesTotal: win10Devices.length,
    tvmWin: (tvmStats.windowsOsDevicesTop || tvmWin).slice(0, CAP),
    tvmWinTotal: tvmWin.length || tvmStats.windowsOsDevices,
    tvmWinCves: tvmWinCves.slice(0, CAP),
    tvmWinCvesTotal: tvmWinCves.length,
    tvmStats,
    huntKqlStatus,
    osBuildDist: osBuildDist.slice(0, CAP),
    patchStatusAll: patchStatusAll.slice(0, CAP),
    highPrivOwners: highPrivOwners.slice(0, CAP),
    securityAlerts: securityAlerts.slice(0, 200),
    securityAlertsTotal: securityAlerts.length,
    collab: {
      antiSpam: antiSpam.slice(0, CAP),
      emailSample: emailSample.slice(0, CAP),
      outboundDomains: outboundDomains.slice(0, CAP),
      forwardingChecks: forwardingChecks.slice(0, CAP),
      teamsGuest: teamsGuest.slice(0, CAP),
      logRetention: logRetention.slice(0, CAP),
    },
    endpoints: {
      rmm: rmm.slice(0, CAP),
      rmmAssets: rmmAssets.slice(0, CAP),
      rmmDismissed: rmmDismissed.slice(0, CAP),
      rmmFamily: rmmFamily.slice(0, CAP),
      aiAgents: aiAgents.slice(0, CAP),
      patchBehind: patchBehind.slice(0, CAP),
      winInventory: winInventory.slice(0, CAP),
      updateRings: updateRings.slice(0, CAP),
      genAiUsers: genAiUsers.slice(0, CAP),
      genAiApps: genAiApps.slice(0, CAP),
      fileShareUsers: fileShareUsers.slice(0, CAP),
      fileShareApps: fileShareApps.slice(0, CAP),
    },
    schema,
  };
}

function escapeHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/**
 * Tenant data is embedded as inert JSON, not as executable JavaScript.
 *
 * The report ships to the customer as a single file, so the payload has to stay
 * inline — but putting it in a `type="application/json"` block means a stray
 * unescaped field can never become script. Only `<` needs neutralising to keep
 * a value from terminating the element early.
 */
function renderJsonPayload(data) {
  return JSON.stringify(data).replace(/</g, "\\u003c");
}

/**
 * Inline jsPDF instead of pulling it from a CDN: assessments are opened on
 * air-gapped or proxy-filtered networks where the download silently fails and
 * the export button does nothing.
 */
function inlineJsPdf() {
  try {
    const p = require.resolve("jspdf/dist/jspdf.umd.min.js");
    return `<script>${fs.readFileSync(p, "utf8")}</script>`;
  } catch {
    console.warn(
      "  ⚠ jspdf not installed — PDF export will fall back to browser print (npm install)"
    );
    return "";
  }
}

/** Inline ExcelJS + remediation workbook builder (air-gapped safe, like jsPDF). */
function inlineXlsxExport() {
  try {
    const excelPath = require.resolve("exceljs/dist/exceljs.min.js");
    const builderPath = path.join(__dirname, "lib", "xlsxReport.js");
    return (
      `<script>${fs.readFileSync(excelPath, "utf8")}</script>\n` +
      `<script>${fs.readFileSync(builderPath, "utf8")}</script>`
    );
  } catch (e) {
    console.warn(
      "  ⚠ Excel export unavailable — npm install exceljs (" +
        (e && e.message) +
        ")"
    );
    return "";
  }
}

function renderHtml(data) {
  const json = renderJsonPayload(data);
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>${escapeHtml(data.meta.brand)} — Security Findings</title>
<!-- No external resources: the report carries tenant data and is opened on
     customer / air-gapped machines, so it must not call out (fonts included). -->
${inlineJsPdf()}
${inlineXlsxExport()}
<script>
(function () {
  try {
    var t = localStorage.getItem("entraCollectTheme");
    document.documentElement.setAttribute("data-theme", t === "dark" ? "dark" : "light");
  } catch (e) {
    document.documentElement.setAttribute("data-theme", "light");
  }
})();
</script>
<style>
:root, [data-theme="light"] {
  --font-display: "Sora", "Segoe UI Variable Display", "Segoe UI", system-ui, sans-serif;
  --font-body: "IBM Plex Sans", "Segoe UI", system-ui, -apple-system, sans-serif;
  --ink: #f1f4f9; --ink-2: #ffffff; --surface: #ffffff; --surface-2: #e8eef6;
  --border: #d5dee9; --muted: #5a6b82; --text: #0f1b2d;
  --accent: #0f766e; --accent-dim: #0d9488; --accent-soft: rgba(15,118,110,.1);
  --warn: #b45309; --danger: #b91c1c; --success: #15803d; --info: #0369a1;
  --card-bg: #ffffff; --card-bg-soft: #f8fafc;
  --glow: rgba(15,118,110,.1); --grid-line: rgba(15,27,45,.05);
  --priority-now-bg: rgba(185,28,28,.06); --priority-next-bg: rgba(180,83,9,.06);
  --row-hover: rgba(15,118,110,.05); --gauge-track: #d5dee9;
  --scrollbar: #c5d0de;
}
[data-theme="dark"] {
  --ink: #0a0f1a; --ink-2: #0f1623; --surface: #141c2b; --surface-2: #1a2436;
  --border: #243044; --muted: #8b9bb4; --text: #e8eef7;
  --accent: #2dd4bf; --accent-dim: #14b8a6; --accent-soft: rgba(45,212,191,.1);
  --warn: #f59e0b; --danger: #ef4444; --success: #22c55e; --info: #38bdf8;
  --card-bg: rgba(20,28,43,.92); --card-bg-soft: rgba(15,22,35,.65);
  --glow: rgba(45,212,191,.12); --grid-line: rgba(36,48,68,.35);
  --priority-now-bg: rgba(239,68,68,.07); --priority-next-bg: rgba(245,158,11,.05);
  --row-hover: rgba(26,36,54,.55); --gauge-track: #243044;
  --scrollbar: #2a3a52;
}
* { box-sizing: border-box; }
html, body { margin: 0; min-height: 100%; }
body { font-family: var(--font-body); background: var(--ink); color: var(--text); -webkit-font-smoothing: antialiased; }
h1,h2,h3 { font-family: var(--font-display); letter-spacing: -0.02em; margin: 0; }
button { font-family: inherit; cursor: pointer; }
::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-thumb { background: var(--scrollbar); border-radius: 999px; }
.shell { display: flex; min-height: 100vh; }
.sidebar {
  position: sticky; top: 0; height: 100vh; width: 270px; flex-shrink: 0;
  border-right: 1px solid var(--border); background: var(--ink-2);
  display: flex; flex-direction: column;
}
.brand { border-bottom: 1px solid var(--border); padding: 1.15rem 1.2rem; }
.brand-title { font-family: var(--font-display); font-weight: 600; font-size: 1.05rem; }
.brand-sub { font-size: 10px; text-transform: uppercase; letter-spacing: .14em; color: var(--muted); margin-top: 4px; }
.nav { flex: 1; overflow: auto; padding: 1rem .75rem; }
.nav-label { font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: .16em; color: var(--muted); padding: .25rem .75rem; margin: .75rem 0 .35rem; }
.nav button {
  width: 100%; text-align: left; border: 0; background: transparent; color: var(--muted);
  border-radius: 10px; padding: .65rem .85rem; display: block; margin-bottom: 2px;
}
.nav button:hover { background: var(--surface-2); color: var(--text); }
.nav button.active { background: var(--accent-soft); color: var(--accent); }
.nav button .desc { display: block; font-size: 11px; color: var(--muted); margin-top: 2px; }
.nav button .pill {
  float: right; font-size: 10px; background: var(--surface-2); color: var(--muted);
  border-radius: 6px; padding: 1px 6px; margin-top: 2px;
}
.side-foot { border-top: 1px solid var(--border); padding: .85rem; font-size: 12px; color: var(--muted); }
.main { flex: 1; min-width: 0; }
.bg-grid {
  background-image:
    radial-gradient(ellipse 80% 50% at 50% -20%, var(--glow), transparent),
    linear-gradient(var(--grid-line) 1px, transparent 1px),
    linear-gradient(90deg, var(--grid-line) 1px, transparent 1px);
  background-size: auto, 48px 48px, 48px 48px;
  min-height: 100%; padding: 2rem;
}
.page-header { display: flex; flex-wrap: wrap; justify-content: space-between; gap: 1rem; align-items: end; margin-bottom: 1.5rem; }
.page-header h1 {
  font-size: 1.85rem; font-weight: 600;
  background: linear-gradient(90deg, var(--text), var(--accent));
  -webkit-background-clip: text; background-clip: text; color: transparent;
}
.page-header p { color: var(--muted); font-size: .9rem; max-width: 44rem; margin-top: .4rem; }
.actions { display: flex; gap: .5rem; flex-wrap: wrap; }
.btn {
  border-radius: 10px; border: 1px solid var(--border); background: var(--surface);
  color: var(--text); padding: .55rem 1rem; font-size: .875rem; font-weight: 600;
}
.btn:hover { border-color: var(--accent-dim); }
.btn-accent { background: var(--accent); color: #fff; border-color: transparent; }
[data-theme="dark"] .btn-accent { color: var(--ink); }
.grid { display: grid; gap: 1rem; }
.grid-4 { grid-template-columns: repeat(4, minmax(0, 1fr)); }
.grid-3 { grid-template-columns: repeat(3, minmax(0, 1fr)); }
.grid-2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
.grid-5 { grid-template-columns: repeat(5, minmax(0, 1fr)); }
@media (max-width: 1100px) {
  .grid-4, .grid-3, .grid-5 { grid-template-columns: repeat(2, 1fr); }
  .sidebar { width: 220px; }
}
@media (max-width: 800px) {
  .grid-4, .grid-3, .grid-2, .grid-5 { grid-template-columns: 1fr; }
  .sidebar { display: none; }
}
.card {
  border: 1px solid var(--border); background: var(--card-bg);
  border-radius: 14px; padding: 1rem 1.1rem;
}
.card h2 { font-size: 1.05rem; margin-bottom: .75rem; }
.card h3 { font-size: .95rem; margin: .5rem 0 .4rem; }
.stat-label { font-size: 11px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); }
.stat-value { font-family: var(--font-display); font-size: 1.75rem; font-weight: 600; margin-top: .35rem; }
.stat-hint { font-size: 12px; color: var(--muted); margin-top: .25rem; }
.tone-danger { border-color: color-mix(in srgb, var(--danger) 35%, var(--border)); }
.tone-warn { border-color: color-mix(in srgb, var(--warn) 35%, var(--border)); }
.tone-success { border-color: color-mix(in srgb, var(--success) 35%, var(--border)); }
.tone-info { border-color: color-mix(in srgb, var(--info) 30%, var(--border)); }
.badge {
  display: inline-flex; align-items: center; border-radius: 6px;
  padding: .15rem .5rem; font-size: 11px; font-weight: 600;
}
.badge-danger { background: color-mix(in srgb, var(--danger) 14%, transparent); color: var(--danger); }
.badge-warn { background: color-mix(in srgb, var(--warn) 14%, transparent); color: var(--warn); }
.badge-success { background: color-mix(in srgb, var(--success) 14%, transparent); color: var(--success); }
.badge-info { background: color-mix(in srgb, var(--info) 14%, transparent); color: var(--info); }
.badge-muted { background: var(--surface-2); color: var(--muted); }
.gauge-wrap { display: flex; flex-direction: column; align-items: center; gap: .5rem; }
.gauge { width: 140px; height: 140px; position: relative; }
.gauge svg { transform: rotate(-90deg); }
.gauge-center {
  position: absolute; inset: 0; display: grid; place-items: center;
  font-family: var(--font-display); font-size: 2rem; font-weight: 700;
}
.toolbar { display: flex; flex-wrap: wrap; gap: .5rem; margin-bottom: 1rem; align-items: center; }
.toolbar input, .toolbar select {
  background: var(--ink-2); border: 1px solid var(--border); color: var(--text);
  border-radius: 10px; padding: .5rem .75rem; font-size: .875rem;
}
.toolbar input { min-width: 220px; }
.ss-cat {
  border: 1px solid var(--border);
  background: var(--surface);
  color: var(--muted);
  border-radius: 6px;
  padding: .35rem .7rem;
  font-size: 12px;
}
.ss-cat:hover { color: var(--text); }
.ss-cat.active {
  background: var(--accent-soft);
  color: var(--accent);
  border-color: color-mix(in srgb, var(--accent) 35%, var(--border));
}
table { width: 100%; border-collapse: collapse; font-size: .82rem; }
th, td { text-align: left; padding: .6rem .65rem; border-bottom: 1px solid var(--border); vertical-align: top; }
th { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .06em; }
tr:hover td { background: var(--row-hover); }
.muted { color: var(--muted); }
.section { display: none; }
.section.active { display: block; animation: fade-up .35s ease both; }
@keyframes fade-up { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }
.finding-card {
  border: 1px solid var(--border); background: var(--card-bg-soft);
  border-radius: 12px; padding: .85rem 1rem; margin-bottom: .55rem;
}
.finding-card.priority-now { border-color: color-mix(in srgb, var(--danger) 45%, var(--border)); background: var(--priority-now-bg); }
.finding-card.priority-next { border-color: color-mix(in srgb, var(--warn) 35%, var(--border)); background: var(--priority-next-bg); }
.finding-card .top { display: flex; flex-wrap: wrap; gap: .45rem; align-items: center; margin-bottom: .35rem; }
.finding-card.compact { opacity: .92; padding: .55rem .75rem; font-size: .86rem; }
.finding-card.compact .dash-fix { display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
.evidence {
  border-left: 2px solid color-mix(in srgb, var(--muted) 35%, transparent); padding: .1rem 0 .1rem .7rem;
  margin: 0 0 .6rem; font-size: 12.5px;
}
.evidence-h { text-transform: uppercase; letter-spacing: .05em; font-size: 10.5px;
  color: var(--muted); margin-bottom: .3rem; font-weight: 600; }
.evidence-one { color: var(--muted); word-break: break-word; }
.evidence-list { list-style: none; margin: 0; padding: 0; }
.evidence-list li {
  color: var(--muted); padding: .18rem 0; word-break: break-word;
  border-bottom: 1px solid color-mix(in srgb, var(--muted) 12%, transparent); line-height: 1.45;
}
.evidence-list li:last-child { border-bottom: 0; }
.evidence-more > summary {
  cursor: pointer; color: var(--accent); font-size: 11.5px;
  padding: .3rem 0; list-style: none;
}
.evidence-more > summary::-webkit-details-marker { display: none; }
.evidence-more > summary::before { content: "▸ "; }
.evidence-more[open] > summary::before { content: "▾ "; }
.remediation { font-size: 13px; line-height: 1.5; margin-bottom: .5rem; }
.remediation strong { color: var(--accent); display: block; text-transform: uppercase;
  letter-spacing: .05em; font-size: 10.5px; margin-bottom: .15rem; }
.narr-foot { display: flex; flex-wrap: wrap; gap: .5rem; align-items: center; margin-top: .5rem; }
.narr-foot .files { font-size: 11px; word-break: break-word; }
.btn-sm { padding: .2rem .55rem; font-size: 11.5px; }
.prio-lane {
  border: 1px solid var(--border); border-radius: 14px; padding: .85rem 1rem;
  margin-bottom: 1rem; background: var(--card-bg-soft);
}
.prio-lane h3 {
  margin: 0 0 .65rem; font-family: var(--font-display); font-size: .95rem;
  letter-spacing: .02em; display: flex; align-items: center; gap: .5rem;
}
.prio-lane.now { border-color: color-mix(in srgb, var(--danger) 40%, var(--border)); }
.prio-lane.next { border-color: color-mix(in srgb, var(--warn) 35%, var(--border)); }
.prio-lane.later { border-color: color-mix(in srgb, var(--muted) 25%, var(--border)); }
tr.row-pass td { opacity: .55; }
tr.row-pass:hover td { opacity: .85; }
details.pass-fold {
  border: 1px solid var(--border); border-radius: 12px; padding: .65rem .85rem;
  background: var(--card-bg-soft); margin-top: .75rem;
}
details.pass-fold summary {
  cursor: pointer; color: var(--muted); font-size: .88rem; list-style: none;
}
details.pass-fold summary::-webkit-details-marker { display: none; }
details.pass-fold[open] summary { margin-bottom: .65rem; color: var(--text); }
.area-card { cursor: pointer; transition: border-color .15s; }
.area-card:hover { border-color: var(--accent); }
.bar { height: 6px; border-radius: 99px; background: var(--surface-2); overflow: hidden; margin-top: .55rem; }
.bar > span { display: block; height: 100%; border-radius: 99px; }
.callout {
  border-left: 3px solid var(--warn); background: color-mix(in srgb, var(--warn) 8%, transparent);
  border-radius: 0 10px 10px 0; padding: .75rem 1rem; margin-bottom: 1rem; font-size: .88rem;
}
.callout.danger { border-left-color: var(--danger); background: color-mix(in srgb, var(--danger) 8%, transparent); }
.callout.info { border-left-color: var(--info); background: color-mix(in srgb, var(--info) 8%, transparent); }
.callout.success { border-left-color: var(--success); background: color-mix(in srgb, var(--success) 8%, transparent); }
.hero-score {
  display: grid; grid-template-columns: 160px 1fr; gap: 1.25rem; align-items: center;
}
@media (max-width: 800px) { .hero-score { grid-template-columns: 1fr; } }
.sev-chips { display: flex; flex-wrap: wrap; gap: .45rem; margin: .65rem 0; }
.sev-chip {
  border: 1px solid var(--border); border-radius: 999px; padding: .25rem .7rem;
  font-size: 12px; font-weight: 600; background: var(--surface);
}
.dash-fix { color: var(--muted); font-size: 12px; line-height: 1.4; margin-top: .2rem; }
.action-table td:last-child { white-space: nowrap; }
.view-toggle .ss-cat { cursor: pointer; }
.narr-area { font-size: 11px; color: var(--muted); letter-spacing: .04em; text-transform: uppercase; }
.finding-actions { display: flex; flex-wrap: wrap; gap: .35rem; margin-top: .45rem; }
.sticky-prio {
  position: sticky; top: 0; z-index: 2; background: var(--ink); padding: .55rem 0;
  border-bottom: 1px solid var(--border); margin: 1rem 0 .65rem;
  font-family: var(--font-display); font-size: .95rem;
}
.checklist-box {
  border: 1px solid var(--border); border-radius: 12px; padding: .75rem 1rem;
  background: var(--card-bg); margin-bottom: .75rem;
}
.checklist-box label {
  display: flex; gap: .55rem; align-items: flex-start; padding: .35rem 0;
  border-bottom: 1px solid color-mix(in srgb, var(--border) 70%, transparent);
  font-size: .88rem; cursor: pointer;
}
.checklist-box label:last-child { border-bottom: 0; }
.checklist-box input { margin-top: .2rem; }
.copied-flash { outline: 2px solid var(--accent); }
@media print {
  .sidebar, .actions, .toolbar, #btnTheme { display: none !important; }
  .shell { display: block; }
  .bg-grid { background: #fff; color: #0f172a; }
  body { background: #fff; color: #0f172a; }
}
</style>
</head>
<body>
<div class="shell">
  <aside class="sidebar">
    <div class="brand">
      <div class="brand-title">${escapeHtml(data.meta.brand)}</div>
      <div class="brand-sub">${escapeHtml(data.meta.tagline || "Identity & M365 attack-path assessment")}</div>
    </div>
    <nav class="nav" id="nav">
      <div class="nav-label">Overview</div>
      <button type="button" data-section="dashboard" class="active">Dashboard<span class="desc">KPIs &amp; coverage</span></button>
      <button type="button" data-section="narratives">Expert findings<span class="desc" id="navNarrCount">Correlated attack paths</span></button>
      <button type="button" data-section="categories">Inventory categories<span class="desc" id="navCatCount">Raw check areas</span></button>
      <button type="button" data-section="findings">Inventory findings<span class="desc" id="navFindCount"></span></button>
      <button type="button" data-section="limits">Limitations<span class="desc" id="navErrCount">Access / schema gaps</span></button>
      <div class="nav-label">Deep dives</div>
      <button type="button" data-section="attackpath">Attack path<span class="desc" id="navApCount">Gaps only</span></button>
      <button type="button" data-section="ca">Conditional Access</button>
      <button type="button" data-section="users">Users &amp; MFA<span class="desc" id="navUsersCount"></span></button>
      <button type="button" data-section="identity">Sign-in signals</button>
      <button type="button" data-section="devices">Devices<span class="desc" id="navDevCount"></span></button>
      <button type="button" data-section="endpoints">Endpoints<span class="desc">RMM / GenAI / share</span></button>
      <button type="button" data-section="collab">Mail &amp; collab<span class="desc">Anti-spam / Teams</span></button>
      <button type="button" data-section="privileged">Privileged</button>
      <button type="button" data-section="apps">Apps</button>
      <button type="button" data-section="score">Secure Score</button>
      <button type="button" data-section="schema">Hunting schema</button>
    </nav>
    <div class="side-foot" id="sideMeta"></div>
  </aside>
  <main class="main">
    <div class="bg-grid">
      <div class="page-header">
        <div>
          <h1 id="pageTitle">Security Dashboard</h1>
          <p id="pageSub">Findings from Entra Collect — including what could not be checked due to rights or schema.</p>
        </div>
        <div class="actions">
          <button type="button" class="btn" id="btnTheme" title="Toggle light / dark">Theme</button>
          <button type="button" class="btn" id="btnPrint">Print</button>
          <button type="button" class="btn" id="btnXlsx" title="Remediation workbook for steering (Owner / Status / Due)">Export Excel</button>
          <button type="button" class="btn btn-accent" id="btnPdf">Download PDF</button>
        </div>
      </div>
      <section id="sec-dashboard" class="section active"></section>
      <section id="sec-narratives" class="section"></section>
      <section id="sec-categories" class="section"></section>
      <section id="sec-findings" class="section"></section>
      <section id="sec-limits" class="section"></section>
      <section id="sec-attackpath" class="section"></section>
      <section id="sec-ca" class="section"></section>
      <section id="sec-users" class="section"></section>
      <section id="sec-identity" class="section"></section>
      <section id="sec-devices" class="section"></section>
      <section id="sec-endpoints" class="section"></section>
      <section id="sec-collab" class="section"></section>
      <section id="sec-privileged" class="section"></section>
      <section id="sec-apps" class="section"></section>
      <section id="sec-score" class="section"></section>
      <section id="sec-schema" class="section"></section>
    </div>
  </main>
</div>
<script id="report-data" type="application/json">${json}</script>
<script>
window.__REPORT__ = JSON.parse(document.getElementById("report-data").textContent);
(function () {
  const D = window.__REPORT__;
  const S = D.summary || {};

  function esc(s) {
    return String(s ?? "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
  }
  function badge(sev, opts) {
    const t = String(sev || "").toLowerCase();
    const mutePass = opts && opts.mutePass && t === "pass";
    const map = {
      high:"danger", critical:"danger", medium:"warn", low:"info", info:"info",
      pass:"muted", fail:"danger", partial:"warn", unknown:"warn",
      notevaluated:"warn", notapplicable:"muted", "n/a":"muted",
      now:"danger", next:"warn", later:"muted",
      enabled:"warn", disabled:"success",
      available:"success", runnable:"success", skipped:"warn", unavailable:"danger",
      forbidden:"danger"
    };
    const tone = mutePass ? "muted" : (map[t] || "muted");
    const label = t === "pass" ? "OK" : sev;
    return '<span class="badge badge-' + tone + '">' + esc(label) + '</span>';
  }
  function statusRank(s) {
    const t = String(s || "").toLowerCase();
    if (t === "fail") return 0;
    if (t === "partial") return 1;
    if (t === "skip" || t === "notevaluated" || t === "unknown") return 2;
    if (t === "pass") return 3;
    if (t === "notapplicable") return 5;
    return 4;
  }
  /** Deep-dive section holding the tables behind each narrative family. */
  const NARR_SECTION = [
    [/^NARR\.(App|Consent)\./i, "apps", "Apps"],
    [/^NARR\.Priv\./i, "privileged", "Privileged"],
    [/^NARR\.CA\./i, "ca", "Conditional Access"],
    [/^NARR\.(MFA|Identity|Guest)\./i, "users", "Users & MFA"],
    [/^NARR\.(DeviceCode|Legacy|Risk)\./i, "identity", "Sign-in signals"],
    [/^NARR\.(Endpoint|Cloud)\./i, "endpoints", "Endpoints"],
    [/^NARR\.Mail\./i, "collab", "Mail & collab"],
    [/^NARR\.Devices\./i, "devices", "Devices"],
    [/^NARR\.SecureScore\./i, "score", "Secure Score"],
  ];
  function deepDiveFor(id) {
    const hit = NARR_SECTION.find(([re]) => re.test(id || ""));
    return hit ? { section: hit[1], label: hit[2] } : null;
  }

  function areaFromId(id) {
    const m = String(id || "").match(/^NARR\\.([^.]+)/i);
    return m ? m[1] : "";
  }
  function copyText(text, el) {
    const t = String(text || "");
    if (!t) return;
    const done = () => {
      if (el) {
        el.classList.add("copied-flash");
        setTimeout(() => el.classList.remove("copied-flash"), 700);
      }
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(t).then(done).catch(() => {});
    } else {
      const ta = document.createElement("textarea");
      ta.value = t; document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); } catch (e) {}
      document.body.removeChild(ta); done();
    }
  }
  /**
   * Evidence is a " | "-joined list. Keep the first items visible; collapse the rest.
   */
  function evidenceBlock(evidence, opts) {
    if (!evidence) return "";
    const collapsed = !(opts && opts.open);
    const items = String(evidence).split(" | ").map(s => s.trim()).filter(Boolean);
    if (items.length <= 1) {
      return '<div class="evidence"><div class="evidence-h">Evidence</div>' +
        '<div class="evidence-one">' + esc(evidence) + '</div></div>';
    }
    const li = (s) => '<li>' + esc(s) + '</li>';
    const headN = collapsed ? 3 : 5;
    const head = items.slice(0, headN);
    const tail = items.slice(headN);
    return '<div class="evidence"><div class="evidence-h">Evidence <span class="muted">(' +
      items.length + ')</span></div><ul class="evidence-list">' + head.map(li).join("") + '</ul>' +
      (tail.length
        ? '<details class="evidence-more"' + (collapsed ? "" : " open") + '><summary>Show ' + tail.length + ' more</summary>' +
          '<ul class="evidence-list">' + tail.map(li).join("") + '</ul></details>'
        : "") + '</div>';
  }

  function narrCard(n, compact) {
    const tone = /critical/i.test(n.Severity) ? "danger" : /high/i.test(n.Severity) ? "danger" : /medium/i.test(n.Severity) ? "warn" : "info";
    const prio = String(n.Priority || "").toLowerCase();
    const prioClass = prio === "now" ? " priority-now" : prio === "next" ? " priority-next" : "";
    const dd = deepDiveFor(n.Id);
    const area = areaFromId(n.Id);
    const aid = "narr-" + String(n.Id || "").replace(/[^a-zA-Z0-9._-]/g, "_");
    const body = compact
      ? '<div class="dash-fix">' + esc((n.Narrative||"").slice(0, 140)) +
        ((n.Narrative||"").length > 140 ? "…" : "") + '</div>' +
        '<div class="finding-actions">' +
          '<button type="button" class="btn btn-sm" data-open-narr="' + esc(n.Id) + '">Open</button>' +
        '</div>'
      : '<div style="margin-bottom:.55rem;line-height:1.45">' + esc(n.Narrative) + '</div>' +
        (n.Remediation
          ? '<div class="remediation"><strong>Fix</strong> ' + esc(n.Remediation) + '</div>'
          : '') +
        '<details class="evidence-more" style="margin:.35rem 0 .5rem"><summary>Evidence &amp; files</summary>' +
          evidenceBlock(n.Evidence, { open: true }) +
          (n.RelatedFiles ? '<div class="muted files" style="margin-top:.35rem">' + esc(n.RelatedFiles) + '</div>' : '') +
        '</details>' +
        '<div class="narr-foot finding-actions">' +
          (dd ? '<button type="button" class="btn btn-sm" data-jump="' + dd.section + '">Deep dive: ' + esc(dd.label) + '</button>' : '') +
          '<button type="button" class="btn btn-sm" data-copy-fix="' + esc(n.Id) + '">Copy fix</button>' +
          '<button type="button" class="btn btn-sm" data-copy-finding="' + esc(n.Id) + '">Copy finding</button>' +
        '</div>';
    return '<div class="finding-card tone-' + tone + prioClass + (compact ? " compact" : "") +
      '" id="' + aid + '" data-narr-id="' + esc(n.Id) + '"><div class="top">' +
      (n.Priority ? badge(n.Priority) : "") + badge(n.Severity) +
      (area ? '<span class="narr-area">' + esc(area) + '</span>' : '') +
      '<span class="badge badge-muted">' + esc(n.Id) + '</span></div>' +
      '<div style="font-weight:600;margin:.35rem 0;font-family:var(--font-display)">' + esc(n.Title) + '</div>' +
      body + '</div>';
  }
  function narrActionRow(n) {
    return '<tr>' +
      '<td>' + (n.Priority ? badge(n.Priority) : "") + '</td>' +
      '<td>' + badge(n.Severity) + '</td>' +
      '<td><strong>' + esc(n.Title) + '</strong>' +
        '<div class="dash-fix">' + esc((n.Narrative || "").slice(0, 110)) +
        ((n.Narrative || "").length > 110 ? "…" : "") + '</div></td>' +
      '<td class="dash-fix">' + esc((n.Remediation || "").slice(0, 140)) +
        ((n.Remediation || "").length > 140 ? "…" : "") + '</td>' +
      '<td><button type="button" class="btn btn-sm" data-open-narr="' + esc(n.Id) + '">Open</button></td></tr>';
  }
  function toneCard(label, value, hint, tone) {
    return '<div class="card tone-' + (tone||"info") + '"><div class="stat-label">' + esc(label) +
      '</div><div class="stat-value">' + esc(value) + '</div>' +
      (hint ? '<div class="stat-hint">' + esc(hint) + '</div>' : '') + '</div>';
  }
  function table(headers, rows, renderCell) {
    if (!rows || !rows.length) return '<p class="muted">No data in this export.</p>';
    let h = '<div style="overflow:auto"><table><thead><tr>' +
      headers.map(x => '<th>' + esc(x) + '</th>').join('') + '</tr></thead><tbody>';
    for (const r of rows) {
      h += '<tr>' + headers.map((hdr,i) => '<td>' + (renderCell ? renderCell(r,hdr,i) : esc(r[hdr])) + '</td>').join('') + '</tr>';
    }
    return h + '</tbody></table></div>';
  }
  /** Filterable card with live search over row values */
  function dataCard(title, totalHint, headers, rows, renderCell) {
    const id = "ft-" + Math.random().toString(36).slice(2, 9);
    const n = (rows || []).length;
    const hint = totalHint != null && totalHint > n
      ? totalHint + " total · showing " + n
      : n + " row" + (n === 1 ? "" : "s");
    return '<div class="card" style="margin-bottom:1rem" data-ft="' + id + '">' +
      '<div style="display:flex;flex-wrap:wrap;gap:.5rem;align-items:center;justify-content:space-between;margin-bottom:.5rem">' +
        '<h2 style="margin:0">' + esc(title) + '</h2>' +
        '<span class="muted" style="font-size:12px" data-ft-count="' + id + '">' + esc(hint) + '</span></div>' +
      '<div class="toolbar" style="margin-bottom:.5rem">' +
        '<input data-ft-filter="' + id + '" placeholder="Filter this table…" style="max-width:280px" />' +
      '</div>' +
      '<div data-ft-body="' + id + '">' + table(headers, rows, renderCell) + '</div></div>';
  }
  function wireFilters() {
    document.querySelectorAll("[data-ft-filter]").forEach(inp => {
      if (inp._wired) return;
      inp._wired = true;
      inp.addEventListener("input", () => {
        const id = inp.getAttribute("data-ft-filter");
        const q = (inp.value || "").toLowerCase();
        const body = document.querySelector('[data-ft-body="' + id + '"]');
        if (!body) return;
        let shown = 0, total = 0;
        body.querySelectorAll("tbody tr").forEach(tr => {
          total++;
          const hit = !q || tr.textContent.toLowerCase().includes(q);
          tr.style.display = hit ? "" : "none";
          if (hit) shown++;
        });
        const c = document.querySelector('[data-ft-count="' + id + '"]');
        if (c) c.textContent = shown + " / " + total + " shown";
      });
    });
  }
  function scoreColor(score) {
    if (score >= 75) return "#22c55e";
    if (score >= 50) return "#f59e0b";
    return "#ef4444";
  }
  function gauge(score) {
    const c = scoreColor(score);
    const track = getComputedStyle(document.documentElement).getPropertyValue("--gauge-track").trim() || "#d5dee9";
    const r = 54, circ = 2 * Math.PI * r, off = circ - (score/100)*circ;
    return '<div class="gauge-wrap"><div class="gauge"><svg viewBox="0 0 128 128" width="140" height="140">' +
      '<circle cx="64" cy="64" r="'+r+'" fill="none" stroke="'+track+'" stroke-width="10"/>' +
      '<circle cx="64" cy="64" r="'+r+'" fill="none" stroke="'+c+'" stroke-width="10" stroke-linecap="round" stroke-dasharray="'+circ+'" stroke-dashoffset="'+off+'"/>' +
      '</svg><div class="gauge-center" style="color:'+c+'">'+score+'</div></div>' +
      '<div class="muted" style="font-size:11px;text-transform:uppercase;letter-spacing:.1em">Posture score</div></div>';
  }
  function openNarr(id) {
    go("narratives");
    const sel = document.getElementById("narrPrio");
    const sev = document.getElementById("narrSev");
    const filt = document.getElementById("narrFilter");
    if (sel) sel.value = "";
    if (sev) sev.value = "";
    if (filt) filt.value = "";
    if (typeof renderNarratives === "function") renderNarratives();
    setTimeout(() => {
      const el = document.querySelector('[data-narr-id="' + CSS.escape(id) + '"]');
      if (el) {
        el.scrollIntoView({ behavior: "smooth", block: "start" });
        el.classList.add("copied-flash");
        setTimeout(() => el.classList.remove("copied-flash"), 1200);
      }
    }, 60);
  }
  function go(section) {
    document.querySelectorAll("#nav button").forEach(b => b.classList.toggle("active", b.dataset.section === section));
    document.querySelectorAll(".section").forEach(s => s.classList.remove("active"));
    document.getElementById("sec-" + section).classList.add("active");
    const titles = {
      dashboard: ["Security Dashboard", "Expert posture score from correlated narratives — inventory checks stay under Inventory tabs."],
      narratives: ["Expert findings", "Static correlation rules joining privileged, CA, apps, and sign-in evidence into attack narratives."],
      categories: ["Inventory categories", "Every Area from 00_Findings.csv (raw collector checks)."],
      findings: ["Inventory findings", "Filterable list of every collector finding (includes Info / skips)."],
      limits: ["Limitations & access gaps", "ERROR_* files, hunting schema, and skipped checks — not a clean bill of health."],
      attackpath: ["Attack-path checklist", "Gaps first (Fail / Partial). Passed controls are collapsed — they are not findings."],
      ca: ["Conditional Access", "Policies, coverage, exclusion groups."],
      users: ["Users & MFA", "No MFA, phone-only MFA, inactive accounts, guests, passkeys / phishing-resistant."],
      identity: ["Sign-in signals", "Device code, legacy auth, risky users."],
      devices: ["Devices", "Stale joined, registered-only, and per-user PC / phone / tablet inventory."],
      endpoints: ["Endpoints", "RMM, GenAI volume, file-sharing, TVM CVEs, patch lag — when Hunting is available."],
      collab: ["Mail & collaboration", "Anti-spam checklist, email hunting samples, outbound domains, Teams guest settings, log retention notes."],
      privileged: ["Privileged access", "High-value roles plus the full directory assignment inventory (readers included)."],
      apps: ["Applications", "Dangerous Graph permissions, path-to-GA, owners, secrets, wildcards."],
      score: ["Secure Score", "In-scope Microsoft Secure Score by category (Identity / Apps / Data) — not the full product catalog."],
      schema: ["Hunting schema", "Tables and capabilities probed this run."]
    };
    document.getElementById("pageTitle").textContent = titles[section][0];
    document.getElementById("pageSub").textContent = titles[section][1];
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  const CS = D.checklistStats || { fail: 0, partial: 0, pass: 0, total: 0 };
  document.getElementById("sideMeta").innerHTML =
    '<div><strong style="color:var(--text)">' + esc(D.meta.outputDir) + '</strong></div>' +
    '<div style="margin-top:4px">' + esc((S.collectedAt || D.meta.generatedAt || "").slice(0,19).replace("T"," ")) + '</div>' +
    '<div style="margin-top:6px">' + esc((D.narratives||[]).length) + ' expert · ' +
      esc(CS.fail) + ' gaps · ' + esc(D.findings.length) + ' inventory</div>';

  document.getElementById("navNarrCount").textContent = (D.narratives||[]).length + " prioritized";
  document.getElementById("navFindCount").textContent = D.findings.length + " items";
  document.getElementById("navCatCount").textContent = (D.byArea||[]).length + " areas";
  document.getElementById("navApCount").textContent =
    CS.fail + " fail · " + CS.partial + " partial";
  document.getElementById("navErrCount").textContent =
    D.errors.length + " errors" + (!S.huntingCanHunt ? " · hunting blocked" : "");

  // ── Dashboard
  const crit = D.sevCount.Critical || 0, high = D.sevCount.High || 0, med = D.sevCount.Medium || 0;
  const limitNote = !S.huntingCanHunt
    ? '<div class="callout danger"><strong>Hunting limited:</strong> Advanced Hunting API is <em>' +
      esc(S.huntingApiStatus || "unavailable") +
      '</em>. RMM / AI / patch / TVM / EmailEvents were not assessed as clean — they were <strong>skipped</strong>. See Limitations.</div>'
    : '';
  const errNote = D.errors.length
    ? '<div class="callout"><strong>' + D.errors.length +
      ' Graph/API calls failed</strong> (often 403 missing roles/scopes). Open <button type="button" class="btn" style="padding:.2rem .5rem;margin-left:.35rem" data-jump="limits">Limitations</button></div>'
    : '';

  // Counts derived from a failed export are unknown, not zero — say so up front
  // rather than letting the dashboard read as a clean tenant.
  const COL = D.collection || {};
  const failedSteps = COL.failedSteps || [];
  // A 401/403 is a missing role, not a glitch: re-running changes nothing, so
  // the two causes need different advice.
  const deniedSteps = failedSteps.filter(s => s.httpStatus === 401 || s.httpStatus === 403);
  const retrySteps = failedSteps.filter(s => s.httpStatus !== 401 && s.httpStatus !== 403);
  const stepList = (steps) =>
    '<div class="muted" style="margin-top:.35rem;font-size:12px">' +
    steps.slice(0, 8).map(s => esc(s.label)).join(" · ") +
    (steps.length > 8 ? ' · +' + (steps.length - 8) + ' more' : '') + '</div>';

  const incompleteNote = failedSteps.length
    ? '<div class="callout danger"><strong>Incomplete collection: ' + failedSteps.length +
      ' step(s) failed.</strong> Counts for those areas are <em>unknown</em>, not zero.' +
      (deniedSteps.length
        ? '<div style="margin-top:.5rem">' + deniedSteps.length +
          ' blocked by <strong>missing permissions</strong> (HTTP 401/403) — these need an additional role, not a re-run.' +
          stepList(deniedSteps) + '</div>'
        : '') +
      (retrySteps.length
        ? '<div style="margin-top:.5rem">' + retrySteps.length +
          ' possibly transient — retry with <code>--resume ' + esc(D.meta.outputDir) + '</code>.' +
          stepList(retrySteps) + '</div>'
        : '') +
      '</div>'
    : (COL.available === false
      ? '<div class="callout"><strong>No collection manifest.</strong> This export predates per-artifact status tracking, so empty tables cannot be distinguished from failed collection steps.</div>'
      : '');

  /** Artifact status from the manifest: ok | empty | failed | partial | absent. */
  function artifactStatus(name) {
    const a = (COL.artifacts || {})[name];
    return a ? a.status : COL.available ? "absent" : "unknown";
  }
  /** Green is only honest when we know the source was really read. */
  function countTone(value, artifact) {
    const st = artifact ? artifactStatus(artifact) : "ok";
    if (st === "failed" || st === "absent") return "warn";
    return value ? "danger" : "success";
  }
  function countLabel(value, artifact) {
    const st = artifact ? artifactStatus(artifact) : "ok";
    return st === "failed" || st === "absent" ? "n/a" : value;
  }

  const narrByPrio = { Now: [], Next: [], Later: [] };
  for (const n of (D.narratives || [])) {
    const p = n.Priority || ( /critical/i.test(n.Severity) ? "Now" : /high/i.test(n.Severity) ? "Next" : "Later");
    (narrByPrio[p] || narrByPrio.Later).push(n);
  }
  const topActions = [
    ...(narrByPrio.Now || []),
    ...(narrByPrio.Next || []),
  ].slice(0, 10);
  const coverageNotes = [incompleteNote, limitNote, errNote].filter(Boolean).join("");

  const gapRows = (D.attackChecklist || [])
    .filter(r => /fail|partial/i.test(r.Status || ""))
    .sort((a,b) => statusRank(a.Status) - statusRank(b.Status));

  document.getElementById("sec-dashboard").innerHTML =
    '<div class="card" style="margin-bottom:1rem">' +
      '<div class="hero-score">' +
        gauge(D.score) +
        '<div>' +
          '<div class="stat-label">Executive snapshot</div>' +
          '<div style="font-family:var(--font-display);font-size:1.15rem;font-weight:600;margin:.25rem 0 .5rem">Fix Now first — inventory tabs are evidence, not priority</div>' +
          '<div class="sev-chips">' +
            '<span class="sev-chip">' + badge("Critical") + ' ' + crit + '</span>' +
            '<span class="sev-chip">' + badge("High") + ' ' + high + '</span>' +
            '<span class="sev-chip">' + badge("Medium") + ' ' + med + '</span>' +
            '<span class="sev-chip">' + badge("Now") + ' ' + (narrByPrio.Now||[]).length + '</span>' +
            '<span class="sev-chip">' + badge("Next") + ' ' + (narrByPrio.Next||[]).length + '</span>' +
            '<span class="sev-chip">' + badge("Later") + ' ' + (narrByPrio.Later||[]).length + '</span>' +
          '</div>' +
          '<div class="grid grid-4" style="margin-top:.75rem">' +
            toneCard("Checklist gaps", CS.fail + " / " + CS.partial, "fail / partial", CS.fail ? "danger" : CS.partial ? "warn" : "success") +
            toneCard("Blocked", D.errors.length + (!S.huntingCanHunt ? "+hunt" : ""), "access limits", D.errors.length || !S.huntingCanHunt ? "warn" : "success") +
            toneCard("Permanent GAs", S.globalAdminPermanent ?? "n/a", "standing GA", (S.globalAdminPermanent||0)>5?"danger":"info") +
            toneCard("Expert findings", (D.narratives||[]).length, "correlated", (crit||high)?"danger":"info") +
          '</div>' +
        '</div>' +
      '</div>' +
    '</div>' +
    (coverageNotes
      ? '<details class="pass-fold" style="margin-bottom:1rem"><summary>Coverage / collection notes' +
        (failedSteps.length || D.errors.length || !S.huntingCanHunt ? ' <span class="badge badge-warn">review</span>' : '') +
        '</summary>' + coverageNotes + '</details>'
      : '') +
    '<div class="card" style="margin-bottom:1rem">' +
      '<div style="display:flex;flex-wrap:wrap;justify-content:space-between;gap:.5rem;align-items:center;margin-bottom:.65rem">' +
        '<h2 style="margin:0">Top actions</h2>' +
        '<button type="button" class="btn btn-sm" data-jump="narratives">All expert findings →</button></div>' +
      (topActions.length
        ? '<div style="overflow:auto"><table class="action-table"><thead><tr>' +
          '<th>Prio</th><th>Sev</th><th>Finding</th><th>Fix</th><th></th></tr></thead><tbody>' +
          topActions.map(narrActionRow).join("") +
          '</tbody></table></div>' +
          ((narrByPrio.Now||[]).length + (narrByPrio.Next||[]).length > topActions.length
            ? '<p class="muted" style="margin-top:.5rem">Showing ' + topActions.length + ' of ' +
              ((narrByPrio.Now||[]).length + (narrByPrio.Next||[]).length) + ' Now/Next — open Expert findings for the full list.</p>'
            : '')
        : '<p class="muted">No Now/Next expert findings.</p>') +
    '</div>' +
    '<div class="grid grid-2" style="margin-bottom:1rem">' +
      '<div class="card"><h2>Identity pulse</h2>' +
        '<div class="grid grid-2">' +
          (() => {
            const total = Number(S.usersWithoutMfa) || 0;
            const human = Number(S.usersWithoutMfaHuman);
            const humanOk = Number.isFinite(human);
            const label = total && humanOk ? (human + " / " + total) : (S.usersWithoutMfa ?? "n/a");
            return toneCard("No MFA", label, humanOk ? "humans / total" : "registrations", (humanOk ? human : total) >= 100 ? "warn" : total ? "info" : "success");
          })() +
          toneCard("Device-code", S.deviceCodeUsers90d ?? "n/a", "users 90d", Number(S.deviceCodeUsers90d) > 0 ? "danger" : "success") +
          toneCard("Risky users", S.riskyUsersAtRisk ?? "n/a", "", Number(S.riskyUsersAtRisk) > 0 ? "warn" : "success") +
          toneCard("RMM agents", S.rmmAgentAssets ?? S.rmmSuspiciousFamilies ?? "n/a", "desktop signal", Number(S.rmmAgentAssets||S.rmmSuspiciousFamilies||0)?"warn":"info") +
        '</div></div>' +
      '<div class="card"><h2>Attack-path gaps</h2>' +
        (gapRows.length
          ? table(["Status","Title"], gapRows.slice(0, 6), (r,h) =>
              h === "Status" ? badge(r[h]) : esc(r.Title || r.CheckId || r[h])) +
            (gapRows.length > 6
              ? '<button type="button" class="btn btn-sm" style="margin-top:.5rem" data-jump="attackpath">+' + (gapRows.length - 6) + ' more</button>'
              : '')
          : '<div class="callout info" style="margin:0">No Fail/Partial on the checklist — still review Expert findings.</div>') +
      '</div></div>';

  // ── Expert narratives
  const narrAreas = [...new Set((D.narratives || []).map(n => areaFromId(n.Id)).filter(Boolean))].sort();
  document.getElementById("sec-narratives").innerHTML =
    '<div class="callout success"><strong>How to use this tab.</strong> Work <em>Now → Next → Later</em>. Use <strong>Table</strong> for steering (copy Fix / open deep dive). Evidence stays collapsed until you need it.</div>' +
    '<div class="toolbar">' +
      '<input id="narrFilter" placeholder="Filter title, fix, id…" />' +
      '<select id="narrPrio"><option value="">All priorities</option><option>Now</option><option>Next</option><option>Later</option></select>' +
      '<select id="narrSev"><option value="">All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Info</option></select>' +
      '<select id="narrArea"><option value="">All areas</option>' +
        narrAreas.map(a => '<option value="' + esc(a) + '">' + esc(a) + '</option>').join("") +
      '</select>' +
      '<span class="view-toggle" id="narrViewToggle">' +
        '<button type="button" class="ss-cat active" data-view="cards">Cards</button>' +
        '<button type="button" class="ss-cat" data-view="table">Table</button>' +
        '<button type="button" class="ss-cat" data-view="checklist">Checklist</button>' +
      '</span>' +
      '<span class="muted" id="narrCount"></span></div>' +
    '<div id="narrList"></div>';
  let narrView = "cards";
  function filteredNarratives() {
    const q = (document.getElementById("narrFilter").value || "").toLowerCase();
    const sev = document.getElementById("narrSev").value;
    const prio = document.getElementById("narrPrio").value;
    const area = document.getElementById("narrArea").value;
    return (D.narratives || []).filter(n => {
      if (sev && n.Severity !== sev) return false;
      if (prio && n.Priority !== prio) return false;
      if (area && areaFromId(n.Id) !== area) return false;
      const blob = [n.Id, n.Title, n.Narrative, n.Evidence, n.Remediation, n.Priority, areaFromId(n.Id)].join(" ").toLowerCase();
      if (q && !blob.includes(q)) return false;
      return true;
    });
  }
  function renderNarratives() {
    const rows = filteredNarratives();
    document.getElementById("narrCount").textContent = rows.length + " / " + (D.narratives||[]).length;
    const host = document.getElementById("narrList");
    if (!rows.length) {
      host.innerHTML = '<p class="muted">No matches.</p>';
      return;
    }
    if (narrView === "table") {
      host.innerHTML = '<div class="card" style="overflow:auto"><table class="action-table"><thead><tr>' +
        '<th>Prio</th><th>Sev</th><th>Area</th><th>Finding</th><th>Fix</th><th></th></tr></thead><tbody>' +
        rows.map(n =>
          '<tr>' +
          '<td>' + (n.Priority ? badge(n.Priority) : "") + '</td>' +
          '<td>' + badge(n.Severity) + '</td>' +
          '<td class="narr-area">' + esc(areaFromId(n.Id)) + '</td>' +
          '<td><strong>' + esc(n.Title) + '</strong><div class="dash-fix">' + esc(n.Id) + '</div></td>' +
          '<td class="dash-fix">' + esc((n.Remediation || "").slice(0, 180)) + '</td>' +
          '<td style="white-space:nowrap">' +
            '<button type="button" class="btn btn-sm" data-open-narr="' + esc(n.Id) + '">Card</button> ' +
            '<button type="button" class="btn btn-sm" data-copy-fix="' + esc(n.Id) + '">Copy fix</button>' +
          '</td></tr>'
        ).join("") +
        '</tbody></table></div>';
      return;
    }
    if (narrView === "checklist") {
      const groups = { Now: [], Next: [], Later: [] };
      for (const n of rows) {
        const p = n.Priority || "Later";
        (groups[p] || groups.Later).push(n);
      }
      host.innerHTML = ["Now","Next","Later"].map(p => {
        const items = groups[p] || [];
        if (!items.length) return "";
        return '<div class="sticky-prio">' + badge(p) + ' ' + p + ' · ' + items.length + '</div>' +
          '<div class="checklist-box">' +
          items.map(n =>
            '<label><input type="checkbox" data-check-narr="' + esc(n.Id) + '" />' +
            '<span><strong>' + esc(n.Title) + '</strong> ' + badge(n.Severity) +
            '<div class="dash-fix">' + esc((n.Remediation || n.Narrative || "").slice(0, 160)) + '</div>' +
            '<button type="button" class="btn btn-sm" data-open-narr="' + esc(n.Id) + '" style="margin-top:.25rem">Details</button>' +
            '</span></label>'
          ).join("") +
          '</div>';
      }).join("") || '<p class="muted">No matches.</p>';
      return;
    }
    // cards grouped by priority
    const groups = { Now: [], Next: [], Later: [] };
    for (const n of rows) {
      const p = n.Priority || "Later";
      (groups[p] || groups.Later).push(n);
    }
    host.innerHTML = ["Now","Next","Later"].map(p => {
      const items = groups[p] || [];
      if (!items.length) return "";
      return '<div class="sticky-prio">' + badge(p) + ' ' + p + ' · ' + items.length + '</div>' +
        items.map(n => narrCard(n, false)).join("");
    }).join("");
  }
  ["narrFilter","narrSev","narrPrio","narrArea"].forEach(id =>
    document.getElementById(id).addEventListener(id==="narrFilter"?"input":"change", renderNarratives)
  );
  document.getElementById("narrViewToggle").addEventListener("click", (e) => {
    const btn = e.target.closest("[data-view]");
    if (!btn) return;
    narrView = btn.getAttribute("data-view");
    document.querySelectorAll("#narrViewToggle .ss-cat").forEach(b =>
      b.classList.toggle("active", b.getAttribute("data-view") === narrView)
    );
    renderNarratives();
  });
  renderNarratives();

  // ── Categories (all areas)
  document.getElementById("sec-categories").innerHTML =
    '<div class="callout info">Inventory categories are <strong>secondary</strong>. Prefer Expert findings for prioritization. Repeated CA exclusion Highs are aggregated when possible.</div>' +
    '<div id="catList"></div>';

  function renderCategories() {
    const host = document.getElementById("catList");
    host.innerHTML = (D.byArea || []).map((a, idx) => {
      const id = "cat-" + idx;
      return '<div class="card" style="margin-bottom:.75rem" id="' + id + '">' +
        '<div style="display:flex;flex-wrap:wrap;gap:.5rem;align-items:center;justify-content:space-between">' +
          '<h2 style="margin:0">' + esc(a.area) + '</h2>' +
          '<div>' + badge(a.High ? "High" : a.Medium ? "Medium" : "Info") +
          ' <span class="badge badge-muted">' + a.total + ' findings</span>' +
          ' <span class="muted" style="font-size:12px;margin-left:.35rem">' +
          a.High + 'H / ' + a.Medium + 'M / ' + a.Info + 'I</span></div></div>' +
        '<div style="margin-top:.75rem">' +
          a.items.map(f =>
            '<div class="finding-card compact"><div class="top">' + badge(f.Severity) + '</div><div>' + esc(f.Detail) + '</div></div>'
          ).join("") +
        '</div></div>';
    }).join("") || '<p class="muted">No findings.</p>';
  }
  renderCategories();

  document.getElementById("sec-dashboard").addEventListener("click", (e) => {
    const card = e.target.closest("[data-area]");
    if (card) {
      go("categories");
      const area = card.getAttribute("data-area");
      const block = [...document.querySelectorAll("#catList h2")].find(h => h.textContent === area);
      if (block) block.parentElement.parentElement.scrollIntoView({ behavior: "smooth", block: "start" });
    }
    const jump = e.target.closest("[data-jump]");
    if (jump) go(jump.getAttribute("data-jump"));
    const open = e.target.closest("[data-open-narr]");
    if (open) openNarr(open.getAttribute("data-open-narr"));
  });
  document.getElementById("sec-narratives").addEventListener("click", (e) => {
    const jump = e.target.closest("[data-jump]");
    if (jump) go(jump.getAttribute("data-jump"));
    const open = e.target.closest("[data-open-narr]");
    if (open) {
      // From table/checklist → switch to cards and focus
      narrView = "cards";
      document.querySelectorAll("#narrViewToggle .ss-cat").forEach(b =>
        b.classList.toggle("active", b.getAttribute("data-view") === "cards")
      );
      if (document.getElementById("narrFilter")) document.getElementById("narrFilter").value = "";
      if (document.getElementById("narrPrio")) document.getElementById("narrPrio").value = "";
      if (document.getElementById("narrSev")) document.getElementById("narrSev").value = "";
      if (document.getElementById("narrArea")) document.getElementById("narrArea").value = "";
      renderNarratives();
      openNarr(open.getAttribute("data-open-narr"));
    }
    const copyFix = e.target.closest("[data-copy-fix]");
    if (copyFix) {
      const id = copyFix.getAttribute("data-copy-fix");
      const n = (D.narratives || []).find(x => x.Id === id);
      if (n) copyText((n.Title || "") + "\\n\\n" + (n.Remediation || ""), copyFix);
    }
    const copyFinding = e.target.closest("[data-copy-finding]");
    if (copyFinding) {
      const id = copyFinding.getAttribute("data-copy-finding");
      const n = (D.narratives || []).find(x => x.Id === id);
      if (n) {
        copyText(
          [n.Priority, n.Severity, n.Id, n.Title, "", n.Narrative || "", "", "Fix: " + (n.Remediation || ""), "", "Evidence: " + (n.Evidence || "")].join("\\n"),
          copyFinding
        );
      }
    }
  });

  // ── Findings filter
  document.getElementById("sec-findings").innerHTML =
    '<div class="callout info">Inventory list — useful for evidence, not for priority. Expert tab = what to fix first.</div>' +
    '<div class="toolbar">' +
      '<input id="findFilter" placeholder="Filter findings…" />' +
      '<select id="findSev"><option value="">All severities</option><option>High</option><option>Medium</option><option>Info</option><option>Low</option></select>' +
      '<select id="findArea"><option value="">All areas</option></select>' +
      '<span class="muted" id="findCount"></span></div><div id="findList"></div>';
  const areaSel = document.getElementById("findArea");
  (D.byArea || []).forEach(a => {
    const o = document.createElement("option"); o.value = a.area; o.textContent = a.area + " (" + a.total + ")";
    areaSel.appendChild(o);
  });
  function renderFindings() {
    const q = (document.getElementById("findFilter").value || "").toLowerCase();
    const sev = document.getElementById("findSev").value;
    const area = document.getElementById("findArea").value;
    const rows = (D.findings || []).filter(f => {
      if (sev && f.Severity !== sev) return false;
      if (area && f.Area !== area) return false;
      if (q && !(String(f.Detail)+String(f.Area)+String(f.Severity)).toLowerCase().includes(q)) return false;
      return true;
    });
    document.getElementById("findCount").textContent = rows.length + " / " + D.findings.length;
    document.getElementById("findList").innerHTML = rows.map(f =>
      '<div class="finding-card compact"><div class="top">' + badge(f.Severity) +
      '<span class="badge badge-muted">' + esc(f.Area) + '</span></div><div>' + esc(f.Detail) + '</div></div>'
    ).join("") || '<p class="muted">No matches.</p>';
  }
  ["findFilter","findSev","findArea"].forEach(id =>
    document.getElementById(id).addEventListener(id==="findFilter"?"input":"change", renderFindings)
  );
  renderFindings();

  // ── Limitations
  const skipped = D.skippedFindings || [];
  document.getElementById("sec-limits").innerHTML =
    '<div class="callout danger"><strong>Important:</strong> Empty RMM/AI/patch results or missing Intune rings usually mean <em>no permission / no schema</em>, not a secure tenant. Treat skipped domains as <strong>unchecked</strong>.</div>' +
    '<div class="card" style="margin-bottom:1rem"><h2>Coverage matrix</h2>' +
      table(["Domain","Status","Impact"], D.coverage || [], (r,h) => h==="Status"?badge(r[h]):esc(r[h])) +
    '</div>' +
    '<div class="card" style="margin-bottom:1rem"><h2>API / permission errors (' + D.errors.length + ')</h2>' +
      (D.errors.length
        ? table(["area","label","reason","needed","status"], D.errors, (r,h) => {
            if (h === "reason") return '<span class="badge badge-warn">' + esc(r.reason) + '</span>';
            if (h === "needed") return r.needed ? '<code style="font-size:11px">' + esc(r.needed) + '</code>' : '<span class="muted">—</span>';
            return esc(r[h]);
          })
        : '<p class="muted">No ERROR_*.json files in this output folder.</p>') +
    '</div>' +
    '<div class="card"><h2>Findings that indicate skip / unavailable (' + skipped.length + ')</h2>' +
      (skipped.length
        ? skipped.map(f =>
            '<div class="finding-card compact"><div class="top">' + badge(f.Severity) +
            '<span class="badge badge-muted">' + esc(f.Area) + '</span></div><div>' + esc(f.Detail) + '</div></div>'
          ).join("")
        : '<p class="muted">None tagged as skipped in findings text.</p>') +
    '</div>';

  // ── Deep dives
  document.getElementById("navUsersCount").textContent =
    (D.noMfaTotal || 0) + " no MFA · " + (D.weakMfaTotal || 0) + " weak";
  document.getElementById("navDevCount").textContent =
    (D.staleDevicesTotal || 0) + " stale";

  const apSorted = [...(D.attackChecklist || [])].sort((a, b) => statusRank(a.Status) - statusRank(b.Status));
  const apNa = apSorted.filter(r => /^notapplicable$/i.test(String(r.Status || "").trim()));
  const apPass = apSorted.filter(r => /pass/i.test(r.Status || ""));
  const apGaps = apSorted.filter(r => !/pass/i.test(r.Status || "") && !/^notapplicable$/i.test(String(r.Status || "").trim()));

  function checklistTable(rows, showSev) {
    return table(
      showSev ? ["Status","Severity","CheckId","Title","Evidence","WhyItMatters"] : ["Status","CheckId","Title","Evidence","WhyItMatters"],
      rows,
      (r, h) => {
        if (h === "Status") return badge(r[h]);
        if (h === "Severity") {
          if (/pass/i.test(r.Status || "")) return '<span class="muted">—</span>';
          return badge(r[h]);
        }
        return esc(r[h]);
      }
    );
  }

  document.getElementById("sec-attackpath").innerHTML =
    '<div class="grid grid-4" style="margin-bottom:1rem">' +
      toneCard("Fail", CS.fail, "Must remediate", CS.fail ? "danger" : "success") +
      toneCard("Partial", CS.partial, "Verify / tighten", CS.partial ? "warn" : "success") +
      toneCard("Pass", CS.pass, "Collapsed below", "info") +
      toneCard("Total checks", CS.total, "", "info") +
    '</div>' +
    '<div class="callout info">Passed controls are <strong>not findings</strong>. They stay collapsed so Fail / Partial stay visible.</div>' +
    '<div class="card" style="margin-bottom:1rem"><h2>Gaps (Fail + Partial)</h2>' +
      (apGaps.length ? checklistTable(apGaps, true) : '<p class="muted">No open gaps on this checklist.</p>') +
    '</div>' +
    '<details class="pass-fold"><summary>Show ' + apPass.length + ' passed controls (OK — not prioritized)</summary>' +
      checklistTable(apPass, false) +
    '</details>' +
    (apNa.length
      ? '<details class="pass-fold"><summary>Show ' + apNa.length + ' not-applicable controls (licence / Security Defaults — not gaps)</summary>' +
          checklistTable(apNa, false) +
        '</details>'
      : '') +
    '<div class="card" style="margin-top:1rem"><h2>CA vs attacker paths</h2>' +
    table(["Control","Covered","Severity","Policies","Why"], D.caCoverage||[], (r,h)=>{
      const raw = String(r.Covered).toLowerCase();
      const na = raw === "n/a";
      const unknown = raw === "unknown" || raw === "";
      const ok = raw === "true" || r.Covered === true;
      if (h==="Covered") return na ? badge("NotApplicable") : unknown ? badge("Unknown") : ok ? badge("Pass") : badge("Fail");
      if (h==="Severity") return ok || unknown || na ? '<span class="muted">—</span>' : badge(r[h]);
      return esc(r[h]);
    }) + '</div>';

  document.getElementById("sec-ca").innerHTML =
    dataCard("Policies", null, ["PolicyName","State","GrantControls","GrantOperator","ClientAppTypes","AuthFlows","SignInRisk","UserRisk","RiskFlags"], D.caAudit||[], (r,h)=>{
      if (h==="State") {
        if (r[h]==="enabled") return badge("Pass");
        if (r[h]==="enabledForReportingButNotEnforced") return badge("Partial");
        return badge("Info");
      }
      return esc(r[h]);
    }) +
    dataCard("Exclusion groups", null, ["DisplayName","IsAssignableToRole","Hardened","Risk"], D.exclGroups||[]);

  document.getElementById("sec-users").innerHTML =
    '<div class="grid grid-4" style="margin-bottom:1rem">' +
      toneCard("No MFA", countLabel(D.noMfaTotal ?? 0, "07_Users_Without_MFA.csv"), "isMfaRegistered=false", countTone(D.noMfaTotal||0, "07_Users_Without_MFA.csv")) +
      toneCard("Weak MFA only", D.weakMfaTotal ?? 0, "Phone/SMS/email · no Authenticator/FIDO/WHfB", (D.weakMfaTotal||0)?"warn":"success") +
      toneCard("Inactive", D.inactiveTotal ?? 0, "Enabled · no sign-in in window", (D.inactiveTotal||0)?"warn":"success") +
      toneCard("Guests", D.guestsTotal ?? 0, "All guest objects", "info") +
    '</div>' +
    '<div class="callout info">Weak MFA = registered MFA methods are only phone / SMS / voice / email (SIM-swap / OTP phishing friendly). Passkey-like users are the positive control.</div>' +
    dataCard("Users without MFA", D.noMfaTotal, ["UPN","DisplayName","IsAdmin","IsSsprRegistered","MethodsRegistered","LastUpdated"], D.noMfa||[], (r,h)=>
      h==="IsAdmin" ? badge(String(r[h]).toLowerCase()==="true"?"Fail":"Pass") : esc(r[h])) +
    dataCard("Weak / legacy MFA methods only", D.weakMfaTotal, ["UPN","DisplayName","IsAdmin","MethodsRegistered","PreferredSecondary","LastUpdated"], D.weakMfa||[], (r,h)=>
      h==="IsAdmin" ? badge(String(r[h]).toLowerCase()==="true"?"Fail":"Pass") : esc(r[h])) +
    dataCard("Inactive enabled accounts", D.inactiveTotal, ["DisplayName","UPN","UserType","AccountEnabled","LastInteractive","LastNonInteractive","Created","DaysSinceInteractive"], D.inactive||[]) +
    (((D.guestHygiene||{}).rows||[]).length
      ? '<div class="card" style="margin-bottom:1rem"><h2>Guest lifecycle</h2>' +
        '<div class="grid grid-4" style="margin:.5rem 0 1rem">' +
          toneCard("Enabled guests", D.guestHygiene.enabled, "Can still redeem access", "info") +
          toneCard("Dormant", D.guestHygiene.dormant, "No sign-in in window", D.guestHygiene.dormant ? "warn" : "success") +
          toneCard("Invite pending", D.guestHygiene.pending, "Never redeemed — live links", D.guestHygiene.pending ? "warn" : "success") +
          toneCard("Disabled", D.guestHygiene.disabled, "Inventory only", "info") +
        '</div>' +
        '<div class="callout info">Guests keep whatever sharing and group membership they were granted until someone removes it, and no owner is reviewing them. Unredeemed invitations are still-valid links. Entra access reviews with auto-removal close both without manual effort.</div>' +
        table(["State","UPN","DisplayName","ExternalUserState","AccountEnabled","Created","Mail"], D.guestHygiene.rows, (r,h)=>{
          if (h==="State") return badge(r[h]==="Active" ? "Pass" : r[h]==="Dormant" ? "Partial" : "Fail") +
            ' <span class="muted" style="font-size:11px">' + esc(r[h]) + '</span>';
          if (h==="AccountEnabled") return badge(String(r[h]).toLowerCase()==="true"?"Enabled":"Disabled");
          return esc(r[h]);
        }) + '</div>'
      : dataCard("Guests", D.guestsTotal, ["DisplayName","UPN","AccountEnabled","Created","ExternalUserState","Mail"], D.guests||[], (r,h)=>
          h==="AccountEnabled" ? badge(String(r[h]).toLowerCase()==="true"?"Enabled":"Disabled") : esc(r[h]))) +
    dataCard("Passkey / phishing-resistant-like", D.passkeyTotal, Object.keys((D.passkey||[])[0]||{UPN:"",DisplayName:"",MethodsRegistered:""}), D.passkey||[]) +
    dataCard("SSPR registered (sample)", null, Object.keys((D.sspr||[])[0]||{Note:"empty"}), D.sspr||[]) +
    dataCard("Domains", null, Object.keys((D.domains||[])[0]||{Note:"empty"}), D.domains||[]);

  document.getElementById("sec-identity").innerHTML =
    '<div class="grid grid-2" style="margin-bottom:1rem">' +
      dataCard("Device code users", null, ["UPN","Events","Apps","Ips"], D.deviceCode||[]) +
      dataCard("Risky users", null, ["UPN","Name","RiskState","RiskLevel","RiskDetail"], D.risky||[], (r,h)=>
        h==="RiskLevel" ? badge(/high/i.test(r[h])?"Critical":/medium/i.test(r[h])?"High":r[h]||"Info") : esc(r[h])) +
    '</div>' +
    dataCard("Device code sign-ins (sample)", null, Object.keys((D.deviceCodeSignIns||[])[0]||{Note:"empty"}), D.deviceCodeSignIns||[]) +
    dataCard("Legacy auth successes", null, Object.keys((D.legacy||[])[0]||{Note:"empty"}), D.legacy||[]) +
    dataCard("Security alerts sample (Graph)", D.securityAlertsTotal, ["Title","Severity","Status","Category","Created","Product"], D.securityAlerts||[], (r,h)=>
      h==="Severity" ? badge(/high|critical/i.test(r[h])?"High":/medium/i.test(r[h])?"Medium":r[h]||"Info") : esc(r[h]));

  document.getElementById("sec-devices").innerHTML =
    '<div class="grid grid-4" style="margin-bottom:1rem">' +
      toneCard("Stale joined/hybrid", D.staleDevicesTotal ?? 0, "Beyond stale threshold", (D.staleDevicesTotal||0)?"warn":"success") +
      toneCard("Registered only", D.registeredOnlyTotal ?? 0, "Workplace join / registered", "info") +
      toneCard("Entra joined", S.devicesEntraJoined ?? S.devicesJoined ?? "n/a", "", "info") +
      toneCard("Hybrid", S.devicesHybridJoined ?? S.devicesHybrid ?? "n/a", "", "info") +
    '</div>' +
    '<div class="grid grid-4" style="margin-bottom:1rem">' +
      toneCard("PC / Phone / Tablet", (S.devicesFormPC ?? 0) + " / " + (S.devicesFormSmartphone ?? 0) + " / " + (S.devicesFormTablet ?? 0), "Form factors (Entra)", "info") +
      toneCard("Multi-PC users", S.usersMultiPC ?? 0, "Users with >1 PC", (S.usersMultiPC||0)?"warn":"success") +
      toneCard("Multi-phone users", S.usersMultiPhone ?? 0, "Users with >1 smartphone", "info") +
      toneCard("PC+phone+tablet", S.usersPcPhoneTablet ?? 0, "Users with all three", "info") +
    '</div>' +
    dataCard("Stale Entra / hybrid joined devices", D.staleDevicesTotal, ["DisplayName","TrustType","OS","LastSeen","Enabled","Compliant","Managed","Manufacturer","Model"], D.staleDevices||[], (r,h)=>{
      if (h==="Enabled") return badge(String(r[h]).toLowerCase()==="true"?"Enabled":"Disabled");
      if (h==="Compliant"||h==="Managed") return badge(String(r[h]).toLowerCase()==="true"?"Pass":"Fail");
      return esc(r[h]);
    }) +
    dataCard("Registered-only devices", D.registeredOnlyTotal, Object.keys((D.registeredOnly||[])[0]||{Note:"empty"}), D.registeredOnly||[]) +
    dataCard(
      "Users with multiple devices (PC / phone / tablet)",
      D.devicesPerUserMultiTotal,
      ["UPN","DisplayName","PC","Smartphone","Tablet","Other","Total","HasPcPhoneTablet","MultiPC","MultiPhone","MultiTablet","OverQuota","SampleDevices"],
      D.devicesPerUserMulti||[],
      (r,h)=>{
        if (["HasPcPhoneTablet","MultiPC","MultiPhone","MultiTablet","OverQuota"].includes(h)) {
          return badge(String(r[h]).toLowerCase()==="true"?"Yes":"No");
        }
        return esc(r[h]);
      }
    ) +
    dataCard("All users with devices (inventory)", D.devicesPerUserTotal, ["UPN","DisplayName","PC","Smartphone","Tablet","Other","Total"], D.devicesPerUser||[]);

  const ep = D.endpoints || {};
  const tvm = D.tvmStats || {};
  const kqlStatus = D.huntKqlStatus || [];
  const caps = S.huntingCapabilities || {};
  // DeviceInfo/DeviceProcess* = full MDE endpoint surface. DeviceTvm* can still
  // supply CVE + RMM software inventory when DeviceInfo is absent.
  const noDeviceInfo = caps.mdeEndpoint === false;
  const hasTvmData =
    !!(D.defenderVulns || []).length ||
    !!(D.tvmWin || []).length ||
    !!(D.tvmWinCves || []).length ||
    caps.vulns === true;
  const hasRmmData =
    !!(ep.rmmFamily || []).length ||
    !!(ep.rmmAssets || []).length ||
    !!(ep.rmm || []).length ||
    caps.rmm === true;
  const hasPatchData =
    !noDeviceInfo &&
    (caps.patch === true ||
      !!(ep.patchBehind || []).length ||
      !!(ep.winInventory || []).length ||
      !!(D.win10Devices || []).length);
  const noEndpointSurface =
    noDeviceInfo && !hasTvmData && !hasRmmData && caps.patch === false && caps.vulns === false && caps.rmm === false;
  const cloudUsageOk = !!(ep.genAiUsers||[]).length || !!(ep.fileShareUsers||[]).length || !!(ep.genAiApps||[]).length;
  const epEmpty = !(ep.rmm||[]).length && !(ep.rmmAssets||[]).length && !(ep.rmmFamily||[]).length && !(ep.aiAgents||[]).length && !(ep.patchBehind||[]).length && !(ep.winInventory||[]).length && !cloudUsageOk && !(D.defenderVulns||[]).length && !(D.win10Devices||[]).length && !(D.tvmWin||[]).length;
  const kqlOk = kqlStatus.filter((r) => r.Status === "OK").length;
  const kqlFail = kqlStatus.filter((r) => r.Status === "Fail").length;
  const kqlMissing = kqlStatus.filter((r) => {
    const st = String(r.Status || "").toLowerCase();
    return st.includes("missing") || st.includes("skip") || st === "n/a";
  }).length;
  const epScopeCallout = noEndpointSurface
    ? '<div class="callout warn"><strong>No Defender endpoint / TVM hunting tables in this tenant.</strong> Advanced Hunting may still work for identity/cloud, but RMM / OS patch lag / endpoint TVM were <em>not assessed</em> — zeros below mean unavailable, not clean.' +
      (cloudUsageOk ? ' CloudApp GenAI / file-share signals may still appear.' : '') +
      '</div>'
    : (noDeviceInfo
      ? '<div class="callout warn"><strong>DeviceInfo / DeviceProcessEvents missing</strong> (full MDE endpoint surface). Patch lag, Windows fleet inventory, and process-based RMM were not assessed. ' +
        (hasTvmData || hasRmmData
          ? 'DeviceTvm* inventory is available — TVM CVEs and/or RMM software rows below are real findings; empty fleet % means prevalence was not measurable, not “clean”.'
          : 'TVM/RMM inventory also empty in this export.') +
        (cloudUsageOk ? ' CloudApp GenAI / file-share signals may still appear.' : '') +
        '</div>'
      : (!S.huntingCanHunt
        ? '<div class="callout danger"><strong>Hunting API unavailable.</strong> Status: <em>' + esc(S.huntingApiStatus || "unavailable") + '</em>. Endpoint / TVM / RMM checks were skipped — see Limitations.</div>'
        : (epEmpty
          ? '<div class="callout warn"><strong>No endpoint / cloud-usage hunt rows in this export.</strong> Hunts ran empty or were skipped — see KQL checklist below, not a clean bill of health.</div>'
          : '')));
  const tvmCallout = !hasTvmData && (noDeviceInfo || caps.vulns === false)
    ? '<div class="callout info"><strong>Endpoint TVM limited/skipped.</strong> DeviceTvmSoftwareVulnerabilities (and/or DeviceInfo) not usable for this export.</div>'
    : (!D.tvmWinTotal && kqlStatus.some((r) => r.Id === "hunt_tvm_os_vulns" && r.Status === "Fail")
    ? '<div class="callout danger"><strong>Windows TVM OS hunt failed.</strong> Check KQL status + <code>ERROR_hunt_tvm_os_vulns.json</code>. Collector uses <code>SortKey</code> + <code>sort|take</code> (portal-compatible).</div>'
    : (D.tvmWinTotal
      ? '<div class="callout success"><strong>Windows OS TVM OK:</strong> ' + esc(D.tvmWinTotal) + ' device/software row(s) with High/Critical vulns in <code>32_TVM_Windows_HighCritical.csv</code>' +
        (D.tvmWinCvesTotal ? ' · ' + esc(D.tvmWinCvesTotal) + ' Windows CVE rows in <code>32_TVM_Windows_CVE_Inventory.csv</code>' : '') +
        '. Top devices often show hundreds of CVE hits on <code>windows_11</code> builds — prioritize Critical count then patch lag.</div>'
      : (hasTvmData
        ? '<div class="callout warn"><strong>Windows OS TVM empty.</strong> No <code>32_TVM_Windows_HighCritical.csv</code> rows — either no windows_* High/Critical vulns, or hunt not run. Broader CVE inventory may still appear below.</div>'
        : '')));
  const tvmTone = (n) => !hasTvmData ? "info" : (n ? "danger" : "success");
  const tvmVal = (n) => !hasTvmData ? "n/a" : (n ?? 0);
  const rmmPrevKnown = S.rmmPrevalenceKnown === true || Number(S.windowsDeviceCount || 0) > 0;
  const rmmCardSub = !hasRmmData
    ? "not in schema"
    : (rmmPrevKnown ? "Low-prevalence families" : "TVM inventory (fleet % n/a)");
  document.getElementById("sec-endpoints").innerHTML =
    epScopeCallout +
    '<h3 style="margin:0 0 .6rem;font-size:1rem;color:var(--navy,#0f2744)">TVM &amp; hunting KQL health</h3>' +
    '<div class="grid grid-4" style="margin-bottom:1rem">' +
      toneCard("KQL hunts OK", kqlOk, kqlFail ? (kqlFail + " failed") : (kqlMissing ? kqlMissing + " missing/skipped" : "no failures"), kqlFail ? "warn" : (noDeviceInfo || kqlMissing ? "info" : "success")) +
      toneCard("TVM CVE rows", tvmVal(tvm.cveRows ?? D.defenderVulnsTotal ?? 0), !hasTvmData ? "TVM not in schema" : ("Critical " + (tvm.critical||0) + " · High " + (tvm.high||0)), tvmTone(tvm.cveRows||D.defenderVulnsTotal)) +
      toneCard("Windows OS TVM devices", tvmVal(D.tvmWinTotal ?? tvm.windowsOsDevices ?? 0), !hasTvmData ? "not assessed" : "windows_* High/Critical", tvmTone(D.tvmWinTotal||tvm.windowsOsDevices)) +
      toneCard("Windows CVE inventory", tvmVal(D.tvmWinCvesTotal ?? 0), !hasTvmData ? "not assessed" : "OS CVE x version", !hasTvmData ? "info" : ((D.tvmWinCvesTotal)?"warn":"info")) +
    '</div>' +
    dataCard("Hunting KQL checklist (artifact vs ERROR_*)", kqlStatus.length || null, ["Hunt","Status","Rows","Artifact","ErrorDetail"], kqlStatus, (r,h)=>{
      if (h!=="Status") return esc(r[h]);
      const s = String(r[h]||"");
      if (s==="OK") return badge("OK");
      if (s==="Fail") return badge("Fail");
      if (s==="Empty") return badge("Empty");
      return esc(s);
    }) +
    tvmCallout +
    (!hasTvmData ? '' :
      dataCard("Windows OS devices — High/Critical TVM (32_TVM_Windows_HighCritical)", D.tvmWinTotal || null, ["DeviceName","Software","Version","Vulns","Critical","High"], D.tvmWin||[], (r,h)=>{
        if (h==="Critical" && Number(r[h])>0) return badge("Critical") + " " + esc(r[h]);
        if (h==="High" && Number(r[h])>0) return esc(r[h]);
        if (h==="Vulns" && Number(r[h])>100) return "<strong>" + esc(r[h]) + "</strong>";
        return esc(r[h]);
      }) +
      dataCard("Windows OS CVE inventory (32_TVM_Windows_CVE_Inventory)", D.tvmWinCvesTotal || null, ["CveId","Severity","Software","Version","Devices"], D.tvmWinCves||[], (r,h)=>h==="Severity"?badge(r[h]):esc(r[h])) +
      dataCard("TVM by software (from 11_Defender_Exploitable_Vulns)", (tvm.bySoftware||[]).length || null, ["Software","CveRows","Critical","High","MaxDevices"], tvm.bySoftware||[]) +
      dataCard("Defender TVM CVE inventory (11_Defender_Exploitable_Vulns)", D.defenderVulnsTotal, ["CveId","Severity","Software","Version","Devices","ExploitAvailable"], D.defenderVulns||[], (r,h)=>h==="Severity"?badge(r[h]):esc(r[h]))) +
    '<h3 style="margin:1.4rem 0 .6rem;font-size:1rem;color:var(--navy,#0f2744)">Endpoints · RMM · GenAI · patch</h3>' +
    '<div class="grid grid-4" style="margin-bottom:1rem">' +
      toneCard("RMM families", !hasRmmData ? "n/a" : (S.rmmSuspiciousFamilies ?? (ep.rmmFamily||[]).length ?? 0), rmmCardSub, !hasRmmData ? "info" : ((S.rmmSuspiciousFamilies||(ep.rmmFamily||[]).length)?"warn":"success")) +
      toneCard("Windows 10", !hasPatchData ? "n/a" : (D.win10DevicesTotal ?? S.windows10Count ?? 0), !hasPatchData ? "needs DeviceInfo" : "Still active", !hasPatchData ? "info" : ((D.win10DevicesTotal||S.windows10Count)?"warn":"success")) +
      toneCard("Behind Patch Tuesday", !hasPatchData ? "n/a" : ((ep.patchBehind||[]).length || S.behindPatchTuesdayCount || 0), !hasPatchData ? "needs DeviceInfo" : (S.patchTuesdayAsOf || ""), !hasPatchData ? "info" : (((ep.patchBehind||[]).length||S.behindPatchTuesdayCount)?"warn":"success")) +
      toneCard("GenAI / file-share", ((ep.genAiUsers||[]).length||0) + " / " + ((ep.fileShareUsers||[]).length||0), "user rows (CloudApp)", ((ep.fileShareUsers||[]).length)?"warn":"info") +
    '</div>' +
    (hasRmmData
      ? dataCard("RMM family summary", null, Object.keys((ep.rmmFamily||[])[0]||{Note:"empty"}), ep.rmmFamily||[], (r,h)=>{
          if (h==="AssumedLegit") return badge(String(r[h]).toLowerCase()==="true"?"Legit":(Number(r.AgentDevices||0)>0?(Number(r.TotalWindows||0)>0?"Review":"Agents"):"Noise"));
          if (h==="Signal") return badge(String(r[h]).toLowerCase()==="true"?"Agent":"Noise");
          return esc(r[h]);
        }) +
        dataCard("RMM affected assets (host · owner · evidence)", (ep.rmmAssets||[]).length || null, ["Family","DeviceName","OSPlatform","Owners","OwnersUPN","RiskClass","Signal","EvidenceSources","EvidenceTrace"], ep.rmmAssets||[], (r,h)=>{
          if (h==="Signal") return badge(String(r[h]).toLowerCase()==="true"||r[h]===true?"Agent":"Noise");
          if (h==="RiskClass") return esc(r[h]||"");
          return esc(r[h]);
        }) +
        dataCard("RMM dismissed artefacts (GoTo Meeting / LogMeIn Live ≠ RMM)", (ep.rmmDismissed||[]).length || null, ["DeviceName","OSPlatform","Owners","SoftwareVendor","SoftwareName","SoftwareVersion","Verdict","Evidence"], ep.rmmDismissed||[]) +
        dataCard("RMM indicators (raw detections)", null, Object.keys((ep.rmm||[])[0]||{Note:"empty"}), ep.rmm||[])
      : (noDeviceInfo
        ? '<div class="callout info">No RMM rows in this export (DeviceTvmSoftwareInventory / DeviceProcessEvents empty or missing).</div>'
        : '')) +
    (hasPatchData
      ? dataCard("AI agent indicators (endpoint)", null, Object.keys((ep.aiAgents||[])[0]||{Note:"empty"}), ep.aiAgents||[]) +
        dataCard("Behind Patch Tuesday / OS lag", null, Object.keys((ep.patchBehind||[])[0]||{Note:"empty"}), ep.patchBehind||[]) +
        dataCard("Windows 10 devices", D.win10DevicesTotal, Object.keys((D.win10Devices||[])[0]||{Note:"empty"}), D.win10Devices||[]) +
        dataCard("OS build distribution", null, Object.keys((D.osBuildDist||[])[0]||{Note:"empty"}), D.osBuildDist||[]) +
        dataCard("Endpoints OS patch status (sample)", null, Object.keys((D.patchStatusAll||[])[0]||{Note:"empty"}), D.patchStatusAll||[]) +
        dataCard("Windows inventory (hunt)", null, Object.keys((ep.winInventory||[])[0]||{Note:"empty"}), ep.winInventory||[]) +
        dataCard("Intune update rings", null, Object.keys((ep.updateRings||[])[0]||{Note:"empty"}), ep.updateRings||[])
      : (noDeviceInfo
        ? '<div class="callout info">Patch lag / Windows 10 fleet / on-device AI agents omitted — DeviceInfo is not in the hunting schema. RMM/TVM above (when present) come from DeviceTvm*.</div>'
        : '')) +
    dataCard("GenAI usage by user (volume)", null, Object.keys((ep.genAiUsers||[])[0]||{Note:"empty"}), ep.genAiUsers||[]) +
    dataCard("GenAI usage by app", null, Object.keys((ep.genAiApps||[])[0]||{Note:"empty"}), ep.genAiApps||[]) +
    dataCard("File-sharing sites by user (WeTransfer / Dropbox / …)", null, Object.keys((ep.fileShareUsers||[])[0]||{Note:"empty"}), ep.fileShareUsers||[]) +
    dataCard("File-sharing by app", null, Object.keys((ep.fileShareApps||[])[0]||{Note:"empty"}), ep.fileShareApps||[]);

  const cb = D.collab || {};
  document.getElementById("sec-collab").innerHTML =
    dataCard("Anti-spam / MDO manual checklist", null, Object.keys((cb.antiSpam||[])[0]||{Note:"empty"}), cb.antiSpam||[]) +
    dataCard("Email delivery hunting sample (7d)", null, Object.keys((cb.emailSample||[])[0]||{Note:"empty"}), cb.emailSample||[]) +
    dataCard("Outbound email domains (30d)", null, Object.keys((cb.outboundDomains||[])[0]||{Note:"empty"}), cb.outboundDomains||[]) +
    dataCard("Mailbox forwarding manual checks", null, Object.keys((cb.forwardingChecks||[])[0]||{Note:"empty"}), cb.forwardingChecks||[]) +
    dataCard("Teams / Groups guest settings", null, Object.keys((cb.teamsGuest||[])[0]||{Note:"empty"}), cb.teamsGuest||[]) +
    dataCard("Log retention notes", null, Object.keys((cb.logRetention||[])[0]||{Note:"empty"}), cb.logRetention||[]);

  // A privileged account nobody uses is a privileged account nobody monitors.
  const dormantPriv = D.dormantPrivileged || [];
  const dormantGa = dormantPriv.filter(r => r.IsGlobalAdmin);
  const dormantCard = dormantPriv.length
    ? '<div class="card" style="margin-bottom:1rem"><h2>Dormant privileged accounts</h2>' +
      '<div class="callout ' + (dormantGa.length ? 'danger' : 'warn') + '">' +
      dormantPriv.length + ' privileged account(s) show no sign-in in the inactivity window' +
      (dormantGa.length ? ', including <strong>' + dormantGa.length + ' Global Administrator</strong>' : '') +
      '. These carry full blast radius with no activity baseline, so a compromise produces nothing that looks unusual.</div>' +
      table(["UPN","Roles","Idle","AccountEnabled","Created"], dormantPriv, (r,h)=>{
        if (h==="Idle") return r.IsGlobalAdmin
          ? '<strong>' + esc(r[h]) + '</strong> ' + badge("Fail")
          : esc(r[h]);
        if (h==="AccountEnabled") return badge(String(r[h]).toLowerCase()==="false" ? "Disabled" : "Enabled");
        return esc(r[h]);
      }) + '</div>'
    : '';

  const privAllRows = D.privAll || [];
  const privByRole = D.privByRole || [];
  const privAllTotal = D.privAllTotal ?? privAllRows.length;
  const highValueTotal = D.privTotal ?? (D.priv || []).length;
  const uniqueRoles = privByRole.length;
  const readerAssign = privAllRows.filter((r) => r.Tier === "Reader").length;
  const dataPlaneAssign = privAllRows.filter((r) => r.Tier === "Data-plane").length;
  const roleTierCards =
    '<div class="grid grid-4" style="margin-bottom:1rem">' +
      toneCard("High-value assignments", highValueTotal, "GA / app / CA / mailbox admins", highValueTotal ? "warn" : "success") +
      toneCard("All directory assignments", countLabel(privAllTotal, "03_PrivilegedRoles_Audit.csv"), uniqueRoles + " distinct role(s)", "info") +
      toneCard("Reader assignments", readerAssign, "Global / Security / Directory Readers", "info") +
      toneCard("Data-plane", dataPlaneAssign, "Purview content purge (not Entra isPrivileged)", dataPlaneAssign ? "warn" : "info") +
    "</div>" +
    '<div class="callout info"><strong>High-value is identity control-plane</strong> (Global Admin, app/CA/Exchange/SharePoint/Intune admins, …). ' +
    "The full list below is every Entra directory role assignment collected, including Global Reader and Security Reader. " +
    "<strong>Purview Workload Content Administrator</strong> is not an Entra privileged role (directory permissions = Directory Readers) — it is synced from Purview Search and Purge / data-security investigation and can <em>purge M365 content</em>. Treat it as data-plane sensitive, not as GA-class.</div>";

  document.getElementById("sec-privileged").innerHTML =
    dormantCard +
    roleTierCards +
    dataCard("High-value roles", highValueTotal, ["RoleName","PrincipalName","PrincipalType","UPNOrAppId","AssignmentType","Scope","ViaGroup"], D.priv||[]) +
    dataCard("All directory role assignments", privAllTotal, ["Tier","RoleName","PrincipalName","PrincipalType","UPNOrAppId","AssignmentType","Scope","ViaGroup"], privAllRows, (r,h)=>{
      if (h==="Tier") {
        if (r[h]==="High-value") return badge("Fail") + ' <span class="muted" style="font-size:11px">high-value</span>';
        if (r[h]==="Data-plane") return badge("Partial") + ' <span class="muted" style="font-size:11px">data-plane</span>';
        if (r[h]==="Reader") return badge("Info") + ' <span class="muted" style="font-size:11px">reader</span>';
        return badge("Pass") + ' <span class="muted" style="font-size:11px">other</span>';
      }
      return esc(r[h]);
    }) +
    dataCard("Assignments by role", uniqueRoles, ["RoleName","Tier","Assignments","Permanent","Eligible","Users","ServicePrincipals"], privByRole, (r,h)=>{
      if (h==="Tier") {
        if (r[h]==="High-value") return badge("Fail");
        if (r[h]==="Data-plane") return badge("Partial");
        if (r[h]==="Reader") return badge("Info");
        return badge("Pass");
      }
      return esc(r[h]);
    }) +
    '<div class="card" style="margin-bottom:1rem"><h2>Hygiene</h2>' +
    '<p class="muted" style="font-size:12px;margin:.25rem 0 .75rem">Badges: <strong>GA / Hybrid = true → Fail</strong> (risky). MFA blank = Unknown. Check <strong>Enabled</strong> — disabled accounts are inventory only.</p>' +
    table(["DisplayName","UPN","Roles","IsGlobalAdmin","OnPremSynced","MfaRegistered","AccountEnabled","HasMailboxHint"], D.privHygiene||[], (r,h)=>{
      if (h==="IsGlobalAdmin") return badge(String(r[h]).toLowerCase()==="true"?"Fail":"Pass") +
        (String(r[h]).toLowerCase()==="true"?' <span class="muted" style="font-size:11px">standing GA</span>':'');
      if (h==="OnPremSynced") return badge(String(r[h]).toLowerCase()==="true"?"Fail":"Pass") +
        (String(r[h]).toLowerCase()==="true"?' <span class="muted" style="font-size:11px">hybrid</span>':'');
      if (h==="MfaRegistered") {
        const v = String(r[h] ?? "").toLowerCase();
        if (v === "true") return badge("Pass");
        if (v === "false") return badge("Fail");
        return badge("Unknown");
      }
      if (h==="AccountEnabled") {
        const on = String(r[h]).toLowerCase()==="true";
        return badge(on ? "Enabled" : "Disabled");
      }
      return esc(r[h]);
    }) + '</div>' +
    dataCard("Privileged SPN credentials", null, Object.keys((D.privSpnCreds||[])[0]||{Note:"empty"}), D.privSpnCreds||[]);

  // Blast radius (permissions) crossed with activity (sign-ins): the same app
  // list, split into what to harden and what to delete.
  const spnAct = D.spnActivity || [];
  const spnLive = spnAct.filter(r => r.SignIns > 0);
  const spnIdle = spnAct.filter(r => r.SignIns === 0);
  const spnCritLive = spnLive.filter(r => r.MaxSeverity === "Critical");
  const spnSpread = spnLive.filter(r => r.DistinctIPs >= 5);
  const spnCard = spnAct.length
    ? '<div class="grid grid-4" style="margin-bottom:1rem">' +
        toneCard("Active + risky", spnLive.length, "Signed in during window", spnLive.length ? "warn" : "success") +
        toneCard("Critical + active", spnCritLive.length, "Live credentials, top blast radius", spnCritLive.length ? "danger" : "success") +
        toneCard("No sign-in", spnIdle.length, "Removal candidates", spnIdle.length ? "info" : "success") +
        toneCard("5+ distinct IPs", spnSpread.length, "Confirm vendor egress", spnSpread.length ? "warn" : "info") +
      '</div>' +
      '<div class="callout info"><strong>Permissions describe what an app could do; sign-ins show which apps are live.</strong> ' +
      'Active entries are real credentials on a real path and should be hardened. Entries with no sign-in carry the same blast radius with no business value on record — they are the cheapest thing to remove.</div>' +
      '<div class="card" style="margin-bottom:1rem"><h2>Over-privileged apps by activity</h2>' +
      table(["Status","App","MaxSeverity","SignIns","DistinctIPs","Failures","LastSeen","Locations","Permissions"], spnAct, (r,h)=>{
        if (h==="Status") return badge(r.SignIns > 0 ? "Active" : "Unused");
        if (h==="MaxSeverity") return r[h] ? badge(r[h]) : '<span class="muted">—</span>';
        if (h==="DistinctIPs") return r[h] >= 5
          ? '<strong>' + r[h] + '</strong> <span class="muted" style="font-size:11px">spread</span>'
          : esc(r[h]);
        return esc(r[h]);
      }) + '</div>'
    : '';

  document.getElementById("sec-apps").innerHTML =
    spnCard +
    dataCard("Path to Global Admin", null, ["SPNDisplayName","Permission","Severity","AttackNote","CreatedDateTime"], D.gaPath||[], (r,h)=>h==="Severity"?badge(r[h]):esc(r[h])) +
    dataCard("Dangerous Graph permissions", null, ["SPNDisplayName","Permission","Severity","PrincipalType","CreatedDateTime"], D.dangerous||[], (r,h)=>h==="Severity"?badge(r[h]):esc(r[h])) +
    dataCard("High-privilege app owners", null, Object.keys((D.highPrivOwners||[])[0]||{Note:"empty"}), D.highPrivOwners||[]) +
    dataCard("App secrets expiry", null, Object.keys((D.secretsExpiry||[])[0]||{Note:"empty"}), D.secretsExpiry||[]) +
    dataCard("Wildcard reply URLs", null, Object.keys((D.wildcardUrls||[])[0]||{Note:"empty"}), D.wildcardUrls||[]);

  const ssCats = (D.secureScoreExplorer && D.secureScoreExplorer.categories) || (D.secureScoreGaps && D.secureScoreGaps.categories) || [];
  const ssCatCards = ssCats.length
    ? '<div class="grid grid-' + Math.min(4, ssCats.length) + '" style="margin-bottom:1rem">' +
      ssCats.map((c) => {
        const gap = Number(c.Gap != null ? c.Gap : c.gap) || 0;
        const score = c.Score != null ? c.Score : c.score;
        const max = c.Max != null ? c.Max : c.max;
        const cat = c.Category || c.category || "?";
        const tone = gap >= 20 ? "danger" : gap >= 8 ? "warn" : "info";
        return toneCard(cat, score + " / " + max, "Gap " + gap + " pts · " + (c.Open != null ? c.Open : "?") + " open / " + (c.Partial != null ? c.Partial : "?") + " partial", tone);
      }).join("") +
      '</div>'
    : '';
  document.getElementById("sec-score").innerHTML =
    '<div class="grid grid-2" style="margin-bottom:1rem">' +
      toneCard("Secure Score", (S.secureScoreCurrent != null ? (Math.round(S.secureScoreCurrent * 10) / 10) : "n/a") + (S.secureScoreMax != null ? " / " + (Math.round(S.secureScoreMax * 10) / 10) : ""), "In-scope Microsoft Secure Score (live controlScores)", "info") +
      toneCard("Expert posture", D.score + " / 100", "Attack-path narratives (different scale)", D.score < 50 ? "danger" : D.score < 75 ? "warn" : "success") +
    '</div>' +
    ssCatCards +
    '<div class="callout info"><strong>Two different scores.</strong> Microsoft Secure Score measures recommended control adoption for products this tenant is scored on (' +
      ((D.secureScoreExplorer && D.secureScoreExplorer.controlCount) || (D.secureScoreGaps && D.secureScoreGaps.controlCount) || "?") +
      ' in-scope controls). The full profile catalog (hundreds of rows) is not used here — empty CurrentScore rows would inflate gaps (e.g. MDE). Expert posture weights correlated attack paths and is a separate scale.</div>' +
    (((D.secureScoreGaps||{}).rows||[]).length
      ? '<div class="card" style="margin-bottom:1rem" data-ss-explorer="1"><h2>Remediation roadmap — in-scope, by recoverable points</h2>' +
        '<div class="callout info">' + D.secureScoreGaps.count + ' open/partial controls, <strong>' +
        D.secureScoreGaps.points + ' points</strong> recoverable. Filter by category or search title/remediation. Ordered by return — feature adoption backlog, not tenant-specific attack paths.</div>' +
        '<div class="toolbar" style="margin-bottom:.75rem;display:flex;flex-wrap:wrap;gap:.5rem;align-items:center">' +
          '<input id="ss-filter" placeholder="Search controls…" style="max-width:260px" />' +
          '<button type="button" class="ss-cat active" data-cat="">All</button>' +
          ssCats.map((c) => {
            const cat = c.Category || c.category;
            return '<button type="button" class="ss-cat" data-cat="' + esc(cat) + '">' + esc(cat) + ' <span class="muted">(' + (c.Gap != null ? c.Gap : c.gap) + ')</span></button>';
          }).join("") +
        '</div>' +
        '<div id="ss-table">' +
        table(["Gain","Category","Title","Status","UserImpact","Threats","Remediation"], D.secureScoreGaps.rows, (r,h)=>{
          if (h==="Gain") return '<strong>+' + r[h] + '</strong>';
          if (h==="Status") return badge(r[h] || "Open");
          if (h==="UserImpact") return r[h] ? badge(r[h]) : '<span class="muted">—</span>';
          if (h==="Remediation") return '<span class="muted" style="font-size:12px">' + esc(String(r[h]).slice(0, 220)) + '</span>';
          return esc(r[h]);
        }) + '</div></div>'
      : '');
  (function wireSecureScoreExplorer() {
    const root = document.querySelector("[data-ss-explorer]");
    if (!root || root._wired) return;
    root._wired = true;
    let cat = "";
    const inp = document.getElementById("ss-filter");
    const apply = () => {
      const q = ((inp && inp.value) || "").toLowerCase();
      root.querySelectorAll("#ss-table tbody tr").forEach((tr) => {
        const cells = tr.querySelectorAll("td");
        const rowCat = (cells[1] && cells[1].textContent || "").trim();
        const text = tr.textContent.toLowerCase();
        const okCat = !cat || rowCat === cat;
        const okQ = !q || text.includes(q);
        tr.style.display = okCat && okQ ? "" : "none";
      });
    };
    root.querySelectorAll(".ss-cat").forEach((btn) => {
      btn.addEventListener("click", () => {
        cat = btn.getAttribute("data-cat") || "";
        root.querySelectorAll(".ss-cat").forEach((b) => b.classList.toggle("active", b === btn));
        apply();
      });
    });
    if (inp) inp.addEventListener("input", apply);
  })();

  const sch = D.schema || {};
  const tables = Object.entries(sch.tables || {}).map(([name, t]) => ({
    Table: name, Available: !!t.available, HasRows: !!t.hasRows, Category: t.category, Classification: t.classification
  }));
  document.getElementById("sec-schema").innerHTML =
    '<div class="grid grid-4" style="margin-bottom:1rem">' +
      toneCard("Hunting API", sch.canHunt ? "OK" : (sch.huntApiStatus || "No"), sch.huntApiDetail || "", sch.canHunt?"success":"danger") +
      toneCard("Identity source", sch.identitySource || S.huntingIdentitySource || "n/a", "", "info") +
      toneCard("Graph sign-ins", (sch.graphSignIns&&sch.graphSignIns.available) || S.graphSignInsAvailable ? "OK" : "No", "", "info") +
      toneCard("Tables", (sch.availableTables||[]).length, "", "info") +
    '</div>' +
    dataCard("Probed tables", null, ["Table","Available","HasRows","Category","Classification"], tables, (r,h)=>
      (h==="Available"||h==="HasRows")?badge(r[h]?"Pass":"Fail"):esc(r[h]));

  wireFilters();

  document.querySelectorAll("#nav button").forEach(btn => {
    btn.addEventListener("click", () => go(btn.dataset.section));
  });
  document.getElementById("btnPrint").addEventListener("click", () => window.print());
  (function initThemeBtn() {
    const btn = document.getElementById("btnTheme");
    if (!btn) return;
    const sync = () => {
      const t = document.documentElement.getAttribute("data-theme") || "light";
      btn.textContent = t === "dark" ? "Light mode" : "Dark mode";
    };
    sync();
    btn.addEventListener("click", () => {
      const cur = document.documentElement.getAttribute("data-theme") || "light";
      const next = cur === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      try { localStorage.setItem("entraCollectTheme", next); } catch (e) {}
      sync();
    });
  })();
  go("dashboard");

  document.getElementById("btnXlsx").addEventListener("click", async () => {
    const ExcelJS = window.ExcelJS;
    const api = window.EntraXlsxReport;
    if (!ExcelJS || !api || !api.downloadBrowser) {
      alert(
        "Excel export unavailable: the ExcelJS / workbook bundle is missing from this report.\\n\\n" +
        "Regenerate it after running npm install (needs the exceljs package)."
      );
      return;
    }
    const btn = document.getElementById("btnXlsx");
    const prev = btn.textContent;
    btn.disabled = true;
    btn.textContent = "Building Excel…";
    try {
      const name = await api.downloadBrowser(ExcelJS, D);
      console.log("Excel exported:", name);
    } catch (err) {
      alert("Excel export failed: " + (err && err.message));
    } finally {
      btn.disabled = false;
      btn.textContent = prev;
    }
  });

  document.getElementById("btnPdf").addEventListener("click", () => {
    if (!window.jspdf || !window.jspdf.jsPDF) {
      alert(
        "PDF export unavailable: the jsPDF bundle is missing from this report.\\n\\n" +
        "Regenerate it after running npm install, or use Print \\u2192 Save as PDF."
      );
      return;
    }
    try {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF({ orientation: "p", unit: "mm", format: "a4" });
    const PAGE_W = 210, PAGE_H = 297, MARGIN = 20, CONTENT_W = PAGE_W - MARGIN * 2;
    const C = {
      coverDark: [11, 17, 32], coverMid: [26, 35, 50], cardDark: [20, 30, 52],
      navy: [15, 23, 42], white: [255, 255, 255], body: [51, 65, 85], muted: [148, 163, 184],
      border: [226, 232, 240], tableHeader: [248, 250, 252], tableStripe: [241, 245, 249],
      accent: [45, 212, 191], emerald: [16, 185, 129], red: [239, 68, 68], amber: [234, 179, 8],
      green: [22, 163, 74], blue: [59, 130, 246], gray: [148, 163, 184], critical: [220, 38, 38]
    };
    const sanitize = (t) => String(t ?? "")
      .replace(/[\\u2018\\u2019\\u201A]/g, "'")
      .replace(/[\\u201C\\u201D\\u201E]/g, '"')
      .replace(/\\u2026/g, "...")
      .replace(/[\\u2013\\u2014]/g, "-")
      .replace(/\\u2192/g, " -> ")
      .replace(/[\\u2022\\u2023\\u25E6]/g, "-")
      .replace(/[^\\x00-\\xFF]/g, "");
    const sevColor = (s) => {
      const t = String(s || "").toLowerCase();
      if (t === "critical") return C.critical;
      if (t === "high") return C.red;
      if (t === "medium") return C.amber;
      if (t === "low") return C.green;
      return C.gray;
    };
    const statusColor = (s) => {
      const t = String(s || "").toLowerCase();
      if (t === "pass") return C.emerald;
      if (t === "fail") return C.red;
      if (t === "partial") return C.amber;
      return C.gray;
    };
    // Same thresholds as the HTML gauge, so a score does not change severity
    // between the on-screen report and the exported PDF.
    const scoreColor = (score) => {
      if (score >= 75) return C.emerald;
      if (score >= 50) return C.amber;
      return C.red;
    };
    let y = MARGIN;
    const ensure = (need) => {
      if (y + need > PAGE_H - MARGIN) { doc.addPage(); y = MARGIN; }
      return y;
    };
    const wrapLines = (text, maxW) => {
      doc.setFontSize(8); doc.setFont("helvetica", "normal");
      const words = sanitize(text).split(/\\s+/);
      const lines = []; let cur = "";
      for (const word of words) {
        const next = cur ? cur + " " + word : word;
        if (doc.getTextWidth(next) > maxW && cur) { lines.push(cur); cur = word; }
        else cur = next;
      }
      if (cur) lines.push(cur);
      return lines.length ? lines : [""];
    };
    const drawWrapped = (text, x, maxW, lineH) => {
      lineH = lineH || 4;
      doc.setFontSize(8); doc.setFont("helvetica", "normal"); doc.setTextColor(...C.body);
      for (const para of sanitize(text).split("\\n")) {
        for (const line of wrapLines(para, maxW)) {
          ensure(lineH);
          doc.text(line, x, y);
          y += lineH;
        }
      }
      return y;
    };
    const drawBadge = (x, yy, label, color) => {
      doc.setFontSize(7); doc.setFont("helvetica", "bold");
      const w = doc.getTextWidth(label) + 6;
      doc.setFillColor(Math.min(color[0] + 180, 255), Math.min(color[1] + 180, 255), Math.min(color[2] + 180, 255));
      doc.roundedRect(x, yy, w, 5, 1.5, 1.5, "F");
      doc.setTextColor(...color);
      doc.text(label, x + 3, yy + 3.7);
      doc.setFont("helvetica", "normal");
      return w;
    };
    const drawScoreBar = (x, yy, width, score, color) => {
      doc.setFillColor(...C.tableStripe);
      doc.roundedRect(x, yy, width, 3.5, 1, 1, "F");
      doc.setFillColor(...color);
      doc.roundedRect(x, yy, Math.max((score / 100) * width, 1), 3.5, 1, 1, "F");
      doc.setFontSize(6.5); doc.setFont("helvetica", "bold"); doc.setTextColor(...C.body);
      doc.text(String(score), x + width + 2, yy + 3);
      doc.setFont("helvetica", "normal");
    };
    const drawKpi = (x, yy, label, value, color) => {
      doc.setFillColor(...C.tableHeader);
      doc.roundedRect(x, yy, 38, 22, 2, 2, "F");
      doc.setDrawColor(...C.border); doc.setLineWidth(0.3);
      doc.roundedRect(x, yy, 38, 22, 2, 2, "S");
      doc.setFillColor(...color); doc.rect(x + 4, yy + 2, 30, 1.2, "F");
      doc.setFontSize(16); doc.setFont("helvetica", "bold"); doc.setTextColor(...color);
      doc.text(value, x + 19 - doc.getTextWidth(value) / 2, yy + 13);
      doc.setFontSize(6.5); doc.setFont("helvetica", "normal"); doc.setTextColor(...C.muted);
      doc.text(label, x + 19 - doc.getTextWidth(label) / 2, yy + 19);
    };
    const drawSection = (title, reserve) => {
      y = ensure(18 + (reserve || 20));
      doc.setFillColor(...C.accent); doc.rect(MARGIN, y, 3, 10, "F");
      doc.setFontSize(12); doc.setFont("helvetica", "bold"); doc.setTextColor(...C.navy);
      doc.text(sanitize(title), MARGIN + 8, y + 7);
      doc.setDrawColor(...C.border); doc.setLineWidth(0.3);
      doc.line(MARGIN, y + 12, MARGIN + CONTENT_W, y + 12);
      doc.setFont("helvetica", "normal");
      y += 18;
    };
    const drawTable = (columns, rows) => {
      y = ensure(17);
      let x = MARGIN;
      doc.setFillColor(...C.tableHeader); doc.rect(MARGIN, y, CONTENT_W, 9, "F");
      doc.setDrawColor(...C.border); doc.setLineWidth(0.2); doc.rect(MARGIN, y, CONTENT_W, 9, "S");
      doc.setFontSize(8); doc.setFont("helvetica", "bold"); doc.setTextColor(...C.navy);
      for (const col of columns) { doc.text(col.header, x + 2, y + 6); x += col.width; }
      y += 9;
      for (let rowIdx = 0; rowIdx < rows.length; rowIdx++) {
        const row = rows[rowIdx];
        let lineCount = 1;
        for (let c = 0; c < columns.length; c++) {
          const cell = row[c];
          const text = typeof cell === "string" ? cell : (cell && cell.text && !cell.badge ? cell.text : "");
          if (text) lineCount = Math.max(lineCount, wrapLines(text, columns[c].width - 4).length);
        }
        const rowH = Math.max(8, 2.5 + lineCount * 3.5 + 2);
        y = ensure(rowH);
        if (rowIdx % 2 === 1) { doc.setFillColor(...C.tableStripe); doc.rect(MARGIN, y, CONTENT_W, rowH, "F"); }
        doc.setDrawColor(...C.border); doc.setLineWidth(0.1); doc.rect(MARGIN, y, CONTENT_W, rowH, "S");
        x = MARGIN;
        for (let c = 0; c < columns.length; c++) {
          const cell = row[c]; const col = columns[c];
          if (typeof cell === "string") {
            doc.setFontSize(8); doc.setFont("helvetica", "normal"); doc.setTextColor(...C.body);
            wrapLines(cell, col.width - 4).forEach((line, i) => doc.text(line, x + 2, y + 2.5 + 3.5 * (i + 1)));
          } else if (cell && cell.badge) {
            drawBadge(x + 2, y + 1.5, cell.text, cell.badge);
          } else if (cell && cell.scoreBar != null) {
            drawScoreBar(x + 2, y + rowH / 2 - 1.75, col.width - 6, cell.scoreBar, cell.color);
          } else if (cell) {
            doc.setFontSize(8); doc.setFont("helvetica", "normal"); doc.setTextColor(...C.body);
            wrapLines(cell.text || "", col.width - 4).forEach((line, i) => doc.text(line, x + 2, y + 2.5 + 3.5 * (i + 1)));
          }
          x += col.width;
        }
        y += rowH;
      }
      y += 4;
    };
    const clipText = (text, max) => {
      const s = sanitize(String(text || "")).replace(/\\s+/g, " ").trim();
      if (s.length <= max) return s;
      const cut = s.slice(0, max);
      const sp = cut.lastIndexOf(" ");
      return (sp > max * 0.55 ? cut.slice(0, sp) : cut).trim() + "...";
    };
    const firstFix = (text) => {
      const s = String(text || "").replace(/\\s+/g, " ").trim();
      if (!s) return "";
      // Prefer first numbered step or first sentence.
      const step = s.match(/^\\s*1\\)\\s*([^2]+?)(?:\\s*2\\)|$)/);
      if (step) return clipText(step[1], 160);
      const sent = s.match(/^(.+?[.!?])(\\s|$)/);
      return clipText(sent ? sent[1] : s, 160);
    };
    const areaOf = (id) => {
      const m = String(id || "").match(/^NARR\\.([^.]+)/i);
      return m ? m[1] : "";
    };

    const drawFindingCard = (n) => {
      const sev = String(n.Severity || "Info");
      const color = sevColor(sev);
      const prio = String(n.Priority || "Later");
      const prioColor = prio === "Now" ? C.critical : prio === "Next" ? C.amber : C.gray;
      y = ensure(32);
      // Header bar
      doc.setFillColor(Math.min(color[0] + 220, 255), Math.min(color[1] + 220, 255), Math.min(color[2] + 220, 255));
      doc.roundedRect(MARGIN, y, CONTENT_W, 8, 1.2, 1.2, "F");
      doc.setFillColor(...color); doc.rect(MARGIN, y, 2.5, 8, "F");
      let bx = MARGIN + 5;
      bx += drawBadge(bx, y + 1.5, prio.toUpperCase(), prioColor) + 2;
      bx += drawBadge(bx, y + 1.5, sev.toUpperCase().slice(0, 8), color) + 3;
      const area = areaOf(n.Id);
      if (area) {
        doc.setFontSize(7); doc.setFont("helvetica", "normal"); doc.setTextColor(...C.muted);
        doc.text(area, bx, y + 5.5);
      }
      y += 11;
      doc.setFontSize(10); doc.setFont("helvetica", "bold"); doc.setTextColor(...C.navy);
      const titleLines = wrapLines(n.Title || n.Id || "Finding", CONTENT_W - 8);
      for (const line of titleLines.slice(0, 2)) {
        ensure(5); doc.text(line, MARGIN + 4, y); y += 4.2;
      }
      if (n.Id) {
        doc.setFontSize(7); doc.setFont("helvetica", "normal"); doc.setTextColor(...C.muted);
        doc.text(sanitize(n.Id), MARGIN + 4, y); y += 3.8;
      }
      if (n.Narrative) {
        y = drawWrapped(clipText(n.Narrative, 320), MARGIN + 4, CONTENT_W - 8, 3.5);
      }
      if (n.Remediation) {
        doc.setFont("helvetica", "bold"); doc.setFontSize(8); doc.setTextColor(...C.accent);
        ensure(4); doc.text("FIX", MARGIN + 4, y); y += 3.4;
        doc.setFont("helvetica", "normal");
        y = drawWrapped(clipText(n.Remediation, 420), MARGIN + 4, CONTENT_W - 8, 3.5);
      }
      if (n.Evidence) {
        const bits = String(n.Evidence).split(" | ").map((s) => s.trim()).filter(Boolean).slice(0, 2);
        if (bits.length) {
          doc.setFontSize(7); doc.setTextColor(...C.muted);
          ensure(3.5); doc.text("Evidence", MARGIN + 4, y); y += 3;
          for (const b of bits) y = drawWrapped("- " + clipText(b, 180), MARGIN + 4, CONTENT_W - 8, 3.2);
        }
      }
      y += 4;
    };
    const drawFooter = (pageLabel, totalPages) => {
      const yy = PAGE_H - 12;
      doc.setFontSize(7); doc.setFont("helvetica", "normal"); doc.setTextColor(...C.muted);
      const brand = "Entra Collect";
      const page = totalPages ? ("Page " + pageLabel + " / " + totalPages) : ("Page " + pageLabel);
      const date = new Date().toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
      doc.text(brand, MARGIN, yy);
      doc.text(page, PAGE_W / 2 - doc.getTextWidth(page) / 2, yy);
      doc.text(date, PAGE_W - MARGIN - doc.getTextWidth(date), yy);
      doc.setDrawColor(...C.border); doc.setLineWidth(0.2);
      doc.line(MARGIN, yy - 4, PAGE_W - MARGIN, yy - 4);
    };

    const prioOrder = { Now: 0, Next: 1, Later: 2 };
    const sevOrder = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
    const sortedNarr = [...(D.narratives || [])].sort((a, b) => {
      const pa = prioOrder[a.Priority] ?? 3;
      const pb = prioOrder[b.Priority] ?? 3;
      if (pa !== pb) return pa - pb;
      return (sevOrder[a.Severity] ?? 9) - (sevOrder[b.Severity] ?? 9);
    });
    const nowNarr = sortedNarr.filter((n) => n.Priority === "Now");
    const nextNarr = sortedNarr.filter((n) => n.Priority === "Next");
    const laterNarr = sortedNarr.filter((n) => n.Priority !== "Now" && n.Priority !== "Next");
    const nextHigh = nextNarr.filter((n) => /critical|high/i.test(n.Severity || ""));
    const byPrioPdf = {
      Now: nowNarr.length,
      Next: nextNarr.length,
      Later: laterNarr.length,
    };
    const apGapsPdf = (D.attackChecklist || []).filter((c) =>
      /fail|partial/i.test(String(c.Status || ""))
    );

    // ── Cover
    doc.setFillColor(...C.coverDark); doc.rect(0, 0, PAGE_W, PAGE_H, "F");
    doc.setFillColor(...C.coverMid); doc.rect(0, 0, PAGE_W, 118, "F");
    doc.setFontSize(14); doc.setFont("helvetica", "bold"); doc.setTextColor(...C.accent);
    doc.text("Entra Collect", MARGIN, 30);
    doc.setFillColor(...C.accent); doc.rect(MARGIN, 52, 3, 46, "F");
    doc.setFontSize(24); doc.setTextColor(...C.white);
    doc.text("Security Findings Report", MARGIN + 10, 70);
    doc.setFontSize(11); doc.setFont("helvetica", "normal"); doc.setTextColor(...C.muted);
    doc.text("Executive remediation brief — Entra / M365", MARGIN + 10, 84);
    doc.setFontSize(9);
    doc.text(sanitize(D.meta.outputDir || ""), MARGIN + 10, 96);

    const cardY = 140;
    doc.setFillColor(...C.cardDark); doc.roundedRect(MARGIN, cardY, CONTENT_W, 78, 3, 3, "F");
    const now = new Date();
    const dateStr = now.toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
    doc.setFontSize(8); doc.setTextColor(...C.muted); doc.text("Generated", MARGIN + 10, cardY + 14);
    doc.setTextColor(...C.white); doc.setFontSize(10); doc.text(dateStr, MARGIN + 10, cardY + 22);
    doc.setFontSize(8); doc.setTextColor(...C.muted); doc.text("Collected", MARGIN + 10, cardY + 36);
    doc.setTextColor(...C.white); doc.setFontSize(9);
    doc.text(sanitize((S.collectedAt || "").slice(0, 19).replace("T", " ")), MARGIN + 10, cardY + 44);

    doc.setFontSize(8); doc.setTextColor(...C.muted); doc.text("Posture score", MARGIN + 105, cardY + 14);
    doc.setTextColor(...C.accent); doc.setFontSize(28); doc.setFont("helvetica", "bold");
    doc.text(String(D.score ?? 0), MARGIN + 105, cardY + 32);
    doc.setFontSize(9); doc.setFont("helvetica", "normal"); doc.setTextColor(...C.muted);
    doc.text("/ 100", MARGIN + 105 + doc.getTextWidth(String(D.score ?? 0)) + 3, cardY + 32);

    // Severity chips on cover
    const chipY = cardY + 52;
    const chips = [
      ["Critical", D.sevCount.Critical || 0, C.critical],
      ["High", D.sevCount.High || 0, C.red],
      ["Now", byPrioPdf.Now, C.critical],
      ["Next", byPrioPdf.Next, C.amber],
    ];
    let cx = MARGIN + 10;
    for (const [label, val, col] of chips) {
      const w = drawBadge(cx, chipY, label.toUpperCase() + "  " + val, col);
      cx += w + 4;
    }

    doc.setFontSize(8); doc.setTextColor(...C.muted);
    doc.text("Confidential — authorized assessment only. Work Now items first.", MARGIN, PAGE_H - 20);
    doc.addPage();

    // ── Executive overview
    y = MARGIN;
    drawSection("Executive overview", 40);
    const kx = MARGIN + 2;
    drawKpi(kx, y, "Score", String(D.score ?? 0), scoreColor(D.score));
    drawKpi(kx + 42, y, "Critical", String(D.sevCount.Critical || 0), C.critical);
    drawKpi(kx + 84, y, "High", String(D.sevCount.High || 0), C.red);
    drawKpi(kx + 126, y, "AP gaps", String(apGapsPdf.length), C.red);
    y += 28;
    drawKpi(kx, y, "Now", String(byPrioPdf.Now), C.critical);
    drawKpi(kx + 42, y, "Next", String(byPrioPdf.Next), C.amber);
    drawKpi(kx + 84, y, "Later", String(byPrioPdf.Later), C.gray);
    drawKpi(kx + 126, y, "Findings", String((D.narratives || []).length), C.accent);
    y += 30;
    doc.setFontSize(8); doc.setFont("helvetica", "normal"); doc.setTextColor(...C.muted);
    doc.text("This PDF is the steering brief: Now details + Next High titles. Full evidence lives in the HTML report / Excel.", MARGIN, y);
    y += 7;

    if (!S.huntingCanHunt) {
      y = ensure(14);
      doc.setFillColor(255, 247, 237);
      doc.roundedRect(MARGIN, y, CONTENT_W, 11, 2, 2, "F");
      doc.setFillColor(...C.amber); doc.rect(MARGIN, y, 2.5, 11, "F");
      doc.setFontSize(8); doc.setTextColor(146, 64, 14);
      doc.text("Hunting limited (" + sanitize(S.huntingApiStatus || "unavailable") + ") — some endpoint checks were skipped, not clean.", MARGIN + 6, y + 7);
      y += 14;
    }

    // ── NOW action table (readable Fix column)
    drawSection("Now — fix this week");
    if (!nowNarr.length) {
      doc.setFontSize(9); doc.setTextColor(...C.muted);
      doc.text("No Now-priority expert findings.", MARGIN, y); y += 8;
    } else {
      drawTable(
        [
          { header: "#", width: 8 },
          { header: "Sev", width: 20 },
          { header: "Finding", width: 78 },
          { header: "Fix", width: 64 }
        ],
        nowNarr.map((n, i) => [
          String(i + 1),
          { text: String(n.Severity || "").toUpperCase().slice(0, 8), badge: sevColor(n.Severity) },
          clipText(n.Title || n.Id || "", 95),
          firstFix(n.Remediation)
        ])
      );
    }

    // ── NEXT High compact
    drawSection("Next — High priority backlog");
    if (!nextHigh.length) {
      doc.setFontSize(9); doc.setTextColor(...C.muted);
      doc.text("No Next/High findings.", MARGIN, y); y += 8;
    } else {
      drawTable(
        [
          { header: "#", width: 8 },
          { header: "Finding", width: 92 },
          { header: "Fix", width: 70 }
        ],
        nextHigh.map((n, i) => [
          String(i + 1),
          clipText(n.Title || n.Id || "", 110),
          firstFix(n.Remediation)
        ])
      );
    }
    if (laterNarr.length || nextNarr.length > nextHigh.length) {
      y = ensure(10);
      doc.setFontSize(8); doc.setTextColor(...C.muted);
      doc.text(
        "Deferred: " +
          laterNarr.length + " Later + " +
          Math.max(0, nextNarr.length - nextHigh.length) +
          " Next (Medium/Low/Info) — see HTML Expert findings / Excel remediation plan.",
        MARGIN,
        y
      );
      y += 8;
    }

    // ── NOW finding details only
    drawSection("Now — finding details");
    if (!nowNarr.length) {
      doc.setFontSize(9); doc.setTextColor(...C.muted);
      doc.text("No Now findings to detail.", MARGIN, y); y += 8;
    } else {
      for (const n of nowNarr) drawFindingCard(n);
    }

    // ── Attack-path gaps
    if (apGapsPdf.length) {
      drawSection("Attack-path gaps");
      drawTable(
        [
          { header: "Status", width: 22 },
          { header: "Check", width: 78 },
          { header: "Evidence", width: 70 }
        ],
        apGapsPdf.slice(0, 14).map((c) => [
          { text: String(c.Status || "").toUpperCase(), badge: statusColor(c.Status) },
          clipText(c.Title || c.CheckId || "", 90),
          clipText(c.Evidence || "", 85)
        ])
      );
    }

    // ── CA coverage (gaps first)
    if ((D.caCoverage || []).length) {
      drawSection("Conditional Access coverage");
      const caRows = [...(D.caCoverage || [])].sort((a, b) => {
        const aa = String(a.Covered).toLowerCase() === "true" ? 1 : 0;
        const bb = String(b.Covered).toLowerCase() === "true" ? 1 : 0;
        return aa - bb;
      });
      drawTable(
        [
          { header: "Control", width: 78 },
          { header: "Covered", width: 24 },
          { header: "Policies", width: 68 }
        ],
        caRows.slice(0, 14).map((c) => [
          clipText(c.Control || "", 90),
          {
            text: String(c.Covered).toLowerCase() === "true" ? "YES" : "NO",
            badge: String(c.Covered).toLowerCase() === "true" ? C.emerald : C.red
          },
          clipText(c.Policies || "", 80)
        ])
      );
    }

    // ── Selective evidence snapshot (not a full inventory dump)
    const epPdf = D.endpoints || {};
    const rmmFam = (epPdf.rmmFamily || []).filter((r) => Number(r.AgentDevices || r.Devices || 0) > 0);
    const hasSnap =
      (D.gaPath || []).length ||
      (D.risky || []).length ||
      (D.deviceCode || []).length ||
      rmmFam.length ||
      (D.tvmStats && D.tvmStats.bySoftware || []).length ||
      (D.tvmWin || []).length;
    if (hasSnap) {
      drawSection("Evidence snapshots");
      if ((D.gaPath || []).length) {
        y = ensure(8);
        doc.setFontSize(9); doc.setFont("helvetica", "bold"); doc.setTextColor(...C.navy);
        doc.text("Apps with path to Global Admin", MARGIN, y); y += 4;
        drawTable(
          [
            { header: "App", width: 70 },
            { header: "Permission", width: 60 },
            { header: "Note", width: 40 }
          ],
          (D.gaPath || []).slice(0, 8).map((r) => [
            clipText(r.SPNDisplayName || "", 55),
            clipText(r.Permission || "", 50),
            clipText(r.AttackNote || "", 40)
          ])
        );
      }
      if ((D.risky || []).length) {
        y = ensure(8);
        doc.setFontSize(9); doc.setFont("helvetica", "bold"); doc.setTextColor(...C.navy);
        doc.text("Risky users (top)", MARGIN, y); y += 4;
        drawTable(
          [
            { header: "UPN", width: 78 },
            { header: "Level", width: 28 },
            { header: "State", width: 64 }
          ],
          (D.risky || []).slice(0, 8).map((r) => [
            clipText(r.UPN || "", 70),
            { text: String(r.RiskLevel || "").toUpperCase() || "—", badge: sevColor(r.RiskLevel === "high" ? "Critical" : r.RiskLevel === "medium" ? "High" : "Info") },
            clipText(r.RiskState || r.RiskDetail || "", 60)
          ])
        );
      }
      if ((D.deviceCode || []).length) {
        y = ensure(8);
        doc.setFontSize(9); doc.setFont("helvetica", "bold"); doc.setTextColor(...C.navy);
        doc.text("Device-code users (sample)", MARGIN, y); y += 4;
        drawTable(
          [{ header: "UPN", width: 90 }, { header: "Events", width: 25 }, { header: "Apps", width: 55 }],
          (D.deviceCode || []).slice(0, 8).map((r) => [
            clipText(r.UPN || "", 80),
            String(r.Events || ""),
            clipText(r.Apps || "", 55)
          ])
        );
      }
      if (rmmFam.length) {
        y = ensure(8);
        doc.setFontSize(9); doc.setFont("helvetica", "bold"); doc.setTextColor(...C.navy);
        doc.text("RMM desktop agents (noise filtered)", MARGIN, y); y += 4;
        drawTable(
          [
            { header: "Family", width: 40 },
            { header: "Agents", width: 24 },
            { header: "Noise", width: 24 },
            { header: "Verdict", width: 82 }
          ],
          rmmFam.slice(0, 8).map((r) => [
            r.Family || "",
            String(r.AgentDevices != null ? r.AgentDevices : r.Devices || ""),
            String(r.NoiseDevices != null ? r.NoiseDevices : ""),
            clipText(r.Verdict || "", 90)
          ])
        );
      }
      if ((D.tvmWin || []).length) {
        y = ensure(8);
        doc.setFontSize(9); doc.setFont("helvetica", "bold"); doc.setTextColor(...C.navy);
        doc.text("Worst Windows TVM hosts", MARGIN, y); y += 4;
        drawTable(
          [
            { header: "Device", width: 70 },
            { header: "Software", width: 40 },
            { header: "Crit", width: 20 },
            { header: "High", width: 20 },
            { header: "Vulns", width: 20 }
          ],
          (D.tvmWin || []).slice(0, 8).map((r) => [
            clipText(r.DeviceName || "", 55),
            clipText(r.Software || "", 32),
            String(r.Critical || ""),
            String(r.High || ""),
            String(r.Vulns || "")
          ])
        );
      } else if ((D.tvmStats && D.tvmStats.bySoftware || []).length) {
        y = ensure(8);
        doc.setFontSize(9); doc.setFont("helvetica", "bold"); doc.setTextColor(...C.navy);
        doc.text("TVM by software (top)", MARGIN, y); y += 4;
        drawTable(
          [
            { header: "Software", width: 70 },
            { header: "CVE rows", width: 30 },
            { header: "Critical", width: 30 },
            { header: "High", width: 40 }
          ],
          (D.tvmStats.bySoftware || []).slice(0, 8).map((r) => [
            clipText(r.Software || "", 55),
            String(r.CveRows || ""),
            String(r.Critical || ""),
            String(r.High || "")
          ])
        );
      }
    }

    // ── Limitations (short)
    drawSection("Limitations");
    const covFail = (D.coverage || []).filter((c) =>
      /skip|unavail|fail|denied|forbid/i.test(String(c.Status || ""))
    );
    const covRows = (covFail.length ? covFail : (D.coverage || [])).slice(0, 10);
    if (covRows.length) {
      drawTable(
        [
          { header: "Domain", width: 70 },
          { header: "Status", width: 36 },
          { header: "Impact", width: 64 }
        ],
        covRows.map((c) => [
          clipText(c.Domain || "", 60),
          clipText(c.Status || "", 28),
          clipText(c.Impact || "", 70)
        ])
      );
    }
    if (D.errors.length) {
      y = ensure(8);
      doc.setFontSize(9); doc.setFont("helvetica", "bold"); doc.setTextColor(...C.navy);
      doc.text("Failed API calls", MARGIN, y); y += 4;
      drawTable(
        [
          { header: "Area", width: 40 },
          { header: "Label", width: 55 },
          { header: "Reason", width: 75 }
        ],
        D.errors.slice(0, 8).map((e) => [
          clipText(e.area || "", 35),
          clipText(e.label || "", 45),
          clipText((e.reason || "") + (e.needed ? " [" + e.needed + "]" : ""), 70)
        ])
      );
    }

    // Footers on content pages (skip cover = page 1)
    const total = doc.getNumberOfPages();
    const contentPages = Math.max(total - 1, 1);
    for (let i = 2; i <= total; i++) {
      doc.setPage(i);
      drawFooter(i - 1, contentPages);
    }
    doc.save("EntraCollect_Findings_" + sanitize(D.meta.outputDir || "report") + ".pdf");
    } catch (err) {
      console.error(err);
      alert("PDF export failed: " + (err && err.message) + "\\n\\nUse Print \\u2192 Save as PDF instead.");
    }
  });
})();
</script>
</body>
</html>`;
}

async function writeReport(outDir) {
  const data = buildReportPayload(outDir);
  const html = renderHtml(data);
  const outPath = path.join(outDir, "00_REPORT.html");
  fs.writeFileSync(outPath, html, "utf8");
  fs.writeFileSync(
    path.join(outDir, "00_REPORT_DATA.json"),
    JSON.stringify(
      {
        meta: data.meta,
        score: data.score,
        sevCount: data.sevCount,
        inventorySevCount: data.inventorySevCount,
        expertFindingCount: (data.narratives || []).length,
        narratives: (data.narratives || []).map((n) => ({
          Id: n.Id,
          Severity: n.Severity,
          Title: n.Title,
        })),
        categoryCount: data.byArea.length,
        errorCount: data.errors.length,
        huntingCanHunt: data.summary.huntingCanHunt,
        huntingApiStatus: data.summary.huntingApiStatus,
        findingsCount: data.findings.length,
        categories: data.byArea.map((a) => ({
          area: a.area,
          High: a.High,
          Medium: a.Medium,
          Info: a.Info,
          total: a.total,
        })),
        errors: data.errors.map((e) => ({
          area: e.area,
          label: e.label,
          reason: e.reason,
          needed: e.needed,
        })),
      },
      null,
      2
    ),
    "utf8"
  );
  try {
    const ExcelJS = require("exceljs");
    const xlsxPath = path.join(outDir, "00_Remediation_Plan.xlsx");
    await writeXlsxReport(ExcelJS, data, xlsxPath);
    console.log("  ✓ 00_Remediation_Plan.xlsx");
  } catch (e) {
    console.warn("  ⚠ Excel workbook not written:", e.message);
  }
  return outPath;
}

async function main(argvOut) {
  if (argvOut === "--help" || argvOut === "-h") {
    console.log(`Entra Collect — report builder

Rebuild expert findings + HTML dashboard + Excel remediation workbook
from an existing collection folder (does not re-collect).

Usage:
  node report.js [outputDir]
  node report.js                 # latest non-empty output_* in the current directory
  node report.js --help

Examples:
  node report.js output_YYYY-MM-DD_HHMM

Outputs:
  00_REPORT.html
  00_Remediation_Plan.xlsx   (This Week / Remediation Plan / …)
  00_Expert_Findings.csv|json
  00_SUMMARY.md|json

Open the HTML, then use Download PDF / Download Excel in the page.
`);
    process.exit(0);
  }
  // Collections default to the working directory; the tool folder is only a
  // fallback for older layouts.
  const outDir = argvOut
    ? path.resolve(argvOut)
    : latestOutputDir(process.cwd()) ||
      (path.resolve(process.cwd()) !== path.resolve(__dirname)
        ? latestOutputDir(path.resolve(__dirname))
        : null);
  if (!outDir || !fs.existsSync(outDir)) {
    console.error(
      "No output directory found.\n" +
        "  Usage: node report.js output_YYYY-MM-DD_HHMM\n" +
        "  Help:  node report.js --help"
    );
    process.exit(1);
  }
  console.log(`Entra Collect — building report for ${path.basename(outDir)}`);
  const p = await writeReport(outDir);
  console.log(`✓ Report written: ${p}`);
  console.log(`  Excel: ${path.join(outDir, "00_Remediation_Plan.xlsx")}`);
  console.log(`  Open the HTML, then Download PDF / Excel from the page.`);
  return p;
}

if (require.main === module) {
  main(process.argv[2]).catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

module.exports = { writeReport, buildReportPayload, latestOutputDir, parseCsv };
