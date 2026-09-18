/**
 * Adaptive security intel — runs with or without MDE Device* tables.
 *
 * When DeviceInfo / TVM / process tables are present, endpoint hunts already
 * cover RMM / AI / patch / vulns. This module still adds:
 *   - Defender XDR alerts (AlertInfo / AlertEvidence) — richer than Graph alerts_v2
 *   - Exposure Manager graph (critical assets + edges)
 *   - IdentityLogonEvents depth (failed logons, privileged account activity)
 *
 * When Device* tables are missing (tenants without full MDE endpoint telemetry), these become the
 * primary hunting signal instead of empty RMM / AI / patch CSVs.
 *
 * Artifacts: 36_ alerts, 37_ exposure (+ paths), 38_ identity intel
 * (Logon + IdentityInfo/AccountInfo), 39_ cloud-app ops.
 */
const { soft } = require("./io");
const { clusterAlertsBySource } = require("./posture");
const { kqlGraphApiAuditWrites } = require("./schema");

function setOf(v) {
  if (Array.isArray(v)) return v.join(" | ");
  return v == null ? "" : String(v);
}

function errSnippet(e) {
  return String((e && e.message) || e || "")
    .replace(/\s+/g, " ")
    .slice(0, 160);
}

/**
 * Try KQL variants until one works. Intermediate 400s are expected when a
 * column is absent on a tenant — only the final failure is recorded as ERROR_*.
 */
async function huntFirst(graph, io, label, queries) {
  const list = (Array.isArray(queries) ? queries : [queries]).filter(Boolean);
  let lastErr;
  for (let i = 0; i < list.length; i++) {
    try {
      const res = await graph.post(`${graph.GRAPH}/security/runHuntingQuery`, {
        Query: list[i],
      });
      if (i > 0) console.log(`  · ${label}: ok on variant ${i + 1}/${list.length}`);
      return res;
    } catch (e) {
      lastErr = e;
      if (list.length > 1) {
        console.log(
          `  · ${label} variant ${i + 1}/${list.length} failed: ${errSnippet(e)}`
        );
      }
    }
  }
  if (lastErr) {
    await soft(label, async () => {
      throw lastErr;
    }, io);
  }
  return null;
}

async function hunt(graph, io, label, query) {
  return huntFirst(graph, io, label, [query]);
}

/**
 * @param {object} opts
 * @param {object} opts.schema
 * @param {object[]} [opts.privilegedAccounts] rows from 03_PrivilegedAccounts_HighValue
 */
async function collectAdaptiveIntel(graph, io, findings, summary, opts = {}) {
  const schema = opts.schema || {
    canHunt: false,
    has: () => false,
    hasAny: () => false,
    capabilities: {},
  };

  const caps = schema.capabilities || {};
  const worthRunning =
    schema.canHunt &&
    (caps.alerts || caps.exposureGraph || caps.identityIntel || caps.auditHunt);

  console.log("── Adaptive intel (alerts / exposure / identity — MDE-optional)");

  if (!worthRunning) {
    console.log(
      "  · Skip adaptive intel — need AlertInfo, ExposureGraph*, IdentityLogon/Info or CloudAppEvents"
    );
    summary.adaptiveIntel = { ran: false, reason: "no_usable_tables" };
    return;
  }

  summary.adaptiveIntel = {
    ran: true,
    mdeEndpoint: !!caps.mdeEndpoint,
    used: {
      alerts: !!caps.alerts,
      exposureGraph: !!caps.exposureGraph,
      identityIntel: !!caps.identityIntel,
      cloudApp: !!schema.has("CloudAppEvents"),
    },
  };

  if (!caps.mdeEndpoint) {
    console.log(
      "  · No MDE Device* tables — leaning on alerts / exposure graph / IdentityInfo / IdentityLogon"
    );
  }

  // ── 36) Defender XDR alerts ───────────────────────────────────────────
  // AlertInfo hunting schema has no Status column (that lives on incidents).
  let alertRows = [];
  if (schema.has("AlertInfo")) {
    const res = await huntFirst(graph, io, "hunt_alertinfo_30d", [
      `
AlertInfo
| where Timestamp > ago(30d)
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Count=count() by AlertId, Title, Severity, ServiceSource, DetectionSource, Category
| sort by Count desc
| take 200
`.trim(),
      `
AlertInfo
| where Timestamp > ago(30d)
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Count=count() by AlertId, Title, Severity, ServiceSource, DetectionSource
| sort by Count desc
| take 200
`.trim(),
      `
AlertInfo
| where Timestamp > ago(30d)
| project Timestamp, AlertId, Title, Severity, ServiceSource, DetectionSource
| sort by Timestamp desc
| take 200
`.trim(),
    ]);
    if (res && res.results) {
      alertRows = res.results.map((r) => ({
        AlertId: r.AlertId,
        Title: r.Title,
        Severity: r.Severity,
        ServiceSource: r.ServiceSource,
        DetectionSource: r.DetectionSource,
        Category: r.Category || "",
        Count: r.Count || 1,
        FirstSeen: r.FirstSeen || r.Timestamp,
        LastSeen: r.LastSeen || r.Timestamp,
      }));
      io.saveCsv("36_Security_Alerts_30d.csv", alertRows);
      summary.securityAlertsHunted = alertRows.length;
      const clustered = clusterAlertsBySource(alertRows);
      const high = clustered.high;
      const sev =
        clustered.endpointHigh ? "High" : high && clustered.irmHigh === high ? "Info" : high ? "Medium" : "Info";
      findings.push({
        Severity: sev,
        Area: "Alerts",
        Detail:
          `${alertRows.length} Defender alert group(s) in 30d (${high} High/Critical` +
          (clustered.irmHigh ? `, ${clustered.irmHigh} Purview IRM` : "") +
          (clustered.endpointHigh ? `, ${clustered.endpointHigh} endpoint/identity` : "") +
          `) — 36_Security_Alerts_30d.csv`,
      });
    }

    if (schema.has("AlertEvidence")) {
      const ev = await huntFirst(graph, io, "hunt_alertevidence_30d", [
        `
AlertEvidence
| where Timestamp > ago(30d)
| summarize Hits=count(), LastSeen=max(Timestamp), Titles=make_set(Title, 6), SampleEntities=make_set(EntityType, 6) by AccountUpn, DeviceName
| where isnotempty(AccountUpn) or isnotempty(DeviceName)
| sort by Hits desc
| take 200
`.trim(),
        `
AlertEvidence
| where Timestamp > ago(30d)
| summarize Hits=count(), LastSeen=max(Timestamp) by EntityType, EvidenceRole
| sort by Hits desc
| take 100
`.trim(),
      ]);
      if (ev && ev.results) {
        io.saveCsv(
          "36_Security_Alert_Evidence_30d.csv",
          ev.results.map((r) => ({
            AccountUpn: r.AccountUpn || "",
            DeviceName: r.DeviceName || "",
            EntityType: r.EntityType || "",
            EvidenceRole: r.EvidenceRole || "",
            Hits: r.Hits,
            LastSeen: r.LastSeen,
            Titles: setOf(r.Titles),
            SampleEntities: setOf(r.SampleEntities),
          }))
        );
      }
    }
  } else {
    console.log("  · Skip AlertInfo hunt (table missing)");
  }

  // ── 37) Exposure Manager graph ────────────────────────────────────────
  // Real columns: NodeId, NodeLabel, NodeName, Categories, NodeProperties, EntityIds.
  // Criticality / internet-facing live under NodeProperties.rawData.*.
  if (schema.has("ExposureGraphNodes")) {
    const nodes = await huntFirst(graph, io, "hunt_exposure_nodes", [
      `
ExposureGraphNodes
| extend CritLvl = toint(NodeProperties.rawData.criticalityLevel.criticalityLevel)
| extend Internet = tostring(NodeProperties.rawData.exposedToInternet)
| extend Sensitive = tostring(NodeProperties.rawData.containsSensitiveData)
| where isnotnull(CritLvl) or Internet =~ "true" or Sensitive =~ "true"
| extend CriticalityLabel = case(CritLvl == 0, "Very High", CritLvl == 1, "High", CritLvl == 2, "Medium", CritLvl == 3, "Low", "n/a")
| project NodeId, NodeName, NodeLabel, Categories, CriticalityLevel=CritLvl, CriticalityLabel, IsInternetFacing=Internet, ContainsSensitiveData=Sensitive
| sort by CriticalityLevel asc, NodeName asc
| take 200
`.trim(),
      `
ExposureGraphNodes
| extend CritLvl = toint(NodeProperties.rawData.criticalityLevel.criticalityLevel)
| where isnotnull(CritLvl) and CritLvl <= 1
| project NodeId, NodeName, NodeLabel, Categories, CriticalityLevel=CritLvl
| sort by CriticalityLevel asc
| take 200
`.trim(),
      `
ExposureGraphNodes
| project NodeId, NodeName, NodeLabel, Categories
| take 200
`.trim(),
    ]);
    if (nodes && nodes.results) {
      io.saveCsv(
        "37_Exposure_Critical_Assets.csv",
        nodes.results.map((r) => ({
          NodeId: r.NodeId,
          NodeName: r.NodeName,
          NodeLabel: r.NodeLabel,
          Categories: setOf(r.Categories),
          CriticalityLevel: r.CriticalityLevel ?? "",
          CriticalityLabel: r.CriticalityLabel || "",
          IsInternetFacing: r.IsInternetFacing || "",
          ContainsSensitiveData: r.ContainsSensitiveData || "",
        }))
      );
      summary.exposureCriticalAssets = nodes.results.length;
      const highCrit = nodes.results.filter(
        (r) => r.CriticalityLevel === 0 || r.CriticalityLevel === 1
      ).length;
      findings.push({
        Severity: highCrit >= 5 ? "Medium" : "Info",
        Area: "ExposureGraph",
        Detail: `${nodes.results.length} Exposure Graph asset(s) exported (${highCrit} Very High/High criticality) — 37_Exposure_Critical_Assets.csv`,
      });
    }

    if (schema.has("ExposureGraphEdges")) {
      const edges = await huntFirst(graph, io, "hunt_exposure_edges", [
        `
ExposureGraphEdges
| summarize EdgeCount=count() by EdgeLabel
| sort by EdgeCount desc
| take 100
`.trim(),
        `
ExposureGraphEdges
| summarize EdgeCount=count() by EdgeLabel, SourceNodeLabel, TargetNodeLabel
| sort by EdgeCount desc
| take 100
`.trim(),
      ]);
      if (edges && edges.results) {
        io.saveCsv(
          "37_Exposure_Edge_Types.csv",
          edges.results.map((r) => ({
            EdgeLabel: r.EdgeLabel,
            SourceNodeLabel: r.SourceNodeLabel || "",
            TargetNodeLabel: r.TargetNodeLabel || "",
            EdgeCount: r.EdgeCount,
          }))
        );
      }

      // Paths: edges touching Very High / High criticality nodes (attack-path view).
      const paths = await huntFirst(graph, io, "hunt_exposure_paths", [
        `
let crit = ExposureGraphNodes
| extend CritLvl = toint(NodeProperties.rawData.criticalityLevel.criticalityLevel)
| where isnotnull(CritLvl) and CritLvl <= 1
| project CritId=NodeId, CritName=NodeName, CritLabel=NodeLabel, CritLvl;
ExposureGraphEdges
| join kind=inner crit on $left.SourceNodeId == $right.CritId
| project EdgeLabel, CritName, CritLabel, CritLvl, Direction="from_critical", NeighborName=TargetNodeName, NeighborLabel=TargetNodeLabel, NeighborId=TargetNodeId
| take 400
`.trim(),
        `
let critIds = toscalar(
  ExposureGraphNodes
  | extend CritLvl = toint(NodeProperties.rawData.criticalityLevel.criticalityLevel)
  | where isnotnull(CritLvl) and CritLvl <= 1
  | summarize make_set(NodeId, 200)
);
ExposureGraphEdges
| where SourceNodeId in (critIds) or TargetNodeId in (critIds)
| project EdgeLabel, SourceNodeName, SourceNodeLabel, TargetNodeName, TargetNodeLabel, SourceNodeId, TargetNodeId
| take 400
`.trim(),
      ]);
      if (paths && paths.results && paths.results.length) {
        const pathRows = paths.results.map((r) => ({
          EdgeLabel: r.EdgeLabel || "",
          CritName: r.CritName || r.SourceNodeName || "",
          CritLabel: r.CritLabel || r.SourceNodeLabel || "",
          CritLvl: r.CritLvl ?? "",
          Direction: r.Direction || "touching_critical",
          NeighborName: r.NeighborName || r.TargetNodeName || "",
          NeighborLabel: r.NeighborLabel || r.TargetNodeLabel || "",
          NeighborId: r.NeighborId || r.TargetNodeId || "",
          SourceNodeName: r.SourceNodeName || "",
          TargetNodeName: r.TargetNodeName || "",
        }));
        // Also pull inbound edges when first variant only did outbound.
        if (pathRows.every((r) => r.Direction === "from_critical")) {
          const inbound = await huntFirst(
            graph,
            io,
            "hunt_exposure_paths_inbound",
            [
              `
let crit = ExposureGraphNodes
| extend CritLvl = toint(NodeProperties.rawData.criticalityLevel.criticalityLevel)
| where isnotnull(CritLvl) and CritLvl <= 1
| project CritId=NodeId, CritName=NodeName, CritLabel=NodeLabel, CritLvl;
ExposureGraphEdges
| join kind=inner crit on $left.TargetNodeId == $right.CritId
| project EdgeLabel, CritName, CritLabel, CritLvl, Direction="to_critical", NeighborName=SourceNodeName, NeighborLabel=SourceNodeLabel, NeighborId=SourceNodeId
| take 400
`.trim(),
            ]
          );
          if (inbound && inbound.results) {
            for (const r of inbound.results) {
              pathRows.push({
                EdgeLabel: r.EdgeLabel || "",
                CritName: r.CritName || "",
                CritLabel: r.CritLabel || "",
                CritLvl: r.CritLvl ?? "",
                Direction: "to_critical",
                NeighborName: r.NeighborName || "",
                NeighborLabel: r.NeighborLabel || "",
                NeighborId: r.NeighborId || "",
                SourceNodeName: "",
                TargetNodeName: "",
              });
            }
          }
        }
        io.saveCsv("37_Exposure_Critical_Paths.csv", pathRows.slice(0, 600));
        summary.exposureCriticalPaths = pathRows.length;
        findings.push({
          Severity: pathRows.length >= 20 ? "Medium" : "Info",
          Area: "ExposureGraph",
          Detail: `${pathRows.length} Exposure Graph edge(s) touching Very High/High assets — 37_Exposure_Critical_Paths.csv`,
        });
      }
    }
  } else {
    console.log("  · Skip ExposureGraph hunts (tables missing)");
  }

  // ── 38a) IdentityInfo / IdentityAccountInfo (UEBA inventory — often has rows when Logon is empty)
  if (schema.has("IdentityInfo")) {
    const idInfo = await huntFirst(graph, io, "hunt_identityinfo_critical", [
      `
IdentityInfo
| summarize arg_max(Timestamp, *) by AccountUpn
| extend Crit = toint(CriticalityLevel)
| where isnotempty(AssignedRoles)
    or isnotempty(PrivilegedEntraPimRoles)
    or (isnotempty(RiskLevel) and RiskLevel !~ "^(None)?$")
    or (isnotnull(Crit) and Crit >= 3)
| project AccountUpn, AccountDisplayName, CriticalityLevel=Crit, RiskLevel, RiskLevelDetails, RiskScore, BlastRadius, AssignedRoles, PrivilegedEntraPimRoles, IsAccountEnabled, Tags, Department, JobTitle, SourceProvider, IdentityEnvironment
| sort by RiskScore desc, CriticalityLevel desc
| take 200
`.trim(),
      `
IdentityInfo
| where isnotempty(AssignedRoles) or isnotempty(PrivilegedEntraPimRoles)
    or (isnotempty(RiskLevel) and RiskLevel !~ "^(None)?$")
| project AccountUpn, AccountDisplayName, CriticalityLevel, RiskLevel, RiskLevelDetails, RiskScore, BlastRadius, AssignedRoles, PrivilegedEntraPimRoles, IsAccountEnabled, Tags, Department, JobTitle, SourceProvider
| take 200
`.trim(),
    ]);
    if (idInfo && idInfo.results) {
      const rows = idInfo.results.map((r) => ({
        AccountUpn: r.AccountUpn || "",
        AccountDisplayName: r.AccountDisplayName || "",
        CriticalityLevel: r.CriticalityLevel ?? "",
        RiskLevel: r.RiskLevel || "",
        RiskLevelDetails: r.RiskLevelDetails || "",
        RiskScore: r.RiskScore ?? "",
        BlastRadius: setOf(r.BlastRadius),
        AssignedRoles: setOf(r.AssignedRoles),
        PrivilegedEntraPimRoles: setOf(r.PrivilegedEntraPimRoles),
        IsAccountEnabled: r.IsAccountEnabled ?? "",
        Tags: setOf(r.Tags),
        Department: r.Department || "",
        JobTitle: r.JobTitle || "",
        SourceProvider: r.SourceProvider || "",
        IdentityEnvironment: r.IdentityEnvironment || "",
      }));
      io.saveCsv("38_IdentityInfo_Critical.csv", rows);
      summary.identityInfoCriticalRows = rows.length;
      const risky = rows.filter((r) =>
        /^(high|medium|atRisk|confirmedcompromised)$/i.test(String(r.RiskLevel || "").trim())
      ).length;
      const withRoles = rows.filter(
        (r) => r.AssignedRoles || r.PrivilegedEntraPimRoles
      ).length;
      if (rows.length) {
        findings.push({
          Severity: risky ? "High" : withRoles >= 5 ? "Medium" : "Info",
          Area: "IdentityInfo",
          Detail: `${rows.length} IdentityInfo role/risk/criticality row(s)` +
            (risky ? ` (${risky} High/Medium RiskLevel)` : "") +
            (withRoles ? `, ${withRoles} with directory roles` : "") +
            ` — 38_IdentityInfo_Critical.csv`,
        });
      }
    }
  }

  if (schema.has("IdentityAccountInfo")) {
    const acct = await huntFirst(graph, io, "hunt_identityaccountinfo", [
      `
IdentityAccountInfo
| summarize arg_max(Timestamp, *) by AccountUpn
| where isnotempty(AssignedRoles) or isnotempty(EligibleRoles)
    or (isnotempty(CriticalityLevel) and toint(CriticalityLevel) <= 1)
| project AccountUpn, DisplayName, CriticalityLevel, AssignedRoles, EligibleRoles, EnrolledMfas, LastPasswordChangeTime, AccountStatus, TenantMembershipType, SourceProvider, AuthenticationMethod
| sort by toint(CriticalityLevel) asc
| take 300
`.trim(),
      `
IdentityAccountInfo
| where isnotempty(AssignedRoles) or isnotempty(EligibleRoles)
| project AccountUpn, DisplayName, CriticalityLevel, AssignedRoles, EligibleRoles, EnrolledMfas, LastPasswordChangeTime, AccountStatus, TenantMembershipType, SourceProvider
| take 300
`.trim(),
    ]);
    if (acct && acct.results) {
      const rows = acct.results.map((r) => ({
        AccountUpn: r.AccountUpn || "",
        DisplayName: r.DisplayName || "",
        CriticalityLevel: r.CriticalityLevel ?? "",
        AssignedRoles: setOf(r.AssignedRoles),
        EligibleRoles: setOf(r.EligibleRoles),
        EnrolledMfas: setOf(r.EnrolledMfas),
        LastPasswordChangeTime: r.LastPasswordChangeTime || "",
        AccountStatus: r.AccountStatus || "",
        TenantMembershipType: r.TenantMembershipType || "",
        SourceProvider: r.SourceProvider || "",
        AuthenticationMethod: r.AuthenticationMethod || "",
      }));
      io.saveCsv("38_IdentityAccountInfo_Privileged.csv", rows);
      summary.identityAccountInfoRows = rows.length;
      const withRoles = rows.filter(
        (r) => String(r.AssignedRoles || "").trim() || String(r.EligibleRoles || "").trim()
      ).length;
      if (rows.length) {
        findings.push({
          Severity: "Info",
          Area: "IdentityAccountInfo",
          Detail: `${rows.length} IdentityAccountInfo privileged/eligible row(s)` +
            (withRoles ? ` (${withRoles} with Assigned/Eligible roles)` : "") +
            ` — 38_IdentityAccountInfo_Privileged.csv`,
        });
      }
    }
  }

  // ── 38b) IdentityLogon depth ──────────────────────────────────────────
  if (schema.has("IdentityLogonEvents")) {
    const failed = await huntFirst(graph, io, "hunt_identity_failed_logons", [
      `
IdentityLogonEvents
| where Timestamp > ago(30d)
| where ActionType has_any ("Failed", "LogonFailed", "LogonFailure") or isnotempty(FailureReason)
| summarize Failures=count(), Ips=dcount(IPAddress), LastSeen=max(Timestamp), SampleIps=make_set(IPAddress, 6), SampleReasons=make_set(FailureReason, 4) by AccountUpn, Application, ActionType
| sort by Failures desc
| take 200
`.trim(),
      `
IdentityLogonEvents
| where Timestamp > ago(30d)
| where ActionType has "Fail"
| summarize Failures=count(), Ips=dcount(IPAddress), LastSeen=max(Timestamp), SampleIps=make_set(IPAddress, 6) by AccountUpn, Application, ActionType
| sort by Failures desc
| take 200
`.trim(),
      `
IdentityLogonEvents
| where Timestamp > ago(30d)
| summarize Events=count(), LastSeen=max(Timestamp) by AccountUpn, Application, ActionType
| sort by Events desc
| take 200
`.trim(),
    ]);
    if (failed && failed.results) {
      const failedOnly = failed.results.filter(
        (r) =>
          r.Failures != null ||
          /fail/i.test(String(r.ActionType || ""))
      );
      const rowsOut = (failedOnly.length ? failedOnly : failed.results).map(
        (r) => ({
          AccountUpn: r.AccountUpn,
          Application: r.Application,
          ActionType: r.ActionType,
          Failures: r.Failures ?? r.Events,
          DistinctIps: r.Ips,
          LastSeen: r.LastSeen,
          SampleIps: setOf(r.SampleIps),
          SampleReasons: setOf(r.SampleReasons),
        })
      );
      io.saveCsv("38_Identity_Failed_Logons_30d.csv", rowsOut);
      summary.identityFailedLogonRows = rowsOut.length;
      const heavy = rowsOut.filter((r) => Number(r.Failures) >= 50).length;
      if (failedOnly.length) {
        findings.push({
          Severity: heavy ? "High" : "Medium",
          Area: "IdentityLogon",
          Detail: `${failedOnly.length} failed-logon account/app row(s) in 30d (${heavy} with ≥50 failures) — 38_Identity_Failed_Logons_30d.csv`,
        });
      }
    }

    const byApp = await huntFirst(graph, io, "hunt_identity_logons_by_app", [
      `
IdentityLogonEvents
| where Timestamp > ago(30d)
| where isnotempty(Application)
| summarize Events=count(), Users=dcount(AccountUpn), LastSeen=max(Timestamp) by Application, Protocol, ActionType
| sort by Events desc
| take 100
`.trim(),
      `
IdentityLogonEvents
| where Timestamp > ago(30d)
| where isnotempty(Application)
| summarize Events=count(), Users=dcount(AccountUpn), LastSeen=max(Timestamp) by Application, ActionType
| sort by Events desc
| take 100
`.trim(),
    ]);
    if (byApp && byApp.results) {
      io.saveCsv(
        "38_Identity_Logons_ByApp_30d.csv",
        byApp.results.map((r) => ({
          Application: r.Application,
          Protocol: r.Protocol,
          ActionType: r.ActionType,
          Events: r.Events,
          Users: r.Users,
          LastSeen: r.LastSeen,
        }))
      );
    }

    // Privileged account activity — only if we have UPNs to look for.
    const privUpns = [
      ...new Set(
        (opts.privilegedAccounts || [])
          .map((r) =>
            String(r.UPNOrAppId || r.UPN || r.UserPrincipalName || "")
              .trim()
              .toLowerCase()
          )
          .filter((u) => u.includes("@"))
      ),
    ].slice(0, 40);

    if (privUpns.length) {
      // Portal KQL: build a dynamic array literal.
      const dyn = JSON.stringify(privUpns);
      const priv = await hunt(
        graph,
        io,
        "hunt_identity_privileged_logons",
        `
let priv = dynamic(${dyn});
IdentityLogonEvents
| where Timestamp > ago(30d)
| where tolower(AccountUpn) in (priv)
| summarize Events=count(), Apps=make_set(Application, 8), Ips=make_set(IPAddress, 8), LastSeen=max(Timestamp), Actions=make_set(ActionType, 6) by AccountUpn
| sort by Events desc
| take 100
`.trim()
      );
      if (priv && priv.results) {
        io.saveCsv(
          "38_Identity_Privileged_Logons_30d.csv",
          priv.results.map((r) => ({
            AccountUpn: r.AccountUpn,
            Events: r.Events,
            LastSeen: r.LastSeen,
            Apps: setOf(r.Apps),
            Ips: setOf(r.Ips),
            Actions: setOf(r.Actions),
          }))
        );
        summary.identityPrivilegedLogonRows = priv.results.length;
      }
    }
  } else {
    console.log("  · Skip IdentityLogon depth hunts (table missing)");
  }

  // ── CloudApp admin ops supplement (when high-value 25_* came back empty) ─
  if (schema.has("CloudAppEvents")) {
    const adminOps = await hunt(
      graph,
      io,
      "hunt_cloudapp_admin_ops",
      `
CloudAppEvents
| where Timestamp > ago(30d)
| where isnotempty(ActionType)
| where ActionType has_any ("Add", "Delete", "Update", "Set", "Remove", "Consent", "Grant", "Role", "Password", "Mailbox", "Forward", "App", "Policy", "Conditional")
| summarize Events=count(), Users=dcount(AccountObjectId), LastSeen=max(Timestamp), SampleAccounts=make_set(AccountDisplayName, 6) by ActionType, Application
| sort by Events desc
| take 150
`.trim()
    );
    if (adminOps && adminOps.results && adminOps.results.length) {
      io.saveCsv(
        "39_CloudApp_Admin_Operations_30d.csv",
        adminOps.results.map((r) => ({
          ActionType: r.ActionType,
          Application: r.Application,
          Events: r.Events,
          Users: r.Users,
          LastSeen: r.LastSeen,
          SampleAccounts: setOf(r.SampleAccounts),
        }))
      );
      summary.cloudAppAdminOpRows = adminOps.results.length;
      findings.push({
        Severity: "Info",
        Area: "CloudApp",
        Detail: `${adminOps.results.length} admin-like CloudAppEvents action type(s) in 30d — 39_CloudApp_Admin_Operations_30d.csv`,
      });
    }
  }

  if (schema.has("GraphAPIAuditEvents")) {
    const sampleColumns =
      (schema.tables &&
        schema.tables.GraphAPIAuditEvents &&
        schema.tables.GraphAPIAuditEvents.sampleColumns) ||
      [];
    const gaa = await huntFirst(
      graph,
      io,
      "hunt_graphapi_audit_writes",
      kqlGraphApiAuditWrites({ sampleColumns })
    );
    if (gaa && gaa.results && gaa.results.length) {
      io.saveCsv(
        "39_GraphAPI_Write_Audit_30d.csv",
        gaa.results.map((r) => ({
          AccountObjectId: r.AccountObjectId || "",
          ServicePrincipalId: r.ServicePrincipalId || "",
          ApplicationId: r.ApplicationId || "",
          Method: r.RequestMethod || "",
          Status: r.ResponseStatusCode || "",
          Events: r.Events,
          LastSeen: r.LastSeen,
          SampleUris: setOf(r.SampleUris),
          SampleIps: setOf(r.SampleIps),
        }))
      );
      summary.graphApiWriteAuditRows = gaa.results.length;
      findings.push({
        Severity: "Info",
        Area: "GraphAudit",
        Detail: `${gaa.results.length} Graph API write cluster(s) in 30d (CA / roles / consent) — 39_GraphAPI_Write_Audit_30d.csv`,
      });
    }
  }

  findings.push({
    Severity: "Info",
    Area: "AdaptiveIntel",
    Detail:
      `Adaptive intel finished (mdeEndpoint=${!!caps.mdeEndpoint}). ` +
      `alerts=${summary.securityAlertsHunted ?? 0}, exposureAssets=${summary.exposureCriticalAssets ?? 0}, ` +
      `exposurePaths=${summary.exposureCriticalPaths ?? 0}, ` +
      `identityInfo=${summary.identityInfoCriticalRows ?? 0}, accountInfo=${summary.identityAccountInfoRows ?? 0}, ` +
      `failedLogons=${summary.identityFailedLogonRows ?? 0}, privLogons=${summary.identityPrivilegedLogonRows ?? 0}, ` +
      `cloudAdminOps=${summary.cloudAppAdminOpRows ?? 0}. See 36_*/37_*/38_*/39_*.`,
  });
}

module.exports = { collectAdaptiveIntel };
