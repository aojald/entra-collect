/**
 * Discover Defender Advanced Hunting (and related) schema, then adapt checks.
 *
 * Tables like DeviceInfo / EntraIdSignInEvents (legacy: AADSignInEventsBeta)
 * only exist when the tenant streams MDE / Identity data into Defender XDR.
 * Without them (or without ThreatHunting.Read.All), hunts fall back to Graph.
 */
const { portalHuntReady } = require("./hunt");

const { soft, STATUS } = require("./io");

/** Tables we care about for this collector, grouped by capability. */
const HUNTING_TABLE_CATALOG = [
  // Devices / MDE
  { name: "DeviceInfo", category: "device", checks: ["windowsInventory", "patch", "rmm"] },
  { name: "DeviceProcessEvents", category: "device", checks: ["rmm", "ai"] },
  { name: "DeviceFileEvents", category: "device", checks: ["ai"] },
  { name: "DeviceNetworkEvents", category: "device", checks: ["ai"] },
  { name: "DeviceTvmSoftwareInventory", category: "device", checks: ["rmm", "ai"] },
  { name: "DeviceTvmSoftwareVulnerabilities", category: "device", checks: ["vulns", "patch"] },
  // Identity in Defender XDR — current names first, then the pre-Oct 2026 aliases.
  // Microsoft: EntraIdSignInEvents replaces AADSignInEventsBeta (coexist until 2026-10-19).
  {
    name: "EntraIdSignInEvents",
    category: "identity",
    checks: ["deviceCode", "legacy", "failures", "singleFactor", "tooling"],
  },
  {
    name: "AADSignInEventsBeta",
    category: "identity",
    checks: ["deviceCode", "legacy", "failures", "singleFactor", "tooling"],
  },
  {
    name: "EntraIdSpnSignInEvents",
    category: "identitySpn",
    checks: ["spnSignIns"],
  },
  { name: "AADSpnSignInEventsBeta", category: "identitySpn", checks: ["spnSignIns"] },
  {
    name: "IdentityLogonEvents",
    category: "identity",
    checks: ["deviceCode", "failures", "identityIntel"],
  },
  { name: "IdentityInfo", category: "identity", checks: ["identityIntel"] },
  { name: "IdentityAccountInfo", category: "identity", checks: ["identityIntel"] },
  // Sometimes exposed when LAW/Sentinel is linked into hunting (rare)
  { name: "SigninLogs", category: "identityLaw", checks: ["deviceCode", "legacy", "failures", "singleFactor", "tooling"] },
  { name: "AADNonInteractiveUserSignInLogs", category: "identityLaw", checks: ["deviceCode"] },
  { name: "AuditLogs", category: "identityLaw", checks: ["audit"] },
  { name: "GraphAPIAuditEvents", category: "cloud", checks: ["audit"] },
  // Email / Cloud apps / Alerts
  { name: "EmailEvents", category: "email", checks: ["antiSpam", "forwarding"] },
  { name: "CloudAppEvents", category: "cloud", checks: ["audit", "cloudGenAi", "fileSharing"] },
  { name: "AlertInfo", category: "alert", checks: ["alerts"] },
  { name: "AlertEvidence", category: "alert", checks: ["alerts"] },
  // Exposure management graph — available with or without MDE device tables
  { name: "ExposureGraphNodes", category: "exposure", checks: ["exposureGraph"] },
  { name: "ExposureGraphEdges", category: "exposure", checks: ["exposureGraph"] },
];

function classifyHuntError(err) {
  const msg = String((err && err.message) || err || "");
  const status = err && err.status;
  if (status === 403 || /Forbidden|Missing application scopes|ThreatHunting/i.test(msg)) {
    return "forbidden";
  }
  if (status === 401 || /Unauthorized/i.test(msg)) {
    return "unauthorized";
  }
  if (/Failed to resolve table or column expression named/i.test(msg)) {
    const m = msg.match(/named '([^']+)'/i);
    return { code: "table_missing", table: m ? m[1] : null };
  }
  if (/Semantic error|Query execution has failed|BadRequest|HTTP 400/i.test(msg)) {
    return "query_error";
  }
  return "other";
}

function createEmptySchema() {
  return {
    discoveredAt: new Date().toISOString(),
    canHunt: false,
    huntApiStatus: "unknown",
    huntApiDetail: "",
    tables: {}, // name -> { available, hasRows, error, category }
    availableTables: [],
    missingTables: [],
    capabilities: {},
    identitySource: null, // EntraIdSignInEvents | AADSignInEventsBeta | SigninLogs | IdentityLogonEvents | graph | none
    spnSource: null, // EntraIdSpnSignInEvents | AADSpnSignInEventsBeta | null
    graphSignIns: null, // { available, detail }
    notes: [],
    has(name) {
      return !!(this.tables[name] && this.tables[name].available);
    },
    hasAny(...names) {
      return names.some((n) => this.has(n));
    },
    hasAll(...names) {
      return names.every((n) => this.has(n));
    },
  };
}

/**
 * Probe Graph Entra sign-in logs (default identity store — no LAW needed).
 */
async function probeGraphSignIns(graph, schema) {
  try {
    const url = `${graph.GRAPH_BETA}/auditLogs/signIns?$top=1&$orderby=createdDateTime desc`;
    await graph.get(url);
    schema.graphSignIns = { available: true, detail: "beta auditLogs/signIns OK" };
  } catch (e1) {
    try {
      const url = `${graph.GRAPH}/auditLogs/signIns?$top=1&$orderby=createdDateTime desc`;
      await graph.get(url);
      schema.graphSignIns = { available: true, detail: "v1.0 auditLogs/signIns OK" };
    } catch (e2) {
      schema.graphSignIns = {
        available: false,
        detail: String(e2.message || e2).split("\n")[0],
      };
    }
  }
}

/**
 * Probe a single Advanced Hunting table with `| take 1`.
 * Returns { available, hasRows, error, classification }.
 */
async function probeTable(graph, tableName) {
  try {
    const res = await graph.post(`${graph.GRAPH}/security/runHuntingQuery`, {
      Query: `${tableName}\n| take 1`,
    });
    const rows = (res && res.results) || [];
    return {
      available: true,
      hasRows: rows.length > 0,
      error: null,
      classification: "ok",
      sampleColumns: rows[0] ? Object.keys(rows[0]) : [],
    };
  } catch (e) {
    const classification = classifyHuntError(e);
    const code = typeof classification === "object" ? classification.code : classification;
    return {
      available: false,
      hasRows: false,
      error: String(e.message || e).slice(0, 400),
      classification: code,
      missingTable:
        typeof classification === "object" ? classification.table : null,
    };
  }
}

function deriveCapabilities(schema) {
  const c = {
    // MDE endpoint surface — when false, adaptive intel (alerts / exposure /
    // IdentityLogon / CloudApp) carries the security signal instead.
    mdeEndpoint: schema.has("DeviceInfo"),
    windowsInventory: schema.has("DeviceInfo"),
    patch: schema.has("DeviceInfo"),
    rmm:
      schema.has("DeviceTvmSoftwareInventory") ||
      schema.has("DeviceProcessEvents"),
    ai:
      schema.has("DeviceProcessEvents") ||
      schema.has("DeviceTvmSoftwareInventory") ||
      schema.has("DeviceFileEvents") ||
      schema.has("DeviceNetworkEvents"),
    vulns: schema.has("DeviceTvmSoftwareVulnerabilities"),
    cloudGenAi: schema.hasAny("CloudAppEvents", "DeviceNetworkEvents"),
    fileSharing: schema.hasAny("CloudAppEvents", "DeviceNetworkEvents"),
    deviceCodeHunt: schema.hasAny(
      "EntraIdSignInEvents",
      "AADSignInEventsBeta",
      "SigninLogs",
      "IdentityLogonEvents",
      "AADNonInteractiveUserSignInLogs"
    ),
    legacyHunt: schema.hasAny(
      "EntraIdSignInEvents",
      "AADSignInEventsBeta",
      "SigninLogs"
    ),
    // IdentityLogonEvents exposes ActionType / FailureReason — enough for
    // failed-logon bursts even when Entra sign-in tables are absent.
    failuresHunt: schema.hasAny(
      "EntraIdSignInEvents",
      "AADSignInEventsBeta",
      "SigninLogs",
      "IdentityLogonEvents"
    ),
    singleFactorHunt: schema.hasAny(
      "EntraIdSignInEvents",
      "AADSignInEventsBeta",
      "SigninLogs"
    ),
    toolingHunt: schema.hasAny(
      "EntraIdSignInEvents",
      "AADSignInEventsBeta",
      "SigninLogs",
      "IdentityLogonEvents"
    ),
    spnSignInsHunt: schema.hasAny(
      "EntraIdSpnSignInEvents",
      "AADSpnSignInEventsBeta"
    ),
    auditHunt: schema.hasAny("CloudAppEvents", "AuditLogs", "GraphAPIAuditEvents"),
    antiSpam: schema.has("EmailEvents"),
    forwarding: schema.has("EmailEvents"),
    alerts: schema.hasAny("AlertInfo", "AlertEvidence"),
    exposureGraph: schema.hasAny("ExposureGraphNodes", "ExposureGraphEdges"),
    identityIntel: schema.hasAny(
      "IdentityLogonEvents",
      "IdentityInfo",
      "IdentityAccountInfo"
    ),
    graphIdentity: !!(schema.graphSignIns && schema.graphSignIns.available),
  };
  // Adaptive path: anything we can still hunt when Device* tables are gone.
  c.adaptiveIntel =
    c.alerts || c.exposureGraph || c.identityIntel || c.auditHunt || c.cloudGenAi;
  schema.capabilities = c;

  const id = pickIdentityDialect(schema);
  schema.identitySource = id.table || (c.graphIdentity ? "graph" : "none");
  const spn = pickSpnDialect(schema);
  schema.spnSource = spn.table || null;
}

function pushSchemaFindings(schema, findings) {
  if (!schema.canHunt) {
    findings.push({
      Severity: "Info",
      Area: "HuntingSchema",
      Detail:
        `Advanced Hunting API unavailable (${schema.huntApiStatus}: ${schema.huntApiDetail || "n/a"}). ` +
        `Identity checks use Graph Entra sign-ins when possible; device/RMM/AI/patch hunts skipped. ` +
        `See 19_Hunting_Schema.json.`,
    });
  } else {
    const avail = schema.availableTables.join(", ") || "(none)";
    findings.push({
      Severity: "Info",
      Area: "HuntingSchema",
      Detail: `Hunting API OK. Tables available: ${avail}. Identity source for hunts: ${schema.identitySource}. See 19_Hunting_Schema.json.`,
    });
  }

  if (!schema.capabilities.windowsInventory && schema.canHunt) {
    const fallbacks = [];
    if (schema.capabilities.alerts) fallbacks.push("AlertInfo");
    if (schema.capabilities.exposureGraph) fallbacks.push("ExposureGraph");
    if (schema.capabilities.identityIntel) fallbacks.push("IdentityLogon/Info");
    if (schema.capabilities.auditHunt) fallbacks.push("CloudAppEvents");
    findings.push({
      Severity: fallbacks.length ? "Info" : "Medium",
      Area: "HuntingSchema",
      Detail:
        "DeviceInfo not in hunting schema — no MDE Advanced Hunting device data (or not onboarded). " +
        "RMM/AI/patch/TVM hunts skipped; Entra devices (09_*) and Intune still apply. " +
        (fallbacks.length
          ? `Adaptive intel will use: ${fallbacks.join(", ")} → see 36_*/37_*/38_*.`
          : "No Alert/Exposure/Identity hunting tables either — security signal limited to Graph."),
    });
  }
  if (schema.capabilities.adaptiveIntel && schema.canHunt) {
    findings.push({
      Severity: "Info",
      Area: "HuntingSchema",
      Detail:
        `Adaptive intel path active (mdeEndpoint=${!!schema.capabilities.mdeEndpoint}). ` +
        "Collects Defender alerts, exposure-graph critical assets and IdentityLogon signals when those tables exist — with or without MDE device tables.",
    });
  }
  if (!schema.capabilities.deviceCodeHunt && schema.canHunt) {
    findings.push({
      Severity: "Info",
      Area: "HuntingSchema",
      Detail:
        "No EntraIdSignInEvents / AADSignInEventsBeta / SigninLogs in hunting — identity hunts rely on Graph auditLogs/signIns (Entra default retention).",
    });
  }
  if (schema.graphSignIns && !schema.graphSignIns.available) {
    findings.push({
      Severity: "High",
      Area: "HuntingSchema",
      Detail: `Graph Entra sign-in logs unavailable: ${schema.graphSignIns.detail}`,
    });
  }
}

/**
 * Main entry: probe Graph + Hunting schema, save report, return schema object.
 */
async function discoverHuntingSchema(graph, io, findings) {
  console.log("── Hunting / log schema discovery");
  const schema = createEmptySchema();

  await probeGraphSignIns(graph, schema);
  console.log(
    `  · Graph sign-ins: ${
      schema.graphSignIns.available ? "available" : "unavailable"
    } (${schema.graphSignIns.detail})`
  );

  // First: can we call runHuntingQuery at all?
  // Use DeviceInfo as canary; classify 403 vs missing table.
  console.log("  · Probing Advanced Hunting API (portal apiproxy / Graph / MTP)…");
  if (portalHuntReady()) {
    console.log("  · Portal apiproxy hunting: ready");
  } else if (graph.pool && graph.pool.hasMtp && graph.pool.hasMtp()) {
    console.log(
      `  · MTP portal token(s): ${graph.pool.listMtp().length} (legacy Bearer path)`
    );
  } else {
    console.log(
      "  · No portal hunting session yet — Graph ThreatHunting.Read.All or browser hunting page required"
    );
  }
  const canary = await probeTable(graph, "DeviceInfo");

  if (canary.classification === "forbidden" || canary.classification === "unauthorized") {
    schema.canHunt = false;
    schema.huntApiStatus = canary.classification;
    schema.huntApiDetail = (canary.error || "").split("\n")[0];
    schema.tables.DeviceInfo = {
      available: false,
      hasRows: false,
      category: "device",
      error: canary.error,
      classification: canary.classification,
    };
    schema.notes.push(
      "Hunting API denied — need either (1) browser session on security.microsoft.com Advanced Hunting " +
        "(portal apiproxy; Security Reader), or (2) Graph ThreatHunting.Read.All admin consent. " +
        "Re-run collect with --auth browser --cdp after opening the hunting page."
    );
    console.log(`  · Hunting API: ${schema.huntApiStatus} — skipping table probes`);
  } else {
    schema.canHunt = true;
    schema.huntApiStatus = "ok";
    schema.huntApiDetail = canary.available
      ? "runHuntingQuery accepted (DeviceInfo present)"
      : "runHuntingQuery accepted (DeviceInfo missing — probing others)";

    // Record canary result
    schema.tables.DeviceInfo = {
      available: canary.available,
      hasRows: canary.hasRows,
      category: "device",
      error: canary.error,
      classification: canary.classification,
      sampleColumns: canary.sampleColumns || [],
    };

    // Probe remaining catalog tables (skip DeviceInfo already done)
    for (const entry of HUNTING_TABLE_CATALOG) {
      if (entry.name === "DeviceInfo") continue;
      process.stdout.write(`  · Probe ${entry.name}… `);
      const result = await probeTable(graph, entry.name);

      // If we suddenly get forbidden mid-way, stop
      if (result.classification === "forbidden" || result.classification === "unauthorized") {
        console.log(result.classification);
        schema.canHunt = false;
        schema.huntApiStatus = result.classification;
        schema.huntApiDetail = (result.error || "").split("\n")[0];
        schema.tables[entry.name] = {
          available: false,
          hasRows: false,
          category: entry.category,
          error: result.error,
          classification: result.classification,
        };
        schema.notes.push(`Stopped probing after ${entry.name}: ${result.classification}`);
        break;
      }

      schema.tables[entry.name] = {
        available: result.available,
        hasRows: result.hasRows,
        category: entry.category,
        error: result.error,
        classification: result.classification,
        sampleColumns: result.sampleColumns || [],
      };
      console.log(result.available ? (result.hasRows ? "OK (rows)" : "OK (empty)") : "missing");
    }

    // Optional: try to enumerate all tables if hunting works (best-effort, capped)
    if (schema.canHunt) {
      const listed = await soft(
        "hunt_schema_list_tables",
        () =>
          graph.post(`${graph.GRAPH}/security/runHuntingQuery`, {
            Query: `
search *
| distinct $table
| sort by $table asc
`.trim(),
          }),
        io
      );
      if (listed && listed.results && listed.results.length) {
        const names = listed.results
          .map((r) => r.$table || r.table || r.TableName || Object.values(r)[0])
          .filter(Boolean)
          .map(String);
        schema.discoveredViaSearch = names;
        for (const n of names) {
          if (!schema.tables[n]) {
            schema.tables[n] = {
              available: true,
              hasRows: true,
              category: "discovered",
              error: null,
              classification: "ok",
              via: "search_distinct",
            };
          } else {
            schema.tables[n].available = true;
          }
        }
        console.log(`  · search * discovered ${names.length} tables`);
      } else {
        schema.notes.push(
          "Could not list all tables via `search * | distinct $table` (permission, cost, or empty). Relied on catalog probes."
        );
      }
    }
  }

  schema.availableTables = Object.keys(schema.tables)
    .filter((n) => schema.tables[n].available)
    .sort();
  schema.missingTables = HUNTING_TABLE_CATALOG.map((t) => t.name).filter(
    (n) => !schema.has(n)
  );

  deriveCapabilities(schema);
  pushSchemaFindings(schema, findings);

  // Serializable copy (strip methods)
  const report = {
    discoveredAt: schema.discoveredAt,
    canHunt: schema.canHunt,
    huntApiStatus: schema.huntApiStatus,
    huntApiDetail: schema.huntApiDetail,
    graphSignIns: schema.graphSignIns,
    identitySource: schema.identitySource,
    spnSource: schema.spnSource,
    capabilities: schema.capabilities,
    availableTables: schema.availableTables,
    missingCatalogTables: schema.missingTables,
    tables: schema.tables,
    discoveredViaSearch: schema.discoveredViaSearch || null,
    notes: schema.notes,
    logLocations: {
      entraSignInsDefault:
        "entra.microsoft.com → Monitoring → Sign-in logs (Graph auditLogs/signIns) — no Log Analytics required",
      logAnalytics:
        "Only if Entra Diagnostic settings → workspace; then SigninLogs/AuditLogs in Azure Logs / Sentinel",
      defenderHunting:
        "security.microsoft.com → Hunting — Device* plus EntraIdSignInEvents (legacy AADSignInEventsBeta) with MDE/XDR identity streams",
    },
  };
  io.saveJson("19_Hunting_Schema.json", report);
  io.saveCsv(
    "19_Hunting_Schema_Tables.csv",
    Object.entries(schema.tables).map(([name, t]) => ({
      Table: name,
      Available: t.available,
      HasRows: t.hasRows,
      Category: t.category,
      Classification: t.classification || "",
      Error: (t.error || "").slice(0, 200),
    }))
  );

  console.log(
    `  · Schema: canHunt=${schema.canHunt} identity=${schema.identitySource} spn=${schema.spnSource || "none"} tables=${schema.availableTables.length}`
  );
  return schema;
}

/**
 * Prefer a table that actually has rows; otherwise the first one that exists.
 * Tenants in the EntraId* / AAD* coexistence window keep whichever stream is populated.
 */
function pickFirstPresent(schema, names) {
  if (!schema || typeof schema.has !== "function") return null;
  const withRows = names.find(
    (n) => schema.has(n) && schema.tables && schema.tables[n] && schema.tables[n].hasRows
  );
  if (withRows) return withRows;
  return names.find((n) => schema.has(n)) || null;
}

/**
 * Prefer identity table for hunting queries.
 * Returns { table, dialect: 'entraid'|'aad'|'signinlogs'|'identitylogon'|null }
 *
 * Order: current XDR name → legacy XDR name → Sentinel SigninLogs →
 * Defender for Identity logons (last resort — not Entra device-code).
 */
function pickIdentityDialect(schema) {
  if (!schema || typeof schema.has !== "function") {
    return { table: null, dialect: null };
  }
  const xdr = pickFirstPresent(schema, [
    "EntraIdSignInEvents",
    "AADSignInEventsBeta",
  ]);
  if (xdr === "EntraIdSignInEvents") return { table: xdr, dialect: "entraid" };
  if (xdr === "AADSignInEventsBeta") return { table: xdr, dialect: "aad" };
  if (schema.has("SigninLogs")) return { table: "SigninLogs", dialect: "signinlogs" };
  if (schema.has("IdentityLogonEvents")) {
    return { table: "IdentityLogonEvents", dialect: "identitylogon" };
  }
  return { table: null, dialect: null };
}

function pickSpnDialect(schema) {
  if (!schema || typeof schema.has !== "function") {
    return { table: null, dialect: null };
  }
  const table = pickFirstPresent(schema, [
    "EntraIdSpnSignInEvents",
    "AADSpnSignInEventsBeta",
  ]);
  if (table === "EntraIdSpnSignInEvents") return { table, dialect: "entraidspn" };
  if (table === "AADSpnSignInEventsBeta") return { table, dialect: "aadspn" };
  return { table: null, dialect: null };
}

/** EntraIdSignInEvents documents ClientAppUsed, not AuthenticationProtocol. */
function kqlEntraIdDeviceCodeWhere() {
  return (
    'ClientAppUsed has "Device Code" or ClientAppUsed has "deviceCode" ' +
    'or AuthenticationProcessingDetails has "deviceCode" or EndpointCall has "devicecode"'
  );
}

function kqlAadDeviceCodeWhere() {
  return (
    'AuthenticationProtocol =~ "Device Code" or AuthenticationProtocol =~ "deviceCode" ' +
    'or AuthenticationProtocol has "deviceCode" or ClientApp has "Device Code"'
  );
}

/** Build device-code KQL for the available identity dialect. */
function kqlDeviceCode(days, dialect) {
  if (dialect === "entraid") {
    return `
EntraIdSignInEvents
| where Timestamp > ago(${days}d)
| where ${kqlEntraIdDeviceCodeWhere()}
| project Timestamp, AccountUpn, Application, IPAddress, Country, City, ErrorCode, ResourceDisplayName, DeviceName, CorrelationId, AuthenticationProtocol = "", ClientApp=ClientAppUsed
| top 2000 by Timestamp desc
`.trim();
  }
  if (dialect === "aad") {
    return `
AADSignInEventsBeta
| where Timestamp > ago(${days}d)
| where ${kqlAadDeviceCodeWhere()}
| project Timestamp, AccountUpn, Application, IPAddress, Country, City, ErrorCode, ResourceDisplayName, DeviceName, CorrelationId, AuthenticationProtocol, ClientApp
| top 2000 by Timestamp desc
`.trim();
  }
  if (dialect === "signinlogs") {
    return `
SigninLogs
| where TimeGenerated > ago(${days}d)
| where AuthenticationProtocol =~ "deviceCode" or AuthenticationProtocol has "deviceCode" or ClientAppUsed has "Device Code" or tostring(AuthenticationDetails) has "deviceCode"
| project Timestamp=TimeGenerated, AccountUpn=UserPrincipalName, Application=AppDisplayName, IPAddress, Country=tostring(Location), City="", ErrorCode=ResultType, ResourceDisplayName, DeviceName="", CorrelationId, AuthenticationProtocol, ClientApp=ClientAppUsed
| top 2000 by Timestamp desc
`.trim();
  }
  if (dialect === "identitylogon") {
    return `
IdentityLogonEvents
| where Timestamp > ago(${days}d)
| where Protocol has "DeviceCode" or Protocol has "deviceCode" or LogonType has "Device"
| project Timestamp, AccountUpn, Application=Application, IPAddress, Country="", City="", ErrorCode=tostring(ActionType), ResourceDisplayName="", DeviceName, CorrelationId="", AuthenticationProtocol=Protocol, ClientApp=LogonType
| top 2000 by Timestamp desc
`.trim();
  }
  return null;
}

function kqlLegacySuccess(days, dialect) {
  if (dialect === "entraid") {
    return `
EntraIdSignInEvents
| where Timestamp > ago(${days}d)
| where ClientAppUsed has_any ("Exchange ActiveSync", "Other clients", "IMAP", "POP", "Authenticated SMTP", "MAPI")
| where ErrorCode == 0
| summarize SignIns=count(), Apps=make_set(Application), Ips=make_set(IPAddress) by AccountUpn, ClientApp=ClientAppUsed
| top 200 by SignIns desc
`.trim();
  }
  if (dialect === "aad") {
    return `
AADSignInEventsBeta
| where Timestamp > ago(${days}d)
| where ClientApp has_any ("Exchange ActiveSync", "Other clients", "IMAP", "POP", "Authenticated SMTP", "MAPI")
| where ErrorCode == 0
| summarize SignIns=count(), Apps=make_set(Application), Ips=make_set(IPAddress) by AccountUpn, ClientApp
| top 200 by SignIns desc
`.trim();
  }
  if (dialect === "signinlogs") {
    return `
SigninLogs
| where TimeGenerated > ago(${days}d)
| where ResultType == 0
| where ClientAppUsed has_any ("Exchange ActiveSync", "Other clients", "IMAP", "POP", "Authenticated SMTP", "MAPI")
| summarize SignIns=count(), Apps=make_set(AppDisplayName), Ips=make_set(IPAddress) by AccountUpn=UserPrincipalName, ClientApp=ClientAppUsed
| top 200 by SignIns desc
`.trim();
  }
  return null;
}

function kqlFailuresByIp(days, dialect) {
  if (dialect === "entraid") {
    return `
EntraIdSignInEvents
| where Timestamp > ago(${days}d)
| where ErrorCode != 0
| summarize Failures=count(), Users=dcount(AccountUpn), SampleUsers=make_set(AccountUpn, 8), ErrorCodes=make_set(ErrorCode, 8) by IPAddress, Country
| sort by Failures desc
| take 50
`.trim();
  }
  if (dialect === "aad") {
    return `
AADSignInEventsBeta
| where Timestamp > ago(${days}d)
| where ErrorCode != 0
| summarize Failures=count(), Users=dcount(AccountUpn), SampleUsers=make_set(AccountUpn, 8), ErrorCodes=make_set(ErrorCode, 8) by IPAddress, Country
| sort by Failures desc
| take 50
`.trim();
  }
  if (dialect === "signinlogs") {
    return `
SigninLogs
| where TimeGenerated > ago(${days}d)
| where ResultType != 0
| summarize Failures=count(), Users=dcount(UserPrincipalName), SampleUsers=make_set(UserPrincipalName, 8), ErrorCodes=make_set(ResultType, 8) by IPAddress, Country=tostring(Location)
| sort by Failures desc
| take 50
`.trim();
  }
  if (dialect === "identitylogon") {
    // IdentityLogonEvents has no ErrorCode; failures show up in ActionType /
    // FailureReason. Best-effort when AADSignInEventsBeta is missing.
    return `
IdentityLogonEvents
| where Timestamp > ago(${days}d)
| where ActionType has_any ("Failed", "LogonFailed", "LogonFailure") or isnotempty(FailureReason)
| summarize Failures=count(), Users=dcount(AccountUpn), SampleUsers=make_set(AccountUpn, 8), SampleReasons=make_set(FailureReason, 6) by IPAddress, ActionType
| sort by Failures desc
| take 50
`.trim();
  }
  return null;
}

function kqlSingleFactor(days, dialect) {
  if (dialect === "entraid") {
    return `
EntraIdSignInEvents
| where Timestamp > ago(${days}d)
| where ErrorCode == 0
| where isnotempty(AccountUpn)
| where AuthenticationRequirement != "multiFactorAuthentication"
| where LogonType != "AppOnly"
| summarize SignIns=count(), Apps=make_set(Application), Countries=make_set(Country) by AccountUpn
| top 200 by SignIns desc
`.trim();
  }
  if (dialect === "aad") {
    return `
AADSignInEventsBeta
| where Timestamp > ago(${days}d)
| where ErrorCode == 0
| where isnotempty(AccountUpn)
| where AuthenticationRequirement != "multiFactorAuthentication"
| where LogonType != "AppOnly"
| summarize SignIns=count(), Apps=make_set(Application), Countries=make_set(Country) by AccountUpn
| top 200 by SignIns desc
`.trim();
  }
  if (dialect === "signinlogs") {
    return `
SigninLogs
| where TimeGenerated > ago(${days}d)
| where ResultType == 0
| where isnotempty(UserPrincipalName)
| where AuthenticationRequirement != "multiFactorAuthentication"
| summarize SignIns=count(), Apps=make_set(AppDisplayName), Countries=make_set(tostring(Location)) by AccountUpn=UserPrincipalName
| top 200 by SignIns desc
`.trim();
  }
  return null;
}

function kqlAdminTooling(days, dialect) {
  if (dialect === "entraid") {
    return `
EntraIdSignInEvents
| where Timestamp > ago(${days}d)
| where ErrorCode == 0
| where Application has_any ("Azure Active Directory PowerShell", "Microsoft Azure CLI", "Microsoft Azure PowerShell", "Microsoft Graph Command Line Tools", "AADInternals", "Graph Explorer")
| summarize SignIns=count(), Users=make_set(AccountUpn, 12), Ips=make_set(IPAddress, 12) by Application
| sort by SignIns desc
| take 50
`.trim();
  }
  if (dialect === "aad") {
    return `
AADSignInEventsBeta
| where Timestamp > ago(${days}d)
| where ErrorCode == 0
| where Application has_any ("Azure Active Directory PowerShell", "Microsoft Azure CLI", "Microsoft Azure PowerShell", "Microsoft Graph Command Line Tools", "AADInternals", "Graph Explorer")
| summarize SignIns=count(), Users=make_set(AccountUpn, 12), Ips=make_set(IPAddress, 12) by Application
| sort by SignIns desc
| take 50
`.trim();
  }
  if (dialect === "signinlogs") {
    return `
SigninLogs
| where TimeGenerated > ago(${days}d)
| where ResultType == 0
| where AppDisplayName has_any ("Azure Active Directory PowerShell", "Microsoft Azure CLI", "Microsoft Azure PowerShell", "Microsoft Graph Command Line Tools", "AADInternals", "Graph Explorer")
| summarize SignIns=count(), Users=make_set(UserPrincipalName, 12), Ips=make_set(IPAddress, 12) by Application=AppDisplayName
| sort by SignIns desc
| take 50
`.trim();
  }
  if (dialect === "identitylogon") {
    return `
IdentityLogonEvents
| where Timestamp > ago(${days}d)
| where Application has_any ("Azure Active Directory PowerShell", "Microsoft Azure CLI", "Microsoft Azure PowerShell", "Microsoft Graph Command Line Tools", "AADInternals", "Graph Explorer", "Azure Portal")
   or Protocol has_any ("OAuth", "OpenID")
| summarize SignIns=count(), Users=make_set(AccountUpn, 12), Ips=make_set(IPAddress, 12) by Application, Protocol
| sort by SignIns desc
| take 50
`.trim();
  }
  return null;
}

function kqlDeviceCodeBlocked(days, dialect) {
  if (dialect === "entraid") {
    return `
EntraIdSignInEvents
| where Timestamp > ago(${days}d)
| where ${kqlEntraIdDeviceCodeWhere()}
| where ErrorCode != 0
| summarize Blocked=count(), Users=dcount(AccountUpn) by ErrorCode, Application
| top 30 by Blocked desc
`.trim();
  }
  if (dialect === "aad") {
    return `
AADSignInEventsBeta
| where Timestamp > ago(${days}d)
| where ${kqlAadDeviceCodeWhere()}
| where ErrorCode != 0
| summarize Blocked=count(), Users=dcount(AccountUpn) by ErrorCode, Application
| top 30 by Blocked desc
`.trim();
  }
  if (dialect === "signinlogs") {
    return `
SigninLogs
| where TimeGenerated > ago(${days}d)
| where AuthenticationProtocol =~ "deviceCode" or AuthenticationProtocol has "deviceCode"
| where ResultType != 0
| summarize Blocked=count(), Users=dcount(UserPrincipalName) by ErrorCode=ResultType, Application=AppDisplayName
| top 30 by Blocked desc
`.trim();
  }
  return null;
}

function kqlSpnSignIns(days, dialectOrPick) {
  const table =
    dialectOrPick && typeof dialectOrPick === "object"
      ? dialectOrPick.table
      : dialectOrPick === "entraidspn"
        ? "EntraIdSpnSignInEvents"
        : dialectOrPick === "aadspn"
          ? "AADSpnSignInEventsBeta"
          : null;
  if (!table) return null;
  return `
${table}
| where Timestamp > ago(${days}d)
| project Timestamp, App=ServicePrincipalName, AppId=ApplicationId, ServicePrincipalId, Resource=ResourceDisplayName, IP=IPAddress, Status=ErrorCode, Location=strcat(City, ", ", Country), IsManagedIdentity
| top 2000 by Timestamp desc
`.trim();
}

/**
 * Build AI-agent union only from tables that exist.
 */
function kqlAiAgents(patternsJson, schema) {
  const branches = [];
  if (schema.has("DeviceTvmSoftwareInventory")) {
    branches.push(`(
  DeviceTvmSoftwareInventory
  | where tostring(SoftwareName) has_any (patterns) or tostring(SoftwareVendor) has_any (patterns)
  | project DeviceId, DeviceName, Signal=strcat(SoftwareVendor, " / ", SoftwareName, " ", SoftwareVersion), Source="TvmSoftwareInventory"
)`);
  }
  if (schema.has("DeviceProcessEvents")) {
    branches.push(`(
  DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where FileName has_any (patterns) or FolderPath has_any (patterns) or ProcessCommandLine has_any (patterns)
  | summarize LastSeen=max(Timestamp), Events=count() by DeviceId, DeviceName, FileName, FolderPath, ProcessCommandLine
  | project DeviceId, DeviceName, Signal=strcat(FolderPath, "\\\\", FileName, " :: ", substring(ProcessCommandLine, 0, 120)), Source="DeviceProcessEvents"
)`);
  }
  if (schema.has("DeviceFileEvents")) {
    branches.push(`(
  DeviceFileEvents
  | where Timestamp > ago(30d)
  | where FileName has_any (patterns) or FolderPath has_any (patterns)
  | summarize LastSeen=max(Timestamp), Events=count() by DeviceId, DeviceName, FileName, FolderPath, ActionType
  | project DeviceId, DeviceName, Signal=strcat(ActionType, " ", FolderPath, "\\\\", FileName), Source="DeviceFileEvents"
)`);
  }
  if (schema.has("DeviceNetworkEvents")) {
    branches.push(`(
  DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteUrl has_any (patterns) or InitiatingProcessFileName has_any (patterns) or InitiatingProcessFolderPath has_any (patterns)
  | summarize LastSeen=max(Timestamp), Events=count() by DeviceId, DeviceName, RemoteUrl, InitiatingProcessFileName
  | project DeviceId, DeviceName, Signal=strcat(InitiatingProcessFileName, " -> ", RemoteUrl), Source="DeviceNetworkEvents"
)`);
  }
  if (!branches.length) return null;

  return `
let patterns = dynamic(${patternsJson});
union
${branches.join(",\n")}
| extend Family = case(
    Signal has_any ("claude", "anthropic"), "Claude",
    Signal has_any ("hermes"), "Hermes",
    Signal has_any ("openclaw", "open-claw"), "OpenClaw",
    Signal has_any ("perplexity"), "Perplexity",
    Signal has_any ("comet"), "CometBrowser",
    Signal has_any ("chatgpt", "openai"), "ChatGPT",
    Signal has_any ("cursor"), "Cursor",
    Signal has_any ("copilot"), "GitHubCopilot",
    Signal has_any ("ollama"), "Ollama",
    Signal has_any ("lm studio", "lmstudio"), "LMStudio",
    Signal has_any ("windsurf", "codeium"), "Windsurf",
    Signal has_any ("tabnine"), "Tabnine",
    Signal has_any ("aider"), "Aider",
    Signal has_any ("cody"), "Cody",
    "OtherAI"
  )
| summarize Devices=dcount(DeviceId), Events=count(), SampleDevices=make_set(DeviceName, 8), SampleSignals=make_set(Signal, 8) by Family, Source
| sort by Devices desc
| take 200
`.trim();
}

/**
 * GraphAPIAuditEvents has no AccountDisplayName (that is IdentityInfo /
 * CloudAppEvents). Actor is AccountObjectId; app is ApplicationId.
 * @param {string[]} [sampleColumns]
 */
function graphApiAuditActorColumn(sampleColumns) {
  const cols = new Set((sampleColumns || []).map(String));
  if (!cols.size || cols.has("AccountObjectId")) return "AccountObjectId";
  if (cols.has("ServicePrincipalId")) return "ServicePrincipalId";
  if (cols.has("ApplicationId")) return "ApplicationId";
  return "AccountObjectId";
}

/**
 * @param {{ sampleColumns?: string[] }} [opts]
 * @returns {string[]} focused write hunt, then a broader fallback
 */
function kqlGraphApiAuditWrites(opts = {}) {
  const cols = new Set((opts.sampleColumns || []).map(String));
  const actor = graphApiAuditActorColumn(opts.sampleColumns);
  const group = [actor];
  for (const c of ["ApplicationId", "ServicePrincipalId", "RequestMethod", "ResponseStatusCode"]) {
    if (c === actor) continue;
    if (!cols.size || cols.has(c)) group.push(c);
  }
  if (!group.includes("RequestMethod")) group.push("RequestMethod");
  const by = group.join(", ");
  const focused = `
GraphAPIAuditEvents
| where Timestamp > ago(30d)
| where RequestMethod in ("PATCH","POST","PUT","DELETE")
| where RequestUri has_any ("conditionalAccess","roleManagement","roleAssignments","oauth2PermissionGrants","appRoleAssignedTo","authenticationMethods")
| summarize Events=count(), LastSeen=max(Timestamp), SampleUris=make_set(RequestUri, 4), SampleIps=make_set(IpAddress, 4) by ${by}
| sort by Events desc
| take 100
`.trim();
  const broad = `
GraphAPIAuditEvents
| where Timestamp > ago(30d)
| where RequestMethod in ("PATCH","POST","PUT","DELETE")
| summarize Events=count(), LastSeen=max(Timestamp) by ${actor}, RequestMethod
| sort by Events desc
| take 80
`.trim();
  return [focused, broad];
}

function skipReason(schema, capability) {
  if (!schema.canHunt) {
    return `Hunting API unavailable (${schema.huntApiStatus})`;
  }
  if (!schema.capabilities[capability]) {
    return `Required tables missing for ${capability} (see 19_Hunting_Schema.json)`;
  }
  return null;
}

module.exports = {
  HUNTING_TABLE_CATALOG,
  discoverHuntingSchema,
  pickIdentityDialect,
  pickSpnDialect,
  kqlDeviceCode,
  kqlLegacySuccess,
  kqlFailuresByIp,
  kqlSingleFactor,
  kqlAdminTooling,
  kqlDeviceCodeBlocked,
  kqlSpnSignIns,
  kqlAiAgents,
  kqlGraphApiAuditWrites,
  graphApiAuditActorColumn,
  skipReason,
  classifyHuntError,
};
