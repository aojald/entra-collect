/**
 * Endpoint hunts: suspicious RMM, AI agents, Win10 / Patch Tuesday lag, Intune update rings.
 * Skips Advanced Hunting queries when schema discovery shows tables are missing / API denied.
 */
const { kqlAiAgents, skipReason } = require("./schema");
const { classifyRmmHit } = require("./rmmClassify");
const {
  FALLBACK_PATCH_TUESDAY,
  resolvePatchBaseline,
  parseOsBuild,
  patchStatus,
} = require("./patchTuesday");

const { soft, STATUS } = require("./io");

function pushFinding(findings, severity, area, detail) {
  findings.push({ Severity: severity, Area: area, Detail: detail });
}

/** @deprecated Offline fallback only — live baseline comes from Microsoft Learn. */
const PATCH_TUESDAY = FALLBACK_PATCH_TUESDAY;

const RMM_INDICATORS = [
  { family: "TeamViewer", patterns: ["teamviewer", "tv_w32", "tv_x64", "teamviewer_service"] },
  { family: "AnyDesk", patterns: ["anydesk"] },
  { family: "ScreenConnect", patterns: ["screenconnect", "connectwisecontrol", "clientsetup"] },
  { family: "ConnectWise", patterns: ["connectwise", "itsupport247", "labtech", "ltagent"] },
  { family: "Splashtop", patterns: ["splashtop", "srserver", "srmanager"] },
  { family: "RustDesk", patterns: ["rustdesk"] },
  { family: "Atera", patterns: ["atera", "agentpackage"] },
  { family: "NinjaRMM", patterns: ["ninjarmm", "ninjarmmagent"] },
  { family: "DattoRMM", patterns: ["datto", "centrastage", "cagservice"] },
  { family: "Kaseya", patterns: ["kaseya", "agentmon", "kaseyavsa"] },
  // LogMeIn/GoTo RMM only — NOT GoTo Meeting / Webinar / Live (TVM often uses vendor "logmein")
  {
    family: "LogMeIn",
    patterns: [
      "logmeinrescue",
      "logmein_rescue",
      "lmi_rescue",
      "logmeincentral",
      "logmein_central",
      "logmeinpro",
      "logmein_pro",
      "gotoassist",
      "gotomypc",
      "logmein hamachi",
      "logmeinignition",
      "logmein resolve",
      "logmeinresolve",
    ],
  },
  { family: "BeyondTrust", patterns: ["bomgar", "beyondtrust", "remotingserver"] },
  { family: "ChromeRemoteDesktop", patterns: ["chromeremotedesktop", "remoting_host", "remote_assistance_host"] },
  { family: "UltraVNC", patterns: ["ultravnc", "winvnc", "uvnc"] },
  { family: "TightVNC", patterns: ["tightvnc", "tvnserver"] },
  { family: "RealVNC", patterns: ["vncserver", "winvnc4", "realvnc"] },
  { family: "Supremo", patterns: ["supremo"] },
  { family: "RemotePC", patterns: ["remotepc"] },
  { family: "DWService", patterns: ["dwagent", "dwservice"] },
  { family: "MeshCentral", patterns: ["meshagent", "meshcentral"] },
  { family: "Action1", patterns: ["action1"] },
  { family: "LevelRMM", patterns: ["level.io", "level-windows"] },
  { family: "Pulseway", patterns: ["pulseway"] },
];

/** Collaboration apps under the old LogMeIn brand — not remote-admin RMM. */
const RMM_MEETING_FALSE_POSITIVE = [
  "gotomeeting",
  "goto_meeting",
  "gotowebinar",
  "goto webinar",
  "goto training",
  "goto connect",
];

const AI_AGENT_INDICATORS = [
  { family: "Claude", patterns: ["claude.exe", "claude helper", "anthropic", "claude-code", "claude app"] },
  { family: "Hermes", patterns: ["hermes.exe", "hermes-agent", "hermes ai", "nousresearch"] },
  { family: "OpenClaw", patterns: ["openclaw", "open-claw", "open_claw"] },
  { family: "Perplexity", patterns: ["perplexity", "perplexityos", "comet"] },
  { family: "CometBrowser", patterns: ["comet.exe", "comet browser", "cometbrowser"] },
  { family: "ChatGPT", patterns: ["chatgpt.exe", "openai chatbot", "openai desktop"] },
  { family: "Cursor", patterns: ["cursor.exe", "cursor helper", "cursoring"] },
  // A bare "copilot" also matches Windows Copilot and Microsoft 365 Copilot,
  // which are sanctioned and drown the Shadow AI signal in false positives.
  {
    family: "GitHubCopilot",
    patterns: [
      "github.copilot",
      "githubcopilot",
      "copilot-language-server",
      "copilot-agent",
      "gh copilot",
    ],
  },
  { family: "Cody", patterns: ["cody.exe", "sourcegraph cody"] },
  { family: "ContinueDev", patterns: ["continue.exe", "continue.dev"] },
  { family: "Aider", patterns: ["aider.exe", "aider-chat"] },
  { family: "Windsurf", patterns: ["windsurf", "codeium"] },
  { family: "Tabnine", patterns: ["tabnine"] },
  { family: "Ollama", patterns: ["ollama.exe", "ollama app"] },
  { family: "LMStudio", patterns: ["lm studio", "lmstudio"] },
  { family: "OpenWebUI", patterns: ["open-webui", "openwebui"] },
  { family: "AutoGPT", patterns: ["autogpt", "auto-gpt"] },
  { family: "BabyAGI", patterns: ["babyagi"] },
  { family: "CrewAI", patterns: ["crewai"] },
  { family: "LangChainAgent", patterns: ["langchain"] },
];

function isRmmMeetingFalsePositive(text) {
  const t = String(text || "")
    .toLowerCase()
    .replace(/\s+/g, " ");
  if (RMM_MEETING_FALSE_POSITIVE.some((p) => t.includes(p))) return true;
  // MDE TVM: vendor=logmein + SoftwareName live|gotomeeting_v9
  if (/\blogmein\b/.test(t) && /\b(live|gotomeeting(_v?\d+)?)\b/.test(t)) {
    if (
      /rescue|central|gotoassist|gotomypc|hamachi|ignition|resolve/.test(t)
    ) {
      return false;
    }
    return true;
  }
  return false;
}

function matchFamily(text, families) {
  const t = String(text || "").toLowerCase();
  if (isRmmMeetingFalsePositive(t)) return null;
  for (const f of families) {
    if (f.patterns.some((p) => t.includes(p))) return f.family;
  }
  return null;
}

/** Parse DeviceInfo.LoggedOnUsers (array / JSON string) into a readable label. */
function formatLoggedOnUsers(raw) {
  if (raw == null || raw === "") return "";
  let arr = raw;
  if (typeof raw === "string") {
    const s = raw.trim();
    if (!s) return "";
    try {
      arr = JSON.parse(s);
    } catch {
      return s;
    }
  }
  if (!Array.isArray(arr)) return String(raw);
  return arr
    .map((u) => {
      if (u == null) return null;
      if (typeof u === "string") return u;
      const user =
        u.UserName ||
        u.AccountName ||
        u.userName ||
        u.accountName ||
        u.Name ||
        "";
      const domain = u.DomainName || u.domainName || u.Domain || "";
      if (user && domain) return `${domain}\\${user}`;
      return user || u.Sid || u.sid || null;
    })
    .filter(Boolean)
    .join(" | ");
}

/** Index Entra devices by displayName / AAD deviceId → registered owners. */
function buildDeviceOwnerIndex(devices) {
  const byName = new Map();
  const byAadId = new Map();
  for (const d of devices || []) {
    const owners = Array.isArray(d.registeredOwners) ? d.registeredOwners : [];
    const userOwners = owners.filter(
      (o) =>
        o &&
        ((o["@odata.type"] || "").toLowerCase().includes("user") ||
          !!o.userPrincipalName)
    );
    const entry = {
      displayName: d.displayName || "",
      aadDeviceId: d.deviceId || "",
      os: d.operatingSystem || "",
      trustType: d.trustType || "",
      ownersDisplay: userOwners
        .map((o) => o.displayName || o.userPrincipalName || "")
        .filter(Boolean)
        .join(" | "),
      ownersUpn: userOwners
        .map((o) => o.userPrincipalName || "")
        .filter(Boolean)
        .join(" | "),
    };
    if (d.displayName) byName.set(String(d.displayName).toLowerCase(), entry);
    if (d.deviceId) byAadId.set(String(d.deviceId).toLowerCase(), entry);
  }
  return { byName, byAadId };
}

function resolveOwners(ownerIndex, deviceName, aadDeviceId) {
  if (!ownerIndex) return { ownersDisplay: "", ownersUpn: "" };
  const byAad =
    aadDeviceId &&
    ownerIndex.byAadId.get(String(aadDeviceId).toLowerCase());
  if (byAad) {
    return {
      ownersDisplay: byAad.ownersDisplay,
      ownersUpn: byAad.ownersUpn,
    };
  }
  const byName =
    deviceName &&
    ownerIndex.byName.get(String(deviceName).toLowerCase());
  if (byName) {
    return {
      ownersDisplay: byName.ownersDisplay,
      ownersUpn: byName.ownersUpn,
    };
  }
  return { ownersDisplay: "", ownersUpn: "" };
}

function isWindows10(osPlatform, osVersion) {
  const p = String(osPlatform || "").toLowerCase();
  const v = String(osVersion || "");
  if (p.includes("windows10") || p === "windows10") return true;
  if (p.includes("windows") && /^10\.0\.19/.test(v)) return true;
  const b = parseOsBuild(v);
  if (b && Number(b.major) >= 19041 && Number(b.major) < 22000) return true;
  return false;
}

function isWindows11(osPlatform, osVersion) {
  const p = String(osPlatform || "").toLowerCase();
  const v = String(osVersion || "");
  if (p.includes("windows11")) return true;
  const b = parseOsBuild(v);
  if (b && Number(b.major) >= 22000) return true;
  return false;
}

async function collectEndpointHunts(graph, io, findings, summary, opts = {}) {
  const rmmLegitThreshold = opts.rmmLegitThreshold ?? 0.7;
  const schema = opts.schema || {
    canHunt: false,
    has: () => false,
    hasAny: () => false,
    capabilities: {},
  };
  const ownerIndex = buildDeviceOwnerIndex(opts.devices || []);
  console.log(
    `── Endpoint hunts (schema-aware; RMM ≥${Math.round(rmmLegitThreshold * 100)}% = assumed legit)`
  );

  const patchBaseline = await resolvePatchBaseline();
  const referenceAgeDays = patchBaseline.ageDays;
  const referenceStale = !!patchBaseline.stale;
  if (patchBaseline.source === "fallback") {
    const msg =
      `Patch Tuesday baseline used the offline fallback (asOf ${patchBaseline.asOf}` +
      `${referenceAgeDays != null ? `, ${referenceAgeDays}d old` : ""}) — ` +
      `Microsoft Learn fetch failed (${(patchBaseline.errors || []).join("; ") || "unknown"}). ` +
      `Patch-lag figures may under-report.`;
    console.warn(`  ⚠ ${msg}`);
    findings.push({ Severity: "Medium", Area: "Coverage", Detail: msg });
  } else {
    console.log(
      `  · Patch Tuesday baseline: ${patchBaseline.source} asOf=${patchBaseline.asOf} ` +
        `(${Object.keys(patchBaseline.builds).length} build families)`
    );
    if (referenceStale) {
      findings.push({
        Severity: "Medium",
        Area: "Coverage",
        Detail:
          `Microsoft Learn patch baseline is ${referenceAgeDays} days old (asOf ${patchBaseline.asOf}). ` +
          `Release-health pages may be stale.`,
      });
    }
  }
  summary.patchTuesdayAsOf = patchBaseline.asOf;
  summary.patchTuesdayReferenceStale = referenceStale;
  summary.patchTuesdaySource = patchBaseline.source;
  io.saveJson("30_patch_tuesday_reference.json", {
    asOf: patchBaseline.asOf,
    label: patchBaseline.label,
    source: patchBaseline.source,
    builds: patchBaseline.builds,
    ageDays: referenceAgeDays,
    stale: referenceStale,
    errors: patchBaseline.errors || [],
  });

  async function hunt(label, query) {
    if (!schema.canHunt || !query) return null;
    return soft(
      label,
      () =>
        graph.post(`${graph.GRAPH}/security/runHuntingQuery`, {
          Query: query,
        }),
      io
    );
  }

  let totalWindows = 0;

  // Total Windows devices for prevalence denominator
  if (schema.has("DeviceInfo")) {
    const deviceInventory = await hunt(
      "hunt_deviceInventory",
      `
DeviceInfo
| where Timestamp > ago(7d)
| where isnotempty(DeviceId)
| summarize arg_max(Timestamp, *) by DeviceId
| where OSPlatform has_any ("Windows", "Windows10", "Windows11") or OSVersion startswith "10.0"
| project DeviceId, DeviceName, OSPlatform, OSVersion, OSBuild, OSArchitecture, MachineGroup
| summarize TotalWindows=dcount(DeviceId)
`.trim()
    );
    if (deviceInventory && deviceInventory.results && deviceInventory.results[0]) {
      totalWindows = Number(deviceInventory.results[0].TotalWindows) || 0;
    }
  } else {
    const why = skipReason(schema, "windowsInventory") || "DeviceInfo missing";
    console.log(`  · Skip Windows inventory hunt: ${why}`);
  }
  summary.windowsDeviceCount = totalWindows;

  // ── 1) RMM software inventory + process signals ───────────────────────
  console.log("  · RMM indicators");
  const rmmPatternKql = [
    ...RMM_INDICATORS.flatMap((f) => f.patterns),
    // Broad LogMeIn/GoTo vendor bait — classified later; Meeting/Live filtered as artefacts
    "logmein",
    "gotomeeting",
    "gotoassist",
  ]
    .map((p) => p.replace(/"/g, ""))
    .filter((p, i, a) => a.indexOf(p) === i)
    .slice(0, 80);

  let rmmHunt = null;
  let rmmProc = null;
  if (schema.has("DeviceTvmSoftwareInventory")) {
    const joinDevice = schema.has("DeviceInfo")
      ? `| join kind=leftouter (
    DeviceInfo
    | where Timestamp > ago(14d)
    | summarize arg_max(Timestamp, OSPlatform, OSVersion, LoggedOnUsers, AadDeviceId) by DeviceId
) on DeviceId
| project DeviceId, DeviceName, SoftwareName, SoftwareVendor, SoftwareVersion, OSPlatform, OSVersion, LoggedOnUsers, AadDeviceId`
      : `| project DeviceId, DeviceName, SoftwareName, SoftwareVendor, SoftwareVersion, OSPlatform="", OSVersion="", LoggedOnUsers="", AadDeviceId=""`;
    rmmHunt = await hunt(
      "hunt_rmm_inventory",
      `
let patterns = dynamic(${JSON.stringify(rmmPatternKql)});
DeviceTvmSoftwareInventory
| where isnotempty(SoftwareName)
| where tostring(SoftwareName) has_any (patterns) or tostring(SoftwareVendor) has_any (patterns)
${joinDevice}
`.trim()
    );
  }
  if (schema.has("DeviceProcessEvents")) {
    const procJoin = schema.has("DeviceInfo")
      ? `| join kind=leftouter (
    DeviceInfo
    | where Timestamp > ago(14d)
    | summarize arg_max(Timestamp, OSPlatform, OSVersion, LoggedOnUsers, AadDeviceId) by DeviceId
) on DeviceId
| project DeviceId, DeviceName, FileName, FolderPath, LastSeen, Events, AccountName, OSPlatform, OSVersion, LoggedOnUsers, AadDeviceId`
      : `| project DeviceId, DeviceName, FileName, FolderPath, LastSeen, Events, AccountName, OSPlatform="", OSVersion="", LoggedOnUsers="", AadDeviceId=""`;
    rmmProc = await hunt(
      "hunt_rmm_processes",
      `
let patterns = dynamic(${JSON.stringify(rmmPatternKql)});
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FolderPath has_any (patterns) or FileName has_any (patterns) or InitiatingProcessFileName has_any (patterns)
| summarize LastSeen=max(Timestamp), Events=count(), AccountName=any(AccountName) by DeviceId, DeviceName, FileName, FolderPath
${procJoin}
| top 2000 by Events desc
`.trim()
    );
  }
  if (!schema.capabilities.rmm) {
    const why = skipReason(schema, "rmm") || "no RMM tables";
    console.log(`  · Skip RMM hunts: ${why}`);
    pushFinding(
      findings,
      "Info",
      "RMM",
      `Skipped — ${why}. See 19_Hunting_Schema.json / Intune apps manually.`
    );
  }

  const rmmRows = [];
  const rmmByFamilyDevice = new Map(); // family -> Set(deviceId)
  const rmmAssetMap = new Map(); // family|deviceKey -> asset row
  const rmmDismissed = []; // meeting / non-RMM artefacts under LogMeIn brand

  function addRmm(deviceId, deviceName, family, evidence, source, extra = {}) {
    if (!family) return;
    const deviceKey = deviceId || deviceName || `${family}|unknown`;
    if (!rmmByFamilyDevice.has(family)) rmmByFamilyDevice.set(family, new Set());
    rmmByFamilyDevice.get(family).add(deviceKey);

    const loggedOn = formatLoggedOnUsers(extra.LoggedOnUsers);
    const owners = resolveOwners(
      ownerIndex,
      deviceName,
      extra.AadDeviceId
    );
    const processAccount = extra.AccountName || "";
    const ownersDisplay =
      owners.ownersDisplay ||
      (loggedOn ? `(MDE logged-on: ${loggedOn})` : "") ||
      (processAccount ? `(process account: ${processAccount})` : "");
    const ownersUpn = owners.ownersUpn || "";

    const risk = classifyRmmHit({
      family,
      evidence,
      deviceName,
      osPlatform: extra.OSPlatform || "",
    });

    rmmRows.push({
      Family: family,
      DeviceId: deviceId,
      DeviceName: deviceName,
      Owners: ownersDisplay,
      OwnersUPN: ownersUpn,
      LoggedOnUsers: loggedOn,
      ProcessAccount: processAccount,
      Evidence: evidence,
      Source: source,
      OSPlatform: extra.OSPlatform || "",
      OSVersion: extra.OSVersion || "",
      AadDeviceId: extra.AadDeviceId || "",
      LastSeen: extra.LastSeen || "",
      Events: extra.Events ?? "",
      RiskClass: risk.class,
      Signal: risk.signal,
      RiskNote: risk.note,
    });

    const assetKey = `${family}|${deviceKey}`;
    if (!rmmAssetMap.has(assetKey)) {
      rmmAssetMap.set(assetKey, {
        Family: family,
        DeviceName: deviceName || "",
        DeviceId: deviceId || "",
        AadDeviceId: extra.AadDeviceId || "",
        OSPlatform: extra.OSPlatform || "",
        OSVersion: extra.OSVersion || "",
        Owners: owners.ownersDisplay || "",
        OwnersUPN: ownersUpn,
        LoggedOnUsers: loggedOn,
        ProcessAccount: processAccount,
        EvidenceSources: new Set([source]),
        EvidenceTraces: [evidence],
        LastSeen: extra.LastSeen || "",
        Events: Number(extra.Events) || 0,
        // Prefer highest-weight signal if multiple evidence lines land later.
        RiskClass: risk.class,
        Signal: risk.signal,
        RiskNote: risk.note,
        RiskWeight: risk.weight,
      });
    } else {
      const a = rmmAssetMap.get(assetKey);
      a.EvidenceSources.add(source);
      if (evidence && !a.EvidenceTraces.includes(evidence)) {
        a.EvidenceTraces.push(evidence);
      }
      if (!a.Owners && owners.ownersDisplay) a.Owners = owners.ownersDisplay;
      if (!a.OwnersUPN && ownersUpn) a.OwnersUPN = ownersUpn;
      if (!a.LoggedOnUsers && loggedOn) a.LoggedOnUsers = loggedOn;
      if (!a.ProcessAccount && processAccount) a.ProcessAccount = processAccount;
      if (!a.OSPlatform && extra.OSPlatform) a.OSPlatform = extra.OSPlatform;
      if (!a.AadDeviceId && extra.AadDeviceId) a.AadDeviceId = extra.AadDeviceId;
      if (extra.LastSeen && (!a.LastSeen || String(extra.LastSeen) > String(a.LastSeen))) {
        a.LastSeen = extra.LastSeen;
      }
      a.Events += Number(extra.Events) || 0;
      // Re-classify each evidence line; keep the strongest (signal + weight).
      let best = {
        class: a.RiskClass,
        signal: a.Signal,
        note: a.RiskNote,
        weight: a.RiskWeight || 0,
      };
      for (const ev of a.EvidenceTraces) {
        const c = classifyRmmHit({
          family,
          evidence: ev,
          deviceName: a.DeviceName,
          osPlatform: a.OSPlatform,
        });
        if (
          Number(c.signal) > Number(best.signal) ||
          (c.signal === best.signal && c.weight > (best.weight || 0))
        ) {
          best = c;
        }
      }
      a.RiskClass = best.class;
      a.Signal = best.signal;
      a.RiskNote = best.note;
      a.RiskWeight = best.weight;
    }
  }

  if (rmmHunt && rmmHunt.results) {
    for (const r of rmmHunt.results) {
      const blob = `${r.SoftwareVendor} / ${r.SoftwareName} ${r.SoftwareVersion || ""}`;
      const family = matchFamily(blob, RMM_INDICATORS);
      const softLabel = `${r.SoftwareVendor || "?"} / ${r.SoftwareName || "?"} ${r.SoftwareVersion || ""}`.trim();
      if (!family) {
        if (isRmmMeetingFalsePositive(blob) || /logmein|gotomeeting/i.test(blob)) {
          const owners = resolveOwners(ownerIndex, r.DeviceName, r.AadDeviceId);
          rmmDismissed.push({
            DeviceName: r.DeviceName,
            OSPlatform: r.OSPlatform || "",
            Owners: owners.ownersDisplay || formatLoggedOnUsers(r.LoggedOnUsers) || "",
            OwnersUPN: owners.ownersUpn || "",
            SoftwareVendor: r.SoftwareVendor,
            SoftwareName: r.SoftwareName,
            SoftwareVersion: r.SoftwareVersion,
            Verdict:
              "Artefact / collaboration — GoTo Meeting or LogMeIn Live (not Rescue/Central/Pro RMM). No High finding.",
            Evidence: `TVM inventory: ${softLabel}`,
            DeviceId: r.DeviceId,
          });
        }
        continue;
      }
      addRmm(
        r.DeviceId,
        r.DeviceName,
        family,
        `TVM inventory: ${softLabel}`,
        "TvmSoftwareInventory",
        {
          OSPlatform: r.OSPlatform,
          OSVersion: r.OSVersion,
          LoggedOnUsers: r.LoggedOnUsers,
          AadDeviceId: r.AadDeviceId,
        }
      );
    }
  }
  if (rmmProc && rmmProc.results) {
    for (const r of rmmProc.results) {
      const family = matchFamily(`${r.FileName} ${r.FolderPath}`, RMM_INDICATORS);
      if (!family) continue;
      const pathLabel = `${r.FolderPath || ""}\\${r.FileName || ""}`.replace(
        /^\\/,
        ""
      );
      addRmm(
        r.DeviceId,
        r.DeviceName,
        family,
        `Process (30d): ${pathLabel} (${r.Events || 0} events, last ${r.LastSeen || "?"})`,
        "DeviceProcessEvents",
        {
          LastSeen: r.LastSeen,
          Events: r.Events,
          AccountName: r.AccountName,
          OSPlatform: r.OSPlatform,
          OSVersion: r.OSVersion,
          LoggedOnUsers: r.LoggedOnUsers,
          AadDeviceId: r.AadDeviceId,
        }
      );
    }
  }

  const rmmAssets = [...rmmAssetMap.values()]
    .map((a) => ({
      Family: a.Family,
      DeviceName: a.DeviceName,
      OSPlatform: a.OSPlatform,
      Owners: a.Owners || a.LoggedOnUsers || a.ProcessAccount || "(owner unknown)",
      OwnersUPN: a.OwnersUPN,
      LoggedOnUsers: a.LoggedOnUsers,
      EvidenceSources: [...a.EvidenceSources].join(" + "),
      EvidenceTrace: a.EvidenceTraces.slice(0, 4).join(" || "),
      LastSeen: a.LastSeen,
      Events: a.Events || "",
      DeviceId: a.DeviceId,
      AadDeviceId: a.AadDeviceId,
      RiskClass: a.RiskClass || "",
      Signal: !!a.Signal,
      RiskNote: a.RiskNote || "",
    }))
    .sort(
      (a, b) =>
        String(a.Family).localeCompare(String(b.Family)) ||
        String(a.DeviceName).localeCompare(String(b.DeviceName))
    );

  const rmmFamilySummary = [];
  for (const [family, devices] of rmmByFamilyDevice.entries()) {
    const famAssets = rmmAssets.filter((a) => a.Family === family);
    const agentDevices = famAssets.filter((a) => a.Signal).length;
    const noiseDevices = famAssets.length - agentDevices;
    const mobileDevices = famAssets.filter((a) => a.RiskClass === "mobile").length;
    const viewerDevices = famAssets.filter((a) => a.RiskClass === "viewer").length;
    const adhocDevices = famAssets.filter((a) => a.RiskClass === "adhoc").length;
    const count = devices.size;
    // Prevalence for "corporate RMM" uses agent hosts when we can tell them apart.
    const prevalenceBase = agentDevices > 0 ? agentDevices : count;
    const pct = totalWindows > 0 ? prevalenceBase / totalWindows : null;
    const assumedLegit =
      totalWindows > 0 && pct != null && pct >= rmmLegitThreshold && agentDevices > 0;
    const noiseOnly = agentDevices === 0 && count > 0;
    const assetSamples = famAssets
      .filter((a) => a.Signal)
      .slice(0, 8)
      .map((a) => `${a.DeviceName || "?"} [${a.Owners}]`)
      .join(" · ");
    const noiseSamples = famAssets
      .filter((a) => !a.Signal)
      .slice(0, 4)
      .map((a) => `${a.DeviceName || "?"} (${a.RiskClass})`)
      .join(" · ");
    rmmFamilySummary.push({
      Family: family,
      Devices: count,
      AgentDevices: agentDevices,
      NoiseDevices: noiseDevices,
      MobileDevices: mobileDevices,
      ViewerDevices: viewerDevices,
      AdhocDevices: adhocDevices,
      TotalWindows: totalWindows,
      PrevalencePct:
        totalWindows && pct != null ? Math.round(pct * 1000) / 10 : "",
      AssumedLegit: assumedLegit,
      Verdict: noiseOnly
        ? "Noise only — mobile/viewer/adhoc inventory (no desktop agent signal)"
        : !totalWindows
          ? `Inventory — ${agentDevices} agent / ${noiseDevices} noise (DeviceInfo missing, fleet % n/a)`
          : assumedLegit
            ? `Likely corporate RMM (≥${Math.round(rmmLegitThreshold * 100)}% agent coverage)`
            : `Review — ${agentDevices} agent host(s), low prevalence / possibly illegitimate`,
      AffectedAssets: assetSamples || noiseSamples,
    });
  }
  rmmFamilySummary.sort(
    (a, b) =>
      Number(b.AgentDevices || 0) - Number(a.AgentDevices || 0) ||
      Number(b.Devices || 0) - Number(a.Devices || 0)
  );

  io.saveCsv("30_RMM_Detections.csv", rmmRows);
  io.saveCsv("30_RMM_Affected_Assets.csv", rmmAssets);
  io.saveCsv("30_RMM_Family_Summary.csv", rmmFamilySummary);
  io.saveCsv("30_RMM_Dismissed_Artefacts.csv", rmmDismissed);
  summary.rmmFamilies = rmmFamilySummary.length;
  summary.rmmAgentFamilies = rmmFamilySummary.filter(
    (x) => Number(x.AgentDevices || 0) > 0 && !x.AssumedLegit
  ).length;
  summary.rmmSuspiciousFamilies = summary.rmmAgentFamilies;
  summary.rmmNoiseOnlyFamilies = rmmFamilySummary.filter(
    (x) => Number(x.AgentDevices || 0) === 0 && Number(x.Devices || 0) > 0
  ).length;
  summary.rmmAffectedAssets = rmmAssets.length;
  summary.rmmAgentAssets = rmmAssets.filter((a) => a.Signal).length;
  summary.rmmNoiseAssets = rmmAssets.filter((a) => !a.Signal).length;
  summary.rmmDismissedArtefacts = rmmDismissed.length;
  summary.rmmLegitThreshold = rmmLegitThreshold;
  summary.rmmPrevalenceKnown = totalWindows > 0;

  if (rmmDismissed.length) {
    const sample = rmmDismissed
      .slice(0, 8)
      .map(
        (d) =>
          `${d.DeviceName}: ${d.SoftwareVendor}/${d.SoftwareName} (${d.Owners || "?"})`
      )
      .join(" | ");
    pushFinding(
      findings,
      "Info",
      "RMM",
      `${rmmDismissed.length} LogMeIn/GoTo TVM hit(s) dismissed as meeting/collaboration artefacts (not Rescue/Central/Pro) — ${sample} — 30_RMM_Dismissed_Artefacts.csv`
    );
  }

  const agentFamilies = rmmFamilySummary.filter((x) => Number(x.AgentDevices || 0) > 0);
  const noiseOnlyFamilies = rmmFamilySummary.filter(
    (x) => Number(x.AgentDevices || 0) === 0 && Number(x.Devices || 0) > 0
  );

  if (noiseOnlyFamilies.length) {
    const sample = noiseOnlyFamilies
      .map(
        (f) =>
          `${f.Family}×${f.Devices} (mobile=${f.MobileDevices}, viewer=${f.ViewerDevices}, adhoc=${f.AdhocDevices})`
      )
      .join("; ");
    pushFinding(
      findings,
      "Info",
      "RMM",
      `Noise-filtered RMM inventory (no desktop agent signal): ${sample} — 30_RMM_Family_Summary.csv`
    );
  }

  if (!totalWindows && agentFamilies.length) {
    const sample = agentFamilies
      .slice(0, 6)
      .map((f) => `${f.Family}×${f.AgentDevices} agents`)
      .join(", ");
    pushFinding(
      findings,
      "Medium",
      "RMM",
      `Desktop RMM agents in TVM inventory (${sample}) — DeviceInfo missing so fleet prevalence was not measured; confirm allow-list — 30_RMM_Affected_Assets.csv`
    );
  }

  for (const f of agentFamilies.filter(
    (x) => totalWindows > 0 && !x.AssumedLegit
  )) {
    const assets = rmmAssets.filter((a) => a.Family === f.Family && a.Signal);
    const assetLines = assets
      .slice(0, 12)
      .map(
        (a) =>
          `${a.DeviceName || "?"} (${a.OSPlatform || "?"}) owner=${a.Owners}; trace=${a.EvidenceTrace}`
      )
      .join(" | ");
    pushFinding(
      findings,
      "High",
      "RMM",
      `${f.Family}: ${f.AgentDevices} agent host(s) (${f.PrevalencePct ?? "?"}% vs ${totalWindows || "?"} Windows; ${f.NoiseDevices} noise hosts filtered) — below ${Math.round(rmmLegitThreshold * 100)}% threshold. Assets: ${assetLines || "see 30_RMM_Affected_Assets.csv"}`
    );
  }
  for (const f of rmmFamilySummary.filter((x) => x.AssumedLegit)) {
    pushFinding(
      findings,
      "Info",
      "RMM",
      `${f.Family} on ${f.AgentDevices || f.Devices} agent host(s) (${f.PrevalencePct}%) — assumed legitimate corporate RMM; assets in 30_RMM_Affected_Assets.csv`
    );
  }
  if (!rmmFamilySummary.length && schema.capabilities.rmm) {
    pushFinding(findings, "Info", "RMM", "No RMM indicators found");
  }

  // ── 2) AI agents ──────────────────────────────────────────────────────
  console.log("  · AI agent indicators");
  const aiPatterns = AI_AGENT_INDICATORS.flatMap((f) => f.patterns)
    .map((p) => p.replace(/"/g, ""))
    .slice(0, 100);

  const aiQuery = kqlAiAgents(JSON.stringify(aiPatterns), schema);
  const aiHunt = aiQuery ? await hunt("hunt_ai_agents", aiQuery) : null;

  let aiDeviceDetail = null;
  if (schema.has("DeviceProcessEvents")) {
    aiDeviceDetail = await hunt(
      "hunt_ai_agents_devices",
      `
let patterns = dynamic(${JSON.stringify(aiPatterns)});
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName has_any (patterns) or FolderPath has_any (patterns) or ProcessCommandLine has_any (patterns)
| summarize LastSeen=max(Timestamp), Events=count() by DeviceId, DeviceName, FileName, FolderPath
| top 1000 by Events desc
`.trim()
    );
  }
  if (!schema.capabilities.ai) {
    const why = skipReason(schema, "ai") || "no AI tables";
    console.log(`  · Skip AI hunts: ${why}`);
    pushFinding(
      findings,
      "Info",
      "AIAgents",
      `Skipped — ${why}. See 19_Hunting_Schema.json.`
    );
  }

  const aiRows = [];
  if (aiHunt && aiHunt.results) {
    for (const r of aiHunt.results) {
      aiRows.push({
        Family: r.Family,
        Source: r.Source,
        Devices: r.Devices,
        Events: r.Events,
        SampleDevices: Array.isArray(r.SampleDevices)
          ? r.SampleDevices.join(" | ")
          : r.SampleDevices,
        SampleSignals: Array.isArray(r.SampleSignals)
          ? r.SampleSignals.join(" | ")
          : r.SampleSignals,
      });
    }
  }
  io.saveCsv("31_AI_Agents_Summary.csv", aiRows);

  const aiDeviceRows = [];
  if (aiDeviceDetail && aiDeviceDetail.results) {
    for (const r of aiDeviceDetail.results) {
      const family =
        matchFamily(`${r.FileName} ${r.FolderPath}`, AI_AGENT_INDICATORS) ||
        "OtherAI";
      aiDeviceRows.push({
        Family: family,
        DeviceId: r.DeviceId,
        DeviceName: r.DeviceName,
        FileName: r.FileName,
        FolderPath: r.FolderPath,
        LastSeen: r.LastSeen,
        Events: r.Events,
      });
    }
  }
  io.saveCsv("31_AI_Agents_Devices.csv", aiDeviceRows);
  summary.aiAgentFamilies = new Set(aiRows.map((r) => r.Family)).size;
  summary.aiAgentDeviceRows = aiDeviceRows.length;
  if (aiRows.length) {
    pushFinding(
      findings,
      "Medium",
      "AIAgents",
      `${aiRows.length} AI-agent signal groups / ${aiDeviceRows.length} device process rows — review 31_AI_Agents_*`
    );
  } else if (schema.capabilities.ai) {
    pushFinding(findings, "Info", "AIAgents", "No AI agent indicators found");
  }

  // ── 3) Windows 10 + Patch Tuesday lag ─────────────────────────────────
  console.log("  · Windows version / Patch Tuesday lag");
  let osHunt = null;
  if (schema.has("DeviceInfo")) {
    osHunt = await hunt(
      "hunt_os_builds",
      `
DeviceInfo
| where Timestamp > ago(7d)
| where isnotempty(DeviceId)
| summarize arg_max(Timestamp, *) by DeviceId
| where OSPlatform has_any ("Windows", "Windows10", "Windows11") or OSVersion startswith "10.0"
| project DeviceId, DeviceName, OSPlatform, OSVersion, OSBuild, MachineGroup, LoggedOnUsers
`.trim()
    );
  } else {
    const why = skipReason(schema, "patch") || "DeviceInfo missing";
    console.log(`  · Skip OS/patch hunt: ${why}`);
    pushFinding(
      findings,
      "Info",
      "PatchTuesday",
      `Skipped — ${why}. Use Intune device reports or Entra devices (09_*). See 19_Hunting_Schema.json.`
    );
  }

  const tvmBuildByDevice = new Map();
  if (schema.has("DeviceTvmSoftwareVulnerabilities") || schema.has("DeviceTvmSoftwareInventory")) {
    const tvmTable = schema.has("DeviceTvmSoftwareInventory")
      ? "DeviceTvmSoftwareInventory"
      : "DeviceTvmSoftwareVulnerabilities";
    const tvmVers = await hunt(
      "hunt_windows_tvm_versions",
      `
${tvmTable}
| where SoftwareName startswith "windows"
| where isnotempty(DeviceId) and isnotempty(SoftwareVersion)
| summarize SoftwareVersion=max(SoftwareVersion) by DeviceId
`.trim()
    );
    if (tvmVers && tvmVers.results) {
      for (const r of tvmVers.results) {
        const b = parseOsBuild(r.SoftwareVersion);
        if (b && b.ubr != null) tvmBuildByDevice.set(String(r.DeviceId), b);
      }
    }
  }

  const osRows = [];
  let win10 = 0;
  let win11 = 0;
  let behind = 0;
  if (osHunt && osHunt.results) {
    for (const r of osHunt.results) {
      const ver = [r.OSVersion, r.OSBuild].filter(Boolean).join(" ");
      let build = parseOsBuild(ver) || parseOsBuild(r.OSVersion) || parseOsBuild(r.OSBuild);
      const tvmBuild = tvmBuildByDevice.get(String(r.DeviceId));
      if (tvmBuild && (build == null || build.ubr == null)) build = tvmBuild;
      else if (tvmBuild && build && build.ubr == null) build = tvmBuild;
      const patch = patchStatus(build, patchBaseline);
      const w10 = isWindows10(r.OSPlatform, ver);
      const w11 = isWindows11(r.OSPlatform, ver);
      if (w10) win10++;
      if (w11) win11++;
      if (patch.status === "BehindPatchTuesday") behind++;
      osRows.push({
        DeviceId: r.DeviceId,
        DeviceName: r.DeviceName,
        OSPlatform: r.OSPlatform,
        OSVersion: ver,
        OSBuild: r.OSBuild,
        IsWindows10: w10,
        IsWindows11: w11,
        BuildMajor: build ? build.major : "",
        UBR: build ? build.ubr : "",
        Product: patch.product,
        PatchStatus: patch.status,
        ExpectedKB: patch.kbExpected,
        LagUBR: patch.lagUbr,
        PatchTuesdayAsOf: patchBaseline.asOf,
        MachineGroup: r.MachineGroup,
      });
    }
  }
  io.saveCsv("32_Endpoints_OS_PatchStatus.csv", osRows);
  io.saveCsv(
    "32_Windows10_Devices.csv",
    osRows.filter((r) => r.IsWindows10)
  );
  io.saveCsv(
    "32_Behind_PatchTuesday.csv",
    osRows.filter((r) => r.PatchStatus === "BehindPatchTuesday")
  );

  const buildDist = {};
  for (const r of osRows) {
    const k = `${r.IsWindows10 ? "Win10" : r.IsWindows11 ? "Win11" : "Other"}|${r.BuildMajor}.${r.UBR}|${r.PatchStatus}`;
    buildDist[k] = (buildDist[k] || 0) + 1;
  }
  io.saveCsv(
    "32_OS_Build_Distribution.csv",
    Object.entries(buildDist).map(([k, n]) => {
      const [family, build, status] = k.split("|");
      return { Family: family, Build: build, PatchStatus: status, Devices: n };
    })
  );

  summary.windows10Count = win10;
  summary.windows11Count = win11;
  summary.behindPatchTuesdayCount = behind;
  summary.patchTuesdayAsOf = patchBaseline.asOf;

  if (osRows.length) {
    pushFinding(
      findings,
      win10 ? "Medium" : "Info",
      "Windows10",
      `${win10} Windows 10 devices still active (EOS/ESU risk) — 32_Windows10_Devices.csv`
    );
    pushFinding(
      findings,
      behind ? "High" : "Info",
      "PatchTuesday",
      `${behind} devices behind ${patchBaseline.label} (${patchBaseline.asOf}, source=${patchBaseline.source}) — 32_Behind_PatchTuesday.csv`
    );
  }

  if (schema.has("DeviceTvmSoftwareVulnerabilities")) {
    // Portal AH: avoid multi-column `top by a,b`. Use SortKey + sort|take.
    const tvmOs = await hunt(
      "hunt_tvm_os_vulns",
      `
DeviceTvmSoftwareVulnerabilities
| where VulnerabilitySeverityLevel in ("Critical","High")
| where SoftwareName startswith "windows"
| summarize Vulns=dcount(CveId), Critical=countif(VulnerabilitySeverityLevel == "Critical"), High=countif(VulnerabilitySeverityLevel == "High") by DeviceId, DeviceName, SoftwareName, SoftwareVersion
| extend SortKey = Critical * 100000 + High
| sort by SortKey desc
| take 500
| project DeviceId, DeviceName, SoftwareName, SoftwareVersion, Vulns, Critical, High
`.trim()
    );
    if (tvmOs && tvmOs.results) {
      io.saveCsv(
        "32_TVM_Windows_HighCritical.csv",
        tvmOs.results.map((r) => ({
          DeviceId: r.DeviceId,
          DeviceName: r.DeviceName,
          Software: r.SoftwareName,
          Version: r.SoftwareVersion,
          Vulns: r.Vulns,
          Critical: r.Critical,
          High: r.High,
        }))
      );
      summary.tvmWindowsHighCritDevices = tvmOs.results.length;
      summary.tvmWindowsHighCritCriticalSum = tvmOs.results.reduce(
        (n, r) => n + (Number(r.Critical) || 0),
        0
      );
      pushFinding(
        findings,
        tvmOs.results.length ? "High" : "Info",
        "TvmWindowsOs",
        `${tvmOs.results.length} Windows device/software row(s) with High/Critical TVM vulns — 32_TVM_Windows_HighCritical.csv`
      );
    }
    const tvmOsCves = await hunt(
      "hunt_tvm_os_cves",
      `
DeviceTvmSoftwareVulnerabilities
| where VulnerabilitySeverityLevel in ("Critical","High")
| where SoftwareName startswith "windows"
| summarize Devices=dcount(DeviceId) by CveId, VulnerabilitySeverityLevel, SoftwareName, SoftwareVersion
| extend SortKey = Devices
| sort by SortKey desc
| take 200
| project CveId, VulnerabilitySeverityLevel, SoftwareName, SoftwareVersion, Devices
`.trim()
    );
    if (tvmOsCves && tvmOsCves.results) {
      io.saveCsv(
        "32_TVM_Windows_CVE_Inventory.csv",
        tvmOsCves.results.map((r) => ({
          CveId: r.CveId,
          Severity: r.VulnerabilitySeverityLevel,
          Software: r.SoftwareName,
          Version: r.SoftwareVersion,
          Devices: r.Devices,
        }))
      );
      summary.tvmWindowsCveInventoryRows = tvmOsCves.results.length;
    }
  }

  // ── 3b) GenAI cloud usage (volume) + file-sharing sites ───────────────
  console.log("  · GenAI usage / file-sharing sites (Cloud Apps + network)");
  const GENAI_APPS = [
    "ChatGPT",
    "OpenAI",
    "Claude",
    "Anthropic",
    "Gemini",
    "Google Bard",
    "Perplexity",
    "Microsoft Copilot",
    "Copilot",
    "Midjourney",
    "Character.AI",
    "Poe",
    "Hugging Face",
    "Grok",
    "You.com",
    "Jasper",
    "Writesonic",
  ];
  const GENAI_DOMAINS = [
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
  const SHARE_APPS = [
    "WeTransfer",
    "Dropbox",
    "Mega",
    "Box",
    "MediaFire",
    "SendSpace",
    "pCloud",
    "SwissTransfer",
    "Smash",
    "TransferNow",
    "Filemail",
    "Gofile",
  ];
  const SHARE_DOMAINS = [
    "wetransfer.com",
    "we.tl",
    "dropbox.com",
    "dropboxusercontent.com",
    "mega.nz",
    "mega.co.nz",
    "mediafire.com",
    "box.com",
    "box.net",
    "sendspace.com",
    "filemail.com",
    "transfernow.net",
    "swisstransfer.com",
    "fromsmash.com",
    "pcloud.com",
    "gofile.io",
    "pixeldrain.com",
    "anonfiles.com",
    "icedrive.net",
  ];

  let genAiUsers = [];
  let genAiApps = [];
  let shareUsers = [];
  let shareApps = [];

  // Portal apiproxy is picky: keep summarize…by on one line, bound make_set,
  // prefer sort|take over top, avoid coalesce on optional CloudApp columns.
  if (schema.has("CloudAppEvents")) {
    const genAiCloud = await hunt(
      "hunt_genai_cloudapp",
      `
let apps = dynamic(${JSON.stringify(GENAI_APPS)});
CloudAppEvents
| where Timestamp > ago(30d)
| where Application has_any (apps)
| extend Account = tostring(AccountObjectId)
| summarize Events=count(), LastSeen=max(Timestamp), SampleActions=make_set(ActionType, 10) by Application, Account
| sort by Events desc
| take 500
`.trim()
    );
    if (genAiCloud && genAiCloud.results) {
      genAiUsers = genAiCloud.results.map((r) => ({
        Application: r.Application,
        Account: r.Account,
        Events: r.Events,
        LastSeen: r.LastSeen,
        SampleActions: Array.isArray(r.SampleActions)
          ? r.SampleActions.join(" | ")
          : r.SampleActions,
        Source: "CloudAppEvents",
      }));
    }

    const genAiByApp = await hunt(
      "hunt_genai_by_app",
      `
let apps = dynamic(${JSON.stringify(GENAI_APPS)});
CloudAppEvents
| where Timestamp > ago(30d)
| where Application has_any (apps)
| summarize Events=count(), Users=dcount(AccountObjectId), LastSeen=max(Timestamp) by Application
| sort by Events desc
| take 200
`.trim()
    );
    if (genAiByApp && genAiByApp.results) {
      genAiApps = genAiByApp.results.map((r) => ({
        Application: r.Application,
        Events: r.Events,
        Users: r.Users,
        LastSeen: r.LastSeen,
        Source: "CloudAppEvents",
      }));
    }

    const shareCloud = await hunt(
      "hunt_fileshare_cloudapp",
      `
let apps = dynamic(${JSON.stringify(SHARE_APPS)});
CloudAppEvents
| where Timestamp > ago(30d)
| where Application has_any (apps)
| extend Account = tostring(AccountObjectId)
| summarize Events=count(), LastSeen=max(Timestamp), SampleActions=make_set(ActionType, 10) by Application, Account
| sort by Events desc
| take 500
`.trim()
    );
    if (shareCloud && shareCloud.results) {
      shareUsers = shareCloud.results.map((r) => ({
        Application: r.Application,
        Account: r.Account,
        Events: r.Events,
        LastSeen: r.LastSeen,
        SampleActions: Array.isArray(r.SampleActions)
          ? r.SampleActions.join(" | ")
          : r.SampleActions,
        Source: "CloudAppEvents",
      }));
    }

    const shareByApp = await hunt(
      "hunt_fileshare_by_app",
      `
let apps = dynamic(${JSON.stringify(SHARE_APPS)});
CloudAppEvents
| where Timestamp > ago(30d)
| where Application has_any (apps)
| summarize Events=count(), Users=dcount(AccountObjectId), LastSeen=max(Timestamp) by Application
| sort by Events desc
| take 200
`.trim()
    );
    if (shareByApp && shareByApp.results) {
      shareApps = shareByApp.results.map((r) => ({
        Application: r.Application,
        Events: r.Events,
        Users: r.Users,
        LastSeen: r.LastSeen,
        Source: "CloudAppEvents",
      }));
    }
  }

  if (schema.has("DeviceNetworkEvents")) {
    const genAiNet = await hunt(
      "hunt_genai_network",
      `
let domains = dynamic(${JSON.stringify(GENAI_DOMAINS)});
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where isnotempty(RemoteUrl)
| where RemoteUrl has_any (domains)
| summarize Events=count(), LastSeen=max(Timestamp), SampleUrls=make_set(RemoteUrl, 8) by DeviceId, DeviceName, InitiatingProcessAccountName
| sort by Events desc
| take 500
`.trim()
    );
    if (genAiNet && genAiNet.results) {
      for (const r of genAiNet.results) {
        genAiUsers.push({
          Application: "GenAI-domain",
          Account: r.InitiatingProcessAccountName || r.DeviceName,
          DeviceName: r.DeviceName,
          Events: r.Events,
          LastSeen: r.LastSeen,
          SampleActions: Array.isArray(r.SampleUrls)
            ? r.SampleUrls.join(" | ")
            : r.SampleUrls,
          Source: "DeviceNetworkEvents",
        });
      }
    }

    const shareNet = await hunt(
      "hunt_fileshare_network",
      `
let domains = dynamic(${JSON.stringify(SHARE_DOMAINS)});
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where isnotempty(RemoteUrl)
| where RemoteUrl has_any (domains)
| summarize Events=count(), LastSeen=max(Timestamp), SampleUrls=make_set(RemoteUrl, 8) by DeviceId, DeviceName, InitiatingProcessAccountName
| sort by Events desc
| take 500
`.trim()
    );
    if (shareNet && shareNet.results) {
      for (const r of shareNet.results) {
        shareUsers.push({
          Application: "FileShare-domain",
          Account: r.InitiatingProcessAccountName || r.DeviceName,
          DeviceName: r.DeviceName,
          Events: r.Events,
          LastSeen: r.LastSeen,
          SampleActions: Array.isArray(r.SampleUrls)
            ? r.SampleUrls.join(" | ")
            : r.SampleUrls,
          Source: "DeviceNetworkEvents",
        });
      }
    }
  }

  if (!schema.capabilities.cloudGenAi && !schema.capabilities.fileSharing) {
    pushFinding(
      findings,
      "Info",
      "CloudUsage",
      "Skipped GenAI / file-sharing hunts — need CloudAppEvents or DeviceNetworkEvents. See 19_Hunting_Schema.json."
    );
  }

  io.saveCsv("34_GenAI_Usage_ByUser.csv", genAiUsers);
  io.saveCsv("34_GenAI_Usage_ByApp.csv", genAiApps);
  io.saveCsv("35_FileShare_Usage_ByUser.csv", shareUsers);
  io.saveCsv("35_FileShare_Usage_ByApp.csv", shareApps);

  // Neither CloudAppEvents nor DeviceNetworkEvents carries transfer volume —
  // the only byte-like column in the schema is InitiatingProcessFileSize, the
  // size of the *executable*. Reporting "~0 MB" from that read as "nobody
  // uploads anything", which is the opposite of the truth. Count reach instead:
  // events, distinct users and distinct devices.
  const genAiEvents = genAiUsers.reduce((s, r) => s + (Number(r.Events) || 0), 0);
  summary.genAiUsageRows = genAiUsers.length;
  summary.genAiApps = genAiApps.length || new Set(genAiUsers.map((r) => r.Application)).size;
  summary.genAiEvents = genAiEvents;
  summary.genAiAccounts = new Set(
    genAiUsers.map((r) => r.Account).filter(Boolean)
  ).size;
  summary.genAiDevices = new Set(
    genAiUsers.map((r) => r.DeviceName).filter(Boolean)
  ).size;
  summary.genAiVolumeAvailable = false;
  summary.fileShareUsageRows = shareUsers.length;
  summary.fileShareEvents = shareUsers.reduce((s, r) => s + (Number(r.Events) || 0), 0);
  summary.fileShareDevices = new Set(
    shareUsers.map((r) => r.DeviceName).filter(Boolean)
  ).size;
  summary.fileShareApps =
    shareApps.length || new Set(shareUsers.map((r) => r.Application)).size;

  if (genAiUsers.length) {
    pushFinding(
      findings,
      "Info",
      "GenAI",
      `${summary.genAiEvents} GenAI interaction/connection events across ${summary.genAiAccounts} account(s) and ${summary.genAiDevices} device(s) in 30d — transfer volume is not exposed by Defender hunting tables — 34_GenAI_Usage_*.csv`
    );
  } else if (schema.capabilities.cloudGenAi) {
    pushFinding(
      findings,
      "Info",
      "GenAI",
      "No GenAI Cloud App / network signals in last 30d"
    );
  }
  if (shareUsers.length) {
    pushFinding(
      findings,
      "Medium",
      "FileSharing",
      `${shareUsers.length} file-sharing usage rows (WeTransfer/Dropbox/…) — review 35_FileShare_Usage_*.csv`
    );
  } else if (schema.capabilities.fileSharing) {
    pushFinding(
      findings,
      "Info",
      "FileSharing",
      "No WeTransfer/Dropbox-class sharing signals in last 30d"
    );
  }

  // ── 4) Intune update rings (Graph — independent of hunting schema) ────
  console.log("  · Intune Windows Update rings");
  const updateRings = [];

  // Classic Windows Update for Business / update ring configs
  const configs = await soft(
    "intune_deviceConfigurations",
    () =>
      graph.getAll(
        `${graph.GRAPH_BETA}/deviceManagement/deviceConfigurations`
      ),
    io
  );
  if (configs && Array.isArray(configs)) {
    for (const c of configs) {
      const odata = c["@odata.type"] || "";
      if (
        /windowsUpdateForBusinessConfiguration|windows10UpdateRing|updateRing/i.test(
          odata + (c.displayName || "")
        ) ||
        /update ring|windows update/i.test(c.displayName || "")
      ) {
        updateRings.push({
          Id: c.id,
          DisplayName: c.displayName,
          Type: odata,
          QualityDeferralDays: c.qualityUpdatesDeferralPeriodInDays,
          FeatureDeferralDays: c.featureUpdatesDeferralPeriodInDays,
          FeaturePeriodDays: c.featureUpdatesPausePeriodInDays,
          QualityPaused: c.qualityUpdatesPaused,
          FeaturePaused: c.featureUpdatesPaused,
          DeadlineQuality: c.deadlineForQualityUpdatesInDays,
          DeadlineFeature: c.deadlineForFeatureUpdatesInDays,
          AllowWindows11Upgrade: c.allowWindows11Upgrade,
          BusinessReady: c.businessReadyUpdatesOnly,
          DriversExcluded: c.driversExcluded,
          PrereleaseChannel: c.prereleaseFeatures,
          EngagedInstallHours: c.engagedRestartDeadlineInDays,
          Created: c.createdDateTime,
          Modified: c.lastModifiedDateTime,
          Source: "deviceConfigurations",
        });
      }
    }
  }

  // Settings catalog policies (newer update rings)
  const configPolicies = await soft(
    "intune_configurationPolicies",
    () =>
      graph.getAll(
        `${graph.GRAPH_BETA}/deviceManagement/configurationPolicies?$select=id,name,description,platforms,technologies,templateReference,createdDateTime,lastModifiedDateTime`
      ),
    io
  );
  if (configPolicies && Array.isArray(configPolicies)) {
    for (const p of configPolicies) {
      const name = `${p.name || ""} ${p.description || ""}`;
      const tmpl =
        (p.templateReference && p.templateReference.templateDisplayName) || "";
      if (/update|quality|feature|windows.?update/i.test(name + tmpl)) {
        // Fetch settings for this policy
        const settings = await soft(
          `intune_policy_settings_${p.id}`,
          () =>
            graph.getAll(
              `${graph.GRAPH_BETA}/deviceManagement/configurationPolicies/${p.id}/settings`
            ),
          io
        );
        updateRings.push({
          Id: p.id,
          DisplayName: p.name,
          Type: "configurationPolicy/settingsCatalog",
          Template: tmpl,
          Platforms: p.platforms,
          Technologies: p.technologies,
          SettingsCount: settings ? settings.length : null,
          SettingsPreview: settings
            ? JSON.stringify(settings).slice(0, 500)
            : "",
          Created: p.createdDateTime,
          Modified: p.lastModifiedDateTime,
          Source: "configurationPolicies",
        });
      }
    }
  }

  // Feature update profiles
  const featureUpdates = await soft(
    "intune_featureUpdateProfiles",
    () =>
      graph.getAll(
        `${graph.GRAPH_BETA}/deviceManagement/windowsFeatureUpdateProfiles`
      ),
    io
  );
  if (featureUpdates && Array.isArray(featureUpdates)) {
    for (const p of featureUpdates) {
      updateRings.push({
        Id: p.id,
        DisplayName: p.displayName,
        Type: "windowsFeatureUpdateProfile",
        FeatureUpdateVersion: p.featureUpdateVersion,
        RolloutPace: p.rolloutSettings && JSON.stringify(p.rolloutSettings),
        Created: p.createdDateTime,
        Modified: p.lastModifiedDateTime,
        Source: "windowsFeatureUpdateProfiles",
      });
    }
  }

  const qualityUpdates = await soft(
    "intune_qualityUpdateProfiles",
    () =>
      graph.getAll(
        `${graph.GRAPH_BETA}/deviceManagement/windowsQualityUpdateProfiles`
      ),
    io
  );
  if (qualityUpdates && Array.isArray(qualityUpdates)) {
    for (const p of qualityUpdates) {
      updateRings.push({
        Id: p.id,
        DisplayName: p.displayName,
        Type: "windowsQualityUpdateProfile",
        DeployedContent: p.deployableContentDisplayName,
        Created: p.createdDateTime,
        Modified: p.lastModifiedDateTime,
        Source: "windowsQualityUpdateProfiles",
      });
    }
  }

  io.saveCsv("33_Intune_UpdateRings.csv", updateRings);
  io.saveJson("33_Intune_UpdateRings_raw.json", {
    deviceConfigurationsMatched: (configs || []).length,
    updateRingRows: updateRings,
  });
  summary.updateRingPolicies = updateRings.length;

  if (updateRings.length) {
    pushFinding(
      findings,
      "Info",
      "UpdateRings",
      `${updateRings.length} Intune update-ring / WUfB / feature-quality profiles — 33_Intune_UpdateRings.csv`
    );
  } else {
    pushFinding(
      findings,
      "Medium",
      "UpdateRings",
      "No Intune update rings readable (missing Intune Reader permission, or none configured) — check Endpoint Manager manually"
    );
  }

  summary.endpointHuntsCollected = true;
}

module.exports = {
  collectEndpointHunts,
  PATCH_TUESDAY,
  RMM_INDICATORS,
  AI_AGENT_INDICATORS,
  formatLoggedOnUsers,
  buildDeviceOwnerIndex,
  resolveOwners,
  matchFamily,
  isRmmMeetingFalsePositive,
  classifyRmmHit,
};
