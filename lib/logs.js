/**
 * High-value Entra sign-in / audit log extractions (device code, legacy auth, etc.)
 * Prefers Graph auditLogs/signIns; uses Advanced Hunting only when schema has identity tables.
 */
const {
  pickIdentityDialect,
  pickSpnDialect,
  kqlDeviceCode,
  kqlLegacySuccess,
  kqlFailuresByIp,
  kqlSingleFactor,
  kqlAdminTooling,
  kqlDeviceCodeBlocked,
  kqlSpnSignIns,
} = require("./schema");

const { aggregateFailuresByIp, classifyAccountKind } = require("./posture");

const { soft, STATUS } = require("./io");

function isoDaysAgo(days) {
  return new Date(Date.now() - days * 86400000).toISOString();
}

function pushFinding(findings, severity, area, detail) {
  findings.push({ Severity: severity, Area: area, Detail: detail });
}

/**
 * `clientAppUsed` values Entra reports for legacy (basic-auth capable)
 * protocols. Same set the portal's "legacy authentication clients" filter and
 * the CA "Other clients" condition cover.
 */
const LEGACY_CLIENT_APPS = [
  "Exchange ActiveSync",
  "Other clients",
  "IMAP4",
  "POP3",
  "SMTP",
  "Authenticated SMTP",
  "Exchange Online PowerShell",
  "Exchange Web Services",
  "MAPI Over HTTP",
  "Offline Address Book",
  "Outlook Anywhere (RPC over HTTP)",
  "Autodiscover",
  "Reporting Web Services",
  "Universal Outlook",
];

function odataQuote(s) {
  return `'${String(s).replace(/'/g, "''")}'`;
}

/** Successful legacy-protocol sign-ins since `since` — filtered by Graph, not sampled. */
function buildLegacyFilter(since) {
  const clients = LEGACY_CLIENT_APPS.map((c) => `clientAppUsed eq ${odataQuote(c)}`).join(" or ");
  return `createdDateTime ge ${since} and status/errorCode eq 0 and (${clients})`;
}

/** Failed sign-ins since `since`. */
function buildFailureFilter(since) {
  return `createdDateTime ge ${since} and status/errorCode ne 0`;
}

/** Device-code sign-ins — `authenticationProtocol` exists on beta only. */
function buildDeviceCodeFilter(since) {
  return `createdDateTime ge ${since} and authenticationProtocol eq 'deviceCode'`;
}

/**
 * Query Graph sign-in logs with pagination and a page budget.
 *
 * The result array carries `truncated: true` when the budget was hit while a
 * nextLink remained — the caller must then say "partial", never "none".
 *
 * @param {"prefer"|"only"|"never"} [opts.beta] beta endpoint policy. `prefer`
 *   falls back to v1.0 only on a *deterministic* first-page rejection, and only
 *   when the filter does not rely on a beta-only property.
 */
async function getSignIns(graph, filter, { top = 999, maxPages = 20, beta = "prefer" } = {}) {
  const items = [];
  const q = `?$filter=${encodeURIComponent(filter)}&$top=${Math.min(top, 999)}&$orderby=createdDateTime desc`;
  const v1Url = `${graph.GRAPH}/auditLogs/signIns${q}`;
  const betaUrl = `${graph.GRAPH_BETA}/auditLogs/signIns${q}`;

  let next = beta === "never" ? v1Url : betaUrl;
  let useBeta = beta !== "never";
  let pages = 0;

  while (next && pages < maxPages) {
    pages++;
    let data;
    try {
      data = await graph.get(next);
    } catch (e) {
      const deterministic = e && e.status === 400;
      if (useBeta && beta === "prefer" && pages === 1 && deterministic) {
        useBeta = false;
        next = v1Url;
        pages = 0;
        continue;
      }
      throw e;
    }
    if (Array.isArray(data.value)) items.push(...data.value);
    else if (data && !data.value) return Array.isArray(data) ? data : [data];
    next = data["@odata.nextLink"] || null;
  }
  if (next) {
    items.truncated = true;
    items.truncatedAtPages = maxPages;
  }
  return items;
}

/** Partial-coverage note for a truncated pull, or "". */
function truncNote(items, unit = "events") {
  return items && items.truncated
    ? ` (partial: page budget reached at ${items.length} most recent ${unit})`
    : "";
}

function mapSignInRow(s) {
  const status = s.status || {};
  return {
    Created: s.createdDateTime,
    User: s.userDisplayName,
    UPN: s.userPrincipalName,
    App: s.appDisplayName,
    AppId: s.appId,
    Resource: s.resourceDisplayName,
    Ip: s.ipAddress,
    Location:
      s.location &&
      [s.location.city, s.location.state, s.location.countryOrRegion]
        .filter(Boolean)
        .join(", "),
    ClientApp: s.clientAppUsed,
    AuthProtocol: s.authenticationProtocol || "",
    IncomingTokenType: s.incomingTokenType || "",
    IsInteractive: s.isInteractive,
    ConditionalAccess: s.conditionalAccessStatus,
    RiskDetail: s.riskDetail,
    RiskLevelAgg: s.riskLevelAggregated,
    RiskState: s.riskState,
    ErrorCode: status.errorCode,
    FailureReason: status.failureReason,
    AdditionalDetails: status.additionalDetails,
    MFA:
      (s.authenticationRequirement || "") +
      (s.authenticationDetails
        ? " | " +
          (s.authenticationDetails || [])
            .map((d) => d.authenticationMethod || d.succeeded)
            .join(",")
        : ""),
    DeviceDetail:
      s.deviceDetail &&
      [s.deviceDetail.browser, s.deviceDetail.operatingSystem, s.deviceDetail.displayName]
        .filter(Boolean)
        .join(" / "),
    CorrelationId: s.correlationId,
    Id: s.id,
  };
}

/** Client-side classifier kept for tests / hunting rows that carry clientAppUsed. */
function isLegacyClient(s) {
  const c = String((s && s.clientAppUsed) || "").trim().toLowerCase();
  return LEGACY_CLIENT_APPS.some((x) => x.toLowerCase() === c);
}

async function collectSignInAndAuditInsights(graph, io, findings, summary, opts = {}) {
  const windows = opts.windows || [30, 90];
  const schema = opts.schema || {
    canHunt: false,
    has: () => false,
    hasAny: () => false,
    capabilities: {},
  };
  const id = pickIdentityDialect(schema);
  const spnId = pickSpnDialect(schema);
  console.log(
    `── Sign-in / audit log insights (Graph + hunting dialect=${id.dialect || "none"}` +
      `${id.table ? ` table=${id.table}` : ""})`
  );

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

  // ── Device code sign-ins ──────────────────────────────────────────────
  //
  // `authenticationProtocol` is a beta-only property, so the filter is sent
  // to beta only. When Graph rejects it and no hunting table is available the
  // answer is *unknown* — a sample of the most recent sign-ins would just be a
  // confident-looking zero.
  for (const days of windows) {
    const since = isoDaysAgo(days);
    summary[`signInWindow${days}d`] = since;

    let deviceCode = await soft(
      `signIns_deviceCode_${days}d`,
      () =>
        getSignIns(graph, buildDeviceCodeFilter(since), {
          maxPages: 15,
          beta: "only",
        }),
      io
    );
    const graphDeviceCodeOk = Array.isArray(deviceCode);

    // Hunting has longer retention and richer fields — use it when Graph
    // failed, or when Graph returned nothing and hunting can confirm.
    if ((!graphDeviceCodeOk || !deviceCode.length) && id.dialect) {
      const huntRes = await hunt(
        `hunt_deviceCode_${days}d`,
        kqlDeviceCode(days, id.dialect)
      );
      if (huntRes && huntRes.results && huntRes.results.length) {
        const rows = huntRes.results.map((r) => ({
          Created: r.Timestamp,
          UPN: r.AccountUpn,
          App: r.Application,
          Resource: r.ResourceDisplayName,
          Ip: r.IPAddress,
          Location: [r.City, r.Country].filter(Boolean).join(", "),
          AuthProtocol: r.AuthenticationProtocol,
          ClientApp: r.ClientApp,
          ErrorCode: r.ErrorCode,
          Device: r.DeviceName,
          CorrelationId: r.CorrelationId,
          Source: `AdvancedHunting:${id.table}`,
        }));
        io.saveCsv(`20_DeviceCode_SignIns_${days}d.csv`, rows);
        const users = [...new Set(rows.map((x) => x.UPN).filter(Boolean))];
        summary[`deviceCodeSignIns${days}d`] = rows.length;
        summary[`deviceCodeUsers${days}d`] = users.length;
        io.saveCsv(
          `20_DeviceCode_Users_${days}d.csv`,
          users.map((u) => ({
            UPN: u,
            Events: rows.filter((r) => r.UPN === u).length,
            Apps: [
              ...new Set(rows.filter((r) => r.UPN === u).map((r) => r.App)),
            ].join(" | "),
          }))
        );
        pushFinding(
          findings,
          rows.length ? "High" : "Info",
          "DeviceCode",
          `${rows.length} device-code sign-in events / ${users.length} users in last ${days}d (hunting:${id.table}) — 20_DeviceCode_SignIns_${days}d.csv`
        );
        continue;
      }
    }

    if (!graphDeviceCodeOk) {
      // Neither Graph nor hunting could answer: record unknown, not zero.
      summary[`deviceCodeSignIns${days}d`] = null;
      summary[`deviceCodeUsers${days}d`] = null;
      summary[`deviceCodeSource${days}d`] = "unavailable";
      io.saveCsv(`20_DeviceCode_SignIns_${days}d.csv`, [], { status: STATUS.FAILED });
      pushFinding(
        findings,
        "Info",
        "DeviceCode",
        `Device-code usage in last ${days}d is unknown — Graph rejected the authenticationProtocol filter (beta) and no identity hunting table was available (see ERROR_signIns_deviceCode_${days}d.json)`
      );
      continue;
    }

    const rows = deviceCode.map((s) => ({
      ...mapSignInRow(s),
      Source: "Graph:auditLogs/signIns",
    }));
    const partial = !!deviceCode.truncated;
    io.saveCsv(`20_DeviceCode_SignIns_${days}d.csv`, rows, {
      status: partial ? STATUS.PARTIAL : undefined,
    });
    const users = [...new Set(rows.map((r) => r.UPN).filter(Boolean))];
    summary[`deviceCodeSignIns${days}d`] = rows.length;
    summary[`deviceCodeUsers${days}d`] = users.length;
    summary[`deviceCodeSource${days}d`] = partial ? "graph-partial" : "graph";
    if (users.length) {
      io.saveCsv(
        `20_DeviceCode_Users_${days}d.csv`,
        users.map((u) => ({
          UPN: u,
          Events: rows.filter((r) => r.UPN === u).length,
          Apps: [
            ...new Set(rows.filter((r) => r.UPN === u).map((r) => r.App)),
          ].join(" | "),
          Ips: [
            ...new Set(rows.filter((r) => r.UPN === u).map((r) => r.Ip)),
          ].join(" | "),
        }))
      );
    }
    pushFinding(
      findings,
      rows.length ? "High" : "Info",
      "DeviceCode",
      rows.length
        ? `${rows.length} device-code sign-ins / ${users.length} users in last ${days}d${truncNote(deviceCode)} — 20_DeviceCode_SignIns_${days}d.csv`
        : `No device-code sign-ins in last ${days}d (Graph beta filter, full window)`
    );
  }

  // ── Other high-value sign-in extractions (90d primary, 30d if 90 fails) ─
  const primaryDays = windows.includes(90) ? 90 : windows[windows.length - 1];
  const since = isoDaysAgo(primaryDays);

  // Legacy auth — filtered by Graph on clientAppUsed over the whole window.
  // (A recency sample of all sign-ins covered minutes on a busy tenant and
  // then reported "no legacy auth" for 90 days.)
  let legacy = await soft(
    `signIns_legacy_${primaryDays}d`,
    () =>
      getSignIns(graph, buildLegacyFilter(since), {
        top: 999,
        maxPages: 50,
        beta: "prefer",
      }),
    io
  );
  const legacyGraphOk = Array.isArray(legacy);
  const legacyTruncated = !!(legacy && legacy.truncated);
  /** @type {object[]} normalized event-ish rows for by-account digest */
  let legacyDigestSource = [];
  let legacySource = legacyGraphOk ? "graph" : "unavailable";
  if (!legacyGraphOk || !legacy.length) {
    const huntLegacy = await hunt(
      `hunt_legacy_${primaryDays}d`,
      kqlLegacySuccess(primaryDays, id.dialect)
    );
    if (huntLegacy && huntLegacy.results) {
      const huntRows = huntLegacy.results.map((r) => ({
        UPN: r.AccountUpn,
        ClientApp: r.ClientApp,
        SignIns: r.SignIns,
        Apps: Array.isArray(r.Apps) ? r.Apps.join(" | ") : r.Apps,
        Ips: Array.isArray(r.Ips) ? r.Ips.join(" | ") : r.Ips,
        Source: `AdvancedHunting:${id.table}`,
      }));
      io.saveCsv(`21_LegacyAuth_Success_${primaryDays}d.csv`, huntRows);
      summary[`legacyAuthUsers${primaryDays}d`] = huntRows.length;
      legacySource = `hunting:${id.table}`;
      // Expand hunt aggregates into digest-friendly pseudo-events.
      for (const r of huntRows) {
        const n = Math.max(1, Number(r.SignIns) || 1);
        legacyDigestSource.push({
          UPN: r.UPN,
          ClientApp: r.ClientApp,
          App: r.Apps,
          Ip: r.Ips,
          Events: n,
          ConditionalAccess: "",
          Created: "",
          Location: "",
        });
      }
      if (huntRows.length) {
        pushFinding(
          findings,
          "High",
          "LegacyAuth",
          `${huntRows.length} successful legacy-auth user/client combos in ${primaryDays}d — 21_LegacyAuth_Success_${primaryDays}d.csv`
        );
      }
    }
  } else {
    legacyDigestSource = legacy
      .filter((s) => !s.status || s.status.errorCode === 0)
      .map(mapSignInRow)
      .map((r) => ({ ...r, Events: 1 }));
    io.saveCsv(`21_LegacyAuth_Success_${primaryDays}d.csv`, legacyDigestSource, {
      status: legacyTruncated ? STATUS.PARTIAL : undefined,
    });
    summary[`legacyAuthEvents${primaryDays}d`] = legacyDigestSource.length;
    if (legacyTruncated) legacySource = "graph-partial";
    if (legacyDigestSource.length) {
      pushFinding(
        findings,
        "High",
        "LegacyAuth",
        `${legacyDigestSource.length} successful legacy-auth sign-ins in ${primaryDays}d${truncNote(legacy)} — 21_LegacyAuth_Success_${primaryDays}d.csv`
      );
    }
  }
  if (!legacyGraphOk && legacySource === "unavailable") {
    summary[`legacyAuthEvents${primaryDays}d`] = null;
    io.saveCsv(`21_LegacyAuth_Success_${primaryDays}d.csv`, [], { status: STATUS.FAILED });
    pushFinding(
      findings,
      "Info",
      "LegacyAuth",
      `Legacy-auth usage in ${primaryDays}d is unknown — sign-in logs not readable and no identity hunting table (see ERROR_signIns_legacy_${primaryDays}d.json)`
    );
  } else if (legacyGraphOk && !legacyDigestSource.length) {
    pushFinding(
      findings,
      "Info",
      "LegacyAuth",
      `No successful legacy-auth sign-ins in ${primaryDays}d (Graph filter on clientAppUsed, full window)`
    );
  }
  summary[`legacyAuthSource${primaryDays}d`] = legacySource;

  // Legacy auth digest by account (spot shared SMTP / service accounts).
  if (legacyDigestSource.length) {
    const byAcct = new Map();
    let totalEvents = 0;
    for (const r of legacyDigestSource) {
      const upn = String(r.UPN || "").toLowerCase() || "(unknown)";
      const add = Number(r.Events) || 1;
      totalEvents += add;
      let row = byAcct.get(upn);
      if (!row) {
        row = {
          UPN: r.UPN || upn,
          Events: 0,
          ClientApps: new Set(),
          Apps: new Set(),
          Ips: new Set(),
          Locations: new Set(),
          CaStatuses: new Set(),
          LastSeen: r.Created || "",
        };
        byAcct.set(upn, row);
      }
      row.Events += add;
      if (r.ClientApp) row.ClientApps.add(r.ClientApp);
      if (r.App) {
        for (const a of String(r.App).split(/\s*\|\s*/)) {
          if (a) row.Apps.add(a);
        }
      }
      if (r.Ip) {
        for (const ip of String(r.Ip).split(/\s*\|\s*/)) {
          if (ip) row.Ips.add(ip);
        }
      }
      if (r.Location) row.Locations.add(r.Location);
      if (r.ConditionalAccess) row.CaStatuses.add(r.ConditionalAccess);
      if (r.Created && (!row.LastSeen || r.Created > row.LastSeen)) {
        row.LastSeen = r.Created;
      }
    }
    const digest = [...byAcct.values()]
      .map((r) => ({
        UPN: r.UPN,
        Events: r.Events,
        ClientApps: [...r.ClientApps].join(" | "),
        Apps: [...r.Apps].join(" | "),
        DistinctIps: r.Ips.size,
        SampleIps: [...r.Ips].slice(0, 8).join(" | "),
        Locations: [...r.Locations].slice(0, 6).join(" | "),
        ConditionalAccess: [...r.CaStatuses].join(" | "),
        LastSeen: r.LastSeen,
      }))
      .sort((a, b) => b.Events - a.Events);
    io.saveCsv(`21_LegacyAuth_ByAccount_${primaryDays}d.csv`, digest);
    summary[`legacyAuthAccounts${primaryDays}d`] = digest.length;
    const top = digest[0];
    if (
      top &&
      top.Events >= 5 &&
      totalEvents > 0 &&
      top.Events / totalEvents >= 0.7
    ) {
      pushFinding(
        findings,
        "High",
        "LegacyAuth",
        `Legacy auth concentrated on ${top.UPN} (${top.Events}/${totalEvents} events, ${top.DistinctIps} IPs, CA=${top.ConditionalAccess || "?"}) — 21_LegacyAuth_ByAccount_${primaryDays}d.csv`
      );
    }
  }

  // Failed sign-ins (password spray / lockout signal)
  const huntFails = await hunt(
    `hunt_failures_${primaryDays}d`,
    kqlFailuresByIp(primaryDays, id.dialect)
  );
  let failRows = null;
  if (huntFails && huntFails.results && huntFails.results.length) {
    failRows = huntFails.results.map((r) => ({
      IP: r.IPAddress,
      Country: r.Country,
      ErrorCode: Array.isArray(r.ErrorCodes)
        ? r.ErrorCodes.join(" | ")
        : r.ErrorCode || r.ErrorCodes || "",
      Failures: r.Failures,
      Users: r.Users,
      SampleUsers: Array.isArray(r.SampleUsers)
        ? r.SampleUsers.join(" | ")
        : r.SampleUsers,
      Source: `AdvancedHunting:${id.table || "identity"}`,
    }));
  } else {
    // Graph fallback — IdentityLogon / AADSignIn often empty on MDE-light / identity-heavy tenants.
    const graphFails = await soft(
      `signIns_failures_${primaryDays}d`,
      () =>
        getSignIns(graph, buildFailureFilter(since), {
          top: 999,
          maxPages: 50,
          beta: "prefer",
        }),
      io
    );
    if (graphFails && graphFails.truncated) {
      summary[`failedSignInsPartial${primaryDays}d`] = true;
      pushFinding(
        findings,
        "Info",
        "Coverage",
        `Failed sign-in clustering is partial: page budget reached at the ${graphFails.length} most recent failures in ${primaryDays}d`
      );
    }
    if (Array.isArray(graphFails) && graphFails.length) {
      const byIp = new Map();
      for (const s of graphFails) {
        const ip = s.ipAddress || "(none)";
        let row = byIp.get(ip);
        if (!row) {
          row = {
            IP: ip,
            Country: (s.location && s.location.countryOrRegion) || "",
            ErrorCode: (s.status && s.status.errorCode) || "",
            Failures: 0,
            users: new Set(),
          };
          byIp.set(ip, row);
        }
        row.Failures++;
        if (s.userPrincipalName) row.users.add(s.userPrincipalName);
        if (s.status && s.status.errorCode != null) row.ErrorCode = s.status.errorCode;
      }
      failRows = [...byIp.values()]
        .map((r) => ({
          IP: r.IP,
          Country: r.Country,
          ErrorCode: r.ErrorCode,
          Failures: r.Failures,
          Users: r.users.size,
          SampleUsers: [...r.users].slice(0, 6).join(" | "),
          Source: "Graph.signIns",
        }))
        .sort((a, b) => b.Failures - a.Failures)
        .slice(0, 200);
    }
  }
  if (failRows && failRows.length) {
    failRows = aggregateFailuresByIp(failRows);
    io.saveCsv(`22_FailedSignIns_ByIP_${primaryDays}d.csv`, failRows);
    summary[`failedSignInIpClusters${primaryDays}d`] = failRows.length;
    const hot = failRows.filter((r) => Number(r.Failures) >= 50);
    if (hot.length) {
      pushFinding(
        findings,
        "Medium",
        "FailedSignIns",
        `${hot.length} IP(s) with ≥50 failures in ${primaryDays}d — 22_FailedSignIns_ByIP_${primaryDays}d.csv`
      );
    }
  } else if (!id.dialect) {
    summary[`failedSignInIpClusters${primaryDays}d`] = "skipped_no_identity_hunt_table";
  }

  // Single-factor / no MFA success (interactive)
  const huntNoMfa = await hunt(
    `hunt_singleFactor_${primaryDays}d`,
    kqlSingleFactor(primaryDays, id.dialect)
  );
  if (huntNoMfa && huntNoMfa.results) {
    io.saveCsv(
      `23_SingleFactor_Success_${primaryDays}d.csv`,
      huntNoMfa.results.map((r) => ({
        UPN: r.AccountUpn,
        SignIns: r.SignIns,
        Apps: Array.isArray(r.Apps) ? r.Apps.join(" | ") : r.Apps,
        Countries: Array.isArray(r.Countries)
          ? r.Countries.join(" | ")
          : r.Countries,
      }))
    );
    summary[`singleFactorUsers${primaryDays}d`] = huntNoMfa.results.length;
    const humanish = huntNoMfa.results.filter((r) => {
      const upn = r.AccountUpn || "";
      return classifyAccountKind(upn) === "human";
    });
    if (humanish.length) {
      pushFinding(
        findings,
        "Medium",
        "SingleFactor",
        `${humanish.length} interactive-looking account(s) with successful non-MFA sign-ins` +
          (humanish.length < huntNoMfa.results.length
            ? ` (${huntNoMfa.results.length - humanish.length} rooms/agents/service filtered)`
            : "") +
          ` — 23_SingleFactor_Success_${primaryDays}d.csv`
      );
    } else if (huntNoMfa.results.length) {
      pushFinding(
        findings,
        "Info",
        "SingleFactor",
        `${huntNoMfa.results.length} non-MFA success row(s) are rooms, Copilot agents or service accounts — not a human password-only path — 23_SingleFactor_Success_${primaryDays}d.csv`
      );
    }
  }

  // Risky sign-ins
  const riskyUsers = await soft(
    "riskyUsers",
    () =>
      graph.getAll(
        `${graph.GRAPH}/identityProtection/riskyUsers?$filter=riskState eq 'atRisk' or riskState eq 'confirmedCompromised'`
      ),
    io
  );
  if (riskyUsers) {
    io.saveCsv(
      "24_RiskyUsers.csv",
      riskyUsers.map((u) => ({
        UPN: u.userPrincipalName,
        Name: u.userDisplayName,
        RiskState: u.riskState,
        RiskLevel: u.riskLevel,
        RiskDetail: u.riskDetail,
        LastUpdated: u.riskLastUpdatedDateTime,
      }))
    );
    summary.riskyUsersAtRisk = riskyUsers.length;
    if (riskyUsers.length) {
      pushFinding(
        findings,
        "High",
        "IdentityProtection",
        `${riskyUsers.length} users atRisk/confirmedCompromised — 24_RiskyUsers.csv`
      );
    }
  }

  // Risk detections (detail behind "hidden" riskLevel when AIP licensed).
  const riskDetSince = isoDaysAgo(90);
  const riskDetections = await soft(
    "riskDetections",
    async () => {
      const urls = [
        `${graph.GRAPH}/identityProtection/riskDetections` +
          `?$filter=detectedDateTime%20ge%20${encodeURIComponent(riskDetSince)}&$top=100`,
        `${graph.GRAPH}/identityProtection/riskDetections?$top=100`,
      ];
      let lastErr;
      for (const url of urls) {
        try {
          return await graph.getAll(url);
        } catch (e) {
          lastErr = e;
          if (e.status !== 400) throw e;
        }
      }
      throw lastErr;
    },
    io
  );
  if (Array.isArray(riskDetections)) {
    const cutoff = Date.parse(riskDetSince);
    const inWindow = riskDetections.filter((d) => {
      const t = Date.parse(d.detectedDateTime || "");
      return !Number.isFinite(cutoff) || !Number.isFinite(t) || t >= cutoff;
    });
    io.saveCsv(
      "24_RiskDetections_90d.csv",
      inWindow.map((d) => ({
        Detected: d.detectedDateTime,
        UPN: d.userPrincipalName,
        RiskEventType: d.riskEventType,
        RiskState: d.riskState,
        RiskLevel: d.riskLevel,
        RiskDetail: d.riskDetail,
        Ip: d.ipAddress,
        Location:
          d.location &&
          [d.location.city, d.location.state, d.location.countryOrRegion]
            .filter(Boolean)
            .join(", "),
        Source: d.source || d.detectionTimingType || "",
        Activity: d.activity || "",
        TokenIssuerType: d.tokenIssuerType || "",
        RequestId: d.requestId || d.id || "",
      }))
    );
    summary.riskDetections90d = inWindow.length;
    if (inWindow.length) {
      const types = [
        ...new Set(inWindow.map((d) => d.riskEventType).filter(Boolean)),
      ];
      pushFinding(
        findings,
        "Medium",
        "IdentityProtection",
        `${inWindow.length} risk detection(s) in 90d` +
          (types.length ? ` (types: ${types.slice(0, 6).join(", ")})` : "") +
          ` — 24_RiskDetections_90d.csv`
      );
    }
  }

  // Audit: role / app consent / forwarding-ish
  //
  // directoryAudits is picky: combining $filter with $orderby is rejected on
  // some tenants, and the window cannot exceed the audit retention (30 days on
  // P1/P2, 7 on free). Walk down to progressively simpler queries rather than
  // losing the whole artifact to one 400.
  const auditVariants = [
    { days: primaryDays, orderBy: true },
    { days: primaryDays, orderBy: false },
    { days: Math.min(primaryDays, 30), orderBy: false },
    { days: 7, orderBy: false },
  ];
  const auditUrl = ({ days, orderBy }) =>
    `${graph.GRAPH}/auditLogs/directoryAudits` +
    `?$filter=activityDateTime%20ge%20${encodeURIComponent(isoDaysAgo(days))}&$top=100` +
    (orderBy ? "&$orderby=activityDateTime%20desc" : "");

  let auditWindowDays = primaryDays;
  const auditInteresting = await soft(
    `auditLogs_${primaryDays}d`,
    async () => {
      let lastErr;
      for (const variant of auditVariants) {
        try {
          const rows = await graph.getAll(auditUrl(variant));
          auditWindowDays = variant.days;
          return rows;
        } catch (e) {
          lastErr = e;
          // Only a rejected query shape or window is worth simplifying;
          // anything else (403, network) is reported as-is.
          if (e.status !== 400) throw e;
        }
      }
      throw lastErr;
    },
    io
  );
  if (auditInteresting && auditWindowDays !== primaryDays) {
    console.log(
      `  · directoryAudits limited to ${auditWindowDays}d (tenant audit retention)`
    );
    summary.auditLogWindowDays = auditWindowDays;
  }

  // Auth method registration / SSPR reset activities (RegistrationAndResetLogs blade).
  if (Array.isArray(auditInteresting) && auditInteresting.length) {
    const regReset = auditInteresting.filter((a) => {
      const name = String(a.activityDisplayName || "");
      const cat = String(
        (Array.isArray(a.category) ? a.category.join(" ") : a.category) || ""
      );
      return /regist|security info|reset password|password reset|authentication method|sspr|strong authentication/i.test(
        `${name} ${cat}`
      );
    });
    if (regReset.length) {
      io.saveCsv(
        `13_Registration_And_Reset_Logs_${Math.min(auditWindowDays, primaryDays)}d.csv`,
        regReset.slice(0, 500).map((a) => ({
          Time: a.activityDateTime,
          Activity: a.activityDisplayName,
          Category: Array.isArray(a.category)
            ? a.category.join(" | ")
            : a.category || "",
          Result: a.result,
          InitiatedBy:
            (a.initiatedBy &&
              a.initiatedBy.user &&
              a.initiatedBy.user.userPrincipalName) ||
            (a.initiatedBy &&
              a.initiatedBy.app &&
              a.initiatedBy.app.displayName) ||
            "",
          Target: (a.targetResources || [])
            .map((t) => t.userPrincipalName || t.displayName)
            .filter(Boolean)
            .join(" | "),
        }))
      );
      summary.registrationResetLogRows = regReset.length;
      pushFinding(
        findings,
        "Info",
        "RegistrationLogs",
        `${regReset.length} registration/reset audit event(s) in directoryAudits sample — 13_Registration_And_Reset_Logs_${Math.min(auditWindowDays, primaryDays)}d.csv`
      );
    }
  }

  let huntAudit = null;
  if (schema.canHunt && schema.has("CloudAppEvents")) {
    huntAudit = await hunt(
      `hunt_audit_highvalue_${primaryDays}d`,
      `
CloudAppEvents
| where Timestamp > ago(${primaryDays}d)
| where ActionType has_any ("Add member to role", "Add eligible member to role", "Consent to application", "Add app role assignment", "Update application", "Set-Mailbox", "Add service principal credentials", "Add owner to application")
| project Timestamp, ActionType, AccountUpn=AccountDisplayName, ActorIP=IPAddress, Raw=RawEventData
| top 300 by Timestamp desc
`.trim()
    );
  } else if (schema.canHunt && schema.has("AuditLogs")) {
    huntAudit = await hunt(
      `hunt_audit_highvalue_law_${primaryDays}d`,
      `
AuditLogs
| where TimeGenerated > ago(${primaryDays}d)
| where OperationName has_any ("Add member to role", "Add eligible member to role", "Consent to application", "Add app role assignment to service principal", "Update application", "Add service principal credentials", "Add owner to application")
| project Timestamp=TimeGenerated, ActionType=OperationName, AccountUpn=Identity, ActorIP="", Raw=""
| top 300 by Timestamp desc
`.trim()
    );
  }

  if (huntAudit && huntAudit.results) {
    io.saveCsv(
      `25_HighValue_CloudAppEvents_${primaryDays}d.csv`,
      huntAudit.results.map((r) => ({
        Timestamp: r.Timestamp,
        ActionType: r.ActionType,
        Account: r.AccountUpn,
        IP: r.ActorIP,
      }))
    );
    summary[`highValueCloudEvents${primaryDays}d`] = huntAudit.results.length;
    if (huntAudit.results.length) {
      pushFinding(
        findings,
        "Info",
        "Audit",
        `${huntAudit.results.length} high-value CloudAppEvents in ${primaryDays}d — 25_HighValue_CloudAppEvents_${primaryDays}d.csv`
      );
    }
  } else if (auditInteresting && auditInteresting.length) {
    const interesting = auditInteresting.filter((a) =>
      /role|consent|application|forward|credential|servicePrincipal/i.test(
        a.activityDisplayName || ""
      )
    );
    io.saveCsv(
      `25_DirectoryAudits_Interesting_${primaryDays}d.csv`,
      interesting.map((a) => ({
        Time: a.activityDateTime,
        Activity: a.activityDisplayName,
        Result: a.result,
        InitiatedBy:
          (a.initiatedBy &&
            a.initiatedBy.user &&
            a.initiatedBy.user.userPrincipalName) ||
          (a.initiatedBy &&
            a.initiatedBy.app &&
            a.initiatedBy.app.displayName) ||
          "",
        Target: (a.targetResources || [])
          .map((t) => t.displayName || t.userPrincipalName)
          .join(" | "),
      }))
    );
  }

  // Tooling / unusual apps often used in attacks
  const huntTools = await hunt(
    `hunt_tooling_${primaryDays}d`,
    kqlAdminTooling(primaryDays, id.dialect)
  );
  if (huntTools && huntTools.results) {
    io.saveCsv(
      `26_AdminTooling_SignIns_${primaryDays}d.csv`,
      huntTools.results.map((r) => ({
        Application: r.Application,
        SignIns: r.SignIns,
        Users: Array.isArray(r.Users) ? r.Users.join(" | ") : r.Users,
        Ips: Array.isArray(r.Ips) ? r.Ips.join(" | ") : r.Ips,
      }))
    );
    summary[`adminToolingApps${primaryDays}d`] = huntTools.results.length;
    pushFinding(
      findings,
      "Info",
      "AdminTooling",
      `${huntTools.results.length} admin/scripting app families seen in sign-ins — 26_AdminTooling_SignIns_${primaryDays}d.csv`
    );
  }

  // CA blocked device code specifically (proves control effectiveness)
  const huntCaBlockDevice = await hunt(
    `hunt_ca_block_devicecode_${primaryDays}d`,
    kqlDeviceCodeBlocked(primaryDays, id.dialect)
  );
  if (huntCaBlockDevice && huntCaBlockDevice.results) {
    io.saveCsv(
      `20_DeviceCode_Blocked_${primaryDays}d.csv`,
      huntCaBlockDevice.results.map((r) => ({
        ErrorCode: r.ErrorCode,
        Application: r.Application,
        Blocked: r.Blocked,
        Users: r.Users,
      }))
    );
  }

  // ── Privileged / dangerous SPN sign-ins (credential use evidence) ─────
  {
    const dangerousSpns = opts.dangerousSpns || [];
    const critIds = [
      ...new Set(
        dangerousSpns
          .filter((r) => /Critical|High/i.test(r.Severity || ""))
          .map((r) => r.PrincipalId)
          .filter(Boolean)
      ),
    ].slice(0, 25);
    const since = isoDaysAgo(primaryDays);
    const spnRows = [];

    // Broad service-principal sign-ins (beta)
    const spnSignIns = await soft(
      `signIns_servicePrincipal_${primaryDays}d`,
      () =>
        getSignIns(
          graph,
          `createdDateTime ge ${since} and signInEventTypes/any(t:t eq 'servicePrincipal')`,
          { maxPages: 10, top: 200 }
        ),
      io
    );
    if (Array.isArray(spnSignIns)) {
      for (const s of spnSignIns) {
        spnRows.push({
          Created: s.createdDateTime,
          App: s.appDisplayName,
          AppId: s.appId,
          ServicePrincipalId: s.servicePrincipalId,
          Resource: s.resourceDisplayName,
          IP: s.ipAddress,
          Status: (s.status && s.status.errorCode) || 0,
          Location:
            s.location &&
            [s.location.city, s.location.state, s.location.countryOrRegion]
              .filter(Boolean)
              .join(", "),
          Source: "Graph.signInEventTypes=servicePrincipal",
        });
      }
    }

    // Focused pulls for Critical/High SPNs (when broad filter empty / capped)
    for (const pid of critIds.slice(0, 12)) {
      const focused = await soft(
        `signIns_spn_${pid.slice(0, 8)}`,
        () =>
          getSignIns(
            graph,
            `createdDateTime ge ${since} and servicePrincipalId eq '${pid}'`,
            { maxPages: 3, top: 50 }
          ),
        io
      );
      if (!Array.isArray(focused) || !focused.length) continue;
      for (const s of focused) {
        spnRows.push({
          Created: s.createdDateTime,
          App: s.appDisplayName,
          AppId: s.appId,
          ServicePrincipalId: s.servicePrincipalId || pid,
          Resource: s.resourceDisplayName,
          IP: s.ipAddress,
          Status: (s.status && s.status.errorCode) || 0,
          Location:
            s.location &&
            [s.location.city, s.location.state, s.location.countryOrRegion]
              .filter(Boolean)
              .join(", "),
          Source: "Graph.servicePrincipalId",
        });
      }
    }

    if (schema.canHunt && spnId.table) {
      const huntSpn = await hunt(
        `hunt_spnSignIns_${primaryDays}d`,
        kqlSpnSignIns(primaryDays, spnId)
      );
      if (huntSpn && Array.isArray(huntSpn.results)) {
        for (const r of huntSpn.results) {
          spnRows.push({
            Created: r.Timestamp,
            App: r.App || r.ServicePrincipalName,
            AppId: r.AppId || r.ApplicationId,
            ServicePrincipalId: r.ServicePrincipalId,
            Resource: r.Resource || r.ResourceDisplayName,
            IP: r.IP || r.IPAddress,
            Status: r.Status != null ? r.Status : r.ErrorCode,
            Location: r.Location || [r.City, r.Country].filter(Boolean).join(", "),
            Source: `AdvancedHunting:${spnId.table}`,
          });
        }
      }
    }

    // Dedup by Created+AppId+IP
    const seen = new Set();
    const deduped = [];
    for (const r of spnRows) {
      const k = `${r.Created}|${r.AppId}|${r.IP}|${r.ServicePrincipalId}`;
      if (seen.has(k)) continue;
      seen.add(k);
      deduped.push(r);
    }
    deduped.sort((a, b) => String(b.Created).localeCompare(String(a.Created)));

    if (deduped.length) {
      io.saveCsv(`27_SPN_SignIns_${primaryDays}d.csv`, deduped.slice(0, 500));
      summary[`spnSignIns${primaryDays}d`] = deduped.length;
      const critHit = deduped.filter((r) =>
        critIds.includes(r.ServicePrincipalId)
      ).length;
      pushFinding(
        findings,
        critHit ? "Medium" : "Info",
        "SpnSignIns",
        `${deduped.length} service-principal sign-in(s) in ${primaryDays}d` +
          (critHit ? ` (${critHit} from Critical/High permission SPNs)` : "") +
          ` — 27_SPN_SignIns_${primaryDays}d.csv`
      );

      // Digest Critical/High SPN activity (path-to-GA apps in use).
      const bySpn = new Map();
      for (const r of deduped) {
        if (critIds.length && !critIds.includes(r.ServicePrincipalId)) continue;
        const key = r.ServicePrincipalId || r.AppId || r.App || "?";
        let row = bySpn.get(key);
        if (!row) {
          row = {
            ServicePrincipalId: r.ServicePrincipalId || "",
            App: r.App || "",
            AppId: r.AppId || "",
            Events: 0,
            Ips: new Set(),
            Resources: new Set(),
            LastSeen: r.Created || "",
          };
          bySpn.set(key, row);
        }
        row.Events++;
        if (r.IP) row.Ips.add(r.IP);
        if (r.Resource) row.Resources.add(r.Resource);
        if (r.Created && (!row.LastSeen || r.Created > row.LastSeen)) {
          row.LastSeen = r.Created;
        }
      }
      // If no crit filter matched, digest top apps by volume instead.
      if (!bySpn.size) {
        for (const r of deduped) {
          const key = r.ServicePrincipalId || r.AppId || r.App || "?";
          let row = bySpn.get(key);
          if (!row) {
            row = {
              ServicePrincipalId: r.ServicePrincipalId || "",
              App: r.App || "",
              AppId: r.AppId || "",
              Events: 0,
              Ips: new Set(),
              Resources: new Set(),
              LastSeen: r.Created || "",
            };
            bySpn.set(key, row);
          }
          row.Events++;
          if (r.IP) row.Ips.add(r.IP);
          if (r.Resource) row.Resources.add(r.Resource);
          if (r.Created && (!row.LastSeen || r.Created > row.LastSeen)) {
            row.LastSeen = r.Created;
          }
        }
      }
      const digest = [...bySpn.values()]
        .map((r) => ({
          ServicePrincipalId: r.ServicePrincipalId,
          App: r.App,
          AppId: r.AppId,
          Events: r.Events,
          DistinctIps: r.Ips.size,
          SampleIps: [...r.Ips].slice(0, 6).join(" | "),
          Resources: [...r.Resources].slice(0, 6).join(" | "),
          LastSeen: r.LastSeen,
          HighPrivSpn: critIds.includes(r.ServicePrincipalId) ? "yes" : "no",
        }))
        .sort((a, b) => b.Events - a.Events)
        .slice(0, 50);
      if (digest.length) {
        io.saveCsv(`27_SPN_SignIns_Digest_${primaryDays}d.csv`, digest);
        summary[`spnSignInDigest${primaryDays}d`] = digest.length;
      }
    }
  }

  // Privileged user interactive sign-ins (Graph — works when IdentityLogon is empty).
  // Keep this short: N sequential Graph filters look "stuck" with no console output.
  {
    // privilegedAccounts rows are per-assignment (RoleName + UPNOrAppId).
    const byUpn = new Map();
    for (const r of opts.privilegedAccounts || []) {
      const upn = String(r.UPNOrAppId || r.UPN || r.UserPrincipalName || "")
        .trim()
        .toLowerCase();
      if (!upn.includes("@") || /^sync_/i.test(upn.split("@")[0])) continue;
      let row = byUpn.get(upn);
      if (!row) {
        row = { upn, roles: [], enabled: true };
        byUpn.set(upn, row);
      }
      if (r.RoleName) row.roles.push(String(r.RoleName));
      if (/false|no|0/i.test(String(r.Enabled ?? r.AccountEnabled ?? "true"))) {
        row.enabled = false;
      }
    }
    const privCandidates = [...byUpn.values()];
    // Prefer Global Admins, then anyone else — max 6 human/admin UPNs.
    const gaFirst = [
      ...privCandidates.filter(
        (r) => r.enabled && r.roles.some((x) => /global\s*admin/i.test(x))
      ),
      ...privCandidates.filter(
        (r) => r.enabled && !r.roles.some((x) => /global\s*admin/i.test(x))
      ),
      ...privCandidates.filter((r) => !r.enabled),
    ];
    const seenUpn = new Set();
    const privUpns = [];
    for (const r of gaFirst) {
      if (seenUpn.has(r.upn)) continue;
      seenUpn.add(r.upn);
      privUpns.push(r.upn);
      if (privUpns.length >= 6) break;
    }
    const since30 = isoDaysAgo(Math.min(primaryDays, 30));
    const privSignInRows = [];
    if (privUpns.length) {
      console.log(
        `  · Privileged Graph sign-ins: ${privUpns.length} UPN(s) (max 1 page each)…`
      );
    }
    const t0 = Date.now();
    const budgetMs = 90_000;
    for (let i = 0; i < privUpns.length; i++) {
      if (Date.now() - t0 > budgetMs) {
        console.log(
          `  · Privileged sign-ins: time budget reached after ${i}/${privUpns.length} — continuing`
        );
        break;
      }
      const upn = privUpns[i];
      process.stdout.write(`  · [${i + 1}/${privUpns.length}] ${upn}… `);
      const safe = upn.replace(/'/g, "''");
      const rows = await soft(
        `signIns_priv_${upn.slice(0, 24)}`,
        () =>
          getSignIns(
            graph,
            `createdDateTime ge ${since30} and userPrincipalName eq '${safe}'`,
            { maxPages: 1, top: 40 }
          ),
        io,
        { retries: 0 }
      );
      const ok = Array.isArray(rows) ? rows.length : 0;
      console.log(ok ? `${ok} events` : "none");
      if (!ok) continue;
      for (const s of rows) {
        if (s.status && s.status.errorCode && s.status.errorCode !== 0) continue;
        privSignInRows.push({
          ...mapSignInRow(s),
          Source: "Graph.privilegedUpn",
        });
      }
    }
    if (privSignInRows.length) {
      privSignInRows.sort((a, b) =>
        String(b.Created || "").localeCompare(String(a.Created || ""))
      );
      io.saveCsv(
        "28_Privileged_SignIns_30d.csv",
        privSignInRows.slice(0, 400)
      );
      const byUser = new Map();
      for (const r of privSignInRows) {
        const u = String(r.UPN || "").toLowerCase();
        byUser.set(u, (byUser.get(u) || 0) + 1);
      }
      summary.privilegedSignInEvents30d = privSignInRows.length;
      summary.privilegedSignInUsers30d = byUser.size;
      pushFinding(
        findings,
        "Info",
        "PrivilegedSignIns",
        `${privSignInRows.length} successful sign-in(s) for ${byUser.size} privileged UPN(s) in 30d — 28_Privileged_SignIns_30d.csv`
      );
    }
  }

  summary.signInInsightsCollected = true;
  summary.signInHuntDialect = id.dialect;
  summary.signInHuntTable = id.table || null;
  summary.spnHuntTable = spnId.table || null;
}

module.exports = {
  collectSignInAndAuditInsights,
  getSignIns,
  buildLegacyFilter,
  buildFailureFilter,
  buildDeviceCodeFilter,
  isLegacyClient,
  LEGACY_CLIENT_APPS,
};
