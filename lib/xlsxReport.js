/**
 * Remediation-oriented Excel workbook from a report payload.
 * Works in Node (write file) and in the browser (button next to PDF).
 * Uses ExcelJS so fills / fonts / freeze panes survive in the .xlsx.
 *
 * Sheets:
 *   Cover              — scores, KPIs, how to use
 *   Steering Board     — priority buckets + This Week focus + ritual
 *   This Week          — Now items only (kickoff / standup)
 *   Remediation Plan   — full backlog (Do this / Owner / Status / Due)
 *   Expert Findings    — full NARR.* detail
 *   Attack Path Gaps   — checklist Fail/Partial
 *   Secure Score       — Track D; Identity/Apps first, Device capped
 *   Inventory Hot      — High/Critical/Medium inventory (reference)
 *   Limitations        — access / schema gaps
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.EntraXlsxReport = factory();
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  /* ── palette (aligned with HTML report) ── */
  const C = {
    ink: "FF0A0F1A",
    ink2: "FF0F1623",
    surface: "FF141C2B",
    border: "FF243044",
    muted: "FF8B9BB4",
    text: "FFE8EEF7",
    accent: "FF2DD4BF",
    accentDim: "FF14B8A6",
    white: "FFFFFFFF",
    paper: "FFFFFFFF",
    zebra: "FFF4F7FB",
    soft: "FFEEF2F7",
    fillMe: "FFFFF8E7",
    line: "FFD0D7E2",
    criticalBg: "FFFEE2E2",
    criticalFg: "FF991B1B",
    highBg: "FFFFEDD5",
    highFg: "FF9A3412",
    mediumBg: "FFFEF3C7",
    mediumFg: "FF92400E",
    lowBg: "FFDBEAFE",
    lowFg: "FF1E40AF",
    infoBg: "FFF1F5F9",
    infoFg: "FF334155",
    nowBg: "FFFEE2E2",
    nowFg: "FF991B1B",
    nextBg: "FFFFEDD5",
    nextFg: "FF9A3412",
    laterBg: "FFE0F2FE",
    laterFg: "FF075985",
    passBg: "FFDCFCE7",
    passFg: "FF166534",
    failBg: "FFFEE2E2",
    failFg: "FF991B1B",
    partialBg: "FFFEF3C7",
    partialFg: "FF92400E",
    sectionBg: "FFE6FFFA",
    sectionFg: "FF0F766E",
    titleBg: "FF0F1623",
    titleFg: "FF2DD4BF",
  };

  const STATUS_OPTIONS = '"Open,In progress,Blocked,Risk accepted,Done"';
  const EFFORT_OPTIONS = '"S,M,L"';

  function s(v) {
    if (v == null) return "";
    if (Array.isArray(v)) return v.join(" | ");
    return String(v);
  }

  function clip(v, n) {
    const t = s(v).replace(/\s+/g, " ").trim();
    if (t.length <= n) return t;
    return t.slice(0, n - 1) + "…";
  }

  function prioRank(p) {
    const n = { Now: 0, Next: 1, Later: 2 }[p];
    return n == null ? 3 : n;
  }
  function sevRank(sev) {
    const n = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 }[sev];
    return n == null ? 9 : n;
  }

  function deepDive(id) {
    const x = String(id || "");
    if (/^NARR\.(App|Consent)\./i.test(x)) return "Apps";
    if (/^NARR\.Priv\./i.test(x)) return "Privileged";
    if (/^NARR\.CA\./i.test(x)) return "Conditional Access";
    if (/^NARR\.(MFA|Identity|Guest)\./i.test(x)) return "Users & MFA";
    if (/^NARR\.(DeviceCode|Legacy|Risk|Auth)\./i.test(x)) return "Sign-in signals";
    if (/^NARR\.(Devices|Endpoint)\./i.test(x)) return "Devices / Endpoints";
    if (/^NARR\.(Mail|Cloud)\./i.test(x)) return "Mail & collab";
    if (/^NARR\.SecureScore\./i.test(x)) return "Secure Score";
    return "General";
  }

  function trackHint(priority, severity) {
    if (priority === "Now" || severity === "Critical") return "Track A — Stop the bleeding";
    if (priority === "Next" || severity === "High") return "Track B — Close attack paths";
    if (severity === "Medium") return "Track C — Harden & hygiene";
    return "Track D — Backlog / adoption";
  }

  function waveFor(priority) {
    if (priority === "Now") return "Wave 1";
    if (priority === "Next") return "Wave 2";
    return "Wave 3";
  }

  /** First concrete step from remediation text (tenant-agnostic). */
  function firstAction(text) {
    const t = String(text || "")
      .replace(/\r\n/g, "\n")
      .replace(/\s+/g, " ")
      .trim();
    if (!t) return "";
    const numbered = t.match(/(?:^|\s)1[.)]\s+(.+?)(?=\s+2[.)]\s+|$)/i);
    if (numbered && numbered[1]) return clip(numbered[1].trim(), 220);
    const bullet = t.match(/^[•\-*]\s*(.+?)(?:\s+[•\-*]\s+|$)/);
    if (bullet && bullet[1]) return clip(bullet[1].trim(), 220);
    const sent = t.match(/^(.+?[.!?])(?:\s|$)/);
    if (sent && sent[1] && sent[1].length >= 24) return clip(sent[1].trim(), 220);
    return clip(t, 220);
  }

  /**
   * Suggested owner *role* (not a person) — works across tenants.
   * Derived from finding id / deep-dive area only.
   */
  function suggestedOwner(n) {
    const blob = `${n.Id || ""} ${deepDive(n.Id)} ${n.Title || ""}`.toLowerCase();
    if (
      /rolemanagement|directory.?role|pim|guest.?admin|approle|service.?principal|consent|app.?reg|^narr\.app\.|^narr\.priv\./.test(
        blob
      )
    ) {
      return "Identity / IAM";
    }
    if (
      /conditional.?access|\bca\.|auth\.|mfa|signin|authentication|passwordless|^narr\.ca\./.test(
        blob
      )
    ) {
      return "Identity / Conditional Access";
    }
    if (
      /endpoint|device|tvm|rmm|defender|intune|patch|vulnerability|win10|bitlocker|^narr\.(devices|endpoint)\./.test(
        blob
      )
    ) {
      return "Endpoint / Intune";
    }
    if (
      /sharepoint|onedrive|teams|exchange|collab|dlp|external.?sharing|^narr\.(mail|cloud)\./.test(
        blob
      )
    ) {
      return "Collaboration / M365";
    }
    if (/attack.?path|graph|privilege.?escalation/.test(blob)) {
      return "Identity / IAM";
    }
    if (/secure.?score|compliance|grc/.test(blob)) {
      return "Security / GRC";
    }
    if (/failed.?sign|risky|threat|soc|incident|^narr\.(risk|devicecode|legacy)\./.test(blob)) {
      return "SOC / Identity";
    }
    return "Security / IT ops";
  }

  function ssCategoryRank(cat) {
    const c = String(cat || "").toLowerCase();
    if (/identity/.test(c)) return 0;
    if (/apps|data|office|exchange|sharepoint|teams/.test(c)) return 1;
    if (/device/.test(c)) return 2;
    return 3;
  }

  /** Prefer Identity/Apps/Data; keep only top Device controls by gain. */
  function selectSecureScoreRows(rows) {
    const open = [...(rows || [])];
    open.sort(
      (a, b) =>
        ssCategoryRank(a.Category || a.Service) -
          ssCategoryRank(b.Category || b.Service) ||
        Number(b.Gain || 0) - Number(a.Gain || 0) ||
        String(a.Title || "").localeCompare(String(b.Title || ""))
    );
    const kept = [];
    let deviceKept = 0;
    for (const r of open) {
      const isDevice = /device/i.test(r.Category || r.Service || "");
      if (isDevice) {
        if (deviceKept >= 12) continue;
        deviceKept++;
      }
      kept.push(r);
    }
    return kept;
  }

  function apDoThis(r, narratives) {
    const existing = String(r.Remediation || r.Detail || r.Note || "").trim();
    if (existing) return firstAction(existing) || clip(existing, 280);
    const check = String(r.CheckId || r.Id || r.Title || "");
    const hit = (narratives || []).find((n) => {
      const blob = `${n.Id || ""} ${n.Title || ""} ${n.RelatedChecks || ""}`.toLowerCase();
      return check && blob.includes(check.toLowerCase());
    });
    if (hit) return firstAction(hit.Remediation) || clip(hit.Remediation, 280);
    if (/fail/i.test(r.Status)) {
      return "Close the standing privilege / assignment path in Evidence; prefer PIM eligible over permanent.";
    }
    if (/partial/i.test(r.Status)) {
      return "Review Evidence; reduce standing access or tighten CA / ownership.";
    }
    return "";
  }

  function orgName(D) {
    const S = D.summary || {};
    return (
      S.tenantDisplayName ||
      S.organizationDisplayName ||
      S.defaultDomain ||
      (D.meta && D.meta.outputDir) ||
      "Tenant"
    );
  }

  function argb(hex) {
    return { argb: hex };
  }

  function fillSolid(hex) {
    return { type: "pattern", pattern: "solid", fgColor: argb(hex) };
  }

  function thinBorder() {
    const edge = { style: "thin", color: argb(C.line) };
    return { top: edge, left: edge, bottom: edge, right: edge };
  }

  function sevStyle(sev) {
    const k = String(sev || "").toLowerCase();
    if (k === "critical") return { bg: C.criticalBg, fg: C.criticalFg };
    if (k === "high") return { bg: C.highBg, fg: C.highFg };
    if (k === "medium") return { bg: C.mediumBg, fg: C.mediumFg };
    if (k === "low") return { bg: C.lowBg, fg: C.lowFg };
    if (k === "info") return { bg: C.infoBg, fg: C.infoFg };
    return null;
  }

  function prioStyle(p) {
    const k = String(p || "");
    if (k === "Now") return { bg: C.nowBg, fg: C.nowFg };
    if (k === "Next") return { bg: C.nextBg, fg: C.nextFg };
    if (k === "Later") return { bg: C.laterBg, fg: C.laterFg };
    return null;
  }

  function statusStyle(st) {
    const k = String(st || "").toLowerCase();
    if (/^fail/.test(k)) return { bg: C.failBg, fg: C.failFg };
    if (/partial/.test(k)) return { bg: C.partialBg, fg: C.partialFg };
    if (/^pass|^ok|^done/.test(k)) return { bg: C.passBg, fg: C.passFg };
    return null;
  }

  function applyBadge(cell, style) {
    if (!style) return;
    cell.fill = fillSolid(style.bg);
    cell.font = Object.assign({}, cell.font || {}, {
      bold: true,
      color: argb(style.fg),
      size: 10,
      name: "Calibri",
    });
    cell.alignment = Object.assign({}, cell.alignment || {}, {
      horizontal: "center",
      vertical: "middle",
    });
  }

  function buildSheets(D) {
    const S = D.summary || {};
    const meta = D.meta || {};
    const narratives = (D.narratives || []).slice().sort((a, b) => {
      const pd = prioRank(a.Priority) - prioRank(b.Priority);
      if (pd) return pd;
      return sevRank(a.Severity) - sevRank(b.Severity);
    });
    const CS = D.checklistStats || {};
    const gaps = (D.attackChecklist || []).filter((r) =>
      /fail|partial/i.test(r.Status || "")
    );
    const ssGaps = ((D.secureScoreGaps && D.secureScoreGaps.rows) || []).slice();
    const invHot = (D.findings || []).filter((f) =>
      /critical|high|medium/i.test(f.Severity || "")
    );
    const errors = D.errors || [];
    const collected =
      (S.collectedAt || meta.generatedAt || "").toString().slice(0, 19).replace("T", " ");

    const cover = {
      kind: "cover",
      name: "Cover",
      title: "Entra Collect — Remediation workbook",
      meta: [
        ["Tenant / run", orgName(D)],
        ["Output folder", meta.outputDir || ""],
        ["Collected at", collected],
        [
          "Report generated",
          (meta.generatedAt || "").toString().slice(0, 19).replace("T", " "),
        ],
      ],
      scores: [
        ["Expert posture score", D.score != null ? D.score + " / 100" : ""],
        [
          "Expert severity",
          "Critical " +
            ((D.sevCount && D.sevCount.Critical) || 0) +
            " · High " +
            ((D.sevCount && D.sevCount.High) || 0) +
            " · Medium " +
            ((D.sevCount && D.sevCount.Medium) || 0),
        ],
        [
          "Microsoft Secure Score",
          S.secureScoreCurrent != null
            ? Math.round(S.secureScoreCurrent * 10) / 10 +
              " / " +
              Math.round((S.secureScoreMax || 0) * 10) / 10
            : "n/a",
        ],
        [
          "Secure Score open",
          String((D.secureScoreGaps && D.secureScoreGaps.count) || 0) +
            " controls · " +
            String((D.secureScoreGaps && D.secureScoreGaps.points) || "?") +
            " pts",
        ],
      ],
      kpis: [
        ["Permanent Global Admins", S.globalAdminPermanent ?? ""],
        ["Users without MFA (inventory)", S.usersWithoutMfa ?? ""],
        ["  of which apparent humans", S.usersWithoutMfaHuman ?? ""],
        ["  rooms / shared / service", S.usersWithoutMfaNonHuman ?? ""],
        ["Risky users (atRisk)", S.riskyUsersAtRisk ?? ""],
        ["Device-code users 90d", S.deviceCodeUsers90d ?? ""],
        ["Attack-path gaps", (CS.fail || 0) + " fail / " + (CS.partial || 0) + " partial"],
        ["Blocked / error steps", errors.length],
        ["Expert narratives", narratives.length],
      ],
      howTo: [
        [
          "1",
          "Start on This Week — assign a named Owner, set Due, flip Status as work progresses.",
        ],
        [
          "2",
          "Remediation Plan is the full backlog (Wave 1→3). Do this = first step; Full remediation = complete guidance.",
        ],
        [
          "3",
          "Suggested role is a team hint (Identity / Endpoint / …) — replace with a named Owner.",
        ],
        [
          "4",
          "Attack Path Gaps = structural Fail/Partial. Secure Score = Track D after Wave 1/2 (Device rows capped).",
        ],
        [
          "5",
          "Inventory Hot is raw signal — do not prioritize over This Week / Expert. Yellow cells are yours to fill.",
        ],
      ],
    };

    const nowNarr = narratives.filter((n) => n.Priority === "Now");
    const nextHigh = narratives.filter(
      (n) => n.Priority === "Next" && /Critical|High/i.test(n.Severity || "")
    );

    // --- This Week (kickoff / standup) ---
    const weekHeader = [
      "Rank",
      "Priority",
      "Severity",
      "Title",
      "Do this (first step)",
      "Suggested role",
      "Owner",
      "Status",
      "Due date",
      "Finding ID",
      "Notes / blockers",
    ];
    const weekRows = nowNarr.map((n, i) => [
      i + 1,
      n.Priority || "",
      n.Severity || "",
      n.Title || "",
      firstAction(n.Remediation),
      suggestedOwner(n),
      "",
      "Open",
      "",
      n.Id || "",
      "",
    ]);

    // Column order optimized for "what / who / when"
    const planHeader = [
      "Rank",
      "Wave",
      "Priority",
      "Severity",
      "Title",
      "Do this (first step)",
      "Suggested role",
      "Owner",
      "Status",
      "Due date",
      "Effort (S/M/L)",
      "Track",
      "Why it matters (summary)",
      "Full remediation",
      "Evidence (clip)",
      "Finding ID",
      "Related files",
      "Related checks",
      "Notes / blockers",
    ];
    const planRows = narratives.map((n, i) => [
      i + 1,
      waveFor(n.Priority),
      n.Priority || "",
      n.Severity || "",
      n.Title || "",
      firstAction(n.Remediation),
      suggestedOwner(n),
      "",
      "Open",
      "",
      "",
      trackHint(n.Priority, n.Severity),
      clip(n.Narrative, 280),
      clip(n.Remediation, 500),
      clip(n.Evidence, 220),
      n.Id || "",
      s(n.RelatedFiles),
      s(n.RelatedChecks),
      "",
    ]);

    const expertHeader = [
      "Priority",
      "Severity",
      "ID",
      "Title",
      "Narrative",
      "Evidence",
      "Remediation",
      "RelatedFiles",
      "RelatedChecks",
      "Deep dive",
      "Track",
      "Suggested role",
      "Confidence",
    ];
    const expertRows = narratives.map((n) => [
      n.Priority || "",
      n.Severity || "",
      n.Id || "",
      n.Title || "",
      s(n.Narrative),
      s(n.Evidence),
      s(n.Remediation),
      s(n.RelatedFiles),
      s(n.RelatedChecks),
      deepDive(n.Id),
      trackHint(n.Priority, n.Severity),
      suggestedOwner(n),
      n.Confidence || "",
    ]);

    const apHeader = [
      "Status",
      "CheckId",
      "Title",
      "Evidence",
      "Do this",
      "Suggested role",
      "Owner",
      "Status (work)",
      "Due date",
      "Confidence",
      "Licence",
    ];
    const apRows = gaps.map((r) => [
      r.Status || "",
      r.CheckId || r.Id || "",
      r.Title || "",
      clip(r.Evidence, 300),
      apDoThis(r, narratives),
      /role|pim|guest|app|ga|admin|approle/i.test(
        `${r.CheckId || ""} ${r.Title || ""}`
      )
        ? "Identity / IAM"
        : "Security / IT ops",
      "",
      "Open",
      "",
      r.Confidence || "",
      r.LicenceRequired || "",
    ]);

    const ssSelected = selectSecureScoreRows(ssGaps);
    const ssHeader = [
      "Gain (pts)",
      "Category",
      "Title",
      "Status",
      "User impact",
      "Threats",
      "Remediation",
      "ControlId",
      "Owner",
      "Status (work)",
      "Due date",
      "Track",
      "Steering note",
    ];
    const ssRows = ssSelected.map((r) => {
      const isDevice = /device/i.test(r.Category || r.Service || "");
      return [
        r.Gain != null ? r.Gain : "",
        r.Category || r.Service || "",
        r.Title || "",
        r.Status || "",
        r.UserImpact || "",
        r.Threats || "",
        clip(r.Remediation, 350),
        r.ControlId || "",
        "",
        "Open",
        "",
        "Track D — Backlog / adoption",
        isDevice
          ? "Device control — only after Wave 1/2 identity work"
          : "",
      ];
    });

    const invHeader = [
      "Severity",
      "Area",
      "Detail",
      "Owner",
      "Status (work)",
      "Due date",
      "Steering note",
    ];
    const invRows = invHot.slice(0, 500).map((f) => [
      f.Severity || "",
      f.Area || "",
      s(f.Detail),
      "",
      "Open",
      "",
      "Raw inventory — confirm via This Week / Expert Findings before assigning effort",
    ]);

    const limHeader = [
      "Type",
      "Area / step",
      "Label",
      "Reason",
      "Needed role / note",
      "Impact on assessment",
    ];
    const limRows = [];
    for (const e of errors) {
      limRows.push([
        "Collection error",
        e.area || e.step || "",
        e.label || e.file || "",
        clip(e.reason || e.message || e.Detail || "", 240),
        clip(e.needed || "", 160),
        "Unknown for this area — not a Pass",
      ]);
    }
    const skipped = D.skippedFindings || [];
    for (const f of skipped.slice(0, 80)) {
      limRows.push([
        "Skipped check",
        f.Area || "",
        "",
        clip(f.Detail, 240),
        "",
        "Not assessed",
      ]);
    }
    // Checks that ran on nothing (input not collected) or cannot apply to
    // this tenant (licence / Security Defaults) belong here, not in the gaps.
    for (const r of (D.attackChecklist || []).filter((x) =>
      /^(notevaluated|skip)$/i.test(String(x.Status || "").trim())
    )) {
      limRows.push([
        "Check not evaluated",
        "Attack path",
        r.CheckId || "",
        clip(r.Evidence || r.Rationale || "", 240),
        "",
        "Unknown — not a Pass",
      ]);
    }
    for (const r of (D.attackChecklist || []).filter((x) =>
      /^notapplicable$/i.test(String(x.Status || "").trim())
    )) {
      limRows.push([
        "Check not applicable",
        "Attack path",
        r.CheckId || "",
        clip(r.Evidence || r.Rationale || "", 240),
        r.LicenceRequired ? `Requires ${r.LicenceRequired}` : "",
        "Design / licence state — not a gap",
      ]);
    }
    if (!limRows.length) {
      limRows.push([
        "Info",
        "",
        "",
        "No ERROR_* / skipped inventory rows recorded in this export.",
        "",
        "",
      ]);
    }

    const nowCount = nowNarr.length;
    const nextCount = narratives.filter((n) => n.Priority === "Next").length;
    const laterCount = narratives.filter((n) => n.Priority === "Later").length;

    const board = {
      kind: "board",
      name: "Steering Board",
      title: "Remediation steering board — use This Week + Remediation Plan",
      buckets: [
        ["Priority bucket", "Count", "Intent"],
        [
          "Now (Wave 1)",
          nowCount,
          "Standing privilege / GA-equivalent / active high-risk",
        ],
        ["Next (Wave 2)", nextCount, "CA gaps, MFA exclusions, identity hardening"],
        [
          "  · of which High+",
          nextHigh.length,
          "Next items already Critical/High — queue after Wave 1",
        ],
        ["Later (Wave 3)", laterCount, "Hygiene / context — not standup fodder"],
      ],
      weekFocus: nowNarr.slice(0, 8).map((n, i) => [
        String(i + 1),
        n.Title || n.Id || "",
        firstAction(n.Remediation),
        suggestedOwner(n),
      ]),
      ritual: [
        ["1", "Open This Week — clear Open / Blocked; update Owner + Due"],
        ["2", "Only pull Wave 2 (Next High) when Wave 1 Open count is shrinking"],
        [
          "3",
          "Secure Score Device rows are capped — prefer Identity/Apps Track D wins",
        ],
      ],
      avoid: [
        [
          "Raw MFA inventory counts when enforced MFA CA already exists — review exclusion groups instead",
        ],
        [
          "Secure Score Device gaps when Expert Findings show RoleManagement / AppRoleAssignment risk",
        ],
        [
          "Failed sign-in volume from known office/plant egress before confirming with IT",
        ],
        [
          "Treating Inventory Hot as equal priority to This Week / Expert Findings",
        ],
      ],
    };

    return [
      cover,
      board,
      {
        kind: "table",
        name: "This Week",
        header: weekHeader,
        rows: weekRows,
        widths: [6, 10, 10, 36, 42, 22, 16, 14, 12, 28, 28],
        wrapCols: [3, 4, 10],
        fillCols: [6, 7, 8, 10],
        statusCol: 7,
        prioCol: 1,
        sevCol: 2,
        freeze: true,
        tabColor: "C62828",
      },
      {
        kind: "table",
        name: "Remediation Plan",
        header: planHeader,
        rows: planRows,
        widths: [
          6, 10, 10, 10, 34, 40, 20, 16, 14, 12, 12, 26, 36, 40, 28, 26, 20, 20,
          24,
        ],
        wrapCols: [4, 5, 12, 13],
        fillCols: [7, 8, 9, 10, 18],
        statusCol: 8,
        effortCol: 10,
        prioCol: 2,
        sevCol: 3,
        freeze: true,
        tabColor: "1565C0",
      },
      {
        kind: "table",
        name: "Expert Findings",
        header: expertHeader,
        rows: expertRows,
        widths: [10, 10, 28, 36, 48, 36, 40, 24, 20, 16, 28, 20, 12],
        wrapCols: [4, 5, 6],
        prioCol: 0,
        sevCol: 1,
        freeze: true,
      },
      {
        kind: "table",
        name: "Attack Path Gaps",
        header: apHeader,
        rows: apRows,
        widths: [10, 22, 32, 36, 36, 18, 16, 14, 12, 12, 10],
        wrapCols: [3, 4],
        fillCols: [6, 7, 8],
        statusCol: 7,
        checkStatusCol: 0,
        freeze: true,
      },
      {
        kind: "table",
        name: "Secure Score",
        header: ssHeader,
        rows: ssRows,
        widths: [10, 14, 36, 14, 14, 22, 40, 22, 16, 14, 12, 28, 32],
        wrapCols: [6, 12],
        fillCols: [8, 9, 10],
        statusCol: 9,
        freeze: true,
      },
      {
        kind: "table",
        name: "Inventory Hot",
        header: invHeader,
        rows: invRows,
        widths: [10, 18, 58, 16, 14, 12, 40],
        wrapCols: [2, 6],
        fillCols: [3, 4, 5],
        statusCol: 4,
        sevCol: 0,
        freeze: true,
      },
      {
        kind: "table",
        name: "Limitations",
        header: limHeader,
        rows: limRows,
        widths: [16, 22, 28, 48, 28, 28],
        wrapCols: [3, 4, 5],
        freeze: true,
      },
    ];
  }

  function styleHeaderRow(row, colCount) {
    row.height = 22;
    for (let c = 1; c <= colCount; c++) {
      const cell = row.getCell(c);
      cell.fill = fillSolid(C.titleBg);
      cell.font = {
        bold: true,
        color: argb(C.titleFg),
        size: 10,
        name: "Calibri",
      };
      cell.alignment = {
        vertical: "middle",
        horizontal: "left",
        wrapText: true,
      };
      cell.border = thinBorder();
    }
  }

  function styleDataCell(cell, opts) {
    cell.font = { name: "Calibri", size: 10, color: argb(C.ink2) };
    cell.alignment = {
      vertical: "top",
      wrapText: !!opts.wrap,
      horizontal: opts.center ? "center" : "left",
    };
    cell.border = thinBorder();
    if (opts.fillMe) {
      cell.fill = fillSolid(C.fillMe);
    } else if (opts.zebra) {
      cell.fill = fillSolid(C.zebra);
    }
  }

  function paintCover(ws, sh) {
    ws.views = [{ showGridLines: false }];
    ws.columns = [{ width: 32 }, { width: 72 }];

    ws.mergeCells("A1:B1");
    const title = ws.getCell("A1");
    title.value = sh.title;
    title.fill = fillSolid(C.titleBg);
    title.font = {
      bold: true,
      color: argb(C.titleFg),
      size: 16,
      name: "Calibri",
    };
    title.alignment = { vertical: "middle", horizontal: "left" };
    ws.getRow(1).height = 36;

    ws.mergeCells("A2:B2");
    const sub = ws.getCell("A2");
    sub.value =
      "Steering workbook · start on This Week · fill Owner / Status / Due (yellow cells)";
    sub.fill = fillSolid(C.surface);
    sub.font = { color: argb(C.muted), size: 10, name: "Calibri", italic: true };
    sub.alignment = { vertical: "middle" };
    ws.getRow(2).height = 20;

    let r = 4;
    function section(label) {
      ws.mergeCells(r, 1, r, 2);
      const cell = ws.getCell(r, 1);
      cell.value = label;
      cell.fill = fillSolid(C.sectionBg);
      cell.font = {
        bold: true,
        color: argb(C.sectionFg),
        size: 11,
        name: "Calibri",
      };
      cell.alignment = { vertical: "middle" };
      ws.getRow(r).height = 20;
      r++;
    }
    function kv(label, value, emphasize) {
      const a = ws.getCell(r, 1);
      const b = ws.getCell(r, 2);
      a.value = label;
      b.value = value;
      a.font = { bold: true, color: argb(C.ink2), size: 10, name: "Calibri" };
      b.font = {
        bold: !!emphasize,
        color: argb(emphasize ? C.accentDim : C.ink2),
        size: emphasize ? 12 : 10,
        name: "Calibri",
      };
      a.fill = fillSolid(C.soft);
      b.fill = fillSolid(C.paper);
      a.border = thinBorder();
      b.border = thinBorder();
      a.alignment = { vertical: "middle" };
      b.alignment = { vertical: "middle", wrapText: true };
      ws.getRow(r).height = emphasize ? 22 : 18;
      r++;
    }

    section("Run metadata");
    for (const [k, v] of sh.meta) kv(k, v, false);
    r++;
    section("Scores");
    for (const [k, v] of sh.scores) kv(k, v, /posture|score/i.test(k));
    r++;
    section("KPIs");
    for (const [k, v] of sh.kpis) kv(k, v, false);
    r++;
    section("How to use this workbook");
    for (const [num, text] of sh.howTo) {
      const a = ws.getCell(r, 1);
      const b = ws.getCell(r, 2);
      a.value = num;
      b.value = text;
      a.fill = fillSolid(C.titleBg);
      a.font = { bold: true, color: argb(C.accent), size: 11, name: "Calibri" };
      a.alignment = { horizontal: "center", vertical: "middle" };
      b.font = { color: argb(C.ink2), size: 10, name: "Calibri" };
      b.alignment = { wrapText: true, vertical: "middle" };
      a.border = thinBorder();
      b.border = thinBorder();
      ws.getRow(r).height = 32;
      r++;
    }
  }

  function paintBoard(ws, sh) {
    ws.views = [{ showGridLines: false }];
    ws.columns = [{ width: 18 }, { width: 42 }, { width: 42 }, { width: 22 }];

    ws.mergeCells("A1:D1");
    const title = ws.getCell("A1");
    title.value = sh.title;
    title.fill = fillSolid(C.titleBg);
    title.font = {
      bold: true,
      color: argb(C.titleFg),
      size: 14,
      name: "Calibri",
    };
    title.alignment = { vertical: "middle" };
    ws.getRow(1).height = 30;

    let r = 3;
    const header = sh.buckets[0];
    for (let c = 0; c < header.length; c++) {
      const cell = ws.getCell(r, c + 1);
      cell.value = header[c];
    }
    styleHeaderRow(ws.getRow(r), 3);
    r++;
    for (let i = 1; i < sh.buckets.length; i++) {
      const row = sh.buckets[i];
      for (let c = 0; c < row.length; c++) {
        const cell = ws.getCell(r, c + 1);
        cell.value = row[c];
        styleDataCell(cell, { zebra: i % 2 === 0, center: c === 1 });
      }
      // Soft badge for Wave labels that aren't exact Now/Next/Later
      const prioKey = String(row[0] || "");
      if (/Wave 1|Now/i.test(prioKey)) applyBadge(ws.getCell(r, 1), prioStyle("Now"));
      else if (/Wave 2|Next|High\+/i.test(prioKey)) applyBadge(ws.getCell(r, 1), prioStyle("Next"));
      else if (/Wave 3|Later/i.test(prioKey)) applyBadge(ws.getCell(r, 1), prioStyle("Later"));
      ws.getRow(r).height = 20;
      r++;
    }

    if (sh.weekFocus && sh.weekFocus.length) {
      r += 1;
      ws.mergeCells(r, 1, r, 4);
      const focusH = ws.getCell(r, 1);
      focusH.value = "This week focus (top Now) — detail + Status on This Week sheet";
      focusH.fill = fillSolid(C.sectionBg);
      focusH.font = {
        bold: true,
        color: argb(C.sectionFg),
        size: 11,
        name: "Calibri",
      };
      r++;
      const fh = ["#", "Title", "Do this (first step)", "Suggested role"];
      for (let c = 0; c < fh.length; c++) {
        ws.getCell(r, c + 1).value = fh[c];
      }
      styleHeaderRow(ws.getRow(r), 4);
      r++;
      sh.weekFocus.forEach((row, i) => {
        for (let c = 0; c < 4; c++) {
          const cell = ws.getCell(r, c + 1);
          cell.value = row[c];
          styleDataCell(cell, { wrap: c === 1 || c === 2, zebra: i % 2 === 1 });
        }
        ws.getRow(r).height = 36;
        r++;
      });
    }

    r += 1;
    ws.mergeCells(r, 1, r, 4);
    const ritualH = ws.getCell(r, 1);
    ritualH.value = "Suggested weekly ritual";
    ritualH.fill = fillSolid(C.sectionBg);
    ritualH.font = {
      bold: true,
      color: argb(C.sectionFg),
      size: 11,
      name: "Calibri",
    };
    r++;
    for (const [num, text] of sh.ritual) {
      ws.getCell(r, 1).value = num;
      ws.mergeCells(r, 2, r, 4);
      ws.getCell(r, 2).value = text;
      styleDataCell(ws.getCell(r, 1), { center: true });
      styleDataCell(ws.getCell(r, 2), {});
      ws.getCell(r, 1).fill = fillSolid(C.titleBg);
      ws.getCell(r, 1).font = {
        bold: true,
        color: argb(C.accent),
        size: 11,
        name: "Calibri",
      };
      r++;
    }

    r += 1;
    ws.mergeCells(r, 1, r, 4);
    const avoidH = ws.getCell(r, 1);
    avoidH.value = "Do not prioritize";
    avoidH.fill = fillSolid(C.highBg);
    avoidH.font = {
      bold: true,
      color: argb(C.highFg),
      size: 11,
      name: "Calibri",
    };
    r++;
    for (const [text] of sh.avoid) {
      ws.getCell(r, 1).value = "—";
      ws.mergeCells(r, 2, r, 4);
      ws.getCell(r, 2).value = text;
      styleDataCell(ws.getCell(r, 1), { center: true });
      styleDataCell(ws.getCell(r, 2), { wrap: true });
      ws.getRow(r).height = 28;
      r++;
    }
  }

  function paintTable(ws, sh) {
    const colCount = sh.header.length;
    ws.columns = (sh.widths || []).map((w) => ({ width: w }));
    while (ws.columns.length < colCount) ws.columns.push({ width: 16 });

    const headerRow = ws.addRow(sh.header);
    styleHeaderRow(headerRow, colCount);

    const wrapSet = new Set(sh.wrapCols || []);
    const fillSet = new Set(sh.fillCols || []);

    sh.rows.forEach((vals, idx) => {
      const row = ws.addRow(vals);
      row.height = wrapSet.size ? 48 : 18;
      for (let c = 1; c <= colCount; c++) {
        const cell = row.getCell(c);
        const ci = c - 1;
        styleDataCell(cell, {
          wrap: wrapSet.has(ci),
          fillMe: fillSet.has(ci),
          zebra: !fillSet.has(ci) && idx % 2 === 1,
          center: ci === sh.prioCol || ci === sh.sevCol || ci === 0,
        });
      }
      if (sh.prioCol != null) applyBadge(row.getCell(sh.prioCol + 1), prioStyle(vals[sh.prioCol]));
      if (sh.sevCol != null) applyBadge(row.getCell(sh.sevCol + 1), sevStyle(vals[sh.sevCol]));
      if (sh.checkStatusCol != null) {
        applyBadge(
          row.getCell(sh.checkStatusCol + 1),
          statusStyle(vals[sh.checkStatusCol])
        );
      }
    });

    if (sh.freeze !== false) {
      ws.views = [{ state: "frozen", xSplit: 0, ySplit: 1, activeCell: "A2" }];
    }

    const lastRow = Math.max(1, sh.rows.length + 1);
    ws.autoFilter = {
      from: { row: 1, column: 1 },
      to: { row: lastRow, column: colCount },
    };

    if (sh.statusCol != null && sh.rows.length) {
      for (let i = 0; i < sh.rows.length; i++) {
        const cell = ws.getCell(i + 2, sh.statusCol + 1);
        cell.dataValidation = {
          type: "list",
          allowBlank: true,
          formulae: [STATUS_OPTIONS],
          showErrorMessage: true,
          errorTitle: "Status",
          error: "Pick a value from the list",
        };
      }
    }
    if (sh.effortCol != null && sh.rows.length) {
      for (let i = 0; i < sh.rows.length; i++) {
        const cell = ws.getCell(i + 2, sh.effortCol + 1);
        cell.dataValidation = {
          type: "list",
          allowBlank: true,
          formulae: [EFFORT_OPTIONS],
          showErrorMessage: true,
        };
      }
    }

    // Accent tab color
    if (sh.tabColor) {
      ws.properties.tabColor = { argb: "FF" + sh.tabColor.replace(/^#/, "") };
    } else {
      ws.properties.tabColor = { argb: C.accentDim };
    }
  }

  /**
   * @param {object} ExcelJS  exceljs module / global
   * @param {object} D        report payload
   * @returns {Promise<object>} workbook
   */
  async function buildWorkbook(ExcelJS, D) {
    const wb = new ExcelJS.Workbook();
    wb.creator = "Entra Collect";
    wb.created = new Date();
    wb.modified = new Date();
    wb.title = "Remediation Plan — " + orgName(D);
    wb.description =
      "Steering workbook generated from Entra/M365 security findings";

    const sheets = buildSheets(D);
    for (const sh of sheets) {
      const ws = wb.addWorksheet(sh.name.slice(0, 31), {
        properties: { defaultRowHeight: 18 },
        pageSetup: {
          orientation: sh.kind === "table" ? "landscape" : "portrait",
          fitToPage: true,
          fitToWidth: 1,
          fitToHeight: 0,
        },
      });
      if (sh.kind === "cover") paintCover(ws, sh);
      else if (sh.kind === "board") paintBoard(ws, sh);
      else paintTable(ws, sh);
    }

    // Cover / board tab colors
    const cover = wb.getWorksheet("Cover");
    if (cover) cover.properties.tabColor = { argb: C.ink2 };
    const board = wb.getWorksheet("Steering Board");
    if (board) board.properties.tabColor = { argb: C.accent };

    return wb;
  }

  function defaultFilename(D) {
    return (
      "EntraCollect_Remediation_" +
      ((D.meta && D.meta.outputDir) || "export").replace(/[^\w.-]+/g, "_") +
      ".xlsx"
    );
  }

  async function downloadBrowser(ExcelJS, D, filename) {
    const wb = await buildWorkbook(ExcelJS, D);
    const name = filename || defaultFilename(D);
    const buffer = await wb.xlsx.writeBuffer();
    const blob = new Blob([buffer], {
      type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
    return name;
  }

  async function writeFileNode(ExcelJS, D, filePath) {
    const wb = await buildWorkbook(ExcelJS, D);
    await wb.xlsx.writeFile(filePath);
    return filePath;
  }

  return {
    buildSheets,
    buildWorkbook,
    downloadBrowser,
    writeFileNode,
    trackHint,
    deepDive,
  };
});
