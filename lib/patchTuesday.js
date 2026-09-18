/**
 * Live Windows Patch Tuesday baseline (no monthly hardcoded KB map).
 *
 * Source of truth: Microsoft Learn release-health pages (same tables Intune
 * calls "2026-09 B"). Fetched at collect time. The baked-in map is only used
 * when the network fetch fails.
 */
const { fetchResilient } = require("./net");

const RELEASE_HEALTH_URLS = [
  "https://learn.microsoft.com/windows/release-health/windows11-release-information",
  "https://learn.microsoft.com/windows/release-health/release-information",
];

/** Last-resort offline map. Prefer live Learn data. */
const FALLBACK_PATCH_TUESDAY = {
  asOf: "2026-07-14",
  label: "July 2026 Patch Tuesday (offline fallback)",
  source: "fallback",
  builds: {
    26200: { minUbr: 8875, kb: "KB5101650", product: "Windows 11 25H2", oobUbr: 8894, oobKb: "KB5121767" },
    26100: { minUbr: 8875, kb: "KB5101650", product: "Windows 11 24H2", oobUbr: 8894, oobKb: "KB5121767" },
    22631: { minUbr: 7376, kb: "KB5099414", product: "Windows 11 23H2" },
    19045: { minUbr: 7548, kb: "KB5099539", product: "Windows 10 22H2 (ESU)" },
    19044: { minUbr: 7548, kb: "KB5099539", product: "Windows 10 21H2 (ESU)" },
  },
};

function htmlToText(raw) {
  return String(raw || "")
    .replace(/<script[\s\S]*?<\/script>/gi, "\n")
    .replace(/<style[\s\S]*?<\/style>/gi, "\n")
    .replace(/<\/(tr|h[1-6]|p|div|section)>/gi, "\n")
    .replace(/<\/(td|th)>/gi, " | ")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&#\d+;/g, " ")
    .replace(/[ \t]+/g, " ")
    .replace(/\n[ \t]+/g, "\n");
}

/**
 * Parse Learn release-health history tables.
 * Newest row is first. "B" = Patch Tuesday security CU; OOB/D may be newer.
 */
function parseReleaseHealthText(text) {
  const body = /<html/i.test(text) ? htmlToText(text) : String(text || "");
  const builds = {};
  const sectionRe =
    /Version\s+([^\n(]+?)\s*\(OS build\s+(\d{5})\)([\s\S]*?)(?=Version\s+[^\n(]+\s*\(OS build|$)/gi;
  let section;
  while ((section = sectionRe.exec(body))) {
    const versionLabel = section[1].replace(/\s*-\s*End of updates.*$/i, "").trim();
    const major = section[2];
    const chunk = section[3];
    const rows = [];
    const rowRe =
      /\|\s*[^\n]*?\|\s*(\d{4}-\d{2})\s+(B|D|OOB|C)\s*\|\s*(\d{4}-\d{2}-\d{2})\s*\|\s*(\d{5})\.(\d+)\s*\|\s*(KB\d+)?/gi;
    let row;
    while ((row = rowRe.exec(chunk))) {
      rows.push({
        yyyymm: row[1],
        kind: row[2],
        date: row[3],
        major: row[4],
        ubr: Number(row[5]),
        kb: row[6] || "",
      });
    }
    if (!rows.length) continue;
    const latest = rows[0];
    const latestB = rows.find((r) => r.kind === "B") || latest;
    const winFamily = Number(major) >= 22000 ? "Windows 11" : "Windows 10";
    const entry = {
      product: `${winFamily} ${versionLabel}`.replace(/\s+/g, " "),
      minUbr: latestB.ubr,
      kb: latestB.kb,
      patchTuesdayDate: latestB.date,
      latestUbr: latest.ubr,
      latestDate: latest.date,
      latestKind: latest.kind,
    };
    if (latest.ubr > latestB.ubr) {
      entry.oobUbr = latest.ubr;
      entry.oobKb = latest.kb;
    }
    const prev = builds[major];
    if (!prev || entry.minUbr > prev.minUbr) builds[major] = entry;
  }
  return builds;
}

function summarizeBuilds(builds) {
  const dates = Object.values(builds)
    .map((b) => b.patchTuesdayDate || b.latestDate)
    .filter(Boolean)
    .sort();
  const asOf = dates.length ? dates[dates.length - 1] : null;
  return {
    asOf,
    label: asOf ? `Patch Tuesday / latest CU (as of ${asOf})` : "Windows CU baseline",
    builds,
  };
}

async function fetchLearnPage(url) {
  const res = await fetchResilient(url, {
    method: "GET",
    headers: {
      Accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
      "User-Agent": "entra-collect/1.1 (+https://github.com/aojald/entra-collect)",
    },
    timeoutMs: 20000,
    retries: 1,
  });
  return res.text();
}

/**
 * Fetch Microsoft's current CU map. Never throws — returns fallback on failure.
 */
async function resolvePatchBaseline(opts = {}) {
  const fetchPage = opts.fetchPage || fetchLearnPage;
  const urls = opts.urls || RELEASE_HEALTH_URLS;
  const merged = {};
  const errors = [];
  for (const url of urls) {
    try {
      const text = await fetchPage(url);
      const parsed = parseReleaseHealthText(text);
      Object.assign(merged, parsed);
    } catch (e) {
      errors.push(`${url}: ${String(e.message || e).split("\n")[0].slice(0, 160)}`);
    }
  }
  if (Object.keys(merged).length) {
    const sum = summarizeBuilds(merged);
    const ageDays = sum.asOf
      ? Math.floor((Date.now() - Date.parse(sum.asOf)) / 86400000)
      : null;
    return {
      ...sum,
      source: "microsoft-learn",
      stale: ageDays != null && ageDays > 45,
      ageDays,
      errors,
    };
  }
  const ageDays = Math.floor(
    (Date.now() - Date.parse(FALLBACK_PATCH_TUESDAY.asOf)) / 86400000
  );
  return {
    ...FALLBACK_PATCH_TUESDAY,
    source: "fallback",
    stale: true,
    ageDays: Number.isFinite(ageDays) ? ageDays : null,
    errors: errors.length ? errors : ["no release-health tables parsed"],
  };
}

function parseOsBuild(osVersionBuild) {
  const s = String(osVersionBuild || "").trim();
  const full = s.match(/(?:10\.0\.)?(\d{5})\.(\d+)/);
  if (full) return { major: full[1], ubr: Number(full[2]), raw: s };
  const majorOnly = s.match(/(?:^|[^\d])(?:10\.0\.)?(\d{5})(?:\s|$)/) || s.match(/^(\d{5})$/);
  if (majorOnly) return { major: majorOnly[1], ubr: null, raw: s, incomplete: true };
  return null;
}

function patchStatus(buildInfo, baseline) {
  const builds = (baseline && baseline.builds) || {};
  if (!buildInfo) return { status: "Unknown", product: "?", kbExpected: "?", lagUbr: null };
  const ref = builds[buildInfo.major];
  if (!ref) {
    const maj = Number(buildInfo.major);
    if (maj >= 19041 && maj < 22000) {
      return {
        status: "Windows10_UnsupportedBuildMap",
        product: `Windows 10 build ${buildInfo.major}`,
        kbExpected: (builds["19045"] && builds["19045"].kb) || "?",
        lagUbr: null,
      };
    }
    return { status: "UnknownBuildFamily", product: `Build ${buildInfo.major}`, kbExpected: "?", lagUbr: null };
  }
  if (buildInfo.ubr == null) {
    return { status: "Unknown", product: ref.product, kbExpected: ref.kb, lagUbr: null };
  }
  const currentUbr = ref.oobUbr || ref.minUbr;
  if (buildInfo.ubr >= currentUbr) {
    return { status: "CurrentOrNewer", product: ref.product, kbExpected: ref.oobKb || ref.kb, lagUbr: 0 };
  }
  if (buildInfo.ubr >= ref.minUbr) {
    return {
      status: ref.oobUbr ? "PatchTuesdayOK_OOBPending" : "Current",
      product: ref.product,
      kbExpected: ref.kb,
      lagUbr: ref.oobUbr ? ref.oobUbr - buildInfo.ubr : 0,
    };
  }
  return {
    status: "BehindPatchTuesday",
    product: ref.product,
    kbExpected: ref.kb,
    lagUbr: ref.minUbr - buildInfo.ubr,
  };
}

module.exports = {
  RELEASE_HEALTH_URLS,
  FALLBACK_PATCH_TUESDAY,
  parseReleaseHealthText,
  htmlToText,
  resolvePatchBaseline,
  parseOsBuild,
  patchStatus,
};
