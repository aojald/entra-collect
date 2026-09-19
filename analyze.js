#!/usr/bin/env node
/**
 * Entra Collect — run expert narrative analysis on a collection output folder.
 *
 * Usage:
 *   node analyze.js --help
 *   node analyze.js output_YYYY-MM-DD_HHMM
 *   node analyze.js                 # latest non-empty output_* folder
 *
 * Prefer `node report.js <dir>` if you also want HTML + Excel rebuilt.
 */
const path = require("path");
const fs = require("fs");
const { analyzeOutputDir } = require("./lib/analyze");

/**
 * Most recent run that actually produced data.
 *
 * Aborted runs leave behind empty output_* folders; picking one of those by
 * date would report a perfect score on a tenant that was never collected.
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

function printHelp() {
  console.log(`Entra Collect — expert analysis

Rebuild NARR.* expert findings (CSV/JSON) for an existing collection folder.
Does not re-collect from the tenant.

Usage:
  node analyze.js [outputDir]
  node analyze.js                 # latest non-empty output_* in the current directory
  node analyze.js --help

Examples:
  node analyze.js output_YYYY-MM-DD_HHMM

Outputs:
  00_Expert_Findings.csv
  00_Expert_Findings.json

Tip: node report.js <dir> runs analysis and rebuilds HTML + Excel.
`);
}

function main(argvOut) {
  if (argvOut === "--help" || argvOut === "-h") {
    printHelp();
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
        "  Usage: node analyze.js output_YYYY-MM-DD_HHMM\n" +
        "  Help:  node analyze.js --help"
    );
    process.exit(1);
  }
  console.log(`Entra Collect — analyzing ${path.basename(outDir)}`);
  const { narratives, score, sevCount } = analyzeOutputDir(outDir);
  const now = narratives.filter((n) => n.Priority === "Now").length;
  const next = narratives.filter((n) => n.Priority === "Next").length;
  console.log(
    `✓ Expert analysis: ${narratives.length} narratives · score ${score}/100 · ` +
      `Critical=${sevCount.Critical || 0} High=${sevCount.High || 0} Medium=${sevCount.Medium || 0}`
  );
  console.log(`  Priority: Now=${now} · Next=${next}`);
  console.log(`  → ${path.join(outDir, "00_Expert_Findings.csv")}`);
  console.log(`  Tip: node report.js ${path.basename(outDir)}  # also rebuild HTML + Excel`);
  return outDir;
}

if (require.main === module) {
  main(process.argv[2]);
}

module.exports = { main };
