/**
 * Shared I/O helpers + artifact manifest.
 *
 * Every artifact records how it came to be, because an empty CSV from a failed
 * API call and an empty CSV from a clean tenant are indistinguishable on disk —
 * and the analyzer/report used to read both as "0 findings".
 */
const fs = require("fs");
const path = require("path");
const { isTransientError } = require("./net");
const { toCsv } = require("./csv");

const MANIFEST_NAME = "00_MANIFEST.json";

/** How a step ended. Anything other than `ok`/`empty` must not be read as data. */
const STATUS = {
  OK: "ok",
  EMPTY: "empty",
  FAILED: "failed",
  SKIPPED: "skipped",
  PARTIAL: "partial",
};

function errorLabel(label) {
  return String(label).replace(/[^a-z0-9]+/gi, "_");
}

/** Graph `error.code` from the response body, when there is one. */
function graphErrorCode(e) {
  const body = e && e.body;
  if (!body) return null;
  try {
    const j = typeof body === "string" ? JSON.parse(body) : body;
    const code = j && j.error && j.error.code;
    return code ? String(code) : null;
  } catch {
    const m = String(body).match(/"code"\s*:\s*"([^"]+)"/);
    return m ? m[1] : null;
  }
}

/** Error kinds — only `transient` is worth a re-run. */
const ERROR_KIND = {
  DENIED: "denied",
  LICENCE: "licence",
  UNSUPPORTED: "unsupported",
  TRANSIENT: "transient",
  ERROR: "error",
};

const LICENCE_CODES = /AadPremiumLicenseRequired|LicenseRequired|PremiumLicenseRequired|NoLicense/i;
const DENIED_CODES =
  /Authorization_RequestDenied|Authentication_RequestFromUnsupportedUserRole|AccessDenied|accessDenied|Forbidden|InsufficientPrivileges|UnknownError_Forbidden/i;
const UNSUPPORTED_CODES = /BadRequest|Request_UnsupportedQuery|Request_BadRequest|InvalidFilter|ResourceNotFound|Request_ResourceNotFound/i;

/**
 * Classify a failed step so the operator (and the report) know whether a
 * re-run can help. A 400 `AadPremiumLicenseRequired` will fail identically on
 * every run; a 429 or socket reset will not.
 */
function classifyStepError(e) {
  const status = Number(e && e.status) || null;
  const code = graphErrorCode(e);
  const msg = String((e && e.message) || "");
  if (code && LICENCE_CODES.test(code)) return ERROR_KIND.LICENCE;
  if (/license/i.test(msg) && /premium|P2|P1|Governance/i.test(msg)) return ERROR_KIND.LICENCE;
  if (status === 401 || status === 403) return ERROR_KIND.DENIED;
  if (code && DENIED_CODES.test(code)) return ERROR_KIND.DENIED;
  if (isTransientError(e) || status === 429 || (status && status >= 500)) {
    return ERROR_KIND.TRANSIENT;
  }
  if (status === 400 || status === 404) {
    if (code && UNSUPPORTED_CODES.test(code)) return ERROR_KIND.UNSUPPORTED;
    if (/Invalid filter|Could not find a property|not supported|unsupported/i.test(msg)) {
      return ERROR_KIND.UNSUPPORTED;
    }
    return ERROR_KIND.UNSUPPORTED;
  }
  return ERROR_KIND.ERROR;
}

function createIo(outDir, opts = {}) {
  const manifest = {
    version: 1,
    startedAt: new Date().toISOString(),
    finishedAt: null,
    artifacts: {},
    steps: {},
  };

  const manifestPath = path.join(outDir, MANIFEST_NAME);
  /** Prior run's manifest, when resuming. */
  const previous = opts.previousManifest || null;
  /**
   * Only the collector owns the manifest. Post-processing passes (analyzer,
   * report) reuse this helper to write files but must not overwrite the record
   * of what the collection actually managed to fetch.
   */
  const tracking = opts.manifest !== false;

  function flushManifest() {
    if (!tracking) return;
    try {
      fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), "utf8");
    } catch {
      /* manifest is best-effort; never abort a run over it */
    }
  }

  function recordArtifact(name, status, extra = {}) {
    manifest.artifacts[name] = {
      status,
      at: new Date().toISOString(),
      ...extra,
    };
    flushManifest();
  }

  function recordStep(label, status, extra = {}) {
    manifest.steps[label] = {
      status,
      at: new Date().toISOString(),
      ...extra,
    };
    flushManifest();
  }

  function saveJson(name, data, meta = {}) {
    const p = path.join(outDir, name);
    fs.writeFileSync(p, JSON.stringify(data, null, 2), "utf8");
    const empty =
      data == null ||
      (Array.isArray(data) && !data.length) ||
      (typeof data === "object" && !Array.isArray(data) && !Object.keys(data).length);
    if (!name.startsWith("ERROR_")) {
      recordArtifact(name, empty ? STATUS.EMPTY : STATUS.OK, meta);
    }
    console.log(`  ✓ ${name}`);
    return p;
  }

  /**
   * @param {object} [meta.status] force a status (e.g. STATUS.FAILED when the
   *   caller knows the source errored and the empty array is not real data)
   */
  function saveCsv(name, rows, meta = {}) {
    const p = path.join(outDir, name);
    const count = rows ? rows.length : 0;
    if (!count) {
      fs.writeFileSync(p, "", "utf8");
      recordArtifact(name, meta.status || STATUS.EMPTY, { rows: 0, ...meta });
      console.log(`  ✓ ${name} (empty)`);
      return p;
    }
    fs.writeFileSync(p, toCsv(rows), "utf8");
    recordArtifact(name, meta.status || (rows.truncated ? STATUS.PARTIAL : STATUS.OK), {
      rows: count,
      truncated: rows.truncated || undefined,
      ...meta,
    });
    console.log(`  ✓ ${name} (${count} rows)`);
    return p;
  }

  function softSaveError(label, e) {
    const name = `ERROR_${errorLabel(label)}.json`;
    const kind = classifyStepError(e);
    const code = graphErrorCode(e);
    const payload = {
      error: e.message,
      status: e.status || null,
      code: code || undefined,
      kind,
      transient: kind === ERROR_KIND.TRANSIENT || undefined,
      details: e.details || undefined,
      at: new Date().toISOString(),
    };
    fs.writeFileSync(path.join(outDir, name), JSON.stringify(payload, null, 2), "utf8");
    recordStep(label, STATUS.FAILED, {
      error: String(e.message || e).split("\n")[0].slice(0, 300),
      httpStatus: e.status || null,
      code: code || undefined,
      kind,
      transient: kind === ERROR_KIND.TRANSIENT || undefined,
    });
    console.log(`  ✓ ${name}`);
  }

  /** Clear a stale ERROR_* file when a step later succeeds (matters on --resume). */
  function clearError(label) {
    const p = path.join(outDir, `ERROR_${errorLabel(label)}.json`);
    try {
      if (fs.existsSync(p)) fs.unlinkSync(p);
    } catch {
      /* ignore */
    }
  }

  /**
   * Run a collection step, converting any failure into a recorded `null`.
   *
   * Unlike the six copies this replaces, transient failures are retried: the
   * network layer already retries individual requests, but a step can span many
   * requests and still lose the race, so one whole-step retry is cheap insurance
   * on a 2-hour run.
   */
  async function soft(label, fn, { retries = 1, retryDelayMs = 4000 } = {}) {
    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        const value = await fn();
        recordStep(label, STATUS.OK);
        clearError(label);
        return value;
      } catch (e) {
        const transient = isTransientError(e) || e.status === 429 || e.status >= 500;
        if (attempt < retries && transient) {
          console.warn(
            `  ↻ ${label}: ${String(e.message).split("\n")[0].slice(0, 120)} — retrying step`
          );
          await new Promise((r) => setTimeout(r, retryDelayMs));
          continue;
        }
        console.warn(`  ⚠ ${label}: ${String(e.message).split("\n")[0]}`);
        softSaveError(label, e);
        return null;
      }
    }
    return null;
  }

  /** Mark a step as deliberately not run (missing permission, capability off). */
  function skip(label, reason) {
    recordStep(label, STATUS.SKIPPED, { reason });
  }

  /**
   * True when a previous run already produced this artifact successfully, so a
   * `--resume` pass can leave it alone.
   */
  function alreadyCollected(name) {
    if (!previous || !previous.artifacts) return false;
    const a = previous.artifacts[name];
    if (!a) return false;
    if (a.status !== STATUS.OK && a.status !== STATUS.EMPTY) return false;
    return fs.existsSync(path.join(outDir, name));
  }

  function finish(extra = {}) {
    manifest.finishedAt = new Date().toISOString();
    Object.assign(manifest, extra);
    flushManifest();
    return manifest;
  }

  flushManifest();

  return {
    outDir,
    saveJson,
    saveCsv,
    softSaveError,
    soft,
    skip,
    clearError,
    alreadyCollected,
    recordArtifact,
    recordStep,
    finish,
    manifest,
    STATUS,
  };
}

/** Free-function form for the `soft(label, fn, io)` call sites across modules. */
function soft(label, fn, io, opts) {
  return io.soft(label, fn, opts);
}

function readManifest(outDir) {
  try {
    return JSON.parse(fs.readFileSync(path.join(outDir, MANIFEST_NAME), "utf8"));
  } catch {
    return null;
  }
}

module.exports = {
  createIo,
  readManifest,
  soft,
  STATUS,
  MANIFEST_NAME,
  ERROR_KIND,
  classifyStepError,
  graphErrorCode,
};
