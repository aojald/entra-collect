/**
 * Output contract for findings (schema version 2).
 *
 * Inventory findings (`00_Findings.csv`) and expert narratives
 * (`00_Expert_Findings.*`) share four extra columns so a reader — human or
 * machine — can tell a verified gap from an unmeasured one:
 *
 *   Status          Fail | Info | NotEvaluated | NotApplicable
 *   Confidence      High | Medium | Low
 *   LicenceRequired "" | P1 | P2 | Governance | E5
 *   Rationale       one line on why this status / severity
 */
const SCHEMA_VERSION = 2;

/** One severity vocabulary. Inventory findings never emit Critical/Low today; kept for narratives. */
const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"];

const STATUS = {
  FAIL: "Fail",
  INFO: "Info",
  NOT_EVALUATED: "NotEvaluated",
  NOT_APPLICABLE: "NotApplicable",
};

const NOT_EVALUATED_RE =
  /could not be collected|not readable|is unknown|not evaluated|inconclusive|unavailable with this session|not collected|export failed/i;
const NOT_APPLICABLE_RE = /not applicable|scored notapplicable|NotApplicable, not Fail/i;
const LOW_CONFIDENCE_RE = /heuristic|looks? like|likely|probably|suggests|best-effort|may be/i;
const MEDIUM_CONFIDENCE_RE =
  /partial|sampled|sample\b|evaluated \d+ of|capped|truncated|first \d+|most recent|page budget|not counted|via All-users|verify/i;

const P2_AREAS = /^(IdentityProtection|Risk)$/i;
const P1_AREAS = /^(CA|Coverage|CA-|ConditionalAccess)$/i;

/**
 * Pure: add Status / Confidence / LicenceRequired / Rationale to an inventory
 * finding without changing its Severity / Area / Detail.
 */
function decorateFinding(f) {
  if (!f || typeof f !== "object") return f;
  const detail = String(f.Detail || "");
  const severity = String(f.Severity || "Info");
  const area = String(f.Area || "");

  let status = f.Status;
  if (!status) {
    if (NOT_APPLICABLE_RE.test(detail)) status = STATUS.NOT_APPLICABLE;
    else if (area === "Coverage" || NOT_EVALUATED_RE.test(detail)) status = STATUS.NOT_EVALUATED;
    else if (/^info$/i.test(severity)) status = STATUS.INFO;
    else status = STATUS.FAIL;
  }

  let confidence = f.Confidence;
  if (!confidence) {
    if (status === STATUS.NOT_EVALUATED) confidence = "";
    else if (LOW_CONFIDENCE_RE.test(detail)) confidence = "Low";
    else if (MEDIUM_CONFIDENCE_RE.test(detail)) confidence = "Medium";
    else confidence = "High";
  }

  let licence = f.LicenceRequired;
  if (licence == null) {
    if (P2_AREAS.test(area) || /Identity Protection|risky users|risk detection/i.test(detail)) licence = "P2";
    else if (P1_AREAS.test(area) && /Conditional Access|CA policy|enforced CA|no enforced/i.test(detail)) licence = "P1";
    else licence = "";
  }

  const rationale =
    f.Rationale ||
    (status === STATUS.NOT_EVALUATED
      ? "Input not collected — unknown, not a pass"
      : status === STATUS.NOT_APPLICABLE
        ? "Tenant cannot be in the tested state (licence / design)"
        : status === STATUS.INFO
          ? "Inventory / context"
          : "");

  return { ...f, Status: status, Confidence: confidence, LicenceRequired: licence, Rationale: rationale };
}

function decorateFindings(list) {
  return (list || []).map(decorateFinding);
}

/** Narrative status is simpler: everything is a verdict unless Info. */
function narrativeStatus(n) {
  if (n.Status) return n.Status;
  return /^info$/i.test(String(n.Severity || "")) ? STATUS.INFO : STATUS.FAIL;
}

module.exports = {
  SCHEMA_VERSION,
  SEVERITIES,
  STATUS,
  decorateFinding,
  decorateFindings,
  narrativeStatus,
};
