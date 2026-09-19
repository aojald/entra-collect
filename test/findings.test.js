const test = require("node:test");
const assert = require("node:assert");
const { decorateFinding, decorateFindings, SCHEMA_VERSION, STATUS } = require("../lib/findings");

test("inventory findings get Status / Confidence / LicenceRequired / Rationale", () => {
  const gap = decorateFinding({ Severity: "High", Area: "CA", Detail: "No enforced CA policy blocks legacy auth" });
  assert.equal(gap.Status, STATUS.FAIL);
  assert.equal(gap.Confidence, "High");
  assert.equal(gap.LicenceRequired, "P1");

  const cov = decorateFinding({
    Severity: "High",
    Area: "Coverage",
    Detail: "Conditional Access policies could not be collected — CA coverage is unknown for this run",
  });
  assert.equal(cov.Status, STATUS.NOT_EVALUATED);
  assert.equal(cov.Confidence, "");
  assert.match(cov.Rationale, /not a pass/i);

  const na = decorateFinding({
    Severity: "Info",
    Area: "Licensing",
    Detail: "No Entra ID P2 service plan detected — Identity Protection / PIM checks are scored NotApplicable, not Fail",
  });
  assert.equal(na.Status, STATUS.NOT_APPLICABLE);

  const risky = decorateFinding({ Severity: "High", Area: "IdentityProtection", Detail: "3 users atRisk" });
  assert.equal(risky.LicenceRequired, "P2");

  const partial = decorateFinding({ Severity: "High", Area: "LegacyAuth", Detail: "12 sign-ins (partial: page budget reached at 999 most recent events)" });
  assert.equal(partial.Confidence, "Medium");

  const heuristic = decorateFinding({ Severity: "Info", Area: "BreakGlass", Detail: "Likely break-glass account x — verify" });
  assert.equal(heuristic.Status, STATUS.INFO);
  assert.equal(heuristic.Confidence, "Low");
});

test("decoration is idempotent and keeps explicit values", () => {
  const once = decorateFindings([{ Severity: "Medium", Area: "Guests", Detail: "x", Status: "Fail", Confidence: "Low" }]);
  const twice = decorateFindings(once);
  assert.deepEqual(twice, once);
  assert.equal(once[0].Confidence, "Low");
  assert.equal(SCHEMA_VERSION, 2);
});
