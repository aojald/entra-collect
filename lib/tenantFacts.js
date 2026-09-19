/**
 * Tenant facts that change how a check must be scored.
 *
 * A Conditional Access "Fail" on a tenant that runs Security Defaults, or a
 * sign-in-risk "Fail" on a tenant without Entra ID P2, is not a gap the
 * customer can close — it is a licensing or design state. These facts let the
 * attack-path checks answer NotApplicable instead of Fail, and let the report
 * say so.
 */
const { soft } = require("./io");

/** servicePlanName fragments → capability flags. */
const PLAN_MATCHERS = {
  p1: /^AAD_PREMIUM$|^AAD_PREMIUM_P1$/i,
  p2: /^AAD_PREMIUM_P2$/i,
  governance: /IDENTITY_GOVERNANCE|ENTRA_ID_GOVERNANCE|AAD_GOVERNANCE/i,
  defenderForIdentity: /^ATA$|DEFENDER_FOR_IDENTITY/i,
  defenderForEndpointP2: /^WINDEFATP$|^MDATP/i,
  defenderForOffice: /^ATP_ENTERPRISE|^THREAT_INTELLIGENCE/i,
  intune: /^INTUNE_A$|^INTUNE_A_D$|^INTUNE_EDU$/i,
};

/**
 * Pure: derive licence capabilities from `GET /subscribedSkus`.
 * Only plans that are actually provisioned on a SKU with enabled units count.
 */
function deriveLicences(skus) {
  const flags = {};
  for (const k of Object.keys(PLAN_MATCHERS)) flags[k] = false;
  const skuRows = [];
  for (const sku of skus || []) {
    const enabled = Number(sku.prepaidUnits && sku.prepaidUnits.enabled) || 0;
    const consumed = Number(sku.consumedUnits) || 0;
    const plans = Array.isArray(sku.servicePlans) ? sku.servicePlans : [];
    const active = enabled > 0 && !/suspended|deleted/i.test(String(sku.capabilityStatus || ""));
    skuRows.push({
      SkuPartNumber: sku.skuPartNumber || "",
      SkuId: sku.skuId || "",
      Status: sku.capabilityStatus || "",
      Enabled: enabled,
      Consumed: consumed,
      Plans: plans.map((p) => p.servicePlanName).filter(Boolean).join(" | "),
    });
    if (!active) continue;
    for (const p of plans) {
      if (String(p.provisioningStatus || "Success").toLowerCase() === "disabled") continue;
      const name = String(p.servicePlanName || "");
      for (const [k, re] of Object.entries(PLAN_MATCHERS)) {
        if (re.test(name)) flags[k] = true;
      }
    }
  }
  // P2 implies P1 features.
  if (flags.p2) flags.p1 = true;
  return {
    ...flags,
    identityProtection: flags.p2,
    pim: flags.p2 || flags.governance,
    conditionalAccess: flags.p1,
    skus: skuRows,
  };
}

/**
 * @param {object} graph
 * @param {object} io
 * @param {object} inputs
 * @param {object|null} inputs.securityDefaults identitySecurityDefaultsEnforcementPolicy
 * @param {object|null} inputs.authMethods authenticationMethodsPolicy
 */
async function collectTenantFacts(graph, io, { securityDefaults = null, authMethods = null } = {}) {
  const skus = await soft(
    "subscribedSkus",
    () => graph.getAll(`${graph.GRAPH}/subscribedSkus`),
    io
  );
  const licences = Array.isArray(skus) ? deriveLicences(skus) : null;

  const facts = {
    securityDefaultsEnabled:
      securityDefaults && typeof securityDefaults.isEnabled === "boolean"
        ? securityDefaults.isEnabled
        : null,
    policyMigrationState:
      (authMethods && authMethods.policyMigrationState) || null,
    licences,
    licencesCollected: licences != null,
  };

  io.saveJson("01_tenant_facts.json", facts);
  if (licences) {
    io.saveCsv("01_Licences.csv", licences.skus);
  }
  return facts;
}

/** Convenience predicates that tolerate an unknown licence state. */
function hasP2(facts) {
  return !!(facts && facts.licences && facts.licences.p2);
}
function licencesKnown(facts) {
  return !!(facts && facts.licences);
}
function securityDefaultsOn(facts) {
  return !!(facts && facts.securityDefaultsEnabled === true);
}

module.exports = {
  collectTenantFacts,
  deriveLicences,
  hasP2,
  licencesKnown,
  securityDefaultsOn,
  PLAN_MATCHERS,
};
