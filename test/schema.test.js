const test = require("node:test");
const assert = require("node:assert");
const {
  pickIdentityDialect,
  pickSpnDialect,
  kqlDeviceCode,
  kqlSpnSignIns,
  kqlLegacySuccess,
  kqlGraphApiAuditWrites,
  graphApiAuditActorColumn,
} = require("../lib/schema");

function mockSchema(present) {
  const tables = {};
  for (const [name, opts] of Object.entries(present)) {
    const hasRows = opts === true || (opts && opts.hasRows !== false);
    tables[name] = { available: true, hasRows };
  }
  return {
    tables,
    has(n) {
      return !!(tables[n] && tables[n].available);
    },
  };
}

test("new XDR table wins over IdentityLogonEvents (InfraVia-style tenant)", () => {
  const id = pickIdentityDialect(
    mockSchema({
      EntraIdSignInEvents: true,
      IdentityLogonEvents: true,
    })
  );
  assert.equal(id.dialect, "entraid");
  assert.equal(id.table, "EntraIdSignInEvents");
});

test("legacy AADSignInEventsBeta still used when it is the only XDR table", () => {
  const id = pickIdentityDialect(
    mockSchema({
      AADSignInEventsBeta: true,
      IdentityLogonEvents: true,
    })
  );
  assert.equal(id.dialect, "aad");
  assert.equal(id.table, "AADSignInEventsBeta");
});

test("during coexistence, prefer the XDR alias that actually has rows", () => {
  const preferNew = pickIdentityDialect(
    mockSchema({
      EntraIdSignInEvents: { hasRows: true },
      AADSignInEventsBeta: { hasRows: true },
    })
  );
  assert.equal(preferNew.table, "EntraIdSignInEvents");

  const preferPopulatedLegacy = pickIdentityDialect(
    mockSchema({
      EntraIdSignInEvents: { hasRows: false },
      AADSignInEventsBeta: { hasRows: true },
    })
  );
  assert.equal(preferPopulatedLegacy.table, "AADSignInEventsBeta");
  assert.equal(preferPopulatedLegacy.dialect, "aad");
});

test("empty EntraIdSignInEvents is still preferred over IdentityLogonEvents", () => {
  const id = pickIdentityDialect(
    mockSchema({
      EntraIdSignInEvents: { hasRows: false },
      IdentityLogonEvents: { hasRows: true },
    })
  );
  assert.equal(id.dialect, "entraid");
  assert.equal(id.table, "EntraIdSignInEvents");
});

test("Sentinel SigninLogs is used when no XDR identity table exists", () => {
  const id = pickIdentityDialect(mockSchema({ SigninLogs: true }));
  assert.equal(id.dialect, "signinlogs");
});

test("IdentityLogonEvents is last-resort when no Entra/Sentinel table exists", () => {
  const id = pickIdentityDialect(mockSchema({ IdentityLogonEvents: true }));
  assert.equal(id.dialect, "identitylogon");
});

test("no identity tables → null dialect", () => {
  const id = pickIdentityDialect(mockSchema({ DeviceInfo: true }));
  assert.equal(id.dialect, null);
  assert.equal(id.table, null);
});

test("SPN dialect prefers EntraIdSpnSignInEvents then AADSpnSignInEventsBeta", () => {
  assert.equal(
    pickSpnDialect(mockSchema({ EntraIdSpnSignInEvents: true })).table,
    "EntraIdSpnSignInEvents"
  );
  assert.equal(
    pickSpnDialect(mockSchema({ AADSpnSignInEventsBeta: true })).table,
    "AADSpnSignInEventsBeta"
  );
  assert.equal(pickSpnDialect(mockSchema({ DeviceInfo: true })).table, null);
});

test("device-code KQL for entraid uses EntraIdSignInEvents columns, not AuthenticationProtocol", () => {
  const q = kqlDeviceCode(90, "entraid");
  assert.match(q, /EntraIdSignInEvents/);
  assert.doesNotMatch(q, /AADSignInEventsBeta/);
  assert.match(q, /ClientAppUsed/);
  assert.doesNotMatch(q, /AuthenticationProtocol =~/);
});

test("device-code KQL for legacy aad is unchanged", () => {
  const q = kqlDeviceCode(90, "aad");
  assert.match(q, /AADSignInEventsBeta/);
  assert.doesNotMatch(q, /EntraIdSignInEvents/);
  assert.match(q, /AuthenticationProtocol/);
});

test("legacy-auth KQL exists for both XDR dialects", () => {
  assert.match(kqlLegacySuccess(90, "entraid"), /EntraIdSignInEvents/);
  assert.match(kqlLegacySuccess(90, "aad"), /AADSignInEventsBeta/);
});

test("SPN KQL uses the picked table name", () => {
  const neu = kqlSpnSignIns(90, { table: "EntraIdSpnSignInEvents", dialect: "entraidspn" });
  const old = kqlSpnSignIns(90, "aadspn");
  assert.match(neu, /EntraIdSpnSignInEvents/);
  assert.match(old, /AADSpnSignInEventsBeta/);
  assert.match(neu, /ServicePrincipalId/);
});

test("GraphAPIAuditEvents KQL never groups by AccountDisplayName", () => {
  const cols = [
    "IdentityProvider",
    "ApplicationId",
    "AccountObjectId",
    "RequestMethod",
    "ResponseStatusCode",
    "RequestUri",
    "IpAddress",
    "ServicePrincipalId",
  ];
  const [focused, broad] = kqlGraphApiAuditWrites({ sampleColumns: cols });
  for (const q of [focused, broad]) {
    assert.doesNotMatch(q, /AccountDisplayName/);
    assert.match(q, /AccountObjectId/);
    assert.match(q, /GraphAPIAuditEvents/);
  }
  assert.equal(graphApiAuditActorColumn(cols), "AccountObjectId");
  assert.equal(graphApiAuditActorColumn([]), "AccountObjectId");
});
