const test = require("node:test");
const assert = require("node:assert");
const { TokenPool, isTokenExpired } = require("../lib/tokens");

function makeJwt(payload) {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${b64({ alg: "none" })}.${b64(payload)}.sig`;
}

const inSeconds = (n) => Math.floor(Date.now() / 1000) + n;

function graphToken(overrides = {}) {
  return makeJwt({
    aud: "https://graph.microsoft.com",
    appid: "app-1",
    scp: "Directory.Read.All",
    exp: inSeconds(3600),
    ...overrides,
  });
}

test("expiry accounts for the safety skew", () => {
  assert.equal(isTokenExpired({ exp: inSeconds(3600) }), false);
  assert.equal(isTokenExpired({ exp: inSeconds(30) }), true, "within skew");
  assert.equal(isTokenExpired({ exp: inSeconds(-10) }), true);
  assert.equal(isTokenExpired({}), false, "no exp claim: cannot judge");
});

test("expired tokens are neither accepted nor served", () => {
  const pool = new TokenPool();
  assert.equal(pool.add(graphToken({ exp: inSeconds(-60) })), null);
  assert.equal(pool.list().length, 0);

  pool.add(graphToken());
  assert.equal(pool.list().length, 1);
});

test("a pool that has gone stale is refilled by a registered refresher", async () => {
  const pool = new TokenPool();
  pool.add(graphToken({ exp: inSeconds(200), scp: "Directory.Read.All" }));
  assert.equal(pool.list().length, 1);

  // Simulate the token ageing out mid-run.
  for (const entry of pool.byHash.values()) entry.payload.exp = inSeconds(-1);
  assert.equal(pool.list().length, 0);

  let minted = 0;
  pool.onRefresh(async () => {
    minted++;
    return graphToken({ scp: "Directory.Read.All Policy.Read.All" });
  }, "test");

  assert.equal(await pool.refresh(), true);
  assert.equal(minted, 1);
  assert.equal(pool.list().length, 1);
  assert.ok(pool.bestPolicy(), "refreshed token is usable for CA");
});

test("refresh attempts are throttled so 401 bursts do not stampede", async () => {
  const pool = new TokenPool();
  let calls = 0;
  pool.onRefresh(async () => {
    calls++;
    return graphToken();
  }, "test");

  await pool.refresh();
  await pool.refresh();
  assert.equal(calls, 1, "second call within the interval is suppressed");
});

test("pool locks to first token tid and rejects foreign-tenant tokens", () => {
  const pool = new TokenPool();
  const a = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
  const b = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
  assert.ok(pool.add(graphToken({ tid: a, scp: "Directory.Read.All" })));
  assert.equal(pool.tenantId(), a);
  assert.equal(pool.add(graphToken({ tid: b, appid: "app-2", scp: "Directory.Read.All" })), null);
  assert.equal(pool.list().length, 1);
  assert.equal(pool.rejectedMixed.length, 1);
  assert.equal(pool.rejectedMixed[0].tid, b);
  const check = pool.assertSingleTenant();
  assert.equal(check.ok, true);
  assert.equal(check.tid, a);
});

test("--tenant lock rejects a first token from another tenant", () => {
  const pool = new TokenPool();
  const pinned = "cccccccc-cccc-cccc-cccc-cccccccccccc";
  const other = "dddddddd-dddd-dddd-dddd-dddddddddddd";
  pool.lockTenant(pinned, "--tenant");
  assert.equal(pool.add(graphToken({ tid: other })), null);
  assert.equal(pool.list().length, 0);
  assert.ok(pool.add(graphToken({ tid: pinned })));
  assert.equal(pool.list().length, 1);
});

test("lockTenant refuses to switch tenants", () => {
  const pool = new TokenPool();
  pool.lockTenant("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "first");
  assert.throws(() => pool.lockTenant("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "second"));
});

test("audiences are matched on the exact host, not a substring", () => {
  const { isGraphAud, isMtpAud } = require("../lib/tokens");
  assert.equal(isGraphAud("https://graph.microsoft.com"), true);
  assert.equal(isGraphAud("https://graph.microsoft.com/"), true);
  assert.equal(isGraphAud("00000003-0000-0000-c000-000000000000"), true);
  assert.equal(isGraphAud("https://graph.microsoft.com.evil.example"), false);
  assert.equal(isGraphAud("https://evil.example/?x=graph.microsoft.com"), false);
  assert.equal(isMtpAud("https://api-eu.security.microsoft.com"), true);
  assert.equal(isMtpAud("https://api.security.microsoft.com.attacker.tld"), false);

  const pool = new TokenPool();
  assert.equal(pool.add(graphToken({ aud: "https://graph.microsoft.com.evil.example" })), null);
  assert.ok(pool.add(graphToken()));
});

test("portal hunting refuses headers from another tenant once locked", () => {
  const { portalSession, mtpBaseFromAud } = require("../lib/hunt");
  portalSession.lockTenant("11111111-1111-1111-1111-111111111111");
  assert.equal(
    portalSession._tidMatches({ "x-tid": "11111111-1111-1111-1111-111111111111" }),
    true
  );
  assert.equal(
    portalSession._tidMatches({ "x-tid": "22222222-2222-2222-2222-222222222222" }),
    false
  );
  assert.equal(portalSession._tidMatches({}), true, "no tid: cannot judge");
  assert.equal(mtpBaseFromAud("https://api.security.microsoft.com"), "https://api.security.microsoft.com");
  assert.equal(mtpBaseFromAud("https://api.security.microsoft.com.evil.tld"), null);
  portalSession.expectedTid = null;
});
