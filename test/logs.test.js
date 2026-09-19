const test = require("node:test");
const assert = require("node:assert");
const {
  getSignIns,
  buildLegacyFilter,
  buildFailureFilter,
  buildDeviceCodeFilter,
  isLegacyClient,
  LEGACY_CLIENT_APPS,
} = require("../lib/logs");

const G = {
  GRAPH: "https://graph.microsoft.com/v1.0",
  GRAPH_BETA: "https://graph.microsoft.com/beta",
};

test("legacy filter is server-side over the whole window and success only", () => {
  const f = buildLegacyFilter("2026-06-01T00:00:00.000Z");
  assert.ok(f.startsWith("createdDateTime ge 2026-06-01T00:00:00.000Z and status/errorCode eq 0 and ("));
  for (const c of LEGACY_CLIENT_APPS) assert.ok(f.includes(`clientAppUsed eq '${c}'`), c);
  assert.ok(!/sample|top/i.test(f));
  assert.equal(buildFailureFilter("X"), "createdDateTime ge X and status/errorCode ne 0");
  assert.equal(buildDeviceCodeFilter("X"), "createdDateTime ge X and authenticationProtocol eq 'deviceCode'");
});

test("isLegacyClient matches exact Entra clientAppUsed values", () => {
  assert.equal(isLegacyClient({ clientAppUsed: "Exchange ActiveSync" }), true);
  assert.equal(isLegacyClient({ clientAppUsed: "Other clients" }), true);
  assert.equal(isLegacyClient({ clientAppUsed: "Browser" }), false);
  assert.equal(isLegacyClient({ clientAppUsed: "Mobile Apps and Desktop clients" }), false);
});

test("getSignIns flags truncation when the page budget is hit with a nextLink left", async () => {
  const calls = [];
  const graph = {
    ...G,
    get: async (url) => {
      calls.push(url);
      return { value: [{ id: calls.length }], "@odata.nextLink": `${url}&page=${calls.length}` };
    },
  };
  const items = await getSignIns(graph, "createdDateTime ge X", { maxPages: 3 });
  assert.equal(items.length, 3);
  assert.equal(items.truncated, true);
  assert.equal(calls.length, 3);
  assert.ok(calls[0].startsWith(G.GRAPH_BETA), "beta first");

  const done = await getSignIns(
    { ...G, get: async () => ({ value: [{ id: 1 }] }) },
    "createdDateTime ge X",
    { maxPages: 3 }
  );
  assert.equal(done.length, 1);
  assert.equal(done.truncated, undefined);
});

test("beta:'only' never falls back to v1.0; beta:'prefer' does on a 400", async () => {
  const seen = [];
  const rejectBeta = async (url) => {
    seen.push(url);
    if (url.startsWith(G.GRAPH_BETA)) {
      const e = new Error("HTTP 400 bad filter");
      e.status = 400;
      throw e;
    }
    return { value: [{ id: "v1" }] };
  };
  await assert.rejects(
    () => getSignIns({ ...G, get: rejectBeta }, "f", { beta: "only" }),
    /HTTP 400/
  );
  seen.length = 0;
  const items = await getSignIns({ ...G, get: rejectBeta }, "f", { beta: "prefer" });
  assert.equal(items.length, 1);
  assert.ok(seen[0].startsWith(G.GRAPH_BETA) && seen[1].startsWith(G.GRAPH), "beta then v1");

  // A 403 is not a query-shape problem: no fallback, surface it.
  const forbid = async () => {
    const e = new Error("HTTP 403");
    e.status = 403;
    throw e;
  };
  await assert.rejects(() => getSignIns({ ...G, get: forbid }, "f", { beta: "prefer" }), /403/);
});
