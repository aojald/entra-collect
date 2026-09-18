const test = require("node:test");
const assert = require("node:assert");
const {
  parseReleaseHealthText,
  parseOsBuild,
  patchStatus,
  resolvePatchBaseline,
  FALLBACK_PATCH_TUESDAY,
} = require("../lib/patchTuesday");

const SAMPLE = `
Version 25H2 (OS build 26200)

| Servicing option | Update type | Availability date | Build | KB article |
| --- | --- | --- | --- | --- |
| General Availability Channel | 2026-09 OOB | 2026-09-14 | 26200.9457 | KB5129195 |
| General Availability Channel | 2026-09 B | 2026-09-08 | 26200.9445 | KB5124008 |
| General Availability Channel | 2026-08 B | 2026-08-11 | 26200.9168 | KB5121003 |

Version 24H2 (OS build 26100)

| Servicing option | Update type | Availability date | Build | KB article |
| --- | --- | --- | --- | --- |
| LTSC • General Availability Channel | 2026-09 OOB | 2026-09-14 | 26100.9457 | KB5129195 |
| LTSC • General Availability Channel | 2026-09 B | 2026-09-08 | 26100.9445 | KB5124008 |
`;

test("parses Learn release-health history: B is Patch Tuesday, OOB is newer", () => {
  const builds = parseReleaseHealthText(SAMPLE);
  assert.equal(builds["26200"].minUbr, 9445);
  assert.equal(builds["26200"].kb, "KB5124008");
  assert.equal(builds["26200"].oobUbr, 9457);
  assert.equal(builds["26100"].minUbr, 9445);
  assert.equal(builds["26100"].patchTuesdayDate, "2026-09-08");
});

test("parseOsBuild accepts full, dotted, or major-only strings", () => {
  assert.deepEqual(parseOsBuild("10.0.26100.9106").ubr, 9106);
  assert.equal(parseOsBuild("26100.9106").major, "26100");
  assert.equal(parseOsBuild("26100").ubr, null);
  assert.equal(parseOsBuild("26100").incomplete, true);
});

test("a July UBR is behind the September Learn baseline", () => {
  const builds = parseReleaseHealthText(SAMPLE);
  const baseline = { builds };
  const behind = patchStatus({ major: "26100", ubr: 8875 }, baseline);
  assert.equal(behind.status, "BehindPatchTuesday");
  assert.ok(behind.lagUbr > 0);
  const current = patchStatus({ major: "26100", ubr: 9457 }, baseline);
  assert.equal(current.status, "CurrentOrNewer");
  const oobPending = patchStatus({ major: "26100", ubr: 9445 }, baseline);
  assert.equal(oobPending.status, "PatchTuesdayOK_OOBPending");
});

test("resolvePatchBaseline uses Learn data when fetch works, else fallback", async () => {
  const live = await resolvePatchBaseline({
    urls: ["https://example.invalid/win11"],
    fetchPage: async () => SAMPLE,
  });
  assert.equal(live.source, "microsoft-learn");
  assert.equal(live.builds["26100"].minUbr, 9445);

  const offline = await resolvePatchBaseline({
    urls: ["https://example.invalid/win11"],
    fetchPage: async () => {
      throw new Error("network down");
    },
  });
  assert.equal(offline.source, "fallback");
  assert.equal(offline.asOf, FALLBACK_PATCH_TUESDAY.asOf);
  assert.equal(offline.stale, true);
});
