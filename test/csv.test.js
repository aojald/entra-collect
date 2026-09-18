const test = require("node:test");
const assert = require("node:assert");
const { parseCsv, toCsv, escapeCsv, detectDelimiter } = require("../lib/csv");

test("parses a plain semicolon file", () => {
  const rows = parseCsv("A;B\n1;2\n3;4");
  assert.deepStrictEqual(rows, [
    { A: "1", B: "2" },
    { A: "3", B: "4" },
  ]);
});

test("keeps a quoted field containing the delimiter intact", () => {
  const rows = parseCsv('A;B\n"x;y";z');
  assert.strictEqual(rows[0].A, "x;y");
  assert.strictEqual(rows[0].B, "z");
});

test("keeps a quoted field containing newlines on one record", () => {
  // Regression: splitting on "\n" before handling quotes shifted every later
  // column onto the wrong header (Secure Score Remediation is multi-line HTML).
  const rows = parseCsv('Id;Remediation;Impact\n1;"line one\nline two";Low\n2;plain;High');
  assert.strictEqual(rows.length, 2);
  assert.strictEqual(rows[0].Remediation, "line one\nline two");
  assert.strictEqual(rows[0].Impact, "Low");
  assert.strictEqual(rows[1].Impact, "High");
});

test("unescapes doubled quotes", () => {
  const rows = parseCsv('A;B\n"say ""hi""";2');
  assert.strictEqual(rows[0].A, 'say "hi"');
});

test("handles CRLF and a trailing newline", () => {
  const rows = parseCsv("A;B\r\n1;2\r\n");
  assert.deepStrictEqual(rows, [{ A: "1", B: "2" }]);
});

test("ignores a UTF-8 BOM", () => {
  assert.strictEqual(parseCsv("\uFEFFA;B\n1;2")[0].A, "1");
});

test("returns [] for empty or whitespace input", () => {
  assert.deepStrictEqual(parseCsv(""), []);
  assert.deepStrictEqual(parseCsv("   \n "), []);
});

test("detects comma files but not commas inside quoted headers", () => {
  assert.strictEqual(detectDelimiter("a,b\n1,2"), ",");
  assert.strictEqual(detectDelimiter('"a,b";c\n1;2'), ";");
});

test("missing trailing cells become empty strings", () => {
  const rows = parseCsv("A;B;C\n1;2");
  assert.deepStrictEqual(rows[0], { A: "1", B: "2", C: "" });
});

test("escapeCsv quotes only when necessary", () => {
  assert.strictEqual(escapeCsv("plain"), "plain");
  assert.strictEqual(escapeCsv("a;b"), '"a;b"');
  assert.strictEqual(escapeCsv("a\nb"), '"a\nb"');
  assert.strictEqual(escapeCsv(null), "");
});

test("round-trips values that would break a naive parser", () => {
  const rows = [
    { Id: "1", Text: 'multi\nline; with "quotes"', Impact: "Low" },
    { Id: "2", Text: "plain", Impact: "High" },
  ];
  assert.deepStrictEqual(parseCsv(toCsv(rows)), rows);
});

test("formula-looking cells are neutralised, numbers are not", () => {
  assert.strictEqual(escapeCsv('=HYPERLINK("http://x")'), `"'=HYPERLINK(""http://x"")"`);
  assert.strictEqual(escapeCsv("+cmd|' /C calc'!A0"), `'+cmd|' /C calc'!A0`);
  assert.strictEqual(escapeCsv("@SUM(1)"), "'@SUM(1)");
  assert.strictEqual(escapeCsv("-12"), "-12");
  assert.strictEqual(escapeCsv(-12), "-12");
  assert.strictEqual(escapeCsv("+3.5"), "+3.5");
  assert.strictEqual(escapeCsv("-jane.doe@contoso.com"), "'-jane.doe@contoso.com");
  const rows = [{ Name: "=1+1", DaysLeft: -3 }];
  const back = parseCsv(toCsv(rows));
  assert.strictEqual(back[0].Name, "'=1+1");
  assert.strictEqual(Number(back[0].DaysLeft), -3);
});

test("toCsv uses the union of keys across rows", () => {
  const csv = toCsv([{ A: 1 }, { B: 2 }]);
  assert.strictEqual(csv.split("\n")[0], "A;B");
  assert.deepStrictEqual(parseCsv(csv), [
    { A: "1", B: "" },
    { A: "", B: "2" },
  ]);
});
