import { test, expect } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { extractTokens, lint, loadReferences } from "./lib/extract.ts";

const ROOT = join(import.meta.dir, "..");
const intake = JSON.parse(readFileSync(join(ROOT, "intake/fixtures/brute-force-dc-chain.intake.json"), "utf8"));
const good = readFileSync(join(ROOT, "evals/samples/brute-force-dc-chain.good.brief.md"), "utf8");
const bad = readFileSync(join(ROOT, "evals/samples/brute-force-dc-chain.bad.brief.md"), "utf8");

test("reference tables load and carry the IDs the fixtures rely on", () => {
  const refs = loadReferences();
  for (const id of ["T1110", "T1110.001", "T1078", "T1021.002", "T1003.006", "T1071.001", "T1071.004"]) expect(refs.attack.has(id)).toBe(true);
  for (const id of ["DE.AE-03", "DE.CM-01", "RS.AN-03", "RS.MI-01", "PR.AA-05", "PR.IR-01"]) expect(refs.csf.has(id)).toBe(true);
  // CSF 1.1 identifiers must not be present.
  for (const id of ["PR.AC-4", "RS.AN-01", "DE.CM-04", "ID.AM-06"]) expect(refs.csf.has(id)).toBe(false);
  expect(refs.csf.size).toBe(106);
});

test("extractTokens ignores sha256 blobs and IP octets when looking for rule IDs", () => {
  const t = extractTokens("sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef and 10.0.0.50 and rule 100220");
  expect([...t.rule_id]).toEqual(["100220"]);
  expect([...t.ip]).toEqual(["10.0.0.50"]);
});

test("extractTokens catches CSF 1.1 shapes so they can be rejected", () => {
  const t = extractTokens("maps to PR.AC-4 and DE.AE-03");
  expect([...t.csf].sort()).toEqual(["DE.AE-03", "PR.AC-4"]);
});

test("good sample brief passes: every citation traces to the intake or a table", () => {
  const r = lint(good, intake);
  expect(r.unknown).toEqual([]);
  expect(r.pass).toBe(true);
  expect(r.counts.rule_id).toBe(4);
  expect(r.counts.host).toBe(2);
  expect(r.counts.ip).toBe(0);
});

test("bad sample brief fails on exactly the planted fabrications", () => {
  const r = lint(bad, intake);
  expect(r.pass).toBe(false);
  const flagged = r.unknown.map((u) => `${u.kind}:${u.token}`).sort();
  expect(flagged).toEqual(["attack:T9999", "csf:PR.AC-4", "host:talonghost", "ip:10.0.0.50", "rule_id:100999"].sort());
});

test("quiet-day intake: any host, rule ID or technique is a fabrication", () => {
  const quiet = JSON.parse(readFileSync(join(ROOT, "intake/fixtures/quiet-day.intake.json"), "utf8"));
  const r = lint("No findings. Pipeline liveness unconfirmed.", quiet);
  expect(r.pass).toBe(true);
  const r2 = lint("talondc01 fired rule 100220 (T1003.006)", quiet);
  expect(r2.unknown.map((u) => u.kind).sort()).toEqual(["host", "rule_id"]);
});

// Real briefs produced by /casa:investigate on the fixtures (kept as *.run1.brief.md) must
// stay lint-clean against the intake they came from.
import { readdirSync } from "node:fs";
for (const f of readdirSync(join(ROOT, "evals/samples")).filter((n) => /\.run\d+\.brief\.md$/.test(n)).sort()) {
  const fixture = f.replace(/\.run\d+\.brief\.md$/, ""); // may carry a .v2 suffix: same intake name
  test(`run sample ${f} traces every citation to ${fixture}`, () => {
    const brief = readFileSync(join(ROOT, "evals/samples", f), "utf8");
    const ik = JSON.parse(readFileSync(join(ROOT, `intake/fixtures/${fixture}.intake.json`), "utf8"));
    const r = lint(brief, ik);
    expect(r.unknown).toEqual([]);
    expect(r.pass).toBe(true);
  });
}

test("port notations are not rule IDs; a bare five-digit number still is", () => {
  const t = extractTokens("port 49152 open, talonmacbook:8443/tcp listening, ports 50000 and 60122/udp, rule 60122 fired, 12345 seen");
  expect([...t.rule_id].sort()).toEqual(["12345", "60122"]);
});

test("the host prefix is a literal, not a regex: metacharacters are refused, the rest escaped", () => {
  expect(() => extractTokens("x", "ta(lon")).toThrow("host prefix");
  expect(() => extractTokens("x", ".*")).toThrow("host prefix");
  expect(() => extractTokens("x", "")).toThrow("host prefix");
  const t = extractTokens("lab-dc01 and lab-ws02 and lab- and labx and slab-dc01", "lab-");
  expect([...t.host].sort()).toEqual(["lab-dc01", "lab-ws02"]);
  expect([...extractTokens("talondc01 talon talonx", "talon").host].sort()).toEqual(["talondc01", "talonx"]);
});
