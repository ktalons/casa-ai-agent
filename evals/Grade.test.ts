import { test, expect } from "bun:test";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { assertExpected, gradeMachine, mergeRubric, type Expected } from "./lib/grade.ts";

const ROOT = join(import.meta.dir, "..");
const read = (p: string) => readFileSync(join(ROOT, p), "utf8");
const json = (p: string) => JSON.parse(read(p));
const FIXTURES = ["brute-force-dc-chain", "beaconing-recon-delta", "quiet-day"];

for (const f of FIXTURES) {
  test(`expected.json for ${f} is structurally valid`, () => {
    const e = json(`intake/fixtures/${f}.expected.json`);
    expect(() => assertExpected(e)).not.toThrow();
    expect(e.fixture).toBe(f);
  });
}

test("assertExpected rejects bad shapes", () => {
  expect(() => assertExpected({ schema: "wrong" })).toThrow();
  const e = json("intake/fixtures/quiet-day.expected.json");
  expect(() => assertExpected({ ...e, confidence: "Critical" })).toThrow();
  expect(() => assertExpected({ ...e, must_cite: { ...e.must_cite, attack: ["T99"] } })).toThrow();
});

const bfExpected = json("intake/fixtures/brute-force-dc-chain.expected.json") as Expected;
const bfIntake = json("intake/fixtures/brute-force-dc-chain.intake.json");

test("good sample brief passes every machine check for brute-force-dc-chain", () => {
  const m = gradeMachine(read("evals/samples/brute-force-dc-chain.good.brief.md"), bfExpected, bfIntake);
  const failed = m.machine.filter((c) => !c.pass).map((c) => `${c.check}: ${c.detail}`);
  expect(failed).toEqual([]);
});

test("bad sample brief fails lint, confidence, must_cite and must_not_cite", () => {
  const m = gradeMachine(read("evals/samples/brute-force-dc-chain.bad.brief.md"), bfExpected, bfIntake);
  const failed = new Set(m.machine.filter((c) => !c.pass).map((c) => c.check));
  for (const c of ["lint", "confidence", "must_cite", "must_not_cite"]) expect(failed.has(c)).toBe(true);
  expect(failed.has("status")).toBe(false);
});

for (const f of readdirSync(join(ROOT, "evals/samples")).filter((n) => n.endsWith(".run1.brief.md")).sort()) {
  const fixture = f.replace(/\.run1\.brief\.md$/, "");
  const base = fixture.replace(/\.v2$/, ""); // v2 twins share the v1 ground truth
  test(`run sample ${f} passes every machine check for ${base}`, () => {
    const m = gradeMachine(read(`evals/samples/${f}`), json(`intake/fixtures/${base}.expected.json`), json(`intake/fixtures/${fixture}.intake.json`));
    const failed = m.machine.filter((c) => !c.pass).map((c) => `${c.check}: ${c.detail}`);
    expect(failed).toEqual([]);
  });
}

test("mergeRubric keeps expected order, fails ungraded items, rejects malformed files", () => {
  const e = json("intake/fixtures/quiet-day.expected.json") as Expected;
  const merged = mergeRubric(e, { rubric: [{ id: "liveness-recommended", text: "x", pass: true, quote: "run the liveness checks" }] });
  expect(merged.map((r) => r.id)).toEqual([...e.must_identify, ...e.must_not].map((r) => r.id));
  expect(merged.find((r) => r.id === "liveness-recommended")?.pass).toBe(true);
  expect(merged.find((r) => r.id === "no-findings")?.pass).toBe(false);
  expect(() => mergeRubric(e, { nope: [] })).toThrow();
  expect(() => mergeRubric(e, { rubric: [{ id: "x", pass: "yes" }] })).toThrow();
});
