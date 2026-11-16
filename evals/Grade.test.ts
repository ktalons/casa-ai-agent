// *****************************************************************************
// *Title: Brief Grader Tests*
// *Author: Kyle Versluis*
// *Description: Machine checks, rubric merge and where grade files land.*
// *****************************************************************************

// *--- Imports ---*

import { test, expect } from "bun:test";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { assertExpected, gradeMachine, mergeRubric, type Expected } from "./lib/grade.ts";
import { formatSummary, loadSets, summarize, type FixtureSets, type StoredGrade } from "./lib/sets.ts";
import { lint } from "./lib/extract.ts";

const ROOT = join(import.meta.dir, "..");
const read = (p: string) => readFileSync(join(ROOT, p), "utf8");
const json = (p: string) => JSON.parse(read(p));
// Every fixture family in the sets manifest, so a new fixture is checked the day it lands.
const FIXTURES = Object.keys(loadSets().fixtures);

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

for (const f of readdirSync(join(ROOT, "evals/samples")).filter((n) => /\.run\d+\.brief\.md$/.test(n)).sort()) {
  const fixture = f.replace(/\.run\d+\.brief\.md$/, "");
  const base = fixture.replace(/\.v\d+$/, ""); // later-version twins share the v1 ground truth
  test(`run sample ${f} passes every machine check for ${base}`, () => {
    const m = gradeMachine(read(`evals/samples/${f}`), json(`intake/fixtures/${base}.expected.json`), json(`intake/fixtures/${fixture}.intake.json`));
    const failed = m.machine.filter((c) => !c.pass).map((c) => `${c.check}: ${c.detail}`);
    expect(failed).toEqual([]);
  });
}

test("a brief with csf or options in the wrong shape fails those checks instead of crashing", () => {
  const expected = json("intake/fixtures/brute-force-dc-chain.expected.json") as Expected;
  const intake = json("intake/fixtures/brute-force-dc-chain.intake.json");
  const brief = "```json\n" + JSON.stringify({ schema: "casa.brief/v1", status: "findings", threads: [{}], overall_confidence: { level: "High" }, csf: { function: "DE" }, options: "none" }) + "\n```\n";
  const m = gradeMachine(brief, expected, intake);
  const by = Object.fromEntries(m.machine.map((c) => [c.check, c]));
  expect(by["brief-json"].pass).toBe(true);
  expect(by.csf_functions.pass).toBe(false);
  expect(by.forbid_option_kinds.pass).toBe(true);
});

test("mergeRubric keeps expected order, fails ungraded items, rejects malformed files", () => {
  const e = json("intake/fixtures/quiet-day.expected.json") as Expected;
  const merged = mergeRubric(e, { rubric: [{ id: "liveness-recommended", text: "x", pass: true, quote: "run the liveness checks" }] });
  expect(merged.map((r) => r.id)).toEqual([...e.must_identify, ...e.must_not].map((r) => r.id));
  expect(merged.find((r) => r.id === "liveness-recommended")?.pass).toBe(true);
  expect(merged.find((r) => r.id === "no-findings")?.pass).toBe(false);
  expect(() => mergeRubric(e, { nope: [] })).toThrow();
  expect(() => mergeRubric(e, { rubric: [{ id: "x", pass: "yes" }] })).toThrow();
});

test("results dir: the machine grade and the evaluator's rubric land in one project evals/results directory", async () => {
  const { mkdtempSync, realpathSync, writeFileSync: write, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { dirname } = await import("node:path");
  // Run from a scratch project, as a marketplace install does: the plugin root is elsewhere.
  // realpath: on macOS the temp dir sits behind a /var symlink, and the child reports the real cwd.
  const project = realpathSync(mkdtempSync(join(tmpdir(), "casa-results-")));
  try {
    const args = ["--brief", join(ROOT, "evals/samples/brute-force-dc-chain.good.brief.md"), "--expected", join(ROOT, "intake/fixtures/brute-force-dc-chain.expected.json"), "--intake", join(ROOT, "intake/fixtures/brute-force-dc-chain.intake.json"), "--json"];
    const grade = Bun.spawnSync(["bun", join(ROOT, "evals/Grade.ts"), ...args], { cwd: project });
    const gradePath: string = JSON.parse(grade.stdout.toString()).path;
    const want = join(project, "evals", "results", "brute-force-dc-chain");
    expect(dirname(gradePath)).toBe(want);

    // The evaluator is told to write its rubric beside the grade file; the merge lands there too.
    const rubricPath = join(dirname(gradePath), "x.rubric.json");
    write(rubricPath, JSON.stringify({ rubric: [] }));
    const merged = Bun.spawnSync(["bun", join(ROOT, "evals/Grade.ts"), ...args, "--rubric", rubricPath], { cwd: project });
    expect(dirname(JSON.parse(merged.stdout.toString()).path)).toBe(want);
    expect(read("agents/evaluator.md")).toContain("in the same directory as the deterministic grade file");
    expect(read("skills/evaluate/SKILL.md")).toContain("in the same directory as the grade file");
  } finally {
    rmSync(project, { recursive: true, force: true });
  }
});

// *--- Held-out scores (ISC-56) ---*

test("held-out: the summary keeps authoring and held-out totals apart and keeps the newest grade per variant", () => {
  const sets: FixtureSets = {
    schema: "casa.fixture-sets/v1",
    about: "",
    fixtures: { a: { set: "authoring", scenarios: [] }, h: { set: "held-out", scenarios: [] } },
  };
  const g = (fixture: string, intake: string | undefined, at: string, mp: number, rp: number | null): StoredGrade => ({
    schema: "casa.grade/v1", fixture, brief: "b", intake, graded_at: at, lint: { pass: true, unknown: [] }, machine: [], rubric: "pending", fabrication: [],
    score: { machine_pass: mp, machine_total: 9, rubric_pass: rp, rubric_total: rp === null ? null : 6 }, path: `${fixture}-${at}`,
  });
  const s = summarize([
    g("a", "x/a.intake.json", "2026-07-01T00:00:00.000Z", 8, 5),
    g("a", "x/a.intake.json", "2026-07-02T00:00:00.000Z", 9, 6), // newer run of the same variant replaces the first
    g("a", "x/a.v2.intake.json", "2026-07-01T00:00:00.000Z", 9, null), // another variant, rubric still pending
    g("h", "x/h.v3.intake.json", "2026-07-01T00:00:00.000Z", 7, 3),
    g("own", undefined, "2026-07-01T00:00:00.000Z", 9, 6), // an older record or a user's own fixture
  ], sets);
  expect(s.sets.authoring).toEqual({ variants: 2, full_marks: 1, machine_pass: 18, machine_total: 18, rubric_pass: 6, rubric_total: 6, rubric_pending: 1 });
  expect(s.sets["held-out"]).toEqual({ variants: 1, full_marks: 0, machine_pass: 7, machine_total: 9, rubric_pass: 3, rubric_total: 6, rubric_pending: 0 });
  expect(s.sets.unlisted?.variants).toBe(1);
  const text = formatSummary(s);
  expect(text).toMatch(/^authoring: 2 variants, 1 at full marks/m);
  expect(text).toMatch(/^held-out: 1 variants, 0 at full marks, machine 7\/9, rubric 3\/6$/m);
  expect(text.indexOf("held-out:")).toBeGreaterThan(text.indexOf("  a.v2"));
});

test("held-out: Grade.ts stamps each grade with its intake and set, and --summary reports the sets apart", async () => {
  const { mkdtempSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const out = mkdtempSync(join(tmpdir(), "casa-summary-"));
  try {
    const intake = join(ROOT, "intake/fixtures/brute-force-dc-chain.v2.intake.json");
    const args = ["--brief", join(ROOT, "evals/samples/brute-force-dc-chain.v2.run1.brief.md"), "--expected", join(ROOT, "intake/fixtures/brute-force-dc-chain.expected.json"), "--intake", intake, "--out", out, "--json"];
    const grade = JSON.parse(Bun.spawnSync(["bun", join(ROOT, "evals/Grade.ts"), ...args]).stdout.toString());
    expect(grade.intake).toBe(intake);
    expect(grade.set).toBe("authoring");
    const summary = JSON.parse(Bun.spawnSync(["bun", join(ROOT, "evals/Grade.ts"), "--summary", "--out", out, "--json"]).stdout.toString());
    expect(Object.keys(summary.sets)).toEqual(["authoring"]);
    expect(summary.rows.map((r: { variant: string }) => r.variant)).toEqual(["brute-force-dc-chain.v2"]);
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});

// *--- Ground truth agrees with the lint ---*

// A brief that states what the ground truth says must pass the lint, or the fixture can never
// grade clean. Every rubric text and must_cite value is linted against each intake variant.
for (const f of FIXTURES) {
  test(`ground truth lints clean: ${f}`, () => {
    const e = json(`intake/fixtures/${f}.expected.json`);
    const text = [...e.must_identify, ...e.must_not].map((m: { text: string }) => m.text).join("\n") + "\n" +
      [...e.must_cite.hosts, ...e.must_cite.rule_ids.map((r: string) => `rule ${r}`), ...e.must_cite.attack].join(" ");
    const variants = readdirSync(join(ROOT, "intake/fixtures")).filter((n) => n.startsWith(`${f}.`) && n.endsWith(".intake.json"));
    expect(variants.length).toBeGreaterThan(0);
    for (const v of variants) expect(lint(text, json(`intake/fixtures/${v}`)).unknown.map((u) => `${u.kind}:${u.token}`), v).toEqual([]);
  });
}

test("held-out: review fixes - a legacy record keeps its variant, a cross-fixture grade is refused, a flag is never a value", async () => {
  const sets = loadSets();
  const legacy: StoredGrade = {
    schema: "casa.grade/v1", fixture: "brute-force-dc-chain", brief: "briefs/2026-07-20-brute-force-dc-chain.v2.brief.md", graded_at: "2026-07-01T00:00:00.000Z",
    lint: { pass: true, unknown: [] }, machine: [], rubric: "pending", fabrication: [],
    score: { machine_pass: 9, machine_total: 9, rubric_pass: null, rubric_total: null }, path: "p",
  };
  expect(summarize([legacy], sets).rows.map((r) => r.variant)).toEqual(["brute-force-dc-chain.v2"]);

  // An authoring truth with a held-out intake would file a held-out score under authoring.
  const crossed = Bun.spawnSync(["bun", join(ROOT, "evals/Grade.ts"), "--brief", join(ROOT, "evals/samples/brute-force-dc-chain.good.brief.md"),
    "--expected", join(ROOT, "intake/fixtures/brute-force-dc-chain.expected.json"), "--intake", join(ROOT, "intake/fixtures/smb-connection-fanout.v3.intake.json"), "--json"]);
  expect(crossed.exitCode).toBe(2);
  expect(crossed.stderr.toString()).toContain("is fixture smb-connection-fanout, but the expected file is for brute-force-dc-chain");

  // `--out --json`: --out takes no value, so the grade lands in the default results dir, not in "./--json".
  const { mkdtempSync, realpathSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const cwd = realpathSync(mkdtempSync(join(tmpdir(), "casa-flags-")));
  try {
    const r = Bun.spawnSync(["bun", join(ROOT, "evals/Grade.ts"), "--brief", join(ROOT, "evals/samples/brute-force-dc-chain.good.brief.md"),
      "--expected", join(ROOT, "intake/fixtures/brute-force-dc-chain.expected.json"), "--intake", join(ROOT, "intake/fixtures/brute-force-dc-chain.intake.json"), "--out", "--json"], { cwd });
    expect(JSON.parse(r.stdout.toString()).path.startsWith(join(cwd, "evals", "results", "brute-force-dc-chain"))).toBe(true);
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});

// *--- Verbatim quotes at the merge (ISC-88) ---*

test("verbatim: a passing rubric item whose quote is not in the brief is failed at the merge", () => {
  const expected = { ...json("intake/fixtures/quiet-day.expected.json") } as Expected;
  const brief = [
    "The intake carries **no detections** for the window.",
    "Confirm whether the SIEM manager and its collector were running.",
    "```json",
    '{ "path": "C:\\\\ProgramData\\\\x.exe", "summary": "a \\"quoted\\" word" }',
    "```",
    "Check the   service state and newest indexed event.",
  ].join("\n");
  const item = (id: string, quote: string, pass = true) => ({ id, text: "", pass, quote });
  const ids = [...expected.must_identify, ...expected.must_not].map((m) => m.id);
  const merged = (quotes: Array<[string, boolean?]>) =>
    mergeRubric(expected, { rubric: ids.map((id, i) => item(id, quotes[i]?.[0] ?? "The intake carries no detections", quotes[i]?.[1] ?? true)) }, brief);
  const cases: Array<[string, boolean]> = [
    ["The intake carries no detections for the window.", true], // Markdown emphasis dropped
    ["Check the service state and newest indexed event.", true], // whitespace collapsed
    ["Confirm whether the SIEM manager ... newest indexed event", true], // passages joined by an ellipsis
    ["newest indexed event | Confirm whether the SIEM manager", true], // or by a bar, in any order
    ["newest indexed event | the collector was down", false], // one passage the brief lacks
    ["Confirm whether the SIEM manager and its newest indexed event", false], // spliced, no marker
    ["Confirm whether the SIEM manager (the brief hedges here)", false], // commentary inside the quote
    ['C:\\ProgramData\\x.exe ... a "quoted" word', true], // a JSON value quoted unescaped
  ];
  for (const [quote, ok] of cases) {
    const r = merged([[quote]])[0];
    expect([quote, r.pass]).toEqual([quote, ok]);
    if (!ok) expect(r.note).toContain("not verbatim");
  }
  // A failed item keeps its verdict and quote untouched, whatever the quote says.
  const failed = merged([["no such statement", false]])[0];
  expect([failed.pass, failed.quote]).toEqual([false, "no such statement"]);
  // Without the brief (older callers) the merge takes the verdict as given.
  expect(mergeRubric(expected, { rubric: ids.map((id) => item(id, "spliced text")) }).every((r) => r.pass)).toBe(true);
});
