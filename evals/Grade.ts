#!/usr/bin/env bun
// *****************************************************************************
// *Title: Brief Grader CLI*
// *Author: Kyle Versluis*
// *Description: Grades a brief against a fixture's machine-checkable truth.*
// *****************************************************************************

/**
 *   bun evals/Grade.ts --brief <md> --expected <expected.json> --intake <intake.json>
 *                      [--rubric <evaluator rubric json>] [--out <dir>] [--host-prefix <prefix>] [--json]
 *
 * Runs the lint and every machine check in casa.expected/v1, writes a casa.grade/v1 record to
 * <out>/<fixture>/<iso>.grade.json, merges the evaluator's rubric verdicts when --rubric is
 * given, prints a table, and exits 1 if any machine check fails. <out> defaults to
 * evals/results under the current working directory (the project), never the plugin root, so
 * the grade lands beside the rubric the evaluator writes; a relative --out resolves there too.
 *
 *   bun evals/Grade.ts --summary [--out <dir>] [--json]
 *
 * Reads every grade record under <out> and reports the newest grade of each intake variant,
 * with authoring and held-out totals kept apart (sets from evals/fixture-sets.json).
 */

// *--- Imports ---*

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { assertExpected, buildGrade, gradeMachine, mergeRubric } from "./lib/grade.ts";
import { assertHostPrefix } from "./lib/extract.ts";
import { baseName, formatSummary, loadSets, readGrades, setOf, summarize, variantOf, type FixtureSets } from "./lib/sets.ts";

// *--- Entry Point ---*

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  const v = i >= 0 ? process.argv[i + 1] : undefined;
  // A flag is never a value: `--out --json` leaves --out unset instead of naming a dir "--json".
  return v === undefined || v.startsWith("--") ? undefined : v;
}
const briefPath = arg("--brief"), expectedPath = arg("--expected"), intakePath = arg("--intake");
const rubricPath = arg("--rubric");
const outDir = resolve(process.cwd(), arg("--out") ?? join("evals", "results"));
const hostPrefix = arg("--host-prefix");

// A plugin copy without the manifest grades everything as "unlisted". A manifest that exists
// but does not parse stops the run: filing held-out grades as "unlisted" would hide them.
let sets: FixtureSets | null = null;
try {
  sets = loadSets();
} catch (e) {
  if ((e as NodeJS.ErrnoException).code !== "ENOENT") {
    console.error(`evals/fixture-sets.json: ${(e as Error).message}`);
    process.exit(2);
  }
}

if (process.argv.includes("--summary")) {
  const summary = summarize(readGrades(outDir), sets ?? { schema: "casa.fixture-sets/v1", about: "", fixtures: {} });
  console.log(process.argv.includes("--json") ? JSON.stringify(summary, null, 2) : formatSummary(summary));
  process.exit(0);
}
if (!briefPath || !expectedPath || !intakePath) {
  console.error("usage: bun evals/Grade.ts --brief <md> --expected <json> --intake <json> [--rubric <json>] [--out <dir>] [--host-prefix <prefix>] [--json]");
  console.error("       bun evals/Grade.ts --summary [--out <dir>] [--json]");
  process.exit(2);
}
if (hostPrefix !== undefined) {
  try { assertHostPrefix(hostPrefix); } catch (e) { console.error(`--host-prefix: ${(e as Error).message}`); process.exit(2); }
}

const expected = JSON.parse(readFileSync(expectedPath, "utf8"));
assertExpected(expected);
// One fixture's intake graded against another's truth would file the score under the wrong set.
const family = baseName(variantOf(intakePath));
if (sets && family !== expected.fixture && (Object.hasOwn(sets.fixtures, family) || Object.hasOwn(sets.fixtures, expected.fixture))) {
  console.error(`intake ${variantOf(intakePath)} is fixture ${family}, but the expected file is for ${expected.fixture}`);
  process.exit(2);
}
const intakeRaw = readFileSync(intakePath);
const intake = JSON.parse(intakeRaw.toString("utf8"));
const intakeSha256 = createHash("sha256").update(intakeRaw).digest("hex");
const briefText = readFileSync(briefPath, "utf8");

const m = gradeMachine(briefText, expected, intake, { hostPrefix, intakeSha256 });
const rubric = rubricPath ? mergeRubric(expected, JSON.parse(readFileSync(rubricPath, "utf8")), briefText) : null;
const grade = buildGrade(expected.fixture, briefPath, m, rubric, { intake: intakePath, set: sets ? setOf(sets, expected.fixture) : "unlisted" });

const dir = join(outDir, expected.fixture);
mkdirSync(dir, { recursive: true });
const outPath = join(dir, `${grade.graded_at.replace(/[:.]/g, "-")}.grade.json`);
writeFileSync(outPath, JSON.stringify(grade, null, 2) + "\n");

if (process.argv.includes("--json")) {
  console.log(JSON.stringify({ ...grade, path: outPath }, null, 2));
} else {
  console.log(`${expected.fixture} (${grade.set}): ${briefPath}`);
  for (const c of grade.machine) console.log(`  ${c.pass ? "✓" : "✗"} ${c.check.padEnd(20)} ${c.detail}`);
  for (const n of m.lint.notes) console.log(`  note: ${n}`);
  if (rubric) for (const r of rubric) console.log(`  ${r.pass ? "✓" : "✗"} rubric:${r.id.padEnd(22)} ${r.quote.slice(0, 100)}${r.note ? ` [${r.note.slice(0, 80)}]` : ""}`);
  const s = grade.score;
  console.log(`  machine ${s.machine_pass}/${s.machine_total}${rubric ? `, rubric ${s.rubric_pass}/${s.rubric_total}` : ", rubric pending"} → ${outPath}`);
}
process.exit(grade.score.machine_pass === grade.score.machine_total ? 0 : 1);
