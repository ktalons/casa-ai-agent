#!/usr/bin/env bun
/**
 * Grade.ts — grade a brief against a fixture's machine-checkable ground truth.
 *
 *   bun evals/Grade.ts --brief <md> --expected <expected.json> --intake <intake.json>
 *                      [--rubric <evaluator rubric json>] [--out <dir>] [--host-prefix <prefix>] [--json]
 *
 * Runs the lint and every machine check in casa.expected/v1, writes a casa.grade/v1 record to
 * <out>/<fixture>/<iso>.grade.json (default out: evals/results), merges the evaluator's rubric
 * verdicts when --rubric is given, prints a table, and exits 1 if any machine check fails.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { assertExpected, buildGrade, gradeMachine, mergeRubric } from "./lib/grade.ts";
import { assertHostPrefix, DEFAULT_HOST_PREFIX } from "./lib/extract.ts";

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}
const briefPath = arg("--brief"), expectedPath = arg("--expected"), intakePath = arg("--intake");
const rubricPath = arg("--rubric");
const outDir = arg("--out") ?? join(import.meta.dir, "results");
const hostPrefix = arg("--host-prefix") ?? DEFAULT_HOST_PREFIX;
if (!briefPath || !expectedPath || !intakePath) {
  console.error("usage: bun evals/Grade.ts --brief <md> --expected <json> --intake <json> [--rubric <json>] [--out <dir>] [--host-prefix <prefix>] [--json]");
  process.exit(2);
}
try { assertHostPrefix(hostPrefix); } catch (e) { console.error(`--host-prefix: ${(e as Error).message}`); process.exit(2); }

const expected = JSON.parse(readFileSync(expectedPath, "utf8"));
assertExpected(expected);
const intake = JSON.parse(readFileSync(intakePath, "utf8"));
const briefText = readFileSync(briefPath, "utf8");

const m = gradeMachine(briefText, expected, intake, hostPrefix);
const rubric = rubricPath ? mergeRubric(expected, JSON.parse(readFileSync(rubricPath, "utf8"))) : null;
const grade = buildGrade(expected.fixture, briefPath, m, rubric);

const dir = join(outDir, expected.fixture);
mkdirSync(dir, { recursive: true });
const outPath = join(dir, `${grade.graded_at.replace(/[:.]/g, "-")}.grade.json`);
writeFileSync(outPath, JSON.stringify(grade, null, 2) + "\n");

if (process.argv.includes("--json")) {
  console.log(JSON.stringify({ ...grade, path: outPath }, null, 2));
} else {
  console.log(`${expected.fixture}: ${briefPath}`);
  for (const c of grade.machine) console.log(`  ${c.pass ? "✓" : "✗"} ${c.check.padEnd(20)} ${c.detail}`);
  if (rubric) for (const r of rubric) console.log(`  ${r.pass ? "✓" : "✗"} rubric:${r.id.padEnd(22)} ${r.quote.slice(0, 100)}`);
  const s = grade.score;
  console.log(`  machine ${s.machine_pass}/${s.machine_total}${rubric ? `, rubric ${s.rubric_pass}/${s.rubric_total}` : ", rubric pending"} → ${outPath}`);
}
process.exit(grade.score.machine_pass === grade.score.machine_total ? 0 : 1);
