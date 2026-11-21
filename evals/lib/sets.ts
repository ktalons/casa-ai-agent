// *****************************************************************************
// *Title: Fixture Sets*
// *Author: Kyle Versluis*
// *Description: Authoring and held-out fixture sets, and grade totals per set.*
// *****************************************************************************

/**
 * The sets manifest (`evals/fixture-sets.json`) puts every fixture family in exactly one set.
 * Authoring fixtures are the ones prompt text may be tuned against; held-out fixtures are never
 * named in prompt text and never tuned against, so their scores measure generalization. A
 * held-out fixture that gets used for tuning moves to authoring and is replaced.
 */

// *--- Imports ---*

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { basename, join } from "node:path";
import type { GradeResult } from "./grade.ts";

// *--- Types ---*

export const SET_NAMES = ["authoring", "held-out"] as const;
export type SetName = (typeof SET_NAMES)[number];

// The eight scenarios S2 must cover (ISC-25). A fixture may cover several, or none.
export const SCENARIOS = [
  "refuted-benign",
  "injected-text",
  "truncation",
  "healthy-quiet-day",
  "lolbins",
  "persistence",
  "log-tampering",
  "internal-scanning",
] as const;
export type Scenario = (typeof SCENARIOS)[number];

export interface FixtureSets {
  schema: "casa.fixture-sets/v1";
  about: string;
  fixtures: Record<string, { set: SetName; scenarios: Scenario[] }>;
}

export interface SetTotals {
  variants: number;
  full_marks: number;
  machine_pass: number;
  machine_total: number;
  rubric_pass: number;
  rubric_total: number;
  rubric_pending: number;
}

export interface SummaryRow {
  variant: string;
  fixture: string;
  set: SetName | "unlisted";
  graded_at: string;
  machine: string;
  rubric: string;
  path: string;
}

export interface Summary {
  sets: Partial<Record<SetName | "unlisted", SetTotals>>;
  rows: SummaryRow[];
}

/** A grade record as read from disk: older records carry no `intake` or `set`. */
export type StoredGrade = GradeResult & { path: string };

// *--- Configuration ---*

export const SETS_PATH = join(import.meta.dir, "..", "fixture-sets.json");

const NAME = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

// *--- Core Logic ---*

/** Structural check of the sets manifest; throws with a reason on the first problem. */
export function assertSets(doc: unknown): asserts doc is FixtureSets {
  if (typeof doc !== "object" || doc === null) throw new Error("sets: not an object");
  const o = doc as Record<string, unknown>;
  if (o.schema !== "casa.fixture-sets/v1") throw new Error("sets: schema must be casa.fixture-sets/v1");
  if (typeof o.fixtures !== "object" || o.fixtures === null || Array.isArray(o.fixtures)) throw new Error("sets: fixtures must be an object");
  for (const [name, entry] of Object.entries(o.fixtures as Record<string, unknown>)) {
    if (!NAME.test(name)) throw new Error(`sets: bad fixture name ${JSON.stringify(name)}`);
    const e = entry as { set?: unknown; scenarios?: unknown };
    if (!(SET_NAMES as readonly unknown[]).includes(e?.set)) throw new Error(`sets: ${name} has set ${JSON.stringify(e?.set)}`);
    if (!Array.isArray(e.scenarios)) throw new Error(`sets: ${name} scenarios must be a list`);
    for (const s of e.scenarios) if (!(SCENARIOS as readonly unknown[]).includes(s)) throw new Error(`sets: ${name} names unknown scenario ${JSON.stringify(s)}`);
  }
}

/** Read and check the manifest. */
export function loadSets(path: string = SETS_PATH): FixtureSets {
  const doc: unknown = JSON.parse(readFileSync(path, "utf8"));
  assertSets(doc);
  return doc;
}

/** The fixture family of an intake variant: `brute-force-dc-chain.v2` → `brute-force-dc-chain`. */
export function baseName(variant: string): string {
  return variant.split(".")[0];
}

/** The variant an intake path names: `.../quiet-day.v3.intake.json` → `quiet-day.v3`. */
export function variantOf(intakePath: string): string {
  return basename(intakePath).replace(/\.intake\.json$/, "");
}

/** Which set a fixture or variant belongs to; a fixture the manifest does not list is `unlisted`. */
export function setOf(sets: FixtureSets, fixtureOrVariant: string): SetName | "unlisted" {
  return Object.hasOwn(sets.fixtures, baseName(fixtureOrVariant)) ? sets.fixtures[baseName(fixtureOrVariant)].set : "unlisted";
}

/** The variants, in the given order, whose family is in `set`. */
export function variantsInSet(sets: FixtureSets, set: SetName, variants: string[]): string[] {
  return variants.filter((v) => setOf(sets, v) === set);
}

// *--- Helper Functions ---*

function emptyTotals(): SetTotals {
  return { variants: 0, full_marks: 0, machine_pass: 0, machine_total: 0, rubric_pass: 0, rubric_total: 0, rubric_pending: 0 };
}

// *--- Public Interfaces ---*

/** Every grade record under `<results>/<fixture>/*.grade.json`. */
export function readGrades(resultsDir: string): StoredGrade[] {
  const out: StoredGrade[] = [];
  if (!existsSync(resultsDir)) return out;
  for (const dir of readdirSync(resultsDir, { withFileTypes: true })) {
    if (!dir.isDirectory()) continue;
    for (const f of readdirSync(join(resultsDir, dir.name))) {
      if (!f.endsWith(".grade.json")) continue;
      const path = join(resultsDir, dir.name, f);
      try {
        const g = JSON.parse(readFileSync(path, "utf8")) as GradeResult;
        if (g?.schema === "casa.grade/v1") out.push({ ...g, path });
      } catch {
        // NOTE: a half-written or hand-edited file is skipped, not fatal; the summary reports
        // what it could read.
      }
    }
  }
  return out;
}

/**
 * Totals per set from the newest grade of each intake variant, so a later run of the same
 * variant replaces the earlier one and the held-out totals never mix with authoring ones.
 */
export function summarize(grades: StoredGrade[], sets: FixtureSets): Summary {
  const latest = new Map<string, StoredGrade>();
  for (const g of grades) {
    // Records older than S2 carry no intake; their brief's name still says `.v2.` or `.v3.`.
    const legacy = /\.(v\d+)\./.exec(basename(g.brief))?.[1];
    const variant = g.intake ? variantOf(g.intake) : legacy ? `${g.fixture}.${legacy}` : g.fixture;
    const prev = latest.get(variant);
    if (!prev || g.graded_at > prev.graded_at) latest.set(variant, g);
  }
  const totals: Summary["sets"] = {};
  const rows: SummaryRow[] = [];
  for (const [variant, g] of [...latest].sort(([a], [b]) => a.localeCompare(b))) {
    const set = setOf(sets, g.fixture);
    const t = (totals[set] ??= emptyTotals());
    const s = g.score;
    const rubricDone = s.rubric_pass !== null && s.rubric_total !== null;
    t.variants++;
    t.machine_pass += s.machine_pass;
    t.machine_total += s.machine_total;
    if (rubricDone) {
      t.rubric_pass += s.rubric_pass as number;
      t.rubric_total += s.rubric_total as number;
    } else t.rubric_pending++;
    if (rubricDone && s.machine_pass === s.machine_total && s.rubric_pass === s.rubric_total) t.full_marks++;
    rows.push({
      variant,
      fixture: g.fixture,
      set,
      graded_at: g.graded_at,
      machine: `${s.machine_pass}/${s.machine_total}`,
      rubric: rubricDone ? `${s.rubric_pass}/${s.rubric_total}` : "pending",
      path: g.path,
    });
  }
  return { sets: totals, rows };
}

/** The summary as a plain-text table, one block per set. */
export function formatSummary(summary: Summary): string {
  const lines: string[] = [];
  for (const set of [...SET_NAMES, "unlisted"] as const) {
    const t = summary.sets[set];
    if (!t) continue;
    lines.push(`${set}: ${t.variants} variants, ${t.full_marks} at full marks, machine ${t.machine_pass}/${t.machine_total}, rubric ${t.rubric_pass}/${t.rubric_total}${t.rubric_pending ? ` (${t.rubric_pending} pending)` : ""}`);
    for (const r of summary.rows.filter((x) => x.set === set)) lines.push(`  ${r.variant.padEnd(32)} machine ${r.machine.padEnd(6)} rubric ${r.rubric.padEnd(8)} ${r.graded_at}`);
  }
  return lines.length ? lines.join("\n") : "no grade records found";
}
