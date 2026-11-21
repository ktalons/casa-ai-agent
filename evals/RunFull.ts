#!/usr/bin/env bun
// *****************************************************************************
// *Title: Full Eval Runner*
// *Author: Kyle*
// *Description: Runs /casa:investigate then /casa:evaluate on every fixture.*
// *****************************************************************************

// Headless and not part of default CI. Needs the Claude Code CLI signed in to a subscription,
// the plugin loaded in place (bun run plugin:link) and the workspace trusted for -p runs.
// Each child runs on EVAL_MODEL with project and local settings only, so the scores measure
// the plugin and not the operator's own Claude Code setup. Investigate runs in a new project
// directory outside the repo with the plugin loaded by path; evaluate runs here, where the
// ground truth is.
//
//   bun evals/RunFull.ts [fixture ...]   # default: every intake fixture of every version
//   bun evals/RunFull.ts --set held-out  # every variant of one set in evals/fixture-sets.json
//
// Each step's JSON result goes to evals/results/runs/<iso>-<fixture>-<step>.json; the exit
// code is non-zero if any step failed, timed out or returned no JSON. The run ends with the
// grade summary, authoring and held-out totals apart.

// *--- Imports ---*

import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join, relative } from "node:path";
import { SET_NAMES, formatSummary, loadSets, readGrades, summarize, variantsInSet, type FixtureSets, type SetName } from "./lib/sets.ts";

// *--- Configuration ---*

const ROOT = join(import.meta.dir, "..");
const FIXTURES_DIR = join(ROOT, "intake", "fixtures");
const OUT = join(ROOT, "evals", "results", "runs");
const BRIEFS_DIR = join(ROOT, "briefs");
// Each investigate step runs in its own new project directory under here, outside the repo: an
// analyst's first run sees no earlier brief, and neither does an eval run. Inside the repo a
// child read earlier briefs (its own fixture's before overwriting it, other fixtures' as format
// examples) and could have opened ground truth, grades and project notes.
const RUNS_ROOT = join(homedir(), ".cache", "casa-evals");
const PROJECT_SETTINGS = join(ROOT, ".claude", "settings.json");
const INVESTIGATE_TURNS = 80;
const EVALUATE_TURNS = 30;
// A hung child is killed at this bound so one stuck step cannot stall the whole loop.
const STEP_TIMEOUT_MS = 45 * 60 * 1000;

// SECURITY: a nested claude refuses to start under CLAUDECODE; the rest would silently move eval
// runs off the subscription (API keys, a gateway URL or headers, Bedrock or Vertex). The OAuth
// token stays: it is the subscription login.
export const STRIPPED_ENV = [
  "CLAUDECODE",
  "ANTHROPIC_API_KEY",
  "ANTHROPIC_AUTH_TOKEN",
  "ANTHROPIC_BASE_URL",
  "ANTHROPIC_CUSTOM_HEADERS",
  "CLAUDE_CODE_USE_BEDROCK",
  "CLAUDE_CODE_USE_VERTEX",
  "AWS_BEARER_TOKEN_BEDROCK",
] as const;

// NOTE: a published score has to name its model. Without this the child takes whatever the
// user's settings pin that day, so two runs of one fixture could measure two models.
export const EVAL_MODEL = "opus";

// The child loads the project's settings (the Bash allow rules) and the local ones (the linked
// plugin), never the user's: user-scope hooks, plugins and MCP servers are not part of CASA, and
// one such hook once had an eval child edit project state. --bare would also do it, but it
// forces API-key billing.
const SETTING_SOURCES = "project,local";

// Instruction files and auto memory can carry fixture names and earlier results into a run.
export const ISOLATION_ENV = ["CLAUDE_CODE_DISABLE_CLAUDE_MDS", "CLAUDE_CODE_DISABLE_AUTO_MEMORY"] as const;

// *--- Types ---*

export interface Invocation {
  cmd: string[];
  env: Record<string, string>;
}

/** What an investigate child needs beyond the defaults: the plugin by path and its permissions. */
export interface InvocationOptions {
  pluginDir?: string;
  settings?: unknown;
}

interface PermissionSettings {
  permissions?: { allow?: string[]; deny?: string[] };
}

interface RunResult {
  is_error?: boolean;
  num_turns?: number;
  total_cost_usd?: number;
  subagent_stats?: { spawned?: number };
  permission_denials?: unknown[];
  modelUsage?: Record<string, unknown>;
}

// *--- Core Logic ---*

/** Copy of the parent environment without the variables a nested headless claude must not see. */
export function childEnv(parent: Record<string, string | undefined>): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(parent)) {
    if (value !== undefined && !(STRIPPED_ENV as readonly string[]).includes(key)) env[key] = value;
  }
  return env;
}

/** The exact command and environment RunFull spawns for one step. */
export function buildInvocation(prompt: string, maxTurns: number, parentEnv: Record<string, string | undefined>, options: InvocationOptions = {}): Invocation {
  const env = childEnv(parentEnv);
  for (const key of ISOLATION_ENV) env[key] = "1";
  const cmd = [
    "claude", "-p", prompt,
    "--model", EVAL_MODEL,
    "--setting-sources", SETTING_SOURCES,
    "--permission-mode", "acceptEdits",
    "--max-turns", String(maxTurns),
    "--output-format", "json",
  ];
  if (options.pluginDir !== undefined) cmd.push("--plugin-dir", options.pluginDir);
  if (options.settings !== undefined) cmd.push("--settings", JSON.stringify(options.settings));
  return { cmd, env };
}

/**
 * Settings for an investigate child, passed on the command line because a new directory is an
 * untrusted workspace whose own settings file Claude Code ignores. The Bash rules are the
 * project's recommended ones. The only files it may read outside its project are the plugin's
 * skills: the fixtures' ground truth, the grader and earlier results stay out of reach.
 */
export function investigateSettings(pluginRoot: string, project: PermissionSettings): PermissionSettings {
  return {
    permissions: {
      allow: [...(project.permissions?.allow ?? []), `Read(/${pluginRoot}/skills/**)`],
      deny: [...(project.permissions?.deny ?? [])],
    },
  };
}

/** Make a new project directory for one investigate run, holding only that run's intake. */
export function prepareRunDir(runsRoot: string, stamp: string, variant: string, intakeFile: string): string {
  const dir = join(runsRoot, `${stamp}-${variant}`);
  mkdirSync(join(dir, "intake"), { recursive: true });
  copyFileSync(intakeFile, join(dir, "intake", basename(intakeFile)));
  return dir;
}

/** Copy a run's brief into `briefsDir`, where evaluate and the kept-sample flow look, and return the copy. */
export function keepBrief(briefFile: string, briefsDir: string): string {
  mkdirSync(briefsDir, { recursive: true });
  const kept = join(briefsDir, basename(briefFile));
  copyFileSync(briefFile, kept);
  return kept;
}

/** The models a step's result says answered, sorted, or "unknown" when it names none. */
export function modelsUsed(result: { modelUsage?: Record<string, unknown> }): string {
  const names = Object.keys(result.modelUsage ?? {}).sort();
  return names.length > 0 ? names.join(", ") : "unknown";
}

/** Fixture names to run: the requested ones in order, or every `*.intake.json` of every version. */
export function listFixtures(dir: string, requested: string[]): string[] {
  const all = readdirSync(dir)
    .filter((f) => f.endsWith(".intake.json"))
    .map((f) => f.slice(0, -".intake.json".length))
    .sort();
  if (requested.length === 0) return all;
  const unknown = requested.filter((r) => !all.includes(r));
  if (unknown.length > 0) throw new Error(`unknown fixture(s): ${unknown.join(", ")}; known: ${all.join(", ")}`);
  return requested;
}

/**
 * The variants a command line asks for: `--set <name>` takes every variant of that set's
 * fixture families (ISC-85); anything else is a list of fixture names for listFixtures.
 */
export function selectFixtures(dir: string, argv: string[], sets: FixtureSets): string[] {
  if (argv[0] !== "--set") return listFixtures(dir, argv);
  const name = argv[1];
  if (!(SET_NAMES as readonly (string | undefined)[]).includes(name)) throw new Error(`--set needs one of ${SET_NAMES.join(", ")}, got ${JSON.stringify(name ?? "")}`);
  if (argv.length > 2) throw new Error("--set takes no fixture names after it");
  const chosen = variantsInSet(sets, name as SetName, listFixtures(dir, []));
  if (chosen.length === 0) throw new Error(`set ${name} has no fixtures in ${dir}`);
  return chosen;
}

/**
 * The brief this run's investigate step wrote for `fixture`: the newest `*-<fixture>.brief.md`
 * in `dir` modified at or after `sinceMs`, or null. The dash and the full suffix keep a `.v2`
 * twin's brief from matching its base fixture.
 */
export function briefForRun(dir: string, fixture: string, sinceMs: number): string | null {
  const suffix = `-${fixture}.brief.md`;
  let best: { path: string; mtime: number } | null = null;
  for (const name of existsSync(dir) ? readdirSync(dir) : []) {
    if (!name.endsWith(suffix)) continue;
    const path = join(dir, name);
    const mtime = statSync(path).mtimeMs;
    if (mtime >= sinceMs && (best === null || mtime > best.mtime)) best = { path, mtime };
  }
  return best?.path ?? null;
}

/** Narrow a parsed stdout to the result fields RunFull reports, or null if it is not an object. */
function asRunResult(value: unknown): RunResult | null {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as RunResult) : null;
}

async function runStep(step: string, fixture: string, prompt: string, maxTurns: number, cwd: string = ROOT, options: InvocationOptions = {}): Promise<boolean> {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const inv = buildInvocation(prompt, maxTurns, process.env, options);
  const proc = Bun.spawn(inv.cmd, { cwd, env: inv.env, stdout: "pipe", stderr: "pipe", timeout: STEP_TIMEOUT_MS });
  const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
  const code = await proc.exited;
  const file = join(OUT, `${stamp}-${fixture}-${step}.json`);
  writeFileSync(file, stdout || JSON.stringify({ error: stderr, exit: code, signal: proc.signalCode }));
  if (proc.signalCode) {
    console.log(`${fixture} ${step}: killed by ${proc.signalCode} after ${STEP_TIMEOUT_MS / 60000} min → ${file}`);
    return false;
  }
  let parsed: RunResult | null = null;
  try {
    parsed = asRunResult(JSON.parse(stdout));
  } catch {
    parsed = null;
  }
  if (parsed === null) {
    console.log(`${fixture} ${step}: exit ${code}, no JSON result → ${file}`);
    return false;
  }
  const cost = typeof parsed.total_cost_usd === "number" ? parsed.total_cost_usd : 0;
  const denials = Array.isArray(parsed.permission_denials) ? parsed.permission_denials.length : 0;
  console.log(`${fixture} ${step}: turns ${parsed.num_turns}, subagents ${parsed.subagent_stats?.spawned ?? 0}, cost $${cost.toFixed(2)}, denials ${denials}, models ${modelsUsed(parsed)} → ${file}`);
  return code === 0 && parsed.is_error !== true;
}

// *--- Entry Point ---*

if (import.meta.main) {
  const sets = loadSets();
  const fixtures = selectFixtures(FIXTURES_DIR, process.argv.slice(2), sets);
  mkdirSync(OUT, { recursive: true });
  const settings = investigateSettings(ROOT, JSON.parse(readFileSync(PROJECT_SETTINGS, "utf8")) as PermissionSettings);
  let allOk = true;
  for (const f of fixtures) {
    const started = Date.now();
    const stamp = new Date(started).toISOString().replace(/[:.]/g, "-");
    // NOTE: the run's LEARN note and drafts stay in its own directory, so no eval run, held-out
    // or not, puts a note in the queue /casa:learn promotes from.
    const runDir = prepareRunDir(RUNS_ROOT, stamp, f, join(FIXTURES_DIR, `${f}.intake.json`));
    const investigated = await runStep("investigate", f, `/casa:investigate intake/${f}.intake.json`, INVESTIGATE_TURNS, runDir, { pluginDir: ROOT, settings });
    // NOTE: the brief is handed to evaluate by path. Left to resolve it in prose, one run
    // graded an old kept sample instead of the brief that had just been written.
    const written = investigated ? briefForRun(join(runDir, "briefs"), f, started) : null;
    if (investigated && written === null) console.log(`${f} evaluate: skipped, investigate wrote no brief (${runDir})`);
    const brief = written === null ? null : keepBrief(written, BRIEFS_DIR);
    const evaluated = brief !== null && (await runStep("evaluate", f, `/casa:evaluate ${f} --brief ${relative(ROOT, brief)}`, EVALUATE_TURNS));
    allOk = allOk && investigated && evaluated;
  }
  console.log(formatSummary(summarize(readGrades(join(ROOT, "evals", "results")), sets)));
  process.exit(allOk ? 0 : 1);
}
