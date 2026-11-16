#!/usr/bin/env bun
// *****************************************************************************
// *Title: Full Eval Runner*
// *Author: Kyle*
// *Description: Runs /casa:investigate then /casa:evaluate on every fixture.*
// *****************************************************************************

// Headless and not part of default CI. Needs the Claude Code CLI signed in to a subscription,
// the plugin loaded in place (bun run plugin:link) and the workspace trusted for -p runs.
//
//   bun evals/RunFull.ts [fixture ...]   # default: every intake fixture of every version
//
// Each step's JSON result goes to evals/results/runs/<iso>-<fixture>-<step>.json; the exit
// code is non-zero if any step failed, timed out or returned no JSON.

// *--- Imports ---*

import { existsSync, mkdirSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";

// *--- Configuration ---*

const ROOT = join(import.meta.dir, "..");
const FIXTURES_DIR = join(ROOT, "intake", "fixtures");
const OUT = join(ROOT, "evals", "results", "runs");
const BRIEFS_DIR = join(ROOT, "briefs");
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

// *--- Types ---*

export interface Invocation {
  cmd: string[];
  env: Record<string, string>;
}

interface RunResult {
  is_error?: boolean;
  num_turns?: number;
  total_cost_usd?: number;
  subagent_stats?: { spawned?: number };
  permission_denials?: unknown[];
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
export function buildInvocation(prompt: string, maxTurns: number, parentEnv: Record<string, string | undefined>): Invocation {
  return {
    cmd: ["claude", "-p", prompt, "--permission-mode", "acceptEdits", "--max-turns", String(maxTurns), "--output-format", "json"],
    env: childEnv(parentEnv),
  };
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

async function runStep(step: string, fixture: string, prompt: string, maxTurns: number): Promise<boolean> {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const inv = buildInvocation(prompt, maxTurns, process.env);
  const proc = Bun.spawn(inv.cmd, { cwd: ROOT, env: inv.env, stdout: "pipe", stderr: "pipe", timeout: STEP_TIMEOUT_MS });
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
  console.log(`${fixture} ${step}: turns ${parsed.num_turns}, subagents ${parsed.subagent_stats?.spawned ?? 0}, cost $${cost.toFixed(2)}, denials ${denials} → ${file}`);
  return code === 0 && parsed.is_error !== true;
}

// *--- Entry Point ---*

if (import.meta.main) {
  const fixtures = listFixtures(FIXTURES_DIR, process.argv.slice(2));
  mkdirSync(OUT, { recursive: true });
  let allOk = true;
  for (const f of fixtures) {
    const started = Date.now();
    const investigated = await runStep("investigate", f, `/casa:investigate intake/fixtures/${f}.intake.json`, INVESTIGATE_TURNS);
    // NOTE: the brief is handed to evaluate by path. Left to resolve it in prose, one run
    // graded an old kept sample instead of the brief that had just been written.
    const brief = investigated ? briefForRun(BRIEFS_DIR, f, started) : null;
    if (investigated && brief === null) console.log(`${f} evaluate: skipped, investigate wrote no brief`);
    const evaluated = brief !== null && (await runStep("evaluate", f, `/casa:evaluate ${f} --brief ${relative(ROOT, brief)}`, EVALUATE_TURNS));
    allOk = allOk && investigated && evaluated;
  }
  process.exit(allOk ? 0 : 1);
}
