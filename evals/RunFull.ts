#!/usr/bin/env bun
/**
 * RunFull.ts — the full loop on every fixture, headless: /casa:investigate, then
 * /casa:evaluate. Needs the Claude Code CLI, an API key or login, the plugin loaded in place
 * (bun run plugin:link) and the workspace trusted for -p runs. Not run by default CI.
 *
 *   bun evals/RunFull.ts [fixture ...]        # default: all three fixtures
 *
 * Writes each run's JSON result to evals/results/runs/<iso>-<fixture>-<step>.json and exits
 * non-zero if any step errored.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "..");
const FIXTURES = process.argv.slice(2).length ? process.argv.slice(2) : ["quiet-day", "beaconing-recon-delta", "brute-force-dc-chain"];
const OUT = join(ROOT, "evals", "results", "runs");
mkdirSync(OUT, { recursive: true });

async function run(step: string, fixture: string, prompt: string, maxTurns: number): Promise<boolean> {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const proc = Bun.spawn(["claude", "-p", prompt, "--permission-mode", "acceptEdits", "--max-turns", String(maxTurns), "--output-format", "json"], {
    cwd: ROOT,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
  const code = await proc.exited;
  const file = join(OUT, `${stamp}-${fixture}-${step}.json`);
  writeFileSync(file, stdout || JSON.stringify({ error: stderr, exit: code }));
  let ok = code === 0;
  try {
    const d = JSON.parse(stdout);
    ok = ok && d.is_error !== true;
    console.log(`${fixture} ${step}: turns ${d.num_turns}, subagents ${d.subagent_stats?.spawned ?? 0}, cost $${(d.total_cost_usd ?? 0).toFixed(2)}, denials ${d.permission_denials?.length ?? 0} → ${file}`);
  } catch {
    console.log(`${fixture} ${step}: exit ${code}, no JSON result → ${file}`);
    ok = false;
  }
  return ok;
}

let allOk = true;
for (const f of FIXTURES) {
  const a = await run("investigate", f, `/casa:investigate intake/fixtures/${f}.intake.json`, 80);
  const b = a && (await run("evaluate", f, `/casa:evaluate ${f}`, 30));
  allOk = allOk && a && b;
}
process.exit(allOk ? 0 : 1);
