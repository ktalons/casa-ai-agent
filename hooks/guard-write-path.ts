#!/usr/bin/env bun
/**
 * guard-write-path.ts — PreToolUse guard for file writes made by CASA subagents.
 *
 * Plugin agents cannot carry their own hooks, so this one hook is registered for the whole
 * plugin and decides by the `agent_type` field Claude Code puts in the hook input:
 *
 *   (no agent_type)             main thread, e.g. the developer or the Overseer: no decision
 *   casa:detection-engineer     may write only under detections/proposed/
 *   casa:evaluator              may write only under evals/results/
 *   any other casa:* agent      denied (they have no Write tool; this is defence in depth)
 *   non-casa agents             no decision
 *
 * Scope: this hook sees the Write, Edit, MultiEdit and NotebookEdit tools. Bash is not a file
 * tool; the analysts that carry it are confined by the permission allowlist (read-only analysis
 * commands), which lives in settings, not in the plugin. See SECURITY.md.
 *
 * Deny is a JSON permissionDecision with a reason and exit 0. Anything unexpected (unreadable
 * input, missing path, a path that escapes cwd, a symlink in the way) exits 2: fail closed.
 * Zero dependencies.
 */
import { lstatSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";

export const LANES: Record<string, string[]> = {
  "casa:detection-engineer": ["detections/proposed"],
  "casa:evaluator": ["evals/results"],
};

export type Decision = { exit: 0; output?: string } | { exit: 2; reason: string };

export function decide(input: unknown): Decision {
  if (typeof input !== "object" || input === null) return { exit: 2, reason: "guard: hook input is not an object" };
  const i = input as { agent_type?: unknown; cwd?: unknown; tool_name?: unknown; tool_input?: { file_path?: unknown; notebook_path?: unknown } };
  const agent = typeof i.agent_type === "string" ? i.agent_type : "";
  if (!agent.startsWith("casa:")) return { exit: 0 }; // main thread or a foreign agent: not ours to judge

  const lanes = LANES[agent];
  const deny = (reason: string): Decision => ({
    exit: 0,
    output: JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: reason } }),
  });
  if (!lanes) return deny(`guard: ${agent} may not write files; return findings in your response instead`);

  const cwd = typeof i.cwd === "string" ? i.cwd : "";
  const raw = i.tool_input?.file_path ?? i.tool_input?.notebook_path;
  if (!cwd || typeof raw !== "string" || raw.length === 0) return { exit: 2, reason: "guard: missing cwd or file path in hook input" };

  const target = resolve(cwd, raw);
  const rel = relative(cwd, target);
  if (rel === "" || rel.startsWith("..") || isAbsolute(rel)) return deny(`guard: ${agent} may not write outside the project (${raw})`);

  // Refuse to write through a symlink anywhere on the path inside the project.
  const parts = rel.split(sep);
  for (let n = 1; n <= parts.length; n++) {
    const p = resolve(cwd, parts.slice(0, n).join(sep));
    try { if (lstatSync(p).isSymbolicLink()) return { exit: 2, reason: `guard: refusing to write through symlink ${p}` }; } catch { break; }
  }

  const allowed = lanes.some((lane) => rel === lane || rel.startsWith(lane + sep));
  return allowed ? { exit: 0 } : deny(`guard: ${agent} may write only under ${lanes.join(", ")} (asked for ${rel})`);
}

if (import.meta.main) {
  let text = "";
  try { text = await Bun.stdin.text(); } catch { console.error("guard: cannot read stdin"); process.exit(2); }
  let input: unknown;
  try { input = JSON.parse(text); } catch { console.error("guard: hook input is not JSON"); process.exit(2); }
  const d = decide(input);
  if (d.exit === 2) { console.error(d.reason); process.exit(2); }
  if (d.output) console.log(d.output);
  process.exit(0);
}
