#!/usr/bin/env bun
// *****************************************************************************
// *Title: CASA Write Guard*
// *Author: Kyle Versluis*
// *Description: PreToolUse guard keeping each CASA subagent inside its lane.*
// *****************************************************************************

/**
 * Plugin agents cannot carry their own hooks, so this one hook is registered for the whole
 * plugin and decides by the agent fields Claude Code puts in the hook input:
 *
 *   no agent_id, no casa: prefix   main thread or a foreign --agent session: no decision
 *   agent_id, agent_type missing   cannot tell who is asking: denied
 *   casa:<name>, or bare <name>    a CASA agent (bare names count only with an agent_id)
 *     detection-engineer           files only under detections/proposed/
 *     evaluator                    files only under evals/results/
 *     any other CASA agent         no file writes
 *     Bash                         read-only allowlist in bash-policy.ts, analysts only
 *   any other subagent             no decision
 *
 * Deny is a JSON permissionDecision with a reason and exit 0. Unreadable input, a missing
 * path or a symlink on the way exits 2, which blocks the call: fail closed. guard.sh wraps
 * this script so a missing or crashing bun still blocks CASA agents.
 */

// *--- Imports ---*

import { lstatSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { checkBash } from "./bash-policy.ts";

// *--- Configuration ---*

// Every agent under agents/; guard.test.ts fails if this drifts from the frontmatter.
export const CASA_AGENTS = new Set([
  "detection-engineer",
  "endpoint-analyst",
  "evaluator",
  "log-analyst",
  "network-analyst",
  "pentester",
  "purple-team-mapper",
  "threat-intel",
]);

export const LANES: Record<string, string[]> = {
  "detection-engineer": ["detections/proposed"],
  evaluator: ["evals/results"],
};

export const BASH_AGENTS = new Set(["endpoint-analyst", "log-analyst", "network-analyst"]);

const PLUGIN_ROOT = resolve(import.meta.dir, "..");

const PREFIX = "casa:";

// *--- Types ---*

export type Decision = { exit: 0; output?: string } | { exit: 2; reason: string };

type Caller = { kind: "foreign" } | { kind: "unknown" } | { kind: "casa"; name: string };

type HookInput = {
  agent_id?: unknown;
  agent_type?: unknown;
  cwd?: unknown;
  tool_name?: unknown;
  tool_input?: { file_path?: unknown; notebook_path?: unknown; command?: unknown };
};

// *--- Helper Functions ---*

/** Work out who is asking from the agent fields of the hook input. */
function identify(i: HookInput): Caller {
  const type = typeof i.agent_type === "string" ? i.agent_type : "";
  const subagent = i.agent_id !== undefined && i.agent_id !== null;
  if (type.startsWith(PREFIX)) return { kind: "casa", name: type.slice(PREFIX.length) };
  if (!subagent) return { kind: "foreign" };
  // SECURITY: Claude Code always pairs agent_id with agent_type; one without the other is drift.
  if (type === "") return { kind: "unknown" };
  return CASA_AGENTS.has(type) ? { kind: "casa", name: type } : { kind: "foreign" };
}

function deny(reason: string): Decision {
  return {
    exit: 0,
    output: JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: reason } }),
  };
}

/** True when any segment of the raw path is `..`, before any normalization. */
function hasParentSegment(raw: string): boolean {
  return raw.split(/[\\/]/).includes("..");
}

// *--- Core Logic ---*

/** Judge a file write by a CASA agent against its lane. */
function decideWrite(agent: string, i: HookInput): Decision {
  const lanes = LANES[agent];
  if (!lanes) return deny(`guard: casa:${agent} may not write files; return findings in your response instead`);

  const cwd = typeof i.cwd === "string" ? i.cwd : "";
  const raw = i.tool_input?.file_path ?? i.tool_input?.notebook_path;
  if (!cwd || typeof raw !== "string" || raw.length === 0) return { exit: 2, reason: "guard: missing cwd or file path in hook input" };

  // SECURITY: '..' after a symlink resolves physically, not lexically, so refuse it outright.
  if (hasParentSegment(raw)) return deny(`guard: casa:${agent} may not use '..' in a write path (${raw})`);

  const target = resolve(cwd, raw);
  const rel = relative(cwd, target);
  if (rel === "" || rel.startsWith("..") || isAbsolute(rel)) return deny(`guard: casa:${agent} may not write outside the project (${raw})`);

  // Refuse to write through a symlink anywhere on the path inside the project.
  const parts = rel.split(sep);
  for (let n = 1; n <= parts.length; n++) {
    const p = resolve(cwd, parts.slice(0, n).join(sep));
    try {
      if (lstatSync(p).isSymbolicLink()) return { exit: 2, reason: `guard: refusing to write through symlink ${p}` };
    } catch {
      break;
    }
  }

  const allowed = lanes.some((lane) => rel === lane || rel.startsWith(lane + sep));
  return allowed ? { exit: 0 } : deny(`guard: casa:${agent} may write only under ${lanes.join(", ")} (asked for ${rel})`);
}

/** Judge a Bash call by a CASA agent against the read-only policy. */
function decideBash(agent: string, i: HookInput, pluginRoot: string): Decision {
  if (!BASH_AGENTS.has(agent)) return deny(`guard: casa:${agent} has no Bash lane`);
  const command = i.tool_input?.command;
  const cwd = typeof i.cwd === "string" ? i.cwd : "";
  if (typeof command !== "string" || !cwd) return { exit: 2, reason: "guard: missing cwd or command in hook input" };
  const verdict = checkBash(command, cwd, pluginRoot);
  return verdict.ok ? { exit: 0 } : deny(`guard: casa:${agent} may run only read-only commands (${verdict.reason})`);
}

// *--- Public Interface ---*

/** Decide one PreToolUse call; `pluginRoot` locates the scripts Bash may run. */
export function decide(input: unknown, pluginRoot: string = PLUGIN_ROOT): Decision {
  if (typeof input !== "object" || input === null) return { exit: 2, reason: "guard: hook input is not an object" };
  const i = input as HookInput;
  const caller = identify(i);
  if (caller.kind === "foreign") return { exit: 0 };
  if (caller.kind === "unknown") return deny("guard: a subagent call arrived without agent_type; refusing because the caller cannot be identified");
  if (i.tool_name === "Bash") return decideBash(caller.name, i, pluginRoot);
  return decideWrite(caller.name, i);
}

// *--- Entry Point ---*

if (import.meta.main) {
  let text = "";
  try {
    text = await Bun.stdin.text();
  } catch {
    console.error("guard: cannot read stdin");
    process.exit(2);
  }
  let input: unknown;
  try {
    input = JSON.parse(text);
  } catch {
    console.error("guard: hook input is not JSON");
    process.exit(2);
  }
  const d = decide(input);
  if (d.exit === 2) {
    console.error(d.reason);
    process.exit(2);
  }
  if (d.output) console.log(d.output);
  process.exit(0);
}
