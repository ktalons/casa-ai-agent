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
 *     detection-engineer           files only under <root>/detections/proposed/
 *     evaluator                    files only under <root>/evals/results/
 *     any other CASA agent         no file writes
 *     Bash, from any of the above  denied: commands go in data_requests for the main thread
 *   any other subagent             no decision
 *
 * <root> is the plugin option output_root, which Claude Code exports to hooks as
 * CLAUDE_PLUGIN_OPTION_OUTPUT_ROOT; empty or unset means the hook's cwd, as it always has, and a
 * relative value resolves against CLAUDE_PROJECT_DIR (else the cwd). A configured root fails closed
 * when it starts with ~, lies inside the plugin, has a detections/accepted segment, is a symlink,
 * or sits behind a symlink inside the project. Deny is a JSON permissionDecision with a reason and exit 0. Unreadable input, a missing
 * path or a symlink on the way exits 2, which blocks the call: fail closed. guard.sh wraps
 * this script so a missing or crashing bun still blocks CASA agents, and runs bun from the
 * hook directory so the project's bunfig.toml and .env cannot load.
 */

// *--- Imports ---*

import { lstatSync, realpathSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";

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

const PREFIX = "casa:";

export const OUTPUT_ROOT_ENV = "CLAUDE_PLUGIN_OPTION_OUTPUT_ROOT";

// *--- Types ---*

export type Env = Record<string, string | undefined>;

export type Decision = { exit: 0; output?: string } | { exit: 2; reason: string };

type Caller = { kind: "foreign" } | { kind: "unknown" } | { kind: "casa"; name: string };

type HookInput = {
  agent_id?: unknown;
  agent_type?: unknown;
  cwd?: unknown;
  tool_name?: unknown;
  tool_input?: { file_path?: unknown; notebook_path?: unknown };
};

// *--- Helper Functions ---*

/** Work out who is asking from the agent fields of the hook input. */
function identify(i: HookInput): Caller {
  // SECURITY: names compare lowercased so a case variant cannot slip past the CASA checks.
  const type = typeof i.agent_type === "string" ? i.agent_type.toLowerCase() : "";
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

/** True when a relative path leaves its base: `..` itself, `..` then a separator, or an absolute result. */
function escapes(rel: string): boolean {
  return rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel);
}

/** True when `path` is `dir` or lies under it. */
function within(dir: string, path: string): boolean {
  return !escapes(relative(dir, path));
}

/** The physical path when it exists, else the path as given. */
function physical(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return path;
  }
}

/** True when the path has a detections/accepted segment pair, in any case. */
function hasAcceptedSegment(path: string): boolean {
  const parts = path.toLowerCase().split(sep);
  return parts.some((p, n) => p === "detections" && parts[n + 1] === "accepted");
}

/** The directory every lane resolves against, or the reason a configured root is refused. */
function outputRoot(cwd: string, env: Env): { root: string } | { refuse: string } {
  const configured = (env[OUTPUT_ROOT_ENV] ?? "").trim();
  if (configured === "") return { root: cwd };
  // SECURITY: no shell expands ~ here, so it would name a directory literally called ~.
  if (configured.startsWith("~")) return { refuse: `guard: the output root ${configured} starts with ~; set an absolute path` };
  const project = (env.CLAUDE_PROJECT_DIR ?? "").trim() || cwd;
  const root = resolve(project, configured);
  // SECURITY: each check reads the path as written and as the filesystem resolves it.
  const forms = [root, physical(root)];
  const plugin = (env.CLAUDE_PLUGIN_ROOT ?? "").trim();
  if (plugin && forms.some((r) => within(plugin, r) || within(physical(plugin), r))) return { refuse: `guard: the output root ${root} is inside the plugin directory` };
  if (forms.some(hasAcceptedSegment)) return { refuse: `guard: the output root ${root} has a detections/accepted segment` };
  // Inside the project every component below it is checked; outside it only the root itself, so a
  // system symlink above an absolute root (macOS /tmp) still works.
  const rel = relative(project, root);
  const steps = within(project, root) && rel !== "" ? rel.split(sep).map((_, n, all) => resolve(project, all.slice(0, n + 1).join(sep))) : [root];
  for (const p of steps) {
    try {
      if (lstatSync(p).isSymbolicLink()) return { refuse: `guard: the output root ${root} goes through symlink ${p}` };
    } catch {
      break;
    }
  }
  return { root };
}

/** Judge a file write by a CASA agent against its lane. */
function decideWrite(agent: string, i: HookInput, env: Env): Decision {
  // SECURITY: own keys only, so casa:__proto__ or casa:constructor cannot reach a prototype member.
  const lanes = Object.hasOwn(LANES, agent) ? LANES[agent] : undefined;
  if (!lanes) return deny(`guard: casa:${agent} may not write files; return findings in your response instead`);

  const cwd = typeof i.cwd === "string" ? i.cwd : "";
  const raw = i.tool_input?.file_path ?? i.tool_input?.notebook_path;
  if (!cwd || typeof raw !== "string" || raw.length === 0) return { exit: 2, reason: "guard: missing cwd or file path in hook input" };

  // SECURITY: '..' after a symlink resolves physically, not lexically, so refuse it outright.
  if (hasParentSegment(raw)) return deny(`guard: casa:${agent} may not use '..' in a write path (${raw})`);

  const chosen = outputRoot(cwd, env);
  if ("refuse" in chosen) return { exit: 2, reason: chosen.refuse };
  const root = chosen.root;
  const target = resolve(cwd, raw);
  const rel = relative(root, target);
  const where = root === cwd ? "the project" : `the output root ${root}`;
  if (rel === "" || escapes(rel)) return deny(`guard: casa:${agent} may not write outside ${where} (${raw})`);

  // Refuse to write through a symlink anywhere on the path inside the root.
  const parts = rel.split(sep);
  for (let n = 1; n <= parts.length; n++) {
    const p = resolve(root, parts.slice(0, n).join(sep));
    try {
      if (lstatSync(p).isSymbolicLink()) return { exit: 2, reason: `guard: refusing to write through symlink ${p}` };
    } catch {
      break;
    }
  }

  const allowed = lanes.some((lane) => rel === lane || rel.startsWith(lane + sep));
  return allowed ? { exit: 0 } : deny(`guard: casa:${agent} may write only under ${lanes.join(", ")} (asked for ${rel})`);
}

// *--- Public Interface ---*

/** Decide one PreToolUse call; `env` supplies the output root option. */
export function decide(input: unknown, env: Env = process.env): Decision {
  if (typeof input !== "object" || input === null) return { exit: 2, reason: "guard: hook input is not an object" };
  const i = input as HookInput;
  const caller = identify(i);
  if (caller.kind === "foreign") return { exit: 0 };
  // SECURITY: no command allowlist survives the shell's parser, so CASA subagents get no shell.
  if (i.tool_name === "Bash") {
    const who = caller.kind === "casa" ? `casa:${caller.name}` : "a subagent without agent_type";
    return deny(`guard: ${who} has no shell; put the command in your finding's data_requests for the main thread to run`);
  }
  if (caller.kind === "unknown") return deny("guard: a subagent call arrived without agent_type; refusing because the caller cannot be identified");
  return decideWrite(caller.name, i, env);
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
