#!/usr/bin/env bun
// *****************************************************************************
// *Title: Run Transcript Scan*
// *Author: Kyle*
// *Description: Lists the tool calls of an eval run that left its lane.*
// *****************************************************************************

// Reads the Claude Code session transcripts of RunFull's investigate steps, main thread and
// subagents, and lists every tool call that names a path outside the run's lane: its own
// project, the plugin's skills, the two scripts the skill runs, and the plugin's data directory.
//
//   bun evals/ScanRuns.ts                      # every investigate result under evals/results/runs
//   bun evals/ScanRuns.ts --since 2026-11-21T07-49   # results whose file name sorts at or after this
//
// Exit 1 when a call outside the lane was not refused, or a run's transcript cannot be found.
// NOTE: the transcript location and line shape are Claude Code's own and may change with it;
// a run whose transcript is missing is reported, never counted as clean.

// *--- Imports ---*

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

// *--- Configuration ---*

const ROOT = join(import.meta.dir, "..");
const RUNS = join(ROOT, "evals", "results", "runs");
const PROJECTS = join(homedir(), ".claude", "projects");
// Top-level directories a path must start under to be read as a file path, so a pattern such as
// a sed address in a command is not mistaken for one.
const PATH_ROOTS = ["Users", "home", "private", "tmp", "var", "opt", "etc", "root", "mnt", "Volumes"];
const RE_ABSOLUTE = new RegExp(`(?<![\\w./~-])/(?:${PATH_ROOTS.join("|")})(?![\\w.-])(?:/[^\\s"'\`\\\\;|&()<>]*)?`, "g");
const RE_PARENT = /(?<![\w./~-])\.\.\/[^\s"'`\\;|&()<>]*/g;
// Tools whose text is prose or file content, where a path is a mention and not an access.
const PROSE_TOOLS = ["Agent", "Task"];
const WRITE_TOOLS = ["Write", "Edit", "MultiEdit", "NotebookEdit"];
// The scripts the investigate skill runs from the plugin, by Bash only.
const PLUGIN_SCRIPTS = [join("intake", "Validate.ts"), join("evals", "Lint.ts")];
// Where the analyst's approved lessons live; the plugin's own, outside the project by design.
const DATA_DIR_MARK = "/.claude/plugins/data/casa-";

// *--- Types ---*

export interface Lane {
  runDir: string;
  pluginRoot: string;
  // The session's id; Claude Code keeps a session's own task output under a directory named for it.
  sessionId?: string;
}

export interface ToolCall {
  name: string;
  input: Record<string, unknown>;
}

export interface Hit {
  tool: string;
  path: string;
  denied: boolean;
}

// *--- Core Logic ---*

/** Every string inside a tool input, at any depth. */
function strings(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(strings);
  if (typeof value === "object" && value !== null) return Object.values(value).flatMap(strings);
  return [];
}

/** The absolute and parent-relative paths a tool input names, in order. */
export function pathsNamed(input: unknown): string[] {
  const out: string[] = [];
  for (const text of strings(input)) {
    const found: Array<{ at: number; path: string }> = [];
    for (const re of [RE_ABSOLUTE, RE_PARENT]) for (const m of text.matchAll(re)) found.push({ at: m.index, path: m[0] });
    out.push(...found.sort((a, b) => a.at - b.at).map((f) => f.path));
  }
  return out;
}

/** True when `path` is `dir` or lies under it. Compared without case: the volume may not have one. */
function within(path: string, dir: string): boolean {
  const p = path.toLowerCase();
  const d = dir.toLowerCase().replace(/\/+$/, "");
  return p === d || p.startsWith(`${d}/`);
}

/** The paths a call names that are outside the run's lane. */
export function outOfLane(call: ToolCall, lane: Lane): string[] {
  if (PROSE_TOOLS.includes(call.name)) return [];
  const named = WRITE_TOOLS.includes(call.name) ? pathsNamed(call.input.file_path) : pathsNamed(call.input);
  return named.filter((path) => {
    if (path.startsWith("../")) return true;
    if (within(path, lane.runDir)) return false;
    if (within(path, join(lane.pluginRoot, "skills"))) return false;
    if (call.name === "Bash" && PLUGIN_SCRIPTS.some((script) => path.toLowerCase() === join(lane.pluginRoot, script).toLowerCase())) return false;
    if (path.includes(DATA_DIR_MARK)) return false;
    if (lane.sessionId !== undefined && path.includes(`/${lane.sessionId}/`)) return false;
    return true;
  });
}

/** True when a tool result is Claude Code's refusal of the call. */
export function wasDenied(content: unknown): boolean {
  return strings(content).some((text) => /Permission to use \w+ has been denied/.test(text));
}

/** Every out-of-lane call in a run's transcripts, with whether each one was refused. */
export function scanTranscript(transcripts: string[], lane: Lane): { calls: number; hits: Hit[] } {
  const hits: Hit[] = [];
  const pending = new Map<string, Hit[]>();
  // NOTE: a transcript can record one tool call on more than one line; the id tells them apart.
  const seen = new Set<string>();
  let calls = 0;
  for (const text of transcripts) {
    for (const line of text.split("\n")) {
      if (line === "") continue;
      let parsed: { message?: { content?: unknown } };
      try {
        parsed = JSON.parse(line) as { message?: { content?: unknown } };
      } catch {
        continue;
      }
      const content = parsed.message?.content;
      if (!Array.isArray(content)) continue;
      for (const block of content as Array<{ type?: string; id?: string; name?: string; input?: Record<string, unknown>; tool_use_id?: string; content?: unknown }>) {
        if (block.type === "tool_use" && typeof block.name === "string" && block.input !== undefined) {
          if (typeof block.id === "string") {
            if (seen.has(block.id)) continue;
            seen.add(block.id);
          }
          calls++;
          const found = outOfLane({ name: block.name, input: block.input }, lane).map((path) => ({ tool: block.name as string, path, denied: false }));
          hits.push(...found);
          if (found.length > 0 && typeof block.id === "string") pending.set(block.id, found);
        } else if (block.type === "tool_result" && typeof block.tool_use_id === "string" && wasDenied(block.content)) {
          for (const hit of pending.get(block.tool_use_id) ?? []) hit.denied = true;
        }
      }
    }
  }
  return { calls, hits };
}

/** A session's transcript files: the main thread's, then any under its own directory. */
function transcriptFiles(sessionId: string): string[] {
  const walk = (dir: string): string[] =>
    readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(dir, e.name)) : e.name.endsWith(".jsonl") ? [join(dir, e.name)] : []));
  for (const project of existsSync(PROJECTS) ? readdirSync(PROJECTS) : []) {
    const main = join(PROJECTS, project, `${sessionId}.jsonl`);
    if (!existsSync(main)) continue;
    const side = join(PROJECTS, project, sessionId);
    return [main, ...(existsSync(side) && statSync(side).isDirectory() ? walk(side) : [])];
  }
  return [];
}

/** The directory a session ran in: the first `cwd` its main transcript records. */
function sessionCwd(mainTranscript: string): string | null {
  for (const line of mainTranscript.split("\n")) {
    if (!line.includes('"cwd"')) continue;
    try {
      const cwd = (JSON.parse(line) as { cwd?: unknown }).cwd;
      if (typeof cwd === "string") return cwd;
    } catch {
      continue;
    }
  }
  return null;
}

// *--- Entry Point ---*

if (import.meta.main) {
  const args = process.argv.slice(2);
  const since = args[0] === "--since" ? (args[1] ?? "") : "";
  if (args.length > 0 && (args[0] !== "--since" || since === "" || args.length > 2)) {
    console.error("usage: bun evals/ScanRuns.ts [--since <result file name prefix>]");
    process.exit(2);
  }
  let runs = 0;
  let calls = 0;
  let open = 0;
  let unproven = 0;
  for (const name of existsSync(RUNS) ? readdirSync(RUNS).sort() : []) {
    if (!name.endsWith("-investigate.json") || name < since) continue;
    let result: { session_id?: unknown; is_error?: unknown };
    try {
      result = JSON.parse(readFileSync(join(RUNS, name), "utf8")) as { session_id?: unknown; is_error?: unknown };
    } catch {
      continue;
    }
    // A step the usage limit or a timeout cut short never investigated anything.
    if (typeof result.session_id !== "string" || result.is_error === true) continue;
    const files = transcriptFiles(result.session_id);
    const texts = files.map((f) => readFileSync(f, "utf8"));
    const runDir = texts.length > 0 ? sessionCwd(texts[0] as string) : null;
    if (runDir === null) {
      unproven++;
      console.log(`${name}: no transcript found, cannot show this run stayed in its lane`);
      continue;
    }
    const found = scanTranscript(texts, { runDir, pluginRoot: ROOT, sessionId: result.session_id });
    runs++;
    calls += found.calls;
    for (const hit of found.hits) {
      if (!hit.denied) open++;
      console.log(`${name}: ${hit.denied ? "refused" : "NOT REFUSED"} ${hit.tool} ${hit.path}`);
    }
  }
  console.log(`${runs} investigate run(s), ${calls} tool call(s); outside the lane and not refused: ${open}; runs without a transcript: ${unproven}`);
  process.exit(open > 0 || unproven > 0 ? 1 : 0);
}
