// *****************************************************************************
// *Title: CASA Bash Policy*
// *Author: Kyle Versluis*
// *Description: Read-only allowlist for Bash calls made by CASA subagents.*
// *****************************************************************************

/**
 * A command passes only when every pipeline segment starts with an allowlisted read-only
 * command, its options cannot name an output file, every file it reads sits inside the
 * project or the plugin and is not a secret, and no redirect writes anywhere but /dev/null.
 * Anything the parser cannot model (substitution, subshells, heredocs, variables, globs,
 * background jobs) is refused: the policy fails closed.
 */

// *--- Imports ---*

import { lstatSync } from "node:fs";
import { isAbsolute, join, relative, resolve, sep } from "node:path";

// *--- Types ---*

export type BashVerdict = { ok: true } | { ok: false; reason: string };

/** One shell word after quote removal, with the expansions bash would still apply to it. */
type Word = { text: string; glob: boolean };

type Redirect = { op: string; target: string; glob: boolean };

type Segment = { words: Word[]; redirects: Redirect[] };

type Parsed = { ok: true; segments: Segment[] } | { ok: false; reason: string };

/**
 * How a command's arguments split into options, option values and operands. Every option
 * a reader may take is listed; any other is refused. Values named in the *Path fields are
 * files the command reads, so they get the same path check as operands.
 */
type OptionSpec = {
  flags: string;
  flagsWithArg: string;
  pathFlags: string;
  long: string[];
  longWithArg: string[];
  longPathArgs: string[];
  longWithTwoArgs: string[];
  longTwoArgPath: string[];
  required: string[];
  operands: "paths" | "none" | "jq";
};

/** Where an argument list's file reads are, after options are taken out. */
type Walked = { paths: Word[]; operands: Word[]; seen: Set<string> };

// *--- Configuration ---*

const SPEC_DEFAULTS: OptionSpec = {
  flags: "",
  flagsWithArg: "",
  pathFlags: "",
  long: [],
  longWithArg: [],
  longPathArgs: [],
  longWithTwoArgs: [],
  longTwoArgPath: [],
  required: [],
  operands: "paths",
};

// Searching and reading files belong to the Grep and Read tools, so grep and cat are absent.
// SECURITY: wc --files0-from reads a named file, tail -f/-F never exits, tshark -w/-X write or
// run code. Only the options a read needs are listed; no reader accepts an unlisted one.
const READERS: Record<string, OptionSpec> = {
  head: { ...SPEC_DEFAULTS, flags: "qv", flagsWithArg: "nc", long: ["quiet", "verbose"], longWithArg: ["bytes", "lines"] },
  tail: { ...SPEC_DEFAULTS, flags: "qv", flagsWithArg: "nc", long: ["quiet", "verbose"], longWithArg: ["bytes", "lines"] },
  wc: { ...SPEC_DEFAULTS, flags: "clLmw", long: ["bytes", "chars", "lines", "max-line-length", "words"] },
  ls: { ...SPEC_DEFAULTS, flags: "1aAhlRrSt" },
  // Flags from zeek-cut's usage text: header blocks, time formats, field separator, negation.
  "zeek-cut": { ...SPEC_DEFAULTS, flags: "cCdhmMnu", flagsWithArg: "DFU", operands: "none" },
  jq: {
    ...SPEC_DEFAULTS,
    flags: "acCefjMnrRsS",
    flagsWithArg: "L",
    pathFlags: "L",
    long: [
      "ascii-output", "color-output", "compact-output", "exit-status", "from-file", "join-output",
      "monochrome-output", "null-input", "raw-input", "raw-output", "raw-output0", "seq", "slurp",
      "sort-keys", "stream", "stream-errors", "tab", "unbuffered",
    ],
    longWithArg: ["indent"],
    longWithTwoArgs: ["arg", "argjson", "rawfile", "slurpfile"],
    longTwoArgPath: ["rawfile", "slurpfile"],
    operands: "jq",
  },
  tshark: {
    ...SPEC_DEFAULTS,
    flags: "2lnPqQVx",
    flagsWithArg: "cdeEHjJNrRStTuYz",
    pathFlags: "rH",
    long: [],
    required: ["r"],
    operands: "none",
  },
};

// SECURITY: env and $ENV print the environment; import and include load files by name.
const JQ_FORBIDDEN = /\$ENV\b|(?<![.\w$])env\b|\bimport\b|\binclude\b/;

const SECRET_DIRS = new Set([".ssh", ".aws"]);

// Plugin scripts a CASA subagent may run; Grade.ts is absent because it writes a grade file.
const PLUGIN_SCRIPTS = ["intake/Validate.ts", "evals/Lint.ts"];

const PLUGIN_ROOT_VAR = "CLAUDE_PLUGIN_ROOT";

// *--- Parser ---*

/** Split a command into pipeline segments the way bash would, refusing what it cannot model. */
export function parseCommand(command: string, pluginRoot: string): Parsed {
  if (/[`]|\$\(|<\(|>\(/.test(command)) return { ok: false, reason: "command or process substitution" };

  const segments: Segment[] = [];
  let seg: Segment = { words: [], redirects: [] };
  let text = "";
  let glob = false;
  let started = false;
  let quotedPart = false;
  let pending: string | null = null;
  let trailing = false;
  let i = 0;

  const fail = (reason: string): Parsed => ({ ok: false, reason });

  const endWord = (): void => {
    if (!started) return;
    if (pending !== null) seg.redirects.push({ op: pending, target: text, glob });
    else seg.words.push({ text, glob });
    pending = null;
    text = "";
    glob = false;
    started = false;
    quotedPart = false;
  };

  const endSegment = (): boolean => {
    endWord();
    if (pending !== null || seg.words.length === 0) return false;
    segments.push(seg);
    seg = { words: [], redirects: [] };
    return true;
  };

  // SECURITY: the only expansion allowed is the plugin root, which the agent cannot set.
  const expandVariable = (at: number): number | null => {
    for (const form of [`\${${PLUGIN_ROOT_VAR}}`, `$${PLUGIN_ROOT_VAR}`]) {
      if (!command.startsWith(form, at)) continue;
      const next = command[at + form.length] ?? "";
      if (form.endsWith("}") || !/[A-Za-z0-9_]/.test(next)) {
        text += pluginRoot;
        return at + form.length;
      }
    }
    return null;
  };

  while (i < command.length) {
    const c = command[i]!;
    if (c === " " || c === "\t") { endWord(); i++; continue; }
    if (c === "\n" || c === ";") {
      // Blank lines are harmless to bash; an empty command before ';' is a syntax error.
      const blank = !started && pending === null && seg.words.length === 0 && seg.redirects.length === 0;
      if (!(c === "\n" && blank) && !endSegment()) return fail("empty command or dangling redirect");
      trailing = true;
      i++;
      continue;
    }
    trailing = false;
    if (c === "\\") {
      if (command[i + 1] === "\n") { i += 2; continue; }
      if (i + 1 >= command.length) return fail("trailing backslash");
      text += command[i + 1];
      started = true;
      i += 2;
      continue;
    }
    if (c === "'") {
      const close = command.indexOf("'", i + 1);
      if (close < 0) return fail("unterminated single quote");
      if (/[\n\r]/.test(command.slice(i + 1, close))) return fail("newline inside quotes");
      text += command.slice(i + 1, close);
      started = true;
      quotedPart = true;
      i = close + 1;
      continue;
    }
    if (c === '"') {
      i++;
      started = true;
      quotedPart = true;
      for (;;) {
        if (i >= command.length) return fail("unterminated double quote");
        const d = command[i]!;
        if (d === '"') { i++; break; }
        if (d === "\n" || d === "\r") return fail("newline inside quotes");
        if (d === "\\" && i + 1 < command.length && '"\\$\n'.includes(command[i + 1]!)) {
          if (command[i + 1] !== "\n") text += command[i + 1];
          i += 2;
          continue;
        }
        if (d === "$") {
          const after = expandVariable(i);
          if (after === null) return fail("variable expansion");
          i = after;
          continue;
        }
        text += d;
        i++;
      }
      continue;
    }
    if (c === "$") {
      const after = expandVariable(i);
      if (after === null) return fail("variable expansion");
      started = true;
      i = after;
      continue;
    }
    if (c === "|") {
      if (command[i + 1] === "&") return fail("|& pipes stderr into a command");
      if (!endSegment()) return fail("empty command or dangling redirect");
      i += command[i + 1] === "|" ? 2 : 1;
      continue;
    }
    if (c === "&") {
      if (command[i + 1] === "&") {
        if (!endSegment()) return fail("empty command or dangling redirect");
        i += 2;
        continue;
      }
      if (command[i + 1] !== ">") return fail("background job");
      endWord();
      if (pending !== null) return fail("dangling redirect");
      const op = command[i + 2] === ">" ? "&>>" : "&>";
      pending = op;
      i += op.length;
      continue;
    }
    if (c === "(" || c === ")") return fail("subshell or grouping");
    if (c === ">" || c === "<") {
      // SECURITY: zsh reads <N-M> as a numeric glob, which could expand to extra file operands.
      if (c === "<" && /^<\d*-\d*>/.test(command.slice(i))) return fail("zsh numeric glob");
      // A bare run of digits right before the operator is a file descriptor, not a word.
      if (started && !quotedPart && /^\d+$/.test(text)) { text = ""; started = false; }
      else endWord();
      if (pending !== null) return fail("dangling redirect");
      const op = /^(>>|>\||>&|>|<<<|<<|<>|<&|<)/.exec(command.slice(i))![1]!;
      pending = op;
      i += op.length;
      continue;
    }
    // SECURITY: an unquoted # opening a word starts a comment the shell skips but this parser would not.
    if (c === "#" && !started) return fail("shell comment");
    // zsh with EXTENDED_GLOB also expands ^, ~ and #, and Claude Code may run the user's zsh.
    if ("*?[]{}^~#".includes(c)) glob = true;
    text += c;
    started = true;
    i++;
  }
  endWord();
  // A trailing ';' or newline leaves an empty last segment that bash ignores.
  const empty = pending === null && seg.words.length === 0 && seg.redirects.length === 0;
  if (!(empty && trailing && segments.length > 0) && !endSegment()) return fail("empty command or dangling redirect");
  return { ok: true, segments };
}

// *--- Checks ---*

/** Return the path relative to `base` when `target` lies at or under it, else null. */
function within(base: string, target: string): string | null {
  const rel = relative(base, target);
  return rel === "" || !(rel === ".." || rel.startsWith(".." + sep) || isAbsolute(rel)) ? rel : null;
}

/** A file read must stay inside the project or the plugin, off symlinks, away from secrets. */
function checkReadPath(raw: string, cwd: string, pluginRoot: string): string | null {
  if (raw === "-" || raw === "/dev/null") return null;
  // SECURITY: ~ and zsh's =cmd expand to paths outside the project before the command sees them.
  if (raw.startsWith("~") || raw.startsWith("=")) return `path ${raw} expands outside the project`;
  if (raw.split(/[\\/]/).includes("..")) return `path ${raw} uses '..'`;
  const target = resolve(cwd, raw);
  const base = [cwd, pluginRoot].find((b) => within(b, target) !== null);
  if (base === undefined) return `path ${raw} is outside the project and the plugin`;
  const parts = within(base, target)!.split(sep).filter((p) => p !== "");
  for (const p of parts) {
    const lower = p.toLowerCase();
    if (SECRET_DIRS.has(lower) || lower === ".env" || lower.startsWith(".env.")) return `path ${raw} names a secret`;
  }
  const name = (parts[parts.length - 1] ?? "").toLowerCase();
  if (name.endsWith(".key") || name.endsWith(".pem") || name.startsWith("id_")) return `path ${raw} names a secret`;
  for (let n = 1; n <= parts.length; n++) {
    const p = join(base, ...parts.slice(0, n));
    try {
      if (lstatSync(p).isSymbolicLink()) return `path ${raw} goes through symlink ${p}`;
    } catch {
      break;
    }
  }
  return null;
}

/** Refuse a redirect unless it reads a safe file, duplicates a descriptor, or discards output. */
function checkRedirect(r: Redirect, cwd: string, pluginRoot: string): string | null {
  if (r.glob) return `redirect ${r.op} with an unquoted glob or brace`;
  if (r.op === "<") return checkReadPath(r.target, cwd, pluginRoot);
  if (r.op === ">&" || r.op === "<&") return /^(\d+|-)$/.test(r.target) ? null : `redirect ${r.op}${r.target} writes a file`;
  if ([">", ">>", ">|", "&>", "&>>"].includes(r.op)) return r.target === "/dev/null" ? null : `redirect ${r.op} ${r.target} writes a file`;
  return `redirect ${r.op} is not allowed`;
}

/** Split a command's arguments into option paths and operands, refusing unlisted options. */
function walkOptions(cmd: string, args: Word[], spec: OptionSpec): Walked | string {
  const walked: Walked = { paths: [], operands: [], seen: new Set() };
  let endOfOptions = false;
  for (let n = 0; n < args.length; n++) {
    const t = args[n]!.text;
    if (endOfOptions || t === "-" || !t.startsWith("-")) {
      walked.operands.push(args[n]!);
      continue;
    }
    if (t === "--") { endOfOptions = true; continue; }
    if (t.startsWith("--")) {
      const eq = t.indexOf("=");
      const name = eq < 0 ? t.slice(2) : t.slice(2, eq);
      walked.seen.add(name);
      if (spec.longWithTwoArgs.includes(name) && eq < 0) {
        if (n + 2 >= args.length) return `${cmd} --${name} needs two arguments`;
        if (spec.longTwoArgPath.includes(name)) walked.paths.push(args[n + 2]!);
        n += 2;
        continue;
      }
      if (spec.longWithArg.includes(name) || spec.longPathArgs.includes(name)) {
        const value = eq < 0 ? args[++n] : { text: t.slice(eq + 1), glob: false };
        if (value === undefined) return `${cmd} --${name} needs an argument`;
        if (spec.longPathArgs.includes(name)) walked.paths.push(value);
        continue;
      }
      if (spec.long.includes(name) && eq < 0) continue;
      return `${cmd} --${name} is not allowed`;
    }
    for (let j = 1; j < t.length; j++) {
      const f = t[j]!;
      walked.seen.add(f);
      if (spec.flagsWithArg.includes(f)) {
        const attached = t.slice(j + 1);
        const value = attached !== "" ? { text: attached, glob: false } : args[++n];
        if (value === undefined) return `${cmd} -${f} needs an argument`;
        if (spec.pathFlags.includes(f)) walked.paths.push(value);
        break;
      }
      if (!spec.flags.includes(f)) return `${cmd} -${f} is not allowed`;
    }
  }
  for (const r of spec.required) if (!walked.seen.has(r)) return `${cmd} without -${r} is not a read`;
  return walked;
}

/** Check a reader's options, then every file it would open. */
function checkReader(cmd: string, args: Word[], spec: OptionSpec, cwd: string, pluginRoot: string): string | null {
  const walked = walkOptions(cmd, args, spec);
  if (typeof walked === "string") return walked;
  const paths = [...walked.paths];
  if (spec.operands === "paths") paths.push(...walked.operands);
  if (spec.operands === "jq") {
    // Without --from-file the first operand is the filter; with it, that operand is a file too.
    const fromFile = walked.seen.has("f") || walked.seen.has("from-file");
    const [first, ...rest] = walked.operands;
    if (first !== undefined && !fromFile && JQ_FORBIDDEN.test(first.text)) return "jq filter uses env, $ENV, import or include";
    paths.push(...(fromFile ? walked.operands : rest));
  }
  for (const p of paths) {
    const bad = checkReadPath(p.text, cwd, pluginRoot);
    if (bad) return bad;
  }
  return null;
}

/** Allow bun only as `bun <plugin script> [args]` for a script that reads and prints. */
function checkBun(args: Word[], cwd: string, pluginRoot: string): string | null {
  const [script, ...rest] = args;
  if (script === undefined) return "bun with no script";
  const target = resolve(cwd, script.text);
  if (!PLUGIN_SCRIPTS.some((s) => target === join(pluginRoot, s))) {
    return `bun may run only ${PLUGIN_SCRIPTS.join(", ")} from the plugin (asked for ${script.text})`;
  }
  // The scripts take file paths and a few flags; every non-flag argument is read as a file.
  for (const a of rest) {
    if (a.text.startsWith("-")) continue;
    const bad = checkReadPath(a.text, cwd, pluginRoot);
    if (bad) return bad;
  }
  return null;
}

/** Check one pipeline segment: allowlisted command, safe options, safe files, safe redirects. */
function checkSegment(seg: Segment, cwd: string, pluginRoot: string): string | null {
  for (const r of seg.redirects) {
    const bad = checkRedirect(r, cwd, pluginRoot);
    if (bad) return bad;
  }
  const [head, ...args] = seg.words;
  const cmd = head!.text;
  if (cmd.includes("=")) return `environment assignment ${cmd}`;
  // SECURITY: a glob or brace could expand to an option (-wfoo), a secret, or a symlink.
  if (seg.words.some((w) => w.glob)) return `${cmd} with an unquoted glob or brace`;
  if (cmd === "bun") return checkBun(args, cwd, pluginRoot);
  const spec = READERS[cmd];
  if (spec) return checkReader(cmd, args, spec, cwd, pluginRoot);
  return `${cmd} is not on the read-only allowlist`;
}

// *--- Public Interface ---*

/** Decide whether a CASA subagent's Bash command is read-only under the shipped policy. */
export function checkBash(command: string, cwd: string, pluginRoot: string): BashVerdict {
  if (command.trim() === "") return { ok: false, reason: "empty command" };
  const parsed = parseCommand(command, pluginRoot);
  if (!parsed.ok) return parsed;
  for (const seg of parsed.segments) {
    const bad = checkSegment(seg, cwd, pluginRoot);
    if (bad) return { ok: false, reason: bad };
  }
  return { ok: true };
}
