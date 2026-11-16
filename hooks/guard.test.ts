// *****************************************************************************
// *Title: CASA Write Guard Tests*
// *Author: Kyle Versluis*
// *Description: Unit and end-to-end tests for the PreToolUse write guard.*
// *****************************************************************************

// *--- Imports ---*

import { afterAll, expect, test } from "bun:test";
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import * as guard from "./guard-write-path.ts";

// *--- Configuration ---*

const ROOT = resolve(import.meta.dir, "..");
const decide = guard.decide;

const cwd = mkdtempSync(join(tmpdir(), "casa-guard-"));
mkdirSync(join(cwd, "detections", "proposed"), { recursive: true });
mkdirSync(join(cwd, "evals", "results"), { recursive: true });
mkdirSync(join(cwd, "agents"));
writeFileSync(join(cwd, "agents", "x.md"), "x");
symlinkSync(join(cwd, "agents"), join(cwd, "detections", "proposed", "link"));

// A PATH with no bun on it, and one bun that always crashes.
const NO_BUN_PATH = "/usr/bin:/bin";
const crashDir = mkdtempSync(join(tmpdir(), "casa-guard-bin-"));
writeFileSync(join(crashDir, "bun"), "#!/bin/sh\nexit 1\n");
chmodSync(join(crashDir, "bun"), 0o755);
const CRASH_PATH = `${crashDir}:${NO_BUN_PATH}`;
const BUN_PATH = `${dirname(process.execPath)}:${NO_BUN_PATH}`;

afterAll(() => {
  rmSync(cwd, { recursive: true, force: true });
  rmSync(crashDir, { recursive: true, force: true });
});

const hooksJson = JSON.parse(readFileSync(join(ROOT, "hooks", "hooks.json"), "utf8"));
const hookEntry = hooksJson.hooks.PreToolUse[0];
const hookCommand: string = hookEntry.hooks[0].command;
const matcher = new RegExp(`^(?:${hookEntry.matcher})$`);

// *--- Helper Functions ---*

type Agent = { agent_type?: string; agent_id?: string };

const sub = (agent_type: string): Agent => ({ agent_type, agent_id: "agent-test" });
const MAIN: Agent = {};

const call = (agent: Agent, tool_name: string, tool_input: Record<string, unknown>, at = cwd) => ({
  session_id: "00000000-0000-4000-8000-000000000000",
  cwd: at,
  hook_event_name: "PreToolUse",
  ...agent,
  tool_name,
  tool_input,
});
const write = (agent: Agent, file_path: string) => call(agent, "Write", { file_path, content: "x\n" });
const bash = (agent: Agent, command: string) => call(agent, "Bash", { command });
const input = (agent_type: string | undefined, file_path: string) => ({ agent_type, cwd, tool_name: "Write", tool_input: { file_path } });

const denyReason = (output: string | undefined): string | null => {
  if (typeof output !== "string" || output === "") return null;
  const o = JSON.parse(output).hookSpecificOutput;
  return o?.permissionDecision === "deny" ? String(o.permissionDecisionReason) : null;
};
const isDeny = (d: ReturnType<typeof decide>) => d.exit === 0 && denyReason(d.output) !== null;
const reasonOf = (d: ReturnType<typeof decide>) => (d.exit === 0 ? denyReason(d.output) : null);

/** Run the hooks.json command as Claude Code would: payload on stdin, `dir` as working directory. */
function runHook(payload: unknown, PATH: string, dir: string = ROOT) {
  const body = typeof payload === "string" ? payload : JSON.stringify(payload);
  const r = Bun.spawnSync(["/bin/sh", "-c", hookCommand], {
    cwd: dir,
    stdin: Buffer.from(body),
    env: { PATH, CLAUDE_PLUGIN_ROOT: ROOT, HOME: process.env.HOME ?? "/" },
    stdout: "pipe",
    stderr: "pipe",
  });
  return { exit: r.exitCode, stdout: r.stdout.toString().trim(), stderr: r.stderr.toString() };
}

/** Read name and tools from every agent file's frontmatter. */
function agentFrontmatter(): { name: string; tools: string[] }[] {
  return readdirSync(join(ROOT, "agents"))
    .filter((f) => f.endsWith(".md"))
    .map((f) => {
      const fm = readFileSync(join(ROOT, "agents", f), "utf8").split("---")[1] ?? "";
      const name = /^name:\s*(.+)$/m.exec(fm)?.[1]?.trim() ?? "";
      const tools = (/^tools:\s*(.+)$/m.exec(fm)?.[1] ?? "").split(",").map((t) => t.trim());
      return { name, tools };
    });
}

/** The recorded fixture payloads, in file order. */
function recordedPayloads() {
  const lines = readFileSync(join(import.meta.dir, "fixtures", "recorded-payloads.jsonl"), "utf8").trim().split("\n");
  return lines.map((l) => JSON.parse(l));
}

const DATA_REQUESTS = "data_requests";

// *--- Lane Tests ---*

test("main thread (no agent_type) gets no decision", () => {
  expect(decide(input(undefined, "agents/x.md"))).toEqual({ exit: 0 });
});
test("a non-casa agent gets no decision", () => {
  expect(decide(input("Explore", "agents/x.md"))).toEqual({ exit: 0 });
});
test("detection-engineer may write under detections/proposed only", () => {
  expect(decide(input("casa:detection-engineer", "detections/proposed/2026-10-05-T1.sigma.yml"))).toEqual({ exit: 0 });
  expect(isDeny(decide(input("casa:detection-engineer", "agents/x.md")))).toBe(true);
  expect(isDeny(decide(input("casa:detection-engineer", "detections/accepted/x.yml")))).toBe(true);
  expect(isDeny(decide(input("casa:detection-engineer", "detections/proposed-evil/x.yml")))).toBe(true);
});
test("evaluator may write under evals/results only, including absolute paths inside cwd", () => {
  expect(decide(input("casa:evaluator", join(cwd, "evals", "results", "f", "r.json")))).toEqual({ exit: 0 });
  expect(isDeny(decide(input("casa:evaluator", "briefs/x.md")))).toBe(true);
});
test("every other casa agent is denied all writes", () => {
  for (const a of ["casa:log-analyst", "casa:network-analyst", "casa:endpoint-analyst", "casa:purple-team-mapper", "casa:threat-intel", "casa:pentester"]) {
    expect(isDeny(decide(input(a, "detections/proposed/x.yml")))).toBe(true);
  }
});
test("escapes and symlinks fail closed", () => {
  expect(isDeny(decide(input("casa:evaluator", "../outside.json")))).toBe(true);
  expect(isDeny(decide(input("casa:evaluator", "/etc/passwd")))).toBe(true);
  const viaLink = decide(input("casa:detection-engineer", "detections/proposed/link/x.md"));
  expect(viaLink.exit).toBe(2);
  expect(decide("not an object").exit).toBe(2);
  expect(decide({ agent_type: "casa:evaluator", cwd, tool_input: {} }).exit).toBe(2);
});

// *--- ISC-12 Recorded Payload ---*

test("recorded payload: real subagent calls carry casa:<name> and agent_id, and each gets the expected decision", () => {
  const payloads = recordedPayloads();
  expect(payloads.length).toBe(3);
  const names = new Set(agentFrontmatter().map((a) => a.name));
  for (const p of payloads) {
    expect(p.hook_event_name).toBe("PreToolUse");
    expect(typeof p.agent_id).toBe("string");
    expect(p.agent_id.length).toBeGreaterThan(0);
    expect(p.agent_type).toMatch(/^casa:[a-z-]+$/);
    expect(names.has(p.agent_type.slice("casa:".length))).toBe(true);
  }
  const [bashCall, inLane, outside] = payloads;
  expect(bashCall.tool_name).toBe("Bash");
  expect(reasonOf(decide(bashCall))).toContain(DATA_REQUESTS);
  expect(inLane.tool_input.file_path.startsWith(`${inLane.cwd}/detections/proposed/`)).toBe(true);
  expect(decide(inLane)).toEqual({ exit: 0 });
  expect(isDeny(decide(outside))).toBe(true);

  // Derived, not recorded: the same calls with the subagent fields removed are the main thread.
  for (const p of [bashCall, outside]) {
    const { agent_id: _id, agent_type: _type, ...mainThread } = p;
    expect(decide(mainThread)).toEqual({ exit: 0 });
  }
});

// *--- ISC-13 Bare Names ---*

test("bare agent name: a CASA agent is judged whether its name arrives prefixed or bare", () => {
  expect(isDeny(decide(write(sub("casa:detection-engineer"), "agents/x.md")))).toBe(true);
  expect(isDeny(decide(write(sub("detection-engineer"), "agents/x.md")))).toBe(true);
  expect(isDeny(decide(write(sub("evaluator"), "briefs/x.md")))).toBe(true);
  expect(isDeny(decide(write(sub("log-analyst"), "detections/proposed/x.yml")))).toBe(true);
  expect(decide(write(sub("detection-engineer"), "detections/proposed/x.yml"))).toEqual({ exit: 0 });

  // A subagent with an agent_id but no agent_type cannot be identified, so it is refused.
  expect(isDeny(decide(write({ agent_id: "agent-test" }, "detections/proposed/x.yml")))).toBe(true);

  // Main thread, a foreign --agent session and other plugins' agents stay undecided.
  expect(decide(write(MAIN, "agents/x.md"))).toEqual({ exit: 0 });
  expect(decide(write({ agent_type: "detection-engineer" }, "agents/x.md"))).toEqual({ exit: 0 });
  expect(decide(write(sub("other:foo"), "agents/x.md"))).toEqual({ exit: 0 });
  expect(decide(write(sub("other:detection-engineer"), "agents/x.md"))).toEqual({ exit: 0 });
  expect(decide(write(sub("general-purpose"), "agents/x.md"))).toEqual({ exit: 0 });
});

// *--- Name Edge Cases ---*

test("prototype names: casa:__proto__ and friends get the normal no-writes deny, not an exception", () => {
  for (const name of ["__proto__", "constructor", "toString", "hasOwnProperty", "valueOf"]) {
    for (const who of [sub(`casa:${name}`), { agent_type: `casa:${name}` }]) {
      const d = decide(write(who, "detections/proposed/x.yml"));
      expect(reasonOf(d)).toContain("may not write files");
    }
  }
});

test("name case: a mixed-case CASA name is judged like the lowercase one", () => {
  for (const type of ["Casa:evaluator", "CASA:LOG-ANALYST", "Log-Analyst", "EVALUATOR"]) {
    expect(reasonOf(decide(bash(sub(type), "ls")))).toContain(DATA_REQUESTS);
    expect(isDeny(decide(write(sub(type), "agents/x.md")))).toBe(true);
  }
  expect(decide(write(sub("Casa:Evaluator"), "evals/results/x.json"))).toEqual({ exit: 0 });
  // Without the hook, a mixed-case CASA name is still blocked when bun is missing.
  expect(runHook(write(sub("Casa:evaluator"), "agents/x.md"), NO_BUN_PATH).exit).toBe(2);
  expect(runHook(write(sub("Log-Analyst"), "agents/x.md"), NO_BUN_PATH).exit).toBe(2);
  // Other names keep their case-insensitive non-CASA status.
  expect(decide(bash(sub("Other:foo"), "ls"))).toEqual({ exit: 0 });
});

// *--- ISC-14 Traversal ---*

test("traversal: a '..' segment in a CASA write path is denied even when it resolves inside the lane", () => {
  const de = sub("casa:detection-engineer");
  expect(isDeny(decide(write(de, "detections/proposed/../../x")))).toBe(true);
  expect(isDeny(decide(write(de, join(cwd, "detections/proposed/../../../outside.md"))))).toBe(true);
  // link points at agents/, so the OS resolves this to agents/../proposed/x.md, outside the lane.
  expect(isDeny(decide(write(de, "detections/proposed/link/../proposed/x.md")))).toBe(true);
  expect(isDeny(decide(write(de, "detections/proposed/../proposed/x.md")))).toBe(true);
  expect(isDeny(decide(write(sub("casa:evaluator"), "evals/results/../results/x.json")))).toBe(true);
});

// *--- ISC-15 Bun Missing ---*

test("bun missing: a CASA subagent call is blocked and everyone else passes", () => {
  expect(Bun.which("bun", { PATH: NO_BUN_PATH })).toBeNull();
  const casaCalls = [
    write(sub("casa:detection-engineer"), "detections/proposed/x.yml"),
    write(sub("detection-engineer"), "detections/proposed/x.yml"),
    write({ agent_id: "agent-test" }, "detections/proposed/x.yml"),
    bash(sub("casa:log-analyst"), "ls"),
  ];
  for (const p of casaCalls) {
    const r = runHook(p, NO_BUN_PATH);
    expect(r.exit).toBe(2);
    expect(r.stderr).toContain("bun is not on PATH");
  }
  const otherCalls = [
    write(MAIN, "agents/x.md"),
    write(sub("other:foo"), "agents/x.md"),
    write({ agent_type: "detection-engineer" }, "agents/x.md"),
    bash(MAIN, "rm -rf build"),
    // The CASA marker inside written content is escaped JSON, not an agent field.
    call(MAIN, "Write", { file_path: "notes.md", content: '{"agent_type":"casa:log-analyst","agent_id":"x"}' }),
  ];
  for (const p of otherCalls) expect(runHook(p, NO_BUN_PATH).exit).toBe(0);
});

test("bun missing or crashing: a guard that exits outside 0 and 2 still blocks CASA calls", () => {
  const r = runHook(write(sub("casa:evaluator"), "evals/results/x.json"), CRASH_PATH);
  expect(r.exit).toBe(2);
  expect(r.stderr).toContain("the guard exited 1");
  expect(runHook(write(MAIN, "agents/x.md"), CRASH_PATH).exit).toBe(0);
});

// *--- Guard Working Directory ---*

test("bunfig: a hostile bunfig.toml in the project cannot turn a CASA out-of-lane write into an allow", () => {
  const project = mkdtempSync(join(tmpdir(), "casa-guard-bunfig-"));
  try {
    mkdirSync(join(project, "detections", "proposed"), { recursive: true });
    writeFileSync(join(project, "preload.ts"), "process.exit(0);\n");
    writeFileSync(join(project, "bunfig.toml"), 'preload = ["./preload.ts"]\n');
    writeFileSync(join(project, ".env"), "CASA_HOSTILE=1\n");
    const r = runHook(call(sub("casa:detection-engineer"), "Write", { file_path: "agents/x.md", content: "x\n" }, project), BUN_PATH, project);
    expect(r.exit).toBe(0);
    expect(denyReason(r.stdout)).toContain("may write only under detections/proposed");
  } finally {
    rmSync(project, { recursive: true, force: true });
  }
});

// *--- ISC-16 Bash Writes ---*

test("bash write: a writing Bash call from a CASA agent is denied", () => {
  expect(matcher.test("Bash")).toBe(true);
  const writes = [
    "jq . alerts.jsonl > out.json",
    "tee out.json < alerts.jsonl",
    "tshark -r cap.pcap -w out.pcap",
    "cp a b",
    "rm -rf detections",
    "sort -o out.txt a.txt",
  ];
  for (const cmd of writes) expect(reasonOf(decide(bash(sub("casa:log-analyst"), cmd)))).toContain(DATA_REQUESTS);
  // The hook itself must see Bash and refuse it.
  expect(denyReason(runHook(bash(sub("casa:network-analyst"), "tshark -r cap.pcap -w out.pcap"), BUN_PATH).stdout)).toContain(DATA_REQUESTS);
});

// *--- Bash Denied ---*

test("bash denied: CASA subagents get no shell at all, read-only commands included", () => {
  const callers = [
    sub("casa:log-analyst"),
    sub("casa:network-analyst"),
    sub("casa:endpoint-analyst"),
    sub("log-analyst"),
    sub("network-analyst"),
    sub("casa:detection-engineer"),
    sub("evaluator"),
    { agent_id: "agent-test" },
  ];
  const commands = [
    "ls intake",
    "jq . x.json",
    "head -n 1 README.md",
    "jq -c 'select(.rule.level > 10)' alerts.jsonl | head -n 20",
    "zeek-cut ts id.orig_h < conn.log",
    "tshark -r cap.pcap -T fields -e ip.dst",
    `bun ${ROOT}/intake/Validate.ts a.json`,
    "",
  ];
  for (const who of callers) {
    for (const cmd of commands) {
      const reason = reasonOf(decide(bash(who, cmd)));
      if (reason === null || !reason.includes(DATA_REQUESTS)) throw new Error(`expected data_requests deny for ${JSON.stringify(who)}: ${cmd}`);
    }
  }
  // The recorded log-analyst Bash call, as captured.
  expect(reasonOf(decide(recordedPayloads()[0]))).toContain(DATA_REQUESTS);

  // Main thread and other plugins' agents keep their shell; the guard does not decide.
  for (const who of [MAIN, sub("other:foo"), sub("general-purpose"), { agent_type: "log-analyst" }]) {
    expect(decide(bash(who, "rm -rf build"))).toEqual({ exit: 0 });
  }
});

// *--- ISC-17 End-to-End Over Stdin ---*

test("stdin: the hooks.json command decides every matched tool end to end", () => {
  for (const t of ["Write", "Edit", "MultiEdit", "NotebookEdit", "Bash"]) expect(matcher.test(t)).toBe(true);
  expect(matcher.test("Read")).toBe(false);

  const de = sub("casa:detection-engineer");
  const cases: { name: string; payload: unknown; exit: number; deny: boolean }[] = [
    { name: "Write in lane", payload: write(de, "detections/proposed/x.yml"), exit: 0, deny: false },
    { name: "Write out of lane", payload: write(de, "agents/x.md"), exit: 0, deny: true },
    { name: "Edit out of lane", payload: call(de, "Edit", { file_path: "agents/x.md", old_string: "x", new_string: "y" }), exit: 0, deny: true },
    { name: "MultiEdit out of lane", payload: call(de, "MultiEdit", { file_path: "agents/x.md", edits: [] }), exit: 0, deny: true },
    { name: "NotebookEdit out of lane", payload: call(de, "NotebookEdit", { notebook_path: "agents/x.ipynb", new_source: "" }), exit: 0, deny: true },
    { name: "NotebookEdit in lane", payload: call(sub("evaluator"), "NotebookEdit", { notebook_path: "evals/results/x.ipynb", new_source: "" }), exit: 0, deny: false },
    { name: "Bash write", payload: bash(sub("casa:log-analyst"), "jq . a.json > b.json"), exit: 0, deny: true },
    { name: "Bash read", payload: bash(sub("casa:log-analyst"), "jq -c . a.json | head"), exit: 0, deny: true },
    { name: "main-thread Write", payload: write(MAIN, "agents/x.md"), exit: 0, deny: false },
    { name: "main-thread Bash", payload: bash(MAIN, "rm -rf build"), exit: 0, deny: false },
    { name: "symlink on path", payload: write(de, "detections/proposed/link/x.md"), exit: 2, deny: false },
    { name: "not JSON", payload: "not json", exit: 2, deny: false },
  ];
  for (const c of cases) {
    const r = runHook(c.payload, BUN_PATH);
    if (r.exit !== c.exit) throw new Error(`${c.name}: exit ${r.exit}, wanted ${c.exit} (${r.stderr})`);
    if (c.deny) expect(denyReason(r.stdout)).toContain("guard:");
    else expect(r.stdout).toBe("");
  }
});

// *--- Registry Drift ---*

test("agent registry matches agents/ frontmatter and guard.sh", () => {
  const agents = agentFrontmatter();
  const names = agents.map((a) => a.name).sort();
  expect([...guard.CASA_AGENTS].sort()).toEqual(names);
  expect(Object.keys(guard.LANES).sort()).toEqual(agents.filter((a) => a.tools.includes("Write")).map((a) => a.name).sort());
  const sh = readFileSync(join(import.meta.dir, "guard.sh"), "utf8");
  const bare = /bare='\(([^)]+)\)'/.exec(sh)?.[1]?.split("|").sort();
  expect(bare).toEqual(names);
});
