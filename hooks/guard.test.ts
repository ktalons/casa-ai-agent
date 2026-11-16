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
const bash = (agent: Agent, command: string, at = cwd) => call(agent, "Bash", { command }, at);
const input = (agent_type: string | undefined, file_path: string) => ({ agent_type, cwd, tool_name: "Write", tool_input: { file_path } });

const denyReason = (output: string | undefined): string | null => {
  if (typeof output !== "string") return null;
  const o = JSON.parse(output).hookSpecificOutput;
  return o?.permissionDecision === "deny" ? String(o.permissionDecisionReason) : null;
};
const isDeny = (d: ReturnType<typeof decide>) => d.exit === 0 && denyReason(d.output) !== null;

/** Run the hooks.json command exactly as Claude Code would, payload on stdin. */
function runHook(payload: unknown, PATH: string) {
  const body = typeof payload === "string" ? payload : JSON.stringify(payload);
  const r = Bun.spawnSync(["/bin/sh", "-c", hookCommand], {
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

// *--- Existing Lane Tests ---*

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
  const lines = readFileSync(join(import.meta.dir, "fixtures", "recorded-payloads.jsonl"), "utf8").trim().split("\n");
  const payloads = lines.map((l) => JSON.parse(l));
  expect(payloads.length).toBe(3);
  const names = new Set(agentFrontmatter().map((a) => a.name));
  for (const p of payloads) {
    expect(p.hook_event_name).toBe("PreToolUse");
    expect(typeof p.agent_id).toBe("string");
    expect(p.agent_id.length).toBeGreaterThan(0);
    expect(p.agent_type).toMatch(/^casa:[a-z-]+$/);
    expect(names.has(p.agent_type.slice("casa:".length))).toBe(true);
  }
  const [bashRead, inLane, outside] = payloads;
  expect(bashRead.tool_name).toBe("Bash");
  expect(decide(bashRead)).toEqual({ exit: 0 });
  expect(inLane.tool_input.file_path.startsWith(`${inLane.cwd}/detections/proposed/`)).toBe(true);
  expect(decide(inLane)).toEqual({ exit: 0 });
  expect(isDeny(decide(outside))).toBe(true);

  // Derived, not recorded: the same call with the subagent fields removed is the main thread.
  const { agent_id: _id, agent_type: _type, ...mainThread } = outside;
  expect(decide(mainThread)).toEqual({ exit: 0 });
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

// *--- ISC-16 Bash Writes ---*

test("bash write: writing or unmodellable Bash from a CASA agent is denied", () => {
  const la = sub("casa:log-analyst");
  // The policy ships in the plugin: the hook itself must see Bash and refuse the write.
  expect(matcher.test("Bash")).toBe(true);
  expect(denyReason(runHook(bash(la, "tshark -r cap.pcap -w out.pcap"), BUN_PATH).stdout)).toContain("read-only");
  const writes = [
    "jq . alerts.jsonl > out.json",
    "jq . alerts.jsonl >> out.json",
    "jq . alerts.jsonl >out.json",
    "jq . alerts.jsonl 1>out.json",
    "jq . alerts.jsonl 2>err.log",
    "jq . alerts.jsonl &> out.json",
    "jq . alerts.jsonl >& out.json",
    "jq . alerts.jsonl >| out.json",
    "jq . alerts.jsonl | tee out.json",
    "tshark -r cap.pcap -w out.pcap",
    "tshark -r cap.pcap -nw out.pcap",
    "tshark -i en0",
    "tshark -r cap.pcap --export-objects http,exported",
    "tshark -r cap.pcap -X lua_script:x.lua",
    "tshark -r cap.pcap -o tls.debug_file:x.log",
    "tshark -r *.pcap",
    "tshark -r {a,b}.pcap",
    "tshark -r ^a.pcap",
    "tshark -r a.pcap ${X:=-wout.pcap}",
    "jq . a.json <->>/dev/null",
    "jq . a >! out.json",
    "jq . a >/dev/null >out.json",
    "jq . a \\\n > out.json",
    "ls #'\nrm b\n#'",
    "jq . f #x",
    "jq . f;#x",
    "jq '.a |\n.b' f",
    'jq ".a |\n.b" f',
    "jq '.a |\r.b' f",
    "jq .[] f",
    "ls a]b",
    "ls a}b",
    "cp a b",
    "mv a b",
    "rm a",
    "touch a",
    "sed -i s/a/b/ a.txt",
    "awk '{print > \"x\"}' a.txt",
    "find . -delete",
    "/bin/rm a",
    "echo $(rm a)",
    "jq . `ls`",
    "jq . <(jq . a)",
    "jq . <<EOF\nx\nEOF",
    "jq . a <> b",
    "FOO=1 jq . a",
    "jq . a & rm b",
    "(jq . a)",
    "jq . a | xargs rm",
    "jq . a; rm b",
    "jq . a && rm b",
    "jq . a || rm b",
    "jq . a\nrm b",
    "bun evals/Grade.ts --out somewhere",
    "bun /tmp/evil.ts",
    "bun ${CLAUDE_PLUGIN_ROOT}/evals/Grade.ts --out somewhere",
    "bun --preload ./x.ts intake/Validate.ts a.json",
  ];
  for (const cmd of writes) {
    const d = decide(bash(la, cmd, ROOT), ROOT);
    if (!isDeny(d)) throw new Error(`expected deny for: ${cmd}`);
  }
  // Readers the Grep and Read tools replace are off the list, even in a harmless shape.
  for (const cmd of ["cat a.log", "grep x a.log", "cut -f1 a.tsv", "sort a.txt", "uniq -c a.txt", "jq . a | sort"]) {
    const d = decide(bash(la, cmd, ROOT), ROOT);
    expect(d.exit === 0 ? denyReason(d.output) : null).toContain("is not on the read-only allowlist");
  }
  // Agents without a Bash lane are refused any Bash at all.
  expect(isDeny(decide(bash(sub("casa:detection-engineer"), "ls"), ROOT))).toBe(true);
  expect(isDeny(decide(bash(sub("evaluator"), "ls"), ROOT))).toBe(true);
});

// *--- ISC-54 Bash Reads ---*

test("bash read: allowlisted read-only Bash from a CASA analyst gets no decision", () => {
  const reads = [
    "ls intake",
    "jq -c 'select(.rule.level > 10) | .agent.name' alerts.jsonl | head -n 20",
    "jq -s 'group_by(.agent.name) | map({k: .[0].agent.name, n: length})' alerts.jsonl",
    "jq --arg h x '.[] | select(.host == $h)' alerts.jsonl",
    "jq . alerts.jsonl 2>&1 | head",
    "tshark -r cap.pcap -T fields -e frame.time_epoch -e ip.dst -Y 'dns' 2>/dev/null",
    "tshark -nr cap.pcap -q -z conv,tcp",
    "zeek-cut ts id.orig_h id.resp_h < conn.log",
    "zeek-cut -d ts uid < conn.log | head",
    "zeek-cut ts id.orig_h < conn.log | jq -R 'split(\"\\t\")'",
    "jq -R 'select(test(\"Failed password\"))' auth.log | wc -l",
    "tail -n 50 sysmon.log",
    "wc -l sysmon.log auth.log",
    `bun ${ROOT}/intake/Validate.ts intake/fixtures/x.json`,
    'bun "${CLAUDE_PLUGIN_ROOT}/evals/Lint.ts" --brief b.md --intake i.json',
    "bun intake/Validate.ts x.json",
    "jq . a.json; jq . b.json\n",
    "jq '.env' alerts.jsonl",
  ];
  for (const a of ["casa:log-analyst", "network-analyst", "casa:endpoint-analyst"]) {
    for (const cmd of reads) {
      const d = decide(bash(sub(a), cmd, ROOT), ROOT);
      if (d.exit !== 0 || d.output !== undefined) throw new Error(`expected no decision for ${a}: ${cmd} -> ${JSON.stringify(d)}`);
    }
  }
});

// *--- Bash File Operands ---*

test("bash path: files a CASA analyst reads stay inside the project or the plugin and off secrets", () => {
  mkdirSync(join(cwd, "logs"), { recursive: true });
  writeFileSync(join(cwd, "logs", "app.log"), "line\n");
  writeFileSync(join(cwd, ".env"), "SECRET=x\n");
  symlinkSync(crashDir, join(cwd, "logs", "out"));
  const la = sub("casa:log-analyst");
  const refused = [
    "jq -R . ~/.aws/credentials",
    "head /home/analyst/.aws/credentials",
    "head /etc/passwd",
    "head '/etc/passwd'",
    "head /*/passwd",
    "tail ../other-repo/.env",
    "tail logs/../../other-repo/x.log",
    "head logs/out/bun",
    "head detections/proposed/link/x.md",
    "head .env",
    "jq -R . config/.env.local",
    "jq -R . .ENV",
    "head certs/server.pem",
    "head tls/server.key",
    "head keys/id_ed25519",
    "ls .ssh",
    "ls /",
    "zeek-cut ts < /etc/passwd",
    "zeek-cut ts < .env",
    "tshark -r /tmp/cap.pcap",
    "tshark -r ../cap.pcap",
    "tshark -r logs/app.log -H /etc/hosts",
    "jq -n --rawfile k /etc/passwd '$k'",
    "jq -L /etc '.' logs/app.log",
    "jq -f /etc/x.jq logs/app.log",
    "jq -n env",
    "jq -n '$ENV'",
    "jq -n 'import \"x\" as $x; $x'",
    "wc -l *.log",
    "jq . < *.json",
    `bun ${ROOT}/intake/Validate.ts /etc/passwd`,
  ];
  for (const cmd of refused) {
    const d = decide(bash(la, cmd), ROOT);
    if (!isDeny(d)) throw new Error(`expected deny for: ${cmd}`);
  }
  const allowed = [
    "head -n 5 logs/app.log",
    "jq -R . logs/app.log",
    `tail -n 3 ${join(cwd, "logs", "app.log")}`,
    "zeek-cut ts < logs/app.log",
    "tshark -r logs/app.log -T fields -e frame.number",
    "jq -n --arg x y '$x'",
    `jq . "${ROOT}/skills/standards/references/attack-techniques.json"`,
    'jq . "${CLAUDE_PLUGIN_ROOT}/skills/standards/references/csf-2.0.json"',
    "jq -c . - < logs/app.log",
  ];
  for (const cmd of allowed) {
    const d = decide(bash(la, cmd), ROOT);
    if (d.exit !== 0 || d.output !== undefined) throw new Error(`expected no decision for: ${cmd} -> ${JSON.stringify(d)}`);
  }
});

// *--- Parser And Option Edges ---*

/** The deny reason the guard gives a log-analyst Bash call, or null when it is not denied. */
function bashReason(command: string): string | null {
  const d = decide(bash(sub("casa:log-analyst"), command), ROOT);
  return d.exit === 0 ? denyReason(d.output) : null;
}

test("shell comment: an unquoted word-initial # is refused, not read through", () => {
  // The shell skips from # to end of line, so `rm b` would run as its own command.
  for (const cmd of ["ls #'\nrm b\n#'", "jq . f #x", "jq . f;#x", "ls >#x"]) {
    expect(bashReason(cmd)).toContain("shell comment");
  }
});

test("quoted newline: a quoted word holding a newline or carriage return is refused", () => {
  for (const cmd of ["jq '.a |\n.b' f", 'jq ".a |\n.b" f', "jq '.a |\r.b' f", 'jq ".a |\r.b" f']) {
    expect(bashReason(cmd)).toContain("newline inside quotes");
  }
});

test("bash options: readers take only their listed options, in either long form", () => {
  const refused = [
    "wc --files0-from=/etc/passwd",
    "wc --files0-from /etc/passwd",
    "wc --lines=5 logs/app.log",
    "tail -f x.log",
    "tail -F x.log",
    "tail --follow=name x.log",
    "tail --follow x.log",
    "tail -r x.log",
    "head --unknown=1 x.log",
    "head -20 x.log",
    "head --lines",
    "ls --color=always",
    "ls -d x",
    "zeek-cut -x ts < conn.log",
    "jq --args . a b",
  ];
  for (const cmd of refused) {
    if (bashReason(cmd) === null) throw new Error(`expected deny for: ${cmd}`);
  }
  expect(bashReason("wc --files0-from=/etc/passwd")).toContain("--files0-from is not allowed");
  const allowed = [
    "head -n 5 x.log",
    "head --lines=5 x.log",
    "head --lines 5 -q x.log",
    "tail -c 10 -v x.log",
    "tail --bytes=10 x.log",
    "wc -lw x.log",
    "wc --max-line-length x.log",
    "ls -laR logs",
    "ls -1Sht",
    "zeek-cut -d -F , ts uid < conn.log",
    "zeek-cut -U %s -n ts < conn.log",
  ];
  for (const cmd of allowed) {
    const reason = bashReason(cmd);
    if (reason !== null) throw new Error(`expected no decision for: ${cmd} -> ${reason}`);
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
    { name: "Bash read", payload: bash(sub("casa:log-analyst"), "jq -c . a.json | head"), exit: 0, deny: false },
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
  expect([...guard.BASH_AGENTS].sort()).toEqual(agents.filter((a) => a.tools.includes("Bash")).map((a) => a.name).sort());
  const sh = readFileSync(join(import.meta.dir, "guard.sh"), "utf8");
  const bare = /bare='\(([^)]+)\)'/.exec(sh)?.[1]?.split("|").sort();
  expect(bare).toEqual(names);
});
