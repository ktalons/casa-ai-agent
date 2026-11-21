// *****************************************************************************
// *Title: Run Transcript Scan Tests*
// *Author: Kyle*
// *Description: Checks which tool calls of an eval run leave its lane.*
// *****************************************************************************

// *--- Imports ---*

import { test, expect } from "bun:test";
import { outOfLane, pathsNamed, scanTranscript, wasDenied, type Lane } from "./ScanRuns.ts";

// *--- Configuration ---*

const LANE: Lane = { runDir: "/home/a/.cache/casa-evals/stamp-x.v3", pluginRoot: "/opt/Casa" };

// *--- Paths a call names ---*

test("paths: every absolute path in a tool input is found, whatever field or command holds it", () => {
  expect(pathsNamed({ file_path: "/opt/Casa/skills/standards/SKILL.md" })).toEqual(["/opt/Casa/skills/standards/SKILL.md"]);
  expect(pathsNamed({ command: "ls /opt/Casa/skills; bun /opt/Casa/evals/Lint.ts --brief briefs/x.brief.md" })).toEqual(["/opt/Casa/skills", "/opt/Casa/evals/Lint.ts"]);
  expect(pathsNamed({ pattern: "a|b", path: "/opt/Casa", head_limit: 5 })).toEqual(["/opt/Casa"]);
  expect(pathsNamed({ command: "bun evals/Lint.ts --brief briefs/x.brief.md" })).toEqual([]);
});

// *--- The lane (ISC-98) ---*

test("lane: the run's own project, the plugin's skills, its two scripts and its data directory are inside", () => {
  const inside = [
    { name: "Read", input: { file_path: "/home/a/.cache/casa-evals/stamp-x.v3/intake/x.v3.intake.json" } },
    { name: "Read", input: { file_path: "/opt/Casa/skills/standards/references/csf-2.0.json" } },
    { name: "Bash", input: { command: "ls /opt/Casa/skills" } },
    { name: "Bash", input: { command: "bun /opt/Casa/intake/Validate.ts intake/x.v3.intake.json" } },
    { name: "Bash", input: { command: "bun /opt/Casa/evals/Lint.ts --finding briefs/scratch/r1/T1.json --intake intake/x.v3.intake.json" } },
    { name: "Read", input: { file_path: "/home/a/.claude/plugins/data/casa-inline/lessons.md" } },
    { name: "Write", input: { file_path: "briefs/2026-01-01-x.v3.brief.md", content: "see /opt/Casa/evals/results for nothing" } },
    // The volume may be case-insensitive and the same path spelled two ways.
    { name: "Read", input: { file_path: "/opt/casa/skills/investigate/SKILL.md" } },
  ];
  for (const call of inside) expect([call.input, outOfLane(call, LANE)]).toEqual([call.input, []]);
});

test("lane: ground truth, grades, samples, other runs, project notes and parent paths are outside", () => {
  const outside: Array<[{ name: string; input: Record<string, unknown> }, string]> = [
    [{ name: "Read", input: { file_path: "/opt/Casa/intake/fixtures/x.expected.json" } }, "/opt/Casa/intake/fixtures/x.expected.json"],
    [{ name: "Bash", input: { command: "cat /opt/Casa/evals/results/x/1.grade.json" } }, "/opt/Casa/evals/results/x/1.grade.json"],
    [{ name: "Read", input: { file_path: "/opt/Casa/evals/samples/x.run1.brief.md" } }, "/opt/Casa/evals/samples/x.run1.brief.md"],
    [{ name: "Grep", input: { pattern: "a", path: "/opt/Casa" } }, "/opt/Casa"],
    [{ name: "Read", input: { file_path: "/opt/Casa/README.md" } }, "/opt/Casa/README.md"],
    [{ name: "Read", input: { file_path: "/home/a/.cache/casa-evals/stamp-y.v3/briefs/2026-01-01-y.v3.brief.md" } }, "/home/a/.cache/casa-evals/stamp-y.v3/briefs/2026-01-01-y.v3.brief.md"],
    [{ name: "Read", input: { file_path: "/opt/Casa/ISA.md" } }, "/opt/Casa/ISA.md"],
    [{ name: "Read", input: { file_path: "../stamp-y.v3/briefs/y.brief.md" } }, "../stamp-y.v3/briefs/y.brief.md"],
    [{ name: "Bash", input: { command: "ls ../../casa-evals" } }, "../../casa-evals"],
    // A script the skill never runs is not excused by living next to one it does.
    [{ name: "Bash", input: { command: "bun /opt/Casa/evals/Grade.ts --summary" } }, "/opt/Casa/evals/Grade.ts"],
    // A sibling whose name starts like the skills directory is not the skills directory.
    [{ name: "Read", input: { file_path: "/opt/Casa/skills-old/x.md" } }, "/opt/Casa/skills-old/x.md"],
  ];
  for (const [call, path] of outside) expect([call.input, outOfLane(call, LANE)]).toEqual([call.input, [path]]);
});

// *--- Denials ---*

test("denied: a refused call is told apart from one that ran", () => {
  expect(wasDenied("Permission to use Read has been denied. IMPORTANT: You *may* attempt")).toBe(true);
  expect(wasDenied([{ type: "text", text: "Permission to use Grep has been denied." }])).toBe(true);
  expect(wasDenied("1\tline one of the file")).toBe(false);
  expect(wasDenied(undefined)).toBe(false);
});

// *--- A whole transcript ---*

test("scan: out-of-lane calls are listed with whether each was refused, across main thread and subagents", () => {
  const line = (obj: unknown): string => JSON.stringify(obj);
  const use = (id: string, name: string, input: Record<string, unknown>) => ({ message: { content: [{ type: "tool_use", id, name, input }] } });
  const result = (id: string, content: unknown) => ({ message: { content: [{ type: "tool_result", tool_use_id: id, content }] } });
  const main = [
    line(use("a", "Read", { file_path: "/opt/Casa/skills/standards/SKILL.md" })),
    line(result("a", "1\t# Standards")),
    line(use("b", "Read", { file_path: "/opt/Casa/README.md" })),
    line(result("b", "Permission to use Read has been denied.")),
    "not json",
  ].join("\n");
  const sub = [line(use("c", "Read", { file_path: "/opt/Casa/intake/fixtures/x.expected.json" })), line(result("c", "1\t{"))].join("\n");
  const found = scanTranscript([main, sub], LANE);
  expect(found.calls).toBe(3);
  expect(found.hits).toEqual([
    { tool: "Read", path: "/opt/Casa/README.md", denied: true },
    { tool: "Read", path: "/opt/Casa/intake/fixtures/x.expected.json", denied: false },
  ]);
});

test("scan: a call the transcript records twice is one call, and its refusal covers both records", () => {
  const line = (obj: unknown): string => JSON.stringify(obj);
  const use = { message: { content: [{ type: "tool_use", id: "g", name: "Grep", input: { pattern: "a", path: "/opt/Casa" } }] } };
  const refused = { message: { content: [{ type: "tool_result", tool_use_id: "g", content: "Permission to use Grep has been denied." }] } };
  const found = scanTranscript([[line(use), line(refused), line(use)].join("\n")], LANE);
  expect(found.calls).toBe(1);
  expect(found.hits).toEqual([{ tool: "Grep", path: "/opt/Casa", denied: true }]);
});

test("lane: the session's own temporary files are inside, another session's are not", () => {
  const lane: Lane = { ...LANE, sessionId: "11111111-2222-4333-8444-555555555555" };
  const own = { name: "Read", input: { file_path: "/private/tmp/claude-502/-home-a/11111111-2222-4333-8444-555555555555/tasks/a05.output" } };
  const other = { name: "Read", input: { file_path: "/private/tmp/claude-502/-home-a/99999999-2222-4333-8444-555555555555/tasks/a05.output" } };
  expect(outOfLane(own, lane)).toEqual([]);
  expect(outOfLane(other, lane)).toEqual([other.input.file_path]);
  // Without a session id nothing under the temporary directory is excused.
  expect(outOfLane(own, LANE)).toEqual([own.input.file_path]);
});
