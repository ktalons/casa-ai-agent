import { test, expect } from "bun:test";
import { mkdtempSync, mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { decide } from "./guard-write-path.ts";

const cwd = mkdtempSync(join(tmpdir(), "casa-guard-"));
mkdirSync(join(cwd, "detections", "proposed"), { recursive: true });
mkdirSync(join(cwd, "evals", "results"), { recursive: true });
mkdirSync(join(cwd, "agents"));
writeFileSync(join(cwd, "agents", "x.md"), "x");
symlinkSync(join(cwd, "agents"), join(cwd, "detections", "proposed", "link"));

const input = (agent_type: string | undefined, file_path: string) => ({ agent_type, cwd, tool_name: "Write", tool_input: { file_path } });
const isDeny = (d: ReturnType<typeof decide>) => d.exit === 0 && typeof d.output === "string" && JSON.parse(d.output).hookSpecificOutput.permissionDecision === "deny";

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
