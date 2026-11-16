// *****************************************************************************
// *Title: RunFull Harness Tests*
// *Author: Kyle*
// *Description: Checks the eval runner's child env and fixture list offline.*
// *****************************************************************************

// *--- Imports ---*

import { test, expect } from "bun:test";
import { mkdtempSync, readdirSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { STRIPPED_ENV, briefForRun, buildInvocation, childEnv, listFixtures, quarantineNotes, selectFixtures } from "./RunFull.ts";
import { baseName, loadSets } from "./lib/sets.ts";

// *--- Configuration ---*

const ROOT = join(import.meta.dir, "..");
const FIXTURES_DIR = join(ROOT, "intake", "fixtures");

// *--- Child environment (ISC-23) ---*

// Each of these either blocks a nested claude or moves its billing off the subscription.
const MUST_STRIP = [
  "CLAUDECODE",
  "ANTHROPIC_API_KEY",
  "ANTHROPIC_AUTH_TOKEN",
  "ANTHROPIC_BASE_URL",
  "ANTHROPIC_CUSTOM_HEADERS",
  "CLAUDE_CODE_USE_BEDROCK",
  "CLAUDE_CODE_USE_VERTEX",
  "AWS_BEARER_TOKEN_BEDROCK",
];

test("env: the strip list names every nesting and billing variable", () => {
  for (const key of MUST_STRIP) expect([...STRIPPED_ENV] as string[]).toContain(key);
});

test("env: the child env drops every stripped variable and keeps the rest", () => {
  const parent: Record<string, string> = { PATH: "/usr/bin", HOME: "/home/x", CLAUDE_CODE_OAUTH_TOKEN: "subscription" };
  for (const key of STRIPPED_ENV) parent[key] = "set";
  const env = childEnv(parent);
  for (const key of STRIPPED_ENV) expect(key in env).toBe(false);
  expect(env.PATH).toBe("/usr/bin");
  expect(env.HOME).toBe("/home/x");
  // The OAuth token is the subscription login itself; stripping it would break auth.
  expect(env.CLAUDE_CODE_OAUTH_TOKEN).toBe("subscription");
  expect(parent.CLAUDECODE).toBe("set");
});

test("env: the invocation RunFull spawns carries the stripped env", () => {
  const inv = buildInvocation("/casa:investigate x", 5, { CLAUDECODE: "1", ANTHROPIC_API_KEY: "k", PATH: "/usr/bin" });
  expect(inv.cmd[0]).toBe("claude");
  expect(inv.cmd).toContain("-p");
  expect("CLAUDECODE" in inv.env).toBe(false);
  expect("ANTHROPIC_API_KEY" in inv.env).toBe(false);
  expect(inv.env.PATH).toBe("/usr/bin");
});

test("env: RunFull spawns claude only through buildInvocation", () => {
  const src = readFileSync(join(import.meta.dir, "RunFull.ts"), "utf8");
  expect(src.match(/Bun\.spawn\(/g)?.length).toBe(1);
  expect(src).toMatch(/Bun\.spawn\(inv\.cmd, \{[^}]*env: inv\.env/);
});

// *--- Fixture coverage (ISC-55) ---*

test("fixtures: the default list covers every intake fixture of every version", () => {
  const onDisk = readdirSync(FIXTURES_DIR).filter((f) => f.endsWith(".intake.json")).map((f) => f.replace(/\.intake\.json$/, "")).sort();
  const listed = listFixtures(FIXTURES_DIR, []);
  expect(listed).toEqual(onDisk);
  const versions = (names: string[]) =>
    new Set(names.map((n) => (JSON.parse(readFileSync(join(FIXTURES_DIR, `${n}.intake.json`), "utf8")) as { schema: string }).schema));
  expect(versions(listed)).toEqual(versions(onDisk));
  expect(versions(listed).size).toBeGreaterThan(1);
});

test("fixtures: named fixtures are kept in order and an unknown name is refused", () => {
  const [first, second] = listFixtures(FIXTURES_DIR, []);
  expect(listFixtures(FIXTURES_DIR, [second, first])).toEqual([second, first]);
  expect(() => listFixtures(FIXTURES_DIR, ["no-such-fixture"])).toThrow(/no-such-fixture/);
});

// *--- Brief hand-off to evaluate ---*

test("brief: evaluate gets the brief this run's investigate step wrote", () => {
  const dir = mkdtempSync(join(tmpdir(), "casa-briefs-"));
  try {
    const touch = (name: string, mtimeMs: number) => {
      const p = join(dir, name);
      writeFileSync(p, "# brief\n");
      utimesSync(p, mtimeMs / 1000, mtimeMs / 1000);
      return p;
    };
    const start = Date.now() - 60_000;
    touch("2026-07-20-brute-force-dc-chain.brief.md", start - 10_000); // older than the run
    const v1 = touch("2026-07-21-brute-force-dc-chain.brief.md", start + 5_000);
    const v2 = touch("2026-07-21-brute-force-dc-chain.v2.brief.md", start + 9_000);
    expect(briefForRun(dir, "brute-force-dc-chain", start)).toBe(v1);
    expect(briefForRun(dir, "brute-force-dc-chain.v2", start)).toBe(v2);
    expect(briefForRun(dir, "quiet-day", start)).toBeNull();
    expect(briefForRun(dir, "brute-force-dc-chain", start + 20_000)).toBeNull();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// *--- Fixture sets (ISC-85) ---*

test("set: --set runs exactly one set's variants, and every fixture family is in exactly one set", () => {
  const sets = loadSets();
  const all = listFixtures(FIXTURES_DIR, []);
  // Both ways: no fixture family outside the manifest, no manifest entry without a fixture.
  expect([...new Set(all.map(baseName))].sort()).toEqual(Object.keys(sets.fixtures).sort());
  const held = selectFixtures(FIXTURES_DIR, ["--set", "held-out"], sets);
  const authoring = selectFixtures(FIXTURES_DIR, ["--set", "authoring"], sets);
  expect(held.length).toBeGreaterThan(0);
  expect(held.every((v) => sets.fixtures[baseName(v)].set === "held-out")).toBe(true);
  expect(authoring.every((v) => sets.fixtures[baseName(v)].set === "authoring")).toBe(true);
  expect([...held, ...authoring].sort()).toEqual([...all].sort());
  expect(() => selectFixtures(FIXTURES_DIR, ["--set", "nope"], sets)).toThrow(/--set needs one of/);
  expect(() => selectFixtures(FIXTURES_DIR, ["--set"], sets)).toThrow(/--set needs one of/);
  expect(() => selectFixtures(FIXTURES_DIR, ["--set", "held-out", "quiet-day"], sets)).toThrow(/no fixture names/);
  expect(selectFixtures(FIXTURES_DIR, ["quiet-day"], sets)).toEqual(["quiet-day"]);
});

test("set: a held-out run's LEARN notes leave the approval queue, and nothing else moves", () => {
  const root = mkdtempSync(join(tmpdir(), "casa-quarantine-"));
  try {
    const pending = join(root, "pending");
    const dest = join(root, "held-out-learn");
    const { mkdirSync } = require("node:fs") as typeof import("node:fs");
    mkdirSync(pending, { recursive: true });
    const write = (name: string, ageMs: number) => {
      writeFileSync(join(pending, name), "note");
      const t = (Date.now() - ageMs) / 1000;
      utimesSync(join(pending, name), t, t);
    };
    write("2026-08-05-powershell-cradle-alert.v3-r1.md", 0); // this run's note: moves
    write("2026-08-04-powershell-cradle-alert.v3-r0.md", 3_600_000); // written before the run: stays
    write("2026-07-20-brute-force-dc-chain.v3-r1.md", 0); // another fixture: stays
    const since = Date.now() - 60_000;
    expect(quarantineNotes(pending, "powershell-cradle-alert.v3", since, dest)).toEqual(["2026-08-05-powershell-cradle-alert.v3-r1.md"]);
    expect(readdirSync(dest)).toEqual(["2026-08-05-powershell-cradle-alert.v3-r1.md"]);
    expect(readdirSync(pending).sort()).toEqual(["2026-07-20-brute-force-dc-chain.v3-r1.md", "2026-08-04-powershell-cradle-alert.v3-r0.md"]);
    // The main loop calls it for held-out variants only.
    const src = readFileSync(join(ROOT, "evals", "RunFull.ts"), "utf8");
    expect(src).toMatch(/if \(setOf\(sets, f\) === "held-out"\) \{\s*const moved = quarantineNotes\(PENDING_DIR, f, started, HELD_OUT_LEARN\)/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
