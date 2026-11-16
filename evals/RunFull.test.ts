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
import { STRIPPED_ENV, briefForRun, buildInvocation, childEnv, listFixtures } from "./RunFull.ts";

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
