// *****************************************************************************
// *Title: RunFull Harness Tests*
// *Author: Kyle*
// *Description: Checks the eval runner's child env and fixture list offline.*
// *****************************************************************************

// *--- Imports ---*

import { test, expect } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EVAL_MODEL, ISOLATION_ENV, STRIPPED_ENV, briefForRun, buildInvocation, childEnv, listFixtures, investigateSettings, keepBrief, modelsUsed, prepareRunDir, selectFixtures } from "./RunFull.ts";
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

// *--- Child isolation (ISC-89, ISC-90) ---*

/** The value that follows `flag` on the child command line. */
function flagValue(cmd: string[], flag: string): string | undefined {
  const at = cmd.indexOf(flag);
  return at === -1 ? undefined : cmd[at + 1];
}

test("isolation: the child loads project and local settings only, no instruction files and no auto memory", () => {
  // A parent that tries to switch the instruction files back on must not win.
  const inv = buildInvocation("/casa:investigate x", 5, { PATH: "/usr/bin", CLAUDE_CODE_DISABLE_CLAUDE_MDS: "0" });
  expect(flagValue(inv.cmd, "--setting-sources")).toBe("project,local");
  for (const key of ISOLATION_ENV) expect(inv.env[key]).toBe("1");
  expect([...ISOLATION_ENV] as string[]).toContain("CLAUDE_CODE_DISABLE_CLAUDE_MDS");
  expect([...ISOLATION_ENV] as string[]).toContain("CLAUDE_CODE_DISABLE_AUTO_MEMORY");
  expect(inv.env.PATH).toBe("/usr/bin");
});

test("model: the child runs on the model the runner names, and the step log names the models that answered", () => {
  const inv = buildInvocation("/casa:evaluate x", 5, { PATH: "/usr/bin" });
  expect(EVAL_MODEL.length).toBeGreaterThan(0);
  expect(flagValue(inv.cmd, "--model")).toBe(EVAL_MODEL);
  expect(modelsUsed({ modelUsage: { "model-b": {}, "model-a": {} } })).toBe("model-a, model-b");
  expect(modelsUsed({})).toBe("unknown");
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

// *--- A new project per investigate run (ISC-92) ---*

test("run dir: an investigate run gets a new project that holds only its intake", () => {
  const root = mkdtempSync(join(tmpdir(), "casa-runs-"));
  try {
    const intake = join(FIXTURES_DIR, "quiet-day.v3.intake.json");
    const dir = prepareRunDir(root, "stamp", "quiet-day.v3", intake);
    expect(dir).toBe(join(root, "stamp-quiet-day.v3"));
    const files: string[] = [];
    const walk = (d: string): void => {
      for (const e of readdirSync(d, { withFileTypes: true })) e.isDirectory() ? walk(join(d, e.name)) : files.push(join(d, e.name).slice(dir.length + 1));
    };
    walk(dir);
    // No expected.json, no earlier brief, no settings file: the intake and nothing else.
    expect(files).toEqual([join("intake", "quiet-day.v3.intake.json")]);
    expect(readFileSync(join(dir, files[0]!), "utf8")).toBe(readFileSync(intake, "utf8"));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("run dir: the child may read the plugin's skills and nothing else outside its project", () => {
  const project = { permissions: { allow: ["Bash(jq *)"], deny: ["Bash(curl *)"] } };
  const settings = investigateSettings("/opt/casa", project);
  expect(settings.permissions?.allow).toEqual(["Bash(jq *)", "Read(//opt/casa/skills/**)"]);
  expect(settings.permissions?.deny).toEqual(["Bash(curl *)"]);
  // The fixtures, the grader and earlier results sit beside the skills and get no rule.
  expect((settings.permissions?.allow ?? []).filter((rule) => rule.startsWith("Read("))).toEqual(["Read(//opt/casa/skills/**)"]);
  expect(project.permissions.allow).toEqual(["Bash(jq *)"]);
  expect(investigateSettings("/opt/casa", {}).permissions?.allow).toEqual(["Read(//opt/casa/skills/**)"]);
});

test("run dir: the plugin and the permissions reach the child on its command line", () => {
  const settings = investigateSettings("/opt/casa", {});
  const inv = buildInvocation("/casa:investigate intake/x.intake.json", 5, { PATH: "/usr/bin" }, { pluginDir: "/opt/casa", settings });
  expect(flagValue(inv.cmd, "--plugin-dir")).toBe("/opt/casa");
  expect(JSON.parse(flagValue(inv.cmd, "--settings") ?? "null")).toEqual(settings);
  expect(flagValue(inv.cmd, "--setting-sources")).toBe("project,local");
  // The evaluate step runs in the repo with the linked plugin and takes neither flag.
  const plain = buildInvocation("/casa:evaluate x", 5, { PATH: "/usr/bin" });
  expect(plain.cmd).not.toContain("--plugin-dir");
  expect(plain.cmd).not.toContain("--settings");
});

test("run dir: RunFull investigates in the new project and never in the repo", () => {
  const src = readFileSync(join(import.meta.dir, "RunFull.ts"), "utf8");
  const main = src.slice(src.indexOf("if (import.meta.main)"));
  expect(main).toMatch(/const runDir = prepareRunDir\(RUNS_ROOT, stamp, f, /);
  expect(main).toMatch(/runStep\("investigate", f, `\/casa:investigate intake\/\$\{f\}\.intake\.json`, INVESTIGATE_TURNS, runDir, \{ pluginDir: ROOT, settings \}\)/);
  expect(main).toMatch(/briefForRun\(join\(runDir, "briefs"\), f, started\)/);
  // The runs root is outside the checkout, so nothing in the repo is a sibling of a run.
  expect(src).toMatch(/const RUNS_ROOT = join\(homedir\(\), /);
});

test("run dir: the run's brief is copied to where evaluate looks, and the original stays", () => {
  const root = mkdtempSync(join(tmpdir(), "casa-keep-"));
  try {
    mkdirSync(join(root, "run", "briefs"), { recursive: true });
    const written = join(root, "run", "briefs", "2026-07-23-quiet-day.v3.brief.md");
    writeFileSync(written, "new brief");
    mkdirSync(join(root, "repo-briefs"));
    writeFileSync(join(root, "repo-briefs", "2026-07-23-quiet-day.v3.brief.md"), "old brief");
    const kept = keepBrief(written, join(root, "repo-briefs"));
    expect(kept).toBe(join(root, "repo-briefs", "2026-07-23-quiet-day.v3.brief.md"));
    expect(readFileSync(kept, "utf8")).toBe("new brief");
    expect(existsSync(written)).toBe(true);
  } finally {
    rmSync(root, { recursive: true, force: true });
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

test("LEARN notes: no eval run writes into the queue /casa:learn promotes from", () => {
  // ISC-87. Investigate runs in its own project, so its LEARN note lands there. The runner
  // copies back the brief and nothing else, whatever set the fixture is in.
  const src = readFileSync(join(ROOT, "evals", "RunFull.ts"), "utf8");
  expect(src).not.toMatch(/learn["/, ]+"?pending/);
  const main = src.slice(src.indexOf("if (import.meta.main)"));
  expect(main.match(/runStep\("investigate"[^\n]*/)?.[0]).toContain("runDir");
  expect(main.match(/copyFileSync|keepBrief\(/g)).toEqual(["keepBrief("]);
});
