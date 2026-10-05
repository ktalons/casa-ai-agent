/**
 * agents.test.ts — frontmatter contract for every CASA agent.
 *
 * `claude plugin validate --strict` does not reject unsupported agent frontmatter keys
 * (verified: a `permissions:` block passes), so this test is the guard. Zero dependencies:
 * the frontmatter is simple enough for a line parser.
 */
import { test, expect } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const AGENTS_DIR = join(import.meta.dir, "..", "..", "agents");

const SUPPORTED_KEYS = new Set([
  "name", "description", "tools", "disallowedTools", "model", "permissionMode", "maxTurns",
  "skills", "mcpServers", "hooks", "memory", "background", "omitClaudeMd", "effort",
  "isolation", "color", "initialPrompt", "experimental",
]);
// Keys that are supported in general but must not appear on a CASA agent.
const FORBIDDEN_KEYS = new Set(["memory", "permissions", "voiceId", "permissionMode", "hooks", "mcpServers"]);
const COLORS = new Set(["red", "blue", "green", "yellow", "purple", "orange", "pink", "cyan"]);

// Tool lanes. An agent may list only the tools in its lane.
const LANES: Record<string, string[]> = {
  "log-analyst": ["Read", "Grep", "Glob", "Bash"],
  "network-analyst": ["Read", "Grep", "Glob", "Bash"],
  "endpoint-analyst": ["Read", "Grep", "Glob", "Bash"],
  "purple-team-mapper": ["Read", "Grep", "Glob"],
  "detection-engineer": ["Read", "Grep", "Glob", "Write"],
  "threat-intel": ["Read", "Grep", "Glob", "WebFetch"],
  "evaluator": ["Read", "Grep", "Glob", "Write"],
  "pentester": ["Read", "Grep", "Glob"],
};

type Frontmatter = Record<string, string | string[]>;

function parseFrontmatter(text: string): Frontmatter {
  const m = text.match(/^---\n([\s\S]*?)\n---\n/);
  if (!m) throw new Error("no frontmatter");
  const fm: Frontmatter = {};
  let current: string | null = null;
  for (const raw of m[1].split("\n")) {
    const item = raw.match(/^\s+-\s+(.*)$/);
    if (item && current) {
      (fm[current] as string[]).push(item[1].trim());
      continue;
    }
    const kv = raw.match(/^([A-Za-z][A-Za-z0-9_]*):\s*(.*)$/);
    if (!kv) throw new Error(`unparseable frontmatter line: ${raw}`);
    const [, key, value] = kv;
    if (value === "") {
      fm[key] = [];
      current = key;
    } else {
      fm[key] = value.trim();
      current = null;
    }
  }
  return fm;
}

const files = readdirSync(AGENTS_DIR).filter((f) => f.endsWith(".md")).sort();

test("agents directory lists exactly the eight CASA agents", () => {
  expect(files.map((f) => f.replace(/\.md$/, ""))).toEqual(Object.keys(LANES).sort());
});

for (const file of files) {
  const name = file.replace(/\.md$/, "");
  const fm = parseFrontmatter(readFileSync(join(AGENTS_DIR, file), "utf8"));

  test(`${file}: name matches filename and is kebab-case`, () => {
    expect(fm.name).toBe(name);
    expect(name).toMatch(/^[a-z][a-z0-9-]*$/);
  });

  test(`${file}: only supported keys, none forbidden`, () => {
    for (const key of Object.keys(fm)) {
      expect(SUPPORTED_KEYS.has(key)).toBe(true);
      expect(FORBIDDEN_KEYS.has(key)).toBe(false);
    }
    expect(typeof fm.description).toBe("string");
    expect((fm.description as string).length).toBeGreaterThan(40);
  });

  test(`${file}: tools are explicit and inside the lane`, () => {
    expect(typeof fm.tools).toBe("string");
    const tools = (fm.tools as string).split(",").map((t) => t.trim());
    expect(tools.length).toBeGreaterThan(0);
    for (const t of tools) expect(LANES[name]).toContain(t);
  });

  test(`${file}: preloads the standards skill, valid color, bounded turns`, () => {
    expect(fm.skills).toEqual(["standards"]);
    expect(COLORS.has(fm.color as string)).toBe(true);
    expect(Number(fm.maxTurns)).toBeGreaterThan(0);
    expect(Number(fm.maxTurns)).toBeLessThanOrEqual(30);
  });
}

test("standards skill stays small enough to preload into every agent", () => {
  const lines = readFileSync(join(AGENTS_DIR, "..", "skills", "standards", "SKILL.md"), "utf8").split("\n").length;
  expect(lines).toBeLessThanOrEqual(160);
});
