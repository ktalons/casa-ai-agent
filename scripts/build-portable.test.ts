// *****************************************************************************
// *Title: Portable Skill Pack Tests*
// *Author: Kyle*
// *Description: Holds the pack to the Agent Skills spec and its sources.*
// *****************************************************************************

// *--- Imports ---*

import { test, expect } from "bun:test";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { KINDS } from "../evals/lib/extract.ts";
import { build, PORTABLE_DIR, REPO_URL } from "./build-portable.ts";

// *--- Configuration ---*

const ROOT = join(import.meta.dir, "..");
const WORKFLOWS = join(ROOT, "skills", "investigate", "references", "workflows");
// The six fields the Agent Skills specification defines (agentskills.io/specification, read 2026-11-21).
const SPEC_FIELDS = ["name", "description", "license", "compatibility", "metadata", "allowed-tools"];
const MAX_NAME = 64;
const MAX_DESCRIPTION = 1024;
const MAX_COMPATIBILITY = 500;
const MAX_BODY_LINES = 500;
// The spec recommends under 5,000 tokens for the body; four characters a token is the usual estimate.
const MAX_BODY_CHARS = 20_000;
const MAX_SCRIPT_BYTES = 20 * 1024;

// What must never reach a portable file: plugin variables, slash commands, the plugin's agents and
// its orchestration words, an em dash, and the two words the README rule bans.
const FORBIDDEN: [string, RegExp][] = [
  ["a plugin variable", /\$\{[A-Za-z_.]+\}/],
  ["an unfilled placeholder", /\{\{[a-z-]*\}\}/],
  ["a slash command", /\/casa:/],
  ["a namespaced agent", /\bcasa:[a-z]/],
  ["a subagent reference", /subagent/i],
  ["the word specialist", /\bspecialists?\b/i],
  ["the main thread", /main thread/i],
  ["the Overseer", /Overseer/],
  ["the Agent tool", /Agent tool|Agent calls/],
  ["a plugin agent name", /\b(?:log|network|endpoint)-analyst\b|threat-intel agent|purple-team[ -]mapper|detection-engineer/],
  ["an em dash", /—/],
  ["a banned word", /capstone|iscap/i],
];

// *--- Helper Functions ---*

const built = build();
const skills = [...new Set([...built.keys()].filter((p) => p.includes("/")).map((p) => p.split("/")[0]))].sort();
const skillFile = (skill: string): string => built.get(`${skill}/SKILL.md`) ?? "";

type Fields = Record<string, string | Record<string, string>>;

/** The frontmatter fields and the body of a SKILL.md, read with the small YAML subset the pack writes. */
function parse(text: string): { fields: Fields; body: string } {
  const m = text.match(/^---\n([\s\S]*?)\n---\n([\s\S]*)$/);
  if (!m) throw new Error("no frontmatter block");
  const fields: Fields = {};
  let open: Record<string, string> | null = null;
  const scalar = (raw: string): string => (raw.startsWith('"') ? (JSON.parse(raw) as string) : raw);
  for (const line of m[1].split("\n")) {
    const nested = line.match(/^ {2}([A-Za-z-]+): (.+)$/);
    const top = line.match(/^([A-Za-z-]+):(?: (.+))?$/);
    if (nested && open) open[nested[1]] = scalar(nested[2]);
    else if (top && top[2] === undefined) {
      open = {};
      fields[top[1]] = open;
    } else if (top) {
      open = null;
      fields[top[1]] = scalar(top[2]);
    } else throw new Error(`frontmatter line not understood: ${line}`);
  }
  return { fields, body: m[2] };
}

/** The first forbidden thing in `text`, by name, or null. */
function forbiddenIn(text: string): string | null {
  for (const [what, re] of FORBIDDEN) if (re.test(text)) return what;
  return null;
}

/** Every file under portable/ on disk, by its path relative to that folder. */
function onDisk(dir = PORTABLE_DIR, prefix = ""): Map<string, string> {
  const out = new Map<string, string>();
  if (!existsSync(dir)) return out;
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const rel = prefix ? `${prefix}/${e.name}` : e.name;
    if (e.isDirectory()) for (const [k, v] of onDisk(join(dir, e.name), rel)) out.set(k, v);
    else out.set(rel, readFileSync(join(dir, e.name), "utf8"));
  }
  return out;
}

// *--- The pack ---*

test("pack: holds exactly the three skills, each with a SKILL.md and the MIT license text", () => {
  expect(skills).toEqual(["casa-evidence-check", "casa-soc-standards", "casa-soc-triage"]);
  const license = readFileSync(join(ROOT, "LICENSE"), "utf8");
  expect(license).toContain("MIT License");
  for (const s of skills) {
    expect(built.has(`${s}/SKILL.md`), s).toBe(true);
    expect(built.get(`${s}/LICENSE`), s).toBe(license);
  }
});

// *--- The Agent Skills spec (ISC-43) ---*

test("spec: every name is lowercase letters, digits and single hyphens, and equals its folder", () => {
  for (const s of skills) {
    const { name } = parse(skillFile(s)).fields;
    expect(name, s).toBe(s);
    expect(s).toMatch(/^[a-z0-9]+(?:-[a-z0-9]+)*$/);
    expect(s.length).toBeLessThanOrEqual(MAX_NAME);
    expect(s.startsWith("casa-"), s).toBe(true);
  }
  // The pattern itself refuses what the spec refuses.
  for (const bad of ["Casa-Soc", "-casa", "casa-", "casa--soc", "casa_soc", ""]) expect(bad).not.toMatch(/^[a-z0-9]+(?:-[a-z0-9]+)*$/);
});

test("spec: frontmatter carries only the six standard fields", () => {
  for (const s of skills) {
    const keys = Object.keys(parse(skillFile(s)).fields);
    expect(keys.filter((k) => !SPEC_FIELDS.includes(k)), s).toEqual([]);
    expect(keys).toContain("name");
    expect(keys).toContain("description");
  }
});

test("spec: the description says what the skill does and when to use it, inside the length limit", () => {
  for (const s of skills) {
    const description = parse(skillFile(s)).fields.description as string;
    expect(typeof description, s).toBe("string");
    expect(description.length, s).toBeGreaterThan(80);
    expect(description.length, s).toBeLessThanOrEqual(MAX_DESCRIPTION);
    expect(description, s).toContain("Use when");
  }
});

test("spec: license, compatibility and metadata have the shapes the spec gives them", () => {
  const version = JSON.parse(readFileSync(join(ROOT, ".claude-plugin", "plugin.json"), "utf8")).version as string;
  for (const s of skills) {
    const { license, compatibility, metadata } = parse(skillFile(s)).fields;
    expect(license, s).toBe("MIT");
    if (compatibility !== undefined) {
      expect(typeof compatibility, s).toBe("string");
      expect((compatibility as string).length, s).toBeGreaterThan(0);
      expect((compatibility as string).length, s).toBeLessThanOrEqual(MAX_COMPATIBILITY);
    }
    // A map from string keys to string values, naming the plugin version it was generated from.
    expect(typeof metadata, s).toBe("object");
    for (const v of Object.values(metadata as Record<string, string>)) expect(typeof v, s).toBe("string");
    expect(metadata, s).toMatchObject({ version, source: REPO_URL });
  }
});

test("spec: each body stays under 500 lines and about 5,000 tokens", () => {
  for (const s of skills) {
    const { body } = parse(skillFile(s));
    expect(body.split("\n").length, s).toBeLessThan(MAX_BODY_LINES);
    expect(body.length, s).toBeLessThan(MAX_BODY_CHARS);
    expect(body.trim().startsWith("# "), s).toBe(true);
  }
});

test("spec: every file a skill names exists one level down, and no bundled file goes unnamed", () => {
  for (const s of skills) {
    const named = new Set([...skillFile(s).matchAll(/\b(references|scripts|assets)\/([A-Za-z0-9._-]+\.[a-z]+)/g)].map((m) => `${m[1]}/${m[2]}`));
    const bundled = [...built.keys()].filter((p) => p.startsWith(`${s}/`) && p.split("/").length > 2).map((p) => p.slice(s.length + 1));
    for (const p of bundled) expect(p.split("/").length, `${s}/${p}`).toBe(2);
    expect([...named].filter((p) => !bundled.includes(p)), `${s} names a file it does not carry`).toEqual([]);
    expect(bundled.filter((p) => !named.has(p)), `${s} carries a file SKILL.md never names`).toEqual([]);
    // No chains: a Markdown reference file does not send the reader to another bundled file.
    for (const p of bundled.filter((b) => b.endsWith(".md"))) expect(built.get(`${s}/${p}`), `${s}/${p}`).not.toMatch(/\b(?:references|scripts|assets)\/[A-Za-z0-9._-]+\.[a-z]+/);
    for (const p of bundled.filter((b) => b.startsWith("scripts/"))) expect(Buffer.byteLength(built.get(`${s}/${p}`) ?? ""), p).toBeLessThanOrEqual(MAX_SCRIPT_BYTES);
  }
});

// *--- Nothing of the plugin's machinery ---*

test("pack: no plugin variable, slash command, agent name or em dash reaches a portable file", () => {
  for (const [path, text] of built) expect([path, forbiddenIn(text)]).toEqual([path, null]);
  // The detector sees each thing it is there to catch.
  const samples = [`${"$"}{CLAUDE_PLUGIN_ROOT}/x`, "{{version}}", "run /casa:investigate", "ask casa:log-analyst", "a subagent", "the specialists", "the main thread", "the Overseer", "the Agent tool", "the network-analyst", "the threat-intel agent", "a — b", "the capstone"];
  for (const sample of samples) expect([sample, forbiddenIn(sample) !== null]).toEqual([sample, true]);
  expect(forbiddenIn("Read each thread through the network lens and cite T1071.")).toBeNull();
});

test("pack: every skill and the pack's README link back to the repository", () => {
  for (const s of skills) expect(skillFile(s), s).toContain(REPO_URL);
  expect(built.get("README.md")).toContain(REPO_URL);
  for (const s of skills) expect(built.get("README.md"), s).toContain(`\`${s}\``);
});

// *--- The pack follows its sources (ISC-44) ---*

test("sources: every token kind the lint checks has a row in the evidence check", () => {
  const rows = [...skillFile("casa-evidence-check").matchAll(/^\| ([^|]+) \| `([a-z_0-9]+)` \|/gm)].map((m) => m[2]);
  expect(rows.sort()).toEqual([...KINDS].sort());
});

test("sources: every workflow card is bundled with the triage skill and listed in it", () => {
  const cards = readdirSync(WORKFLOWS).filter((f) => f.endsWith(".md")).sort();
  expect(cards.length).toBeGreaterThanOrEqual(9);
  for (const c of cards) {
    expect(built.has(`casa-soc-triage/references/${c}`), c).toBe(true);
    expect(skillFile("casa-soc-triage"), c).toContain(`\`references/${c}\``);
  }
});

test("sources: the standards skill carries the seven numbered rule sections and the three tables", () => {
  const text = skillFile("casa-soc-standards");
  for (const heading of ["## 1. Scope", "## 2. Untrusted data", "## 3. Anti-fabrication", "## 4. Reasoning trace", "## 5. Confidence", "## 6. Citations", "## 7. Human-in-the-loop framing"]) expect(text).toContain(heading);
  expect(text).not.toContain("## 8.");
  const source = (f: string): string => readFileSync(join(ROOT, "skills", "standards", "references", f), "utf8");
  for (const f of ["attack-techniques.json", "csf-2.0.json"]) expect(built.get(`casa-soc-standards/references/${f}`), f).toBe(source(f));
  // The citation table is the source's, less the square brackets around its status mark.
  const citations = built.get("casa-soc-standards/references/nist-citations.md") ?? "";
  expect(citations).toBe(source("nist-citations.md").replaceAll("[verified]", "verified"));
  expect(citations).not.toMatch(/\[[a-z ]+\](?!\()/);
});

test("drift: the build is deterministic and portable/ on disk is exactly what the sources generate", () => {
  expect([...build()]).toEqual([...built]);
  const disk = onDisk();
  expect([...disk.keys()].sort()).toEqual([...built.keys()].sort());
  for (const [path, text] of built) expect([path, disk.get(path) === text]).toEqual([path, true]);
});
