// *****************************************************************************
// *Title: Prompt Consistency Checks*
// *Author: Kyle*
// *Description: Checks that skills, cards and agents agree on shared rules.*
// *****************************************************************************

// *--- Imports ---*

import { test, expect } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

// *--- Configuration ---*

const ROOT = join(import.meta.dir, "..", "..");
const ROOT_VAR = "${CLAUDE_PLUGIN_ROOT}";
const DATA_VAR = "${CLAUDE_PLUGIN_DATA}";
const SEED_LESSONS = `${ROOT_VAR}/skills/standards/references/lessons.md`;
const DATA_LESSONS = `${DATA_VAR}/lessons.md`;
const STANDARDS = join("skills", "standards", "SKILL.md");
const INVESTIGATE = join("skills", "investigate", "SKILL.md");
const LEARN = join("skills", "learn", "SKILL.md");
const DETECTION_ENGINEER = join("agents", "detection-engineer.md");
const WORKFLOWS = join("skills", "investigate", "references", "workflows");

// The read-only command set the plugin's Bash allowlist permits. A recipe may chain these with
// a pipe; anything else (grep, sort, awk, sed) is outside the allowlist and the run is refused.
const ALLOWED_COMMANDS = new Set(["jq", "tshark", "zeek-cut", "head", "tail", "wc", "cat", "ls"]);
const ALLOWED_BUN = /^bun \$\{CLAUDE_PLUGIN_ROOT\}\/(intake\/Validate\.ts|evals\/Lint\.ts|evals\/Grade\.ts)\b/;
const SHELL_WORDS = ["grep", "egrep", "rg", "sort", "uniq", "awk", "sed", "cut", "xargs", "find", "python", "python3", "perl", "lsof", "rm", "curl", "wget"];

// *--- Helper Functions ---*

/** Read a repo file as text. */
function read(rel: string): string {
  return readFileSync(join(ROOT, rel), "utf8");
}

/** Markdown files the investigate path loads: every skill and agent except the grading path. */
function promptFiles(): string[] {
  const out: string[] = [];
  const walk = (dir: string): void => {
    for (const e of readdirSync(join(ROOT, dir), { withFileTypes: true })) {
      const rel = join(dir, e.name);
      if (rel === join("skills", "evaluate") || rel === join("agents", "evaluator.md")) continue;
      if (e.isDirectory()) walk(rel);
      else if (e.name.endsWith(".md")) out.push(rel);
    }
  };
  walk("skills");
  walk("agents");
  return out.sort();
}

/** Text of one `## `/`### ` section, from its heading up to the next heading of that depth or higher. */
function section(text: string, heading: string): string {
  const lines = text.split("\n");
  const start = lines.findIndex((l) => l.trim() === heading);
  if (start === -1) return "";
  const depth = heading.match(/^#+/)![0].length;
  const end = lines.findIndex((l, i) => i > start && /^#+ /.test(l) && l.match(/^#+/)![0].length <= depth);
  return lines.slice(start + 1, end === -1 ? undefined : end).join("\n");
}

/** Prose sentences, with fenced code removed and list items and table rows split apart. */
function sentences(text: string): string[] {
  const prose = text.replace(/^(```|````)[\s\S]*?^\1\s*$/gm, "");
  return prose
    .split(/\n\s*\n|\n\s*(?=[-*|#]|\d+\. )|(?<=[a-z)`*][.!?])\s+(?=[A-Z`*(])/)
    .map((s) => s.replace(/\s+/g, " ").trim())
    .filter(Boolean);
}

/** Sentences that gate containment options on a verdict or confidence level. */
function containmentGates(text: string): string[] {
  return sentences(text).filter(
    (s) => /\bcontainment\b|`contain`|\bcontain options?\b/i.test(s) && /\b(High|Medium|Low|supported|refuted|undetermined|confidence|threshold)\b/.test(s),
  );
}

/** Split a command line on pipes that sit outside single or double quotes. */
function pipeSegments(line: string): string[] {
  const segs: string[] = [];
  let quote = "";
  let cur = "";
  for (const ch of line) {
    if (quote) {
      if (ch === quote) quote = "";
    } else if (ch === "'" || ch === '"') {
      quote = ch;
    } else if (ch === "|") {
      segs.push(cur.trim());
      cur = "";
      continue;
    }
    cur += ch;
  }
  segs.push(cur.trim());
  return segs;
}

/** Shell command lines inside fenced code blocks, one entry per pipeline segment. */
function recipeSegments(text: string): string[] {
  const out: string[] = [];
  for (const block of text.matchAll(/^```[a-z]*\n([\s\S]*?)^```\s*$/gm)) {
    for (const line of block[1].split("\n")) {
      const cmd = line.trim();
      if (!cmd || cmd.startsWith("#")) continue;
      out.push(...pipeSegments(cmd));
    }
  }
  return out;
}

/** Whether one pipeline segment is inside the read-only allowlist. */
function allowedSegment(seg: string): boolean {
  // Quoted programs (jq filters, tshark display filters) and <placeholders> are arguments, not shell syntax.
  const bare = seg.replace(/'[^']*'|"[^"]*"/g, "''").replace(/<[^<>\s]+>/g, "PLACEHOLDER");
  if (bare === "" || /[;&`>]|\$\(/.test(bare)) return false;
  const first = bare.split(/\s+/)[0];
  if (first === "bun") return ALLOWED_BUN.test(seg);
  return ALLOWED_COMMANDS.has(first);
}

// *--- ISC-28: approved lessons reach every run ---*

test("lessons read: OBSERVE reads the shipped seed and the persistent data file", () => {
  const observe = section(read(INVESTIGATE), "### 1. OBSERVE");
  expect(observe).toContain(SEED_LESSONS);
  expect(observe).toContain(DATA_LESSONS);
});

test("lessons read: /casa:learn appends to the data file, never to the shipped seed", () => {
  const learn = read(LEARN);
  const promote = section(learn, "## Promote");
  expect(promote).toContain(DATA_LESSONS);
  expect(promote).not.toContain(SEED_LESSONS);
  expect(learn).not.toMatch(/read by the standards skill/i);
  expect(learn).toMatch(/explicit approval/i);
});

test("lessons read: the integration runbook says where approved lessons live", () => {
  const doc = read(join("docs", "talonsoclab-integration.md"));
  const step2 = doc.slice(doc.indexOf("## 2."), doc.indexOf("## 3."));
  expect(step2).toContain(DATA_VAR);
  expect(step2).not.toMatch(/overwrites; copy it back by hand/);
  expect(doc).not.toMatch(/lessons file in the CASA checkout/);
});

// *--- ISC-30: one containment rule ---*

test("containment: the standards skill holds exactly one containment rule", () => {
  expect(containmentGates(read(STANDARDS))).toHaveLength(1);
});

test("containment: no card, agent or other skill restates a containment threshold", () => {
  const restated: string[] = [];
  for (const f of promptFiles()) {
    if (f === STANDARDS) continue;
    for (const s of containmentGates(read(f))) restated.push(`${f}: ${s}`);
  }
  expect(restated).toEqual([]);
});

// *--- ISC-31: detection drafts never overwrite each other ---*

test("draft names: every detection draft path carries the run id", () => {
  const de = read(DETECTION_ENGINEER);
  const paths = [...de.matchAll(/detections\/proposed\/[^`\s]+/g)].map((m) => m[0]).filter((p) => /\.(sigma\.yml|wazuh\.xml|md)$/.test(p));
  expect(paths.length).toBe(3);
  for (const p of paths) expect(p).toContain("<run_id>");
});

test("draft names: no prompt file names an output by date and thread alone", () => {
  const dated: string[] = [];
  for (const f of promptFiles()) if (/<date>-<thread_id>|<date>-<slug>/.test(read(f))) dated.push(f);
  expect(dated).toEqual([]);
});

test("draft names: the investigate skill defines a run-unique run_id and hands it to the detection engineer", () => {
  const inv = read(INVESTIGATE);
  expect(sentences(inv).some((s) => s.includes("run_id") && /unique/i.test(s))).toBe(true);
  expect(sentences(section(inv, "### 5. MAP")).some((s) => s.includes("run_id") && s.includes("casa:detection-engineer"))).toBe(true);
});

// *--- ISC-59: raw-mode recipes stay inside the allowlist ---*

test("recipes: every fenced command in the workflow cards and agents is allowlisted", () => {
  const files = [
    ...readdirSync(join(ROOT, WORKFLOWS)).map((f) => join(WORKFLOWS, f)),
    ...promptFiles().filter((f) => f.startsWith("agents")),
  ];
  const outside: string[] = [];
  let checked = 0;
  for (const f of files) {
    for (const seg of recipeSegments(read(f))) {
      checked++;
      if (!allowedSegment(seg)) outside.push(`${f}: ${seg}`);
    }
  }
  expect(checked).toBeGreaterThan(0);
  expect(outside).toEqual([]);
});

test("recipes: no prompt prose tells an agent to run a command outside the allowlist", () => {
  const word = new RegExp("`(" + SHELL_WORDS.join("|") + ")\\b[^`]*`");
  const named: string[] = [];
  for (const f of promptFiles()) {
    for (const s of sentences(read(f))) if (word.test(s)) named.push(`${f}: ${s}`);
  }
  expect(named).toEqual([]);
});

test("recipes: the allowlist checker rejects a grep or sort pipe and accepts a jq one", () => {
  expect(allowedSegment("grep '<host ip>'")).toBe(false);
  expect(allowedSegment("sort -n")).toBe(false);
  expect(allowedSegment("jq -r '.a' <alerts.jsonl>")).toBe(true);
  expect(allowedSegment("bun ${CLAUDE_PLUGIN_ROOT}/evals/Lint.ts --brief <b>")).toBe(true);
  expect(allowedSegment("bun x.ts")).toBe(false);
});
