// *****************************************************************************
// *Title: Prompt Consistency Checks*
// *Author: Kyle*
// *Description: Checks that skills, cards and agents agree on shared rules.*
// *****************************************************************************

// *--- Imports ---*

import { test, expect, afterAll } from "bun:test";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkBash, type BashVerdict } from "../../hooks/bash-policy.ts";

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

// Commands prose must never tell a subagent to run; the guard refuses every one of them.
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

// NOTE: one sentence at a time, so a rule split across two sentences (the condition in one,
// the word "containment" in the next) is not caught; review prose changes for that shape.
/** Sentences that gate containment options on a verdict or confidence level. */
function containmentGates(text: string): string[] {
  return sentences(text).filter(
    (s) => /\bcontainment\b|`contain`|\bcontain options?\b/i.test(s) && /\b(High|Medium|Low|supported|refuted|undetermined|confidence|threshold)\b/.test(s),
  );
}

/** Shell command lines inside fenced code blocks, comments and blanks dropped. */
function recipeLines(text: string): string[] {
  const out: string[] = [];
  for (const block of text.matchAll(/^```[a-z]*\n([\s\S]*?)^```\s*$/gm)) {
    for (const line of block[1].split("\n")) {
      const cmd = line.trim();
      if (cmd && !cmd.startsWith("#")) out.push(cmd);
    }
  }
  return out;
}

/** Fill a recipe's placeholders the way an analyst would and create the files it reads. */
function materialize(recipe: string, project: string): string {
  // A placeholder with an extension names a file (<alerts.jsonl>); any other is a value (<host ip>).
  const cmd = recipe.replace(/<([A-Za-z0-9_-]+\.[A-Za-z0-9]+)>/g, "$1").replace(/<[a-z][a-z ]*>/g, "192.0.2.5");
  for (const m of cmd.matchAll(/(?<=^|\s)([A-Za-z0-9_-]+\.(?:jsonl|json|log|pcap|md))(?=\s|$)/g)) writeFileSync(join(project, m[1]), "");
  return cmd;
}

/** The guard's verdict on one recipe line, run in a scratch project with the plugin at ROOT. */
function guardVerdict(recipe: string, project: string): BashVerdict {
  return checkBash(materialize(recipe, project), project, ROOT);
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

// Every test in this file shares one scratch project; it is removed when the file finishes.
const scratch = mkdtempSync(join(tmpdir(), "casa-recipes-"));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

test("recipes: every fenced command in the workflow cards and agents passes the shipped guard", () => {
  const files = [
    ...readdirSync(join(ROOT, WORKFLOWS)).map((f) => join(WORKFLOWS, f)),
    ...promptFiles().filter((f) => f.startsWith("agents")),
  ];
  const refused: string[] = [];
  let checked = 0;
  for (const f of files) {
    for (const recipe of recipeLines(read(f))) {
      // A line naming the plugin root documents a command the Overseer runs on the main thread
      // under the settings allowlist (Grade.ts is one); the subagent guard never sees it.
      if (recipe.includes(ROOT_VAR)) continue;
      checked++;
      const verdict = guardVerdict(recipe, scratch);
      if (!verdict.ok) refused.push(`${f}: ${recipe} -> ${verdict.reason}`);
    }
  }
  expect(checked).toBeGreaterThan(0);
  expect(refused).toEqual([]);
});

test("recipes: no prompt prose tells an agent to run a command outside the allowlist", () => {
  const word = new RegExp("`(" + SHELL_WORDS.join("|") + ")\\b[^`]*`");
  const named: string[] = [];
  for (const f of promptFiles()) {
    for (const s of sentences(read(f))) if (word.test(s)) named.push(`${f}: ${s}`);
  }
  expect(named).toEqual([]);
});

test("recipes: the checker agrees with the guard on cat and bun Grade.ts", () => {
  expect(guardVerdict("cat <alerts.jsonl>", scratch).ok).toBe(false);
  const grade = guardVerdict(`bun ${join(ROOT, "evals", "Grade.ts")} --fixture <name>`, scratch);
  expect(grade.ok).toBe(false);
  expect(grade.ok ? "" : grade.reason).toMatch(/bun may run only/);
});

test("recipes: the checker refuses a grep or sort pipe and passes jq, zeek-cut and Lint.ts", () => {
  expect(guardVerdict("zeek-cut ts < <conn.log> | grep '<host ip>'", scratch).ok).toBe(false);
  expect(guardVerdict("zeek-cut ts < <conn.log> | sort -n", scratch).ok).toBe(false);
  expect(guardVerdict("jq -r '.a' <alerts.jsonl>", scratch).ok).toBe(true);
  expect(guardVerdict("zeek-cut ts < <conn.log> | jq -R -r 'split(\"\\t\") | @tsv'", scratch).ok).toBe(true);
  // Subagents reach plugin scripts by absolute path; the guard expands no variable.
  expect(guardVerdict(`bun ${join(ROOT, "evals", "Lint.ts")} --brief <brief.md> --intake <intake.json>`, scratch).ok).toBe(true);
  expect(guardVerdict("bun x.ts", scratch).ok).toBe(false);
});

test("recipes: every Bash-carrying analyst names what the guard lets it run", () => {
  const missing: string[] = [];
  for (const f of promptFiles().filter((p) => p.startsWith("agents"))) {
    const text = read(f);
    if (!/^tools:.*\bBash\b/m.test(text)) continue;
    const rule = sentences(text).find((s) => s.includes("Validate.ts") && s.includes("Lint.ts"));
    if (!rule) {
      missing.push(`${f}: no allowlist sentence`);
      continue;
    }
    for (const term of ["`jq`", "`tshark -r`", "`zeek-cut`", "`head`", "`tail`", "`wc`", "`ls`", "absolute path", "Read and Grep tools"]) {
      if (!rule.includes(term)) missing.push(`${f}: allowlist sentence lacks ${term}`);
    }
  }
  expect(missing).toEqual([]);
});

test("recipes: the runbook says the Grade.ts allow rule is for the main thread", () => {
  const doc = read(join("docs", "talonsoclab-integration.md"));
  expect(sentences(doc).some((s) => s.includes("Grade.ts") && /main thread/.test(s) && /subagent/.test(s))).toBe(true);
});

test("threading: a chain that returns to an earlier tactic on another host stays one chain", () => {
  const hyp = section(read(INVESTIGATE), "### 2. HYPOTHESIZE");
  expect(sentences(hyp).some((s) => /return/i.test(s) && /earlier tactic/i.test(s) && /(another|second) host/i.test(s) && /one chain/i.test(s))).toBe(true);
});

test("containment: the one rule gates on a supported finding at High (ruling of 2026-11-15)", () => {
  const [rule] = containmentGates(read(STANDARDS));
  expect(rule).toMatch(/`supported`/);
  expect(rule).toMatch(/\bHigh\b/);
});

test("containment: the detector flags a card that argues for containment below High", () => {
  expect(containmentGates("Containment options are appropriate at Medium or above because the cost is total.")).toHaveLength(1);
  expect(containmentGates("Containment options follow the standards skill's rule.")).toEqual([]);
});
