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

// Commands no prompt names in backticks: the recommended settings do not allow them, and jq
// does their filtering and counting in every recipe.
const SHELL_WORDS = ["grep", "egrep", "rg", "sort", "uniq", "awk", "sed", "cut", "xargs", "find", "python", "python3", "perl", "lsof", "rm", "curl", "wget"];
// Commands a data request may carry for the main thread or the human analyst to run.
const QUERY_WORDS = ["jq", "tshark", "zeek-cut", "head", "tail", "wc", "ls", "cat", "bun"];

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
  // A `# comment` inside a fenced command block is not a heading.
  let fenced = false;
  const end = lines.findIndex((l, i) => {
    if (i > start && /^```/.test(l)) fenced = !fenced;
    return i > start && !fenced && /^#+ /.test(l) && l.match(/^#+/)![0].length <= depth;
  });
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

/** Each `## ` section of a Markdown file that holds a fenced command, keyed by its heading. */
function recipeSections(text: string): Array<{ heading: string; body: string }> {
  const out: Array<{ heading: string; body: string }> = [];
  for (const heading of text.split("\n").filter((l) => /^## /.test(l))) {
    const body = section(text, heading.trim());
    if (recipeLines(body).length > 0) out.push({ heading: heading.trim(), body });
  }
  return out;
}

/** Commands the recommended settings let the main thread run without a prompt. */
function mainThreadCommands(): Set<string> {
  const allow: string[] = JSON.parse(read(join("docs", "settings.recommended.json"))).permissions.allow;
  return new Set(allow.map((r) => r.match(/^Bash\(([a-z-]+) \*\)$/)?.[1]).filter((c): c is string => c !== undefined));
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

// *--- ISC-59: raw-data queries are data requests, never a specialist's shell ---*

test("recipes: every card recipe sits in a data-request section the main thread runs", () => {
  const wrong: string[] = [];
  let sections = 0;
  for (const card of readdirSync(join(ROOT, WORKFLOWS)).map((f) => join(WORKFLOWS, f))) {
    for (const { heading, body } of recipeSections(read(card))) {
      sections++;
      if (!/data request/i.test(heading)) wrong.push(`${card}: recipe under "${heading}"`);
      const framed = sentences(body).some((s) => /main thread/.test(s) && /specialist/.test(s) && /\bnever\b/.test(s));
      if (!framed) wrong.push(`${card}: "${heading}" does not say the main thread runs these and a specialist never does`);
    }
  }
  expect(sections).toBeGreaterThan(0);
  expect(wrong).toEqual([]);
});

test("recipes: every card recipe uses only commands the recommended settings allow", () => {
  const allowed = mainThreadCommands();
  const outside: string[] = [];
  for (const card of readdirSync(join(ROOT, WORKFLOWS)).map((f) => join(WORKFLOWS, f))) {
    for (const line of recipeLines(read(card))) {
      for (const seg of pipeSegments(line)) {
        const cmd = seg.split(/\s+/)[0] ?? "";
        if (!allowed.has(cmd)) outside.push(`${card}: ${seg}`);
      }
    }
  }
  expect(allowed.size).toBeGreaterThan(0);
  expect(outside).toEqual([]);
});

test("recipes: no agent tells a specialist to run a shell command", () => {
  const query = new RegExp("`(" + [...QUERY_WORDS, ...SHELL_WORDS].join("|") + ")\\b[^`]*`");
  const told: string[] = [];
  for (const f of promptFiles().filter((p) => p.startsWith("agents"))) {
    const text = read(f);
    if (recipeLines(text).length > 0) told.push(`${f}: fenced command block`);
    for (const s of sentences(text)) if (query.test(s) && !/data_requests|data request/.test(s)) told.push(`${f}: ${s}`);
    if (/\bBash\b/.test(text.replace(/^---\n[\s\S]*?\n---\n/, ""))) told.push(`${f}: body mentions Bash`);
  }
  expect(told).toEqual([]);
});

test("recipes: no prompt prose names a command outside the allowlist", () => {
  const word = new RegExp("`(" + SHELL_WORDS.join("|") + ")\\b[^`]*`");
  const named: string[] = [];
  for (const f of promptFiles()) {
    for (const s of sentences(read(f))) if (word.test(s)) named.push(`${f}: ${s}`);
  }
  expect(named).toEqual([]);
});

test("recipes: the runbook and README say specialists have no shell", () => {
  for (const f of [join("docs", "talonsoclab-integration.md"), "README.md"]) {
    expect(sentences(read(f)).some((s) => /specialists/i.test(s) && /no shell/i.test(s))).toBe(true);
  }
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

// *--- Intake v3 and Output Root ---*

test("v3 fields: the investigate skill names the split users, the typed groups, the include list and the counts", () => {
  const text = read(INVESTIGATE);
  for (const field of ["talonsoclab.soc-intake/v3", "subject_user", "target_user", "logon_type", "src_port", "dst_port", "engine", "include_rule_ids", "counts", "process_create", "network_connect", "file_create", "registry_value_set", "dns_query", "suricata"]) {
    // Named inside a code span, alone or as a path such as `filter.include_rule_ids`.
    const span = new RegExp("`[^`\\n]*\\b" + field.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&") + "\\b[^`\\n]*`");
    expect([field, span.test(text)]).toEqual([field, true]);
  }
});

test("v3 fields: every card with a v2 note has a v3 note that names a v3 field", () => {
  const V3_FIELDS = /`(?:subject_user|target_user|logon_type|src_port|dst_port|proto|engine(?:\.rule_id)?|sysmon|process_create|network_connect|file_create|registry_value_set|dns_query|suricata|tls_sni|http_hostname|app_proto|image)`/;
  const cards = readdirSync(join(ROOT, WORKFLOWS)).filter((f) => f.endsWith(".md"));
  for (const card of cards) {
    const text = read(join(WORKFLOWS, card));
    if (!text.includes("**v2 intakes:**")) continue;
    const note = text.split("**v3 intakes:**")[1]?.split(/\n- \*\*|\n\n/)[0] ?? "";
    expect([card, V3_FIELDS.test(note)]).toEqual([card, true]);
  }
});

test("output root: the manifest declares the option and every writing skill and agent resolves against it", () => {
  const manifest = JSON.parse(read(join(".claude-plugin", "plugin.json")));
  expect(manifest.userConfig?.output_root?.type).toBe("directory");
  expect(manifest.userConfig.output_root.required).toBeUndefined();
  const token = "${user_config.output_root}";
  const standards = read(STANDARDS);
  expect(standards).toContain(token);
  expect(standards).toMatch(/empty[\s\S]{0,80}placeholder[\s\S]{0,80}project\s+directory/);
  for (const rel of [INVESTIGATE, LEARN, join("skills", "evaluate", "SKILL.md")]) expect([rel, read(rel).includes(token)]).toEqual([rel, true]);
  for (const rel of [INVESTIGATE, LEARN, join("skills", "evaluate", "SKILL.md"), DETECTION_ENGINEER, join("agents", "evaluator.md")]) {
    expect([rel, /output root/i.test(read(rel))]).toEqual([rel, true]);
  }
  expect(read(join("skills", "evaluate", "SKILL.md"))).toContain("--out");
});

// *--- Finding scratch files (ISC-91) ---*

test("scratch: findings are saved under the output root, in a place the skill names", () => {
  const verify = section(read(INVESTIGATE), "### 4. VERIFY");
  // A bare "scratchpad" names no directory; headless runs then try paths the harness refuses.
  expect(verify).not.toMatch(/\bscratchpad\b/i);
  expect(verify).toContain("briefs/scratch/<run_id>/");
  expect(verify).toMatch(/output root/i);
  for (const rel of promptFiles()) expect([rel, /\bscratchpad\b|\/tmp\b/i.test(read(rel))]).toEqual([rel, false]);
});

// *--- Confidence, time bounds and verdict framing (ISC-93, ISC-94, ISC-95) ---*

test("confidence: unknowns narrow the claim, and a benign reading nothing supports does not hold the level down", () => {
  const confidence = section(read(STANDARDS), "## 5. Confidence").replace(/\s+/g, " ");
  expect(confidence).toMatch(/narrows the claim and becomes a data request/);
  expect(confidence).toMatch(/counts against High only when something in the input supports it/);
  expect(confidence).toMatch(/only not ruled out[^.]*does not hold the level down/);
});

test("time bounds: a truncated input's first and last detections are edges of the collection, not of the activity", () => {
  const rule = section(read(STANDARDS), "## 3. Anti-fabrication").replace(/\s+/g, " ");
  expect(rule).toMatch(/truncated[^.]*earliest and latest detections are the edges of what was collected, never the start or end of the activity/);
});

test("verdict framing: a benign outcome refutes the threat hypothesis instead of supporting a benign one", () => {
  const hypothesize = section(read(INVESTIGATE), "### 2. HYPOTHESIZE").replace(/\s+/g, " ");
  expect(hypothesize).toMatch(/threat reading the detections themselves assert/);
  expect(hypothesize).toMatch(/that hypothesis is `refuted`/);
});

test("confidence: truncation still lowers the level, and a refutation on the input's own account stays at Medium", () => {
  const confidence = section(read(STANDARDS), "## 5. Confidence").replace(/\s+/g, " ");
  // Missing evidence inside the claim is not an unknown around it.
  expect(confidence).toMatch(/Truncated window applies whenever the input says detections were cut/);
  expect(confidence).toMatch(/level drops one and the brief names that as the reason/);
  // The rule that protects a supported finding must not be run backwards to wave activity through.
  expect(confidence).toMatch(/`refuted` verdict that rests on the input's own account of sanctioned activity[^.]*is Medium at most until someone outside the input confirms/);
});

test("mapping: a brief that offers containment cites the Respond subcategory it falls under", () => {
  const brief = section(read(INVESTIGATE), "### 6. BRIEF").replace(/\s+/g, " ");
  expect(brief).toMatch(/`contain` option[^.]*cites the Respond \(RS\) subcategory/);
});

// *--- Workflow cards for the S2 technique families ---*

const CARD_HEADINGS = ["## 1. Applies when", "## 2. Hypotheses", "## 3. Intake-only decision rules", "## 4. Data requests", "## 5. Raw-data requests", "## 6. Confidence ladder"];

// Each family is named by the technique roots its card's "applies when" section must name.
const CARD_FAMILIES: Record<string, string[]> = {
  "script and signed-binary proxy execution": ["T1059", "T1218"],
  "service and autostart persistence": ["T1543", "T1547"],
  "log and defense tampering": ["T1685", "T1070"],
  "internal discovery and scanning": ["T1046"],
};

const TECHNIQUE_ID = /\bT\d{4}(?:\.\d{3})?\b/g;
const RECON = /recon[-_ ]delta|recon_delta/i;

/** Every workflow card, as a repo-relative path. */
function cardPaths(): string[] {
  return readdirSync(join(ROOT, WORKFLOWS)).filter((f) => f.endsWith(".md")).sort().map((f) => join(WORKFLOWS, f));
}

/** The full heading line that starts with a numbered prefix, such as "## 4. Data requests (what settles H1)". */
function headingLine(text: string, prefix: string): string {
  return text.split("\n").find((l) => l === prefix || l.startsWith(`${prefix} `)) ?? "";
}

/** One card section by its numbered prefix, or "" when the card lacks it. */
function cardSection(text: string, prefix: string): string {
  const line = headingLine(text, prefix);
  return line ? section(text, line) : "";
}

/** True when the text names the technique root itself or one of its sub-techniques. */
function namesRoot(text: string, root: string): boolean {
  return new RegExp(`\\b${root}(?:\\.\\d{3})?\\b`).test(text);
}

/** The one card whose "applies when" names every root of a family; [] or several when that fails. */
function familyCards(roots: string[]): string[] {
  return cardPaths().filter((p) => {
    const applies = cardSection(read(p), "## 1. Applies when");
    return roots.every((r) => namesRoot(applies, r));
  });
}

/** Top-level list items of a Markdown section, each joined onto one line. */
function listItems(text: string): string[] {
  return text
    .split(/\n(?=- )/)
    .filter((s) => s.startsWith("- "))
    .map((s) => s.replace(/\s+/g, " ").trim());
}

/** Rows of the technique-to-specialist table under HYPOTHESIZE, as [family cell, specialists cell]. */
function techniqueTable(): Array<[string, string]> {
  const rows = section(read(INVESTIGATE), "### 2. HYPOTHESIZE").split("\n").filter((l) => /^\|/.test(l));
  return rows
    .slice(2)
    .map((l) => l.split("|").slice(1, -1).map((c) => c.trim()))
    .filter((cells) => cells.length === 2)
    .map(([family, specialists]) => [family, specialists]);
}

test("cards: each new technique family has exactly one card with all six numbered sections and a CSF line", () => {
  for (const [family, roots] of Object.entries(CARD_FAMILIES)) {
    const cards = familyCards(roots);
    expect([family, cards.length]).toEqual([family, 1]);
    const text = read(cards[0]);
    const lines = CARD_HEADINGS.map((h) => text.split("\n").indexOf(headingLine(text, h)));
    expect([family, lines.every((i) => i >= 0)]).toEqual([family, true]);
    // In order, so a card cannot satisfy the shape with its sections shuffled.
    expect([family, lines.every((i, k) => k === 0 || i > lines[k - 1])]).toEqual([family, true]);
    expect([family, /^CSF 2\.0: /m.test(cardSection(text, "## 6. Confidence ladder"))]).toEqual([family, true]);
  }
});

test("cards: the investigate skill's technique table has one row per new family, naming existing specialists only", () => {
  const specialists = new Set(
    [...section(read(INVESTIGATE), "# /casa:investigate").matchAll(/^\| `casa:([a-z-]+)` \|/gm)].map((m) => m[1]),
  );
  expect(specialists.size).toBeGreaterThan(0);
  const table = techniqueTable();
  for (const [family, roots] of Object.entries(CARD_FAMILIES)) {
    const rows = table.filter(([cell]) => roots.every((r) => namesRoot(cell, r)));
    expect([family, rows.length]).toEqual([family, 1]);
    const named = rows[0][1].split(",").map((s) => s.trim());
    expect([family, named.length > 0 && named.every((s) => specialists.has(s))]).toEqual([family, true]);
  }
});

test("cards: every technique ID a card or the skill table names is in the ATT&CK reference table", () => {
  const known = new Set(
    (JSON.parse(read(join("skills", "standards", "references", "attack-techniques.json"))) as { techniques: Array<{ id: string }> }).techniques.map((t) => t.id),
  );
  const sources: Array<[string, string]> = cardPaths().map((p) => [p, read(p)]);
  sources.push([`${INVESTIGATE} (HYPOTHESIZE)`, section(read(INVESTIGATE), "### 2. HYPOTHESIZE")]);
  const unknown: string[] = [];
  let seen = 0;
  for (const [where, text] of sources) {
    for (const [id] of text.matchAll(TECHNIQUE_ID)) {
      seen++;
      if (!known.has(id)) unknown.push(`${where}: ${id}`);
    }
  }
  expect(seen).toBeGreaterThan(0);
  expect(unknown).toEqual([]);
});

test("cards: each new card's decision rules say when a recon-delta change counts once toward High", () => {
  for (const [family, roots] of Object.entries(CARD_FAMILIES)) {
    const [card] = familyCards(roots);
    const rules = listItems(cardSection(card ? read(card) : "", "## 3. Intake-only decision rules")).filter((s) => RECON.test(s));
    // Agrees with standards §5 (detections plus a recon change) and VERIFY (counts once), in one
    // sentence, so a "once" elsewhere in the bullet cannot stand in for the rule itself.
    const counted = rules.some((r) => sentences(r).some((s) => /\bindependent\b/i.test(s) && /\bHigh\b/.test(s) && /\bonce\b/.test(s)));
    expect([family, counted]).toEqual([family, true]);
    // The borrowed beaconing wording that started this slice.
    const demoted = rules.filter((s) => /context only|not proof|does not raise/i.test(s));
    expect([family, demoted]).toEqual([family, []]);
  }
});

test("cards: recipes name Windows event fields the way Wazuh writes them", () => {
  // Wazuh's event channel decoder lowers the first letter of every eventdata field, as the
  // recordings under intake/raw show; a recipe that keeps Windows' own casing selects nothing.
  for (const name of readdirSync(join(ROOT, WORKFLOWS)).filter((f) => f.endsWith(".md"))) {
    const wrong = [...read(join(WORKFLOWS, name)).matchAll(/\.eventdata\.([A-Z][A-Za-z]*)/g)].map((m) => m[1]);
    expect([name, wrong]).toEqual([name, []]);
  }
  const recorded = readFileSync(join(ROOT, "intake", "raw", "brute-force-dc-chain.v2.alerts.jsonl"), "utf8");
  expect(recorded).toContain('"targetUserName"');
  expect(recorded).not.toContain('"TargetUserName"');
});
