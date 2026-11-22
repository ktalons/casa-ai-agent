#!/usr/bin/env bun
// *****************************************************************************
// *Title: Portable Skill Pack Builder*
// *Author: Kyle*
// *Description: Generates the portable casa-* skills from the plugin sources.*
// *****************************************************************************

/**
 *   bun scripts/build-portable.ts            write portable/ from the sources
 *   bun scripts/build-portable.ts --check    exit 1 when portable/ differs from what they generate
 *
 * The pack is three skills in the Agent Skills format (agentskills.io) for agents that cannot
 * load the plugin. Rule text is pulled from the plugin's own skills, cards and agents, never
 * retyped, and every pull names the exact text it expects: when a source sentence changes, the
 * build fails until someone looks at it. The glue around those pulls lives in scripts/portable-src/.
 */

// *--- Imports ---*

import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { KINDS } from "../evals/lib/extract.ts";

// *--- Configuration ---*

const ROOT = join(import.meta.dir, "..");
const TEMPLATES = join(import.meta.dir, "portable-src");
export const PORTABLE_DIR = join(ROOT, "portable");
export const REPO_URL = "https://github.com/ktalons/casa-ai-agent";

const STANDARDS = join("skills", "standards", "SKILL.md");
const STANDARDS_REFS = join("skills", "standards", "references");
const INVESTIGATE = join("skills", "investigate", "SKILL.md");
const BRIEF_TEMPLATE = join("skills", "investigate", "references", "brief-template.md");
const WORKFLOWS = join("skills", "investigate", "references", "workflows");

// The plugin's path to its reference tables, as the sources write it.
const DOLLAR = "$";
const PLUGIN_REFS = `${DOLLAR}{CLAUDE_PLUGIN_ROOT}/skills/standards/references/`;
const WIDTH = 96;

type Kind = (typeof KINDS)[number];

// How each token kind reads in prose, and when a value of that kind traces. A kind the lint
// gains has no entry here, so the typecheck fails before a stale pack can be built.
const KIND_RULES: Record<Kind, { label: string; plural: string; rule: string }> = {
  rule_id: { label: "Rule ID", plural: "rule ID", rule: "It equals the `rule_id` of a detection in the input. Checked where the text says rule, rule ID or SID, or lists `rule_ids`." },
  alert_id: { label: "Alert ID", plural: "alert ID", rule: "It equals an `alert_id` in the input." },
  host: { label: "Host", plural: "host", rule: "The input names it, on a detection or in the recon delta. An account name the input carries is not an invented host." },
  attack: { label: "ATT&CK technique ID", plural: "ATT&CK technique ID", rule: "It is in the ATT&CK table of `casa-soc-standards`, written in its canonical form (`T<number>` or `T<number>.<sub>`)." },
  csf: { label: "NIST CSF 2.0 ID", plural: "CSF ID", rule: "It is in the CSF table of `casa-soc-standards`, written in its canonical form." },
  ip: { label: "IPv4 address", plural: "IPv4 address", rule: "It is present in the input, or is a special-use address listed in the reference file." },
  ipv6: { label: "IPv6 address", plural: "IPv6 address", rule: "It is present in the input, compared in canonical form, or is a special-use address listed in the reference file." },
  user: { label: "User or account", plural: "user", rule: "The input names it. A `DOMAIN\\user` form traces when the account part is named." },
  event_id: { label: "Event ID", plural: "event ID", rule: "It is in the input, or is a real event ID listed in the reference file." },
  port: { label: "Port", plural: "port", rule: "It is in the input, or is a well-known service port listed in the reference file. A host and port written together must appear together in the input." },
  domain: { label: "Domain", plural: "domain", rule: "It is present in the input, or is a documentation domain listed in the reference file." },
  hash: { label: "Hash", plural: "hash", rule: "It is present in the input." },
  timestamp: { label: "Date or time", plural: "timestamp", rule: "It is present in the input at the precision written. A time in a proposed query window traces when it falls inside the input's own window." },
};

// The note every workflow card carries above its raw-data queries, and its single-agent form.
const RAW_NOTE = "A specialist never runs these: they are data requests, which the main thread runs under the user's own permission settings when raw telemetry exists, handing the output to the specialists, or which go into `data_requests` as exact commands for the human analyst.";
const RAW_NOTE_PORTABLE = "Run these only on raw files the analyst supplied, under your own permission settings. Otherwise\nwrite each one into the brief's `data_requests` as an exact command for the analyst to run.";

// *--- Types ---*

interface Skill {
  name: string;
  description: string;
  compatibility?: string;
  body: () => string;
  files: () => Record<string, string>;
}

// *--- Helper Functions ---*

const read = (rel: string): string => readFileSync(join(ROOT, rel), "utf8");
const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** `text` with `from` replaced by `to`. Fails unless `from` occurs exactly `times` times, so a source edit cannot pass unseen. */
function swap(text: string, from: string, to: string, times = 1): string {
  const found = text.split(from).length - 1;
  if (found !== times) throw new Error(`build-portable: expected ${times} of ${JSON.stringify(from)} in a source, found ${found}`);
  return text.split(from).join(to);
}

/** The part of `text` from `start` up to `end`, or to the end of the text. A missing or repeated start fails the build. */
function between(text: string, start: string, end: string | null): string {
  const a = text.indexOf(start);
  if (a === -1 || text.indexOf(start, a + 1) !== -1) throw new Error(`build-portable: ${JSON.stringify(start)} must occur exactly once in its source`);
  const b = end === null ? text.length : text.indexOf(end, a + start.length);
  if (b === -1) throw new Error(`build-portable: ${JSON.stringify(end)} not found after ${JSON.stringify(start)}`);
  return text.slice(a, b);
}

/** One paragraph on one line: every run of whitespace becomes a single space. */
const flow = (text: string): string => text.replace(/\s+/g, " ").trim();

/** Wraps a one-line paragraph at WIDTH. Continuation lines take `indent`. */
function wrap(text: string, indent = ""): string {
  const lines: string[] = [];
  let line = "";
  // A Markdown link is one word, so its text never breaks across lines.
  for (const word of text.match(/\[[^\]]*\]\([^)]*\)\S*|\S+/g) ?? []) {
    if (line.trim() && line.length + 1 + word.length > WIDTH) {
      lines.push(line);
      line = indent + word;
    } else line = line ? `${line} ${word}` : word;
  }
  if (line) lines.push(line);
  return lines.join("\n");
}

/** Rewraps the paragraphs and bullets of a Markdown document, leaving headings, tables and code as they are. */
function reflow(doc: string): string {
  let fenced = false;
  const blocks = doc.split("\n\n").map((block) => {
    const fences = (block.match(/^```/gm) ?? []).length;
    const inside = fenced;
    if (fences % 2 === 1) fenced = !fenced;
    if (inside || fences > 0 || /^[#|]/.test(block)) return block;
    if (block.startsWith("- ")) return block.split(/\n(?=- )/).map((b) => wrap(flow(b), "  ")).join("\n");
    return wrap(flow(block));
  });
  return blocks.join("\n\n");
}

/** Fills every `{{key}}` of a template. An unknown, unused or leftover key fails the build. */
function fill(template: string, values: Record<string, string>): string {
  let out = template;
  for (const [key, value] of Object.entries(values)) {
    const mark = `{{${key}}}`;
    if (!out.includes(mark)) throw new Error(`build-portable: the template has no ${mark}`);
    out = out.split(mark).join(value);
  }
  const left = out.match(/\{\{[a-z-]+\}\}/);
  if (left) throw new Error(`build-portable: ${left[0]} was never filled`);
  return out;
}

const template = (name: string): string => readFileSync(join(TEMPLATES, name), "utf8");
const pluginVersion = (): string => JSON.parse(read(join(".claude-plugin", "plugin.json"))).version as string;
const attackVersion = (): string => JSON.parse(read(join(STANDARDS_REFS, "attack-techniques.json"))).attack_version as string;
const sentence = (text: string): string => `${text[0].toUpperCase()}${text.slice(1)}${text.endsWith(".") ? "" : "."}`;

/** A list in prose: "a, b and c". */
function listed(items: string[]): string {
  return `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;
}

// *--- Pulls from the plugin sources ---*

/** Sections 1 to 7 of the standards skill, with the plugin's table paths made relative. */
function standardsRules(): string {
  const src = read(STANDARDS);
  const sections = [1, 2, 3, 4, 5, 6, 7].map((n) => {
    const start = src.indexOf(`\n## ${n}. `);
    const end = src.indexOf(`\n## ${n + 1}. `);
    if (start === -1 || end === -1) throw new Error(`build-portable: standards section ${n} not found`);
    return src.slice(start + 1, end).trim();
  });
  let out = sections.join("\n\n");
  out = swap(out, PLUGIN_REFS, "references/", 4);
  // Outside the plugin there is no finding record with an injection_flags field to fill.
  out = swap(out, "Copy the text verbatim into `injection_flags[]`", "Quote the text verbatim in a list of injection flags in your output");
  return out;
}

/** The NIST citation table. Its status mark loses the square brackets, which Markdown reads as a link with no target. */
function nistCitations(): string {
  return swap(read(join(STANDARDS_REFS, "nist-citations.md")), "[verified]", "verified", 22);
}

/** What a specialist's lane says it does, as one sentence for the matching lens. */
function lens(agent: string): string {
  const m = read(join("agents", `${agent}.md`)).match(/- \*\*Do\*\*: ([\s\S]*?)\n- \*\*Don't\*\*/);
  if (!m) throw new Error(`build-portable: no Do lane in agents/${agent}.md`);
  return sentence(flow(m[1]));
}

/** The technique table of the investigate skill, with specialists named as lenses. */
function techniqueTable(inv: string): string {
  let table = between(inv, "| Technique family | Specialists |", "### 3. INVESTIGATE").trim();
  table = swap(table, "| Technique family | Specialists |", "| Technique family | Lenses |");
  table = swap(table, `\`${PLUGIN_REFS}attack-techniques.json\``, "the `casa-soc-standards` ATT&CK table");
  table = swap(table, "| threat-intel |", "| threat intelligence |");
  return table.replaceAll("log-analyst", "log").replaceAll("endpoint-analyst", "endpoint").replaceAll("network-analyst", "network");
}

/** A workflow card for one assistant working alone. */
function card(text: string, name: string): string {
  const note = new RegExp(RAW_NOTE.split(" ").map(escapeRe).join("\\s+"));
  if (!note.test(text)) throw new Error(`build-portable: ${name} does not carry the raw-data note`);
  return text
    .replace(note, RAW_NOTE_PORTABLE)
    .replace(/the threat-intel agent can look\s+up/g, "a threat-intelligence lookup can use")
    .replaceAll("threat-intel agent", "threat-intelligence lookup")
    .replaceAll("(standards §", "(`casa-soc-standards` section ");
}

const cardNames = (): string[] => readdirSync(join(ROOT, WORKFLOWS)).filter((f) => f.endsWith(".md")).sort();

/** The brief template without the plugin's agent names. */
function briefTemplate(): string {
  let out = read(BRIEF_TEMPLATE);
  out = swap(out, '"findings_from": ["casa:log-analyst", "..."]', '"findings_from": ["log lens", "..."]');
  return swap(out, " from the purple-team mapper", "");
}

// *--- The three skills ---*

function standardsBody(): string {
  return reflow(fill(template("casa-soc-standards.md"), {
    "standards-rules": standardsRules(),
    "attack-version": attackVersion(),
    "repo-url": REPO_URL,
    version: pluginVersion(),
  }));
}

function triageBody(): string {
  const inv = read(INVESTIGATE);
  const versions = between(inv, "- **v2 intakes**", "- **`detections` is empty**").trim();
  let strip = flow(between(inv, "Strip each one from the finding", "Then check"));
  strip = swap(strip, "from the finding, downgrade that finding one", "from its thread, lower that thread one");
  let rubric = flow(between(inv, "Medium and Low findings carry", "**Disagreement between specialists.**"));
  rubric = swap(swap(rubric, "Medium and Low findings carry", "Medium and Low threads carry"), "High findings carry", "High threads carry");
  let disagreement = flow(between(inv, "**Disagreement between specialists.**", "### 5. MAP"));
  disagreement = swap(disagreement, "**Disagreement between specialists.** When findings for the same thread carry different levels", "**When lenses disagree.** When two lenses put the same thread at different levels");
  let respond = `${flow(between(inv, "Each `contain` option is a", "; the mapper maps findings"))}.`;
  respond = swap(respond, "from the same reference table", "from the same CSF table");
  let quiet = flow(between(inv, "Zero detections means zero Agent calls.", null));
  quiet = swap(swap(quiet, "Zero detections means zero Agent calls.", "Zero detections means no lens runs."), " Skip LEARN.", "");
  const cards = cardNames().map((name) => {
    const title = read(join(WORKFLOWS, name)).match(/^# (.+)$/m);
    if (!title) throw new Error(`build-portable: ${name} has no title`);
    return `| \`references/${name}\` | ${title[1]} |`;
  });
  return reflow(fill(template("casa-soc-triage.md"), {
    "intake-versions": versions,
    threading: flow(between(inv, "Group, don't itemize.", "Pick the workflow card from")),
    "technique-table": techniqueTable(inv),
    "card-table": ["| Card | Covers |", "|---|---|", ...cards].join("\n"),
    "lens-log": lens("log-analyst"),
    "lens-network": lens("network-analyst"),
    "lens-endpoint": lens("endpoint-analyst"),
    "token-kinds": listed(KINDS.map((k) => KIND_RULES[k].plural)),
    "strip-rule": strip,
    "rubric-check": rubric,
    disagreement,
    "respond-rule": respond,
    "thread-order": flow(between(inv, "Order threads by severity;", "Each `contain` option is a")),
    "quiet-branch": quiet,
    "repo-url": REPO_URL,
    version: pluginVersion(),
  }));
}

function evidenceBody(): string {
  const rows = KINDS.map((k) => `| ${KIND_RULES[k].label} | \`${k}\` | ${KIND_RULES[k].rule} |`);
  return reflow(fill(template("casa-evidence-check.md"), {
    "kinds-table": ["| Value | Lint kind | Traces when |", "|---|---|---|", ...rows].join("\n"),
    "repo-url": REPO_URL,
    version: pluginVersion(),
  }));
}

const SKILLS: Skill[] = [
  {
    name: "casa-soc-standards",
    description:
      "Rules for analysing security alerts without inventing anything: every host, address, rule, event, technique and time must trace to the input; a three-level confidence rubric; MITRE ATT&CK and NIST CSF 2.0 IDs taken only from the bundled tables; recommendations written as options with trade-offs. Use when triaging security alerts, writing an incident note or analyst brief, mapping findings to ATT&CK or NIST CSF, or reviewing AI-written security analysis.",
    body: standardsBody,
    files: () => ({
      "references/attack-techniques.json": read(join(STANDARDS_REFS, "attack-techniques.json")),
      "references/csf-2.0.json": read(join(STANDARDS_REFS, "csf-2.0.json")),
      "references/nist-citations.md": nistCitations(),
    }),
  },
  {
    name: "casa-soc-triage",
    description:
      "Single-agent SOC alert triage: threads detections into chains, reads each chain through log, network, endpoint and threat intelligence lenses, checks every cited value against the input, maps to NIST CSF 2.0 and MITRE ATT&CK, and writes one analyst brief with confidence levels, alternatives, data requests and options. Use when given SIEM alerts, a Wazuh, Sysmon or Suricata alert digest, or a soc-intake JSON file to investigate. It proposes and never acts.",
    compatibility: "Needs the casa-soc-standards skill from the same pack installed alongside it.",
    body: triageBody,
    files: () => ({
      "references/brief-template.md": briefTemplate(),
      ...Object.fromEntries(cardNames().map((name) => [`references/${name}`, card(read(join(WORKFLOWS, name)), name)])),
    }),
  },
  {
    name: "casa-evidence-check",
    description:
      "Checks a security brief, finding or incident note against the alerts it was written from: every rule ID, host, address, user, event ID, port, domain, hash, technique ID and timestamp must appear in the input or in a reference table. Use when reviewing AI-written security analysis for invented details, before sending a SOC brief, or after editing one.",
    compatibility: "Needs the casa-soc-standards skill from the same pack for the ATT&CK and NIST CSF tables.",
    body: evidenceBody,
    files: () => ({ "references/lint-references.json": read(join(STANDARDS_REFS, "lint-references.json")) }),
  },
];

// *--- Core Logic ---*

/** The frontmatter of one skill: the standard fields only, every string double-quoted. */
function frontmatter(skill: Skill): string {
  const lines = ["---", `name: ${skill.name}`, `description: ${JSON.stringify(skill.description)}`, "license: MIT"];
  if (skill.compatibility) lines.push(`compatibility: ${JSON.stringify(skill.compatibility)}`);
  lines.push("metadata:", `  author: ${JSON.stringify("ktalons")}`, `  version: ${JSON.stringify(pluginVersion())}`, `  source: ${JSON.stringify(REPO_URL)}`, "---");
  return lines.join("\n");
}

/** Every file of the pack, by its path under portable/. */
export function build(): Map<string, string> {
  const out = new Map<string, string>();
  const license = read("LICENSE");
  for (const skill of SKILLS) {
    out.set(`${skill.name}/SKILL.md`, `${frontmatter(skill)}\n\n${skill.body().trim()}\n`);
    out.set(`${skill.name}/LICENSE`, license);
    for (const [path, text] of Object.entries(skill.files())) out.set(`${skill.name}/${path}`, text);
  }
  const rows = SKILLS.map((s) => `| \`${s.name}\` | ${s.description.split(". Use when")[0]}. |`);
  const table = ["| Skill | What it gives an agent |", "|---|---|", ...rows].join("\n");
  out.set("README.md", `${reflow(fill(template("README.md"), { "skill-table": table, "repo-url": REPO_URL, version: pluginVersion() })).trim()}\n`);
  return out;
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

/** The paths where portable/ on disk and the build disagree, each with what is wrong. */
export function drift(built: Map<string, string>, disk: Map<string, string>): string[] {
  const out: string[] = [];
  for (const [path, text] of built) {
    if (!disk.has(path)) out.push(`${path}: missing`);
    else if (disk.get(path) !== text) out.push(`${path}: differs from its sources`);
  }
  for (const path of disk.keys()) if (!built.has(path)) out.push(`${path}: not generated by the build`);
  return out.sort();
}

// *--- Entry Point ---*

if (import.meta.main) {
  const built = build();
  if (process.argv.includes("--check")) {
    const wrong = drift(built, onDisk());
    if (wrong.length) {
      console.error(`✗ portable/ is out of date; run bun scripts/build-portable.ts\n${wrong.map((w) => `    ${w}`).join("\n")}`);
      process.exit(1);
    }
    console.log(`✓ portable/ matches its sources (${built.size} files)`);
  } else {
    // portable/ holds generated files only, so it is rebuilt whole.
    rmSync(PORTABLE_DIR, { recursive: true, force: true });
    for (const [path, text] of built) {
      mkdirSync(dirname(join(PORTABLE_DIR, path)), { recursive: true });
      writeFileSync(join(PORTABLE_DIR, path), text);
    }
    console.log(`✓ wrote ${built.size} files under portable/`);
  }
}
