// *****************************************************************************
// *Title: Eval Contamination Guard*
// *Author: Kyle*
// *Description: Fails when investigation prompt text carries fixture answers.*
// *****************************************************************************

// *--- Imports ---*

import { test, expect } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";

// *--- Configuration ---*

const ROOT = join(import.meta.dir, "..", "..");
const FIXTURES_DIR = join(ROOT, "intake", "fixtures");

// The grading path (the evaluate skill and the evaluator agent) must name fixtures to do its
// job. Everything else under skills/ and agents/ is text the investigate path can read.
const GRADING_PATH = new Set([join("skills", "evaluate"), join("agents", "evaluator.md")]);

// Six words is long enough that ordinary security prose does not collide by chance, and short
// enough to catch a clause lifted from a rule description.
const SHINGLE_WORDS = 6;

// *--- Types ---*

interface Corpus {
  names: Set<string>;
  shingles: Map<string, string>;
  tokens: Set<string>;
}

// *--- Helper Functions ---*

/** Lowercase word list with punctuation folded to spaces. */
function words(text: string): string[] {
  return text.toLowerCase().replace(/[^a-z0-9>=<]+/g, " ").trim().split(/\s+/).filter(Boolean);
}

/**
 * Every Markdown or JSON file the investigate path can load (the reference tables are JSON);
 * with the grading path, every prompt file.
 */
function promptFiles(withGradingPath = false): string[] {
  const out: string[] = [];
  const walk = (dir: string): void => {
    for (const e of readdirSync(join(ROOT, dir), { withFileTypes: true })) {
      const rel = join(dir, e.name);
      if (!withGradingPath && GRADING_PATH.has(rel)) continue;
      if (e.isDirectory()) walk(rel);
      else if (e.name.endsWith(".md") || e.name.endsWith(".json")) out.push(rel);
    }
  };
  walk("skills");
  walk("agents");
  return out.sort();
}

/** Fixture names, rule-description shingles and identifying tokens, read from the fixtures. */
function loadCorpus(): Corpus {
  const names = new Set<string>();
  const shingles = new Map<string, string>();
  const tokens = new Set<string>();
  for (const file of readdirSync(FIXTURES_DIR)) {
    names.add(file.split(".")[0]);
    if (!file.endsWith(".intake.json")) continue;
    const intake = JSON.parse(readFileSync(join(FIXTURES_DIR, file), "utf8")) as {
      detections?: Array<Record<string, unknown>>;
      recon_delta?: unknown;
    };
    for (const d of intake.detections ?? []) {
      if (typeof d.description === "string") {
        const w = words(d.description);
        const n = Math.min(SHINGLE_WORDS, w.length);
        for (let i = 0; i + n <= w.length; i++) shingles.set(w.slice(i, i + n).join(" "), d.description);
      }
      for (const key of ["rule_id", "agent", "src_ip", "dst_ip", "user", "alert_id"]) {
        if (typeof d[key] === "string" && d[key] !== "") tokens.add((d[key] as string).toLowerCase());
      }
    }
    const recon = intake.recon_delta;
    if (recon && typeof recon === "object" && Array.isArray((recon as { changes?: unknown }).changes)) {
      for (const c of (recon as { changes: Array<{ host?: unknown }> }).changes) {
        if (typeof c.host === "string") tokens.add(c.host.toLowerCase());
      }
    }
  }
  return { names, shingles, tokens };
}

/** Six-word shingles of one free-text value, keyed back to the value. */
function addShingles(shingles: Map<string, string>, text: string): void {
  const w = words(text);
  const n = Math.min(SHINGLE_WORDS, w.length);
  for (let i = 0; i + n <= w.length; i++) shingles.set(w.slice(i, i + n).join(" "), text);
}

/**
 * The held-out corpus (ISC-26) reads more than the authoring one: v3 user fields, engine rule
 * IDs, every identifying string in the typed Sysmon and Suricata groups (anything with a digit,
 * a path separator or a dotted name), and six-word phrases of every string of five words or
 * more, whatever its key, so no clause of a held-out story can sit in prompt text.
 */
function loadHeldOutCorpus(): Corpus {
  const sets = JSON.parse(readFileSync(join(ROOT, "evals", "fixture-sets.json"), "utf8")) as { fixtures: Record<string, { set: string }> };
  const heldOut = new Set(Object.entries(sets.fixtures).filter(([, e]) => e.set === "held-out").map(([n]) => n));
  const corpus: Corpus = { names: new Set(heldOut), shingles: new Map(), tokens: new Set() };
  const FREE_TEXT = /^(description|command_line|commandline|parent_command_line|signature|markdown|details)$/i;
  const identifying = (v: string) => /\d|[\\/]|[a-z0-9-]\.[a-z]{2,}/i.test(v) && v.length >= 4;
  // A Windows system path names a stock binary, which any card may cite; it is not story.
  const OS_PATH = /^"?c:\\windows\\/i;
  // Event IDs, logon types, protocols, ports and clock times are shared vocabulary every card may
  // name; they say nothing about which held-out story is which.
  const SHARED = /^(event_id|logon_type|proto|protocol|app_proto|[a-z_]*port|[a-z_]*time|timestamp)$/i;
  const visit = (value: unknown, key: string): void => {
    if (SHARED.test(key)) return;
    if (typeof value === "string") {
      const v = value.trim();
      if (OS_PATH.test(v)) return;
      // NOTE: a phrase under five words ("sc.exe stop Sysmon64") is generic technique prose; words
      // are counted by spaces, so one path is one word, not five.
      if (v.split(/\s+/).length >= 5) addShingles(corpus.shingles, v);
      else if (!FREE_TEXT.test(key) && identifying(v) && !OS_PATH.test(v)) corpus.tokens.add(v.toLowerCase());
    } else if (Array.isArray(value)) for (const v of value) visit(v, key);
    else if (value && typeof value === "object") for (const [k, v] of Object.entries(value)) visit(v, k);
  };
  for (const file of readdirSync(FIXTURES_DIR)) {
    if (!heldOut.has(file.split(".")[0]) || !file.endsWith(".intake.json")) continue;
    const intake = JSON.parse(readFileSync(join(FIXTURES_DIR, file), "utf8")) as { detections?: unknown[]; recon_delta?: unknown };
    // NOTE: timestamps, levels, tactics and groups are shared vocabulary, not a fixture's material.
    for (const d of intake.detections ?? []) {
      const { timestamp: _t, level: _l, tactic: _ta, groups: _g, mitre: _m, ...rest } = d as Record<string, unknown>;
      visit(rest, "");
    }
    visit(intake.recon_delta, "");
  }
  return corpus;
}

/** Escape every regex metacharacter, backslash included, so a fixture value matches literally. */
function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\-]/g, "\\$&");
}

/** Every way one prompt file leaks fixture material, as readable strings. */
function leaks(text: string, corpus: Corpus, opts: { directory: boolean } = { directory: true }): string[] {
  const found: string[] = [];
  const lower = text.toLowerCase();
  for (const name of corpus.names) {
    if (new RegExp(`(^|[^a-z0-9-])${escapeRegExp(name)}([^a-z0-9-]|$)`).test(lower)) found.push(`fixture name: ${name}`);
  }
  if (opts.directory && lower.includes("intake/fixtures")) found.push("fixture directory: intake/fixtures");
  for (const token of corpus.tokens) {
    if (new RegExp(`(^|[^a-z0-9.])${escapeRegExp(token)}([^a-z0-9]|$)`).test(lower)) found.push(`fixture value: ${token}`);
  }
  const w = words(text);
  const seen = new Set<string>();
  for (const len of new Set([...corpus.shingles.keys()].map((s) => s.split(" ").length))) {
    for (let i = 0; i + len <= w.length; i++) {
      const gram = w.slice(i, i + len).join(" ");
      const source = corpus.shingles.get(gram);
      if (source && !seen.has(source)) {
        seen.add(source);
        found.push(`rule description: "${gram}" from "${source}"`);
      }
    }
  }
  return found;
}

// *--- Tests ---*

const corpus = loadCorpus();
const files = promptFiles();

test("authoring: the fixture corpus and the prompt files load", () => {
  expect(corpus.names.size).toBeGreaterThan(0);
  expect(corpus.shingles.size).toBeGreaterThan(0);
  expect(corpus.tokens.size).toBeGreaterThan(0);
  expect(files).toContain(join("skills", "investigate", "SKILL.md"));
  expect(files).toContain(join("skills", "standards", "references", "lessons.md"));
  expect(files.some((f) => f.startsWith(join("skills", "investigate", "references", "workflows")))).toBe(true);
});

test("authoring: the detector catches a lifted clause, a fixture name and a fixture host", () => {
  const [gram] = corpus.shingles.keys();
  const [name] = corpus.names;
  const [token] = corpus.tokens;
  expect(leaks(`a rule that says ${gram} here`, corpus).length).toBe(1);
  expect(leaks(`see the ${name} case`, corpus).length).toBe(1);
  expect(leaks(`on ${token} today`, corpus).length).toBe(1);
  expect(leaks("a burst of failed logons that ends in a success", corpus)).toEqual([]);
});

for (const file of files) {
  test(`authoring: ${relative(".", file)} names no fixture and quotes no fixture rule text`, () => {
    expect(leaks(readFileSync(join(ROOT, file), "utf8"), corpus)).toEqual([]);
  });
}

// *--- Held-out set (ISC-26) ---*

const heldOut = loadHeldOutCorpus();
const everyPromptFile = promptFiles(true);

test("held-out: the held-out corpus loads and the detector catches its name, values and clauses", () => {
  expect(heldOut.names.size).toBeGreaterThan(0);
  expect(heldOut.tokens.size).toBeGreaterThan(0);
  expect(heldOut.shingles.size).toBeGreaterThan(0);
  expect(everyPromptFile).toContain(join("skills", "evaluate", "SKILL.md"));
  expect(everyPromptFile).toContain(join("agents", "evaluator.md"));
  // Every name, value and phrase, so a value with backslashes, quotes or dots is proven to match.
  const missed = (items: Iterable<string>, wrap: (s: string) => string) =>
    [...items].filter((s) => leaks(wrap(s), heldOut, { directory: false }).length === 0);
  expect(missed(heldOut.names, (n) => `grade the ${n} fixture`)).toEqual([]);
  expect(missed(heldOut.tokens, (t) => `look at ${t} first`)).toEqual([]);
  expect(missed(heldOut.shingles.keys(), (g) => `a card that says ${g} here`)).toEqual([]);
  expect(leaks("cite C:\\Windows\\System32\\cmd.exe and run sc.exe stop on the service", heldOut, { directory: false })).toEqual([]);
});

for (const file of everyPromptFile) {
  test(`held-out: ${relative(".", file)} names no held-out fixture and quotes none of its material`, () => {
    expect(leaks(readFileSync(join(ROOT, file), "utf8"), heldOut, { directory: false })).toEqual([]);
  });
}
