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

/** Every Markdown file the investigate path can load. */
function promptFiles(): string[] {
  const out: string[] = [];
  const walk = (dir: string): void => {
    for (const e of readdirSync(join(ROOT, dir), { withFileTypes: true })) {
      const rel = join(dir, e.name);
      if (GRADING_PATH.has(rel)) continue;
      if (e.isDirectory()) walk(rel);
      else if (e.name.endsWith(".md")) out.push(rel);
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

/** Every way one prompt file leaks fixture material, as readable strings. */
function leaks(text: string, corpus: Corpus): string[] {
  const found: string[] = [];
  const lower = text.toLowerCase();
  for (const name of corpus.names) {
    if (new RegExp(`(^|[^a-z0-9-])${name.replace(/[-.]/g, "\\$&")}([^a-z0-9-]|$)`).test(lower)) found.push(`fixture name: ${name}`);
  }
  if (lower.includes("intake/fixtures")) found.push("fixture directory: intake/fixtures");
  for (const token of corpus.tokens) {
    if (new RegExp(`(^|[^a-z0-9.])${token.replace(/[.]/g, "\\.")}([^a-z0-9]|$)`).test(lower)) found.push(`fixture value: ${token}`);
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
