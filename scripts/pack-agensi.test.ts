// *****************************************************************************
// *Title: Agensi Pack Tests*
// *Author: Kyle*
// *Description: Holds the upload ZIP to the pack sources and Agensi's rules.*
// *****************************************************************************

// *--- Imports ---*

import { test, expect } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build } from "./build-portable.ts";
import { checkListing, checkPackage, checkoutNames, packEntries, zip } from "./pack-agensi.ts";

// *--- Helper Functions ---*

const bytes = (s: string): Uint8Array => new TextEncoder().encode(s);
const sha = (b: Uint8Array): string => createHash("sha256").update(b).digest("hex");
const SKILL = "---\nname: a-skill\ndescription: Does one thing. Use when asked.\n---\n\n# A skill\n";

/** A package of one valid skill plus the given extra entries. */
function pkg(extra: Record<string, string> = {}): Map<string, Uint8Array> {
  const out = new Map<string, Uint8Array>([["a-skill/SKILL.md", bytes(SKILL)]]);
  for (const [path, text] of Object.entries(extra)) out.set(path, bytes(text));
  return out;
}

/** Run unzip on the built archive and return its exit code and output. */
function unzip(args: string[], archive: Uint8Array): { code: number; out: string } {
  const dir = mkdtempSync(join(tmpdir(), "casa-pack-"));
  try {
    const file = join(dir, "pack.zip");
    writeFileSync(file, archive);
    const r = Bun.spawnSync(["unzip", ...args, file], { stdout: "pipe", stderr: "pipe" });
    return { code: r.exitCode, out: r.stdout.toString() };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// *--- ISC-114: the ZIP holds the pack ---*

test("holds: every generated pack file is an entry with its exact bytes, and unzip accepts the archive", () => {
  const built = build();
  const archive = zip(packEntries());
  expect(unzip(["-tq"], archive).code).toBe(0);
  const names = unzip(["-Z1"], archive).out.trim().split("\n").sort();
  expect(names).toEqual([...built.keys()].sort());
  expect(names.filter((n) => n.endsWith("/SKILL.md")).length).toBe(3);
  for (const name of ["casa-soc-triage/SKILL.md", "casa-soc-standards/references/csf-2.0.json"]) {
    expect(unzip(["-p"], archive).code).toBe(0);
    const dir = mkdtempSync(join(tmpdir(), "casa-pack-"));
    try {
      const file = join(dir, "pack.zip");
      writeFileSync(file, archive);
      const got = Bun.spawnSync(["unzip", "-p", file, name], { stdout: "pipe" }).stdout.toString();
      expect(got).toBe(built.get(name) ?? "");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

// *--- ISC-115: the build is reproducible ---*

test("identical: two builds of the same tree are byte-identical, whatever order the entries arrive in", () => {
  const first = zip(packEntries());
  const second = zip(packEntries());
  expect(sha(second)).toBe(sha(first));
  const reversed = new Map([...packEntries()].reverse());
  expect(sha(zip(reversed))).toBe(sha(first));
});

// *--- ISC-116: Agensi's packaging rules (agensi.io/docs/packaging, read 2026-11-22) ---*

test("packaging: the real pack passes, and each rule refuses the case it exists for", () => {
  expect(checkPackage(packEntries())).toEqual([]);
  expect(checkPackage(pkg())).toEqual([]);
  const refused: [string, Map<string, Uint8Array>, RegExp][] = [
    ["no skill at all", new Map([["notes.md", bytes("x")]]), /no SKILL\.md/],
    ["no frontmatter", pkg({ "b/SKILL.md": "# B\n" }), /b\/SKILL\.md: no frontmatter/],
    ["no name", pkg({ "b/SKILL.md": "---\ndescription: d\n---\n" }), /b\/SKILL\.md: no `name`/],
    ["no description", pkg({ "b/SKILL.md": "---\nname: b\n---\n" }), /b\/SKILL\.md: no `description`/],
    ["an executable", pkg({ "a-skill/bin/tool.exe": "MZ" }), /tool\.exe: file type \.exe is refused/],
    ["a jar in capitals", pkg({ "a-skill/lib/X.JAR": "PK" }), /X\.JAR: file type \.jar is refused/],
    ["a dependency folder", pkg({ "a-skill/node_modules/x/index.js": "x" }), /node_modules/],
    ["a virtualenv", pkg({ "a-skill/.venv/pyvenv.cfg": "x" }), /\.venv/],
    ["a git folder", pkg({ "a-skill/.git/HEAD": "x" }), /\.git/],
    ["a Finder file", pkg({ "a-skill/.DS_Store": "x" }), /\.DS_Store/],
    ["a resource fork", pkg({ "a-skill/._SKILL.md": "x" }), /\._SKILL\.md/],
    ["a Mac archive folder", pkg({ "__MACOSX/a-skill/x": "x" }), /__MACOSX/],
  ];
  for (const [label, entries, expected] of refused) expect([label, checkPackage(entries).join("\n")]).toEqual([label, expect.stringMatching(expected)]);
  const many = pkg();
  for (let i = 0; i < 1000; i++) many.set(`a-skill/references/f${i}.md`, bytes("x"));
  expect(checkPackage(many).join("\n")).toMatch(/1001 files, over the limit of 1000/);
  const skills = new Map<string, Uint8Array>();
  for (let i = 0; i < 51; i++) skills.set(`s${i}/SKILL.md`, bytes(SKILL));
  expect(checkPackage(skills).join("\n")).toMatch(/51 skills, over the limit of 50/);
  expect(checkPackage(pkg({ "a-skill/big.md": "" }), { maxBytes: 10 }).join("\n")).toMatch(/bytes, over the limit of 10/);
});

// *--- ISC-117: no outside checkout ---*

test("checkout: the pack names no outside checkout, and the detector sees each one it must", () => {
  for (const [path, data] of packEntries()) expect([path, checkoutNames(new TextDecoder().decode(data))]).toEqual([path, []]);
  const samples = ["get it on Gumroad", "whop.com/x", "Lemon Squeezy store", "lemonsqueezy.com", "payhip.com/b/1", "ko-fi.com/me", "support on Ko-fi", "patreon.com/me", "https://buy.stripe.com/abc", "a Stripe payment link"];
  for (const s of samples) expect([s, checkoutNames(s).length]).toEqual([s, 1]);
  expect(checkoutNames("payouts go through Stripe Connect; whopping results")).toEqual([]);
});

// *--- ISC-118: the listing draft fits the submit form ---*

const LISTING = [
  "# Listing",
  "## Name",
  "CASA SOC Triage Pack",
  "## Summary",
  "Three skills for evidence-first alert triage.",
  "## Description",
  "What it does.",
  "## Categories",
  "- Security",
  "- Operations",
  "## See it in action",
  "x".repeat(700),
].join("\n\n");

test("listing: a draft inside the form's limits passes, and each limit refuses its case", () => {
  expect(checkListing(LISTING)).toEqual([]);
  const withField = (heading: string, body: string): string => LISTING.replace(new RegExp(`(## ${heading}\\n\\n)[^#]*`), `$1${body}\n\n`);
  expect(checkListing(withField("Name", "n".repeat(61))).join("\n")).toMatch(/Name: 61 characters, over the limit of 60/);
  expect(checkListing(withField("Summary", "s".repeat(301))).join("\n")).toMatch(/Summary: 301 characters, over the limit of 300/);
  expect(checkListing(withField("Categories", "- a\n- b\n- c\n- d")).join("\n")).toMatch(/Categories: 4, over the limit of 3/);
  expect(checkListing(withField("See it in action", "short")).join("\n")).toMatch(/See it in action: 5 characters, under the 700/);
  expect(checkListing(withField("Description", "Good — very good.")).join("\n")).toMatch(/em dash/);
  expect(checkListing(withField("Description", "Also on Gumroad.")).join("\n")).toMatch(/outside checkout/);
  expect(checkListing(LISTING.replace("## Summary", "## Tagline")).join("\n")).toMatch(/Summary: missing/);
});
