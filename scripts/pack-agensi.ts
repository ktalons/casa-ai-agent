#!/usr/bin/env bun
// *****************************************************************************
// *Title: Agensi Pack Builder*
// *Author: Kyle*
// *Description: Writes the pack's upload ZIP and checks a listing draft.*
// *****************************************************************************

/**
 *   bun scripts/pack-agensi.ts                          write dist/casa-soc-pack-<version>.zip
 *   bun scripts/pack-agensi.ts --check-listing <file>   check a listing draft against the form's limits
 *
 * Agensi takes one ZIP and treats two or more SKILL.md files in it as one skill pack
 * (agensi.io/docs/packaging, read 2026-11-22). The archive is built from what
 * build-portable.ts generates, never from portable/ on disk, so it cannot carry a stray file.
 * Entries are stored without compression, in name order, with one fixed timestamp: the same
 * tree always gives the same bytes, and the printed SHA-256 names exactly what was uploaded.
 */

// *--- Imports ---*

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { build } from "./build-portable.ts";

// *--- Configuration ---*

const ROOT = join(import.meta.dir, "..");
const DIST = join(ROOT, "dist");

// Agensi's limits for a website upload.
const MAX_FILES = 1000;
const MAX_BYTES = 50 * 1024 * 1024;
const MAX_SKILLS = 50;
const REFUSED_TYPES = ["exe", "dll", "so", "dylib", "bin", "app", "dmg", "msi", "deb", "rpm", "wasm", "class", "jar", "war"];
const DEPENDENCY_FOLDERS = ["node_modules", "site-packages", ".venv", "venv", "__pycache__", ".git", "__MACOSX"];

// The submit form's limits (agensi.io/docs/submit-on-the-website, read 2026-11-22).
const MAX_NAME = 60;
const MAX_SUMMARY = 300;
const MAX_CATEGORIES = 3;
const MIN_EXAMPLE = 700;
const REQUIRED_FIELDS = ["Name", "Summary", "Description", "Categories", "See it in action"];

// Outside checkouts a listing may not name or link to.
const CHECKOUTS: [string, RegExp][] = [
  ["Gumroad", /\bgumroad\b/i],
  ["Whop", /\bwhop(\.com)?\b/i],
  ["Lemon Squeezy", /\blemon ?squeezy\b/i],
  ["Payhip", /\bpayhip\b/i],
  ["Ko-fi", /\bko-fi\b/i],
  ["Patreon", /\bpatreon\b/i],
  ["Stripe payment link", /\bbuy\.stripe\.com\b|\bstripe payment links?\b/i],
];

// 1980-01-01 00:00:00, the earliest date the ZIP format can hold.
const DOS_TIME = 0;
const DOS_DATE = (1 << 5) | 1;
// Bit 11: entry names are UTF-8.
const FLAGS = 0x0800;
const VERSION_NEEDED = 20;
// Made on Unix, so the external attributes carry a file mode.
const VERSION_MADE_BY = (3 << 8) | VERSION_NEEDED;
const FILE_MODE = 0o100644 << 16;

// *--- Helper Functions ---*

const encode = (s: string): Uint8Array => new TextEncoder().encode(s);
const decode = (b: Uint8Array): string => new TextDecoder().decode(b);

/** A little-endian record built from [value, byte width] pairs. */
function record(fields: [number, 2 | 4][]): Uint8Array {
  const out = new Uint8Array(fields.reduce((n, [, w]) => n + w, 0));
  const view = new DataView(out.buffer);
  let at = 0;
  for (const [value, width] of fields) {
    if (width === 2) view.setUint16(at, value, true);
    else view.setUint32(at, value >>> 0, true);
    at += width;
  }
  return out;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

// *--- The archive ---*

/** The generated pack as archive entries: path to bytes. */
export function packEntries(): Map<string, Uint8Array> {
  const out = new Map<string, Uint8Array>();
  for (const [path, text] of build()) out.set(path, encode(text));
  return out;
}

/** A ZIP of the entries: stored, sorted by name, one fixed timestamp. */
export function zip(entries: Map<string, Uint8Array>): Uint8Array {
  const local: Uint8Array[] = [];
  const central: Uint8Array[] = [];
  let offset = 0;
  for (const path of [...entries.keys()].sort()) {
    const data = entries.get(path) ?? new Uint8Array();
    const name = encode(path);
    const crc = Bun.hash.crc32(data);
    const shared: [number, 2 | 4][] = [[VERSION_NEEDED, 2], [FLAGS, 2], [0, 2], [DOS_TIME, 2], [DOS_DATE, 2], [crc, 4], [data.length, 4], [data.length, 4], [name.length, 2], [0, 2]];
    const header = concat([record([[0x04034b50, 4], ...shared]), name]);
    local.push(header, data);
    central.push(record([[0x02014b50, 4], [VERSION_MADE_BY, 2], ...shared, [0, 2], [0, 2], [0, 2], [FILE_MODE, 4], [offset, 4]]), name);
    offset += header.length + data.length;
  }
  const directory = concat(central);
  const end = record([[0x06054b50, 4], [0, 2], [0, 2], [entries.size, 2], [entries.size, 2], [directory.length, 4], [offset, 4], [0, 2]]);
  return concat([...local, directory, end]);
}

// *--- Checks ---*

/** The outside checkouts a text names. */
export function checkoutNames(text: string): string[] {
  return CHECKOUTS.filter(([, pattern]) => pattern.test(text)).map(([name]) => name);
}

/** What in a package Agensi's packaging rules refuse. Empty when it passes. */
export function checkPackage(entries: Map<string, Uint8Array>, limits: { maxBytes?: number } = {}): string[] {
  const out: string[] = [];
  const maxBytes = limits.maxBytes ?? MAX_BYTES;
  const skills = [...entries.keys()].filter((p) => p === "SKILL.md" || p.endsWith("/SKILL.md"));
  if (skills.length === 0) out.push("package: no SKILL.md");
  if (skills.length > MAX_SKILLS) out.push(`package: ${skills.length} skills, over the limit of ${MAX_SKILLS}`);
  if (entries.size > MAX_FILES) out.push(`package: ${entries.size} files, over the limit of ${MAX_FILES}`);
  for (const path of skills) {
    const front = decode(entries.get(path) ?? new Uint8Array()).match(/^---\n([\s\S]*?)\n---(\n|$)/)?.[1];
    if (front === undefined) {
      out.push(`${path}: no frontmatter`);
      continue;
    }
    for (const field of ["name", "description"]) if (!new RegExp(`^${field}:\\s*\\S`, "m").test(front)) out.push(`${path}: no \`${field}\``);
  }
  for (const path of entries.keys()) {
    const parts = path.split("/");
    const file = parts[parts.length - 1] ?? "";
    const type = file.includes(".") ? (file.split(".").pop() ?? "").toLowerCase() : "";
    if (REFUSED_TYPES.includes(type)) out.push(`${path}: file type .${type} is refused`);
    const folder = parts.slice(0, -1).find((p) => DEPENDENCY_FOLDERS.includes(p));
    if (folder) out.push(`${path}: inside ${folder}, which is not allowed`);
    if (file === ".DS_Store" || file.startsWith("._")) out.push(`${path}: an operating-system file`);
  }
  const packed = zip(entries).length;
  if (packed > maxBytes) out.push(`package: ${packed} bytes, over the limit of ${maxBytes}`);
  return out;
}

/** Where a listing draft breaks the submit form's limits. The draft is Markdown with one `## Field` heading per form field. */
export function checkListing(markdown: string): string[] {
  const out: string[] = [];
  const fields = new Map<string, string>();
  for (const part of markdown.split(/^## /m).slice(1)) {
    const at = part.indexOf("\n");
    fields.set(part.slice(0, at === -1 ? part.length : at).trim(), at === -1 ? "" : part.slice(at + 1).trim());
  }
  for (const field of REQUIRED_FIELDS) if (!fields.get(field)) out.push(`${field}: missing`);
  const length = (field: string): number => [...(fields.get(field) ?? "")].length;
  if (length("Name") > MAX_NAME) out.push(`Name: ${length("Name")} characters, over the limit of ${MAX_NAME}`);
  if (length("Summary") > MAX_SUMMARY) out.push(`Summary: ${length("Summary")} characters, over the limit of ${MAX_SUMMARY}`);
  const categories = (fields.get("Categories") ?? "").split("\n").filter((l) => /^[-*] /.test(l)).length;
  if (categories > MAX_CATEGORIES) out.push(`Categories: ${categories}, over the limit of ${MAX_CATEGORIES}`);
  if (fields.get("See it in action") && length("See it in action") < MIN_EXAMPLE) out.push(`See it in action: ${length("See it in action")} characters, under the ${MIN_EXAMPLE} the form asks for`);
  if (markdown.includes("—")) out.push("draft: contains an em dash");
  const named = checkoutNames(markdown);
  if (named.length) out.push(`draft: names an outside checkout (${named.join(", ")})`);
  return out;
}

// *--- Entry Point ---*

if (import.meta.main) {
  const at = process.argv.indexOf("--check-listing");
  if (at !== -1) {
    const file = process.argv[at + 1];
    if (!file) {
      console.error("usage: bun scripts/pack-agensi.ts --check-listing <file>");
      process.exit(2);
    }
    const wrong = checkListing(readFileSync(file, "utf8"));
    if (wrong.length) {
      console.error(`✗ ${file}\n${wrong.map((w) => `    ${w}`).join("\n")}`);
      process.exit(1);
    }
    console.log(`✓ ${file} fits the submit form`);
  } else {
    const entries = packEntries();
    const wrong = [...checkPackage(entries), ...[...entries].flatMap(([path, data]) => checkoutNames(decode(data)).map((n) => `${path}: names ${n}`))];
    if (wrong.length) {
      console.error(`✗ the pack breaks Agensi's packaging rules\n${wrong.map((w) => `    ${w}`).join("\n")}`);
      process.exit(1);
    }
    const version = (JSON.parse(readFileSync(join(ROOT, ".claude-plugin", "plugin.json"), "utf8")) as { version: string }).version;
    const archive = zip(entries);
    const file = join(DIST, `casa-soc-pack-${version}.zip`);
    mkdirSync(DIST, { recursive: true });
    writeFileSync(file, archive);
    console.log(`✓ wrote ${file}`);
    console.log(`    ${entries.size} files, ${archive.length} bytes`);
    console.log(`    sha256 ${createHash("sha256").update(archive).digest("hex")}`);
  }
}
