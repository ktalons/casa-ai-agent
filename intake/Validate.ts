#!/usr/bin/env bun
/**
 * Validate.ts — validator for talonsoclab.soc-intake artifacts (v1, v2 and v3).
 *
 * Two passes, zero dependencies:
 *   1. the JSON Schema in schema/soc-intake.<v>.schema.json, evaluated by lib/schema.ts, which
 *      supports exactly the keywords the schemas use and throws on anything else;
 *   2. the semantic rules in lib/semantic.ts (real instants, newest-first, level floor, cap and
 *      truncation agreement, duplicates, window containment; for v3 also the include list,
 *      per-day counts, and engine and typed-group agreement).
 *
 * Usage:
 *   bun intake/Validate.ts                 # validate every fixtures/*.intake.json
 *   bun intake/Validate.ts path.json ...   # validate specific intake files
 *
 * Each accepted file is followed by a `sha256` line: the hash of the file as read, which is the
 * value a brief records as `intake.sha256` and the lint checks it against.
 *
 * Exit codes: 0 all valid, 1 any violation or unreadable file. Warnings never fail.
 */
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { validateAgainstSchema, type Schema } from "./lib/schema.ts";
import { semanticV1, semanticV2, semanticV3, type IntakeV1, type IntakeV2, type IntakeV3, type SemanticResult } from "./lib/semantic.ts";

const INTAKE_DIR = dirname(Bun.fileURLToPath(import.meta.url));
// validateIntake runs the schema pass first, so each semantic check gets a document that
// already has its version's shape; the cast below states that and nothing more.
const VERSIONS: Record<string, { schema: string; semantic: (doc: unknown) => SemanticResult }> = {
  "talonsoclab.soc-intake/v1": { schema: "soc-intake.v1.schema.json", semantic: (doc) => semanticV1(doc as IntakeV1) },
  "talonsoclab.soc-intake/v2": { schema: "soc-intake.v2.schema.json", semantic: (doc) => semanticV2(doc as IntakeV2) },
  "talonsoclab.soc-intake/v3": { schema: "soc-intake.v3.schema.json", semantic: (doc) => semanticV3(doc as IntakeV3) },
};
const schemaCache = new Map<string, Schema>();
function loadSchema(file: string): Schema {
  const cached = schemaCache.get(file);
  if (cached) return cached;
  const schema = JSON.parse(readFileSync(join(INTAKE_DIR, "schema", file), "utf8")) as Schema;
  schemaCache.set(file, schema);
  return schema;
}

export function validateIntake(doc: unknown): { errors: string[]; warnings: string[] } {
  const errors: string[] = [], warnings: string[] = [];
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) return { errors: ["root: not a JSON object"], warnings };
  const id = String((doc as { schema?: unknown }).schema);
  const version = Object.hasOwn(VERSIONS, id) ? VERSIONS[id] : undefined;
  if (!version) return { errors: [`schema: expected one of ${Object.keys(VERSIONS).join(", ")}, got ${JSON.stringify((doc as { schema?: unknown }).schema)}`], warnings };
  for (const e of validateAgainstSchema(doc, loadSchema(version.schema))) errors.push(`${e.path}: ${e.message}`);
  if (errors.length) return { errors, warnings };
  const s = version.semantic(doc);
  return { errors: s.errors, warnings: s.warnings };
}

if (import.meta.main) {
  let targets = process.argv.slice(2);
  if (targets.length === 0) {
    const dir = join(INTAKE_DIR, "fixtures");
    targets = readdirSync(dir).filter((f) => f.endsWith(".intake.json")).sort().map((f) => join(dir, f));
  }
  if (targets.length === 0) { console.error("no intake files found to validate"); process.exit(1); }
  let failed = 0;
  for (const target of targets) {
    let result: { errors: string[]; warnings: string[] };
    let sha256 = "";
    try {
      const raw = readFileSync(target);
      sha256 = createHash("sha256").update(raw).digest("hex");
      result = validateIntake(JSON.parse(raw.toString("utf8")));
    }
    catch (err) { result = { errors: [`unreadable or invalid JSON: ${err instanceof Error ? err.message : String(err)}`], warnings: [] }; }
    if (result.errors.length === 0) {
      console.log(`✓ ${target}`);
      console.log(`    sha256 ${sha256}`);
      for (const w of result.warnings) console.log(`    ! ${w}`);
    } else {
      failed++;
      console.error(`✗ ${target}`);
      for (const e of result.errors) console.error(`    ${e}`);
    }
  }
  if (failed > 0) { console.error(`\n${failed} file(s) failed validation`); process.exit(1); }
}
