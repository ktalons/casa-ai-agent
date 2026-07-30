#!/usr/bin/env bun
/**
 * Validate.ts — structural validator for talonsoclab.soc-intake/v1 artifacts.
 *
 * Zero dependencies on purpose: this is the enforcement layer for the
 * cross-repo contract, so its supply chain stays empty. The JSON Schema in
 * schema/soc-intake.v1.schema.json documents the same rules for humans and
 * other tooling; if you change one, change both (v1 is frozen — changes mean
 * a v2 schema and new fixtures).
 *
 * Usage:
 *   bun intake/Validate.ts                 # validate every fixtures/*.intake.json
 *   bun intake/Validate.ts path.json ...   # validate specific intake files
 *
 * Exit codes: 0 all valid, 1 any violation or unreadable file.
 */

import { readdirSync } from 'fs';
import { join, dirname } from 'path';

const INTAKE_DIR = dirname(Bun.fileURLToPath(import.meta.url));
const SCHEMA_CONST = 'talonsoclab.soc-intake/v1';
const DETECTION_KEYS = ['level', 'description', 'rule_id', 'agent', 'mitre', 'timestamp'] as const;
const TOP_KEYS = ['schema', 'generated', 'source', 'consumer', 'detections', 'recon_delta', 'note'] as const;
const MITRE_RE = /^T\d{4}(\.\d{3})?$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

function validateIntake(doc: unknown, errors: string[]): void {
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
    errors.push('root: not a JSON object');
    return;
  }
  const obj = doc as Record<string, unknown>;

  for (const key of TOP_KEYS) {
    if (!(key in obj)) errors.push(`root: missing required field "${key}"`);
  }
  for (const key of Object.keys(obj)) {
    if (!(TOP_KEYS as readonly string[]).includes(key)) {
      errors.push(`root: unexpected field "${key}" (v1 is frozen — new fields mean a v2 schema)`);
    }
  }

  if (obj.schema !== SCHEMA_CONST) errors.push(`schema: expected "${SCHEMA_CONST}", got ${JSON.stringify(obj.schema)}`);
  if (typeof obj.generated !== 'string' || !DATE_RE.test(obj.generated)) {
    errors.push(`generated: expected "YYYY-MM-DD" string, got ${JSON.stringify(obj.generated)}`);
  }
  for (const key of ['source', 'consumer', 'recon_delta', 'note'] as const) {
    if (typeof obj[key] !== 'string') errors.push(`${key}: expected string, got ${typeof obj[key]}`);
  }

  if (!Array.isArray(obj.detections)) {
    errors.push(`detections: expected array, got ${typeof obj.detections}`);
    return;
  }
  obj.detections.forEach((det, i) => {
    const where = `detections[${i}]`;
    if (typeof det !== 'object' || det === null || Array.isArray(det)) {
      errors.push(`${where}: not an object`);
      return;
    }
    const d = det as Record<string, unknown>;
    for (const key of DETECTION_KEYS) {
      if (!(key in d)) errors.push(`${where}: missing required field "${key}"`);
    }
    for (const key of Object.keys(d)) {
      if (!(DETECTION_KEYS as readonly string[]).includes(key)) errors.push(`${where}: unexpected field "${key}"`);
    }
    if (typeof d.level !== 'number' || !Number.isInteger(d.level) || d.level < 0 || d.level > 16) {
      errors.push(`${where}.level: expected integer 0-16, got ${JSON.stringify(d.level)}`);
    }
    for (const key of ['description', 'rule_id', 'agent', 'timestamp'] as const) {
      if (typeof d[key] !== 'string' || (d[key] as string).length === 0) {
        errors.push(`${where}.${key}: expected non-empty string, got ${JSON.stringify(d[key])}`);
      }
    }
    if (!Array.isArray(d.mitre)) {
      errors.push(`${where}.mitre: expected array, got ${typeof d.mitre}`);
    } else {
      d.mitre.forEach((id, j) => {
        if (typeof id !== 'string' || !MITRE_RE.test(id)) {
          errors.push(`${where}.mitre[${j}]: not a MITRE ATT&CK technique id: ${JSON.stringify(id)}`);
        }
      });
    }
  });
}

async function main(): Promise<void> {
  let targets = process.argv.slice(2);
  if (targets.length === 0) {
    const fixturesDir = join(INTAKE_DIR, 'fixtures');
    targets = readdirSync(fixturesDir)
      .filter((f) => f.endsWith('.intake.json'))
      .sort()
      .map((f) => join(fixturesDir, f));
  }
  if (targets.length === 0) {
    console.error('no intake files found to validate');
    process.exit(1);
  }

  let failed = 0;
  for (const target of targets) {
    const errors: string[] = [];
    try {
      const doc = JSON.parse(await Bun.file(target).text());
      validateIntake(doc, errors);
    } catch (err) {
      errors.push(`unreadable or invalid JSON: ${err instanceof Error ? err.message : String(err)}`);
    }
    if (errors.length === 0) {
      console.log(`✓ ${target}`);
    } else {
      failed++;
      console.error(`✗ ${target}`);
      for (const e of errors) console.error(`    ${e}`);
    }
  }

  if (failed > 0) {
    console.error(`\n${failed} file(s) failed validation`);
    process.exit(1);
  }
}

main();
