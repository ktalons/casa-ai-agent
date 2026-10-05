/**
 * semantic.ts — the rules a JSON Schema cannot express: timestamps that are real instants,
 * ordering, severity floor, cap and truncation agreement, duplicates, window containment.
 * Pure functions; Validate.ts runs them after the schema pass. Zero dependencies.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

export interface SemanticResult { errors: string[]; warnings: string[] }

const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const V1_FLOOR = 12, V1_CAP = 200;

/** A real UTC instant: matches the ISO shape and survives a Date round-trip (kills Feb 30). */
export function isRealInstant(ts: string): boolean {
  if (!ISO_RE.test(ts)) return false;
  const d = new Date(ts);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 19) === ts.slice(0, 19);
}
export function isRealDate(day: string): boolean {
  if (!DATE_RE.test(day)) return false;
  const d = new Date(day + "T00:00:00Z");
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === day;
}

let attackIds: Set<string> | null = null;
function knownTechniques(): Set<string> {
  if (attackIds) return attackIds;
  try {
    const t = JSON.parse(readFileSync(join(import.meta.dir, "..", "..", "skills", "standards", "references", "attack-techniques.json"), "utf8"));
    attackIds = new Set<string>(t.techniques.map((x: { id: string }) => x.id));
  } catch {
    attackIds = new Set();
  }
  return attackIds;
}

type Det = { level: number; rule_id: string; agent: string; mitre: string[]; timestamp: string; alert_id?: string };

function checkDetections(dets: Det[], floor: number, cap: number, dupKey: (d: Det) => string, r: SemanticResult): void {
  const seen = new Set<string>();
  let prev: number | null = null;
  dets.forEach((d, i) => {
    const where = `detections[${i}]`;
    if (!isRealInstant(d.timestamp)) r.errors.push(`${where}.timestamp: "${d.timestamp}" is not a real UTC instant`);
    else {
      const t = Date.parse(d.timestamp);
      if (prev !== null && t > prev) r.errors.push(`${where}: not newest-first (later than detections[${i - 1}])`);
      prev = t;
    }
    if (d.level < floor) r.errors.push(`${where}.level: ${d.level} is below the level floor ${floor}`);
    const key = dupKey(d);
    if (seen.has(key)) r.errors.push(`${where}: duplicate of an earlier detection (${key})`);
    seen.add(key);
    const known = knownTechniques();
    if (known.size) for (const m of d.mitre) if (!known.has(m)) r.warnings.push(`${where}.mitre: ${m} is not in the ATT&CK reference table`);
  });
  if (dets.length > cap) r.errors.push(`detections: ${dets.length} entries exceeds the cap ${cap}`);
}

export function semanticV1(doc: any): SemanticResult {
  const r: SemanticResult = { errors: [], warnings: [] };
  if (!isRealDate(doc.generated)) r.errors.push(`generated: "${doc.generated}" is not a real date`);
  checkDetections(doc.detections, V1_FLOOR, V1_CAP, (d) => `${d.rule_id}|${d.agent}|${d.timestamp}`, r);
  return r;
}

export function semanticV2(doc: any): SemanticResult {
  const r: SemanticResult = { errors: [], warnings: [] };
  for (const [k, v] of [["generated", doc.generated], ["window.start", doc.window.start], ["window.end", doc.window.end]] as [string, string][]) {
    if (!isRealInstant(v)) r.errors.push(`${k}: "${v}" is not a real UTC instant`);
  }
  if (doc.pipeline.last_event_seen !== null && !isRealInstant(doc.pipeline.last_event_seen)) r.errors.push(`pipeline.last_event_seen: not a real UTC instant`);
  if (doc.recon_delta.baseline !== null && !isRealDate(doc.recon_delta.baseline)) r.errors.push(`recon_delta.baseline: not a real date`);
  if (r.errors.length) return r;

  const start = Date.parse(doc.window.start), end = Date.parse(doc.window.end), gen = Date.parse(doc.generated);
  if (end <= start) r.errors.push(`window: end is not after start`);
  if (gen < end) r.errors.push(`generated: earlier than window.end`);
  const hours = (end - start) / 3_600_000;
  if (Math.abs(hours - doc.window.lookback_hours) > 1) r.warnings.push(`window: spans ${hours.toFixed(1)}h but lookback_hours is ${doc.window.lookback_hours}`);

  checkDetections(doc.detections, doc.filter.min_level, doc.filter.cap, (d) => String(d.alert_id), r);
  doc.detections.forEach((d: Det, i: number) => {
    if (isRealInstant(d.timestamp)) {
      const t = Date.parse(d.timestamp);
      if (t < start || t > end) r.errors.push(`detections[${i}].timestamp: outside window ${doc.window.start}..${doc.window.end}`);
    }
  });
  const atCap = doc.detections.length === doc.filter.cap;
  if (doc.truncated !== atCap) r.errors.push(`truncated: ${doc.truncated} but detections.length (${doc.detections.length}) ${atCap ? "equals" : "is below"} the cap ${doc.filter.cap}`);
  return r;
}
