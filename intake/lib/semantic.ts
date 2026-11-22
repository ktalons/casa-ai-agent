/**
 * semantic.ts — the rules a JSON Schema cannot express: timestamps that are real instants,
 * ordering, severity floor (an error for v2 and v3, a warning for the frozen v1), cap and
 * truncation agreement, duplicates, window containment, and for v3 the include list, per-day
 * counts, engine and typed-group agreement.
 * Pure functions; Validate.ts runs them after the schema pass. Zero dependencies.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

export interface SemanticResult { errors: string[]; warnings: string[] }

const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const V1_FLOOR = 12, V1_CAP = 200;
// The longest v3 window: 366 days. Anything longer is refused before its dates are listed.
const V3_MAX_WINDOW_HOURS = 8784;
// How many dates from each end a counts error quotes.
const QUOTED_DATES = 3;

/** A real UTC instant: matches the ISO shape and survives a Date round-trip (kills Feb 30). */
export function isRealInstant(ts: string): boolean {
  if (!ISO_RE.test(ts)) return false;
  const d = new Date(ts);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 19) === ts.slice(0, 19);
}
export function isRealDate(day: string): boolean {
  if (!DATE_RE.test(day)) return false;
  const d = new Date(`${day}T00:00:00Z`);
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

// The fields these rules read. Validate.ts runs the schema pass first, so a document that
// reaches a semantic function already has its version's shape.
export interface IntakeV1 { generated: string; detections: Det[] }
interface IntakeCommon {
  generated: string;
  window: { start: string; end: string; lookback_hours: number };
  pipeline: { last_event_seen: string | null };
  recon_delta: { baseline: string | null };
  truncated: boolean;
}
export interface IntakeV2 extends IntakeCommon { filter: { min_level: number; cap: number }; detections: Det[] }

function checkDetections(dets: Det[], floor: number, floorIs: "error" | "warning", cap: number, dupKey: (d: Det) => string, r: SemanticResult): void {
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
    if (d.level < floor) r[floorIs === "error" ? "errors" : "warnings"].push(`${where}.level: ${d.level} is below the level floor ${floor}`);
    const key = dupKey(d);
    if (seen.has(key)) r.errors.push(`${where}: duplicate of an earlier detection (${key})`);
    seen.add(key);
    const known = knownTechniques();
    if (known.size) for (const m of d.mitre) if (!known.has(m)) r.warnings.push(`${where}.mitre: ${m} is not in the ATT&CK reference table`);
  });
  if (dets.length > cap) r.errors.push(`detections: ${dets.length} entries exceeds the cap ${cap}`);
}

export function semanticV1(doc: IntakeV1): SemanticResult {
  const r: SemanticResult = { errors: [], warnings: [] };
  if (!isRealDate(doc.generated)) r.errors.push(`generated: "${doc.generated}" is not a real date`);
  // v1 is frozen and carries no floor field; 12 is the producer default, so a lower level is a warning.
  checkDetections(doc.detections, V1_FLOOR, "warning", V1_CAP, (d) => `${d.rule_id}|${d.agent}|${d.timestamp}`, r);
  return r;
}

export function semanticV2(doc: IntakeV2): SemanticResult {
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

  checkDetections(doc.detections, doc.filter.min_level, "error", doc.filter.cap, (d) => String(d.alert_id), r);
  doc.detections.forEach((d: Det, i: number) => {
    if (isRealInstant(d.timestamp)) {
      const t = Date.parse(d.timestamp);
      if (t < start || t > end) r.errors.push(`detections[${i}].timestamp: outside window ${doc.window.start}..${doc.window.end}`);
    }
  });
  // truncated means the cap cut the list, so the list must be exactly cap long. A list that
  // happens to be cap long without being cut is honest with truncated: false.
  const n = doc.detections.length, cap = doc.filter.cap;
  if (doc.truncated && n !== cap) r.errors.push(`truncated: true but detections.length (${n}) ${n < cap ? "is below" : "exceeds"} the cap ${cap}`);
  return r;
}

// v3: instants carry up to six fractional digits and a Z or +hh:mm offset.
const V3_INSTANT_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(?:Z|([+-])(\d{2}):(\d{2}))$/;

/**
 * A v3 instant in microseconds since the epoch, or null when the text is not a real instant.
 * Components are checked before any offset is applied, so 30 February or 24:00 never rolls over.
 */
export function instantMicros(ts: string): bigint | null {
  const m = V3_INSTANT_RE.exec(ts);
  if (!m) return null;
  const [y, mo, d, h, mi, s] = m.slice(1, 7).map(Number);
  if (h > 23 || mi > 59 || s > 59) return null;
  // Date.UTC reads years 0 to 99 as 1900 to 1999, so the year is set on its own.
  const back = new Date(Date.UTC(2000, mo - 1, d, h, mi, s));
  back.setUTCFullYear(y, mo - 1, d);
  const ms = back.getTime();
  if (back.getUTCFullYear() !== y || back.getUTCMonth() !== mo - 1 || back.getUTCDate() !== d) return null;
  let offset = 0;
  if (m[8] !== undefined) {
    const oh = Number(m[9]), om = Number(m[10]);
    if (om > 59 || oh * 60 + om > 14 * 60) return null;
    offset = (m[8] === "-" ? -1 : 1) * (oh * 60 + om);
  }
  const utcMs = ms - offset * 60_000;
  // utcDate slices a four-digit year, so an instant the offset pushes outside 0000 to 9999 is refused.
  const utcYear = new Date(utcMs).getUTCFullYear();
  if (utcYear < 0 || utcYear > 9999) return null;
  const frac = BigInt((m[7] ?? "").padEnd(6, "0"));
  return BigInt(utcMs) * 1000n + frac;
}

/** The UTC calendar date of a microsecond instant. */
export function utcDate(micros: bigint): string {
  // BigInt division truncates toward zero; a pre-epoch instant must floor to its own millisecond.
  const ms = micros >= 0n ? micros / 1000n : -((-micros + 999n) / 1000n);
  return new Date(Number(ms)).toISOString().slice(0, 10);
}

/** Every UTC date from the one holding `start` to the one holding `end`, both included. */
export function windowDays(start: bigint, end: bigint): string[] {
  const out: string[] = [];
  const last = utcDate(end);
  for (let d = Date.parse(`${utcDate(start)}T00:00:00Z`); ; d += 86_400_000) {
    const day = new Date(d).toISOString().slice(0, 10);
    out.push(day);
    if (day >= last) return out;
  }
}

/** A date list for an error message: the whole list when short, else its first and last few. */
function quoteDates(dates: string[]): string {
  if (dates.length <= QUOTED_DATES * 2) return dates.join(", ") || "none";
  return `${dates.slice(0, QUOTED_DATES).join(", ")}, ... ${dates.length - QUOTED_DATES * 2} more ..., ${dates.slice(-QUOTED_DATES).join(", ")}`;
}

// The Sysmon group each supported event ID must carry, and the Security events with a LogonType.
const SYSMON_GROUP: Record<string, string> = { "1": "process_create", "3": "network_connect", "11": "file_create", "13": "registry_value_set", "22": "dns_query" };
const LOGON_EVENTS = new Set(["4624", "4625", "4634"]);

type DetV3 = {
  level: number; rule_id: string; mitre: string[]; timestamp: string; alert_id: string;
  engine: { name: string; rule_id: string }; logon_type: number | null; event_id: string | null;
  sysmon: Record<string, unknown> | null; suricata: { event_type: string } | null;
};

/** Engine, typed-group and logon-type agreement for one v3 detection. */
function checkShapeV3(d: DetV3, where: string, r: SemanticResult): void {
  if (d.engine.name === "wazuh" && d.engine.rule_id !== d.rule_id) r.errors.push(`${where}.engine: a wazuh engine rule_id (${d.engine.rule_id}) must equal rule_id (${d.rule_id})`);
  if (d.engine.name === "suricata" && d.suricata?.event_type !== "alert") r.errors.push(`${where}.engine: a suricata engine needs a suricata block with event_type "alert"`);
  if (d.sysmon !== null) {
    const groups = Object.keys(d.sysmon);
    const want = Object.hasOwn(SYSMON_GROUP, String(d.event_id)) ? SYSMON_GROUP[String(d.event_id)] : undefined;
    if (groups.length !== 1) r.errors.push(`${where}.sysmon: carries ${groups.length} groups, expected exactly one`);
    else if (groups[0] !== want) r.errors.push(`${where}.sysmon: group ${groups[0]} does not match event_id ${d.event_id}`);
    if (d.engine.name === "suricata") r.errors.push(`${where}: a suricata engine detection cannot carry a sysmon block`);
  }
  if (d.logon_type !== null && !LOGON_EVENTS.has(String(d.event_id))) r.errors.push(`${where}.logon_type: set, but event_id ${d.event_id} carries no logon type`);
}

type DayCount = { date: string; matched: number; included: number };
export interface IntakeV3 extends IntakeCommon {
  filter: { min_level: number; cap: number; include_rule_ids: string[] };
  detections: DetV3[];
  counts: DayCount[];
}

export function semanticV3(doc: IntakeV3): SemanticResult {
  const r: SemanticResult = { errors: [], warnings: [] };
  const at = (field: string, v: string): bigint | null => {
    const t = instantMicros(v);
    if (t === null) r.errors.push(`${field}: "${v}" is not a real instant`);
    return t;
  };
  const gen = at("generated", doc.generated), start = at("window.start", doc.window.start), end = at("window.end", doc.window.end);
  if (doc.pipeline.last_event_seen !== null) at("pipeline.last_event_seen", doc.pipeline.last_event_seen);
  if (doc.recon_delta.baseline !== null && !isRealDate(doc.recon_delta.baseline)) r.errors.push(`recon_delta.baseline: not a real date`);
  doc.counts.forEach((c: { date: string }, i: number) => { if (!isRealDate(c.date)) r.errors.push(`counts[${i}].date: "${c.date}" is not a real date`); });
  if (r.errors.length || gen === null || start === null || end === null) return r;

  if (end <= start) r.errors.push(`window: end is not after start`);
  if (gen < end) r.errors.push(`generated: earlier than window.end`);
  const hours = Number(end - start) / 3_600_000_000;
  if (hours > V3_MAX_WINDOW_HOURS) {
    r.errors.push(`window: spans ${hours.toFixed(1)}h, longer than ${V3_MAX_WINDOW_HOURS} hours (366 days)`);
    return r;
  }
  if (Math.abs(hours - doc.window.lookback_hours) > 1) r.warnings.push(`window: spans ${hours.toFixed(1)}h but lookback_hours is ${doc.window.lookback_hours}`);

  const floor: number = doc.filter.min_level, cap: number = doc.filter.cap;
  const include = new Set<string>(doc.filter.include_rule_ids);
  const seen = new Set<string>();
  const perDay = new Map<string, number>();
  let prev: bigint | null = null;
  (doc.detections as DetV3[]).forEach((d, i) => {
    const where = `detections[${i}]`;
    const t = instantMicros(d.timestamp);
    if (t === null) r.errors.push(`${where}.timestamp: "${d.timestamp}" is not a real instant`);
    else {
      if (prev !== null && t > prev) r.errors.push(`${where}: not newest-first (later than detections[${i - 1}])`);
      prev = t;
      if (t < start || t > end) r.errors.push(`${where}.timestamp: outside window ${doc.window.start}..${doc.window.end}`);
      perDay.set(utcDate(t), (perDay.get(utcDate(t)) ?? 0) + 1);
    }
    if (d.level < floor && !include.has(d.rule_id)) r.errors.push(`${where}.level: ${d.level} is below the level floor ${floor} and rule ${d.rule_id} is not in include_rule_ids`);
    if (seen.has(d.alert_id)) r.errors.push(`${where}: duplicate of an earlier detection (${d.alert_id})`);
    seen.add(d.alert_id);
    const known = knownTechniques();
    if (known.size) for (const m of d.mitre) if (!known.has(m)) r.warnings.push(`${where}.mitre: ${m} is not in the ATT&CK reference table`);
    checkShapeV3(d, where, r);
  });

  const n = doc.detections.length;
  if (n > cap) r.errors.push(`detections: ${n} entries exceeds the cap ${cap}`);
  if (doc.truncated && n !== cap) r.errors.push(`truncated: true but detections.length (${n}) ${n < cap ? "is below" : "exceeds"} the cap ${cap}`);

  // Per-day counts make truncation visible: one entry per window date, oldest first.
  const days = windowDays(start, end);
  const dates = (doc.counts as { date: string }[]).map((c) => c.date);
  if (dates.join() !== days.join()) {
    r.errors.push(`counts: dates must be each UTC date of the window once, oldest first (expected ${quoteDates(days)}; got ${quoteDates(dates)})`);
    return r;
  }
  let matched = 0;
  // Truncation keeps the newest alerts, so once a day lost some, every older day must have kept none.
  let oldestKept: string | undefined, lostAfterKept = false;
  (doc.counts as { date: string; matched: number; included: number }[]).forEach((c, i) => {
    matched += c.matched;
    if (c.matched > c.included && oldestKept !== undefined && !lostAfterKept) {
      r.errors.push(`counts: day ${c.date} lost alerts to the cap but an older day ${oldestKept} kept some`);
      lostAfterKept = true;
    }
    if (c.included > 0 && oldestKept === undefined) oldestKept = c.date;
    const k = perDay.get(c.date) ?? 0;
    if (c.included !== k) r.errors.push(`counts[${i}]: included ${c.included} but ${k} detection(s) fall on ${c.date}`);
    if (c.matched < c.included) r.errors.push(`counts[${i}]: matched ${c.matched} is below included ${c.included}`);
  });
  if (doc.truncated && matched <= n) r.errors.push(`truncated: true but counts show ${matched} matched for ${n} included`);
  if (!doc.truncated && matched > n) r.errors.push(`truncated: false but counts show ${matched} matched for only ${n} included`);
  return r;
}
