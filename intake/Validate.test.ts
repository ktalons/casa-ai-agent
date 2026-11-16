import { test, expect } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { validateIntake } from "./Validate.ts";
import { validateAgainstSchema, UnsupportedKeyword } from "./lib/schema.ts";
import { isRealInstant, isRealDate, instantMicros, utcDate } from "./lib/semantic.ts";

const DIR = import.meta.dir;
const json = (p: string) => JSON.parse(readFileSync(join(DIR, p), "utf8"));

for (const f of readdirSync(join(DIR, "fixtures")).filter((n) => n.endsWith(".intake.json")).sort()) {
  test(`fixture ${f} validates with no errors`, () => {
    const r = validateIntake(json(`fixtures/${f}`));
    expect(r.errors).toEqual([]);
  });
}

const manifest = json("fixtures-invalid/manifest.json") as Record<string, string>;
for (const [f, reason] of Object.entries(manifest)) {
  test(`invalid fixture ${f} is rejected for: ${reason}`, () => {
    const r = validateIntake(json(`fixtures-invalid/${f}`));
    expect(r.errors.length).toBeGreaterThan(0);
    expect(r.errors.join("\n")).toContain(reason);
  });
}

test("every invalid fixture has a manifest entry and vice versa", () => {
  const files = readdirSync(join(DIR, "fixtures-invalid")).filter((n) => n.endsWith(".intake.json")).sort();
  expect(files).toEqual(Object.keys(manifest).sort());
});

test("the schema evaluator refuses keywords it does not enforce", () => {
  expect(() => validateAgainstSchema({ a: 1 }, { type: "object", properties: { a: { type: "integer", multipleOf: 2 } } })).toThrow(UnsupportedKeyword);
  expect(() => validateAgainstSchema({}, { anyOf: [] })).toThrow(UnsupportedKeyword);
});

test("the schema evaluator reports type, const, pattern, required and additionalProperties", () => {
  const schema = { type: "object", additionalProperties: false, required: ["id"], properties: { id: { type: "string", pattern: "^T\\d{4}$" }, n: { type: ["integer", "null"], minimum: 0 } } };
  expect(validateAgainstSchema({ id: "T1003", n: null }, schema)).toEqual([]);
  const errs = validateAgainstSchema({ id: "x", n: -1, extra: true }, schema).map((e) => e.message);
  expect(errs.some((m) => m.includes("does not match"))).toBe(true);
  expect(errs.some((m) => m.includes("below minimum"))).toBe(true);
  expect(errs.some((m) => m.includes('unexpected field "extra"'))).toBe(true);
  expect(validateAgainstSchema({ n: 1 }, schema).map((e) => e.message)).toContain('missing required field "id"');
});

test("real instants and dates: Feb 30 and bare dates are rejected", () => {
  expect(isRealInstant("2026-07-20T02:19:47.418Z")).toBe(true);
  expect(isRealInstant("2026-02-30T00:00:00Z")).toBe(false);
  expect(isRealInstant("2026-07-20T02:19:47")).toBe(false);
  expect(isRealDate("2026-02-29")).toBe(false);
  expect(isRealDate("2024-02-29")).toBe(true);
});

test("a wrong schema identifier is rejected before any other check", () => {
  expect(validateIntake({ schema: "wrong" }).errors[0]).toContain("expected one of");
});

test("field names that live on Object.prototype do not slip past the schema", () => {
  const schema = { type: "object", additionalProperties: false, required: ["id"], properties: { id: { type: "string" } } };
  const errs = validateAgainstSchema({ id: "x", constructor: "y", toString: 5 }, schema).map((e) => e.message);
  expect(errs).toContain('unexpected field "constructor"');
  expect(errs).toContain('unexpected field "toString"');
  expect(validateAgainstSchema({ constructor: "x" }, schema).map((e) => e.message)).toContain('missing required field "id"');
  expect(validateIntake({ schema: "constructor" }).errors[0]).toContain("expected one of");
});

test("v2 truncation: true needs exactly cap entries, false allows a list that happens to be cap long", () => {
  const v2 = json("fixtures/brute-force-dc-chain.v2.intake.json");
  const n = v2.detections.length;
  const at = (truncated: boolean, cap: number) => validateIntake({ ...v2, truncated, filter: { ...v2.filter, cap } }).errors;
  expect(at(false, n)).toEqual([]);
  expect(at(true, n)).toEqual([]);
  expect(at(true, n + 1).join("\n")).toContain("is below the cap");
  const over = at(true, n - 1).join("\n");
  expect(over).toContain("exceeds the cap");
  expect(over).not.toContain("is below the cap");
});

test("v1 has no floor field, so a level under the default floor is a warning, not an error", () => {
  const v1 = json("fixtures/brute-force-dc-chain.intake.json");
  const low = { ...v1, detections: v1.detections.map((d: { level: number }, i: number) => (i === v1.detections.length - 1 ? { ...d, level: 10 } : d)) };
  const r = validateIntake(low);
  expect(r.errors).toEqual([]);
  expect(r.warnings.join("\n")).toContain("below the level floor 12");
});

test("v3 fields: the schema defines all eight field groups", () => {
  const s = json("schema/soc-intake.v3.schema.json");
  const det = s.definitions.detection.properties;
  // 1 engine and its IDs, 2 ports, 3 subject/target user and logon type, 4 typed Sysmon,
  // 5 Suricata EVE, 6 microsecond and offset instants, 7 floor plus include list, 8 per-day counts.
  expect(Object.keys(s.definitions.engine.properties).sort()).toEqual(["name", "rev", "rule_id"]);
  expect(s.definitions.engine.properties.name.enum).toEqual(["wazuh", "suricata", "sigma"]);
  for (const k of ["src_port", "dst_port", "proto", "subject_user", "target_user", "logon_type", "engine", "sysmon", "suricata"]) expect(det).toHaveProperty(k);
  expect(det).not.toHaveProperty("user");
  expect(Object.keys(s.definitions.sysmon.properties).sort()).toEqual(["dns_query", "file_create", "network_connect", "process_create", "registry_value_set"]);
  for (const k of ["signature", "category", "severity", "flow_id", "app_proto", "http_hostname", "tls_sni", "dns_rrname"]) expect(s.definitions.suricata.properties).toHaveProperty(k);
  const instant = new RegExp(s.definitions.instant.pattern);
  expect(instant.test("2026-07-20T02:19:47.418123Z")).toBe(true);
  expect(instant.test("2026-07-20T09:19:47.418123+07:00")).toBe(true);
  expect(instant.test("2026-07-20T02:19:47.4181234Z")).toBe(false);
  expect(s.properties.filter.required).toEqual(["min_level", "include_rule_ids", "cap", "order"]);
  expect(s.definitions.day.required).toEqual(["date", "matched", "included"]);
});

test("v3 instants: microseconds order, offsets convert, impossible components are refused", () => {
  expect(instantMicros("2026-07-20T09:19:47.418123+07:00")).toBe(instantMicros("2026-07-20T02:19:47.418123Z"));
  expect(instantMicros("2026-07-20T02:19:47.000001Z")! > instantMicros("2026-07-20T02:19:47Z")!).toBe(true);
  for (const bad of ["2026-02-30T00:00:00Z", "2026-07-20T24:00:00Z", "2026-07-20T00:00:60Z", "2026-07-20T00:00:00+14:30", "2026-07-20T00:00:00+05:60", "2026-07-20T00:00:00"]) expect(instantMicros(bad)).toBeNull();
  expect(instantMicros("2026-07-20T00:00:00-12:00")).not.toBeNull();
});

test("include list: a rule below the floor is valid only when the include list names it", () => {
  const v3 = json("fixtures/brute-force-dc-chain.v3.intake.json");
  const low = { ...v3, detections: v3.detections.map((d: { level: number }, i: number) => (i === 3 ? { ...d, level: 6 } : d)) };
  expect(validateIntake(low).errors.join("\n")).toContain("is not in include_rule_ids");
  expect(validateIntake({ ...low, filter: { ...low.filter, include_rule_ids: ["100200"] } }).errors).toEqual([]);
  expect(validateIntake({ ...low, filter: { ...low.filter, include_rule_ids: ["100201"] } }).errors.join("\n")).toContain("is not in include_rule_ids");
});

test("v3 invalid set: each file fails naming its rule, and truncation agrees with the counts", () => {
  const v3 = Object.entries(manifest).filter(([f]) => f.startsWith("v3-"));
  expect(v3.length).toBeGreaterThanOrEqual(11);
  for (const [f, reason] of v3) {
    const r = validateIntake(json(`fixtures-invalid/${f}`));
    expect(r.errors.join("\n")).toContain(reason);
  }
  const ok = json("fixtures/brute-force-dc-chain.v3.intake.json");
  const cut = { ...ok, truncated: true, filter: { ...ok.filter, cap: 4 }, counts: [ok.counts[0], { ...ok.counts[1], matched: 7 }] };
  expect(validateIntake(cut).errors).toEqual([]);
  expect(validateIntake({ ...cut, counts: ok.counts }).errors.join("\n")).toContain("truncated: true but counts show");
});

test("instants before year 100: years 0000 to 0099 parse, and a pre-epoch instant keeps its own UTC day", () => {
  expect(instantMicros("0050-03-01T00:00:00Z")).not.toBeNull();
  expect(instantMicros("0000-01-01T00:00:00Z")).not.toBeNull();
  expect(instantMicros("0099-12-31T23:59:59Z")! < instantMicros("0100-01-01T00:00:00Z")!).toBe(true);
  expect(utcDate(instantMicros("1969-12-31T23:59:59.999999Z")!)).toBe("1969-12-31");
  expect(utcDate(instantMicros("0050-03-01T12:00:00Z")!)).toBe("0050-03-01");
});

test("window cap: a window longer than 366 days is refused fast, and the counts error quotes few dates", () => {
  const ok = json("fixtures/brute-force-dc-chain.v3.intake.json");
  const huge = { ...ok, generated: "9999-12-31T00:00:00Z", window: { ...ok.window, start: "0100-01-01T00:00:00Z", end: "9999-12-31T00:00:00Z" } };
  const t0 = performance.now();
  const errs = validateIntake(huge).errors.join("\n");
  expect(performance.now() - t0).toBeLessThan(100);
  expect(errs).toContain("longer than 8784 hours");
  const wide = { ...ok, counts: [ok.counts[0]] };
  const msg = validateIntake({ ...wide, window: { ...ok.window, start: "2025-09-20T00:00:00Z" }, generated: ok.generated }).errors.join("\n");
  expect(msg).toContain("counts: dates must be each UTC date");
  expect(msg.length).toBeLessThan(400);
});

test("counts: truncation keeps the newest alerts, so a newer day that lost some forbids an older day that kept some", () => {
  const ok = json("fixtures/brute-force-dc-chain.v3.intake.json");
  const old = { ...ok.detections[3], timestamp: "2026-07-19T05:00:00.000Z" };
  const detections = [...ok.detections.slice(0, 3), old];
  const counts = [
    { date: "2026-07-19", matched: 1, included: 1 },
    { date: "2026-07-20", matched: 4, included: 3 },
  ];
  const bad = { ...ok, detections, truncated: true, filter: { ...ok.filter, cap: 4 }, counts };
  expect(validateIntake(bad).errors).toEqual(["counts: day 2026-07-20 lost alerts to the cap but an older day 2026-07-19 kept some"]);
  // The honest shape: the older day lost its own alerts too, so it keeps none.
  const fine = { ...bad, detections: ok.detections, counts: [{ date: "2026-07-19", matched: 3, included: 0 }, { date: "2026-07-20", matched: 5, included: 4 }] };
  expect(validateIntake(fine).errors).toEqual([]);
});

test("instants: one whose UTC year falls outside 0000 to 9999 after the offset is null", () => {
  expect(instantMicros("9999-12-31T23:30:00-01:00")).toBeNull();
  expect(instantMicros("9999-12-31T23:30:00Z")).not.toBeNull();
  expect(instantMicros("0000-01-01T00:30:00+01:00")).toBeNull();
  expect(instantMicros("0000-01-01T00:30:00Z")).not.toBeNull();
});
