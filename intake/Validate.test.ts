import { test, expect } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { validateIntake } from "./Validate.ts";
import { validateAgainstSchema, UnsupportedKeyword } from "./lib/schema.ts";
import { isRealInstant, isRealDate } from "./lib/semantic.ts";

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
