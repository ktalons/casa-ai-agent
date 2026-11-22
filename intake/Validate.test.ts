import { test, expect } from "bun:test";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { validateIntake } from "./Validate.ts";
import { validateAgainstSchema, UnsupportedKeyword } from "./lib/schema.ts";
import { isRealInstant, isRealDate, instantMicros, utcDate } from "./lib/semantic.ts";
import { assertExpected } from "../evals/lib/grade.ts";
import { SCENARIOS } from "../evals/lib/sets.ts";

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
  expect(micros("2026-07-20T02:19:47.000001Z") > micros("2026-07-20T02:19:47Z")).toBe(true);
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
  expect(micros("0099-12-31T23:59:59Z") < micros("0100-01-01T00:00:00Z")).toBe(true);
  expect(utcDate(micros("1969-12-31T23:59:59.999999Z"))).toBe("1969-12-31");
  expect(utcDate(micros("0050-03-01T12:00:00Z"))).toBe("0050-03-01");
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

// *--- S2 fixture breadth (ISC-25, ISC-27, ISC-57, ISC-84) ---*

const SETS = JSON.parse(readFileSync(join(DIR, "..", "evals", "fixture-sets.json"), "utf8")) as {
  fixtures: Record<string, { set: string; scenarios: string[] }>;
};
const intakeVariants = (base: string) =>
  readdirSync(join(DIR, "fixtures")).filter((n) => n.endsWith(".intake.json") && n.split(".")[0] === base).sort();
const newestVariant = (base: string) => intakeVariants(base).at(-1) as string;
const covers = (ids: string[], want: string) => ids.some((id) => id === want || id.startsWith(`${want}.`));

/** A v3 instant that must parse; one that does not fails the test with its own text. */
function micros(ts: string): bigint {
  const parsed = instantMicros(ts);
  if (parsed === null) throw new Error(`not a real instant: ${ts}`);
  return parsed;
}

/** The intake and ground-truth fields the scenario checks read. */
type Truth = {
  intake: {
    detections: { description: string; mitre?: string[] }[];
    recon_delta?: { markdown?: string };
    truncated: boolean;
    pipeline?: { collector_ok: boolean; agents_reporting: number; last_event_seen: string | null };
  };
  expected: { status: string; forbid_option_kinds: string[]; must_identify: { text: string }[]; must_cite: { attack: string[] } };
};
// What each scenario means, checked on the fixture's own data; at least one tagged fixture must show it.
const SCENARIO_SHOWN: Record<string, (t: Truth) => boolean> = {
  "refuted-benign": ({ expected }) =>
    expected.status === "findings" && expected.forbid_option_kinds.includes("contain") &&
    expected.must_identify.some((m: { text: string }) => /refut/i.test(m.text)),
  "injected-text": ({ intake }) => {
    const addressed = (s: string) => /\b(ai|assistant|analyst|model)\b/i.test(s) && /\b(ignore|disregard|mark|omit|exclude|leave|suppress|approved|benign)\b/i.test(s);
    return intake.detections.some((d: { description: string }) => addressed(d.description)) && addressed(intake.recon_delta?.markdown ?? "");
  },
  truncation: ({ intake }) => intake.truncated === true,
  "healthy-quiet-day": ({ intake, expected }) =>
    expected.status === "quiet" && intake.detections.length === 0 && intake.pipeline?.collector_ok === true &&
    intake.pipeline.agents_reporting > 0 && intake.pipeline.last_event_seen !== null,
};
// Techniques the ISA names for each technique scenario: each tagged fixture cites one, together all.
const SCENARIO_TECHNIQUES: Record<string, string[]> = {
  lolbins: ["T1059", "T1218"],
  persistence: ["T1543", "T1547"],
  "log-tampering": ["T1685.005", "T1685"], // ATT&CK v19 moved T1070.001 and T1562 here
  "internal-scanning": ["T1046"],
};

test("scenarios: each of the eight S2 scenarios is covered by a valid fixture whose own data shows it", () => {
  expect(SCENARIOS.length).toBe(8);
  for (const scenario of SCENARIOS) {
    const tagged = Object.entries(SETS.fixtures).filter(([, e]) => e.scenarios.includes(scenario)).map(([n]) => n);
    expect(tagged, scenario).not.toEqual([]);
    const truths: Truth[] = tagged.map((base) => {
      expect(intakeVariants(base), base).not.toEqual([]);
      for (const v of intakeVariants(base)) expect(validateIntake(json(`fixtures/${v}`)).errors, v).toEqual([]);
      const expected = json(`fixtures/${base}.expected.json`);
      assertExpected(expected);
      expect(expected.fixture).toBe(base);
      expect(readFileSync(join(DIR, "fixtures", `${base}.expected.md`), "utf8").length).toBeGreaterThan(200);
      return { intake: json(`fixtures/${newestVariant(base)}`), expected };
    });
    if (SCENARIO_SHOWN[scenario]) expect(truths.some(SCENARIO_SHOWN[scenario]), scenario).toBe(true);
    const wanted = SCENARIO_TECHNIQUES[scenario];
    if (wanted) {
      for (const [i, t] of truths.entries()) {
        const intakeIds = t.intake.detections.flatMap((d: { mitre?: string[] }) => d.mitre ?? []);
        expect(wanted.some((w) => covers(t.expected.must_cite.attack, w) && covers(intakeIds, w)), `${tagged[i]} ${scenario}`).toBe(true);
      }
      for (const w of wanted) expect(truths.some((t) => covers(t.expected.must_cite.attack, w)), `${scenario} ${w}`).toBe(true);
    }
  }
});

// Every intake artifact: the fixtures, the invalid set, and the raw recordings they replay from.
// The kept sample briefs too: they quote the fixtures they were written from.
const ARTIFACT_DIRS = ["fixtures", "fixtures-invalid", "raw", join("..", "evals", "samples")];
const artifactFiles = () => ARTIFACT_DIRS.flatMap((d) => readdirSync(join(DIR, d)).map((f) => join(d, f)));

/** Address literals in a text that are not in a documentation range. */
function undocumentedAddresses(text: string): string[] {
  const bad: string[] = [];
  for (const m of text.matchAll(/(?<![\w.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d]|\.\d)/g)) {
    // NOTE: an octet over 255 or a leading letter (v1.2.3.4) marks a version string, not an address.
    if ([m[1], m[2], m[3], m[4]].some((o) => Number(o) > 255)) continue;
    const [a, b, c] = [m[1], m[2], m[3]].map(Number);
    const doc = (a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113);
    if (!doc) bad.push(m[0]);
  }
  for (const m of text.matchAll(/(?<![\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])/gi)) {
    // NOTE: a clock time has two colons and no "::"; only "::" forms and full eight-group forms are addresses.
    if (!m[0].includes("::") && m[0].split(":").length !== 8) continue;
    const [g0, g1] = m[0].split(":").map((g) => (g === "" ? NaN : parseInt(g, 16)));
    if (!(g0 === 0x2001 && g1 === 0x0db8)) bad.push(m[0]);
  }
  return bad;
}

test("documentation ranges: every address in every intake artifact is a documentation address", () => {
  expect(undocumentedAddresses("from 10.10.20.77 and 2001:db8::14 at 02:19:47, to 203.0.113.9 and fe80::1")).toEqual(["10.10.20.77", "fe80::1"]);
  expect(undocumentedAddresses("192.0.2.77 198.51.100.14 2001:0db8:0:0:0:0:0:1 v1.784600387.418001 v4.14.9.1 999.1.1.1")).toEqual([]);
  for (const f of artifactFiles()) expect(undocumentedAddresses(readFileSync(join(DIR, f), "utf8")), f).toEqual([]);
});

test("neutral hosts: no intake artifact names a talon host", () => {
  const TALON = /(?<![a-z])talon(?!soclab(?![-\w]))[\w.-]*/gi;
  expect([..."talonsoclab-dc01 talonsoclab.soc-intake/v3 ktalons \"talonsoclab\" talondc9".matchAll(TALON)].map((m) => m[0])).toEqual(["talonsoclab-dc01", "talondc9"]);
  for (const f of artifactFiles()) {
    const text = readFileSync(join(DIR, f), "utf8");
    // `talonsoclab` is the schema namespace and the producer name, and `ktalons` the repo owner
    // in the consumer URL; neither is a host.
    expect([...text.matchAll(TALON)].map((m) => m[0]), f).toEqual([]);
  }
  for (const f of readdirSync(join(DIR, "fixtures")).filter((n) => n.endsWith(".intake.json"))) {
    const intake = json(`fixtures/${f}`);
    const hosts = [
      ...intake.detections.map((d: { agent: string }) => d.agent),
      ...(intake.recon_delta?.changes ?? []).map((c: { host: string }) => c.host),
    ];
    for (const h of hosts) expect(h.toLowerCase().startsWith("talon"), `${f} ${h}`).toBe(false);
  }
});

test("neutral names: no fixture file name tells the investigation its verdict", () => {
  const VERDICT = /benign|refut|malicious|clean|inject|positive|harmless|legit|innocent/i;
  const names = [...readdirSync(join(DIR, "fixtures")), ...Object.keys(SETS.fixtures)];
  expect(names.filter((n) => VERDICT.test(n))).toEqual([]);
  expect(VERDICT.test("benign-admin-scan")).toBe(true);
});

test("sha256: the CLI prints the SHA-256 of each file it accepts, the value the lint computes, and none for a refused file", () => {
  const run = (rel: string) => Bun.spawnSync(["bun", join(DIR, "Validate.ts"), join(DIR, rel)], { stdout: "pipe", stderr: "pipe" });
  const good = "fixtures/brute-force-dc-chain.v3.intake.json";
  const expected = createHash("sha256").update(readFileSync(join(DIR, good))).digest("hex");
  const ok = run(good);
  expect(ok.exitCode).toBe(0);
  expect(ok.stdout.toString()).toContain(`    sha256 ${expected}\n`);
  const bad = run(`fixtures-invalid/${Object.keys(manifest)[0]}`);
  expect(bad.exitCode).toBe(1);
  expect(`${bad.stdout}${bad.stderr}`).not.toMatch(/sha256 [0-9a-f]{64}/);
});
