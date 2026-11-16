// *****************************************************************************
// *Title: Brief Grader*
// *Author: Kyle Versluis*
// *Description: Deterministic machine checks of a brief against ground truth.*
// *****************************************************************************

/** Pure functions for grading a brief against casa.expected/v1; evals/Grade.ts is the CLI. */

// *--- Imports ---*

import { analyze, firstJsonBlock, KINDS, type Kind, type LintOptions, type LintResult } from "./extract.ts";
import type { SetName } from "./sets.ts";

// *--- Types ---*

export type Level = "High" | "Medium" | "Low";
export interface Expected {
  schema: "casa.expected/v1";
  fixture: string;
  status: "findings" | "quiet";
  must_cite: { rule_ids: string[]; hosts: string[]; attack: string[] };
  must_not_cite: { rule_ids: string[] | "*"; hosts: string[] | "*"; attack: string[] | "*"; ip_literals: boolean };
  confidence: Level | null;
  csf_functions: string[];
  thread_count: { min: number; max: number };
  forbid_option_kinds: string[];
  must_identify: { id: string; text: string }[];
  must_not: { id: string; text: string }[];
}

export interface MachineCheck { check: string; pass: boolean; detail: string }
export interface Fabrication { token: string; kind: Kind; present: boolean }
export interface RubricItem { id: string; text: string; pass: boolean; quote: string }

export interface GradeResult {
  schema: "casa.grade/v1";
  fixture: string;
  brief: string;
  // The intake variant graded and its fixture set (ISC-56); absent on records older than S2.
  intake?: string;
  set?: SetName | "unlisted";
  graded_at: string;
  lint: { pass: boolean; unknown: string[] };
  machine: MachineCheck[];
  rubric: "pending" | RubricItem[];
  fabrication: Fabrication[];
  score: { machine_pass: number; machine_total: number; rubric_pass: number | null; rubric_total: number | null };
}

// *--- Core Logic ---*

const EXPECTED_KEYS = ["schema", "fixture", "status", "must_cite", "must_not_cite", "confidence", "csf_functions", "thread_count", "forbid_option_kinds", "must_identify", "must_not"];

/** Structural check of an expected.json; throws with a reason on the first problem. */
export function assertExpected(e: unknown): asserts e is Expected {
  if (typeof e !== "object" || e === null) throw new Error("expected: not an object");
  const o = e as Record<string, unknown>;
  for (const k of EXPECTED_KEYS) if (!(k in o)) throw new Error(`expected: missing key ${k}`);
  if (o.schema !== "casa.expected/v1") throw new Error("expected: schema must be casa.expected/v1");
  if (o.status !== "findings" && o.status !== "quiet") throw new Error("expected: status must be findings|quiet");
  if (!(o.confidence === null || ["High", "Medium", "Low"].includes(o.confidence as string))) throw new Error("expected: confidence must be High|Medium|Low|null");
  const tc = o.thread_count as { min: number; max: number };
  if (typeof tc?.min !== "number" || typeof tc?.max !== "number" || tc.min > tc.max) throw new Error("expected: thread_count min/max invalid");
  for (const a of (o.must_cite as { attack: string[] }).attack) if (!/^T\d{4}(\.\d{3})?$/.test(a)) throw new Error(`expected: bad technique id ${a}`);
  for (const f of o.csf_functions as string[]) if (!["GV", "ID", "PR", "DE", "RS", "RC"].includes(f)) throw new Error(`expected: bad CSF function ${f}`);
  for (const r of [...(o.must_identify as { id: string }[]), ...(o.must_not as { id: string }[])]) if (!/^[a-z0-9-]+$/.test(r.id)) throw new Error(`expected: bad rubric id ${r.id}`);
}

// *--- Helper Functions ---*

function parseBrief(text: string): Record<string, any> | null {
  const block = firstJsonBlock(text);
  if (!block) return null;
  try {
    const b = JSON.parse(block);
    return b && b.schema === "casa.brief/v1" ? b : null;
  } catch {
    return null;
  }
}

export function gradeMachine(briefText: string, expected: Expected, intake: unknown, opts: LintOptions = {}): { lint: LintResult; machine: MachineCheck[]; fabrication: Fabrication[]; brief: Record<string, any> | null } {
  const checks: MachineCheck[] = [];
  const brief = parseBrief(briefText);
  checks.push({ check: "brief-json", pass: brief !== null, detail: brief ? "first json block parses as casa.brief/v1" : "no parseable casa.brief/v1 block" });

  const { result: l, tokens, knowledge } = analyze(briefText, intake, opts);
  checks.push({ check: "lint", pass: l.pass, detail: l.pass ? "every citation traces to the intake or a reference table" : l.unknown.map((u) => `${u.kind}:${u.token}`).join(", ") });

  const fabrication: Fabrication[] = [];
  const known = new Set(l.unknown.map((u) => `${u.kind}:${u.token}`));
  for (const kind of KINDS) for (const t of tokens[kind]) fabrication.push({ token: t, kind, present: !known.has(`${kind}:${t}`) });

  if (brief) {
    checks.push({ check: "status", pass: brief.status === expected.status, detail: `brief ${brief.status}, expected ${expected.status}` });
    const n = Array.isArray(brief.threads) ? brief.threads.length : -1;
    checks.push({ check: "thread_count", pass: n >= expected.thread_count.min && n <= expected.thread_count.max, detail: `brief ${n}, expected ${expected.thread_count.min}..${expected.thread_count.max}` });
    const oc = brief.overall_confidence ?? {};
    if (expected.confidence === null) checks.push({ check: "confidence", pass: oc.basis === "coverage", detail: `basis ${oc.basis ?? "missing"}, expected coverage` });
    else checks.push({ check: "confidence", pass: oc.level === expected.confidence, detail: `brief ${oc.level ?? "missing"}, expected ${expected.confidence}` });
    // The brief is model-written: a wrong shape is a failed check, never a crash.
    const csfRows: { function?: unknown }[] = Array.isArray(brief.csf) ? brief.csf : [];
    const fns = new Set(csfRows.map((c) => (typeof c?.function === "string" ? c.function : "")));
    const missingFn = expected.csf_functions.filter((f) => !fns.has(f));
    checks.push({ check: "csf_functions", pass: missingFn.length === 0, detail: missingFn.length ? `missing ${missingFn.join(", ")}` : `brief has ${[...fns].join(", ") || "none"}` });
    const optRows: { kind?: unknown }[] = Array.isArray(brief.options) ? brief.options : [];
    const kinds = optRows.map((o) => (typeof o?.kind === "string" ? o.kind : ""));
    const forbidden = kinds.filter((k: string) => expected.forbid_option_kinds.includes(k));
    checks.push({ check: "forbid_option_kinds", pass: forbidden.length === 0, detail: forbidden.length ? `forbidden kinds present: ${[...new Set(forbidden)].join(", ")}` : `option kinds ${[...new Set(kinds)].join(", ") || "none"}` });
  }

  // must_cite: every listed token must appear in the brief text.
  const missing: string[] = [];
  for (const r of expected.must_cite.rule_ids) if (!tokens.rule_id.has(r)) missing.push(`rule_id:${r}`);
  for (const h of expected.must_cite.hosts) if (!tokens.host.has(h.toLowerCase())) missing.push(`host:${h}`);
  for (const a of expected.must_cite.attack) if (!tokens.attack.has(a)) missing.push(`attack:${a}`);
  checks.push({ check: "must_cite", pass: missing.length === 0, detail: missing.length ? `missing ${missing.join(", ")}` : "all required citations present" });

  // must_not_cite: listed tokens must be absent; "*" means nothing of that kind beyond the intake's own typed values.
  const offending: string[] = [];
  const kindMap: [keyof Expected["must_not_cite"], Kind, Set<string>][] = [["rule_ids", "rule_id", knowledge.rule_ids], ["hosts", "host", knowledge.hosts], ["attack", "attack", knowledge.attack_in_intake]];
  for (const [field, kind, own] of kindMap) {
    const rule = expected.must_not_cite[field];
    if (rule === "*") for (const t of tokens[kind]) if (!own.has(t)) offending.push(`${kind}:${t}`);
    if (Array.isArray(rule)) for (const t of rule) if (tokens[kind].has(t)) offending.push(`${kind}:${t}`);
  }
  if (expected.must_not_cite.ip_literals) for (const ip of tokens.ip) if (!knowledge.ips.has(ip)) offending.push(`ip:${ip}`);
  checks.push({ check: "must_not_cite", pass: offending.length === 0, detail: offending.length ? `present: ${offending.join(", ")}` : "nothing forbidden cited" });

  return { lint: l, machine: checks, fabrication, brief };
}

// *--- Public Interfaces ---*

export function buildGrade(fixture: string, briefPath: string, m: ReturnType<typeof gradeMachine>, rubric: RubricItem[] | null, where: { intake?: string; set?: SetName | "unlisted" } = {}): GradeResult {
  const machine_pass = m.machine.filter((c) => c.pass).length;
  return {
    schema: "casa.grade/v1",
    fixture,
    brief: briefPath,
    ...where,
    graded_at: new Date().toISOString(),
    lint: { pass: m.lint.pass, unknown: m.lint.unknown.map((u) => `${u.kind}:${u.token}`) },
    machine: m.machine,
    rubric: rubric ?? "pending",
    fabrication: m.fabrication,
    score: { machine_pass, machine_total: m.machine.length, rubric_pass: rubric ? rubric.filter((r) => r.pass).length : null, rubric_total: rubric ? rubric.length : null },
  };
}

/** Validate an evaluator rubric file against the expected rubric ids; returns the items in expected order. */
export function mergeRubric(expected: Expected, rubricDoc: unknown): RubricItem[] {
  const items = (rubricDoc as { rubric?: unknown })?.rubric;
  if (!Array.isArray(items)) throw new Error("rubric file: missing rubric[]");
  const byId = new Map<string, RubricItem>();
  for (const it of items as RubricItem[]) {
    if (typeof it?.id !== "string" || typeof it?.pass !== "boolean" || typeof it?.quote !== "string") throw new Error(`rubric file: bad item ${JSON.stringify(it).slice(0, 80)}`);
    byId.set(it.id, it);
  }
  const wanted = [...expected.must_identify, ...expected.must_not];
  return wanted.map((w) => {
    const it = byId.get(w.id);
    if (!it) return { id: w.id, text: w.text, pass: false, quote: "(not graded by the evaluator)" };
    return { id: w.id, text: w.text, pass: it.pass, quote: it.quote };
  });
}
