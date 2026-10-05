/**
 * extract.ts — shared token extraction and knowledge sets for the fabrication lint and the
 * grader. Zero dependencies. Everything here is deterministic string work.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

export const REFERENCES_DIR = join(import.meta.dir, "..", "..", "skills", "standards", "references");

export type Kind = "rule_id" | "host" | "attack" | "csf" | "ip";

export interface Tokens {
  rule_id: Set<string>;
  host: Set<string>;
  attack: Set<string>;
  csf: Set<string>;
  ip: Set<string>;
}

export interface Knowledge {
  rule_ids: Set<string>;
  hosts: Set<string>;
  attack_in_intake: Set<string>;
  attack_table: Set<string>;
  csf_table: Set<string>;
  intake_text: string;
  ips_in_intake: Set<string>;
}

// Hosts in the lab share a name prefix. The lint takes only that prefix, never a regular
// expression: the prefix is validated against the hostname character set and escaped before
// it is placed in a regex, so a caller cannot change the expression's meaning or its cost.
export const DEFAULT_HOST_PREFIX = "talon";
const RE_HOST_PREFIX = /^[a-z0-9-]{1,63}$/;

const RE_HEX_BLOB = /\b[0-9a-f]{32,}\b/gi; // sha256 and friends: never rule IDs
// Rule IDs: five or six digits. Four-digit numbers are deliberately out of range, because
// Windows event IDs (4624, 4662) and years share that shape; a four-digit built-in Wazuh rule is
// therefore not lint-checked. Port notations ("port 49152", "49152/tcp", "host:49152") are
// stripped before this pass so a high port is not read as a rule ID.
const RE_RULE_ID = /\b\d{5,6}\b/g;
const RE_PORT = /\b(?:ports?\s+\d{1,5}|\d{1,5}\/(?:tcp|udp))\b/gi;
const RE_ATTACK = /\bT\d{4}(?:\.\d{3})?\b/g;
// Catches both CSF 2.0 (DE.AE-03) and CSF 1.1 (PR.AC-4) shapes so 1.1 leftovers fail.
const RE_CSF = /\b(?:GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d{1,2}\b/g;
const RE_IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

/** Escape every regex metacharacter so the string matches itself and nothing else. */
function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** The prefix itself when it is made of hostname characters only; throws otherwise. */
export function assertHostPrefix(prefix: string): string {
  if (!RE_HOST_PREFIX.test(prefix)) throw new Error(`host prefix must match ${RE_HOST_PREFIX}, got ${JSON.stringify(prefix)}`);
  return prefix;
}

/** A global finder for whole host tokens that start with the prefix: <prefix><host chars>. */
function hostRegex(prefix: string): RegExp {
  return new RegExp(`\\b${escapeRegExp(assertHostPrefix(prefix))}[a-z0-9-]+\\b`, "g");
}

export function extractTokens(text: string, hostPrefix = DEFAULT_HOST_PREFIX): Tokens {
  const cleaned = text.replace(RE_HEX_BLOB, " ");
  const grab = (re: RegExp) => new Set((cleaned.match(re) ?? []).map((s) => s.trim()));
  const ips = grab(RE_IPV4);
  // Strip IPv4 literals and port notations before the rule-ID pass so "10.0.0.50" never
  // yields a 5-digit run and "port 49152" is not a rule.
  const noIps = cleaned.replace(RE_IPV4, " ").replace(RE_PORT, " ");
  return {
    rule_id: new Set((noIps.match(RE_RULE_ID) ?? [])),
    host: grab(hostRegex(hostPrefix)),
    attack: grab(RE_ATTACK),
    csf: grab(RE_CSF),
    ip: ips,
  };
}

export function loadReferences(): { attack: Set<string>; csf: Set<string>; attack_version: string } {
  const attack = JSON.parse(readFileSync(join(REFERENCES_DIR, "attack-techniques.json"), "utf8"));
  const csf = JSON.parse(readFileSync(join(REFERENCES_DIR, "csf-2.0.json"), "utf8"));
  return {
    attack: new Set<string>(attack.techniques.map((t: { id: string }) => t.id)),
    csf: new Set<string>(Object.keys(csf.subcategories)),
    attack_version: String(attack.attack_version),
  };
}

export function intakeKnowledge(intake: unknown, hostPrefix = DEFAULT_HOST_PREFIX): Knowledge {
  const text = JSON.stringify(intake);
  const refs = loadReferences();
  const detections: Array<{ rule_id?: string; agent?: string; mitre?: string[] }> =
    (intake as { detections?: typeof detections }).detections ?? [];
  const hosts = new Set<string>();
  for (const d of detections) if (d.agent) hosts.add(d.agent);
  const recon = (intake as { recon_delta?: unknown }).recon_delta;
  const reconText = typeof recon === "string" ? recon : JSON.stringify(recon ?? "");
  for (const h of extractTokens(reconText, hostPrefix).host) hosts.add(h);
  return {
    rule_ids: new Set(detections.map((d) => d.rule_id).filter((r): r is string => typeof r === "string")),
    hosts,
    attack_in_intake: new Set(detections.flatMap((d) => d.mitre ?? [])),
    attack_table: refs.attack,
    csf_table: refs.csf,
    intake_text: text,
    ips_in_intake: new Set(text.match(RE_IPV4) ?? []),
  };
}

export interface Unknown { token: string; kind: Kind; reason: string }

export interface LintResult {
  pass: boolean;
  unknown: Unknown[];
  counts: Record<Kind, number>;
  attack_not_in_intake: string[];
}

/** Producer metadata (schema id, source, consumer) is not a citation; strip it before extraction. */
export function stripProducerStrings(text: string, intake: unknown): string {
  const meta = intake as { schema?: unknown; source?: unknown; consumer?: unknown };
  let out = text;
  for (const v of [meta.schema, meta.source, meta.consumer]) if (typeof v === "string" && v.length > 0) out = out.split(v).join(" ");
  return out;
}

/** Every token in `text` must trace to the intake or to a reference table. */
export function lint(text: string, intake: unknown, hostPrefix = DEFAULT_HOST_PREFIX): LintResult {
  const k = intakeKnowledge(intake, hostPrefix);
  const t = extractTokens(stripProducerStrings(text, intake), hostPrefix);
  const unknown: Unknown[] = [];
  for (const r of t.rule_id) if (!k.rule_ids.has(r) && !k.intake_text.includes(r)) unknown.push({ token: r, kind: "rule_id", reason: "not a rule_id in the intake" });
  for (const h of t.host) if (!k.hosts.has(h)) unknown.push({ token: h, kind: "host", reason: "host not named in the intake" });
  for (const a of t.attack) if (!k.attack_table.has(a)) unknown.push({ token: a, kind: "attack", reason: "technique ID not in the ATT&CK reference table" });
  for (const c of t.csf) if (!k.csf_table.has(c)) unknown.push({ token: c, kind: "csf", reason: "subcategory ID not in the CSF 2.0 reference table" });
  for (const ip of t.ip) if (!k.ips_in_intake.has(ip)) unknown.push({ token: ip, kind: "ip", reason: "IPv4 literal not present in the intake" });
  const attack_not_in_intake = [...t.attack].filter((a) => k.attack_table.has(a) && !k.attack_in_intake.has(a)).sort();
  return {
    pass: unknown.length === 0,
    unknown: unknown.sort((a, b) => a.kind.localeCompare(b.kind) || a.token.localeCompare(b.token)),
    counts: { rule_id: t.rule_id.size, host: t.host.size, attack: t.attack.size, csf: t.csf.size, ip: t.ip.size },
    attack_not_in_intake,
  };
}

/** The first fenced ```json block in a markdown document, or the whole text if it is JSON. */
export function firstJsonBlock(text: string): string | null {
  const m = text.match(/```json\s*\n([\s\S]*?)\n```/);
  if (m) return m[1];
  const trimmed = text.trim();
  return trimmed.startsWith("{") ? trimmed : null;
}
