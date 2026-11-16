// *****************************************************************************
// *Title: Evidence Token Extraction*
// *Author: Kyle Versluis*
// *Description: Token extraction and intake knowledge for the lint and grader.*
// *****************************************************************************

/**
 * Every token kind the standards skill names (hosts, addresses, rule IDs, event IDs, techniques,
 * users, ports, timestamps) plus domains, hashes and alert IDs is pulled out of a document and
 * checked against what the same extraction finds in the intake, or against a reference table.
 * Zero dependencies; everything here is deterministic string work.
 */

// *--- Imports ---*

import { readFileSync } from "node:fs";
import { join } from "node:path";

// *--- Configuration ---*

export const REFERENCES_DIR = join(import.meta.dir, "..", "..", "skills", "standards", "references");
const LINT_REFERENCES = join(import.meta.dir, "..", "..", "skills", "standards", "references", "lint-references.json");

export const KINDS = ["rule_id", "alert_id", "host", "attack", "csf", "ip", "ipv6", "user", "event_id", "port", "domain", "hash", "timestamp"] as const;

// A host prefix is a plain prefix, never a regular expression: it is validated against the
// hostname character set and escaped before it is placed in a regex.
const RE_HOST_PREFIX = /^[a-z0-9-]{1,63}$/;

const HASH_LENGTHS = new Set([32, 40, 64, 128]);
const RE_HEX_BLOB = /\b[0-9a-f]{32,}\b/gi;
const RE_GUID = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;
const RE_MAC = /\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b/gi;
const RE_IPV6_CANDIDATE = /(?<![\w:.])(?:[0-9a-f]{0,4}:){2,7}(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9a-f]{0,4})(?![\w:])/gi;
const RE_DATETIME = /\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:?\d{2})?(?![\w:]|\.\d)/g;
// A date glued to more file-name characters is part of a path, not a timestamp claim.
const RE_DATE = /(?<![\w\/.-])\d{4}-\d{2}-\d{2}(?![\w]|-[A-Za-z0-9]|[.\/][A-Za-z0-9])/g;
const RE_DATE_ANY = /\b\d{4}-\d{2}-\d{2}\b/g;
const RE_TIME = /(?<![\w:.])\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?Z?(?![\w:]|\.\d)/g;
const RE_ALERT_ID = /(?<![\w.])\d{9,11}\.\d{3,9}(?![\w]|\.\d)/g;
const RE_HOST_PORT = /(?<![\w.\/-])((?:\d{1,3}\.){3}\d{1,3}|[A-Za-z][A-Za-z0-9.-]*[A-Za-z0-9]):(\d{1,5})(\/(?:tcp|udp|sctp))?(?![\w:]|\.\d)/gi;
const RE_PORT_PROTO = /(?<![\w.:\/])(\d{1,5})\/(?:tcp|udp|sctp)\b/gi;
const RE_PORT_LIST = /\b(?:ports?|dst_port|src_port|dest_port|dport|sport|destinationport|sourceport)\b\s*[:=]?\s*((?:\d{1,5}(?![\d:.]\d|\d)(?:\s*,\s*(?:and|or)?\s*|\s+(?:and|or)\s+)?)+)/gi;
const RE_IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const RE_DOMAIN = /(?<![\w.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))(?![\w-]|\.[a-z0-9])/g;
const RE_ATTACK = /\bT\d{4}(?:\.\d{3})?\b/g;
// Catches both CSF 2.0 (DE.AE-03) and CSF 1.1 (PR.AC-4) shapes so 1.1 leftovers fail.
const RE_CSF = /\b(?:GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d{1,2}\b/g;
const RE_EVENT_LIST = /\b(?:sysmon|security|event\s*ids?|events?|eids?|event_ids?|eventcodes?|event\s+codes?)\b\s*[:=#]?\s*((?:\d{1,5}(?![\d:.]\d|\d|\/(?:tcp|udp))(?:\s*,\s*(?:and|or)?\s*|\s+(?:and|or)\s+|\s*\/\s*)?)+)/gi;
// Bare four-digit numbers in this block are Windows Security event IDs in SOC prose.
const RE_EVENT_BARE = /(?<![\w.:-])4[6-9]\d\d(?![\w]|[.:]\d)/g;
// Rule IDs are five or six digits; four-digit built-in Wazuh rules share a shape with event IDs and years.
const RE_RULE_ID = /\b\d{5,6}\b/g;
const RE_HOST_KEYWORD = /\b(?:host|hosts|hostname|endpoint|workstation|server|machine|computer)\s+([A-Za-z][A-Za-z0-9-]*\d[A-Za-z0-9-]*)\b/gi;
const RE_HOST_SHAPE = /(?<![\w.\/\\:-])[a-z][a-z-]*[a-z]\d+(?![\w-]|[.\/\\]\w)/g;
const RE_HOST_STOP = /^(?:sha|md|ipv|utf|base|aes|rc|des|ntlmv|smbv|tlsv|sslv|snmpv|http|https|pkcs|rfc|cve|cwe|kb|ms|iso|ecma|es|py|python|node|bun|ver|run|rev|phase|step|round|part|page|line|level|tier|top|gen|win|wow|amd|arm|int|uint|float|ec|office|windows|server|dr|isc|cl)\d+$/i;
const RE_BRIEF_ID = /^(?:T\d+(?:\.\d+)?|DR\d+)$/;
const RE_USER_KEYWORD = /\b(?:user|users|account|accounts|username|targetusername|subjectusername)(?:\s*[:=]\s*|\s+)(`[^`\s]+`|"[^"\s]+"|'[^'\s]+'|[A-Za-z][A-Za-z0-9._$@\\-]*)/gi;
const RE_USER_SHAPE = /[-_.$@\\\d]/;

// Keys that name a host or a user inside a brief's or finding's JSON block. `agent` is not one:
// in casa.finding/v1 it is the CASA agent's own name.
const DOC_HOST_KEYS = /^(?:hosts?|hostnames?|computers?|src_host|dst_host)$/i;
const DOC_USER_KEYS = /^(?:users?|usernames?|user_name|accounts?|target_user|subject_user)$/i;
// Keys that carry typed values inside an intake. In an intake, `agent` is the host.
const INTAKE_HOST_KEYS = /^(?:agent|agent_name|hosts?|hostnames?|computer|src_host|dst_host|source_host|dest_host)$/i;
const INTAKE_USER_KEYS = /^(?:users?|usernames?|user_name|accounts?|account_name|src_user|dst_user|subject_user|target_user|subjectusername|targetusername)$/i;
const INTAKE_RULE_KEYS = /^rule_?id$/i;
const INTAKE_ALERT_KEYS = /^alert_?id$/i;
const INTAKE_EVENT_KEYS = /^event_?id$/i;
const INTAKE_PORT_KEYS = /(?:^|_)port$/i;
const INTAKE_ATTACK_KEYS = /^(?:mitre|mitre_ids?|techniques?)$/i;
const PRODUCER_KEYS = new Set(["schema", "source", "consumer"]);
const HOSTNAME_VALUE = /^[A-Za-z0-9][A-Za-z0-9.-]*$/;

// *--- Types ---*

export type Kind = (typeof KINDS)[number];
export type Tokens = Record<Kind, Set<string>> & { exposure: Set<string> };

/** Naming patterns learned from the intake, used to recognize hosts and users in prose. */
export interface NamePatterns {
  knownHosts: string[];
  hostPrefixes: string[];
  hostStems: string[];
  userPrefixes: string[];
}

export interface LintOptions {
  hostPrefix?: string;
  intakeSha256?: string;
}

interface Stamp { date?: string; time?: string; zone?: string }

export interface Knowledge {
  rule_ids: Set<string>;
  alert_ids: Set<string>;
  hosts: Set<string>;
  users: Set<string>;
  event_ids: Set<string>;
  ports: Set<string>;
  exposures: Set<string>;
  ips: Set<string>;
  ipv6: Set<string>;
  domains: Set<string>;
  hashes: Set<string>;
  stamps: Stamp[];
  dates: Set<string>;
  attack_in_intake: Set<string>;
  intake_text: string;
  patterns: NamePatterns;
}

export interface References {
  attack: Set<string>;
  csf: Set<string>;
  attack_version: string;
  event_ids: Set<string>;
  ports: Set<string>;
  domains: Set<string>;
  tlds: Set<string>;
}

export interface Unknown { token: string; kind: Kind; reason: string }

export interface LintResult {
  pass: boolean;
  unknown: Unknown[];
  counts: Record<Kind, number>;
  beyond_intake: { attack: string[]; event_id: string[]; port: string[] };
  notes: string[];
}

export interface Analysis { result: LintResult; tokens: Tokens; knowledge: Knowledge }

// *--- Helper Functions ---*

/** Escape every regex metacharacter so the string matches itself and nothing else. */
function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** The prefix itself when it is made of hostname characters only; throws otherwise. */
export function assertHostPrefix(prefix: string): string {
  if (!RE_HOST_PREFIX.test(prefix)) throw new Error(`host prefix must match ${RE_HOST_PREFIX}, got ${JSON.stringify(prefix)}`);
  return prefix;
}

function emptyTokens(): Tokens {
  const t = { exposure: new Set<string>() } as Tokens;
  for (const k of KINDS) t[k] = new Set<string>();
  return t;
}

/** Run a global regex over a mutable buffer, hand each match to `fn`, and blank what `fn` returns as consumed. */
function consume(buf: { s: string }, re: RegExp, fn: (m: RegExpExecArray) => string | null): void {
  buf.s = buf.s.replace(re, (...args) => {
    const groups = args.slice(0, -2) as string[];
    const m = Object.assign(groups, { index: args[args.length - 2] as number, input: buf.s }) as unknown as RegExpExecArray;
    const keep = fn(m);
    return keep === null ? m[0] : keep.padEnd(m[0].length, " ");
  });
}

/** Expand an IPv6 address to eight lowercase groups without leading zeros, or null if it is not one. */
export function canonicalIpv6(raw: string): string | null {
  let s = raw.toLowerCase();
  const halves = s.split("::");
  if (halves.length > 2) return null;
  let tail4: number[] = [];
  const v4 = s.match(/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const o = v4.slice(1).map(Number);
    if (o.some((n) => n > 255)) return null;
    tail4 = [(o[0] << 8) | o[1], (o[2] << 8) | o[3]];
    s = s.slice(0, -v4[0].length).replace(/:$/, "");
  }
  const split = (h: string) => (h === "" ? [] : h.split(":"));
  const [head, tail] = s.split("::").map(split) as [string[], string[] | undefined];
  const groups = [...head, ...(tail ?? [])];
  if (!groups.every((g) => /^[0-9a-f]{1,4}$/.test(g))) return null;
  const total = groups.length + tail4.length;
  if (tail === undefined ? total !== 8 : total >= 8) return null;
  const fill = tail === undefined ? [] : Array(8 - total).fill("0");
  const all = [...head, ...fill, ...(tail ?? [])].map((g) => parseInt(g, 16).toString(16));
  return [...all, ...tail4.map((n) => n.toString(16))].join(":");
}

/** Split a timestamp token into its date, time-of-day and zone parts. */
function parseStamp(token: string): Stamp {
  const m = token.match(/^(\d{4}-\d{2}-\d{2})?[T ]?(\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)?(Z|[+-]\d{2}:?\d{2})?$/);
  if (!m) return {};
  return { date: m[1], time: m[2], zone: m[3] };
}

function isUtc(zone: string | undefined): boolean {
  return zone === undefined || zone === "Z" || /^[+-]00:?00$/.test(zone);
}

function minuteOf(time: string): number {
  return Number(time.slice(0, 2)) * 60 + Number(time.slice(3, 5));
}

function validTime(time: string): boolean {
  const [h, m, s] = time.split(":").map((p) => Number(p.slice(0, 2)));
  return h < 24 && m < 60 && (s === undefined || s < 60);
}

/** Every JSON value reachable from `root`, with the key it sits under and that key's parent key. */
function* walk(root: unknown, key = "", parent = ""): Generator<{ key: string; parent: string; value: unknown }> {
  yield { key, parent, value: root };
  if (Array.isArray(root)) for (const v of root) yield* walk(v, key, parent);
  else if (root && typeof root === "object") for (const [k, v] of Object.entries(root)) yield* walk(v, k, key);
}

/** Every fenced json block in a markdown document, or the whole text when it is JSON. */
function jsonBlocks(text: string): unknown[] {
  const out: unknown[] = [];
  const sources = [...text.matchAll(/```json\s*\n([\s\S]*?)\n```/g)].map((m) => m[1]);
  if (sources.length === 0 && text.trim().startsWith("{")) sources.push(text.trim());
  for (const src of sources) {
    try {
      out.push(JSON.parse(src));
    } catch {
      // A malformed block is the grader's concern (brief-json); prose extraction still covers it.
    }
  }
  return out;
}

/** String values found under keys matching `keys`, from strings or arrays of strings. */
function valuesUnder(doc: unknown, keys: RegExp): string[] {
  const out: string[] = [];
  for (const { key, value } of walk(doc)) {
    if (!keys.test(key) || Array.isArray(value)) continue;
    if (typeof value === "string" && value.length > 0) out.push(value);
    else if (typeof value === "number") out.push(String(value));
    else if (value && typeof value === "object" && typeof (value as { name?: unknown }).name === "string") out.push((value as { name: string }).name);
  }
  return out;
}

/** Longest common prefix of the hosts, trimmed to hostname characters. */
function commonPrefix(hosts: string[]): string {
  if (hosts.length < 2) return "";
  let p = hosts[0];
  for (const h of hosts.slice(1)) while (!h.startsWith(p)) p = p.slice(0, -1);
  return RE_HOST_PREFIX.test(p) ? p : "";
}

// *--- Reference Tables ---*

let cachedRefs: References | null = null;

/** The ATT&CK and CSF tables under the standards skill plus the lint's own reference tables. */
export function loadReferences(): References {
  if (cachedRefs) return cachedRefs;
  const attack = JSON.parse(readFileSync(join(REFERENCES_DIR, "attack-techniques.json"), "utf8"));
  const csf = JSON.parse(readFileSync(join(REFERENCES_DIR, "csf-2.0.json"), "utf8"));
  const lr = JSON.parse(readFileSync(LINT_REFERENCES, "utf8"));
  if (typeof lr?.event_ids !== "object" || typeof lr?.service_ports !== "object" || !Array.isArray(lr?.tlds) || !Array.isArray(lr?.reference_domains)) {
    throw new Error(`${LINT_REFERENCES}: missing event_ids, service_ports, tlds or reference_domains`);
  }
  const excluded = new Set<string>([...(lr.excluded_tlds?.file_extensions ?? []), ...(lr.excluded_tlds?.field_path_words ?? [])]);
  cachedRefs = {
    attack: new Set<string>(attack.techniques.map((t: { id: string }) => t.id)),
    csf: new Set<string>(Object.keys(csf.subcategories)),
    attack_version: String(attack.attack_version),
    event_ids: new Set<string>(Object.values(lr.event_ids as Record<string, Record<string, string>>).flatMap((ch) => Object.keys(ch))),
    ports: new Set<string>(Object.keys(lr.service_ports)),
    domains: new Set<string>(lr.reference_domains),
    tlds: new Set<string>((lr.tlds as string[]).filter((t) => !excluded.has(t))),
  };
  return cachedRefs;
}

// *--- Core Logic ---*

/** Every evidence token in `text`, recognized with the naming patterns learned from an intake. */
export function extractTokens(text: string, patterns: Partial<NamePatterns> = {}): Tokens {
  const p: NamePatterns = { knownHosts: [], hostPrefixes: [], hostStems: [], userPrefixes: [], ...patterns };
  for (const prefix of [...p.hostPrefixes, ...p.hostStems]) assertHostPrefix(prefix);
  const known = new Set(p.knownHosts.map((h) => h.toLowerCase()));
  const tlds = loadReferences().tlds;
  const t = emptyTokens();
  const buf = { s: text };

  // Structured hosts and users first: the JSON block declares what each value is.
  for (const doc of jsonBlocks(text)) {
    for (const v of valuesUnder(doc, DOC_HOST_KEYS)) if (HOSTNAME_VALUE.test(v) && !/^[\d.]+$/.test(v)) t.host.add(v.toLowerCase());
    for (const v of valuesUnder(doc, DOC_USER_KEYS)) if (!/\s/.test(v)) t.user.add(v.toLowerCase());
  }

  // Long hex runs, GUIDs and MACs go before any numeric pass so their digits are never read as IDs.
  consume(buf, RE_HEX_BLOB, (m) => {
    if (HASH_LENGTHS.has(m[0].length)) t.hash.add(m[0].toLowerCase());
    return "";
  });
  consume(buf, RE_GUID, () => "");
  consume(buf, RE_MAC, () => "");
  consume(buf, RE_IPV6_CANDIDATE, (m) => {
    if (!m[0].includes("::") && (m[0].match(/:/g) ?? []).length < 7) return null;
    if (!canonicalIpv6(m[0])) return null;
    t.ipv6.add(m[0]);
    return "";
  });

  // Timestamps, then dates, then bare times of day.
  consume(buf, RE_DATETIME, (m) => (t.timestamp.add(m[0]), ""));
  consume(buf, RE_DATE, (m) => (t.timestamp.add(m[0]), ""));
  consume(buf, RE_DATE_ANY, () => "");
  consume(buf, RE_TIME, (m) => {
    if (!validTime(m[0].replace(/Z$/, ""))) return null;
    t.timestamp.add(m[0]);
    return "";
  });
  consume(buf, RE_ALERT_ID, (m) => (t.alert_id.add(m[0]), ""));

  // Ports: host:port exposures, then N/proto, then keyword lists.
  consume(buf, RE_HOST_PORT, (m) => {
    const [whole, host, port, proto] = m;
    const isIp = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host);
    const lower = host.toLowerCase();
    const hostLike = isIp || proto !== undefined || known.has(lower) || /\d/.test(host);
    if (!hostLike || Number(port) > 65535) return null;
    t.port.add(port);
    if (!isIp) {
      t.exposure.add(`${lower}:${port}`);
      if (!lower.includes(".")) t.host.add(lower);
    }
    return whole.slice(0, host.length);
  });
  consume(buf, RE_PORT_PROTO, (m) => {
    if (Number(m[1]) > 65535) return null;
    t.port.add(m[1]);
    return "";
  });
  consume(buf, RE_PORT_LIST, (m) => {
    for (const n of m[1].match(/\d+/g) ?? []) if (Number(n) <= 65535) t.port.add(n);
    return m[0].slice(0, m[0].length - m[1].length);
  });
  consume(buf, RE_IPV4, (m) => (t.ip.add(m[0]), ""));

  // Domains are lowercase dotted names with a recognized TLD; an FQDN is a domain, not a host.
  consume(buf, RE_DOMAIN, (m) => {
    if (!tlds.has(m[2])) return null;
    t.domain.add(m[1]);
    return "";
  });

  consume(buf, RE_ATTACK, (m) => (t.attack.add(m[0]), ""));
  consume(buf, RE_CSF, (m) => (t.csf.add(m[0]), ""));
  consume(buf, RE_EVENT_LIST, (m) => {
    for (const n of m[1].match(/\d+/g) ?? []) t.event_id.add(String(Number(n)));
    return m[0].slice(0, m[0].length - m[1].length);
  });
  consume(buf, RE_EVENT_BARE, (m) => (t.event_id.add(m[0]), ""));
  for (const m of buf.s.matchAll(RE_RULE_ID)) t.rule_id.add(m[0]);

  // Hosts in prose: learned prefixes and stems, a keyword before the name, or a letters-then-digits name.
  for (const prefix of p.hostPrefixes) for (const m of buf.s.matchAll(new RegExp(`\\b${escapeRegExp(prefix)}[a-z0-9-]+\\b`, "gi"))) t.host.add(m[0].toLowerCase());
  for (const stem of p.hostStems) for (const m of buf.s.matchAll(new RegExp(`\\b${escapeRegExp(stem)}\\d+\\b`, "gi"))) t.host.add(m[0].toLowerCase());
  for (const m of buf.s.matchAll(RE_HOST_KEYWORD)) if (!RE_BRIEF_ID.test(m[1]) && !RE_HOST_STOP.test(m[1])) t.host.add(m[1].toLowerCase());
  for (const m of buf.s.matchAll(RE_HOST_SHAPE)) if (!RE_HOST_STOP.test(m[0])) t.host.add(m[0]);
  for (const h of known) if (new RegExp(`(?<![\\w.-])${escapeRegExp(h)}(?![\\w-])`, "i").test(buf.s)) t.host.add(h);

  // Users: a keyword before an account-shaped name (or a quoted one), or a learned account prefix.
  for (const m of buf.s.matchAll(RE_USER_KEYWORD)) {
    const quoted = /^[`"']/.test(m[1]);
    const name = quoted ? m[1].slice(1, -1) : m[1].replace(/[.\\]+$/, "");
    if (quoted || RE_USER_SHAPE.test(name)) t.user.add(name.toLowerCase());
  }
  for (const prefix of p.userPrefixes) for (const m of buf.s.matchAll(new RegExp(`(?<![\\w.-])${escapeRegExp(prefix)}[a-z0-9._$-]*[a-z0-9$]`, "gi"))) t.user.add(m[0].toLowerCase());
  return t;
}

/** What the intake carries, per token kind, plus the naming patterns learned from it. */
export function intakeKnowledge(intake: unknown, opts: LintOptions = {}): Knowledge {
  const k: Knowledge = {
    rule_ids: new Set(), alert_ids: new Set(), hosts: new Set(), users: new Set(), event_ids: new Set(), ports: new Set(),
    exposures: new Set(), ips: new Set(), ipv6: new Set(), domains: new Set(), hashes: new Set(), stamps: [], dates: new Set(),
    attack_in_intake: new Set(), intake_text: JSON.stringify(intake),
    patterns: { knownHosts: [], hostPrefixes: [], hostStems: [], userPrefixes: [] },
  };

  // Typed fields first: these decide rule IDs and alert IDs on their own.
  for (const { key, parent, value } of walk(intake)) {
    const scalar = typeof value === "string" || typeof value === "number" ? String(value) : null;
    if (scalar !== null && (INTAKE_RULE_KEYS.test(key) || (key === "id" && parent === "rule"))) k.rule_ids.add(scalar);
    if (scalar !== null && INTAKE_ALERT_KEYS.test(key)) k.alert_ids.add(scalar);
    if (scalar !== null && INTAKE_EVENT_KEYS.test(key)) k.event_ids.add(String(Number(scalar)));
    if (scalar !== null && INTAKE_PORT_KEYS.test(key)) k.ports.add(scalar);
    if (typeof value === "string" && INTAKE_ATTACK_KEYS.test(key)) k.attack_in_intake.add(value);
    if (value && typeof value === "object" && !Array.isArray(value)) {
      const o = value as Record<string, unknown>;
      const host = Object.keys(o).find((x) => INTAKE_HOST_KEYS.test(x));
      const port = Object.keys(o).find((x) => INTAKE_PORT_KEYS.test(x));
      if (host && port && typeof o[host] === "string" && (typeof o[port] === "number" || typeof o[port] === "string")) k.exposures.add(`${(o[host] as string).toLowerCase()}:${o[port]}`);
    }
  }
  for (const h of valuesUnder(intake, INTAKE_HOST_KEYS)) k.hosts.add(h.toLowerCase());
  for (const u of valuesUnder(intake, INTAKE_USER_KEYS)) k.users.add(u.toLowerCase());

  const hosts = [...k.hosts];
  if (opts.hostPrefix !== undefined) assertHostPrefix(opts.hostPrefix);
  // A learned prefix shorter than three characters would match ordinary words.
  const learned = commonPrefix(hosts);
  const prefixes = [...(opts.hostPrefix ? [opts.hostPrefix] : []), ...(learned.length >= 3 ? [learned] : [])];
  k.patterns = {
    knownHosts: hosts,
    hostPrefixes: [...new Set(prefixes)],
    hostStems: [...new Set(hosts.map((h) => h.match(/^([a-z][a-z0-9-]*[a-z-])\d+$/)?.[1]).filter((s): s is string => !!s && RE_HOST_PREFIX.test(s) && s.length >= 2))],
    userPrefixes: [...new Set([...k.users].map((u) => u.match(/^([a-z0-9]{2,}[-_.])/)?.[1]).filter((s): s is string => !!s))],
  };

  // Then the same extraction the document gets, over every intake string except producer metadata.
  for (const { key, parent, value } of walk(intake)) {
    if (typeof value !== "string" || (parent === "" && PRODUCER_KEYS.has(key))) continue;
    const t = extractTokens(value, k.patterns);
    for (const h of t.host) k.hosts.add(h);
    for (const u of t.user) k.users.add(u);
    for (const e of t.event_id) k.event_ids.add(e);
    for (const p of t.port) k.ports.add(p);
    for (const x of t.exposure) k.exposures.add(x);
    for (const ip of t.ip) k.ips.add(ip);
    for (const ip of t.ipv6) k.ipv6.add(canonicalIpv6(ip) as string);
    for (const d of t.domain) k.domains.add(d);
    for (const h of t.hash) k.hashes.add(h);
    for (const a of t.attack) k.attack_in_intake.add(a);
    for (const ts of t.timestamp) {
      const st = parseStamp(ts);
      k.stamps.push(st);
      if (st.date) k.dates.add(st.date);
    }
  }
  return k;
}

/** True when a timestamp token is an intake time, at the precision the token gives. */
function stampTraces(token: string, k: Knowledge): boolean {
  const st = parseStamp(token);
  if (!st.date && !st.time) return false;
  if (!isUtc(st.zone)) return k.intake_text.includes(token);
  if (!st.time) return k.dates.has(st.date as string);
  return k.stamps.some((c) => {
    if (!c.time || (st.date && c.date !== st.date)) return false;
    const want = st.time as string;
    if (want.length > 5) return c.time.startsWith(want);
    // A minute-precision time is an intake time rounded down or up to the minute.
    const floor = minuteOf(c.time);
    const ceil = floor + (/^\d{2}:\d{2}:00(?:\.0+)?$/.test(c.time) || c.time.length === 5 ? 0 : 1);
    return minuteOf(want) === floor || minuteOf(want) === ceil;
  });
}

/** Producer metadata (schema id, source, consumer) is not a citation; strip it before extraction. */
export function stripProducerStrings(text: string, intake: unknown): string {
  const meta = intake as { schema?: unknown; source?: unknown; consumer?: unknown };
  let out = text;
  for (const v of [meta.schema, meta.source, meta.consumer]) if (typeof v === "string" && v.length > 0) out = out.split(v).join(" ");
  return out;
}

/** Remove the brief's own record of the intake hash, which is provenance, and note a stale one. */
function stripIntakeHash(text: string, opts: LintOptions): { text: string; notes: string[] } {
  const notes: string[] = [];
  for (const doc of jsonBlocks(text)) {
    const recorded = (doc as { intake?: { sha256?: unknown } })?.intake?.sha256;
    if (typeof recorded !== "string" || recorded.length === 0) continue;
    if (opts.intakeSha256 && recorded.toLowerCase() !== opts.intakeSha256.toLowerCase()) {
      notes.push(`intake.sha256 ${recorded} is not the hash of this intake file (${opts.intakeSha256}); the brief was written against another version of it`);
    }
    const keyed = new RegExp(`("sha256"\\s*:\\s*")${escapeRegExp(recorded)}"`);
    return { text: text.replace(keyed, '$1"'), notes };
  }
  return { text, notes };
}

/** Extract every token from a document and check each against the intake and the reference tables. */
export function analyze(text: string, intake: unknown, opts: LintOptions = {}): Analysis {
  const k = intakeKnowledge(intake, opts);
  const refs = loadReferences();
  const stripped = stripIntakeHash(stripProducerStrings(text, intake), opts);
  const t = extractTokens(stripped.text, k.patterns);
  const unknown: Unknown[] = [];
  const miss = (kind: Kind, token: string, reason: string) => unknown.push({ token, kind, reason });

  for (const r of t.rule_id) if (!k.rule_ids.has(r)) miss("rule_id", r, "not a detection rule_id in the intake");
  for (const a of t.alert_id) if (!k.alert_ids.has(a)) miss("alert_id", a, "not an alert_id in the intake");
  for (const h of t.host) if (!k.hosts.has(h)) miss("host", h, "host not named in the intake");
  for (const a of t.attack) if (!refs.attack.has(a)) miss("attack", a, "technique ID not in the ATT&CK reference table");
  for (const c of t.csf) if (!refs.csf.has(c)) miss("csf", c, "subcategory ID not in the CSF 2.0 reference table");
  for (const ip of t.ip) if (!k.ips.has(ip)) miss("ip", ip, "IPv4 literal not present in the intake");
  for (const ip of t.ipv6) if (!k.ipv6.has(canonicalIpv6(ip) as string)) miss("ipv6", ip, "IPv6 literal not present in the intake");
  for (const u of t.user) if (!k.users.has(u)) miss("user", u, "user not named in the intake");
  for (const e of t.event_id) if (!k.event_ids.has(e) && !refs.event_ids.has(e)) miss("event_id", e, "event ID neither in the intake nor in the event ID reference table");
  for (const p of t.port) if (!k.ports.has(p) && !refs.ports.has(p)) miss("port", p, "port neither in the intake nor in the service port reference table");
  for (const x of t.exposure) if (!k.exposures.has(x)) miss("port", x, "exposure (host and port together) not in the intake");
  for (const d of t.domain) if (!k.domains.has(d) && !refs.domains.has(d)) miss("domain", d, "domain not present in the intake");
  for (const h of t.hash) if (!k.hashes.has(h)) miss("hash", h, "hash not present in the intake");
  for (const s of t.timestamp) if (!stampTraces(s, k)) miss("timestamp", s, "time or date not present in the intake at this precision");

  const counts = Object.fromEntries(KINDS.map((kind) => [kind, t[kind].size])) as Record<Kind, number>;
  const result: LintResult = {
    pass: unknown.length === 0,
    unknown: unknown.sort((a, b) => a.kind.localeCompare(b.kind) || a.token.localeCompare(b.token)),
    counts,
    beyond_intake: {
      attack: [...t.attack].filter((a) => refs.attack.has(a) && !k.attack_in_intake.has(a)).sort(),
      event_id: [...t.event_id].filter((e) => refs.event_ids.has(e) && !k.event_ids.has(e)).sort((a, b) => Number(a) - Number(b)),
      port: [...t.port].filter((p) => refs.ports.has(p) && !k.ports.has(p)).sort((a, b) => Number(a) - Number(b)),
    },
    notes: stripped.notes,
  };
  return { result, tokens: t, knowledge: k };
}

/** Every token in `text` must trace to the intake or to a reference table. */
export function lint(text: string, intake: unknown, opts: LintOptions = {}): LintResult {
  return analyze(text, intake, opts).result;
}

/** The first fenced ```json block in a markdown document, or the whole text if it is JSON. */
export function firstJsonBlock(text: string): string | null {
  const m = text.match(/```json\s*\n([\s\S]*?)\n```/);
  if (m) return m[1];
  const trimmed = text.trim();
  return trimmed.startsWith("{") ? trimmed : null;
}
