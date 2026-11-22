#!/usr/bin/env bun
// *****************************************************************************
// *Title: Wazuh Intake Producer*
// *Author: Kyle Versluis*
// *Description: Turns Wazuh indexer alerts into a soc-intake/v3 artifact.*
// *****************************************************************************

/**
 * Usage:
 *   bun intake/producers/wazuh.ts --replay alerts.jsonl [--out intake.json | --stdout]
 *   WAZUH_INDEXER_URL=... WAZUH_INDEXER_USER=... WAZUH_INDEXER_PASS=... \
 *     bun intake/producers/wazuh.ts [--out intake.json]
 *
 * Exit codes: 0 success, 1 run failure, 2 bad usage. Messages go to stderr; the
 * intake goes to --out or stdout. Live mode never accepts a password flag.
 */

// *--- Imports ---*

import { readFileSync, statSync, writeFileSync } from "node:fs";
import { validateIntake } from "../Validate.ts";
import { instantMicros, utcDate, windowDays } from "../lib/semantic.ts";

// *--- Configuration ---*

const SCHEMA = "talonsoclab.soc-intake/v3";
const CONSUMER = "casa-ai-agent (github.com/ktalons/casa-ai-agent)";
const NOTE = "Deterministic intake. Reasoning happens in CASA, not here.";
const INDEX = "wazuh-alerts-*";
const REQUEST_TIMEOUT_MS = 30_000;
// The indexer refuses a search past this many hits (index.max_result_window default).
const MAX_RESULT_WINDOW = 10_000;
// Below this length a password is likely to occur in ordinary alert text.
const MIN_PASSWORD_LENGTH = 8;
// 2001:db8::/32 and 192.0.2.0/24, the documentation ranges aliases are drawn from.
const DOC6_BASE = 0x20010db8n << 96n;
const DOC4_BASE = 0xc0000200;
// The shortest base64 run read; most shorter runs are plain words.
const BLOB_MIN = 16;
const SYSMON_GROUP: Record<string, string> = { "1": "process_create", "3": "network_connect", "11": "file_create", "13": "registry_value_set", "22": "dns_query" };
const LOGON_EVENTS = new Set(["4624", "4625", "4634"]);
const SURICATA_EVENTS = new Set(["alert", "anomaly", "dns", "http", "tls", "flow", "fileinfo", "ssh", "smb"]);
const VALUE_FLAGS = new Set(["--replay", "--out", "--min-level", "--include-rules", "--cap", "--lookback", "--window-end", "--alias", "--recon-delta", "--source", "--url", "--password-file", "--ca-file"]);
const BOOL_FLAGS = new Set(["--stdout", "--redact"]);
const USAGE = `usage: bun intake/producers/wazuh.ts [--replay <file.jsonl|file.json>] [options]
  --out <path> | --stdout   where the intake goes (default: stdout)
  --min-level <n>           level floor, 0 to 16 (default 12)
  --include-rules <a,b>     rule IDs admitted below the floor
  --cap <n>                 most detections kept (default 200)
  --lookback <24h|3d>       window length (default 24h)
  --window-end <instant>    replay only: window end (default: newest alert, rounded up)
  --redact                  rewrite private addresses, SIDs and GUIDs
  --alias <host>=<alias>    replace a literal under --redact (repeatable)
  --recon-delta <file.json> {markdown, baseline, changes}
  --source <name>           source field (default wazuh)
live mode (no --replay):
  --url <https url> | WAZUH_INDEXER_URL
  WAZUH_INDEXER_USER, and the password from WAZUH_INDEXER_PASS or --password-file <path>
  --ca-file <path> | WAZUH_INDEXER_CA`;

// Private ranges, one source for every form they take.
const V4_PRIVATE = String.raw`(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])|169\.254)\.\d{1,3}\.\d{1,3}`;
const V6_PRIVATE = "(?:fe[89ab][0-9a-f]|f[cd][0-9a-f]{2})";
// A digit or digit-dot before, or a digit or dot-digit after, means it is not an address.
// One pass for plain addresses and reverse names, so a reverse name is taken whole and both are
// numbered in the order they appear.
const V4_ANY = new RegExp(String.raw`(?<!\d)(?<!\d\.)(?:(\d{1,3}(?:\.\d{1,3}){3})(\.in-addr\.arpa)|(${V4_PRIVATE}))(?!\d)(?!\.\d)`, "gi");
const V4_PORTED = new RegExp(String.raw`(?<!\d)(?<!\d\.)(${V4_PRIVATE})(?!\d)`, "g");
const V4_ARPA = /(?<!\d)(?<!\d\.)(\d{1,3}(?:\.\d{1,3}){3})\.in-addr\.arpa/gi;
const IS_V4_PRIVATE = new RegExp(`^${V4_PRIVATE}$`);
const V6_ADDR = new RegExp(String.raw`(?<![0-9a-f:])(${V6_PRIVATE}:(?=[0-9a-f:])[0-9a-f:]*(?:\d{1,3}(?:\.\d{1,3}){3})?)(?:%[A-Za-z0-9_~-]+)?(?![0-9a-f:]|\.\d)`, "gi");
const V6_GLUED = new RegExp(`(?<=[0-9a-f:])${V6_PRIVATE}:(?=[0-9a-f:])`, "gi");
// A full ip6.arpa nibble name: 32 nibbles, lowest first.
const ARPA6 = /((?:[0-9a-f]\.){32})(ip6\.arpa)/gi;
// A ::ffff: (mapped) or 64:ff9b:: (NAT64) address ending in hex; the value decides which. Each open
// stretch is capped at 39 characters, the longest IPv6 text, so a long run fails fast.
const V6_MAPPED = /(?<![0-9a-f:])([0-9a-f:]{0,39}:(?:ffff|ff9b:[0-9a-f:]{0,39}):[0-9a-f]{1,4}:[0-9a-f]{1,4})(?:%[A-Za-z0-9_~-]+)?(?![0-9a-f:]|\.\d)/gi;
// The last 32 bits of a ::ffff: or ::ffff:0: form, and of any form under 64:ff9b:, in hex or dotted.
const V4_IN_MAPPED = /:ffff:(?:0{1,4}:)?(?:([0-9a-f]{1,4}):([0-9a-f]{1,4})|(\d{1,3}(?:\.\d{1,3}){3}))(?![0-9a-f:]|\.\d)/gi;
const V4_IN_NAT64 = /(?<![0-9a-f:])(?:(?!64:ff9b:)[0-9a-f:])*64:ff9b:[0-9a-f:]*?:(?:([0-9a-f]{1,4}):([0-9a-f]{1,4})|(\d{1,3}(?:\.\d{1,3}){3}))(?![0-9a-f:]|\.\d)/gi;
const BLOB = new RegExp(`[A-Za-z0-9+/]{${BLOB_MIN},}={0,2}`, "g");
const SID = /(S-1-5-21-)(\d+)-(\d+)-(\d+)(?!\d)/gi;
const GUID_TYPED = /^\{([0-9a-f]{8})-/i;
// An alias begins and ends with a letter g to z, so text beside it never reads as part of an address.
const ALIAS_EDGES = /^[g-z](?:.*[g-z])?$/i;
const SAFE_TOKEN = /^[^\s=]{1,128}$/;
const SAFE_ALIAS = /^[A-Za-z0-9._-]{1,128}$/;

// *--- Types ---*

type Obj = Record<string, unknown>;
type FetchInit = {
  method: string;
  headers: Record<string, string>;
  body: string;
  signal: AbortSignal;
  redirect: "error";
  tls: { rejectUnauthorized: true; ca?: string };
};
export type FetchFn = (url: string, init: FetchInit) => Promise<Response>;

export interface Deps {
  fetch: FetchFn;
  env: Record<string, string | undefined>;
  now: () => number;
  stdout: (s: string) => void;
  stderr: (s: string) => void;
}

export interface Options {
  replay?: string;
  out?: string;
  minLevel: number;
  include: string[];
  cap: number;
  lookbackHours: number;
  windowEnd?: bigint;
  redact: boolean;
  aliases: [string, string][];
  reconDelta?: string;
  source: string;
  url?: string;
  passwordFile?: string;
  caFile?: string;
}

interface Rec {
  id: string | null;
  ts: string;
  micros: bigint;
  src: Obj;
  level: number | null;
  ruleId: string | null;
  agent: string | null;
  description: string | null;
}

interface Det { micros: bigint; det: Obj }
interface Pipeline { collector_ok: boolean; agents_reporting: number; last_event_seen: string | null }
interface Recon { markdown: string; baseline: string | null; changes: unknown[] }

class UsageError extends Error {}
class RunError extends Error {}

// *--- Helper Functions ---*

const obj = (v: unknown): Obj | null => (typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Obj) : null);

function at(v: unknown, ...path: string[]): unknown {
  let cur = v;
  for (const k of path) {
    const o = obj(cur);
    if (!o) return undefined;
    cur = o[k];
  }
  return cur;
}

/** A non-empty string, or null: numbers and booleans become text, "-" and blanks mean null. */
function text(v: unknown): string | null {
  const s = typeof v === "number" || typeof v === "boolean" ? String(v) : v;
  if (typeof s !== "string") return null;
  const t = s.trim();
  return t === "" || t === "-" ? null : s;
}

/** A strict non-negative integer from a number or a string of digits. */
function int(v: unknown): number | null {
  if (typeof v === "number") return Number.isSafeInteger(v) && v >= 0 ? v : null;
  return typeof v === "string" && /^\d{1,15}$/.test(v) ? Number(v) : null;
}

const port = (v: unknown): number | null => {
  const n = int(v);
  return n !== null && n <= 65535 ? n : null;
};
const pid = int;

function bool(v: unknown): boolean | null {
  if (typeof v === "boolean") return v;
  const s = text(v)?.toLowerCase();
  return s === "true" ? true : s === "false" ? false : null;
}

function guid(v: unknown): string | null {
  const s = text(v)?.trim();
  if (!s) return null;
  const bare = s.replace(/^\{|\}$/g, "");
  return /^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$/.test(bare) ? `{${bare}}` : null;
}

function pick<T>(cands: unknown[], conv: (v: unknown) => T | null): T | null {
  for (const c of cands) {
    const r = conv(c);
    if (r !== null) return r;
  }
  return null;
}

function strList(v: unknown): string[] {
  const items = Array.isArray(v) ? v : v === undefined ? [] : [v];
  return items.map(text).filter((s): s is string => s !== null);
}

/** Wazuh writes +0000; the schema wants +00:00. Digits beyond microseconds are cut. */
function normalizeInstant(s: string): string {
  return s.replace(/([+-]\d{2})(\d{2})$/, "$1:$2").replace(/(\.\d{6})\d+/, "$1");
}

function fmtMicros(m: bigint): string {
  const base = new Date(Number(m / 1_000_000n) * 1000).toISOString().slice(0, 19);
  const frac = (m % 1_000_000n).toString().padStart(6, "0").replace(/0+$/, "");
  return `${base}${frac ? `.${frac}` : ""}Z`;
}

const ceilSecond = (m: bigint): bigint => ((m + 999_999n) / 1_000_000n) * 1_000_000n;
const hostOf = (u: URL): string => u.host;

function errCode(e: unknown): string {
  const code = (e as { code?: unknown } | null)?.code;
  if (typeof code === "string" && /^[A-Za-z_]{1,40}$/.test(code)) return code;
  return e instanceof Error && /^[A-Za-z]{1,40}$/.test(e.name) ? e.name : "error";
}

// *--- Field Mapping ---*

function parseRecord(hit: unknown): Rec | null {
  const h = obj(hit);
  if (!h) return null;
  const src = obj(h._source) ?? h;
  const raw = text(src["@timestamp"]) ?? text(src.timestamp);
  if (raw === null) return null;
  const ts = normalizeInstant(raw);
  const micros = instantMicros(ts);
  if (micros === null) return null;
  const level = int(at(src, "rule", "level"));
  return {
    id: text(src.id) ?? text(h._id),
    ts,
    micros,
    src,
    level: level !== null && level <= 16 ? level : null,
    ruleId: text(at(src, "rule", "id")),
    agent: text(at(src, "agent", "name")),
    description: text(at(src, "rule", "description")),
  };
}

/** A record with every field a detection needs. */
type UsableRec = Rec & { id: string; level: number; ruleId: string; agent: string; description: string };

const usable = (r: Rec): r is UsableRec => r.id !== null && r.level !== null && r.ruleId !== null && r.agent !== null && r.description !== null;

function hashes(v: unknown): Obj | null {
  const s = text(v);
  if (s === null) return null;
  const out: Obj = { md5: null, sha1: null, sha256: null, imphash: null };
  const want: Record<string, [string, number]> = { MD5: ["md5", 32], SHA1: ["sha1", 40], SHA256: ["sha256", 64], IMPHASH: ["imphash", 32] };
  for (const part of s.split(",")) {
    const i = part.indexOf("=");
    const spec = i < 0 ? undefined : want[part.slice(0, i).trim().toUpperCase()];
    const val = part.slice(i + 1).trim().toLowerCase();
    if (spec && new RegExp(`^[0-9a-f]{${spec[1]}}$`).test(val)) out[spec[0]] = val;
  }
  return out;
}

/** The one Sysmon group for the event, or null when the channel or a required field is missing. */
function sysmonBlock(ed: Obj, channel: string | null, eventId: string | null): Obj | null {
  if (!channel || !/sysmon/i.test(channel) || eventId === null || !Object.hasOwn(SYSMON_GROUP, eventId)) return null;
  const image = text(ed.image);
  if (image === null) return null;
  const base = { image, process_id: pid(ed.processId), process_guid: guid(ed.processGuid), user: text(ed.user) };
  switch (eventId) {
    case "1":
      return {
        process_create: {
          image, command_line: text(ed.commandLine), parent_image: text(ed.parentImage), parent_command_line: text(ed.parentCommandLine),
          process_id: base.process_id, parent_process_id: pid(ed.parentProcessId), process_guid: base.process_guid,
          parent_process_guid: guid(ed.parentProcessGuid), user: base.user, integrity_level: text(ed.integrityLevel),
          current_directory: text(ed.currentDirectory), hashes: hashes(ed.hashes),
        },
      };
    case "3":
      return { network_connect: { ...base, initiated: bool(ed.initiated), source_hostname: text(ed.sourceHostname), destination_hostname: text(ed.destinationHostname) } };
    case "11": {
      const target = text(ed.targetFilename);
      return target === null ? null : { file_create: { ...base, target_filename: target } };
    }
    case "13": {
      const target = text(ed.targetObject);
      return target === null ? null : { registry_value_set: { ...base, event_type: text(ed.eventType), target_object: target, details: text(ed.details) } };
    }
    default: {
      const name = text(ed.queryName);
      return name === null ? null : { dns_query: { ...base, query_name: name, query_status: text(ed.queryStatus), query_results: text(ed.queryResults) } };
    }
  }
}

function suricataBlock(data: Obj): Obj | null {
  const eventType = text(data.event_type);
  if (eventType === null || !SURICATA_EVENTS.has(eventType)) return null;
  const sev = int(at(data, "alert", "severity"));
  const action = text(at(data, "alert", "action"));
  const flow = data.flow_id;
  return {
    event_type: eventType,
    signature: text(at(data, "alert", "signature")),
    category: text(at(data, "alert", "category")),
    severity: sev !== null && sev >= 1 && sev <= 4 ? sev : null,
    action: action === "allowed" || action === "blocked" ? action : null,
    // A JSON number past 2^53 has already lost digits, so only a digit string or a safe integer is kept.
    flow_id: typeof flow === "string" ? (/^\d{1,20}$/.test(flow) ? flow : null) : typeof flow === "number" && Number.isSafeInteger(flow) && flow >= 0 ? String(flow) : null,
    app_proto: text(data.app_proto),
    http_hostname: text(at(data, "http", "hostname")),
    http_url: text(at(data, "http", "url")),
    http_user_agent: text(at(data, "http", "http_user_agent")),
    tls_sni: text(at(data, "tls", "sni")),
    dns_rrname: text(at(data, "dns", "rrname")),
  };
}

/** Maps one usable record to a v3 detection. */
export function toDetection(r: Rec): Obj {
  const data = obj(at(r.src, "data")) ?? {};
  const ed = obj(at(data, "win", "eventdata")) ?? {};
  const rawId = text(at(data, "win", "system", "eventID"));
  const eventId = rawId !== null && /^\d{1,5}$/.test(rawId) ? rawId : null;
  const sigId = text(at(data, "alert", "signature_id"));
  const suricataEngine = sigId !== null && text(data.event_type) === "alert";
  const engine = suricataEngine
    ? { name: "suricata", rule_id: sigId, rev: int(at(data, "alert", "rev")) }
    : { name: "wazuh", rule_id: r.ruleId, rev: null };
  const proto = pick([data.proto, ed.protocol], (v) => {
    const p = text(v)?.toLowerCase();
    return p !== undefined && /^[a-z0-9-]{1,16}$/.test(p) ? p : null;
  });
  const logon = eventId !== null && LOGON_EVENTS.has(eventId) ? int(ed.logonType) : null;
  return {
    level: r.level,
    description: r.description,
    rule_id: r.ruleId,
    agent: r.agent,
    mitre: strList(at(r.src, "rule", "mitre", "id")).filter((m) => /^T\d{4}(\.\d{3})?$/.test(m)),
    timestamp: r.ts,
    alert_id: r.id,
    tactic: strList(at(r.src, "rule", "mitre", "tactic")),
    groups: strList(at(r.src, "rule", "groups")),
    engine,
    src_ip: pick([data.srcip, data.src_ip, ed.ipAddress, ed.sourceIp], text),
    src_port: pick([data.srcport, data.src_port, ed.ipPort, ed.sourcePort], port),
    dst_ip: pick([data.dstip, data.dest_ip, ed.destinationIp], text),
    dst_port: pick([data.dstport, data.dest_port, ed.destinationPort], port),
    proto,
    subject_user: pick([ed.subjectUserName, data.srcuser], text),
    target_user: pick([ed.targetUserName, data.dstuser], text),
    logon_type: logon !== null && logon <= 13 ? logon : null,
    event_id: eventId,
    sysmon: suricataEngine ? null : sysmonBlock(ed, text(at(data, "win", "system", "channel")), eventId),
    suricata: suricataBlock(data),
  };
}

// *--- Options ---*

function numFlag(flag: string, v: string, min: number, max: number): number {
  if (!/^\d{1,5}$/.test(v) || Number(v) < min || Number(v) > max) throw new UsageError(`${flag} needs a whole number from ${min} to ${max}`);
  return Number(v);
}

/** Parses argv into Options; throws UsageError. Neither a flag name nor its value is ever echoed. */
export function parseArgs(argv: string[]): Options {
  const o: Options = { minLevel: 12, include: [], cap: 200, lookbackHours: 24, redact: false, aliases: [], source: "wazuh" };
  let stdout = false;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const eq = arg.indexOf("=");
    const name = arg.startsWith("--") && eq > 0 ? arg.slice(0, eq) : arg;
    if (name === "--password" || name === "--pass") throw new UsageError("the --password flag is not accepted: set WAZUH_INDEXER_PASS or use --password-file <path>");
    if (name === "--help" || name === "-h") throw new UsageError(USAGE);
    if (BOOL_FLAGS.has(name) && eq < 0) {
      if (name === "--stdout") stdout = true;
      else o.redact = true;
      continue;
    }
    if (!VALUE_FLAGS.has(name)) throw new UsageError(name.startsWith("--") ? "unknown flag" : "unexpected argument");
    let value: string | undefined;
    if (name !== arg) value = arg.slice(eq + 1);
    else {
      value = argv[++i];
      if (value === undefined || value.startsWith("--")) throw new UsageError(`${name} needs a value`);
    }
    switch (name) {
      case "--replay": o.replay = value; break;
      case "--out": o.out = value; break;
      case "--min-level": o.minLevel = numFlag(name, value, 0, 16); break;
      case "--cap": o.cap = numFlag(name, value, 1, MAX_RESULT_WINDOW); break;
      case "--source": if (value.trim() === "") throw new UsageError("--source needs a name"); o.source = value; break;
      case "--recon-delta": o.reconDelta = value; break;
      case "--url": o.url = value; break;
      case "--password-file": o.passwordFile = value; break;
      case "--ca-file": o.caFile = value; break;
      case "--include-rules": {
        const ids = value.split(",").map((s) => s.trim());
        if (ids.some((s) => s === "")) throw new UsageError("--include-rules needs a comma list of rule IDs");
        o.include = [...new Set(ids)];
        break;
      }
      case "--lookback": {
        const m = /^(\d{1,4})([hd])$/.exec(value);
        const hours = m ? Number(m[1]) * (m[2] === "d" ? 24 : 1) : 0;
        if (hours < 1 || hours > 8760) throw new UsageError("--lookback needs 1h to 8760h, written like 24h or 3d");
        o.lookbackHours = hours;
        break;
      }
      case "--window-end": {
        const m = instantMicros(value);
        if (m === null) throw new UsageError("--window-end needs an ISO 8601 instant");
        o.windowEnd = m;
        break;
      }
      case "--alias": {
        const parts = value.split("=");
        if (parts.length !== 2 || !SAFE_TOKEN.test(parts[0]) || !SAFE_ALIAS.test(parts[1])) throw new UsageError("--alias needs host=alias, the alias holding letters, digits, dot, dash or underscore");
        o.aliases.push([parts[0], parts[1]]);
        break;
      }
    }
  }
  if (stdout && o.out !== undefined) throw new UsageError("--out and --stdout cannot be combined");
  if (o.aliases.length && !o.redact) throw new UsageError("--alias needs --redact");
  if (o.replay === undefined && o.windowEnd !== undefined) throw new UsageError("--window-end applies to replay only");
  if (o.replay !== undefined && (o.url !== undefined || o.passwordFile !== undefined || o.caFile !== undefined)) throw new UsageError("--url, --password-file and --ca-file apply to live mode only");
  checkAliases(o.aliases);
  return o;
}

function checkAliases(aliases: [string, string][]): void {
  const probe = makeRedactor([], [], emptyTaken());
  aliases.forEach(([from, to], i) => {
    if (!ALIAS_EDGES.test(to)) throw new UsageError(`--alias #${i + 1}: the alias must begin and end with a letter g to z`);
    if (probe(to) !== to || to.search(SID) !== -1 || /(?<![0-9a-z])[0-9a-f]{8}(?=-)/i.test(to)) throw new UsageError(`--alias #${i + 1}: the alias looks like an address, SID or GUID`);
    aliases.forEach(([f2, t2], j) => {
      if (j === i) return;
      if (f2.toLowerCase() === from.toLowerCase() || t2.toLowerCase() === to.toLowerCase()) throw new UsageError(`--alias #${i + 1} repeats a source or an alias of --alias #${j + 1}`);
    });
    if (aliases.some(([f]) => to.toLowerCase().includes(f.toLowerCase()))) throw new UsageError(`--alias #${i + 1}: the alias holds an alias source`);
  });
}

// *--- Redaction ---*

interface Taken { v4: Set<number>; v6: Set<number>; sid: Set<number> }
const emptyTaken = (): Taken => ({ v4: new Set(), v6: new Set(), sid: new Set() });

function alloc(taken: Set<number>, max: number, what: string): number {
  for (let n = 1; n <= max; n++) {
    if (!taken.has(n)) {
      taken.add(n);
      return n;
    }
  }
  throw new RunError(`more than ${max} distinct ${what}, and an alias is never reused`);
}

function v4Value(d: string): number | null {
  const o = d.split(".").map(Number);
  return o.length === 4 && o.every((x) => x <= 255) ? o[0] * 16_777_216 + o[1] * 65536 + o[2] * 256 + o[3] : null;
}

/** The 128-bit value of an IPv6 address written without a zone, or null. */
function v6Value(t: string): bigint | null {
  let s = t.toLowerCase();
  const q = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (q) {
    const o = q.slice(1).map(Number);
    if (o.some((x) => x > 255)) return null;
    s = `${s.slice(0, q.index)}${((o[0] << 8) | o[1]).toString(16)}:${((o[2] << 8) | o[3]).toString(16)}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const parts = halves.map((h) => (h === "" ? [] : h.split(":")));
  const given = parts.flat();
  if (!given.every((g) => /^[0-9a-f]{1,4}$/.test(g))) return null;
  const gap = 8 - given.length;
  if (halves.length === 1 ? gap !== 0 : gap < 1) return null;
  const groups = halves.length === 1 ? given : [...parts[0], ...Array<string>(gap).fill("0"), ...parts[1]];
  return groups.reduce((acc, g) => (acc << 16n) | BigInt(Number.parseInt(g, 16)), 0n);
}

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const v4Text = (n: number): string => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
const reversed = (dotted: string): string => dotted.split(".").reverse().join(".");
const isMapped = (v: bigint): boolean => v >> 32n === 0xffffn;
// The NAT64 well-known prefix 64:ff9b::/96 carries an IPv4 address in its last 32 bits.
const isNat64 = (v: bigint): boolean => v >> 32n === 0x64ff9bn << 64n;
const isV6Private = (v: bigint): boolean => new RegExp(`^${V6_PRIVATE}$`, "i").test((v >> 112n).toString(16).padStart(4, "0"));
const nibbles = (v: bigint): string => [...v.toString(16).padStart(32, "0")].reverse().join(".");
const fromNibbles = (name: string): bigint => BigInt(`0x${[...name.replaceAll(".", "")].reverse().join("")}`);
/** The embedded IPv4 of a mapped or NAT64 value when it is private, as a number, else null. */
function embeddedPrivate(v: bigint): number | null {
  if (!isMapped(v) && !isNat64(v)) return null;
  const n = Number(v & 0xffffffffn);
  return IS_V4_PRIVATE.test(v4Text(n)) ? n : null;
}

/** One mapping per run: aliases, SIDs, GUID first fields, then private addresses, in that order. */
function makeRedactor(aliases: [string, string][], guidPrefixes: string[], taken: Taken): (s: string) => string {
  const literals = aliases.map(([from, to]): [RegExp, string] => [new RegExp(`(?<![A-Za-z0-9_-])${escapeRe(from)}(?![A-Za-z0-9_-])`, "gi"), to]);
  const guidRe = guidPrefixes.length ? new RegExp(`(?<![0-9a-z])(?:${guidPrefixes.join("|")})(?=-)`, "gi") : null;
  const v4 = new Map<number, number>();
  const v6 = new Map<string, number>();
  const sids = new Map<string, number>();
  const alias4 = (value: number): number => {
    let alias = v4.get(value);
    if (alias === undefined) {
      alias = alloc(taken.v4, 254, "private IPv4 addresses");
      v4.set(value, alias);
    }
    return alias;
  };
  const alias6 = (key: string): number => {
    let alias = v6.get(key);
    if (alias === undefined) {
      alias = alloc(taken.v6, 0xffff, "private IPv6 addresses");
      v6.set(key, alias);
    }
    return alias;
  };
  // The alias value of a private address given as a number, or null when it is not private.
  // A mapped or NAT64 address keeps its prefix and its embedded IPv4 address takes its plain alias.
  const aliasOf = (v: bigint): bigint | null => {
    const inner = embeddedPrivate(v);
    if (inner !== null) return (v & ~0xffffffffn) | BigInt(DOC4_BASE + alias4(inner));
    if (isMapped(v) || isNat64(v)) return null;
    return isV6Private(v) ? DOC6_BASE + BigInt(alias6(v.toString())) : null;
  };
  return (s) => {
    let t = s;
    for (const [re, to] of literals) t = t.replace(re, to);
    t = t.replace(SID, (m, head: string, a: string, b: string, c: string) => {
      if (a === "0" && b === "0") return m;
      const key = [a, b, c].map((x) => x.replace(/^0+(?=\d)/, "")).join("-");
      if (!sids.has(key)) sids.set(key, alloc(taken.sid, Number.MAX_SAFE_INTEGER, "account SIDs"));
      return `${head}0-0-${sids.get(key)}`;
    });
    if (guidRe) t = t.replace(guidRe, "00000000");
    t = t.replace(V6_ADDR, (_m, addr: string) => {
      // A trailing single colon is sentence punctuation, not part of the address.
      const tail = /[^:]:$/.test(addr) ? ":" : "";
      const body = tail ? addr.slice(0, -1) : addr;
      const value = v6Value(body);
      const key = value === null ? `text:${body.toLowerCase()}` : value.toString();
      return `2001:db8::${alias6(key).toString(16)}${tail}`;
    });
    t = t.replace(V4_ANY, (m, ptr: string | undefined, suffix: string | undefined, plain: string | undefined) => {
      if (plain !== undefined) {
        const value = v4Value(plain);
        return value === null ? m : `192.0.2.${alias4(value)}`;
      }
      // A reverse name is rewritten only when the address it names is private; a public one stays whole.
      if (ptr === undefined) return m;
      const fwd = reversed(ptr);
      const value = v4Value(fwd);
      return value !== null && IS_V4_PRIVATE.test(fwd) ? `${alias4(value)}.2.0.192${suffix}` : m;
    });
    t = t.replace(ARPA6, (m, name: string, suffix: string) => {
      const out = aliasOf(fromNibbles(name));
      return out === null ? m : `${nibbles(out)}.${suffix}`;
    });
    // A zone index is not part of the address, so it is not written back.
    return t.replace(V6_MAPPED, (m, addr: string) => {
      const v = v6Value(addr);
      const out = v === null ? null : aliasOf(v);
      if (out === null || (!isMapped(out) && !isNat64(out))) return m;
      return `${isNat64(out) ? "64:ff9b::" : "::ffff:"}${((out >> 16n) & 0xffffn).toString(16)}:${(out & 0xffffn).toString(16)}`;
    });
  };
}

function mapStrings(v: unknown, f: (s: string) => string): unknown {
  if (typeof v === "string") return f(v);
  if (Array.isArray(v)) return v.map((x) => mapStrings(x, f));
  const o = obj(v);
  return o ? Object.fromEntries(Object.entries(o).map(([k, x]) => [k, mapStrings(x, f)])) : v;
}

/** True when the hex-and-colon run ending at `end`, read back from `at`, is a global (2000::/3) address. */
function inGlobal(s: string, at: number, end: number): boolean {
  let a = at;
  while (a > 0 && /[0-9a-f:]/i.test(s[a - 1])) a--;
  const v = v6Value(s.slice(a, end));
  return v !== null && v >> 125n === 1n;
}

/** Why a string still holds a private address or an unmapped SID in plain text, or null. */
function plainLeftover(s: string): string | null {
  for (const m of s.matchAll(V4_ARPA)) {
    const fwd = reversed(m[1]);
    if (v4Value(fwd) !== null && IS_V4_PRIVATE.test(fwd)) return "a private IPv4 address in a reverse-lookup name";
  }
  for (const m of s.matchAll(ARPA6)) {
    const v = fromNibbles(m[1]);
    if (embeddedPrivate(v) !== null || (!isMapped(v) && !isNat64(v) && isV6Private(v))) return "a private IPv6 address in a reverse-lookup name";
  }
  const nat64 = /64:ff9b:/i.test(s) ? [...s.matchAll(V4_IN_NAT64)] : [];
  for (const m of [...s.matchAll(V4_IN_MAPPED), ...nat64]) {
    const n = m[3] === undefined ? Number.parseInt(m[1], 16) * 65536 + Number.parseInt(m[2], 16) : v4Value(m[3]);
    if (n !== null && IS_V4_PRIVATE.test(v4Text(n)) && !inGlobal(s, m.index, m.index + m[0].length)) return "a private IPv4 address in an IPv4-mapped or NAT64 address";
  }
  // A reverse name of a public address may start like a private one; it is not an address.
  const masked = s.replace(V4_ARPA, (m) => " ".repeat(m.length));
  for (const m of masked.matchAll(V4_PORTED)) if (v4Value(m[1]) !== null) return "a private IPv4 address";
  for (const m of s.matchAll(SID)) if (!(m[2] === "0" && m[3] === "0")) return "an account SID";
  if (new RegExp(V6_ADDR.source, "i").test(s)) return "a private IPv6 address";
  for (const m of s.matchAll(V6_GLUED)) {
    let a = m.index;
    let b = m.index;
    while (a > 0 && /[0-9a-f:]/i.test(s[a - 1])) a--;
    while (b < s.length && /[0-9a-f:]/i.test(s[b])) b++;
    const v = v6Value(s.slice(a, b));
    // Inside a global (2000::/3) address the group is only a group.
    if (v === null || v >> 125n !== 1n) return "a private IPv6 address run into the text before it";
  }
  return null;
}

/** Each text a base64 run may hide: UTF-8 and UTF-16LE, from each of the four group offsets and both byte alignments. */
function decodings(run: string): string[] {
  const out: string[] = [];
  for (let offset = 0; offset < 4; offset++) {
    const bytes = Buffer.from(run.slice(offset), "base64");
    out.push(bytes.toString("utf8"), bytes.toString("utf16le"), bytes.subarray(1).toString("utf16le"));
  }
  return out;
}

/** Why a string still holds a private address or an unmapped SID, in plain text or inside base64, or null. */
function leftover(s: string): string | null {
  const plain = plainLeftover(s);
  if (plain) return plain;
  // SECURITY: base64 hides text from every pattern above, so an encoded private value refuses the run.
  for (const [run] of s.matchAll(BLOB)) {
    if (decodings(run).some((d) => plainLeftover(d) !== null)) return "an encoded blob holding a private address or account SID";
  }
  return null;
}

function findLeftover(v: unknown, path: string): string | null {
  if (typeof v === "string") {
    const why = leftover(v);
    return why ? `${path}: ${why}` : null;
  }
  if (Array.isArray(v)) {
    for (const [i, x] of v.entries()) {
      const r = findLeftover(x, `${path}[${i}]`);
      if (r) return r;
    }
    return null;
  }
  const o = obj(v);
  if (o) {
    for (const [k, x] of Object.entries(o)) {
      const r = findLeftover(x, path ? `${path}.${k}` : k);
      if (r) return r;
    }
  }
  return null;
}

/** Rewrites every string in the intake with one mapping; refuses when a private value remains. */
export function redactIntake(doc: Obj, aliases: [string, string][]): Obj {
  const json = JSON.stringify(doc);
  const taken = emptyTaken();
  for (const m of json.matchAll(/(?<![\d.])192\.0\.2\.(\d{1,3})(?![\d.])/g)) taken.v4.add(Number(m[1]));
  for (const m of json.matchAll(/(?<![\d.])(\d{1,3})\.2\.0\.192\.in-addr\.arpa/gi)) taken.v4.add(Number(m[1]));
  // Reserve a documentation value wherever it sits: a plain or mapped address, or a nibble name.
  const reserve6 = (v: bigint | null): void => {
    if (v === null) return;
    if (v > DOC6_BASE && v - DOC6_BASE <= 0xffffn) taken.v6.add(Number(v - DOC6_BASE));
    const low = Number(v & 0xffffffffn);
    if ((isMapped(v) || isNat64(v)) && low >>> 8 === DOC4_BASE >>> 8) taken.v4.add(low & 255);
  };
  for (const m of json.matchAll(ARPA6)) reserve6(fromNibbles(m[1]));
  // Reserve by value, so an expanded or zero-padded spelling of 2001:db8::n keeps its number too.
  for (const m of json.matchAll(/[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}/gi)) reserve6(v6Value(m[0]));
  for (const m of json.matchAll(/S-1-5-21-0-0-(\d+)(?!\d)/gi)) taken.sid.add(Number(m[1]));
  // Only a typed Sysmon GUID field teaches a prefix, so free text cannot get one zeroed.
  const prefixes = new Set<string>();
  for (const d of (doc.detections as Obj[]) ?? []) {
    for (const group of Object.values(obj(d.sysmon) ?? {})) {
      for (const f of ["process_guid", "parent_process_guid"]) {
        const m = GUID_TYPED.exec(String(obj(group)?.[f] ?? ""));
        if (m && m[1] !== "00000000") prefixes.add(m[1].toLowerCase());
      }
    }
  }
  const out = mapStrings(doc, makeRedactor(aliases, [...prefixes], taken)) as Obj;
  const bad = findLeftover(out, "");
  if (bad) throw new RunError(`redaction left a private value at ${bad}; nothing written`);
  return out;
}

// *--- Core Logic ---*

function loadHits(file: string): unknown[] {
  let raw: string;
  try {
    raw = readFileSync(file, "utf8");
  } catch (err) {
    throw new RunError(`cannot read the replay file (${errCode(err)})`);
  }
  if (file.endsWith(".jsonl")) {
    return raw.split("\n").flatMap((line, i) => {
      if (line.trim() === "") return [];
      try {
        return [JSON.parse(line)];
      } catch {
        throw new RunError(`replay file line ${i + 1} is not valid JSON`);
      }
    });
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new RunError("the replay file is not valid JSON");
  }
  const hits = Array.isArray(parsed) ? parsed : at(parsed, "hits", "hits");
  if (!Array.isArray(hits)) throw new RunError("the replay JSON is neither an array of hits nor a _search response");
  return hits;
}

function loadRecon(file: string | undefined): Recon {
  if (file === undefined) return { markdown: "", baseline: null, changes: [] };
  let v: unknown;
  try {
    v = JSON.parse(readFileSync(file, "utf8"));
  } catch (err) {
    throw new RunError(`cannot read --recon-delta (${errCode(err)})`);
  }
  const o = obj(v);
  if (!o || typeof o.markdown !== "string" || !(typeof o.baseline === "string" || o.baseline === null) || !Array.isArray(o.changes)) {
    throw new RunError("--recon-delta must be an object {markdown: string, baseline: string|null, changes: array}");
  }
  return { markdown: o.markdown, baseline: o.baseline as string | null, changes: o.changes };
}

function assemble(o: Options, w: { start: bigint; end: bigint; generated: bigint }, dets: Det[], matched: Map<string, number>, totalMatched: number, pipeline: Pipeline): Obj {
  const included = new Map<string, number>();
  for (const d of dets) {
    const day = utcDate(d.micros);
    included.set(day, (included.get(day) ?? 0) + 1);
  }
  return {
    schema: SCHEMA,
    generated: fmtMicros(w.generated),
    source: o.source,
    consumer: CONSUMER,
    window: { start: fmtMicros(w.start), end: fmtMicros(w.end), lookback_hours: o.lookbackHours },
    filter: { min_level: o.minLevel, include_rule_ids: o.include, cap: o.cap, order: "newest_first" },
    truncated: totalMatched > dets.length,
    counts: windowDays(w.start, w.end).map((date) => ({ date, matched: matched.get(date) ?? 0, included: included.get(date) ?? 0 })),
    pipeline,
    detections: dets.map((d) => d.det),
    recon_delta: loadRecon(o.reconDelta),
    note: NOTE,
  };
}

/** Newest first, ties kept in input order, cut at the cap. */
function newestFirst(recs: Rec[], cap: number): Det[] {
  return recs
    .map((r, i) => ({ r, i }))
    .sort((a, b) => (a.r.micros === b.r.micros ? a.i - b.i : a.r.micros > b.r.micros ? -1 : 1))
    .slice(0, cap)
    .map(({ r }) => ({ micros: r.micros, det: toDetection(r) }));
}

function replay(o: Options, file: string, deps: Deps): Obj {
  const parsed = loadHits(file).map(parseRecord);
  const recs = parsed.filter((r): r is Rec => r !== null);
  const unparsed = parsed.length - recs.length;
  let end = o.windowEnd;
  if (end === undefined) {
    if (recs.length === 0) throw new RunError("the replay file holds no record with a usable timestamp; pass --window-end");
    end = ceilSecond(recs.reduce((m, r) => (r.micros > m ? r.micros : m), 0n));
  }
  const start = end - BigInt(o.lookbackHours) * 3_600_000_000n;
  const inWin = recs.filter((r) => r.micros >= start && r.micros <= end);
  const include = new Set(o.include);
  const seen = new Set<string>();
  const matched: Rec[] = [];
  let skipped = 0;
  for (const r of inWin) {
    if (!usable(r)) {
      skipped++;
      continue;
    }
    if (!(r.level >= o.minLevel || include.has(r.ruleId)) || seen.has(r.id)) continue;
    seen.add(r.id);
    matched.push(r);
  }
  if (unparsed) deps.stderr(`wazuh: skipped ${unparsed} record(s) whose timestamp cannot be parsed\n`);
  if (skipped) deps.stderr(`wazuh: skipped ${skipped} record(s) in the window with no level, rule ID, description, agent or alert ID\n`);
  const perDay = new Map<string, number>();
  for (const r of matched) perDay.set(utcDate(r.micros), (perDay.get(utcDate(r.micros)) ?? 0) + 1);
  const agents = new Set(inWin.map((r) => r.agent).filter((a): a is string => a !== null));
  const newest = inWin.reduce<Rec | null>((m, r) => (m === null || r.micros > m.micros ? r : m), null);
  const pipeline = { collector_ok: true, agents_reporting: agents.size, last_event_seen: newest?.ts ?? null };
  return assemble(o, { start, end, generated: end }, newestFirst(matched, o.cap), perDay, matched.length, pipeline);
}

// *--- Live Mode ---*

interface Live { base: URL; auth: string; ca?: string; secrets: string[] }

/** Checks every refusal before any request goes out. */
function liveConfig(o: Options, deps: Deps): Live {
  const rawUrl = o.url ?? deps.env.WAZUH_INDEXER_URL;
  if (!rawUrl) throw new UsageError("live mode needs --url or WAZUH_INDEXER_URL (or --replay)");
  let base: URL;
  try {
    base = new URL(rawUrl);
  } catch {
    throw new UsageError("the indexer URL is not a valid URL");
  }
  // SECURITY: Basic credentials only ever travel over TLS, and never inside the URL.
  if (base.protocol !== "https:") throw new UsageError("the indexer URL must use https");
  if (base.username !== "" || base.password !== "") throw new UsageError("the indexer URL must not carry credentials");
  // SECURITY: the requests pin verification on, but a disabled-verification environment is refused outright.
  if (deps.env.NODE_TLS_REJECT_UNAUTHORIZED === "0") throw new UsageError("certificate verification is turned off in this environment (NODE_TLS_REJECT_UNAUTHORIZED); unset it and pass --ca-file <path> to trust the indexer's CA");
  const user = deps.env.WAZUH_INDEXER_USER;
  if (!user) throw new UsageError("live mode needs WAZUH_INDEXER_USER");
  let pass = deps.env.WAZUH_INDEXER_PASS;
  if (o.passwordFile !== undefined) {
    try {
      pass = readFileSync(o.passwordFile, "utf8").split("\n")[0].replace(/\r$/, "");
      if ((statSync(o.passwordFile).mode & 0o077) !== 0) deps.stderr("wazuh: the password file is readable by group or others\n");
    } catch (err) {
      throw new UsageError(`cannot read the password file (${errCode(err)})`);
    }
  }
  if (!pass) throw new UsageError("live mode needs a password: set WAZUH_INDEXER_PASS or use --password-file <path>");
  // SECURITY: the output check refuses any intake holding the password, so a short one refuses often.
  if (pass.length < MIN_PASSWORD_LENGTH) deps.stderr(`wazuh: the password is shorter than ${MIN_PASSWORD_LENGTH} characters; a short password matches ordinary text, so the output check may refuse runs\n`);
  const caPath = o.caFile ?? deps.env.WAZUH_INDEXER_CA;
  let ca: string | undefined;
  if (caPath) {
    try {
      ca = readFileSync(caPath, "utf8");
    } catch (err) {
      throw new UsageError(`cannot read the CA bundle (${errCode(err)})`);
    }
  }
  const token = Buffer.from(`${user}:${pass}`).toString("base64");
  if (!base.pathname.endsWith("/")) base.pathname += "/";
  return { base, auth: `Basic ${token}`, ca, secrets: [pass, token] };
}

async function search(live: Live, deps: Deps, body: unknown): Promise<unknown> {
  const url = new URL(`${INDEX}/_search`, live.base);
  const host = hostOf(url);
  let res: Response;
  try {
    res = await deps.fetch(url.href, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: live.auth },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      // SECURITY: a redirect would carry the Basic credentials to a host nobody named.
      redirect: "error",
      // SECURITY: verification is set per request, so no process-wide setting can turn it off.
      tls: { rejectUnauthorized: true, ...(live.ca ? { ca: live.ca } : {}) },
    });
  } catch (err) {
    throw new RunError(`request to ${host} failed (${errCode(err)})`);
  }
  if (!res.ok) throw new RunError(`indexer at ${host} answered ${res.status}`);
  try {
    return await res.json();
  } catch {
    throw new RunError(`indexer at ${host} sent an unreadable response`);
  }
}

async function liveRun(o: Options, deps: Deps, live: Live): Promise<Obj> {
  const start = BigInt(Math.floor(deps.now() / 1000) * 1000) * 1000n - BigInt(o.lookbackHours) * 3_600_000_000n;
  // The window end is taken after the query, so the query runs to the whole second above now.
  const range = (end: bigint) => ({ range: { "@timestamp": { gte: fmtMicros(start), lte: fmtMicros(end) } } });
  const upper = ceilSecond(BigInt(deps.now()) * 1000n);
  const should: unknown[] = [{ range: { "rule.level": { gte: o.minLevel } } }];
  if (o.include.length) should.push({ terms: { "rule.id": o.include } });
  // Discarded hits (duplicates, missing fields) are replaced from the extra hits, up to the window limit.
  const main = await search(live, deps, {
    size: Math.min(o.cap * 2, MAX_RESULT_WINDOW),
    track_total_hits: true,
    sort: [{ "@timestamp": { order: "desc" } }],
    query: { bool: { filter: [range(upper), { bool: { should, minimum_should_match: 1 } }] } },
    aggs: { per_day: { date_histogram: { field: "@timestamp", calendar_interval: "day", time_zone: "UTC", min_doc_count: 0 } } },
  });
  const hits = at(main, "hits", "hits");
  const buckets = at(main, "aggregations", "per_day", "buckets");
  if (!Array.isArray(hits) || !Array.isArray(buckets)) throw new RunError(`indexer at ${hostOf(live.base)} answered with an unexpected shape`);
  // The query ran to `upper`, so the window ends there: nothing after it was asked for.
  const end = upper;
  const matched = new Map<string, number>();
  let total = 0;
  for (const b of buckets) {
    const key = at(b, "key");
    const n = int(at(b, "doc_count"));
    if (typeof key !== "number" || n === null) throw new RunError(`indexer at ${hostOf(live.base)} sent a malformed day bucket`);
    matched.set(utcDate(BigInt(key) * 1000n), n);
    total += n;
  }
  const seen = new Set<string>();
  const recs: Rec[] = [];
  for (const r of hits.map(parseRecord)) {
    if (r !== null && usable(r) && !seen.has(r.id)) {
      seen.add(r.id);
      recs.push(r);
    } else if (r !== null) {
      // A discarded hit matched the query but is not an alert the intake can carry: not matched.
      const day = utcDate(r.micros);
      const left = matched.get(day) ?? 0;
      if (left > 0) {
        matched.set(day, left - 1);
        total--;
      }
    }
  }
  if (recs.length < hits.length) deps.stderr(`wazuh: skipped ${hits.length - recs.length} hit(s) that were duplicates or lacked a field the intake needs\n`);

  let pipeline: Pipeline = { collector_ok: false, agents_reporting: 0, last_event_seen: null };
  try {
    const p = await search(live, deps, {
      size: 0,
      query: { bool: { filter: [range(end)] } },
      aggs: { agents: { cardinality: { field: "agent.name" } }, last: { max: { field: "@timestamp" } } },
    });
    const agents = int(at(p, "aggregations", "agents", "value"));
    const lastMs = at(p, "aggregations", "last", "value");
    if (agents === null) throw new RunError("pipeline query answered with an unexpected shape");
    pipeline = {
      collector_ok: true,
      agents_reporting: agents,
      last_event_seen: typeof lastMs === "number" ? new Date(lastMs).toISOString() : null,
    };
  } catch (err) {
    deps.stderr(`wazuh: pipeline query failed, collector_ok is false: ${err instanceof Error ? err.message : "error"}\n`);
  }
  return assemble(o, { start, end, generated: ceilSecond(BigInt(deps.now()) * 1000n) }, newestFirst(recs, o.cap), matched, total, pipeline);
}

// *--- Entry Point ---*

async function run(o: Options, deps: Deps, register: (s: string[]) => void): Promise<string> {
  let secrets: string[] = [];
  let doc: Obj;
  if (o.replay !== undefined) doc = replay(o, o.replay, deps);
  else {
    const live = liveConfig(o, deps);
    secrets = live.secrets;
    // SECURITY: every later message is scrubbed of the credentials, wherever they were read from.
    register(secrets);
    doc = await liveRun(o, deps, live);
  }
  if (o.redact) doc = redactIntake(doc, o.aliases);
  const json = `${JSON.stringify(doc, null, 2)}\n`;
  // SECURITY: a credential inside alert data must not reach the output either, in any spelling.
  const strings: string[] = [];
  mapStrings(doc, (x) => {
    strings.push(x);
    return x;
  });
  const spellings = secrets.flatMap((x) => [x, JSON.stringify(x).slice(1, -1)]);
  if (secrets.some((x) => strings.some((t) => t.includes(x))) || spellings.some((x) => json.includes(x))) throw new RunError("the intake holds the indexer credentials; nothing written");
  const result = validateIntake(doc);
  if (result.errors.length) throw new RunError(`the intake failed validation: ${result.errors.slice(0, 5).join("; ")}`);
  const detections = doc.detections as unknown[];
  deps.stderr(`wazuh: ${detections.length} detection(s), truncated: ${doc.truncated}\n`);
  return json;
}

/** Runs the CLI against injected dependencies and returns the exit code. */
export async function main(argv: string[], deps: Deps): Promise<number> {
  let secrets: string[] = [];
  // SECURITY: a secret may reach a message raw or JSON-escaped (a validation error quotes values).
  const scrub = (m: string) => secrets.flatMap((s) => [s, JSON.stringify(s).slice(1, -1)]).reduce((acc, s) => acc.split(s).join("[redacted]"), m);
  // SECURITY: registered before parseArgs, so no argument-parsing message can carry the environment password.
  const pass = deps.env.WAZUH_INDEXER_PASS;
  if (pass) secrets = [pass, Buffer.from(`${deps.env.WAZUH_INDEXER_USER ?? ""}:${pass}`).toString("base64")];
  try {
    const o = parseArgs(argv);
    const json = await run(o, { ...deps, stderr: (s) => deps.stderr(scrub(s)) }, (s) => {
      secrets = [...secrets, ...s];
    });
    if (o.out !== undefined) writeFileSync(o.out, json);
    else deps.stdout(json);
    return 0;
  } catch (err) {
    if (err instanceof UsageError) {
      deps.stderr(`wazuh: ${scrub(err.message)}\n`);
      return 2;
    }
    const msg = err instanceof RunError ? err.message : `unexpected failure (${errCode(err)})`;
    deps.stderr(`wazuh: ${scrub(msg)}\n`);
    return 1;
  }
}

if (import.meta.main) {
  process.exitCode = await main(process.argv.slice(2), {
    fetch: (url, init) => fetch(url, init),
    env: process.env,
    now: () => Date.now(),
    stdout: (s) => void process.stdout.write(s),
    stderr: (s) => void process.stderr.write(s),
  });
}
