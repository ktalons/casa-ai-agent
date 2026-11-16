// *****************************************************************************
// *Title: Fabrication Lint Tests*
// *Author: Kyle Versluis*
// *Description: Every token kind the standard names must trace or fail.*
// *****************************************************************************

// *--- Imports ---*

import { test, expect } from "bun:test";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { extractTokens, intakeKnowledge, lint, loadReferences, type Kind } from "./lib/extract.ts";

// *--- Configuration ---*

const ROOT = join(import.meta.dir, "..");
const read = (p: string) => readFileSync(join(ROOT, p), "utf8");
const json = (p: string) => JSON.parse(read(p));
const intake = json("intake/fixtures/brute-force-dc-chain.intake.json");
const intakeV2 = json("intake/fixtures/brute-force-dc-chain.v2.intake.json");
const good = read("evals/samples/brute-force-dc-chain.good.brief.md");
const bad = read("evals/samples/brute-force-dc-chain.bad.brief.md");
const SHA256_A = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const SHA256_B = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

// *--- Helper Functions ---*

/** The flagged tokens of one kind, as `kind:token` strings. */
function flagged(text: string, ik: unknown, kind?: Kind): string[] {
  return lint(text, ik).unknown.filter((u) => !kind || u.kind === kind).map((u) => `${u.kind}:${u.token}`);
}

/** A v2 intake with one detection's fields replaced, for kinds the fixtures never carry. */
function intakeWith(fields: Record<string, unknown>): unknown {
  const copy = structuredClone(intakeV2);
  Object.assign(copy.detections[0], fields);
  return copy;
}

// *--- Reference Tables ---*

test("reference tables load and carry the IDs the fixtures rely on", () => {
  const refs = loadReferences();
  for (const id of ["T1110", "T1110.001", "T1078", "T1021.002", "T1003.006", "T1071.001", "T1071.004"]) expect(refs.attack.has(id)).toBe(true);
  for (const id of ["DE.AE-03", "DE.CM-01", "RS.AN-03", "RS.MI-01", "PR.AA-05", "PR.IR-01"]) expect(refs.csf.has(id)).toBe(true);
  // CSF 1.1 identifiers must not be present.
  for (const id of ["PR.AC-4", "RS.AN-01", "DE.CM-04", "ID.AM-06"]) expect(refs.csf.has(id)).toBe(false);
  expect(refs.csf.size).toBe(106);
  for (const id of ["4624", "4625", "4662", "4688", "4738", "4769", "1", "3", "10"]) expect(refs.event_ids.has(id)).toBe(true);
  for (const id of ["4999", "4600", "99"]) expect(refs.event_ids.has(id)).toBe(false);
  for (const p of ["53", "88", "389", "443", "445", "3389"]) expect(refs.ports.has(p)).toBe(true);
  expect(refs.ports.has("4444")).toBe(false);
});

test("TLD list holds only lowercase root-zone names; special-use names stay separate but still read as domains", () => {
  const lr = json("skills/standards/references/lint-references.json");
  const special = new Set<string>(lr.special_use_names.names);
  expect(lr.tlds.filter((t: string) => t !== t.toLowerCase())).toEqual([]);
  expect(lr.tlds.filter((t: string) => special.has(t))).toEqual([]);
  expect([...extractTokens("corpdc01 resolved dc01.corp and files.internal").domain].sort()).toEqual(["dc01.corp", "files.internal"]);
  expect(flagged("corpdc01 resolved dc01.corp", intakeV2)).toEqual(["domain:dc01.corp"]);
});

// *--- Extraction ---*

test("extractTokens ignores sha256 blobs and IP octets when looking for rule IDs", () => {
  const t = extractTokens(`sha256 ${SHA256_A} and 10.0.0.50 and rule 100220`);
  expect([...t.rule_id]).toEqual(["100220"]);
  expect([...t.ip]).toEqual(["10.0.0.50"]);
  expect([...t.hash]).toEqual([SHA256_A]);
});

test("extractTokens catches CSF 1.1 shapes so they can be rejected", () => {
  const t = extractTokens("maps to PR.AC-4 and DE.AE-03");
  expect([...t.csf].sort()).toEqual(["DE.AE-03", "PR.AC-4"]);
});

test("port notations are not rule IDs, and a bare five-digit number needs a rule keyword to be one", () => {
  const t = extractTokens("port 49152 open, corpws12:8443/tcp listening, ports 50000 and 60122/udp, rule 60122 fired, 12345 seen");
  expect([...t.rule_id].sort()).toEqual(["60122"]);
  expect([...t.port].sort()).toEqual(["49152", "50000", "60122", "8443"]);
  expect([...t.exposure]).toEqual(["corpws12:8443"]);
});

test("the host prefix is a literal, not a regex: metacharacters are refused, the rest escaped", () => {
  expect(() => extractTokens("x", { hostPrefixes: ["ta(lon"] })).toThrow("host prefix");
  expect(() => extractTokens("x", { hostPrefixes: [".*"] })).toThrow("host prefix");
  expect(() => extractTokens("x", { hostPrefixes: [""] })).toThrow("host prefix");
  // Tokens without digits, so only the prefix rule can see them.
  const t = extractTokens("lab-dc and lab-ws and lab- and labx and slab-dc", { hostPrefixes: ["lab-"] });
  expect([...t.host].sort()).toEqual(["lab-dc", "lab-ws"]);
  expect([...extractTokens("corpdc corp corpx", { hostPrefixes: ["corp"] }).host].sort()).toEqual(["corpdc", "corpx"]);
});

test("ordinary words, file names and technical tokens are not read as hosts, users or domains", () => {
  const prose = "Pull sha256 and md5 for the ipv6 path; read conn.log, dce_rpc.log and lessons.md; level-12 alerts, " +
    "the user and the account used, a host that is not a DC, x.run1.brief.md, System.IO.File, DR10, T1, id.resp_h.";
  const t = extractTokens(prose);
  expect([...t.host]).toEqual([]);
  expect([...t.user]).toEqual([]);
  expect([...t.domain]).toEqual([]);
  expect([...t.timestamp]).toEqual([]);
});

// *--- F3 Criteria ---*

test("invented host: a hostname without the intake's prefix fails in prose, notation, keyword and JSON forms", () => {
  const cases = [
    "Lateral movement from web07 to corpdc01 (rule 100215).",
    "The host WEB07 authenticated to corpdc01.",
    "New exposure on web07:3389/tcp.",
    "```json\n{ \"schema\": \"casa.brief/v1\", \"threads\": [ { \"hosts\": [\"webserver\"] } ] }\n```",
  ];
  for (const text of cases) expect(flagged(text, intakeV2, "host").length).toBe(1);
  // The intake's own hosts, in any case, pass.
  expect(flagged("CORPDC01 and corpws07, corpws07:3389/tcp", intakeV2)).toEqual([]);
  // A host the intake names only inside recon_delta markdown is known.
  expect(flagged("corpdc01:445/tcp is unchanged", intake)).toEqual([]);
  // A real host bound to a port the intake never reported for it is an invented exposure.
  expect(flagged("corpdc01:3389/tcp is open", intakeV2)).toEqual(["port:corpdc01:3389"]);
});

test("rule id exact: digits found only inside an alert_id fail as a rule ID", () => {
  // 418001 is the fractional part of the first detection's alert_id, never a rule.
  expect(flagged("rule 418001 fired on corpdc01", intakeV2)).toEqual(["rule_id:418001"]);
  expect(flagged("rule 100220 fired on corpdc01", intakeV2)).toEqual([]);
  // The alert_id itself traces; an invented one does not.
  expect(flagged("alert 1784600387.418001 on corpdc01", intakeV2)).toEqual([]);
  expect(flagged("alert 1784600387.999999 on corpdc01", intakeV2)).toEqual(["alert_id:1784600387.999999"]);
});

test("token kinds: an invented user, event ID, port, IPv6 address, domain, hash and timestamp each fail (7 of 7)", () => {
  const invented: [Kind, string][] = [
    ["user", "The logon used account svc-sqlagent on corpdc01."],
    ["event_id", "corpdc01 logged event 4999 during the replication."],
    ["port", "corpws07 also listened on 4444/tcp."],
    ["ipv6", "The request came from 2001:db8::bad:1."],
    ["domain", "corpws07 resolved update-check.example.net before the burst."],
    ["hash", `The dropped binary had sha256 ${SHA256_A}.`],
    ["timestamp", "The replication began at 2026-07-20T03:41:07Z."],
  ];
  const caught = invented.filter(([kind, text]) => flagged(text, intakeV2, kind).length === 1);
  expect(caught.map(([k]) => k)).toEqual(invented.map(([k]) => k));

  // The same kinds pass when they trace to the intake.
  expect(flagged("user svc-backup; event 4662 then 4624; port 3389/tcp; at 02:19:47Z on 2026-07-20, about 02:20Z", intakeV2)).toEqual([]);
  const rich = intakeWith({ src_ip: "2001:db8:0:0::14", description: `query for cdn-sync.example.net, file ${SHA256_B}` });
  expect(flagged(`from 2001:db8::14 resolving cdn-sync.example.net, sha256 ${SHA256_B.toUpperCase()}`, rich)).toEqual([]);

  // Data requests may name real event IDs and service ports from the reference tables.
  expect(flagged("Security 4688 and Sysmon events 1, 3 and 10 would show the process; Kerberos on 88/tcp.", intakeV2)).toEqual([]);
  expect(lint("Security 4688 would show the process.", intakeV2).beyond_intake.event_id).toEqual(["4688"]);

  // A user named in backticks after the keyword is checked even without separators.
  expect(flagged("the account `jdoe` logged on", intakeV2)).toEqual(["user:jdoe"]);
  // An HH:MM time outside the intake window and more than a rounding away from any intake time is
  // invented. The v1 intake has no window field, so its window is the detection span.
  expect(flagged("between 02:14Z and 02:30Z", intake)).toEqual(["timestamp:02:30Z"]);
});

test("honest phrasing: ordinary SOC prose, lookup sites and in-window ranges lint clean", () => {
  const honest = [
    "Pull logs from 01:30Z to 03:30Z.",
    "Query 2026-07-20 02:00-03:00 on the DC.",
    "Check user sign-in logs, account lock-out and user re-authentication.",
    "Pull events 30 minutes either side.",
    "Scan ports 1-1024 on the segment.",
    "The app used oauth2 and ran a ps1 script.",
    "Windows 10.0.19045.3693, Windows build 19045, PID 12345, CVE-2021-44228, ISO 27001, mem 65536 KB, TCP 31337.",
    "Agent version 2.0.1.5 is current.",
    "regsvr32 and rundll32 ran from System32 and SysWOW64.",
    "A ratio 10:30 and a score 12:34 are not times.",
    "Look the indicator up on virustotal.com, abuse.ch, urlhaus.abuse.ch, shodan.io, greynoise.io and otx.alienvault.com.",
    "See attack.mitre.org and learn.microsoft.com; placeholders use example.com, example.org and example.net.",
    "The service listened on 0.0.0.0 and 127.0.0.1.",
    "It ran as NT AUTHORITY\\SYSTEM under BUILTIN\\Administrators and loaded System.Net and Microsoft.Win32.",
  ];
  const failing = honest.map((text) => ({ text, flagged: flagged(text, intakeV2) })).filter((r) => r.flagged.length > 0);
  expect(failing).toEqual([]);
});

test("fabricated phrasing: obfuscated, re-cased and loosely written tokens each fail as their kind", () => {
  const hex = (pair: string, n: number) => pair.repeat(n / 2);
  const cases: [Kind, string, unknown][] = [
    ["domain", "corpdc01 resolved evil[.]com.", intakeV2],
    ["domain", "Beacon to hxxp://evil[.]com/gate.", intakeV2],
    ["ip", "corpdc01 talked to 10[.]9[.]9[.]9.", intakeV2],
    ["ip", "corpdc01 talked to 10(.)9(.)9(.)9.", intakeV2],
    ["domain", "corpdc01 resolved EVIL.com.", intakeV2],
    ["domain", "corpdc01 resolved Evil.Com.", intakeV2],
    ["ip", "The source was ip10.9.9.9 per the log.", intakeV2],
    ["ip", "The source was ip_10.9.9.9 per the log.", intakeV2],
    ["host", "Lateral movement reached FILESERVER01.", intakeV2],
    ["host", "Lateral movement reached fileserver-01.", intakeV2],
    ["host", "Lateral movement reached WS-0042.", intakeV2],
    ["host", "Lateral movement reached ws_0042.", intakeV2],
    ["user", "The logon was CORP\\bob.", intakeV2],
    ["user", "Mail went to bob.smith@corp.example.", intakeV2],
    ["user", "Then user `mallory` logged on.", intakeV2],
    ["user", "Then user \"mallory\" logged on.", intakeV2],
    ["attack", "This maps to t9999.", intakeV2],
    ["attack", "This maps to T 9999.", intakeV2],
    ["csf", "This maps to de.cm-01.", intakeV2],
    ["csf", "This maps to DE.CM 01.", intakeV2],
    ["timestamp", "It started Dec 31 2026.", intakeV2],
    ["timestamp", "It started 12/31/2026.", intakeV2],
    ["rule_id", "Then rule 1003400 fired.", intakeV2],
    ["rule_id", "Check rule numbers 100341, 99999 next.", intakeV2],
    ["rule_id", "Then the rule fired (99999).", intakeV2],
    ["hash", `The payload hash was 0x${SHA256_A}.`, intakeV2],
    ["hash", `The payload was hash_${SHA256_A}.`, intakeV2],
    ["hash", `The SHA-224 was ${hex("ab", 56)}.`, intakeV2],
    ["hash", `The SHA-384 was ${hex("cd", 96)}.`, intakeV2],
    // Inside the window but outside query context, a time must match an intake time.
    ["timestamp", "The logon at 02:47Z came from the same source.", intakeV2],
    ["timestamp", "The logon succeeded at 2026-07-20 02:47Z.", intakeV2],
    // Outside the intake window, ranges and bare UTC times still fail.
    ["timestamp", "Query 2026-07-21 02:00-03:00 on the DC.", intakeV2],
    ["timestamp", "Pull logs from 01:30Z to 03:30Z.", intake],
  ];
  const wrong = cases
    .map(([kind, text, ik]) => ({ kind, text, kinds: [...new Set(lint(text, ik).unknown.map((u) => u.kind))] }))
    .filter((r) => r.kinds.length !== 1 || r.kinds[0] !== r.kind);
  expect(wrong).toEqual([]);
});

test("linear time: a 100,000-character brief of one repeated shape lints in under a second", () => {
  const n = 100_000;
  const spaces = " ".repeat(n);
  const inputs: Record<string, string> = {
    "a run": "a".repeat(n),
    "1 run": "1".repeat(n),
    "colon run": ":".repeat(n),
    "dot run": ".".repeat(n),
    "dotted numbers": "10.0.0.1.".repeat(n / 9),
    "defanged dots": "[.]".repeat(n / 3),
    // Blanked spans become whitespace, so keyword-then-whitespace is a real shape, not a contrived one.
    "space run": spaces,
    "events then spaces": "events" + spaces,
    "ports then spaces": "ports" + spaces,
    "rule then spaces": "rule" + spaces,
    "list comma then spaces": "events 1," + spaces,
  };
  const slow: string[] = [];
  for (const [name, text] of Object.entries(inputs)) {
    const t0 = performance.now();
    lint(text, intakeV2);
    const ms = performance.now() - t0;
    if (ms >= 1000) slow.push(`${name}: ${ms.toFixed(0)} ms`);
  }
  expect(slow).toEqual([]);
}, 60_000);

test("the brief's own intake hash is provenance, not evidence, and a stale one is reported as a note", () => {
  const raw = readFileSync(join(ROOT, "intake/fixtures/brute-force-dc-chain.intake.json"));
  const sha = createHash("sha256").update(raw).digest("hex");
  const brief = (h: string) => "```json\n" + JSON.stringify({ schema: "casa.brief/v1", intake: { sha256: h } }) + "\n```\n";
  expect(lint(brief(sha), intake, { intakeSha256: sha })).toMatchObject({ pass: true, notes: [] });
  const stale = lint(brief(SHA256_B), intake, { intakeSha256: sha });
  expect(stale.pass).toBe(true);
  expect(stale.notes.length).toBe(1);
  // Cited anywhere else, the same value is an ordinary hash claim.
  expect(flagged(brief(SHA256_B) + `\nThe payload hash was ${SHA256_B}.`, intake)).toEqual([`hash:${SHA256_B}`]);
});

test("quiet-day intake: any host, rule ID or technique is a fabrication", () => {
  const quiet = json("intake/fixtures/quiet-day.intake.json");
  const r = lint("No findings. Pipeline liveness unconfirmed.", quiet);
  expect(r.pass).toBe(true);
  const r2 = lint("corpdc01 fired rule 100220 (T1003.006)", quiet);
  expect(r2.unknown.map((u) => u.kind).sort()).toEqual(["host", "rule_id"]);
});

// *--- Kept Samples ---*

test("samples: good sample brief passes, every citation traces to the intake or a table", () => {
  const r = lint(good, intake);
  expect(r.unknown).toEqual([]);
  expect(r.pass).toBe(true);
  expect(r.counts.rule_id).toBe(4);
  expect(r.counts.host).toBe(2);
  expect(r.counts.ip).toBe(0);
});

test("samples: bad sample brief fails on exactly the planted fabrications", () => {
  const r = lint(bad, intake);
  expect(r.pass).toBe(false);
  const got = r.unknown.map((u) => `${u.kind}:${u.token}`).sort();
  expect(got).toEqual(["attack:T9999", "csf:PR.AC-4", "host:corpghost", "ip:203.0.113.250", "rule_id:100999"].sort());
});

// Real briefs produced by /casa:investigate on the fixtures (kept as *.runN.brief.md) must
// stay lint-clean against the intake they came from.
for (const f of readdirSync(join(ROOT, "evals/samples")).filter((n) => /\.run\d+\.brief\.md$/.test(n)).sort()) {
  // May carry a .v2 or .v3 suffix: the intake file has the same name.
  const fixture = f.replace(/\.run\d+\.brief\.md$/, "");
  test(`samples: run sample ${f} traces every citation to ${fixture}`, () => {
    const r = lint(read(`evals/samples/${f}`), json(`intake/fixtures/${fixture}.intake.json`));
    expect(r.unknown).toEqual([]);
    expect(r.pass).toBe(true);
  });
}

// *--- Intake v3 ---*

/** The v3 twin with typed fields filled in: a Suricata alert, a Sysmon DNS query, a Sysmon connection. */
function richV3(): unknown {
  const v3 = json("intake/fixtures/brute-force-dc-chain.v3.intake.json");
  const nulls = { process_id: null, process_guid: null, user: null };
  Object.assign(v3.detections[1], {
    engine: { name: "suricata", rule_id: "2024217", rev: 3 }, dst_ip: "203.0.113.80", dst_port: 8443, proto: "tcp",
    suricata: { event_type: "alert", signature: "ET POLICY test", category: null, severity: 2, action: "allowed", flow_id: "1234", app_proto: "tls", http_hostname: null, http_url: null, http_user_agent: null, tls_sni: "files.example.io", dns_rrname: null },
  });
  Object.assign(v3.detections[2], { src_port: 51544, logon_type: 3 });
  Object.assign(v3.detections[3], {
    event_id: "22",
    sysmon: { dns_query: { ...nulls, image: "C:\\Tools\\agent.exe", user: "LAB\\opsuser", query_name: "sync-cdn.example.zz", query_status: "0", query_results: null } },
  });
  v3.detections.push({ ...v3.detections[3], alert_id: "9.9", event_id: "3", sysmon: { network_connect: { ...nulls, image: "C:\\Tools\\agent.exe", initiated: true, source_hostname: "wkstn-07", destination_hostname: "backhaul.example.com" } } });
  return v3;
}

test("v3 fields: subject and target users, ports, engine rule IDs and Sysmon names trace, and inventions fail", () => {
  const v3 = richV3();
  const honest = [
    "Suricata SID 2024217 fired on corpdc01 for files.example.io on 8443/tcp.",
    "On corpws07 the target user svc-backup logged on from source port 51544.",
    "On corpdc01 the subject user svc-backup requested replication.",
    "The resolver asked for sync-cdn.example.zz, and wkstn-07 then reached backhaul.example.com.",
  ];
  for (const line of honest) expect([line, flagged(line, v3)]).toEqual([line, []]);
  const invented: [Kind, string][] = [
    ["rule_id", "Suricata SID 2024299 fired on corpdc01."],
    ["port", "corpdc01 also reached 9443/tcp."],
    ["user", "The subject user svc-sqlagent requested replication."],
    ["domain", "The resolver asked for sync-cdn2.example.zz."],
  ];
  for (const [kind, line] of invented) expect([line, flagged(line, v3, kind).length]).toEqual([line, 1]);
});

test("v3 fields: a detection's own ports do not become host:port exposures", () => {
  const v3 = richV3();
  expect(flagged("corpdc01:8443 was exposed.", v3).length).toBeGreaterThan(0);
  expect(flagged("corpws07:3389 was exposed.", v3)).toEqual([]);
});

test("v3 offsets: an intake time with a non-UTC offset traces by its UTC date and time, not its local clock", () => {
  const v3 = richV3() as { detections: { timestamp: string }[] };
  v3.detections[0].timestamp = "2026-07-20T09:19:47.418123+07:00";
  expect(flagged("The first alert fired at 2026-07-20 02:19:47Z.", v3, "timestamp")).toEqual([]);
  expect(flagged("The first alert fired at 2026-07-20 09:19:47Z.", v3, "timestamp").length).toBe(1);
  // Across midnight the UTC date is the earlier day.
  v3.detections[0].timestamp = "2026-07-20T05:10:00+07:00";
  expect(intakeKnowledge(v3).stamps.some((s) => s.date === "2026-07-19" && s.time === "22:10:00")).toBe(true);
});

test("v3 learned TLDs: only a TLD the domain pattern can read is learned", () => {
  const v3 = richV3() as { detections: { sysmon: { dns_query?: { query_name: string } } | null }[] };
  const k = (name: string) => {
    v3.detections[3].sysmon!.dns_query!.query_name = name;
    return intakeKnowledge(v3).patterns.domainTlds;
  };
  expect(k("sync-cdn.example.zz")).toContain("zz");
  for (const [name, tld] of [["a.example.c0m", "c0m"], ["a.example.x-y", "x-y"], [`a.example.${"q".repeat(30)}`, "q".repeat(30)]]) expect(k(name)).not.toContain(tld);
});

test("v3 Sysmon hosts: a single-label hostname found only in source_hostname traces, and a stranger still fails", () => {
  const v3 = richV3() as { detections: { sysmon?: { network_connect?: Record<string, unknown> } | null }[] };
  const conn = v3.detections.at(-1)!.sysmon!.network_connect!;
  conn.source_hostname = "wkstn-relay";
  conn.destination_hostname = null;
  const hosts = (text: string, hostPrefix?: string) => lint(text, v3, { hostPrefix }).unknown.filter((u) => u.kind === "host").map((u) => u.token);
  // In prose the prefix makes a single-label name readable as a host; only the intake can vouch for it.
  expect(hosts("wkstn-relay connected out.", "wkstn-")).toEqual([]);
  expect(hosts("wkstn-other connected out.", "wkstn-")).toEqual(["wkstn-other"]);
  // A brief's JSON block names a host with no prefix to read it by, so the intake's typed field is the only voucher.
  const block = (h: string) => "```json\n" + JSON.stringify({ schema: "casa.brief/v1", threads: [{ hosts: [h] }] }) + "\n```\n";
  expect(hosts(block("wkstn-relay"))).toEqual([]);
  expect(hosts(block("wkstn-other"))).toEqual(["wkstn-other"]);
});
