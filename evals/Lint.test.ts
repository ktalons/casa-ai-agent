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
import { extractTokens, lint, loadReferences, type Kind } from "./lib/extract.ts";

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

test("port notations are not rule IDs; a bare five-digit number still is", () => {
  const t = extractTokens("port 49152 open, talonmacbook:8443/tcp listening, ports 50000 and 60122/udp, rule 60122 fired, 12345 seen");
  expect([...t.rule_id].sort()).toEqual(["12345", "60122"]);
  expect([...t.port].sort()).toEqual(["49152", "50000", "60122", "8443"]);
  expect([...t.exposure]).toEqual(["talonmacbook:8443"]);
});

test("the host prefix is a literal, not a regex: metacharacters are refused, the rest escaped", () => {
  expect(() => extractTokens("x", { hostPrefixes: ["ta(lon"] })).toThrow("host prefix");
  expect(() => extractTokens("x", { hostPrefixes: [".*"] })).toThrow("host prefix");
  expect(() => extractTokens("x", { hostPrefixes: [""] })).toThrow("host prefix");
  // Tokens without digits, so only the prefix rule can see them.
  const t = extractTokens("lab-dc and lab-ws and lab- and labx and slab-dc", { hostPrefixes: ["lab-"] });
  expect([...t.host].sort()).toEqual(["lab-dc", "lab-ws"]);
  expect([...extractTokens("talondc talon talonx", { hostPrefixes: ["talon"] }).host].sort()).toEqual(["talondc", "talonx"]);
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

test("invented host: a hostname with no talon prefix fails in prose, notation, keyword and JSON forms", () => {
  const cases = [
    "Lateral movement from web07 to talondc01 (rule 100215).",
    "The host WEB07 authenticated to talondc01.",
    "New exposure on web07:3389/tcp.",
    "```json\n{ \"schema\": \"casa.brief/v1\", \"threads\": [ { \"hosts\": [\"webserver\"] } ] }\n```",
  ];
  for (const text of cases) expect(flagged(text, intakeV2, "host").length).toBe(1);
  // The intake's own hosts, in any case, pass.
  expect(flagged("TALONDC01 and talondellbox, talondellbox:3389/tcp", intakeV2)).toEqual([]);
  // A host the intake names only inside recon_delta markdown is known.
  expect(flagged("talondc01:445/tcp is unchanged", intake)).toEqual([]);
  // A real host bound to a port the intake never reported for it is an invented exposure.
  expect(flagged("talondc01:3389/tcp is open", intakeV2)).toEqual(["port:talondc01:3389"]);
});

test("rule id exact: digits found only inside an alert_id fail as a rule ID", () => {
  // 418001 is the fractional part of the first detection's alert_id, never a rule.
  expect(flagged("rule 418001 fired on talondc01", intakeV2)).toEqual(["rule_id:418001"]);
  expect(flagged("rule 100220 fired on talondc01", intakeV2)).toEqual([]);
  // The alert_id itself traces; an invented one does not.
  expect(flagged("alert 1784600387.418001 on talondc01", intakeV2)).toEqual([]);
  expect(flagged("alert 1784600387.999999 on talondc01", intakeV2)).toEqual(["alert_id:1784600387.999999"]);
});

test("token kinds: an invented user, event ID, port, IPv6 address, domain, hash and timestamp each fail (7 of 7)", () => {
  const invented: [Kind, string][] = [
    ["user", "The logon used account svc-sqlagent on talondc01."],
    ["event_id", "talondc01 logged event 4999 during the replication."],
    ["port", "talondellbox also listened on 4444/tcp."],
    ["ipv6", "The request came from 2001:db8::bad:1."],
    ["domain", "talondellbox resolved update-check.example.net before the burst."],
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
  // An HH:MM time more than a rounding away from any intake time is invented.
  expect(flagged("between 02:14Z and 02:30Z", intakeV2)).toEqual(["timestamp:02:30Z"]);
});

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
  const r2 = lint("talondc01 fired rule 100220 (T1003.006)", quiet);
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
  expect(got).toEqual(["attack:T9999", "csf:PR.AC-4", "host:talonghost", "ip:10.0.0.50", "rule_id:100999"].sort());
});

// Real briefs produced by /casa:investigate on the fixtures (kept as *.runN.brief.md) must
// stay lint-clean against the intake they came from.
for (const f of readdirSync(join(ROOT, "evals/samples")).filter((n) => /\.run\d+\.brief\.md$/.test(n)).sort()) {
  // May carry a .v2 suffix: the intake file has the same name.
  const fixture = f.replace(/\.run\d+\.brief\.md$/, "");
  test(`samples: run sample ${f} traces every citation to ${fixture}`, () => {
    const r = lint(read(`evals/samples/${f}`), json(`intake/fixtures/${fixture}.intake.json`));
    expect(r.unknown).toEqual([]);
    expect(r.pass).toBe(true);
  });
}
