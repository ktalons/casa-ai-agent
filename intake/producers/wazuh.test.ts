// *****************************************************************************
// *Title: Wazuh Producer Tests*
// *Author: Kyle Versluis*
// *Description: Replay, redaction, secret handling and live-mode tests.*
// *****************************************************************************

// *--- Imports ---*

import { afterAll, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { validateIntake } from "../Validate.ts";
import { type Deps, type FetchFn, main } from "./wazuh.ts";

// *--- Configuration ---*

const ROOT = join(import.meta.dir, "..");
const RECORDING = join(ROOT, "raw", "brute-force-dc-chain.v2.alerts.jsonl");
const V2_FIXTURE = join(ROOT, "fixtures", "brute-force-dc-chain.v2.intake.json");
const SAMPLE = join(import.meta.dir, "fixtures", "lab-sample.alerts.jsonl");
const SAMPLE_END = ["--window-end", "2026-08-04T06:00:00Z"];
const NOW = Date.parse("2026-08-04T06:00:00Z");
const PW = "pw-canary-7f3a9c";
const USER = "indexer-reader";
const BASIC = Buffer.from(`${USER}:${PW}`).toString("base64");
const dir = mkdtempSync(join(tmpdir(), "wazuh-producer-"));

afterAll(() => rmSync(dir, { recursive: true, force: true }));

// *--- Helper Functions ---*

interface Ran { code: number; out: string; err: string }

async function run(argv: string[], over: Partial<Deps> = {}): Promise<Ran> {
  const out: string[] = [];
  const err: string[] = [];
  const deps: Deps = {
    fetch: async () => {
      throw new Error("the network is not available in tests");
    },
    env: {},
    now: () => NOW,
    stdout: (s) => out.push(s),
    stderr: (s) => err.push(s),
    ...over,
  };
  const code = await main(argv, deps);
  return { code, out: out.join(""), err: err.join("") };
}

const replay = (...extra: string[]) => run(["--replay", SAMPLE, ...SAMPLE_END, "--stdout", ...extra]);
const detections = (r: Ran): any[] => JSON.parse(r.out).detections;

function allStrings(v: unknown, into: string[] = []): string[] {
  if (typeof v === "string") into.push(v);
  else if (Array.isArray(v)) v.forEach((x) => allStrings(x, into));
  else if (typeof v === "object" && v !== null) Object.values(v).forEach((x) => allStrings(x, into));
  return into;
}

const PRIVATE_V4 = /(?<!\d)(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])|169\.254)\.\d{1,3}\.\d{1,3}(?!\d)/;

// The matched alerts of the sample, as an indexer would return them.
const sampleHits = readFileSync(SAMPLE, "utf8").trim().split("\n").map((l) => JSON.parse(l));
const served = sampleHits.filter((h, i, all) => h._source.rule.level >= 12 && all.findIndex((x) => x._id === h._id) === i);

function indexerFake(seen: { url: string; init: any }[], status = 200): FetchFn {
  return async (url, init) => {
    seen.push({ url, init });
    if (status !== 200) return new Response("denied", { status });
    const body = JSON.parse(init.body);
    if (body.size === 0) {
      return Response.json({ aggregations: { agents: { value: 3 }, last: { value: Date.parse("2026-08-04T04:10:00.100Z") } } });
    }
    const days = new Map<number, number>();
    for (const h of served) {
      const k = Date.parse(h._source["@timestamp"].slice(0, 10) + "T00:00:00Z");
      days.set(k, (days.get(k) ?? 0) + 1);
    }
    const buckets = [...days].sort((a, b) => a[0] - b[0]).map(([key, doc_count]) => ({ key, doc_count }));
    const hits = [...served].sort((a, b) => (a._source["@timestamp"] < b._source["@timestamp"] ? 1 : -1)).slice(0, body.size);
    return Response.json({ hits: { total: { value: served.length }, hits }, aggregations: { per_day: { buckets } } });
  };
}

const liveEnv = { WAZUH_INDEXER_URL: "https://indexer.example:9200", WAZUH_INDEXER_USER: USER, WAZUH_INDEXER_PASS: PW };

// *--- Replay ---*

describe("replay mode", () => {
  test("replay", async () => {
    const r = await run(["--replay", RECORDING, "--stdout"]);
    expect(r.code).toBe(0);
    const doc = JSON.parse(r.out);
    expect(validateIntake(doc).errors).toEqual([]);
    expect(doc.schema).toBe("talonsoclab.soc-intake/v3");
    expect(doc.window).toEqual({ start: "2026-07-19T02:19:48Z", end: "2026-07-20T02:19:48Z", lookback_hours: 24 });
    expect(doc.counts).toEqual([{ date: "2026-07-19", matched: 0, included: 0 }, { date: "2026-07-20", matched: 4, included: 4 }]);
    expect(doc.pipeline).toEqual({ collector_ok: true, agents_reporting: 2, last_event_seen: "2026-07-20T02:19:47.418Z" });
    expect(doc.truncated).toBe(false);
  });

  test("parity", async () => {
    const r = await run(["--replay", RECORDING, "--stdout"]);
    const want = JSON.parse(readFileSync(V2_FIXTURE, "utf8")).detections.map((d: any) => d.alert_id);
    expect(detections(r).map((d) => d.alert_id)).toEqual(want);
    expect(want).toHaveLength(4);
  });

  test("replay writes --out and says so on stderr only", async () => {
    const out = join(dir, "out.json");
    const r = await run(["--replay", RECORDING, "--out", out]);
    expect(r.code).toBe(0);
    expect(r.out).toBe("");
    expect(validateIntake(JSON.parse(readFileSync(out, "utf8"))).errors).toEqual([]);
  });

  test("the sysmon and suricata blocks validate and carry the mapped fields", async () => {
    const r = await replay();
    expect(r.code).toBe(0);
    expect(validateIntake(JSON.parse(r.out)).errors).toEqual([]);
    const byId = new Map(detections(r).map((d) => [d.alert_id, d]));
    const proc = byId.get("1785800400.400004").sysmon.process_create;
    expect(proc.hashes).toEqual({ md5: "00112233445566778899aabbccddeeff", sha1: "aabbccddeeff00112233445566778899aabbccdd", sha256: "ab".repeat(32), imphash: null });
    expect(proc.process_id).toBe(4120);
    expect(proc.integrity_level).toBe("High");
    const net = byId.get("1785800500.500005");
    expect(net.sysmon.network_connect.initiated).toBe(true);
    expect(net).toMatchObject({ src_ip: "10.20.30.41", src_port: 50123, dst_ip: "192.168.5.9", dst_port: 443, proto: "tcp" });
    expect(Object.keys(byId.get("1785800600.600006").sysmon)).toEqual(["file_create"]);
    expect(byId.get("1785800700.700007").sysmon.registry_value_set.event_type).toBe("SetValue");
    expect(byId.get("1785800800.800008").sysmon.dns_query.query_name).toBe("rare.example.net");
    const sur = byId.get("1785800900.900009");
    expect(sur.engine).toEqual({ name: "suricata", rule_id: "2024897", rev: 3 });
    expect(sur.sysmon).toBeNull();
    expect(sur.suricata).toMatchObject({ event_type: "alert", severity: 2, action: "allowed", flow_id: "1727463534105821", app_proto: "http", http_hostname: "update.example.net" });
    expect(sur).toMatchObject({ src_ip: "172.16.4.8", dst_port: 80, proto: "tcp" });
  });

  test("users, logon types and the event id come from the Windows fields", async () => {
    const byId = new Map(detections(await replay()).map((d) => [d.alert_id, d]));
    expect(byId.get("1785800100.100001")).toMatchObject({ subject_user: "CORP-DC01$", target_user: "svc-sync", logon_type: 3, event_id: "4624", src_port: 49812, engine: { name: "wazuh", rule_id: "100215", rev: null } });
    expect(byId.get("1785800200.200002")).toMatchObject({ subject_user: null, target_user: "admin", logon_type: 10, src_port: null });
    // 4662 carries no logon type even when the field is present.
    expect(byId.get("1785800300.300003")).toMatchObject({ logon_type: null, subject_user: "svc-sync", target_user: null });
  });

  test("the include list admits a below-floor rule", async () => {
    const without = await replay();
    expect(detections(without).some((d) => d.rule_id === "100340")).toBe(false);
    const r = await replay("--include-rules", "100340");
    expect(validateIntake(JSON.parse(r.out)).errors).toEqual([]);
    const doc = JSON.parse(r.out);
    expect(doc.filter.include_rule_ids).toEqual(["100340"]);
    expect(doc.detections.find((d: any) => d.rule_id === "100340").level).toBe(8);
    expect(doc.counts.find((c: any) => c.date === "2026-08-04")).toEqual({ date: "2026-08-04", matched: 8, included: 8 });
  });

  test("truncation and per-day counts with a small cap", async () => {
    const r = await replay("--cap", "3");
    expect(r.code).toBe(0);
    const doc = JSON.parse(r.out);
    expect(validateIntake(doc).errors).toEqual([]);
    expect(doc.truncated).toBe(true);
    expect(doc.detections.map((d: any) => d.alert_id)).toEqual(["1785800100.100001", "1785800200.200002", "1785800300.300003"]);
    expect(doc.counts).toEqual([{ date: "2026-08-03", matched: 2, included: 0 }, { date: "2026-08-04", matched: 7, included: 3 }]);
  });

  test("a group missing its required string leaves the sysmon block null", async () => {
    const file = join(dir, "no-image.jsonl");
    const hit = structuredClone(sampleHits.find((h) => h._id === "1785800500.500005"));
    delete hit._source.data.win.eventdata.image;
    writeFileSync(file, `${JSON.stringify(hit)}\n`);
    const r = await run(["--replay", file, "--stdout"]);
    expect(r.code).toBe(0);
    expect(detections(r)[0].sysmon).toBeNull();
    expect(validateIntake(JSON.parse(r.out)).errors).toEqual([]);
  });
});

// *--- Redaction ---*

describe("redaction", () => {
  test("redact addresses", async () => {
    const r = await replay("--redact");
    expect(r.code).toBe(0);
    expect(validateIntake(JSON.parse(r.out)).errors).toEqual([]);
    expect(r.out).not.toMatch(PRIVATE_V4);
    expect(r.out).not.toMatch(/fd12:|fe80:|%eth0/i);
    const d = new Map(detections(r).map((x) => [x.alert_id, x]));
    // One mapping per run, numbered in order of first sight, shared across fields.
    expect(d.get("1785800100.100001").src_ip).toBe("192.0.2.1");
    expect(d.get("1785800300.300003").src_ip).toBe("192.0.2.1");
    expect(d.get("1785800400.400004").sysmon.process_create.command_line).toContain("\\\\192.0.2.1\\share");
    expect(d.get("1785800500.500005")).toMatchObject({ src_ip: "192.0.2.2", dst_ip: "192.0.2.3" });
    expect(d.get("1785800200.200002").src_ip).toBe("2001:db8::1");
    const results: string = d.get("1785800800.800008").sysmon.dns_query.query_results;
    expect(results).toContain("::ffff:192.0.2.2;");
    expect(results).toContain("2001:db8::2;");
    expect(d.get("1785800900.900009")).toMatchObject({ src_ip: "192.0.2.4", dst_ip: "192.0.2.5" });
  });

  test("redact sids", async () => {
    const r = await replay("--redact");
    expect(r.out).not.toContain("1111111111");
    expect(r.out).not.toContain("3333333333");
    const d = new Map(detections(r).map((x) => [x.alert_id, x]));
    // The RID after the three sub-authorities stays, and both copies share one number.
    expect(d.get("1785800700.700007").sysmon.registry_value_set.target_object).toContain("HKU\\S-1-5-21-0-0-1-1105\\Software");
    expect(d.get("1785800400.400004").sysmon.process_create.command_line).toContain("/user S-1-5-21-0-0-1-1105 ");
  });

  test("redact guids", async () => {
    const r = await replay("--redact");
    expect(r.out.toLowerCase()).not.toContain("a1b2c3d4");
    const proc = detections(r).find((x) => x.alert_id === "1785800400.400004").sysmon.process_create;
    expect(proc.process_guid).toBe("{00000000-0001-6650-1c00-000000001d00}");
    expect(proc.parent_process_guid).toBe("{00000000-0001-6650-0a00-000000001a00}");
    // The same first field inside free text is zeroed too.
    expect(proc.command_line).toContain("--ctx {00000000-0001-6650-1c00-000000001d00}");
  });

  test("aliases replace whole tokens, case-insensitively", async () => {
    const r = await replay("--redact", "--alias", "corp-dc01=host-xray", "--alias", "CORP-WS07=host-bravo");
    expect(r.code).toBe(0);
    expect(r.out.toLowerCase()).not.toContain("corp-dc01");
    expect(r.out.toLowerCase()).not.toContain("corp-ws07");
    expect(detections(r)[0].agent).toBe("host-xray");
    expect(detections(r).find((x) => x.alert_id === "1785800400.400004").agent).toBe("host-bravo");
    // A dot ends the token, so the alias also lands inside the dotted hostname.
    expect(r.out).toContain("host-bravo.corp-lab.example");
  });

  test("a bad alias is a usage error", async () => {
    expect((await replay("--alias", "corp-dc01=host-xray")).code).toBe(2);
    expect((await replay("--redact", "--alias", "corp-dc01=7host")).code).toBe(2);
    expect((await replay("--redact", "--alias", "corp-dc01=192.0.2.9")).code).toBe(2);
  });

  test("a private value redaction cannot place stops the run and writes nothing", async () => {
    const file = join(dir, "glued.jsonl");
    const out = join(dir, "glued.out.json");
    const hit = structuredClone(sampleHits[0]);
    hit._source.rule.description = "relay host:fd00::5 seen";
    writeFileSync(file, `${JSON.stringify(hit)}\n`);
    const r = await run(["--replay", file, "--redact", "--out", out]);
    expect(r.code).toBe(1);
    expect(r.err).toContain("detections[0].description");
    expect(r.err).not.toContain("fd00::5");
    expect(existsSync(out)).toBe(false);
  });
});

// *--- Live Mode ---*

describe("live mode", () => {
  test("no secret output", async () => {
    const check = (r: Ran, extra = "") => {
      for (const text of [r.out, r.err, extra]) {
        expect(text).not.toContain(PW);
        expect(text).not.toContain(BASIC);
      }
    };

    const denied: { url: string; init: any }[] = [];
    const out401 = join(dir, "out-401.json");
    const r401 = await run(["--out", out401], { env: liveEnv, fetch: indexerFake(denied, 401) });
    expect(r401.code).toBe(1);
    expect(r401.err).toContain("401");
    expect(r401.err).toContain("indexer.example:9200");
    check(r401);
    expect(existsSync(out401)).toBe(false);

    const threw = await run([], { env: liveEnv, fetch: async () => { throw new Error(`connect failed with Basic ${BASIC} and ${PW}`); } });
    expect(threw.code).toBe(1);
    check(threw);

    const seen: { url: string; init: any }[] = [];
    const outOk = join(dir, "out-ok.json");
    const ok = await run(["--out", outOk], { env: liveEnv, fetch: indexerFake(seen) });
    expect(ok.code).toBe(0);
    const written = readFileSync(outOk, "utf8");
    check(ok, written);
    expect(seen[0].init.headers.Authorization).toBe(`Basic ${BASIC}`);
    expect(seen[0].url).toBe("https://indexer.example:9200/wazuh-alerts-*/_search");
    const doc = JSON.parse(written);
    expect(validateIntake(doc).errors).toEqual([]);
    expect(doc.pipeline).toEqual({ collector_ok: true, agents_reporting: 3, last_event_seen: "2026-08-04T04:10:00.100Z" });
    expect(doc.counts).toEqual([{ date: "2026-08-03", matched: 2, included: 2 }, { date: "2026-08-04", matched: 7, included: 7 }]);
    expect(doc.truncated).toBe(false);
  });

  test("the query follows the contract and the CA bundle goes to fetch", async () => {
    const ca = join(dir, "ca.pem");
    writeFileSync(ca, "-----BEGIN CERTIFICATE-----\nplaceholder\n-----END CERTIFICATE-----\n");
    const seen: { url: string; init: any }[] = [];
    const r = await run(["--ca-file", ca, "--min-level", "10", "--include-rules", "100340,100341", "--cap", "5"], { env: liveEnv, fetch: indexerFake(seen) });
    expect(r.code).toBe(0);
    expect(seen).toHaveLength(2);
    const q = JSON.parse(seen[0].init.body);
    // Twice the cap, so discarded hits can be replaced without a second query.
    expect(q.size).toBe(10);
    expect(q.track_total_hits).toBe(true);
    expect(q.sort).toEqual([{ "@timestamp": { order: "desc" } }]);
    const [range, should] = q.query.bool.filter;
    expect(range.range["@timestamp"].gte).toBe("2026-08-03T06:00:00Z");
    expect(should.bool.minimum_should_match).toBe(1);
    expect(should.bool.should).toEqual([{ range: { "rule.level": { gte: 10 } } }, { terms: { "rule.id": ["100340", "100341"] } }]);
    expect(q.aggs.per_day.date_histogram).toMatchObject({ calendar_interval: "day", time_zone: "UTC" });
    expect(seen[0].init.tls).toEqual({ rejectUnauthorized: true, ca: readFileSync(ca, "utf8") });
    expect(JSON.parse(seen[1].init.body).size).toBe(0);
  });

  test("a failed pipeline query leaves collector_ok false", async () => {
    const base = indexerFake([]);
    const r = await run([], { env: liveEnv, fetch: async (u, i) => (JSON.parse(i.body).size === 0 ? new Response("no", { status: 500 }) : base(u, i)) });
    expect(r.code).toBe(0);
    expect(JSON.parse(r.out).pipeline).toEqual({ collector_ok: false, agents_reporting: 0, last_event_seen: null });
    expect(r.err).not.toContain(PW);
  });

  test("https only", async () => {
    const seen: { url: string; init: any }[] = [];
    const fetch = indexerFake(seen);
    const plain = await run([], { env: { ...liveEnv, WAZUH_INDEXER_URL: "http://indexer.example:9200" }, fetch });
    expect(plain.code).toBe(2);
    expect(plain.err).toContain("https");
    const userinfo = await run(["--url", "https://bob:pw-canary-userinfo@indexer.example:9200"], { env: liveEnv, fetch });
    expect(userinfo.code).toBe(2);
    expect(userinfo.err).not.toContain("pw-canary-userinfo");
    expect(userinfo.err).not.toContain("bob");
    expect(seen).toHaveLength(0);
  });

  test("no secret output: a password read from a file is scrubbed like one from the environment", async () => {
    // An error code that happens to spell the password is the narrowest path into stderr.
    const pw = "Filepw_canary";
    const file = join(dir, "pw-scrub.txt");
    writeFileSync(file, `${pw}\n`, { mode: 0o600 });
    const fetch: FetchFn = async () => {
      throw Object.assign(new Error("x"), { code: pw });
    };
    for (const [argv, env] of [[["--password-file", file], { ...liveEnv, WAZUH_INDEXER_PASS: undefined }], [[], { ...liveEnv, WAZUH_INDEXER_PASS: pw }]] as const) {
      const r = await run([...argv], { env, fetch });
      expect(r.code).toBe(1);
      expect(r.err).not.toContain(pw);
    }
  });

  test("password source", async () => {
    const seen: { url: string; init: any }[] = [];
    const fetch = indexerFake(seen);
    for (const argv of [["--password", "hunter2-canary"], ["--pass", "hunter2-canary"], ["--password=hunter2-canary"], ["--pass=hunter2-canary"]]) {
      const r = await run(argv, { env: liveEnv, fetch });
      expect(r.code).toBe(2);
      expect(r.err).toContain("not accepted");
      expect(r.err).not.toContain("hunter2-canary");
      expect(r.out).not.toContain("hunter2-canary");
    }
    const none = await run([], { env: { ...liveEnv, WAZUH_INDEXER_PASS: undefined }, fetch });
    expect(none.code).toBe(2);
    expect(seen).toHaveLength(0);

    const file = join(dir, "pw.txt");
    writeFileSync(file, "filepw-canary\nsecond line ignored\n", { mode: 0o600 });
    const ok = await run(["--password-file", file], { env: { ...liveEnv, WAZUH_INDEXER_PASS: undefined }, fetch });
    expect(ok.code).toBe(0);
    expect(seen[0].init.headers.Authorization).toBe(`Basic ${Buffer.from(`${USER}:filepw-canary`).toString("base64")}`);
    expect(ok.err + ok.out).not.toContain("filepw-canary");
  });

  test("a credential inside alert data never reaches the output", async () => {
    const poisoned = structuredClone(served[0]);
    poisoned._source.rule.description = `leaked ${PW} here`;
    const fetch: FetchFn = async (_u, init) => {
      if (JSON.parse(init.body).size === 0) return Response.json({ aggregations: { agents: { value: 1 }, last: { value: NOW } } });
      return Response.json({ hits: { hits: [poisoned] }, aggregations: { per_day: { buckets: [{ key: Date.parse("2026-08-04T00:00:00Z"), doc_count: 1 }] } } });
    };
    const out = join(dir, "poisoned.json");
    const r = await run(["--out", out], { env: liveEnv, fetch });
    expect(r.code).toBe(1);
    expect(r.err).not.toContain(PW);
    expect(existsSync(out)).toBe(false);
  });

  test("live-only and replay-only flags are checked", async () => {
    expect((await run(["--window-end", "2026-08-04T06:00:00Z"], { env: liveEnv })).code).toBe(2);
    expect((await run(["--replay", SAMPLE, "--url", "https://indexer.example"])).code).toBe(2);
    expect((await run(["--replay", SAMPLE, "--out", "a", "--stdout"])).code).toBe(2);
    expect((await run(["--replay", SAMPLE, "--min-level", "17"])).code).toBe(2);
    expect((await run(["--replay", SAMPLE, "--lookback", "0h"])).code).toBe(2);
    expect((await run(["--replay", join(dir, "missing.jsonl")])).code).toBe(1);
  });
});

// *--- Review Findings (2026-11-16) ---*

/** A fake indexer over the given hits, counting every hit in its day bucket as a real index would. */
function fakeOver(hits: any[], seen: { url: string; init: any }[] = []): FetchFn {
  return async (url, init) => {
    seen.push({ url, init });
    const body = JSON.parse(init.body);
    if (body.size === 0) return Response.json({ aggregations: { agents: { value: 3 }, last: { value: Date.parse("2026-08-04T04:10:00.100Z") } } });
    const days = new Map<number, number>();
    for (const h of hits) {
      const k = Date.parse(h._source["@timestamp"].slice(0, 10) + "T00:00:00Z");
      days.set(k, (days.get(k) ?? 0) + 1);
    }
    const buckets = [...days].sort((a, b) => a[0] - b[0]).map(([key, doc_count]) => ({ key, doc_count }));
    const sorted = [...hits].sort((a, b) => (a._source["@timestamp"] < b._source["@timestamp"] ? 1 : -1)).slice(0, body.size);
    return Response.json({ hits: { total: { value: hits.length }, hits: sorted }, aggregations: { per_day: { buckets } } });
  };
}

describe("review findings", () => {
  test("no secret output: a password with JSON-escaped characters inside alert text still blocks the output", async () => {
    const pw = "pw\"quote\\canary";
    const leaky = structuredClone(served);
    leaky[0]._source.rule.description = `login with ${pw} seen`;
    const out = join(dir, "out-escaped.json");
    const r = await run(["--out", out], { env: { ...liveEnv, WAZUH_INDEXER_PASS: pw }, fetch: fakeOver(leaky) });
    expect(r.code).toBe(1);
    expect(existsSync(out)).toBe(false);
    for (const text of [r.out, r.err]) {
      expect(text).not.toContain(pw);
      expect(text).not.toContain(JSON.stringify(pw).slice(1, -1));
    }
  });

  test("live window: the window ends at the query upper bound even when the clock moves during the run", async () => {
    const seen: { url: string; init: any }[] = [];
    let t = NOW;
    const r = await run([], { env: liveEnv, fetch: fakeOver(served, seen), now: () => (t += 1500) });
    expect(r.code).toBe(0);
    const doc = JSON.parse(r.out);
    const lte = JSON.parse(seen[0].init.body).query.bool.filter[0].range["@timestamp"].lte;
    expect(doc.window.end).toBe(lte);
    expect(JSON.parse(seen[1].init.body).query.bool.filter[0].range["@timestamp"].lte).toBe(lte);
  });

  test("live counts: duplicates and unusable hits are not counted as matched, so no false truncation", async () => {
    const extra = structuredClone(served);
    const dup = structuredClone(served[0]);
    dup._id = "dup-of-" + dup._id;
    const broken = structuredClone(served[0]);
    broken._id = broken._source.id = "broken-1";
    delete broken._source.rule.description;
    extra.push(dup, broken);
    const r = await run([], { env: liveEnv, fetch: fakeOver(extra) });
    expect(r.err).toContain("skipped 2");
    expect(r.code).toBe(0);
    const doc = JSON.parse(r.out);
    expect(validateIntake(doc).errors).toEqual([]);
    expect(doc.truncated).toBe(false);
    expect(doc.counts.reduce((n: number, c: { matched: number }) => n + c.matched, 0)).toBe(served.length);
  });

  test("live counts: with a cap, discarded hits are replaced so a truncated list is still exactly cap long", async () => {
    const extra = structuredClone(served);
    for (let i = 0; i < 2; i++) {
      const broken = structuredClone(served[i]);
      broken._id = broken._source.id = `broken-${i}`;
      delete broken._source.rule.description;
      extra.push(broken);
    }
    const seen: { url: string; init: any }[] = [];
    const r = await run(["--cap", "3"], { env: liveEnv, fetch: fakeOver(extra, seen) });
    expect(r.code).toBe(0);
    const doc = JSON.parse(r.out);
    expect(validateIntake(doc).errors).toEqual([]);
    expect(doc.detections).toHaveLength(3);
    expect(doc.truncated).toBe(true);
    expect(JSON.parse(seen[0].init.body).size).toBeGreaterThan(3);
  });

  test("redact: a documentation IPv6 address already present in any spelling keeps its number", async () => {
    const at = join(dir, "doc6.jsonl");
    const lines = readFileSync(SAMPLE, "utf8").trim().split("\n").map((l) => JSON.parse(l));
    lines[0]._source.rule.description += " peer 2001:0db8:0000:0000:0000:0000:0000:0001";
    writeFileSync(at, lines.map((l) => JSON.stringify(l)).join("\n") + "\n");
    const r = await run(["--replay", at, ...SAMPLE_END, "--stdout", "--redact"]);
    expect(r.code).toBe(0);
    const text = allStrings(JSON.parse(r.out)).join("\n");
    expect(text).toContain("2001:0db8:0000:0000:0000:0000:0000:0001");
    expect(text).not.toMatch(/2001:db8::1(?![0-9a-f])/i);
  });
});

// *--- Real TLS ---*

const HAS_OPENSSL = Bun.spawnSync(["openssl", "version"], { stdout: "ignore", stderr: "ignore" }).exitCode === 0;

/** A throwaway CA and a localhost certificate it signed, written under `at`. */
function makeCerts(at: string): void {
  const ssl = (...args: string[]) => {
    const r = Bun.spawnSync(["openssl", ...args], { cwd: at, stdout: "ignore", stderr: "pipe" });
    if (r.exitCode !== 0) throw new Error(`openssl ${args[0]} failed: ${r.stderr.toString()}`);
  };
  writeFileSync(join(at, "ext.cnf"), "subjectAltName=DNS:localhost\n");
  ssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "1", "-subj", "/CN=casa-test-ca", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=keyCertSign");
  ssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "srv.key", "-out", "srv.csr", "-subj", "/CN=localhost");
  ssl("x509", "-req", "-in", "srv.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "srv.pem", "-days", "1", "-extfile", "ext.cnf");
}

test.skipIf(!HAS_OPENSSL)("tls verification: an unknown CA is refused and --ca-file makes the same server pass", async () => {
  const at = mkdtempSync(join(dir, "tls-"));
  makeCerts(at);
  const server = Bun.serve({
    port: 0,
    tls: { cert: Bun.file(join(at, "srv.pem")), key: Bun.file(join(at, "srv.key")) },
    fetch: async (req) => {
      const body = (await req.json()) as { size?: number };
      if (body.size === 0) return Response.json({ aggregations: { agents: { value: 1 }, last: { value: NOW } } });
      return Response.json({ hits: { hits: [] }, aggregations: { per_day: { buckets: [] } } });
    },
  });
  try {
    const env = { WAZUH_INDEXER_URL: `https://localhost:${server.port}`, WAZUH_INDEXER_USER: USER, WAZUH_INDEXER_PASS: PW };
    const real: FetchFn = (u, i) => fetch(u, i as RequestInit);
    const refused = await run(["--stdout"], { env, fetch: real, now: () => Date.now() });
    expect(refused.code).toBe(1);
    expect(refused.err).toMatch(/failed \((?:UNABLE_TO_VERIFY_LEAF_SIGNATURE|SELF_SIGNED_CERT_IN_CHAIN|DEPTH_ZERO_SELF_SIGNED_CERT|[A-Z_]*CERT[A-Z_]*)\)/);
    // A process-wide override must not turn verification off for this tool. It runs in a child
    // process whose environment carries the override, so the test runner's own stays untouched.
    const script = join(at, "override.ts");
    writeFileSync(
      script,
      [
        `import { main } from ${JSON.stringify(join(import.meta.dir, "wazuh.ts"))};`,
        "const env = JSON.parse(process.argv[2]);",
        "process.exitCode = await main([\"--stdout\"], { fetch: (u, i) => fetch(u, i as RequestInit), env, now: () => Date.now(), stdout: () => {}, stderr: (s) => void process.stderr.write(s) });",
      ].join("\n"),
    );
    const child = Bun.spawn([process.execPath, script, JSON.stringify(env)], {
      env: { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "", NODE_TLS_REJECT_UNAUTHORIZED: "0" },
      stdout: "ignore",
      stderr: "pipe",
    });
    const [childErr, childCode] = await Promise.all([new Response(child.stderr).text(), child.exited]);
    expect(childCode).toBe(1);
    expect(childErr).toMatch(/failed \((?:[A-Z_]*CERT[A-Z_]*|UNABLE_TO_VERIFY_LEAF_SIGNATURE)\)/);
    const trusted = await run(["--stdout", "--ca-file", join(at, "ca.pem")], { env, fetch: real, now: () => Date.now() });
    expect(trusted.err).toContain("0 detection(s)");
    expect(trusted.code).toBe(0);
  } finally {
    server.stop(true);
  }
});

// *--- Review Findings, Round 2 ---*

describe("review findings, round 2", () => {
  test("live tls: every request verifies certificates, with or without a CA bundle", async () => {
    const seen: { url: string; init: any }[] = [];
    const r = await run([], { env: liveEnv, fetch: indexerFake(seen) });
    expect(r.code).toBe(0);
    expect(seen).toHaveLength(2);
    for (const s of seen) expect(s.init.tls).toEqual({ rejectUnauthorized: true });
  });

  test("live tls: an environment that turns verification off is refused before any request", async () => {
    const seen: { url: string; init: any }[] = [];
    const r = await run([], { env: { ...liveEnv, NODE_TLS_REJECT_UNAUTHORIZED: "0" }, fetch: indexerFake(seen) });
    expect(r.code).toBe(2);
    expect(r.err).toContain("--ca-file");
    expect(seen).toHaveLength(0);
  });

  test("live redirects: every request refuses to follow a redirect", async () => {
    const seen: { url: string; init: any }[] = [];
    await run([], { env: liveEnv, fetch: indexerFake(seen) });
    expect(seen.length).toBeGreaterThan(0);
    for (const s of seen) expect(s.init.redirect).toBe("error");
  });

  test("stderr scrub: a password is also scrubbed in its JSON-escaped spelling", async () => {
    const pw = 'pw"quote\\canary';
    const delta = join(dir, "escaped-delta.json");
    writeFileSync(delta, JSON.stringify({ markdown: "", baseline: null, changes: [{ host: "h", port: 1, proto: `x ${pw} y`, status: "new" }] }));
    const r = await run(["--replay", SAMPLE, ...SAMPLE_END, "--stdout", "--recon-delta", delta], { env: { WAZUH_INDEXER_PASS: pw } });
    expect(r.code).toBe(1);
    expect(r.err).toContain("failed validation");
    expect(r.err).not.toContain(pw);
    expect(r.err).not.toContain(JSON.stringify(pw).slice(1, -1));
  });

  test("unknown flag: its text, which may hold the env password, never reaches stderr", async () => {
    const pw = "Zq7pass-canary-9";
    const flag = `--zz-${pw}`;
    const r = await run([flag, "value"], { env: { WAZUH_INDEXER_PASS: pw } });
    expect(r.code).toBe(2);
    expect(r.err).toContain("unknown flag");
    expect(r.err).not.toContain(pw);
    expect(r.err).not.toContain("--zz-");
  });

  test("short password: a password under 8 characters warns on stderr without printing it", async () => {
    const r = await run([], { env: { ...liveEnv, WAZUH_INDEXER_PASS: "Zq7#k" }, fetch: indexerFake([]) });
    expect(r.err).toContain("shorter than 8 characters");
    expect(r.err).not.toContain("Zq7#k");
    const long = await run([], { env: liveEnv, fetch: indexerFake([]) });
    expect(long.err).not.toContain("shorter than 8 characters");
  });

  test("replay skipped note: records whose timestamp cannot be parsed are counted", async () => {
    const file = join(dir, "bad-time.jsonl");
    const good = structuredClone(sampleHits[0]);
    const bad = structuredClone(sampleHits[1]);
    bad._source["@timestamp"] = "2026-08-04T25:99:00Z";
    writeFileSync(file, `${JSON.stringify(good)}\n${JSON.stringify(bad)}\n`);
    const r = await run(["--replay", file, "--stdout"]);
    expect(r.code).toBe(0);
    expect(r.err).toMatch(/skipped 1 record\(s\) whose timestamp cannot be parsed/);
  });
});

// *--- Redaction Parity With The Lab ---*

/** Replays one sample record whose description is `desc`, under --redact. */
async function redactOne(desc: string, extra: string[] = []): Promise<{ r: Ran; out: string; desc: string | null }> {
  const file = join(dir, `one-${Math.random().toString(36).slice(2)}.jsonl`);
  const out = join(dir, `${Math.random().toString(36).slice(2)}.out.json`);
  const hit = structuredClone(sampleHits[0]);
  hit._source.rule.description = desc;
  writeFileSync(file, `${JSON.stringify(hit)}\n`);
  const r = await run(["--replay", file, "--redact", "--out", out, ...extra]);
  return { r, out, desc: existsSync(out) ? JSON.parse(readFileSync(out, "utf8")).detections[0].description : null };
}

/** The ip6.arpa nibble name of a 128-bit value. */
const nibbleName = (v: bigint) => `${[...v.toString(16).padStart(32, "0")].reverse().join(".")}.ip6.arpa`;
const DOC6 = 0x20010db8n << 96n;

describe("redaction parity with the lab", () => {
  test("ip6.arpa: fe80::/10 and fc00::/7 nibble names take the nibble name of their alias", async () => {
    const fe80 = (0xfe80n << 112n) | 1n;
    const fd = (0xfd12n << 112n) | 0x5n;
    const { r, desc } = await redactOne(`link fe80::1 ptr ${nibbleName(fe80)} and ${nibbleName(fd)}`);
    expect(r.code).toBe(0);
    expect(desc).toBe(`link 2001:db8::1 ptr ${nibbleName(DOC6 + 1n)} and ${nibbleName(DOC6 + 2n)}`);
  });

  test("mapped and NAT64: a private embedded IPv4 takes its alias in hex, the prefix kept", async () => {
    // a01:203 is 10.1.2.3; c0a8:105 is 192.168.1.5.
    const { r, desc } = await redactOne("hosts 10.1.2.3, ::ffff:a01:203, 64:ff9b::c0a8:105 and ::ffff:808:808");
    expect(r.code).toBe(0);
    expect(desc).toBe("hosts 192.0.2.1, ::ffff:c000:201, 64:ff9b::c000:202 and ::ffff:808:808");
  });

  test("in-addr.arpa: a public reverse name is untouched, even when it starts like a private address", async () => {
    // 10.0.0.1.in-addr.arpa is the PTR name of the public 1.0.0.10.
    const { r, desc } = await redactOne("ptr 10.0.0.1.in-addr.arpa answered");
    expect(r.code).toBe(0);
    expect(desc).toBe("ptr 10.0.0.1.in-addr.arpa answered");
  });

  test("in-addr.arpa: plain and reverse names are numbered in the order they appear", async () => {
    const { r, desc } = await redactOne("10.9.9.9 asked for 5.1.168.192.in-addr.arpa");
    expect(r.code).toBe(0);
    expect(desc).toBe("192.0.2.1 asked for 2.2.0.192.in-addr.arpa");
  });

  test("reserved aliases: a documentation reverse name or mapped alias already present keeps its number", async () => {
    const { r, desc } = await redactOne("seen 1.2.0.192.in-addr.arpa and ::ffff:c000:202, then 10.9.9.9");
    expect(r.code).toBe(0);
    expect(desc).toBe("seen 1.2.0.192.in-addr.arpa and ::ffff:c000:202, then 192.0.2.3");
  });

  test("base64: a run that decodes to a private address or an unmapped SID refuses the run", async () => {
    const blobs = [
      Buffer.from("net use \\\\10.1.2.3\\share", "utf8").toString("base64"),
      Buffer.from("Invoke-Thing -Target 192.168.4.20", "utf16le").toString("base64"),
      Buffer.from("owner S-1-5-21-1111111111-2222222222-3333333333-500", "utf8").toString("base64"),
    ];
    for (const blob of blobs) {
      const { r, out } = await redactOne(`ran -enc ${blob} on host`);
      expect(r.code).toBe(1);
      expect(r.err).toContain("detections[0].description");
      expect(r.err).not.toContain(blob);
      expect(existsSync(out)).toBe(false);
    }
    const harmless = Buffer.from("hello from the lab, nothing private here", "utf8").toString("base64");
    const ok = await redactOne(`ran -enc ${harmless} on host`);
    expect(ok.r.code).toBe(0);
    expect(ok.desc).toContain(harmless);
  });
});
