# Intake — the TalonSocLab seam

This directory is CASA's side of the `talonsoclab.soc-intake` contract: versions v1 and v2, both frozen, and v3, which CASA's own producer emits. [TalonSocLab](https://github.com/ktalons/talonsoclab) is the deterministic **data plane**: it collects, filters, and cites SOC telemetry, then emits a JSON intake artifact. CASA is the **reasoning plane** that consumes it. The contract between the two is this schema — not a shared API or key.

There is **no live dependency** here. These are files: schemas, hand-authored fixtures, a validator, and a producer whose live mode runs only when you point it at an indexer. They let CASA's workflows be written and evaluated against a stable data shape before the lab's pipeline is deployed.

## The `soc-intake/v1` artifact

Produced by the lab's former Python digest collector (`build_intake` / `normalize_alert`), which the lab removed from its public tree on 2026-11-04. A TypeScript producer that ships with CASA replaces it. One object per run:

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | Always `talonsoclab.soc-intake/v1` |
| `generated` | string | UTC date the intake was built, `YYYY-MM-DD` |
| `source` | string | Producing system (`talonsoclab`) |
| `consumer` | string | Intended consumer (`casa-ai-agent (...)`) |
| `detections` | array | Normalized Wazuh alerts (see below) |
| `recon_delta` | string | Newest attack-surface delta from the recon triage queue, verbatim markdown |
| `note` | string | Producer's reminder that reasoning is CASA's job |

Each `detections[]` entry:

| Field | Type | Meaning |
|---|---|---|
| `level` | integer 0–16 | Wazuh rule level |
| `description` | string | Wazuh rule description |
| `rule_id` | string | Wazuh rule ID |
| `agent` | string | Reporting agent (endpoint) name |
| `mitre` | string[] | MITRE ATT&CK technique IDs (`Txxxx[.yyy]`), possibly empty |
| `timestamp` | string | Alert `@timestamp` |

**Provenance.** A live intake carries only alerts at `rule.level >= 12` within a 24h lookback, capped at 200, newest first. Level-12+ is a deliberately narrow slice — in Wazuh, alerts, archives, and raw events are separate channels, so a downstream consumer sees only what scored high enough to alert.

**v1 is frozen.** Any field addition, removal, or rename is a `v2` schema with its own fixtures — never a silent change to v1. `Validate.ts` rejects unexpected fields for exactly this reason.

## The `soc-intake/v2` artifact

v2 (`schema/soc-intake.v2.schema.json`) keeps every v1 field and adds what v1 could not carry:
the window and filter the producer applied, whether the list was truncated, pipeline liveness,
per-detection correlation fields, and a structured recon delta. A producer emits v1 or v2; the
validator accepts both.

| Field | Type | Meaning |
|---|---|---|
| `generated` | ISO 8601 UTC datetime | when the intake was built (v1 used a date) |
| `window` | `{start, end, lookback_hours}` | the interval the detections were pulled from |
| `filter` | `{min_level, cap, order}` | the floor, the cap and `newest_first` |
| `truncated` | boolean | true when the cap cut the list, which then has exactly `cap` entries |
| `pipeline` | `{collector_ok, agents_reporting, last_event_seen}` | lets a quiet window be distinguished from a dead pipeline |
| `recon_delta` | `{markdown, baseline, changes[]}` | the prose plus one `{host, port, proto, status}` per change |

Each `detections[]` entry adds, all required and nullable: `alert_id`, `src_ip`, `dst_ip`,
`user`, `event_id`, `tactic[]`, `groups[]`. `src_ip` and `user` are what make a cross-host chain
data rather than inference.

**Producer change (TalonSocLab).** `build_intake` / `normalize_alert` need to emit the new
top-level blocks and copy `id`, `data.srcip`/`data.win.eventdata.IpAddress`, `data.dstip`,
`data.srcuser`/`data.win.eventdata.TargetUserName`, `data.win.system.eventID`,
`rule.mitre.tactic` and `rule.groups` into each detection. Until then the v2 fixtures here are
hand-authored twins of the v1 ones (`*.v2.intake.json`) and share their ground truth.

## The `soc-intake/v3` artifact

v3 (`schema/soc-intake.v3.schema.json`) is what `producers/wazuh.ts` emits. It keeps every v2
block and adds what a Wazuh lab running Sysmon and Suricata actually produces. v2's single
`user` is gone: v3 says which account acted and which was acted upon.

| Field | Type | Meaning |
|---|---|---|
| timestamps | ISO 8601 instant | up to microseconds, `Z` or a `+hh:mm` offset |
| `filter` | `{min_level, include_rule_ids[], cap, order}` | a detection is in when its level is at least `min_level` or its `rule_id` is listed |
| `counts` | `[{date, matched, included}]` | one entry per UTC date the window touches, oldest first; `matched` above `included` means the cap cut that day |

Each `detections[]` entry carries the v2 fields except `user`, plus (all required, nullable
where it makes sense):

| Field | Meaning |
|---|---|
| `engine` | `{name, rule_id, rev}`: `wazuh`, `suricata` or `sigma`, and that engine's own rule ID (a Suricata signature ID next to the Wazuh `rule_id`) |
| `src_port`, `dst_port`, `proto` | the connection, stated once on the detection |
| `subject_user`, `target_user` | the account that acted (SubjectUserName) and the one logged on or acted upon (TargetUserName) |
| `logon_type` | the Windows logon type, only on 4624, 4625 and 4634 |
| `sysmon` | one typed group matching `event_id`: `process_create` (1), `network_connect` (3), `file_create` (11), `registry_value_set` (13), `dns_query` (22) |
| `suricata` | EVE fields: `event_type`, `signature`, `category`, `severity`, `action`, `flow_id`, `app_proto`, `http_hostname`, `http_url`, `http_user_agent`, `tls_sni`, `dns_rrname` |

The `*.v3.intake.json` fixtures are twins of the v2 ones and share their ground truth: same
detections, `user` split by event (a 4662 actor is the subject, a logon account the target).

**Producer.** `producers/wazuh.ts` replays a recorded export (`--replay`) or queries a live
indexer over HTTPS with certificate verification, and `--redact` applies the lab's mapping
(documentation addresses, `S-1-5-21-0-0-n` SIDs, zeroed Sysmon GUID heads) before anything is
written; it is a second layer with known gaps in encoded text, listed in the runbook. Runbook: [`docs/talonsoclab-integration.md`](../docs/talonsoclab-integration.md), step 3.

## Validation rules beyond the schema

`lib/schema.ts` evaluates the JSON Schema itself and refuses any keyword it does not implement,
so the schema file and the validator cannot drift apart. `lib/semantic.ts` adds what a schema
cannot say: timestamps must be real UTC instants (no 30 February), detections newest-first,
every `level` at or above the floor (`filter.min_level` for v2; for v1 the default floor of 12
is a warning, since the frozen contract has no floor field), no more entries than the cap, no
duplicates (`rule_id`+`agent`+`timestamp` for v1, `alert_id` for v2), v2 and v3 timestamps inside the
window, and a `truncated: true` list exactly `cap` long. v3 adds: a detection below the floor
only when `include_rule_ids` names its rule; `counts` covering each window date once, agreeing
with the detections per day and with `truncated`; a `wazuh` engine's `rule_id` equal to the
detection's, a `suricata` engine only with a Suricata `alert`; exactly one `sysmon` group, the one
matching `event_id`; and `logon_type` only on a logon event. Offsets and microseconds are
checked as written, so 30 February or `+15:00` fails. `fixtures-invalid/` holds one file per
rule with `manifest.json` naming the expected error; `Validate.test.ts` runs them all.

## Layout

```text
intake/
├── schema/soc-intake.v1.schema.json   JSON Schema (draft-07) — the human/tooling contract
├── schema/soc-intake.v2.schema.json   v2: window, filter, pipeline, correlation fields, structured recon delta
├── schema/soc-intake.v3.schema.json   v3: engines, ports, subject/target users, Sysmon and Suricata fields, counts
├── lib/schema.ts, lib/semantic.ts     the two validation passes (zero dependencies)
├── Validate.ts                        CLI: schema pass then semantic pass, v1, v2 and v3
├── producers/wazuh.ts                 Wazuh alerts (replay or live HTTPS) to a v3 intake, with --redact
├── Validate.test.ts                   every fixture passes; every fixtures-invalid/* fails for its reason
├── fixtures/                          representative intakes + paired ground truth
│   ├── <name>.intake.json             v1 intake
│   ├── <name>.v2.intake.json          v2 twin, same ground truth
│   ├── <name>.v3.intake.json          v3 twin, same ground truth
│   ├── <name>.expected.md             human checklist
│   └── <name>.expected.json           machine-checkable ground truth (casa.expected/v1)
├── fixtures-invalid/ + manifest.json  one bad intake per semantic rule
└── raw/
    └── brute-force-dc-chain*.alerts.jsonl  raw Wazuh alerts, replayable through the producer
```

## Validate

```bash
bun intake/Validate.ts            # every fixtures/*.intake.json
bun intake/Validate.ts path.json  # a specific artifact
```

Non-zero exit on any structural violation. Run it against a freshly produced intake before feeding it to CASA.

## Round-trip through the producer

`raw/brute-force-dc-chain.v2.alerts.jsonl` is the raw-alert form of the brute-force fixture, with a
duplicate and a below-floor alert the producer must drop. Replaying it yields the fixture's four
alerts in the same order, as v3, without touching an indexer:

```bash
bun intake/producers/wazuh.ts --replay intake/raw/brute-force-dc-chain.v2.alerts.jsonl --stdout
```

`producers/wazuh.test.ts` checks that parity on every run.

## Evaluation

The fixtures double as an eval set. For each: feed the intake to CASA, run `/casa:investigate` (`skills/investigate/SKILL.md`), and grade the analysis against the paired `*.expected.md` checklist. `quiet-day` specifically checks that CASA reports nothing rather than inventing findings.

## Not in scope

Any TalonSocLab code, and any change to a lab. The producer's live mode is the one network path here: HTTPS to an indexer you name, with certificate verification always on and the password read from the environment or a file.
