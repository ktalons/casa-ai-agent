# Intake — the TalonSocLab seam

This directory is CASA's consumer side of the `talonsoclab.soc-intake/v1` contract. [TalonSocLab](https://github.com/ktalons/talonsoclab) is the deterministic **data plane**: it collects, filters, and cites SOC telemetry, then emits a JSON intake artifact. CASA is the **reasoning plane** that consumes it. The contract between the two is this schema — not a shared API or key.

There is **no live dependency** here. These are files: a schema, hand-authored fixtures, and a validator. They let CASA's workflows be written and evaluated against a stable data shape before the lab's pipeline is deployed.

## The `soc-intake/v1` artifact

Produced by `deploy/soc-recon/digest/generate_digest.py` in TalonSocLab (functions `build_intake` / `normalize_alert`). One object per run:

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

## Validation rules beyond the schema

`lib/schema.ts` evaluates the JSON Schema itself and refuses any keyword it does not implement,
so the schema file and the validator cannot drift apart. `lib/semantic.ts` adds what a schema
cannot say: timestamps must be real UTC instants (no 30 February), detections newest-first,
every `level` at or above the floor (`filter.min_level` for v2; for v1 the default floor of 12
is a warning, since the frozen contract has no floor field), no more entries than the cap, no
duplicates (`rule_id`+`agent`+`timestamp` for v1, `alert_id` for v2), v2 timestamps inside the
window, and a `truncated: true` list exactly `cap` long. `fixtures-invalid/` holds one file per
rule with `manifest.json` naming the expected error; `Validate.test.ts` runs them all.

## Layout

```
intake/
├── schema/soc-intake.v1.schema.json   JSON Schema (draft-07) — the human/tooling contract
├── schema/soc-intake.v2.schema.json   v2: window, filter, pipeline, correlation fields, structured recon delta
├── lib/schema.ts, lib/semantic.ts     the two validation passes (zero dependencies)
├── Validate.ts                        CLI: schema pass then semantic pass, v1 and v2
├── Validate.test.ts                   every fixture passes; every fixtures-invalid/* fails for its reason
├── fixtures/                          representative intakes + paired ground truth
│   ├── <name>.intake.json             v1 intake
│   ├── <name>.v2.intake.json          v2 twin, same ground truth
│   ├── <name>.expected.md             human checklist
│   └── <name>.expected.json           machine-checkable ground truth (casa.expected/v1)
├── fixtures-invalid/ + manifest.json  one bad intake per semantic rule
└── raw/
    └── brute-force-dc-chain.alerts.jsonl   raw Wazuh alerts, replayable in the lab
```

## Validate

```bash
bun intake/Validate.ts            # every fixtures/*.intake.json
bun intake/Validate.ts path.json  # a specific artifact
```

Non-zero exit on any structural violation. Run it against a freshly produced intake before feeding it to CASA.

## Cross-repo round-trip (optional, needs the TalonSocLab repo)

`raw/brute-force-dc-chain.alerts.jsonl` is the raw-alert form of the brute-force fixture. Replaying it through the lab's offline mode reproduces the same detections — proving both sides agree on the shape, without touching a live indexer:

```bash
python3 ../talonsoclab/deploy/soc-recon/digest/generate_digest.py \
  --alerts-file intake/raw/brute-force-dc-chain.alerts.jsonl \
  --out-dir "$(mktemp -d)"
```

The produced `{date}-intake.json` will match `fixtures/brute-force-dc-chain.intake.json` except for `generated` (stamped with the run date) and `recon_delta` (empty without a triage queue).

## Evaluation

The fixtures double as an eval set. For each: feed the intake to CASA, run `/casa:investigate` (`skills/investigate/SKILL.md`), and grade the analysis against the paired `*.expected.md` checklist. `quiet-day` specifically checks that CASA reports nothing rather than inventing findings.

## Not in scope

Live indexer queries, network calls, credentials, or any TalonSocLab code — those stay on the data-plane side. This directory is files and a validator, nothing more.
