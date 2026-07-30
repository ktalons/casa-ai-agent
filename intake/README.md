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

## Layout

```
intake/
├── schema/soc-intake.v1.schema.json   JSON Schema (draft-07) — the human/tooling contract
├── Validate.ts                        zero-dependency structural validator (CI-run)
├── fixtures/                          representative intakes + paired ground truth
│   ├── brute-force-dc-chain.intake.json / .expected.md
│   ├── beaconing-recon-delta.intake.json / .expected.md
│   └── quiet-day.intake.json / .expected.md   (negative control)
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

The fixtures double as an eval set. For each: feed the intake to CASA, run the intake-triage workflow (`.claude/skills/CyberAnalysis/Workflows/IntakeTriage.md`), and grade the analysis against the paired `*.expected.md` checklist. `quiet-day` specifically checks that CASA reports nothing rather than inventing findings.

## Not in scope

Live indexer queries, network calls, credentials, or any TalonSocLab code — those stay on the data-plane side. This directory is files and a validator, nothing more.
