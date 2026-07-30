# Intake Triage Workflow

**Triggers**: A `talonsoclab.soc-intake/v1` JSON artifact (from TalonSocLab's digest collector, or a fixture under `intake/fixtures/`). This is the entry point when CASA is handed SOC telemetry rather than a free-text question — it classifies what's in the intake and routes each thread to the right investigation workflow.

## Contract

The intake shape is fixed by `intake/schema/soc-intake.v1.schema.json` and documented in `intake/README.md`. Key facts for reasoning:

- `detections[]` are **pre-filtered to level >= 12** and already cited (rule ID, agent, MITRE). They are a narrow high-severity slice, not the full event stream — absence of an alert is not absence of activity.
- `recon_delta` is attack-surface change, verbatim. Treat it as **corroborating context** for the detections, not a separate report.
- The producer does **no reasoning**. Correlation, severity judgement, and response framing are entirely CASA's job.

## Routing

```
soc-intake/v1 JSON
     |
     v
[Overseer] — validate shape, group detections
     |     group by agent + MITRE tactic; note recon_delta overlaps
     |
     +--> auth/credential techniques (T1110, T1078, T1021, T1003...) --> AuthAnomalyInvestigation + LateralMovementDetection
     +--> C2 / exfil techniques (T1071, T1041, T1048...)             --> NetworkBeaconingDetection / DataExfiltrationAnalysis
     +--> recon_delta shows new exposure on a detection's agent      --> fold into that thread as attack surface
     |
     v
[LogAnalyst] / [NetworkAnalyst] — per-thread analysis (see the routed workflow)
     |
     v
[PurpleTeamMapper] — map the correlated picture to NIST CSF 2.0 + ATT&CK
     |
     v
[Overseer] — synthesize one analyst brief
```

## Triage steps

1. **Validate.** Confirm the artifact parses and matches v1 (`bun intake/Validate.ts <file>`). A malformed intake is a data-plane bug — report it, don't reason over it.
2. **Empty check.** If `detections` is empty: report no actionable findings and recommend a pipeline-liveness check (agents reporting? collector running?). Do **not** manufacture findings. Stop here.
3. **Group, don't itemize.** Cluster detections by agent and by MITRE tactic. Multiple detections on one agent, or a tactic progression across agents, usually mean **one chain** — say so.
4. **Correlate the recon delta.** If `recon_delta` names a host that also appears in `detections`, tie them together (new exposure as a likely vector). If it's unrelated, note it separately.
5. **Route** each group to the matching investigation workflow above. Run them, then hand the combined findings to PurpleTeamMapper.
6. **Synthesize** one brief. Order threads by severity. Lead with the highest-level detection and its chain.

## Output (explainability standard)

Follow `ExplainabilityStandards.md`. Every intake triage produces:

- **Reasoning trace** — how detections were grouped into chains and why.
- **Per-thread finding** — the correlated story, each claim citing the `rule_id` / `agent` / MITRE ID it rests on.
- **Confidence** — High/Medium/Low, with the specific evidence behind it. Confirmed chains are High; single-signal hypotheses (e.g. beaconing from periodicity alone) are Medium and must name what would raise them.
- **NIST CSF 2.0 mapping + recommended next steps** — framed as options for the analyst, never auto-executed.

Invent nothing. Every hostname, rule ID, and technique in the brief must trace to the intake.

## Evaluation

The `intake/fixtures/` artifacts are the eval set. For each fixture: run this workflow on `*.intake.json`, then grade the analysis against the paired `*.expected.md` checklist.

- `brute-force-dc-chain` — must reconstruct the escalation chain and flag the DCSync as critical (confidence High).
- `beaconing-recon-delta` — must correlate the two detections with the new port and stay at Medium pending PCAP confirmation.
- `quiet-day` — must report nothing and recommend a liveness check (tests against fabrication).

This is the concrete measure behind the roadmap's "validated against representative log volume" gate.
