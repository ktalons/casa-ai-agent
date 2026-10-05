# CASA brief — quiet-day.v2 — 2026-07-23T12:00:00Z

```json
{
  "schema": "casa.brief/v1",
  "intake": { "path": "intake/fixtures/quiet-day.v2.intake.json", "schema": "talonsoclab.soc-intake/v2", "generated": "2026-07-23T12:00:00Z", "sha256": "7f118098b06762b55abe137be985883839799f9140d6f7db54e34524f0f705d4" },
  "status": "quiet",
  "threads": [],
  "overall_confidence": { "level": "Low", "basis": "coverage", "justification": "The window holds zero detections, but pipeline.collector_ok is false, pipeline.agents_reporting is 0 and pipeline.last_event_seen is null. The empty window therefore cannot be read as absence of activity: the pipeline is not producing." },
  "csf": [],
  "options": [
    { "kind": "liveness", "action": "Check whether the collector is running and why pipeline.collector_ok is false.", "tradeoff": "Read-only status check, low cost. It confirms the failure but does not restore coverage by itself.", "depends_on": [] },
    { "kind": "liveness", "action": "Check why agents_reporting is 0: list enrolled agents and their last keep-alive time.", "tradeoff": "Read-only. A manager-side listing may not show whether agents are failing or the network path is broken.", "depends_on": ["collector status"] },
    { "kind": "liveness", "action": "Find the last event the pipeline ingested, since last_event_seen is null, to date the start of the gap.", "tradeoff": "Dating the gap bounds the blind period but needs access to the raw alert store, not just the intake.", "depends_on": ["collector status"] }
  ],
  "data_requests": [
    { "id": "DR1", "source": "collector / manager service status", "fields": ["service state", "last restart", "error log tail"], "why": "collector_ok is false and the intake cannot say why." },
    { "id": "DR2", "source": "agent enrollment list", "fields": ["agent id", "status", "last keep-alive"], "why": "agents_reporting is 0, so no host is confirmed to be reporting." },
    { "id": "DR3", "source": "alert store", "fields": ["timestamp of newest event"], "why": "last_event_seen is null; the start of the blind period is unknown." }
  ],
  "trace": [
    "OBSERVE: intake validated (exit 0). Schema v2, window 2026-07-22T12:00:00Z to 2026-07-23T12:00:00Z (24h), filter min_level 12 cap 200, truncated false. detections is empty; recon_delta.changes is empty and baseline is null.",
    "OBSERVE: pipeline reports collector_ok false, agents_reporting 0, last_event_seen null. This names the failing check.",
    "OBSERVE: no imperative strings found in any string field; injection_flags is empty.",
    "BRANCH: zero detections, so the quiet branch applies. No specialist agents were invoked, no technique or severity was assigned, and LEARN was skipped.",
    "VERIFY: lint run on this brief, see verify."
  ],
  "injection_flags": [],
  "verify": { "lint": "pass", "report": "0 rule IDs, 0 hosts, 0 ATT&CK IDs, 0 CSF IDs, 0 IPv4 literals; every citation traces to the intake or a reference table" }
}
```

## Summary
The window contains no detections, but this should not be read as a quiet day. The pipeline block shows the collector is not OK, no agents are reporting, and no event has ever been seen. An empty window can mean quiet or a pipeline that is not producing, and here the pipeline evidence points to the second. Coverage confidence is Low.

## Threads
None. There were no detections to thread.

## Mapping
None. There are no findings to map.

## Options for the analyst
1. **Check collector status.** Confirms why `collector_ok` is false. Low cost and read-only; it does not restore coverage. Depends on nothing.
2. **Check agent reporting.** Lists enrolled agents and their last keep-alive to explain `agents_reporting: 0`. Read-only; it may not separate agent failure from a network path problem. Depends on option 1.
3. **Find the last event seen.** Dates the start of the blind period, since `last_event_seen` is null. Needs access to the raw alert store. Depends on option 1.

## Data requests
- DR1: collector / manager service state, last restart, error log tail.
- DR2: agent enrollment list with status and last keep-alive.
- DR3: timestamp of the newest event in the alert store.

## Reasoning trace
- OBSERVE: intake validated; v2, 24h window, not truncated, zero detections, empty recon_delta. Pipeline: collector_ok false, agents_reporting 0, last_event_seen null.
- No injection strings found.
- Quiet branch: zero Agent calls; LEARN skipped.
- VERIFY: nothing stripped.
