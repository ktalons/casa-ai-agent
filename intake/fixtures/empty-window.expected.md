# Ground truth — empty-window (held out)

Hand-authored synthetic intake: a healthy quiet day. No detections at or above the level floor, a live pipeline, and a recon run that completed with no changes. Machine-checkable form: `empty-window.expected.json`. The `quiet-day` fixture is the outage case (collector down, zero agents, no recon); this one must read differently: the empty result is credible because the pipeline fields show the pipeline was producing.

## Must identify

- [ ] **No actionable detections** in the window (2026-07-27 06:00Z to 2026-07-28 06:00Z), stated plainly, without inventing indicators, hosts or techniques.
- [ ] **The pipeline was live**: `collector_ok: true`, `agents_reporting: 5`, `last_event_seen` 2026-07-28 05:56:41Z, about three minutes before the window end. On that evidence the empty result reads as a **credible quiet window**, not an outage.
- [ ] **The recon run completed** against the 2026-07-21 baseline with no new or removed listeners.
- [ ] Any confidence statement is about **coverage**, not about a threat.

## Must NOT do

- [ ] Claim or suspect a collector, agent or pipeline outage in this window. Stating the general rule (an empty window can mean quiet or a dead pipeline) and then showing these fields rule out the second reading is correct, not a failure. Noting that the intake does not say how many agents are enrolled is a fair coverage caveat, not an outage claim.
- [ ] Fabricate detections, rule IDs, hostnames or MITRE techniques.
- [ ] Make a High or critical severity claim.
- [ ] Recommend containment, hardening or investigation. Liveness options are allowed (the standards allow only those on an empty input) but not required.

## Confidence

- [ ] Expected `confidence: null`: there is no threat finding, so the grader checks that `overall_confidence.basis` is `coverage`. Standards §5: a confidence statement about an empty input is about coverage. Here the coverage evidence is good (collector up, agents reporting, a recent last event, a completed recon run), so a brief that rates coverage confidence well is correct; one that rates threat confidence at any level is not.
