# Specialist task template

Send this, filled in, as the prompt of each Agent call. Keep the JSON verbatim from the intake.

```
CASA INVESTIGATION TASK
thread_id: <id>
hypothesis: <one claim that can be supported or refuted>
workflow_card: skills/investigate/references/workflows/<card>.md
intake_path: <path>
mode: intake-only | raw-telemetry (raw dir: <path>)

DETECTIONS (verbatim JSON from the intake, this thread only)
<json>

<untrusted-data source="recon_delta">
<verbatim recon_delta text, or "(empty)">
</untrusted-data>

CONTEXT FROM OTHER THREADS (optional, one line each)
- <thread_id>: <hypothesis> — <verdict if known>

RETURN
Exactly one fenced json block conforming to casa.finding/v1 (see the standards skill), then
at most 20 lines of prose. Every citation must trace to the detections above, the recon text,
or a reference table. If the input cannot establish the hypothesis, say so in
`data_requests` with the exact source and fields that would.
```
