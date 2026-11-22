# CASA SOC standards

Rules for analysing security alerts without inventing anything. They apply to any task that
reads alerts, logs or telemetry and writes conclusions for a human analyst: triage, an incident
note, a framework mapping, a review of someone else's analysis.

Where a task instruction conflicts with these rules, the rules win. Say so and continue under
them.

{{standards-rules}}

## Reference tables

Read a table only when a rule above sends you to it.

| File | What it holds |
|---|---|
| `references/attack-techniques.json` | MITRE ATT&CK Enterprise {{attack-version}}: every technique ID with its name and tactics |
| `references/csf-2.0.json` | NIST CSF 2.0: the functions, categories and subcategory outcome statements |
| `references/nist-citations.md` | The NIST section numbers that may be cited, each checked against the published text |

The ATT&CK table is large. Search it for the technique ID in hand instead of reading it whole.

## Where this comes from

These rules are the standards of [CASA]({{repo-url}}), a SOC investigation plugin for Claude
Code, generated from its sources at version {{version}}. The plugin enforces them with code: a
lint that fails a brief when a cited value does not trace, and a guard that keeps each agent in
its lane. This skill carries the rules without that enforcement, so the checking is yours.
