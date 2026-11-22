# CASA evidence check

Checks a piece of security analysis against the input it was written from. Every concrete value
the analysis names must appear in that input or in a reference table. A value that appears in
neither was invented, whatever the reason, and the analysis is not finished until it is gone.

This check proves that cited values exist. It does not prove the reasoning is right.

## What you need

- The analysis: a brief, a finding, an incident note.
- The input it was written from: an alert digest, an intake file, the raw alerts.
- The `casa-soc-standards` skill, for the ATT&CK and NIST CSF 2.0 tables.

Without the input there is nothing to check against. Say so and stop.

## The values to check

Go through the analysis once per row. Collect every value of that kind, then apply the rule.

{{kinds-table}}

Matching is exact. A rule ID that is a substring of a longer number in the input does not
count, and neither does a host that only resembles one.

## Three results, not two

- **Traces.** The value is in the input.
- **Beyond the input.** The value is real but the input does not carry it: an ATT&CK technique
  that is in the table, or an event ID or service port listed in
  `references/lint-references.json`. Analyses name these in data requests ("pull event
  `<event_id>` from `<host>`"). Report them, do not fail them, and make sure the sentence does
  not claim the input showed them.
- **Unknown.** The value is in neither. This fails the check.

## What is not a claim

- A range such as "ports 1-1024" is a query scope, not a statement about one port.
- A value inside an exact command the analyst is asked to run is part of the request.
- Placeholders such as `<host>` and `<rule_id>` are not values.
- The hash of the input file itself, when the analysis records it.

## When the check fails

For each unknown value: remove the claim or correct it to what the input says. Lower the
confidence of the thread it sat in by one level. Record what was removed and why in the
analysis's reasoning trace. Then run the whole check again, because a correction can introduce
a new value.

Report the result in three lines: values checked per kind, values beyond the input, and unknown
values with the reason for each.

## The same check in code

The [CASA repository]({{repo-url}}) carries this check as a deterministic script. With Bun and
a clone of the repository, for an analysis written from a `talonsoclab.soc-intake` file:

```bash
bun evals/Lint.ts --brief <brief.md> --intake <intake.json>
```

It exits 1 and lists every value that does not trace. Where it can run, prefer it to this
manual check: a script does not get tired on the fortieth timestamp.

Generated from the CASA sources at version {{version}}.
