---
name: casa-evidence-check
description: "Checks a security brief, finding or incident note against the alerts it was written from: every rule ID, host, address, user, event ID, port, domain, hash, technique ID and timestamp must appear in the input or in a reference table. Use when reviewing AI-written security analysis for invented details, before sending a SOC brief, or after editing one."
license: MIT
compatibility: "Needs the casa-soc-standards skill from the same pack for the ATT&CK and NIST CSF tables."
metadata:
  author: "ktalons"
  version: "5.2.0"
  source: "https://github.com/ktalons/casa-ai-agent"
---

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

| Value | Lint kind | Traces when |
|---|---|---|
| Rule ID | `rule_id` | It equals the `rule_id` of a detection in the input. Checked where the text says rule, rule ID or SID, or lists `rule_ids`. |
| Alert ID | `alert_id` | It equals an `alert_id` in the input. |
| Host | `host` | The input names it, on a detection or in the recon delta. An account name the input carries is not an invented host. |
| ATT&CK technique ID | `attack` | It is in the ATT&CK table of `casa-soc-standards`, written in its canonical form (`T<number>` or `T<number>.<sub>`). |
| NIST CSF 2.0 ID | `csf` | It is in the CSF table of `casa-soc-standards`, written in its canonical form. |
| IPv4 address | `ip` | It is present in the input, or is a special-use address listed in the reference file. |
| IPv6 address | `ipv6` | It is present in the input, compared in canonical form, or is a special-use address listed in the reference file. |
| User or account | `user` | The input names it. A `DOMAIN\user` form traces when the account part is named. |
| Event ID | `event_id` | It is in the input, or is a real event ID listed in the reference file. |
| Port | `port` | It is in the input, or is a well-known service port listed in the reference file. A host and port written together must appear together in the input. |
| Domain | `domain` | It is present in the input, or is a documentation domain listed in the reference file. |
| Hash | `hash` | It is present in the input. |
| Date or time | `timestamp` | It is present in the input at the precision written. A time in a proposed query window traces when it falls inside the input's own window. |

Matching is exact. A rule ID that is a substring of a longer number in the input does not count,
and neither does a host that only resembles one.

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
analysis's reasoning trace. Then run the whole check again, because a correction can introduce a
new value.

Report the result in three lines: values checked per kind, values beyond the input, and unknown
values with the reason for each. Write each count with the number first ("4 rule IDs, 3 ports"):
a number written after the kind word reads as a value of that kind.

## The same check in code

The [CASA repository](https://github.com/ktalons/casa-ai-agent) carries this check as a
deterministic script. With Bun and a clone of the repository, for an analysis written from a
`talonsoclab.soc-intake` file:

```bash
bun evals/Lint.ts --brief <brief.md> --intake <intake.json>
```

It exits 1 and lists every value that does not trace. Where it can run, prefer it to this manual
check: a script does not get tired on the fortieth timestamp.

Generated from the CASA sources at version 5.2.0.
