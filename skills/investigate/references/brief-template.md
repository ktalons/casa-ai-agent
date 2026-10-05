# Analyst brief template (`casa.brief/v1`)

The brief is a Markdown file whose first fenced `json` block is the machine-readable record;
the prose after it is for the analyst. Both must agree.

````markdown
# CASA brief — <intake basename> — <generated>

```json
{
  "schema": "casa.brief/v1",
  "intake": { "path": "...", "schema": "talonsoclab.soc-intake/v1", "generated": "...", "sha256": "..." },
  "status": "findings" | "quiet" | "malformed",
  "threads": [
    {
      "id": "T1", "title": "...", "hosts": [], "rule_ids": [], "attack": [], "tactic_sequence": [],
      "hypothesis": "...", "verdict": "supported|refuted|undetermined",
      "confidence": { "level": "High|Medium|Low", "justification": "enumerate each independent reference the level rests on, e.g. a rule_id chain across <host A> and <host B>, a rule description that asserts the source relation, recon:<host A>:<port>/<proto>", "would_raise": [] },
      "findings_from": ["casa:log-analyst", "..."], "summary": "..."
    }
  ],
  "overall_confidence": { "level": "...", "basis": "threat|coverage", "justification": "..." },
  "csf": [ { "function": "DE", "category": "DE.AE", "subcategory": "DE.AE-02", "why": "..." } ],
  "options": [ { "kind": "investigate|contain|harden|liveness", "action": "...", "tradeoff": "...", "depends_on": [] } ],
  "data_requests": [ { "id": "...", "source": "...", "fields": [], "why": "..." } ],
  "trace": [ "OBSERVE: ...", "HYPOTHESIZE: ...", "VERIFY: ..." ],
  "injection_flags": [],
  "verify": { "lint": "pass|fail", "report": "..." }
}
```

## Summary
Two to five sentences. Lead with the most severe thread and its verdict.

## Threads
### T1 — <title>  (<verdict>, <confidence>)
What the evidence shows, each claim followed by its reference in parentheses, e.g. (rule 100220 on talondc01).
**Alternatives considered** — only for Medium/Low.
**What would raise confidence** — exact data, exact source.

## Mapping
CSF 2.0 and ATT&CK rows from the purple-team mapper, each with a one-line "why".

## Options for the analyst
Numbered. Each: the action, what it achieves, what it costs or risks, what it depends on.

## Data requests
What the intake could not show and where it lives.

## Reasoning trace
The ordered trace, including anything VERIFY stripped and why.
````
