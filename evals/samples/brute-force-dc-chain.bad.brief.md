# CASA brief — brute-force-dc-chain — 2026-07-20 (deliberately bad sample)

This sample exists so the lint has something to fail on. It cites a rule that is not in the
intake, a host that does not exist, an IP literal the intake never carried, a technique ID
that is not in ATT&CK, and a CSF 1.1 identifier.

```json
{
  "schema": "casa.brief/v1",
  "intake": { "path": "intake/fixtures/brute-force-dc-chain.intake.json", "schema": "talonsoclab.soc-intake/v1", "generated": "2026-07-20", "sha256": "6b7ad13fcf6eee29186aad50fa82d05db93d5b6cfd8db639958e3457182f7844" },
  "status": "findings",
  "threads": [
    {
      "id": "T1",
      "title": "Suspicious activity across the lab",
      "hosts": ["talondellbox", "talonghost"],
      "rule_ids": ["100200", "100999"],
      "attack": ["T1110", "T9999"],
      "tactic_sequence": ["credential-access"],
      "hypothesis": "Something happened on talonghost.",
      "verdict": "supported",
      "confidence": { "level": "Low", "justification": "unclear", "would_raise": [] },
      "findings_from": ["casa:log-analyst"],
      "summary": "talonghost at 10.0.0.50 triggered rule 100999."
    }
  ],
  "overall_confidence": { "level": "Low", "basis": "threat", "justification": "weak" },
  "csf": [ { "function": "PR", "category": "PR.AC", "subcategory": "PR.AC-4", "why": "access control" } ],
  "options": [],
  "data_requests": [],
  "trace": [],
  "injection_flags": [],
  "verify": { "lint": "pass", "report": "" }
}
```

## Summary

The host talonghost (10.0.0.50) fired rule 100999 matching T9999, which maps to PR.AC-4.
