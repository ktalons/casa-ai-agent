# CASA brief — brute-force-dc-chain — 2026-07-20

```json
{
  "schema": "casa.brief/v1",
  "intake": { "path": "intake/fixtures/brute-force-dc-chain.intake.json", "schema": "talonsoclab.soc-intake/v1", "generated": "2026-07-20", "sha256": "6b7ad13fcf6eee29186aad50fa82d05db93d5b6cfd8db639958e3457182f7844" },
  "status": "findings",
  "threads": [
    {
      "id": "T1",
      "title": "Brute force on talondellbox escalating to DCSync-class replication on talondc01",
      "hosts": ["talondellbox", "talondc01"],
      "rule_ids": ["100200", "100210", "100215", "100220"],
      "attack": ["T1110", "T1110.001", "T1078", "T1021.002", "T1003.006"],
      "tactic_sequence": ["credential-access", "lateral-movement", "credential-access"],
      "hypothesis": "The four detections are one chain: a failed-auth burst on talondellbox, a success from the same source, a network logon to talondc01 from that source, then a directory replication request from a non-DC host.",
      "verdict": "supported",
      "confidence": { "level": "High", "justification": "Four detections on two hosts form a time-ordered tactic progression (02:14 → 02:17 → 02:18 → 02:19), and the recon delta independently reports a new RDP exposure on the first host.", "would_raise": [] },
      "findings_from": ["casa:log-analyst", "casa:endpoint-analyst", "casa:network-analyst"],
      "summary": "One escalating chain from workstation to domain controller; rule 100220 (DRSUAPI replication from a non-DC host) is the critical item."
    }
  ],
  "overall_confidence": { "level": "High", "basis": "threat", "justification": "Chain is internally consistent and corroborated by the recon delta." },
  "csf": [
    { "function": "DE", "category": "DE.AE", "subcategory": "DE.AE-03", "why": "four alerts across two hosts correlated into one chain" },
    { "function": "DE", "category": "DE.CM", "subcategory": "DE.CM-01", "why": "the network logon and replication request were observed on monitored services" },
    { "function": "RS", "category": "RS.AN", "subcategory": "RS.AN-03", "why": "root cause established as credential compromise on talondellbox" },
    { "function": "RS", "category": "RS.MI", "subcategory": "RS.MI-01", "why": "containment options are offered for both hosts" },
    { "function": "PR", "category": "PR.AA", "subcategory": "PR.AA-05", "why": "the account that reached talondc01 should not have replication rights" }
  ],
  "options": [
    { "kind": "contain", "action": "Isolate talondellbox from the workstation VLAN", "tradeoff": "Stops further lateral movement; interrupts whoever uses that workstation", "depends_on": [] },
    { "kind": "investigate", "action": "Pull TargetUserName for rule 100210 and 100215 from the raw alerts, then reset that account", "tradeoff": "One query; the reset locks out a legitimate user if the account was shared", "depends_on": ["data request DR1"] },
    { "kind": "investigate", "action": "Hunt talondc01 for 4662 events carrying the replication GUIDs and for krbtgt changes", "tradeoff": "Confirms or rules out a completed DCSync; needs the DC security log", "depends_on": [] },
    { "kind": "harden", "action": "Close the new 3389/tcp exposure on talondellbox reported in the recon delta", "tradeoff": "Removes the likely entry path; breaks RDP for anyone who relied on it", "depends_on": [] }
  ],
  "data_requests": [
    { "id": "DR1", "source": "wazuh-alerts data.win.eventdata", "fields": ["TargetUserName", "IpAddress", "LogonType"], "why": "v1 intake carries no account or source address, so the account to reset cannot be named" }
  ],
  "trace": [
    "OBSERVE: 4 detections, 2 hosts, levels 12–15, span 02:14:31Z–02:19:47Z; recon delta names talondellbox, which is also a detection agent",
    "HYPOTHESIZE: one thread; merge rule (a) tactic progression credential-access → lateral-movement → credential-access on the DC, all within 6 minutes",
    "INVESTIGATE: log-analyst supported the chain; endpoint-analyst undetermined on the account (DR1); network-analyst tied recon:talondellbox:3389/tcp to the thread",
    "VERIFY: all 4 rule IDs, 2 hosts and 5 technique IDs trace to the intake; no IP literals; nothing stripped",
    "MAP: DE.AE-03, DE.CM-01, RS.AN-03, RS.MI-01, PR.AA-05"
  ],
  "injection_flags": [],
  "verify": { "lint": "pass", "report": "0 unknown tokens" }
}
```

## Summary

Four level-12 to level-15 detections between 02:14 and 02:19 UTC form one escalating chain:
a failed-authentication burst on talondellbox (rule 100200), a success from the same source
(rule 100210), a network logon to talondc01 from a source with a preceding failure burst
(rule 100215), and a directory replication request from a host that is not a domain
controller (rule 100220). The last is DCSync-class credential theft (T1003.006) and is the
critical item. The recon delta's new 3389/tcp exposure on talondellbox is the plausible
entry path and corroborates the chain.

## Threads

### T1 — Brute force on talondellbox escalating to DCSync-class replication on talondc01 (supported, High)

The sequence is time-ordered and tactic-consistent (rule 100200 → 100210 on talondellbox;
rule 100215 → 100220 on talondc01). T1110.001 then T1078 then T1021.002 then T1003.006 is a
documented progression. Two independent evidence sources corroborate: the alert chain and
the recon delta (recon:talondellbox:3389/tcp). No benign reading fits a replication request
from a non-DC host minutes after a brute-forced logon.

**What would raise confidence** — nothing further is needed for the chain itself; the
account name (DR1) is needed to act, not to conclude.

## Mapping

DE.AE-03 (correlation across sources), DE.CM-01 (network services monitored), RS.AN-03
(root cause), RS.MI-01 (containment), PR.AA-05 (least privilege on replication rights).

## Options for the analyst

1. Isolate talondellbox from the workstation VLAN. Stops further movement; interrupts its user.
2. Pull TargetUserName for rules 100210 and 100215 from the raw alerts, then reset that
   account. One query; a reset locks out a legitimate user if the account was shared.
3. Hunt talondc01 for 4662 events with the replication GUIDs and for krbtgt changes. Confirms
   whether the DCSync completed; needs the DC security log.
4. Close the new 3389/tcp exposure on talondellbox. Removes the likely entry path; breaks RDP
   for anyone who relied on it.

## Data requests

DR1 — wazuh-alerts data.win.eventdata: TargetUserName, IpAddress, LogonType. The v1 intake
carries no account or source address, so the account to reset cannot be named from it.

## Reasoning trace

See the trace array above. Nothing was stripped at VERIFY.
