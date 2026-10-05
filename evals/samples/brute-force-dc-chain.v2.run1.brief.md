# CASA brief — brute-force-dc-chain.v2.intake.json — 2026-07-20T03:00:00Z

```json
{
  "schema": "casa.brief/v1",
  "intake": {
    "path": "intake/fixtures/brute-force-dc-chain.v2.intake.json",
    "schema": "talonsoclab.soc-intake/v2",
    "generated": "2026-07-20T03:00:00Z",
    "sha256": "aa99a1083f259cc8c812e5275321e1c5bd4cc590cf199ce75adf9a2ba7bad487"
  },
  "status": "findings",
  "threads": [
    {
      "id": "T1",
      "title": "Brute force on talondellbox to svc-backup logon on talondc01 to DCSync-class replication",
      "hosts": ["talondellbox", "talondc01"],
      "rule_ids": ["100220", "100215", "100210", "100200"],
      "attack": ["T1110", "T1110.001", "T1078", "T1021.002", "T1003.006"],
      "tactic_sequence": ["credential-access", "lateral-movement", "credential-access"],
      "hypothesis": "The four detections form one escalating chain: brute force against svc-backup from 10.10.20.77 on talondellbox, then a successful network logon of svc-backup to talondc01 from 10.10.30.14, then DCSync-class directory replication from that non-DC source.",
      "verdict": "supported",
      "confidence": {
        "level": "High",
        "justification": "Three independent references: (1) a time-ordered chain across talondellbox and talondc01 (rule 100200, 100210, 100215, 100220 in order within about 5m16s, user svc-backup on rules 100210, 100215 and 100220); (2) the description of rule 100215, which itself asserts a preceding failed-auth burst; (3) recon:talondellbox:3389/tcp, a new exposure on a thread host. Additionally rules 100215 and 100220 share src_ip and user, 85 s apart. A sanctioned-replication reading is not excluded by data but has no supporting evidence in the intake.",
        "would_raise": [
          "talondc01 event 4662 SubjectUserName and Properties (replication GUIDs), and 4624 LogonType and IpAddress",
          "IP-to-host mapping showing whether 10.10.20.77 and 10.10.30.14 are one machine or a pivot",
          "talondellbox events 4625 with TargetUserName for the burst"
        ]
      },
      "findings_from": ["casa:log-analyst", "casa:endpoint-analyst", "casa:network-analyst", "casa:purple-team-mapper", "casa:detection-engineer", "casa:threat-intel"],
      "summary": "A failed-auth burst and a success on talondellbox are followed within about 2.5 minutes by a svc-backup network logon to talondc01 and by directory replication requested from a non-DC source. The DC segment is the critical item."
    }
  ],
  "overall_confidence": {
    "level": "High",
    "basis": "threat",
    "justification": "Same as T1. The source addresses differ between the two hosts, so the first hop is carried by the account, time order and the rule 100215 description, not by address."
  },
  "csf": [
    { "function": "DE", "category": "DE.AE", "subcategory": "DE.AE-02", "why": "Correlating four alerts across two hosts into one chain." },
    { "function": "DE", "category": "DE.AE", "subcategory": "DE.AE-03", "why": "Information from multiple sources (talondellbox, talondc01, recon delta) is correlated." },
    { "function": "DE", "category": "DE.CM", "subcategory": "DE.CM-09", "why": "No process-level view of what ran under svc-backup on either host." },
    { "function": "RS", "category": "RS.AN", "subcategory": "RS.AN-03", "why": "Analysis to establish what happened and the root cause." },
    { "function": "PR", "category": "PR.AA", "subcategory": "PR.AA-05", "why": "Replication rights held by svc-backup need review." },
    { "function": "PR", "category": "PR.IR", "subcategory": "PR.IR-01", "why": "RDP on talondellbox became reachable from the workstation VLAN." },
    { "function": "ID", "category": "ID.AM", "subcategory": "ID.AM-01", "why": "The two source addresses cannot be mapped to hosts from the intake." }
  ],
  "options": [
    { "kind": "investigate", "action": "Pull talondc01 events 4662 and 4624 and the IP-to-host mapping first.", "tradeoff": "Read-only and cheap, but only confirms the DC segment and the address link; depends on 4662 auditing being enabled.", "depends_on": ["DR1", "DR2", "DR4"] },
    { "kind": "contain", "action": "Analyst may consider disabling or resetting svc-backup and isolating the host behind 10.10.30.14.", "tradeoff": "Stops further use of the credential but may break backup jobs; a reset does not undo a completed replication.", "depends_on": ["analyst decision", "DR4"] },
    { "kind": "contain", "action": "If DR1 confirms replication GUIDs requested by svc-backup, analyst may consider scoping a krbtgt and privileged-credential rotation.", "tradeoff": "Addresses a completed DCSync but is disruptive and needs a sequenced rotation with the AD owner.", "depends_on": ["DR1", "AD owner agreement"] },
    { "kind": "harden", "action": "Review replication rights of svc-backup and whether RDP exposure on talondellbox is intended.", "tradeoff": "Reduces recurrence but may affect admin workflows; RDP is not shown to be the vector.", "depends_on": ["DR6", "DR5"] },
    { "kind": "harden", "action": "Review the draft correlation rules and Sigma chain under detections/proposed/, fill placeholders, test, and promote by hand if they pass.", "tradeoff": "One correlated alert for the chain, no new single-stage coverage; user-only correlation across hosts can chain unrelated activity; rules are untested.", "depends_on": ["DR1", "DR4"] }
  ],
  "data_requests": [
    { "id": "DR1", "source": "talondc01 Security log, event 4662", "fields": ["SubjectUserName", "SubjectDomainName", "Properties", "AccessMask"], "why": "Who requested replication and which replication GUIDs were used." },
    { "id": "DR2", "source": "talondc01 Security log, event 4624 before the 4662", "fields": ["IpAddress", "LogonType", "LogonProcessName", "TargetLogonId"], "why": "Confirms logon source and type, and ties the 4662 session." },
    { "id": "DR3", "source": "talondellbox Security log 4625 and 4624, conn.log or firewall logs", "fields": ["TargetUserName", "IpAddress", "LogonType", "id.resp_p"], "why": "Rule 100200 has a null user, and the port of the failed attempts (3389/tcp or not) is not shown." },
    { "id": "DR4", "source": "DHCP, ARP, NAT or CMDB records", "fields": ["host owning 10.10.20.77", "host owning 10.10.30.14"], "why": "Whether the two addresses are one machine, NAT or a pivot." },
    { "id": "DR5", "source": "Firewall change log for talondellbox:3389/tcp", "fields": ["rule change timestamp", "author"], "why": "Whether the RDP exposure predates the first detection." },
    { "id": "DR6", "source": "AD ACL on the domain naming context; list of sanctioned sync and backup accounts", "fields": ["DS-Replication-Get-Changes holders", "DC list"], "why": "Rules out a sanctioned replication source." },
    { "id": "DR7", "source": "Sysmon events 1 and 3 on talondellbox and on the host behind 10.10.30.14; Security 4688", "fields": ["Image", "ParentImage", "CommandLine", "User", "DestinationIp"], "why": "Process that issued the replication request and what ran under svc-backup." },
    { "id": "DR8", "source": "Zeek dce_rpc.log and conn.log for talondc01; talondc01 events 4738 and 4769", "fields": ["id.orig_h", "id.resp_h", "operation", "TargetUserName"], "why": "Wire confirmation of replication and scope of downstream impact." }
  ],
  "trace": [
    "OBSERVE: intake validated; v2; 4 detections, 2 hosts (talondellbox 2, talondc01 2); levels 12-15; span 02:14:31Z to 02:19:47Z (about 5m16s); tactics credential-access, lateral-movement, persistence; recon_delta names talondellbox (3389/tcp new), which is also a detection agent; truncated false; pipeline ok (collector_ok true, 3 agents reporting). Cross-host link as data: user svc-backup on rules 100210, 100215 and 100220; src_ip differs across hosts (10.10.20.77 vs 10.10.30.14).",
    "HYPOTHESIZE: one thread. Rules (a) tactic progression credential-access, lateral-movement, credential-access in time order, (b) detections within 15 minutes across hosts, and (c) recon change naming talondellbox all fired. Workflow card credential-theft-dcsync. Specialists: log-analyst, endpoint-analyst, network-analyst. All technique IDs are in the local table, so threat-intel was run only for indicator context.",
    "INVESTIGATE: three specialists returned valid findings: log-analyst High, endpoint-analyst Medium, network-analyst High. Overseer note: the task prompt to endpoint-analyst contained a transcription error in the groups of rule 100200; it was corrected by message and the intake file was named as authoritative. The endpoint-analyst re-ran and its level was unchanged.",
    "VERIFY: bun evals/Lint.ts passed for all three findings; nothing stripped. Normalised two formatting items: endpoint-analyst level written as lowercase medium, and agent names without the casa: prefix. No rubric violations: Medium finding carries alternatives, High findings carry at least two independent evidence refs, every option has a tradeoff.",
    "VERIFY (disagreement): findings differed (High, Medium, High). Independent references counted: (1) time-ordered chain across two hosts, (2) rule 100215 description asserting a preceding failed-auth burst, (3) recon:talondellbox:3389/tcp. Count 3, no benign fit supported by the intake, so the thread is High. The endpoint-analyst's Medium rested on the address mismatch and the null user on rule 100200, which are missing fields the intake cannot carry; they are recorded as data requests DR3 and DR4, not a downgrade.",
    "MAP: purple-team-mapper produced the CSF mapping and visibility gaps; detection-engineer drafted Sigma and Wazuh rules under detections/proposed/ (untested, placeholders unresolved); threat-intel found only internal indicators and no external lookup applies."
  ],
  "injection_flags": [],
  "verify": { "lint": "pass", "report": "bun evals/Lint.ts --brief: 4 rule IDs, 2 hosts, 5 ATT&CK IDs, 7 CSF IDs, 2 IPv4 literals; every citation traces to the intake or a reference table" }
}
```

## Summary
One escalating chain, supported at High. A failed-auth burst and a success on talondellbox are followed, within about 5 minutes, by a svc-backup network logon to talondc01 and by directory replication requested from a non-DC source (rule 100220, level 15). The replication is the critical item. The source address differs between the two hosts, so the link from talondellbox to the DC is carried by the account and time order; it is listed as a data request.

## Threads
### T1 — Brute force to DC logon to DCSync-class replication  (supported, High)
- A burst of 20 or more failures in 60 s from 10.10.20.77 on talondellbox (rule 100200, 02:14:31Z), then a success after failures for svc-backup from the same source (rule 100210, 02:17:05Z).
- 77 s later, a network logon of svc-backup to talondc01 from 10.10.30.14 (rule 100215, 02:18:22Z), whose description asserts a preceding failed-auth burst.
- 85 s after that, DRSUAPI GetNCChanges requested from a host that is not a domain controller, same user and src_ip (rule 100220, 02:19:47Z, T1003.006).
- RDP on talondellbox is newly reachable from the workstation VLAN (recon:talondellbox:3389/tcp). It is a contributing exposure, not shown as the vector. The recon text is dated by day only.
- Gaps: rule 100200 has no user; the two source addresses are not related by the intake; no 4662 Properties, logon type or process detail.

**What would raise confidence** — talondc01 Security 4662 (SubjectUserName, Properties) and 4624 (IpAddress, LogonType); DHCP/ARP/NAT or CMDB mapping for the two addresses; talondellbox 4625 TargetUserName.

## Mapping
ATT&CK tactic order: credential-access (T1110, T1110.001), then lateral-movement and persistence (T1021.002, T1078), then credential-access (T1003.006). CSF rows are in the JSON record above, primary function DETECT with PR and ID support.

## Options for the analyst
1. Investigate first: pull talondc01 4662 and 4624 and the address mapping. Read-only; confirms the DC segment and the address link; needs 4662 auditing enabled.
2. Contain (analyst decision): consider disabling or resetting svc-backup and isolating the host behind 10.10.30.14. Stops credential use; may break backups; does not undo a completed replication.
3. Contain, conditional: if replication GUIDs are confirmed, consider scoping a krbtgt and privileged-credential rotation. Disruptive; needs the AD owner.
4. Harden: review replication rights of svc-backup and the RDP exposure on talondellbox.
5. Harden: review the draft correlation rules and Sigma chain in detections/proposed/ (2026-10-05-T1.*). Untested, placeholders unresolved, user-only cross-host correlation can chain unrelated activity.

## Data requests
DR1 to DR8 in the JSON record: 4662 and 4624 fields on talondc01, talondellbox 4625 and conn data, address ownership, firewall change log, AD replication ACL and sanctioned accounts, Sysmon process data, Zeek dce_rpc and krbtgt events.

## Reasoning trace
See the `trace` array in the JSON record. Nothing was stripped by VERIFY. Specialist level disagreement (High, Medium, High) was resolved to High on three independent references.
