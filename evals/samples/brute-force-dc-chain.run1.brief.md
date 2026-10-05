# CASA brief — brute-force-dc-chain.intake — 2026-07-20

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
      "rule_ids": ["100220", "100215", "100210", "100200"],
      "attack": ["T1110", "T1110.001", "T1021.002", "T1078", "T1003.006"],
      "tactic_sequence": ["credential-access", "lateral-movement", "credential-access"],
      "hypothesis": "The four detections form one escalating chain: brute force on talondellbox, a successful network logon to talondc01, then DCSync-class directory replication against talondc01.",
      "verdict": "supported",
      "confidence": {
        "level": "High",
        "justification": "Scoped to the talondc01 segment: rule 100215 (T1021.002) precedes rule 100220 (T1003.006) on the same DC by about 85 s, inside the workflow card's 15-minute bound, so two independent detections corroborate. The link from talondellbox to the DC logon is inferred from timing and rule wording only; the intake carries no source address or account. Specialists disagreed on the full four-stage chain: log-analyst High, network-analyst Medium, endpoint-analyst undetermined at Medium.",
        "would_raise": [
          "talondc01 event 4624 (LogonType 3) whose source address and account match the talondellbox failures and success",
          "talondc01 event 4662 with replication control-access GUIDs from a non-DC, non-sync account"
        ]
      },
      "findings_from": ["casa:log-analyst", "casa:network-analyst", "casa:endpoint-analyst", "casa:purple-team-mapper", "casa:detection-engineer"],
      "summary": "Rule 100220 (level 15) on talondc01 is the critical item: directory replication requested from a non-DC host, preceded within 85 s by a network logon to the DC (rule 100215) and within about 5 minutes by a failed-auth burst and success on talondellbox (rules 100200, 100210)."
    }
  ],
  "overall_confidence": { "level": "High", "basis": "threat", "justification": "High for DCSync-class activity on talondc01; Medium for attribution of the DC logon to the talondellbox burst." },
  "csf": [
    { "function": "DE", "category": "DE.AE", "subcategory": "DE.AE-02", "why": "Rules 100215 and 100220 need analysis as one related activity sequence." },
    { "function": "DE", "category": "DE.AE", "subcategory": "DE.AE-03", "why": "The chain exists only when rules 100200, 100210, 100215 and 100220 are correlated across both hosts." },
    { "function": "DE", "category": "DE.CM", "subcategory": "DE.CM-09", "why": "Endpoint process and network telemetry on talondellbox is not in the intake." },
    { "function": "PR", "category": "PR.AA", "subcategory": "PR.AA-05", "why": "Rule 100220 shows replication rights exercised from a non-DC; the replication permission scope needs review." },
    { "function": "RS", "category": "RS.AN", "subcategory": "RS.AN-03", "why": "Root cause (source and account of the DC logon) is unresolved." }
  ],
  "options": [
    { "kind": "investigate", "action": "Pull the talondc01 4624 and 4662 events first, then the talondellbox 4625/4624 events, and join source and account across hosts.", "tradeoff": "Confirms or breaks the inferred cross-host link; costs analyst time and depends on log retention and 4662 auditing being enabled.", "depends_on": ["DR1", "DR2", "DR3"] },
    { "kind": "investigate", "action": "Check the rule 100220 requester against the AD DC list and sync/backup service accounts, and review Zeek dce_rpc.log.", "tradeoff": "Rules out or confirms a legitimate replication source; needs an authoritative, current list.", "depends_on": ["DR4", "DR5"] },
    { "kind": "contain", "action": "Consider isolating the host or disabling the account identified by the 4624 and 4662 events, and restricting the workstation-VLAN path to talondellbox:3389/tcp.", "tradeoff": "Stops further replication and lateral movement; disrupts legitimate users and may alert an operator, and the source is not yet identified. The cost of a completed DCSync is total, so the analyst should weigh this promptly.", "depends_on": ["DR1", "DR2", "analyst decision"] },
    { "kind": "contain", "action": "If replication rights were used or krbtgt was touched, weigh a controlled double krbtgt reset and credential rotation for involved accounts.", "tradeoff": "Invalidates stolen domain secrets; operationally heavy and needs sequencing with AD administrators.", "depends_on": ["DR1", "DR6", "AD admin involvement"] },
    { "kind": "harden", "action": "Review which principals hold directory replication rights and restrict them to DCs and named sync accounts.", "tradeoff": "Reduces DCSync exposure; may break undocumented sync or backup tooling.", "depends_on": ["DR4"] },
    { "kind": "harden", "action": "Review why talondellbox:3389/tcp became reachable from the workstation VLAN after the 2026-07-13 baseline.", "tradeoff": "Reduces entry surface if unintended; may break an approved workflow.", "depends_on": ["change records for 2026-07-13 to 2026-07-20"] }
  ],
  "data_requests": [
    { "id": "DR1", "source": "talondc01 Security log, event 4624 (LogonType 3) just before rule 100215, via Wazuh data.win.eventdata", "fields": ["IpAddress", "TargetUserName", "LogonType", "LogonProcessName"], "why": "Names the source and account of the DC logon; the missing cross-host link." },
    { "id": "DR2", "source": "talondellbox Security log, events 4625, 4624, 4672", "fields": ["IpAddress", "TargetUserName", "LogonType", "WorkstationName"], "why": "Gives the brute-force source and the logon type of the success; LogonType 10 would confirm RDP as the entry path." },
    { "id": "DR3", "source": "talondc01 Security log, event 4662, via Wazuh data.win.eventdata", "fields": ["SubjectUserName", "SubjectDomainName", "ObjectType", "Properties", "AccessMask"], "why": "Identifies the replication requester and the rights used; settles DCSync against a benign sync source." },
    { "id": "DR4", "source": "AD computer objects, Wazuh agent.name list, Entra Connect and backup service-account inventory", "fields": ["DC list", "sync and backup service accounts"], "why": "Rules out a legitimate replication source." },
    { "id": "DR5", "source": "Zeek dce_rpc.log and conn.log for talondc01 and talondellbox", "fields": ["id.orig_h", "id.resp_h", "id.resp_p", "endpoint", "operation"], "why": "Independent network confirmation of the replication source and of the burst port." },
    { "id": "DR6", "source": "talondc01 Security log, events 4738 and 4769", "fields": ["TargetUserName", "request counts per source"], "why": "Shows whether krbtgt was touched after the replication." },
    { "id": "DR7", "source": "talondellbox Sysmon events 1 and 3, Security 4688 and 4648", "fields": ["Image", "ParentImage", "CommandLine", "DestinationPort", "TargetServerName"], "why": "Shows what ran after the successful logon and any outbound SMB or RPC toward talondc01." },
    { "id": "DR8", "source": "One sample 4662 event and one 4624 LogonType 3 event from talondc01 in Wazuh JSON", "fields": ["field paths for SubjectUserName, Properties, AccessMask, IpAddress"], "why": "The detection engineer could not draft a requester or GUID rule without confirmed field paths." }
  ],
  "trace": [
    "OBSERVE: intake validated. 4 detections; talondellbox 2, talondc01 2. Levels 12 to 15. Span 02:14:31.671Z to 02:19:47.418Z, about 5 m 16 s. Technique tactics: T1110 and T1110.001 and T1003.006 credential access, T1021.002 lateral movement, T1078 valid accounts. recon_delta names talondellbox and talondc01, both detection agents. No imperative text found.",
    "HYPOTHESIZE: one thread. Rules (a) tactic progression credential access to lateral movement to credential access, (b) all detections within 15 minutes across hosts, and (c) recon_delta naming talondellbox and talondc01 all fired. Workflow card: credential-theft-dcsync. Specialists: log-analyst, endpoint-analyst, network-analyst. All technique IDs are in the local table, so threat-intel was not called; the intake carries no external indicators.",
    "INVESTIGATE: three specialists in parallel. log-analyst supported/High; network-analyst supported/Medium; endpoint-analyst undetermined/Medium. All three agree the DC segment meets the card's High criterion and that the talondellbox to DC link is not shown by the intake.",
    "VERIFY: bun evals/Lint.ts --finding passed for the log-analyst, network-analyst, endpoint-analyst and mapper findings; nothing was stripped. Parenthetical tactic text in network-analyst, endpoint-analyst and mapper citation lists was normalized to bare technique IDs and HTML-escaped comparison operators were restored when saving the findings. Rubric check: Medium findings carry alternatives; the High finding carries four independent detection refs; every option has a tradeoff.",
    "RESOLVE: thread verdict is supported. Confidence is High scoped to the talondc01 segment per the card; the cross-host link is stated as inferred, and the endpoint-analyst dissent is recorded rather than averaged away.",
    "MAP: purple-team-mapper returned CSF 2.0 subcategories and gaps; the five most load-bearing are listed in this brief. detection-engineer returned undetermined and wrote no files because field paths for 4662 and 4624 are not confirmed; recorded as DR8. Sigma and Wazuh drafts are therefore not produced in this run."
  ],
  "injection_flags": [],
  "verify": { "lint": "pass", "report": "bun evals/Lint.ts --brief: 4 rule IDs, 2 hosts, 5 ATT&CK IDs, 17 CSF IDs, 0 IPv4 literals; every citation traces to the intake or a reference table" }
}
```

## Summary
Critical item: rule 100220 (level 15) on talondc01, directory replication requested from a host that is not a domain controller. It is supported at High for the DC segment because rule 100215, a network logon to the same DC, fired about 85 s earlier, and that logon cites a preceding failed-auth burst. Earlier the same host pair shows rules 100200 and 100210 on talondellbox. The talondellbox to talondc01 link is inferred from timing and rule wording; the intake carries no source address or account. Treat this as a likely DCSync-class credential theft pending the 4624 and 4662 events.

## Threads
### T1 — Brute force on talondellbox escalating to DCSync-class replication on talondc01  (supported, High)
- A failed-auth burst of at least 20 in 60 s was seen on talondellbox at 02:14:31 (rule 100200 on talondellbox), followed by a success from the same source at 02:17:05 (rule 100210 on talondellbox).
- A successful network logon to talondc01 from a source with a preceding failed-auth burst followed at 02:18:22 (rule 100215 on talondc01).
- Directory replication (DRSUAPI GetNCChanges) from a non-DC host followed at 02:19:47 (rule 100220 on talondc01), about 85 s after the logon. The workflow card treats a lateral-movement detection on the DC within 15 minutes of T1003.006 as High for DCSync.
- Recon: talondellbox:3389/tcp is newly reachable from the workstation VLAN (recon_delta, untrusted data). It fits an entry path but shows reachability only, not use.
- Confidence is scoped: High for the DC segment, Medium for the talondellbox attribution. Log-analyst rated the whole chain High, network-analyst Medium and endpoint-analyst undetermined.

**What would raise confidence** — talondc01 event 4624 LogonType 3 with IpAddress and TargetUserName matching the talondellbox events (DR1, DR2), and talondc01 event 4662 with replication GUIDs from a non-DC, non-sync account (DR3).

## Mapping
ATT&CK sequence: credential access (T1110, T1110.001 on talondellbox), then lateral movement and valid accounts (T1021.002, T1078 on talondc01), then credential access (T1003.006 on talondc01).

| CSF 2.0 | Why |
|---|---|
| DE.AE-02 | Rules 100215 and 100220 need analysis as one related sequence. |
| DE.AE-03 | The chain exists only when all four rules are correlated across both hosts. |
| DE.CM-09 | talondellbox endpoint and network telemetry is absent from the intake. |
| PR.AA-05 | Replication rights were exercised from a non-DC; permission scope needs review. |
| RS.AN-03 | Source and account of the DC logon, the root cause, is unresolved. |

Visibility gaps named by the mapper: DC 4624/4662/4738/4769, talondellbox 4625/4624/4688 and Sysmon, Zeek dce_rpc.log and conn.log, the AD DC list, and source address and account in the intake alerts. The mapper's full CSF list also includes DE.AE-04, DE.AE-06, DE.AE-08, DE.CM-01, DE.CM-03, PR.AA-03, PR.IR-01, PR.PS-04, ID.AM-01, ID.AM-03, RS.AN-08 and RS.MA-03.

## Options for the analyst
1. **Investigate** — pull the talondc01 4624 and 4662 events, then the talondellbox 4625/4624 events, and join source and account. Confirms or breaks the inferred link; costs analyst time and needs 4662 auditing and retention.
2. **Investigate** — check the rule 100220 requester against the AD DC list and sync/backup accounts, and review Zeek dce_rpc.log. Rules out a legitimate source; needs a current authoritative list.
3. **Contain** — consider isolating the identified host or account and restricting the path to talondellbox:3389/tcp. Stops further replication; disrupts users and may alert an operator, and the source is not yet identified. A completed DCSync exposes every domain secret, so weigh this promptly.
4. **Contain** — if replication rights were used or krbtgt was touched, weigh a controlled double krbtgt reset and credential rotation. Invalidates stolen secrets; heavy and needs AD administrators.
5. **Harden** — restrict directory replication rights to DCs and named sync accounts. Reduces DCSync exposure; may break undocumented tooling.
6. **Harden** — review why talondellbox:3389/tcp became reachable after the 2026-07-13 baseline. Reduces entry surface if unintended; may break an approved workflow.

All options are for the analyst to decide; CASA takes no response action.

## Data requests
DR1 to DR8 are in the JSON block above. Priority order: DR1, DR3, DR2, DR4. DR8 (sample 4662 and 4624 events) unblocks the detection engineer, whose Sigma and Wazuh drafts were not produced in this run.

## Reasoning trace
See the `trace` array above. VERIFY stripped nothing. It normalized citation formatting only, and rubric checks passed. The endpoint-analyst and detection-engineer returned `undetermined`; both are reported rather than overridden.
