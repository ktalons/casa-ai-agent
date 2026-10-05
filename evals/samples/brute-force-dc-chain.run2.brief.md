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
      "rule_ids": ["100220", "100215", "100210", "100200"],
      "attack": ["T1110", "T1110.001", "T1021.002", "T1078", "T1003.006"],
      "tactic_sequence": ["credential-access", "lateral-movement", "credential-access"],
      "hypothesis": "A credential attack on talondellbox (failed-auth burst then success) led via a network logon to talondc01 and ended in DCSync-class directory replication from a non-DC source, forming one escalating chain within about 5 minutes.",
      "verdict": "supported",
      "confidence": {
        "level": "High",
        "justification": "Three independent references: (1) a time-ordered rule_id chain across talondellbox (100200, 100210) and talondc01 (100215, 100220), each step within 2m34s of the last and 5m16s end to end; (2) rule 100215's own description asserts the DC logon came from a source with a preceding failed-auth burst; (3) recon:talondellbox:3389/tcp is a NEW exposure on the source host inside the window. No plausible benign fit: a legitimate replicator does not log on over SMB 85 s after a failure burst. The links rest on rule assertions and time order, not shared address or account fields, because the v1 intake carries none.",
        "would_raise": [
          "talondc01 event 4624 (LogonType 3) whose IpAddress and TargetUserName match the talondellbox failures and success",
          "talondc01 event 4662 with replication control-access GUIDs and the requesting SubjectUserName"
        ]
      },
      "findings_from": ["casa:log-analyst", "casa:endpoint-analyst", "casa:network-analyst", "casa:purple-team-mapper", "casa:detection-engineer"],
      "summary": "Rule 100220 (level 15) on talondc01 is the critical item: directory replication requested from a non-DC host, 85 s after a network logon to the DC (rule 100215) that follows a failed-auth burst and success on talondellbox (rules 100200, 100210). The RDP exposure is corroborating context only; it is not shown to be the entry path."
    }
  ],
  "overall_confidence": { "level": "High", "basis": "threat", "justification": "All three specialists independently reached High with at least two independent references and no benign fit. Identity of the requester, source address and account are not in the intake and are listed as data requests." },
  "csf": [
    { "function": "DE", "category": "DE.AE", "subcategory": "DE.AE-02", "why": "Rules 100200 to 100220 are potentially adverse events that need analysis as one chain." },
    { "function": "DE", "category": "DE.AE", "subcategory": "DE.AE-03", "why": "The chain is established by correlating detections from two hosts." },
    { "function": "DE", "category": "DE.AE", "subcategory": "DE.AE-04", "why": "The scope of exposure from rule 100220 is unknown until the requester and replicated data are identified." },
    { "function": "DE", "category": "DE.CM", "subcategory": "DE.CM-09", "why": "Host-level telemetry on both hosts is the visibility gap for tooling and accounts." },
    { "function": "PR", "category": "PR.AA", "subcategory": "PR.AA-05", "why": "Replication rights should be limited to justified principals." },
    { "function": "PR", "category": "PR.IR", "subcategory": "PR.IR-01", "why": "recon:talondellbox:3389/tcp became reachable from the workstation VLAN." },
    { "function": "RS", "category": "RS.AN", "subcategory": "RS.AN-03", "why": "Investigate options establish what happened and the root cause." }
  ],
  "options": [
    { "kind": "investigate", "action": "Pull talondc01 events 4662 (SubjectUserName, Properties, AccessMask) and 4624 (IpAddress, TargetUserName, LogonType) around 02:18Z to 02:20Z.", "tradeoff": "Read-only and fast; turns asserted links into shared-field evidence. Needs DC Security log access and retention for the window.", "depends_on": ["DC Security log access"] },
    { "kind": "investigate", "action": "Pull talondellbox events 4625 and 4624 for 02:14Z to 02:18Z to name the burst source, the targeted accounts and the logon type of the success.", "tradeoff": "Separates brute force from spraying and shows whether RDP was the path. Needs host log access.", "depends_on": ["talondellbox Security log access"] },
    { "kind": "contain", "action": "Consider isolating talondellbox and disabling or resetting the account used in the 02:17:05Z success once identified.", "tradeoff": "Stops further use of the foothold but disrupts the user and may alert the actor. Acting before the account and source are identified risks isolating the wrong host.", "depends_on": ["talondellbox 4624 and talondc01 4624 results", "analyst and asset-owner approval"] },
    { "kind": "contain", "action": "Consider treating domain credentials as exposed, including krbtgt rotation, if 4662 confirms replication rights were used by a non-DC account.", "tradeoff": "Addresses total domain-secret exposure but is disruptive domain-wide and should follow scope confirmation.", "depends_on": ["talondc01 4662 and 4738/4769 results", "domain admin decision"] },
    { "kind": "harden", "action": "Review why 3389/tcp on talondellbox became reachable from the workstation VLAN after the 2026-07-13 baseline, and which principals hold directory replication rights.", "tradeoff": "Narrows brute-force exposure and DCSync capability; may break a legitimate admin path or sync service if not scoped.", "depends_on": ["firewall or VLAN change records", "AD permission export"] }
  ],
  "data_requests": [
    { "id": "DR1", "source": "talondc01 Windows Security 4662 via Wazuh data.win.eventdata", "fields": ["SubjectUserName", "SubjectDomainName", "ObjectType", "Properties", "AccessMask"], "why": "Names the replication requester and rights used; settles a legitimate sync source." },
    { "id": "DR2", "source": "talondc01 Windows Security 4624 just before the 4662, LogonType 3", "fields": ["IpAddress", "TargetUserName", "LogonType", "LogonProcessName"], "why": "Ties the DC logon to talondellbox as data." },
    { "id": "DR3", "source": "talondellbox Windows Security 4625 and 4624, 02:14Z to 02:18Z", "fields": ["IpAddress", "TargetUserName", "LogonType", "SubStatus"], "why": "Burst source, targeted accounts, and whether the success arrived over RDP." },
    { "id": "DR4", "source": "talondellbox Sysmon events 1, 3 and 10, Security 4688", "fields": ["Image", "ParentImage", "CommandLine", "TargetImage", "GrantedAccess"], "why": "Host-side process ancestry and LSASS access; the intake has none." },
    { "id": "DR5", "source": "talondc01 Security 4738 and 4769; Zeek dce_rpc.log and conn.log", "fields": ["TargetUserName", "id.orig_h", "id.resp_h", "endpoint", "operation"], "why": "Whether krbtgt was touched and which host sent DRSGetNCChanges on the wire." },
    { "id": "DR6", "source": "AD computer objects and Wazuh agent.name list", "fields": ["DC list", "Entra Connect and backup service accounts"], "why": "Rules out a legitimate replication source." },
    { "id": "DR7", "source": "Firewall or host change records for talondellbox:3389/tcp since 2026-07-13", "fields": ["change time", "actor", "rule added"], "why": "Shows whether the exposure pre-dates the burst and was authorized." },
    { "id": "DR8", "source": "Wazuh rule 100220 definition and a sample 4662 event as ingested", "fields": ["if_sid", "decoder field paths"], "why": "Needed by the detection engineer to draft a 4662 rule without guessing field names; no rule was drafted." }
  ],
  "trace": [
    "OBSERVE: 4 detections on 2 hosts, levels 12 to 15, span 2026-07-20T02:14:31Z to 02:19:47Z (5m16s). talondellbox: 2, talondc01: 2. Tactics: credential-access x2 (T1110, T1110.001), lateral-movement (T1021.002) with T1078, credential-access (T1003.006). recon_delta names talondellbox, which is also a detection agent. No injection-like strings found.",
    "HYPOTHESIZE: one thread T1. Merge rules fired: (a) tactic progression credential-access to lateral-movement to credential-access in time order; (b) all detections within 15 minutes across hosts; (c) recon change names talondellbox. Card: credential-theft-dcsync, with auth-anomaly. Specialists: log, endpoint, network. All technique IDs are in the local table, so no threat-intel call; the intake carries no IP or domain indicators.",
    "INVESTIGATE: three specialists launched in parallel; each returned a valid casa.finding/v1 block first time.",
    "VERIFY: bun evals/Lint.ts --finding on each of the three findings: every citation traces; nothing stripped, no confidence downgrade. Rubric by hand: all High with at least two independent references; no Medium or Low findings so no alternatives required, and every option carries a tradeoff.",
    "VERIFY (disagreement): none. All three returned High. Independent reference count: 3 (cross-host rule_id chain, rule 100215 description asserting the failed-auth burst, recon:talondellbox:3389/tcp). The network-analyst held the RDP-as-entry-path clause as undetermined context; the brief adopts that. Missing source address, account and requester are data requests, not a downgrade.",
    "MAP: purple-team-mapper returned CSF and gap mapping (DE.AE-02/03/04, DE.CM-09, PR.AA-05, PR.IR-01, RS.AN-03 retained here; its other IDs are omitted for brevity). detection-engineer returned undetermined and wrote no rule files because the 4662 field names are not in the intake; recorded as DR8.",
    "BRIEF: written; lint run on the whole file, result in verify."
  ],
  "injection_flags": [],
  "verify": { "lint": "pass", "report": "4 rule IDs, 2 hosts, 5 ATT&CK IDs, 7 CSF IDs, 0 IPv4 literals; every citation traces to the intake or a reference table" }
}
```

## Summary
Thread T1 is supported at High and is the critical item: rule 100220 (level 15) shows directory replication requested from a non-DC host on talondc01, 85 s after a network logon to the DC (rule 100215) that follows a failed-auth burst and success on talondellbox (rules 100200, 100210). The whole chain spans 5m16s. The links rest on rule descriptions and time order; the intake carries no account, source address or requester, so those are data requests.

## Threads
### T1 — Brute force on talondellbox escalating to DCSync-class replication on talondc01  (supported, High)
- Failure burst of at least 20 in 60s on talondellbox (rule 100200, T1110), then failures followed by a success (rule 100210, T1110.001) 2m34s later.
- 1m17s later, a network logon to talondc01 whose own description asserts a preceding failed-auth burst (rule 100215, T1021.002, T1078).
- 1m25s after that, DRSUAPI GetNCChanges from a non-DC host on talondc01 (rule 100220, T1003.006).
- RDP on talondellbox is newly reachable from the workstation VLAN (recon:talondellbox:3389/tcp). It is corroborating context; no detection places the failures on 3389, and the DC logon is SMB-class (T1021.002), not RDP.
- talondc01 ports 445 and 389 are unchanged (recon:talondc01:445/tcp), so no new DC exposure contributed.

**What would raise confidence** — already High. DR1 and DR2 convert the asserted links into shared-field evidence; DR6 rules out a legitimate sync source.

## Mapping
- DE.AE-02, DE.AE-03: the four detections are analysed and correlated as one chain across two hosts.
- DE.AE-04: scope of exposure from rule 100220 is not yet known.
- DE.CM-09: host telemetry is the gap for tooling and accounts.
- PR.AA-05: replication rights should be limited to justified principals.
- PR.IR-01: the new 3389/tcp reachability on talondellbox.
- RS.AN-03: investigate options establish what happened and the root cause.
- ATT&CK order: credential-access (T1110, T1110.001), lateral-movement (T1021.002) with T1078, credential-access (T1003.006). T1078 is not assigned to one tactic because the input does not say which applies.
- Standards: NIST SP 800-61r3 §3.2 (Detect, Respond, Recover) and NIST SP 800-92 §5.1.

## Options for the analyst
1. **Investigate DC events 4662 and 4624** around 02:18Z to 02:20Z. Achieves: names the requester and DC logon source. Cost: DC log access and analyst time. Depends on: DC Security log retention.
2. **Investigate talondellbox 4625/4624** for 02:14Z to 02:18Z. Achieves: burst source, accounts, logon type. Cost: host log access. Depends on: talondellbox Security log.
3. **Contain (consider): isolate talondellbox, reset the account used in the success.** Achieves: stops foothold use. Risk: disruption and alerting the actor; wrong host if identity is unconfirmed. Depends on: results of 1 and 2, analyst approval.
4. **Contain (consider): treat domain credentials as exposed, including krbtgt rotation,** if 4662 confirms replication rights were used by a non-DC account. Achieves: limits value of stolen hashes. Risk: domain-wide disruption. Depends on: DR1, DR5, domain admin decision.
5. **Harden: review the 3389/tcp exposure and replication rights.** Achieves: narrower brute-force and DCSync surface. Risk: may break admin paths or sync services. Depends on: change records, AD permission export.

## Data requests
DR1 to DR8 in the JSON block: DC 4662 and 4624; talondellbox 4625/4624; Sysmon process and LSASS access; krbtgt events and Zeek DRSUAPI; DC and sync-account inventory; RDP change records; the Wazuh rule 100220 definition plus a sample 4662 event so a gap rule can be drafted.

## Reasoning trace
See the `trace` array. VERIFY stripped nothing and downgraded nothing. There was no disagreement between specialists. The detection engineer drafted no rules because the needed 4662 fields are not in the intake.
