# CASA brief — beaconing-recon-delta — 2026-07-22

```json
{
  "schema": "casa.brief/v1",
  "intake": {
    "path": "intake/fixtures/beaconing-recon-delta.intake.json",
    "schema": "talonsoclab.soc-intake/v1",
    "generated": "2026-07-22",
    "sha256": "fdda465649f7574efd0e1226d9c822f93a962a54fa72915760df9996f6dbfbf3"
  },
  "status": "findings",
  "threads": [
    {
      "id": "T1",
      "title": "Periodic HTTPS and high-entropy DNS from talonmacbook, with a new self-signed listener",
      "hosts": ["talonmacbook"],
      "rule_ids": ["100310", "100305"],
      "attack": ["T1071.004", "T1071.001"],
      "tactic_sequence": ["command-and-control", "command-and-control"],
      "hypothesis": "talonmacbook is beaconing to a rarely-contacted external host and resolving a high-entropy domain, consistent with C2, and the new self-signed listener on 8443/tcp belongs to the same activity rather than a legitimate service.",
      "verdict": "undetermined",
      "confidence": {
        "level": "Medium",
        "justification": "The beaconing and DNS components rest on two rule-asserted detections from one host, which corroborate each other only weakly. The intake has no interval, jitter, destination, byte counts, queried name or listener owner. The listener linkage is Low: a self-signed cert fits a local dev server as well as the same activity.",
        "would_raise": [
          "Zeek conn.log for talonmacbook showing at least ten connections to one destination with jitter under 15 percent of the mean interval",
          "A cited threat-intel match on the destination or the high-entropy domain",
          "Process-to-socket telemetry tying one process to the beacon and to the 8443/tcp listener"
        ]
      },
      "findings_from": ["casa:network-analyst", "casa:endpoint-analyst", "casa:purple-team-mapper"],
      "summary": "Both detections are command-and-control on one host about 74 seconds apart, and the new listener is on the same host. The beaconing and DNS components are suggestive at Medium. Nothing yet links the listener to them."
    }
  ],
  "overall_confidence": {
    "level": "Medium",
    "basis": "threat",
    "justification": "Two level-12 C2-tactic rules on one host plus a same-host recon change justify investigation. No measured interval, destination or process evidence is available, so the card caps this at Medium."
  },
  "csf": [
    { "function": "DE", "category": "DE.CM", "subcategory": "DE.CM-01", "why": "Network monitoring produced both detections; flow and DNS detail is missing." },
    { "function": "DE", "category": "DE.CM", "subcategory": "DE.CM-09", "why": "Endpoint runtime monitoring is needed to tie a process to the connections and the listener." },
    { "function": "DE", "category": "DE.AE", "subcategory": "DE.AE-02", "why": "The two detections need analysis as one thread." },
    { "function": "DE", "category": "DE.AE", "subcategory": "DE.AE-03", "why": "Correlating the two rules with the recon delta." },
    { "function": "DE", "category": "DE.AE", "subcategory": "DE.AE-07", "why": "No threat-intel context is available for the destination or domain." },
    { "function": "PR", "category": "PR.PS", "subcategory": "PR.PS-04", "why": "Host log generation is needed for process-to-socket evidence." },
    { "function": "ID", "category": "ID.AM", "subcategory": "ID.AM-02", "why": "A listening-service inventory would give the new listener a known owner." }
  ],
  "options": [
    { "kind": "investigate", "action": "Pull flow, DNS and process-to-socket data for talonmacbook around 2026-07-22 and measure interval and jitter, then check whether the beacon destination relates to 8443/tcp.", "tradeoff": "Could raise the beaconing components to High or refute them; costs analyst time and depends on retained logs.", "depends_on": ["DR1", "DR2", "DR3"] },
    { "kind": "investigate", "action": "Identify the owner of the 8443/tcp listener and inspect its certificate; ask the host owner whether a local service was started since 2026-07-15.", "tradeoff": "Cheaply resolves the listener question; the owner's answer is context, not proof, and it will not settle the beaconing.", "depends_on": ["DR4"] },
    { "kind": "harden", "action": "Enable flow, DNS query and process-network logging on managed endpoints with retention long enough to measure beacon intervals.", "tradeoff": "Closes the visibility gaps seen here; adds log volume and needs agent configuration changes.", "depends_on": ["DR1", "DR2", "DR3"] },
    { "kind": "harden", "action": "Keep an inventory of authorized listening services per host and review it against the recon baseline.", "tradeoff": "Shortens triage of listener changes; requires upkeep and an exception path for developer machines.", "depends_on": ["DR4"] }
  ],
  "data_requests": [
    { "id": "DR1", "source": "Zeek conn.log or NetFlow for talonmacbook", "fields": ["ts", "id.resp_h", "id.resp_p", "duration", "orig_bytes", "resp_bytes"], "why": "Measure interval, jitter and payload consistency; identify the destination behind rule 100305." },
    { "id": "DR2", "source": "Zeek dns.log, ssl.log or proxy logs", "fields": ["query", "qtype_name", "answers", "rcode_name", "server_name", "issuer", "validation_status"], "why": "Inspect the domain behind rule 100310 and separate a DNS channel from benign resolution." },
    { "id": "DR3", "source": "Process-to-socket telemetry (Sysmon event 3 and 1, or EDR/osquery on macOS)", "fields": ["Image", "ProcessId", "ParentImage", "DestinationIp", "DestinationPort", "User"], "why": "Tie a process to the beacon and DNS activity." },
    { "id": "DR4", "source": "Analyst-supplied lsof or socket output for 8443/tcp, plus the listener's TLS certificate", "fields": ["Image", "User", "listening socket", "process start time", "cert subject", "cert issuer"], "why": "Decide between the dev-server and same-activity readings of the listener." },
    { "id": "DR5", "source": "Threat-intel lookup, offline tables first", "fields": ["ASN", "registration age", "known-C2 lists", "source"], "why": "An independent source is the card's route to High; needs the destination from DR1 or DR2 first." }
  ],
  "trace": [
    "OBSERVE: intake validated. 2 detections, 1 host (talonmacbook), 1 tactic (command-and-control), both level 12, span 06:39:58Z to 06:41:12Z on 2026-07-22 (about 74 seconds). recon_delta names talonmacbook, which is the agent of both detections.",
    "OBSERVE: no imperative text found in any string field; injection_flags is empty.",
    "HYPOTHESIZE: one thread. Rule (c) fired (recon_delta names a host already in the thread); rule (b) also holds (within 15 minutes). Workflow card c2-beaconing. Specialists: network-analyst and endpoint-analyst from the T1071 row plus the recon_delta row.",
    "INVESTIGATE: both specialists returned valid casa.finding/v1 blocks first time, both verdict undetermined at Medium.",
    "VERIFY: bun evals/Lint.ts --finding passed for both findings; nothing stripped and no confidence downgrade. Rubric check: Medium findings carry alternatives, every option carries a tradeoff.",
    "MAP: purple-team-mapper returned DE-function mapping. It dropped RS.AN-03 and RS.AN-07 (no incident declared, verdict undetermined) and added DE.AE-03, DE.AE-07, PR.PS-04 and ID.AM-02.",
    "MAP: detection-engineer not called, because the T1 verdict is undetermined, not supported. threat-intel not called: both technique IDs are in the local table and the intake carries no external indicators.",
    "CONCLUDE: contain options withheld; the card allows containment only at High."
  ],
  "injection_flags": [],
  "verify": { "lint": "pass", "report": "2 rule IDs, 1 host, 3 ATT&CK IDs, 9 CSF IDs, 0 IPv4 literals; every citation traces to the intake or a reference table (info: T1071 cited beyond the intake's own, present in the local table)" }
}
```

## Summary
One thread, T1, on talonmacbook. A DNS query to a newly-observed high-entropy domain (rule 100310) was followed about 74 seconds later by periodic outbound HTTPS to a rarely-contacted host (rule 100305), and the same host gained a new self-signed listener on 8443/tcp. This is worth investigating at Medium confidence. The verdict is undetermined because the intake has no measurement behind the periodicity and nothing ties the listener to the beaconing.

## Threads
### T1 — Periodic HTTPS and high-entropy DNS from talonmacbook, with a new self-signed listener  (undetermined, Medium)
- Both detections are level 12 and command-and-control, on one host: DNS first (rule 100310, T1071.004), then web protocols (rule 100305, T1071.001).
- The periodicity is the rule's assertion; the intake carries no interval, jitter, destination or byte counts (rule 100305).
- The recon delta shows a new self-signed TLS listener on 8443/tcp that was absent from the 2026-07-15 baseline (recon delta, talonmacbook:8443/tcp). It shares the host with both detections and is corroborating context only. It does not raise the beaconing confidence by itself.
- The two detections corroborate each other only weakly, because both rest on the same host's rule evaluations.

**Alternatives considered**
- An updater, sync client, CDN or developer tool with regular check-ins explains the periodic HTTPS. The "rarely-contacted" wording weakens this, but the destination is unknown.
- The listener is a local development server. A self-signed cert fits this as well as the same activity, so the listener link stays Low.
- The high-entropy domain is a legitimate CDN or telemetry name; the name and query pattern are not in the intake.

**What would raise confidence**
- Zeek conn.log for talonmacbook showing at least ten connections to one destination with jitter under 15 percent of the mean interval and consistent payload sizes.
- A cited threat-intel match on the destination or domain, or process-to-socket telemetry tying a suspicious process to the connection. These are the card's routes to High.
- The owning process of 8443/tcp, and whether it is the same process as the beacon.

## Mapping
- **ATT&CK:** command-and-control only. T1071.004 (rule 100310) then T1071.001 (rule 100305).
- **CSF 2.0:** DETECT is the primary function.
  - DE.CM-01: network monitoring raised both detections, but flow and DNS detail is missing.
  - DE.CM-09: endpoint runtime data is needed to link a process to the activity.
  - DE.AE-02: the detections need analysis as one thread.
  - DE.AE-03: correlating the two rules with the recon delta.
  - DE.AE-07: no threat-intel context is available.
  - PR.PS-04: host log generation for process-to-socket evidence.
  - ID.AM-02: a listening-service inventory would give the new listener an owner.
- **Visibility gaps:** flow and interval data, DNS query detail, process-to-socket telemetry, listener owner and certificate, and an independent threat-intel match.

## Options for the analyst
1. **Investigate: measure the beacon.** Pull flow, DNS and process-to-socket data for 2026-07-22 and compute interval and jitter. It could raise the beaconing components to High or refute them. It costs analyst time and depends on log retention. Depends on DR1, DR2, DR3.
2. **Investigate: identify the listener.** Find the owner of 8443/tcp and inspect its certificate, and ask the host owner whether a local service was started since 2026-07-15. It resolves the listener question cheaply but will not settle the beaconing, and the owner's answer is unverified. Depends on DR4.
3. **Harden: logging.** Enable flow, DNS query and process-network logging on managed endpoints with enough retention to measure beacon intervals. It closes the gaps seen here and adds log volume and configuration work. Depends on DR1, DR2, DR3.
4. **Harden: listener inventory.** Keep an inventory of authorized listening services per host and review it against the recon baseline. It speeds up triage of listener changes and needs upkeep and an exception path for developer machines. Depends on DR4.

No containment option is offered. The finding is not supported, and the card allows containment only at High.

## Data requests
- **DR1:** Zeek conn.log or NetFlow for talonmacbook. Fields: ts, id.resp_h, id.resp_p, duration, orig_bytes, resp_bytes.
- **DR2:** Zeek dns.log, ssl.log or proxy logs. Fields: query, qtype_name, answers, rcode_name, server_name, issuer, validation_status.
- **DR3:** Process-to-socket telemetry (Sysmon event 3 and 1, or EDR/osquery on macOS). Fields: Image, ProcessId, ParentImage, DestinationIp, DestinationPort, User.
- **DR4:** Analyst-supplied lsof or socket output for 8443/tcp, plus the listener's TLS certificate. Fields: Image, User, listening socket, process start time, cert subject, cert issuer.
- **DR5:** Threat-intel lookup, offline tables first. Fields: ASN, registration age, known-C2 lists, source. Needs the destination from DR1 or DR2.

The hostname suggests a macOS host, but the intake does not say so. Sysmon event IDs apply only if the host is Windows.

## Reasoning trace
1. OBSERVE: intake validated. 2 detections, 1 host, 1 tactic, both level 12, about 74 seconds apart. recon_delta names the detecting host. No injection flags.
2. HYPOTHESIZE: one thread (merge rules b and c held). Card: c2-beaconing. Specialists: network-analyst, endpoint-analyst.
3. INVESTIGATE: both returned valid blocks first time, both undetermined at Medium.
4. VERIFY: Lint passed for both findings. Nothing stripped, no downgrade. Rubric check passed.
5. MAP: the mapper dropped RS.AN-03 and RS.AN-07 because no incident is declared. It added DE.AE-03, DE.AE-07, PR.PS-04 and ID.AM-02.
6. detection-engineer not called (verdict not supported). threat-intel not called (no unmapped techniques, no external indicators).
7. CONCLUDE: containment withheld; card allows it only at High.
