# Command and control: beaconing, DNS channels, unknown listeners

## 1. Applies when

- Technique IDs: T1071 and sub-techniques (.001 web protocols, .004 DNS), T1573 (Encrypted
  Channel), T1571 (Non-Standard Port), T1572 (Protocol Tunneling), T1568.002 (Domain
  Generation Algorithms), T1105 (Ingress Tool Transfer).
- Wazuh rule descriptions naming periodic outbound connections, high-entropy or newly seen
  domains, TLS to an unknown destination, or a new listening port on a workstation.
- A recon delta reporting a new listener on a host that also has a C2-tactic detection.

## 2. Hypotheses

- H1: `<host>` is beaconing to `<destination>` on a fixed interval, consistent with C2.
- H2: the DNS activity from `<host>` is a channel (tunnelling or DGA resolution), not
  ordinary resolution.
- H3: the new listener on `<host>` belongs to the same activity (staging or a reverse
  channel), not to a legitimate service.
- H4 (benign): an updater, monitoring agent, CDN, or developer tool with regular check-ins;
  a self-signed certificate on a local development server.

## 3. Intake-only decision rules

- A T1071.* detection asserting periodicity makes H1 `supported` at **Medium** at most:
  periodicity inferred by a rule is suggestive, and the intake carries no interval, jitter,
  destination or byte counts. Name the measurement that would confirm it.
- Two C2-tactic detections on the same host in the window (for example periodic HTTPS plus
  a high-entropy DNS query) stay **Medium** but become one thread; they corroborate each
  other only weakly because both rest on the same host's rule evaluations.
- A recon-delta listener on that host is corroborating context for H3; it does not raise H1
  by itself. A self-signed certificate on a workstation port is as consistent with H4 as
  with H3; say so in `alternatives`.
- **v2 intakes:** `dst_ip` on the detections is an indicator the threat-intel agent can look
  up, and a structured `recon_delta.changes[]` entry for the host is the listener fact.
- **High** is reachable in intake-only mode only when an independent source corroborates:
  a threat-intelligence match on the destination (threat-intel agent, with a cited source)
  or a host-level detection tying a suspicious process to the connection.

## 4. Data requests

| Need | Source | Fields |
|---|---|---|
| Interval and jitter | Zeek `conn.log` for the host | `ts`, `id.resp_h`, `id.resp_p`, `duration`, `orig_bytes`, `resp_bytes` |
| Destination identity | Zeek `ssl.log`, `dns.log`; proxy logs | `server_name`, `issuer`, `validation_status`, `query`, `answers`, `rcode_name` |
| DNS channel signs | `dns.log` | query length, label entropy, record type (`TXT`, `NULL`), NXDOMAIN rate, distinct subdomains per domain |
| The process behind the connection | Sysmon event 3 (network connection), event 1 (process create) | `Image`, `ProcessId`, `DestinationIp`, `DestinationPort`, `ParentImage` |
| What owns the new listener | Sysmon event 3 inbound, or `lsof -i :<port>` output supplied by the analyst | `Image`, `User`, listening socket |
| Destination reputation | threat-intel agent, offline tables first | ASN, registration age, known-C2 lists, with the source cited |

## 5. Raw-telemetry mode

```
# connections from the host to one destination, in time order (compute deltas from ts)
zeek-cut ts id.orig_h id.resp_h id.resp_p orig_bytes resp_bytes < conn.log | grep '<host ip>' | sort -n

# inter-arrival deltas and spread (jitter) for one destination
zeek-cut ts < conn.log | jq -s -R 'split("\n") | map(select(length>0)|tonumber) | sort | [.[1:], .[:-1]] | transpose | map(.[0]-.[1]) | {n:length, mean:(add/length), min:min, max:max}'

# DNS queries by length and type
zeek-cut ts query qtype_name rcode_name < dns.log | grep '<host ip>'

# TLS to the destination from a capture
tshark -r <capture.pcap> -Y 'tls.handshake.type == 1' -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tls.handshake.extensions_server_name
```

Beaconing signature: inter-arrival jitter below 15 percent of the mean interval over at
least ten connections, small and consistent payload sizes, common intervals (30 s, 60 s,
300 s, 600 s, 3600 s). Legitimate periodic traffic (NTP, updaters, monitoring) must be
excluded by destination before the signature counts.

## 6. Confidence ladder

| Level | Requires |
|---|---|
| Low | A single C2-tactic detection whose description fits a benign periodic service |
| Medium | Periodicity or a DNS anomaly asserted by a rule, with or without a recon-delta listener on the same host |
| High | A measured interval with low jitter over ten or more connections, plus a destination with a cited malicious reputation or a suspicious owning process |

CSF 2.0: DE.CM-01, DE.CM-09, DE.AE-02, DE.AE-07; hardening PR.IR-01, PR.PS-05; response
RS.AN-03, RS.AN-07. Posture is investigate before respond: containment options only at High.
