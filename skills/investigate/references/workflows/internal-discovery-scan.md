# Discovery: internal scanning, sweeps and enumeration

## 1. Applies when

- Technique IDs: T1046 (Network Service Discovery), T1018 (Remote System Discovery), T1135
  (Network Share Discovery), T1087.002 (Domain Account), T1069.002 (Domain Groups), T1016
  (System Network Configuration Discovery), T1049 (System Network Connections Discovery); and
  T1595 (Active Scanning; .001 Scanning IP Blocks, .002 Vulnerability Scanning) when the source
  is outside the organization.
- IDS signatures for a SYN sweep, a port scan or a scanner's probe fingerprint; one source
  touching many hosts or many ports in minutes; bursts of refused or unanswered connections;
  share, account or group enumeration against many hosts or a domain controller; enumeration
  commands run on a host.

## 2. Hypotheses

- H1: `<source>` scanned or enumerated `<targets>` in the window as hostile reconnaissance,
  from a compromised or unauthorized host.
- H2: the scan was followed by use: a connection, a logon or an exploit attempt against a host
  or port the scan reached.
- H3: the source host shows other compromise: an execution or persistence detection, or a new
  listener.
- H4 (benign): the organization's sanctioned scanner (a recon job, a vulnerability scanner, an
  asset-discovery tool), a monitoring system's checks, or an administrator troubleshooting.
  When the evidence shows this, H1 is `refuted`; H4 is never the hypothesis marked
  `supported`.

## 3. Intake-only decision rules

- A T1046 detection from an internal source that nothing in the input accounts for makes H1
  `supported` at **Medium** on one source. Several scan alerts from one sensor about one
  source are one source and one thread, however many targets they name.
- **A scan the input itself describes.** When the input describes a scan (the recon delta's
  record of its own run, a scanner named in a description) and the alerts match it on source
  address, time span and port set, H1 is `refuted` at **Medium** at most: the description is
  telemetry, not confirmed context (standards §5). Name analyst confirmation of the scanner and
  its schedule as what would raise it. An alert that misses on any of the three (outside the
  run's span, a port outside its set, another source) is not explained by the run and keeps
  that part of H1 open.
- **Recon delta.** The recon record can be two different things here. As the account of the
  organization's own scan, it is the same activity seen from its author's side and is never an
  independent reference for H1. As a `recon_delta.changes[]` entry with status `new` or
  `removed` on a host in this thread (the scanning source, or a host the scan reached), it
  counts once as an independent reference toward **High** for H2 or H3: a new listener on the
  source, or a new service on a target that later traffic used. It counts once however many
  ports changed on that host. An `unchanged` entry is not a change and counts for nothing, and
  the record does not say which process holds a new port, so that is a data request.
- **Past scanning.** A detection after the scan against a host and port it reached (a logon, an
  exploit signature, an execution on that host) is a second, independent reference: it makes
  the thread a chain, H2 `supported`, and the target goes to the lateral-movement card or the
  card its technique matches. With two independent references and no benign reading the input
  supports, H1 is **High**. Without one, say plainly that nothing in the intake goes past
  scanning.
- **Benign readings.** "Probably the vulnerability scanner", with nothing in the input naming a
  scanner, is an alternative with a request (the scanner inventory and schedule from its
  owner); it does not hold the level down.
- An external source is reconnaissance against exposed services (T1595): its end cannot be
  collected, but the targets' responses and anything that followed can.
- A truncated window lowers the level one; the earliest alert is the first seen in the window,
  not the start of the scan.
- **v2 intakes:** `src_ip` and `dst_ip` on each alert name the source and the targets as data;
  distinct targets per source separate a sweep (many hosts) from a port scan (one host).
- **v3 intakes:** `dst_port` and `proto` give the port set to compare with any described run;
  one `src_port` repeated across alerts suggests one tool's raw-packet run; `engine.rule_id` is
  the IDS signature ID and the `suricata` block's `signature` and `flow_id` name each probe.

## 4. Data requests

| Need | Source | Fields |
|---|---|---|
| The scan's full shape | Zeek `conn.log` for the source | distinct `id.resp_h` and `id.resp_p`, first and last `ts`, `conn_state`, `history` |
| What answered | `conn.log` `history` per target and port (a responder SYN-ACK shows as `h`) | the host and port pairs that answered |
| Is the source a sanctioned scanner | the scanner inventory and the job's schedule or configuration, from its owner, not from the alerts | source address, job name, schedule, target list, port set |
| What on the source sent the probes: the other end | Sysmon 1 and 3 on the source host, or its EDR telemetry | `Image`, `CommandLine`, `User`, `Hashes` of the process opening connections to many hosts |
| The scanning tool, collected before anyone removes it | the binary or script on the source host, with its hash | path, SHA-256 |
| Did anything follow | detections, 4624 and 4625, and IDS exploit signatures against the scanned hosts after the scan began | target host, port, time |
| Enumeration on the directory side | domain controller 4661 and 4662 bursts, 4798 and 4799, SMB 5140 and 5145 on many hosts from one source | `SubjectUserName`, `IpAddress`, `ShareName` |

## 5. Raw-data requests

A specialist never runs these: they are data requests, which the main thread runs under the
user's own permission settings when raw telemetry exists, handing the output to the
specialists, or which go into `data_requests` as exact commands for the human analyst.

```bash
# the scan's shape from one source: span, distinct hosts and ports, and which pairs answered
zeek-cut ts id.orig_h id.resp_h id.resp_p history < conn.log | jq -R -s 'split("\n") | map(select(length>0) | split("\t") | select(.[1]=="<source ip>")) | {first:(map(.[0]|tonumber)|min), last:(map(.[0]|tonumber)|max), hosts:(map(.[2])|unique|length), ports:(map(.[3])|unique), answered:(map(select(.[4]|test("h"))) | map(.[2]+":"+.[3]) | unique)}'

# IDS alerts from the source, in time order
jq -s -r 'map(._source // .) | map(select(.data.src_ip=="<source ip>" or .data.srcip=="<source ip>")) | sort_by(.timestamp // ."@timestamp") | .[] | [(.timestamp // ."@timestamp"), .rule.id, .data.dest_ip, .data.dest_port, .data.alert.signature] | @tsv' <alerts.jsonl>

# anything on the scanned hosts after the scan began
jq -r --arg since '<scan start, ISO 8601>' '(._source // .) | select((.timestamp // ."@timestamp") >= $since) | select(.agent.name | IN("<target host>", "<target host>")) | [(.timestamp // ."@timestamp"), .agent.name, .rule.id, .rule.description] | @tsv' <alerts.jsonl>

# from a capture: SYNs per source, with distinct targets and ports
tshark -r <capture.pcap> -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0' -T fields -e ip.src -e ip.dst -e tcp.dstport | jq -R -s 'split("\n") | map(select(length>0) | split("\t")) | group_by(.[0]) | map({src:.[0][0], targets:(map(.[1])|unique|length), ports:(map(.[2])|unique|length)})'
```

Scan signature: one source to many hosts on one port (a sweep) or to many ports on one host (a
port scan) within seconds or minutes; mostly unanswered SYNs; a fixed source port or a fixed
TCP window across probes from a raw-packet tool. A sanctioned scanner shows the same shape, so
the shape alone never decides H1: the source's identity and schedule, confirmed outside the
alerts, and what followed the scan decide it.

## 6. Confidence ladder

| Level | Requires |
|---|---|
| Low | A connection-count or failure-count rule alone, with no scan signature and no source named |
| Medium | Scan detections from one sensor that nothing in the input accounts for (H1 supported); or alerts that match a scan the input itself describes, on source, span and ports (H1 refuted until confirmed outside the input) |
| High | H1 supported plus an independent reference (activity past scanning against a scanned host, another detection on the source host, or a recon-delta change on a thread host) and no benign reading the input supports; or H1 refuted with the scanner and its schedule confirmed by the analyst |

CSF 2.0: DE.CM-01, DE.AE-02, DE.AE-03; hardening ID.AM-01, PR.IR-01; response RS.AN-03.

**Options to offer.** Containment options follow the standards skill's rule. One option per
action, each named concretely:

- `investigate`: confirm the scanner and its schedule with the person who owns it.
- `investigate`: pull the source host's process telemetry, and collect the scanning tool with
  its SHA-256, before it is removed.
- `harden`: scope a confirmed scanner out of the scan rules by its source address and run
  window, rather than disabling the rules, which would blind the sensor to the next real scan.
- `contain`: isolate a source host that is not a sanctioned scanner, by its agent name, with
  what it costs the host's users.
