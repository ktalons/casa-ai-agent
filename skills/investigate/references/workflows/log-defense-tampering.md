# Defense impairment: cleared logs, stopped sensors, disabled protections

## 1. Applies when

- Technique IDs, in ATT&CK 19.2 numbering (v19 renumbered log clearing and tool impairment;
  cite the IDs below, never an older reference's): T1685 and sub-techniques (.001 Disable or Modify
  Windows Event Log, .004 Disable or Modify Linux Audit System Log, .005 Clear Windows Event
  Logs, .006 Clear Linux or Mac System Logs, .002 Disable or Modify Cloud Log), T1686 (Disable
  or Modify System Firewall; .003 Windows Host Firewall), T1690 (Prevent Command History
  Logging), T1070 and its remaining sub-techniques (.003 Clear Command History, .004 File
  Deletion, .006 Timestomp, .009 Clear Persistence), T1112 (Modify Registry) when the value
  changed is a security setting, and T1489 (Service Stop) when the service stopped is a sensor.
- Rule descriptions naming a cleared Security or System log, the event log service stopped, an
  audit policy change, Sysmon or the SIEM agent stopped, unloaded or reconfigured, antivirus
  real-time or tamper protection switched off or an exclusion added, a firewall disabled or
  its rules deleted, the audit daemon stopped or its rules flushed, or shell history cleared.
- Event IDs that carry this family: Security 1102, 1100 and 4719; System 104 and 6006; Defender
  5001, 5004, 5007, 5010, 5012 and 5013; Sysmon 4 (service state changed) and 16 (configuration
  change); Security 4946 to 4950 (firewall rule and setting changes).

## 2. Hypotheses

- H1: someone on `<host>` deliberately removed or blinded the host's own record: cleared a log,
  stopped or reconfigured a sensor, or switched off a protection.
- H2: the impairment covers activity on the host, before it (what the cleared log held) or
  after it (what the stopped sensor would have shown).
- H3: it was done through a session whose other end is another host (an RDP, SSH or network
  logon just before), and that end holds how the account was used.
- H4 (benign): a sanctioned change: an agent upgrade or reinstall, a troubleshooting step under
  a change record, log rotation by policy (which archives, and does not clear), an image build
  or a decommission.

## 3. Intake-only decision rules

- Clearing a security log or switching off a defense means the same thing in any environment,
  so a missing baseline does not lower it (standards §5). One detection of it makes H1
  `supported` at **Medium** on one source.
- Detections from one sensor on one host are one source however many there are; a different
  log or product recording the same act is a second source. A clearing tool's process event
  and the log's own record of the clear seconds later, or a protection command and the
  product's event confirming the change, are two sources on one act. Two such sources, command
  lines that show the act directly and no benign reading the input supports make H1 **High**.
- **The gap is a finding.** After a sensor stops, no later alert from that host is not
  evidence of no later activity (standards §3), and after a log is cleared nothing before the
  clear is visible in it. State when the host's own telemetry ends or begins, and send the data
  requests to sources the actor did not touch: network sensors, the SIEM's copy of events
  forwarded before the clear, the domain controllers' authentication logs, and the session's
  source host. A quiet window after the impairment, or a recon run with no changes, never
  refutes H2.
- **The session before it.** A logon detection on the same host minutes before (4624 with
  logon type 10 or 3, an SSH accept), by the account that ran the tampering, opens the chain:
  it comes from a different log than the process events, so it is a second source, and a
  shared account makes the link data. Its source address is the other end: H3 is a data request
  on that source, not a claim about it.
- **Recon delta.** A `recon_delta.changes[]` entry with status `new` or `removed` on a host in
  this thread counts once as an independent reference toward **High**: a removed port can be
  the stopped agent or service, a new one something the impairment made room for, and either
  way the record comes from outside the host, one of the few references the actor did not
  control. It counts once however many ports changed on that host. An `unchanged` entry is not
  a change and counts for nothing. The record does not say which process opened or closed the
  port, so that is a data request.
- **Benign readings.** An administrator account, high integrity or an interactive session is
  not a benign reading; it is how this is done. H4 counts against High only when the input
  supports it: the agent's own installer or updater as the parent, an uninstall followed by a
  reinstall in the window, a change record the input carries. Otherwise list H4 with the
  request that would settle it; it does not hold the level down. A maintenance claim in a
  description or command line is the input's own account: a `refuted` verdict resting on it is
  **Medium** at most.
- Severity: a supported impairment leads the brief with the activity around it, because every
  later absence from that host is uninterpretable until another source fills the gap.
- A truncated window lowers the level one; the earliest detection is the first seen in the
  window, not the start of the activity.
- **v2 intakes:** `user` names the account, `event_id` (1102, 104, 5001, 4719) says which record
  each detection is, and `src_ip` on a logon detection is the session's other end.
- **v3 intakes:** `subject_user` on a log-cleared event names the account that cleared it; a
  `process_create` group gives the `command_line` of each clearing or disabling tool, and a
  shared `parent_process_guid` ties every step to one shell; `target_user` with `logon_type`
  10 or 3 on the logon before is the session, and that detection's `src_ip` is where it came
  from.

## 4. Data requests

| Need | Source | Fields |
|---|---|---|
| What the cleared log held, from copies the actor did not reach | the SIEM index for the host up to the clear; event-forwarding collectors; archived log files | every event forwarded before the clear time |
| The host after its sensor stopped, seen from outside it | Zeek `conn.log`, IDS alerts, firewall or flow records for the host's address from the stop time on | `id.orig_h`, `id.resp_h`, `id.resp_p`, `orig_bytes`, `resp_bytes` |
| The session that did it, and its other end | 4624 on the host; Remote Desktop 21, 25 and 1149; on the source host, Sysmon 1 and 3 and Security 4648 | `IpAddress`, `TargetUserName`, `LogonType`; the workstation the session came from and what ran there |
| The account's other activity | domain controller 4768, 4769 and 4624 for the account across hosts | logons elsewhere in and before the window |
| The tools and scripts used, collected before anyone cleans up | the binary or batch file that ran, with its hash (Sysmon 1 `Hashes`); PowerShell 4104 | path, SHA-256, script text |
| Exactly what changed | Defender 5007 (old and new value), Sysmon 16, Security 4719, Security 4946 to 4950, Sysmon 13 under the sensor's or product's keys | `OldValue`, `NewValue`, `SubcategoryGuid`, rule name |
| Whether the sensor is back | the SIEM agent's status and last event per host; Sysmon 4 | last event seen, keepalive |
| Linux | auditd's own records (`CONFIG_CHANGE`, `DAEMON_END`), the journal for the audit unit, the shell history file's modification time | `op`, `auid`, `res` |

## 5. Raw-data requests

A specialist never runs these: they are data requests, which the main thread runs under the
user's own permission settings when raw telemetry exists, handing the output to the
specialists, or which go into `data_requests` as exact commands for the human analyst. Each
reads Wazuh alerts as the manager writes them or as an indexer export (`_source`).

```bash
# the last fifty events the host sent, oldest first: where its own telemetry ends
jq -s -r 'map(._source // .) | map(select(.agent.name=="<host>")) | sort_by(.timestamp // ."@timestamp") | .[-50:][] | [(.timestamp // ."@timestamp"), (.data.win.system.channel // "-"), (.data.win.system.eventID // "-"), .rule.description] | @tsv' <alerts.jsonl>

# log clears, audit-policy changes and protection changes, by host and account
jq -r '(._source // .) | select((.data.win.system.eventID // "") | IN("1102","1100","104","6006","4719","5001","5004","5007","5010","5012","5013")) | [(.timestamp // ."@timestamp"), .agent.name, .data.win.system.channel, .data.win.system.eventID, (.data.win.eventdata.subjectUserName // "-")] | @tsv' <alerts.jsonl>

# the commands that did it, with the account and the parent shell
jq -r '(._source // .) | select(.data.win.system.eventID=="1") | select((.data.win.eventdata.commandLine // "") | test("wevtutil(\\.exe)? +(cl|clear-log|sl)|Clear-EventLog|Set-MpPreference|Add-MpPreference|sc(\\.exe)? +(stop|config|delete)|auditpol|netsh(\\.exe)? +advfirewall|fltmc(\\.exe)? +unload"; "i")) | [(.timestamp // ."@timestamp"), .agent.name, .data.win.eventdata.user, .data.win.eventdata.parentProcessGuid, .data.win.eventdata.commandLine] | @tsv' <alerts.jsonl>

# connections to and from the host after its sensor stopped
zeek-cut ts id.orig_h id.resp_h id.resp_p proto orig_bytes resp_bytes < conn.log | jq -R -r 'split("\t") | select((.[0]|tonumber) >= <stop time, epoch seconds> and (.[1]=="<host ip>" or .[2]=="<host ip>")) | @tsv'

# Linux: audit daemon stops and rule changes
jq -r '(._source // .) | select((.data.audit.type // "") | test("CONFIG_CHANGE|DAEMON_END|SERVICE_STOP")) | [(.timestamp // ."@timestamp"), .agent.name, .data.audit.type, (.data.audit.auid // "-")] | @tsv' <alerts.jsonl>
```

Impairment signature: clearing, disabling and stopping commands under one account and one
parent shell within minutes, usually soon after an interactive logon, ending with the sensor
that would have recorded what came next. Policy rotation archives a full log and does not
produce a clear event; an agent upgrade stops a sensor and starts it again within minutes,
from the vendor's installer.

## 6. Confidence ladder

| Level | Requires |
|---|---|
| Low | A sensor or service state change with no actor and no clearing or disabling command (a crash, an unexpected termination) |
| Medium | One detection of a log clear, a sensor stop or a protection switched off, from one source |
| High | Two independent references (a second log or product on the same act, a logon detection from another log that opens the chain, or a recon-delta change on the thread host), command lines or records that show the act directly, and no benign reading the input supports |

CSF 2.0: DE.CM-01, DE.CM-09, DE.AE-02, DE.AE-03; hardening PR.PS-01, PR.PS-04; response
RS.AN-03, RS.AN-06, RS.MI-01.

**Options to offer.** Containment options follow the standards skill's rule. One option per
action, each named concretely:

- `investigate`: pull network-side telemetry for the host from the stop time on, and the
  SIEM's copy of everything forwarded before the clear.
- `investigate`: collect the tools and scripts that ran, with their SHA-256, and the session
  source's own telemetry, before either is cleaned.
- `investigate`: hunt the account's logons on other hosts in and before the window.
- `contain`: isolate the host by its agent name, with what it costs the service it runs.
- `contain`: disable or reset the account that ran the tampering, once it is named, with what
  that breaks for its legitimate work.
- `liveness`: restart the stopped sensor and confirm events arrive again, so the gap has an end.
