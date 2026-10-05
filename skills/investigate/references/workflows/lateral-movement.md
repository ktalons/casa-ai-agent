# Lateral movement: remote services, credential reuse, internal spread

## 1. Applies when

- Technique IDs: T1021 and sub-techniques (.001 RDP, .002 SMB/Windows Admin Shares, .004 SSH,
  .006 WinRM), T1570 (Lateral Tool Transfer), T1550 (Use Alternate Authentication Material;
  .002 pass the hash, .003 pass the ticket), T1047 (WMI), T1053.005 (Scheduled Task),
  T1569.002 (Service Execution), T1210 (Exploitation of Remote Services).
- Wazuh rule descriptions naming a network logon to a server from a source that recently
  failed authentication, admin share access, service installation on a remote host, or one
  account logging on to many hosts.

## 2. Hypotheses

- H1: an actor moved from `<source host>` to `<target host>` using `<remote service>`.
- H2: the same credential was reused across several hosts in a short window.
- H3: the movement was automated (many hosts in minutes) rather than interactive.
- H4 (benign): an administrator's normal remote work, a patching job, or a monitoring agent.

## 3. Intake-only decision rules

- A T1021.* detection on `<target host>` makes H1 `supported` at **Medium** when its
  description names a preceding failure burst or an unusual source; **Low** otherwise.
- If a credential-access or T1110 detection on a different host precedes it by no more than
  15 minutes, H1 is **High** on the chain (two hosts, two detections, time-ordered).
- If the recon delta reports a newly reachable remote-service port on `<source host>` or
  `<target host>` (3389, 445, 22, 5985/5986), tie it in as the plausible path; it is
  corroborating context, not proof.
- H2 and H3 are undetermined in v1 (no account, no source address). Request section 4 data.
- H4 is the alternative to record for every Medium finding here.
- **v2 intakes:** a `src_ip` on the target's logon that matches the source host, or a `user`
  shared across hosts, establishes H1 and H2 as data; `groups` naming the remote service
  settles which T1021 sub-technique applies.

## 4. Data requests

| Need | Source | Fields |
|---|---|---|
| Logon chain across hosts | Windows Security 4624 on each host | `IpAddress`, `TargetUserName`, `LogonType` (3 network, 10 remote interactive, 9 new credentials) |
| Pass-the-hash indicator | 4624 with `LogonType` 9, or NTLM where Kerberos is expected | `AuthenticationPackageName`, `LogonProcessName` |
| Explicit credential use | 4648 | `TargetServerName`, `TargetUserName` |
| Admin share access | 5140, 5145 | `ShareName` (`ADMIN$`, `C$`, `IPC$`), `IpAddress` |
| Remote execution artifacts | 7045 (service install), 4688 with parent `WmiPrvSE.exe`, 4698 (task created) | `ServiceName`, `ImagePath`, `ParentProcessName`, `TaskName` |
| Kerberos anomalies | 4768, 4769, 4771 | `TicketEncryptionType`, `ServiceName`, failure codes |
| East-west flows | Zeek `conn.log` | `id.orig_h`, `id.resp_h`, `id.resp_p`, `duration`, `orig_bytes` |

## 5. Raw-telemetry mode

```
# network and remote-interactive logons per source host and account
jq -r 'select(.data.win.system.eventID=="4624") | select(.data.win.eventdata.LogonType=="3" or .data.win.eventdata.LogonType=="10") | [.timestamp, .agent.name, .data.win.eventdata.IpAddress, .data.win.eventdata.TargetUserName, .data.win.eventdata.LogonType] | @tsv' <alerts.jsonl>

# service installs and WMI-spawned processes on the target
jq -r 'select(.data.win.system.eventID=="7045" or (.data.win.system.eventID=="4688" and (.data.win.eventdata.ParentProcessName|test("WmiPrvSE")))) | [.timestamp, .agent.name, .data.win.system.eventID, (.data.win.eventdata.ServiceName // .data.win.eventdata.NewProcessName)] | @tsv' <alerts.jsonl>

# east-west connections to admin ports
zeek-cut ts id.orig_h id.resp_h id.resp_p duration orig_bytes < conn.log | grep -E '\s(445|3389|22|5985|5986|135)\s'
```

Thresholds worth stating: one account on more than 3 hosts within an hour; one source
reaching more than 10 hosts on 445 in a short period; RDP between two hosts with no prior
RDP history.

## 6. Confidence ladder

| Level | Requires |
|---|---|
| Low | A single T1021.* detection with a description that could fit routine admin work |
| Medium | The detection names an anomalous source or a preceding failure; or a recon-delta exposure on the path |
| High | A time-ordered chain across two hosts (credential attack or theft on one, remote logon on the other) within 15 minutes, or raw 4624/5145/7045 evidence linking source and target |

CSF 2.0: DE.CM-01, DE.CM-09, DE.AE-03, DE.AE-04; hardening PR.AA-05, PR.IR-01; response
RS.AN-03, RS.AN-08, RS.MI-01.
