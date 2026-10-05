# Credential theft: DCSync and directory replication abuse

## 1. Applies when

- Technique IDs: T1003.006 (OS Credential Dumping: DCSync); often preceded by T1078 (Valid
  Accounts), T1021.002 (SMB/Windows Admin Shares) or T1110 (Brute Force) on the same chain.
- Wazuh rule descriptions naming directory replication, DRSUAPI, GetNCChanges, or replication
  requested from a host that is not a domain controller.
- Any detection on a domain controller whose `agent` is a DC and whose technique is in the
  credential-access tactic, within minutes of a lateral-movement detection reaching that DC.

## 2. Hypotheses

- H1 (supported/refuted): a non-DC host or a non-DC account requested directory replication
  from `<dc host>`, which is DCSync-class credential theft of domain secrets.
- H2: the replication request is the end of a chain that began with credential compromise on
  `<source host>` and reached the DC by a remote logon.
- H3 (benign alternative to rule out): the request came from a legitimate DC, Azure AD
  Connect / Entra Connect sync server, or a backup product with replication rights.

## 3. Intake-only decision rules

The v1 intake carries `level`, `description`, `rule_id`, `agent`, `mitre[]`, `timestamp`. It
does not carry the requesting account, the source address, or the replication GUIDs.

- If a detection with T1003.006 fires on a DC agent, H1 is `supported` at **Medium** on the
  description alone: the rule asserts "non-DC source", but the intake cannot show which host.
- If, in the same intake, a lateral-movement detection (T1021.*) on the same DC precedes the
  T1003.006 detection by no more than 15 minutes, H2 is `supported` and H1 rises to **High**:
  two independent detections corroborate, and no benign replication source logs on by SMB
  minutes before replicating.
- If the only detection is T1003.006 with no preceding chain, keep **Medium** and name H3 as
  the alternative; the data request in section 4 decides it.
- **Cross-host chain (H2).** When a credential-attack detection on `<source host>` precedes
  the DC logon, and the DC logon's own description asserts the relation ("from a source with
  a preceding failed-auth burst"), that assertion plus the time order is the link; the intake
  not naming the address is a data request, not a reason to hedge. A recon-delta change on
  `<source host>` inside the window is a second, independent source. With both, H2 and H1 are
  **High** for the whole chain, not only for the DC segment.
- **v2 intakes:** a `user` shared by the source-host success and the DC logon, or a `src_ip`
  shared by the DC logon and the replication request, establishes the link as data.
- Severity: a `supported` H1 is the most critical item in any intake it appears in. Lead the
  brief with it. Containment options are appropriate at Medium or above because the cost of
  a completed DCSync (every domain hash, including krbtgt) is total.

## 4. Data requests (what settles H1 and H3)

| Need | Source | Fields |
|---|---|---|
| Who requested replication | DC Security log, event 4662, via Wazuh `data.win.eventdata` | `SubjectUserName`, `SubjectDomainName`, `ObjectType`, `Properties`, `AccessMask` |
| Replication rights used | event 4662 `Properties` containing the control-access GUIDs | `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes), `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes-All), `89e95b76-444d-4c62-991a-0facbeda640c` (Get-Changes-In-Filtered-Set) |
| Source of the request | event 4624 on the DC just before the 4662, LogonType 3 | `IpAddress`, `TargetUserName`, `LogonType`, `LogonProcessName` |
| Is the requester a DC or sync server | AD computer objects; Wazuh `agent.name` list | DC list, Entra Connect / backup service accounts |
| Was krbtgt touched | DC Security log events 4738 (user account changed), 4769 bursts | `TargetUserName` = `krbtgt`, request counts per source |
| Network path | Zeek `dce_rpc.log` and `conn.log` for the DC | `id.orig_h`, `id.resp_h`, `endpoint` = `drsuapi`, `operation` = `DRSGetNCChanges` |

Every row becomes a `data_requests[]` entry with the exact `source` and `fields`.

## 5. Raw-telemetry mode (allowlisted commands only)

```
# 4662 events carrying a replication GUID, with the requesting account
jq -c 'select(.data.win.system.eventID=="4662") | select(.data.win.eventdata.Properties|test("1131f6a[ad]|89e95b76")) | {t:.timestamp, who:.data.win.eventdata.SubjectUserName, host:.agent.name}' <alerts.jsonl>

# DRSUAPI GetNCChanges over the wire, by source host
zeek-cut ts id.orig_h id.resp_h endpoint operation < dce_rpc.log | grep -i DRSGetNCChanges

# same from a capture (DRSGetNCChanges is drsuapi opnum 3)
tshark -r <capture.pcap> -Y 'drsuapi.opnum == 3' -T fields -e frame.time -e ip.src -e ip.dst
```

Quote each value you use as `raw:<file>:<line>`.

## 6. Confidence ladder

| Level | Requires |
|---|---|
| Low | A replication-related description with no technique ID, or a technique ID with no DC agent |
| Medium | T1003.006 on a DC agent, description asserting a non-DC source; no second detection |
| High | Medium plus a preceding lateral-movement or credential-access detection on the same chain within 15 minutes, or raw evidence of 4662 with a replication GUID from a non-DC account |

What moves Medium to High in intake-only mode is a second, independent detection on the
chain. What refutes H1 is raw evidence that the requester is a DC or an authorized sync
account. CSF 2.0: DE.AE-02, DE.AE-03, DE.CM-09, RS.AN-03, RS.MI-01; hardening PR.AA-05.

**Options when H1 or H2 is supported.** One option per action, each named concretely:

- `contain`: isolate the first host in the chain by its agent name, the one whose detection
  opened the chain, not "the host behind <address>". Name the DC separately only if the
  replication is confirmed from raw 4662.
- `contain`: reset the account, but only once it is named. In v1 that is a `TargetUserName`
  data request on the success rules, listed first in `depends_on`; in v2 the `user` field names
  it and the option can be written out directly.
- `harden`: close a new exposure the recon delta shows on a chain host (`<host>:<port>/<proto>`).
  Say "close", with what it costs, not "review".
- `investigate`: hunt the DC for replication abuse and krbtgt changes (events 4662, 4738, 4769).
