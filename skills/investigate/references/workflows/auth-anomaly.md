# Authentication anomaly: brute force, spraying, stuffing, and burst-then-success

## 1. Applies when

- Technique IDs: T1110 and sub-techniques (.001 password guessing, .003 password spraying,
  .004 credential stuffing), T1078 (Valid Accounts), T1098 (Account Manipulation).
- Wazuh rule descriptions naming multiple authentication failures, failures followed by a
  success, lockouts, or logons at unusual times or from unusual sources.

## 2. Hypotheses

- H1: `<host>` received a credential attack (burst of failures from one source) in the window.
- H2: the attack succeeded: a success from the same source followed the burst.
- H3: the pattern is spraying (few attempts per account, many accounts) rather than brute
  force (many attempts against one account); the response differs.
- H4 (benign): a misconfigured service account, a user who changed a password, or a
  vulnerability scanner produced the failures.

## 3. Intake-only decision rules

- A T1110 detection on `<host>` makes H1 `supported` at **Medium**: the rule counted failures,
  but the intake does not show the source or the accounts.
- A second detection on the same host whose description says failures were followed by a
  success (T1110.001 with T1078, or a "burst then success" rule) makes H2 `supported` at
  **Medium**; it reaches **High** when a third detection shows what the success led to (a
  lateral-movement or credential-access detection on another host within 15 minutes).
- H3 cannot be decided from v1: the intake has no account field. State it as undetermined
  and request the data in section 4.
- H4 stays open until the source address is known. Say so in `alternatives`.
- **Chain into another host.** If a later detection on a second host says in its own
  description that the logon came from a source with a preceding failure burst, treat that
  as the link to this burst; the missing address is a data request. With a recon-delta change
  on this host in the window as well, the chain reaches **High**; hand it to the
  lateral-movement or DCSync card for the second host.
- **v2 intakes:** `src_ip` and `user` on each detection decide spraying versus brute force
  directly and tie the success to the burst; the ceilings above lift accordingly.
- Threshold guidance from the lab's rules: a burst of 20 or more failures in 60 seconds from
  one source is the level-12 floor; below that nothing reaches the intake.

## 4. Data requests

| Need | Source | Fields |
|---|---|---|
| Source and accounts of the failures | Windows Security 4625 / Linux `sshd` and PAM via Wazuh `data.win.eventdata` or `data` | `IpAddress`, `TargetUserName`, `LogonType`, `FailureReason`, `Status`, `SubStatus`; `srcip`, `srcuser` |
| The success that followed | Windows Security 4624 | `IpAddress`, `TargetUserName`, `LogonType`, `AuthenticationPackageName` |
| Spraying vs brute force | counts per account and per source over the burst | distinct `TargetUserName` per `IpAddress` |
| Lockouts | Windows Security 4740, 4776 | `TargetUserName`, `TargetDomainName`, `Workstation` |
| What the account did next | 4672 (special privileges), 4648 (explicit credentials), 4698, 7045 | `TargetUserName`, `ProcessName`, `TaskName`, `ServiceName` |
| Is the source a scanner or a known admin host | asset inventory, recon delta | host role, exposure changes |

## 5. Raw-telemetry mode

```
# failures by source and account in the window
jq -r 'select(.data.win.system.eventID=="4625") | [.timestamp, .data.win.eventdata.IpAddress, .data.win.eventdata.TargetUserName] | @tsv' <alerts.jsonl>

# the first success after the burst, from the same source
jq -r 'select(.data.win.system.eventID=="4624") | select(.data.win.eventdata.IpAddress=="<source>") | [.timestamp, .data.win.eventdata.TargetUserName, .data.win.eventdata.LogonType] | @tsv' <alerts.jsonl>

# Linux
jq -r 'select(.rule.groups|index("authentication_failed")) | [.timestamp, .data.srcip, .data.srcuser] | @tsv' <alerts.jsonl>
```

Spraying signature: many distinct accounts per source with one or two attempts each.
Brute force: one account, many attempts. Stuffing: varied accounts from many sources.

## 6. Confidence ladder

| Level | Requires |
|---|---|
| Low | Failures only, no technique ID, or a volume below the lab's floor |
| Medium | A T1110 detection; or burst-then-success asserted by a rule with no corroboration |
| High | Burst-then-success plus an independent detection showing what the account did next (lateral movement, privilege use, or credential access), or raw 4625 → 4624 evidence from one source |

CSF 2.0: DE.CM-01, DE.CM-03, DE.AE-02, DE.AE-03; hardening PR.AA-01, PR.AA-03, PR.AA-05;
response RS.AN-03, RS.MI-01.

**Options when burst-then-success is supported.** One option per action, each named
concretely: `contain` isolates the host that saw the success, by agent name; `contain` resets
the account once it is named (v1: a `TargetUserName` data request listed first in
`depends_on`; v2: the `user` field); `harden` closes a new exposure the recon delta shows on
that host, named as `<host>:<port>/<proto>`, with the cost of closing it; `investigate` pulls
the raw 4625 and 4624 events for the source.
