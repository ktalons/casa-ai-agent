# Authentication anomaly: brute force, spraying, stuffing, and burst-then-success

## 1. Applies when

- Technique IDs: T1110 and sub-techniques (.001 password guessing, .003 password spraying,
  .004 credential stuffing), T1078 (Valid Accounts), T1098 (Account Manipulation).
- Wazuh rule descriptions naming repeated authentication failures, a burst that ends in a
  successful logon, lockouts, or logons at unusual times or from unusual sources.

## 2. Hypotheses

- H1: `<host>` received a credential attack (burst of failures from one source) in the window.
- H2: the attack succeeded: the same source logged on successfully after the burst.
- H3: the pattern is spraying (few attempts per account, many accounts) rather than brute
  force (many attempts against one account); the response differs.
- H4 (benign): a misconfigured service account, a user who changed a password, or a
  vulnerability scanner produced the failures.

## 3. Intake-only decision rules

- A T1110 detection on `<host>` makes H1 `supported` at **Medium**: the rule counted failures,
  but the intake does not show the source or the accounts.
- A second detection on the same host showing that the burst ended in a successful logon
  makes H2 `supported` at **Medium**; it reaches **High** when a further detection shows what
  the success led to (a lateral-movement or credential-access detection on another host
  within 15 minutes).
- H3 cannot be decided from v1: the intake has no account field. State it as undetermined
  and request the data in section 4.
- H4 stays open until the source address is known. Say so in `alternatives`.
- **Chain into another host.** A later detection on a second host whose own rule description
  asserts its relation to this burst, in time order, is the link between them; the missing
  address is a data request. Rate the chain with the standards confidence rubric over all of
  its independent references, and hand the second host to the lateral-movement or DCSync card.
- **v2 intakes:** `src_ip` and `user` on each detection decide spraying versus brute force
  directly and tie the success to the burst; the ceilings above lift accordingly.
- **v3 intakes:** `target_user` and `logon_type` on each failure separate spraying (many
  targets from one source) from brute force (one target); `subject_user` is the caller when a
  service authenticates on a user's behalf.
- Thresholds: the rule's own description and level state what it counted. A burst below the
  producer's level floor never reaches the intake, so no burst detection is not evidence of no
  failures.

## 4. Data requests

| Need | Source | Fields |
|---|---|---|
| Source and accounts of the failures | Windows Security 4625 / Linux `sshd` and PAM via Wazuh `data.win.eventdata` or `data` | `IpAddress`, `TargetUserName`, `LogonType`, `FailureReason`, `Status`, `SubStatus`; `srcip`, `srcuser` |
| The success that followed | Windows Security 4624 | `IpAddress`, `TargetUserName`, `LogonType`, `AuthenticationPackageName` |
| Spraying vs brute force | counts per account and per source over the burst | distinct `TargetUserName` per `IpAddress` |
| Lockouts | Windows Security 4740, 4776 | `TargetUserName`, `TargetDomainName`, `Workstation` |
| What the account did next | 4672 (special privileges), 4648 (explicit credentials), 4698, 7045 | `TargetUserName`, `ProcessName`, `TaskName`, `ServiceName` |
| Is the source a scanner or a known admin host | asset inventory, recon delta | host role, exposure changes |

## 5. Raw-data requests

A specialist never runs these: they are data requests, which the main thread runs under the
user's own permission settings when raw telemetry exists, handing the output to the
specialists, or which go into `data_requests` as exact commands for the human analyst.

```bash
# failures by source and account in the window
jq -r 'select(.data.win.system.eventID=="4625") | [.timestamp, .data.win.eventdata.ipAddress, .data.win.eventdata.targetUserName] | @tsv' <alerts.jsonl>

# the first success after the burst, from the same source
jq -r 'select(.data.win.system.eventID=="4624") | select(.data.win.eventdata.ipAddress=="<source>") | [.timestamp, .data.win.eventdata.targetUserName, .data.win.eventdata.logonType] | @tsv' <alerts.jsonl>

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

**Options to offer.** Containment options follow the standards skill's rule. One option per
action, each named concretely: `contain` isolates the host that saw the success, by agent name; `contain` resets
the account once it is named (v1: a `TargetUserName` data request listed first in
`depends_on`; v2: the `user` field); `harden` closes a new exposure the recon delta shows on
that host, named as `<host>:<port>/<proto>`, with the cost of closing it; `investigate` pulls
the raw 4625 and 4624 events for the source.
