# Ground truth — eventlog-service-alerts (held out)

Hand-authored synthetic intake. Machine-checkable form: `eventlog-service-alerts.expected.json`. An administrator account logs on to the server `corpsrv52` over RDP and, within five minutes, clears the event logs, turns off Defender real-time protection and disables Sysmon. The test is whether CASA calls the impairment what it is and sees that the host's own telemetry can no longer be trusted to show what came next.

The filter floor is 10 and rule `100960` (the RDP logon, level 5) is admitted through `filter.include_rule_ids`. That is a context rule the producer always includes, not truncation.

## The story

All times 2026-08-12, Z:

| Time | Rule | Source | What it shows |
|---|---|---|---|
| 03:12:07.118402 | `100960` (level 5, included) | Security 4624 | RDP logon (logon type 10) of `adm-ops17` from `198.51.100.36` |
| 03:14:41.203 | `100961` | Sysmon 1 | `wevtutil.exe cl Security` by `CORP\adm-ops17`, parent `cmd.exe` |
| 03:14:41.587 | `100962` (level 13) | Security 1102 | the Security audit log was cleared, subject `adm-ops17` |
| 03:14:44.910233 | `100961` | Sysmon 1 | `wevtutil.exe cl System` |
| 03:15:58.402 | `100963` | Sysmon 1 | `powershell.exe ... Set-MpPreference -DisableRealtimeMonitoring $true` |
| 03:15:59.771 | `100964` | Defender 5001 | real-time protection was disabled |
| 03:17:05.336 | `100965` | Sysmon 1 | `sc.exe config Sysmon64 start= disabled` |
| 03:17:09.648117 | `100966` (level 13) | Sysmon 1 | `sc.exe stop Sysmon64`, the last Sysmon event the host can send |

Every Sysmon process event shares one parent (`cmd.exe`, PID 6120) under `CORP\adm-ops17` at High integrity.

## Technique IDs

The CASA reference table is ATT&CK 19.2 (`skills/standards/references/attack-techniques.json`), which has moved the older IDs: Clear Windows Event Logs is **T1685.005** (formerly T1070.001) and Disable or Modify Tools is **T1685** (formerly T1562.001), both under the defense-impairment tactic. The intake uses the 19.2 IDs, so a brief citing T1070.001 or T1562.001 fails the lint (neither is in the intake or the table).

## Must identify

- [ ] One sequence on `corpsrv52`, oldest to newest as above, about five minutes long.
- [ ] Deliberate indicator removal and defense impairment (T1685.005, T1685) through an interactive RDP session (T1021.001), not routine administration.
- [ ] **The telemetry gap.** Sysmon on `corpsrv52` stops at 03:17:09Z and is set not to start again; the Security and System logs before 03:14Z are gone. No later alert from the host is **not** evidence of no later activity (standards §3: absence of an alert is not absence of activity).
- [ ] Data requests to sources the actor did not touch: network-side telemetry for `corpsrv52` after 03:17Z (IDS alerts, flow or firewall records), and the RDP source `198.51.100.36` (the workstation the session came from).
- [ ] Options: isolate `corpsrv52`; restrict or reset `adm-ops17`; hunt the account's other logons.

## Must NOT do

- [ ] Explain the sequence as maintenance, log rotation or troubleshooting, or lower the verdict because the account is an administrator.
- [ ] Say or imply the host went quiet because nothing follows the Sysmon stop.

## Confidence

- [ ] **High.** Standards §5: direct evidence in the input; documented techniques (T1685.005, T1685, T1021.001); at least two independent sources corroborate, and here three do on the same acts: Sysmon process events, the Security log (4624, then 1102 less than half a second after `wevtutil cl Security`) and Defender (5001 a second after `Set-MpPreference`); no plausible benign explanation fits, since clearing the Security log and disabling both Defender and Sysmon within minutes of an interactive logon has no maintenance reading. No modifier applies: the recon baseline is present and the window is not truncated. Containment options are therefore allowed (§7). One thread: one host, one session, minutes apart.
