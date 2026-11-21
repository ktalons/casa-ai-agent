# Ground truth — linux-audit-alerts (held out)

Hand-authored synthetic intake. Machine-checkable form: `linux-audit-alerts.expected.json`. An account logs on to the Linux server `corplnx73` over SSH with a password from an internal workstation address and, inside three minutes, switches the kernel audit system off, stops the audit daemon, truncates `/var/log/auth.log` and empties its own shell history. The test is whether CASA calls the tampering what it is and sees that the host's own audit telemetry can no longer show what came next.

The filter floor is 10 and rule `101000` (the SSH logon, level 3) is admitted through `filter.include_rule_ids`. That is a context rule the producer always includes, not truncation.

## The story

All times 2026-09-03, Z:

| Time | Rule | Source on `corplnx73` | What it shows |
|---|---|---|---|
| 02:41:07.214 | `101000` (level 3, included) | auth.log, sshd | password logon of `adm-infra62` from `198.51.100.58` |
| 02:42:15.338 | `101001` | auth.log, sudo | `adm-infra62` runs `/usr/sbin/auditctl -e 0` as root |
| 02:42:15.341204 | `101002` (level 13) | kernel audit trail | configuration change `audit_enabled=0 old=1`, auid `adm-infra62` |
| 02:42:31.902 | `101003` | auth.log, sudo | `adm-infra62` runs `/usr/bin/systemctl stop auditd` as root |
| 02:42:31.958417 | `101004` | kernel audit trail | `DAEMON_END`, the last record the audit daemon writes |
| 02:43:02.117 | `101005` (level 13) | auth.log, sudo | `adm-infra62` runs `/usr/bin/truncate -s 0 /var/log/auth.log` as root |
| 02:43:02.640 | `101006` | Wazuh file integrity | `/var/log/auth.log` shrank from 61427 to 0 bytes |
| 02:43:49.075 | `101007` | Wazuh file integrity | `/home/adm-infra62/.bash_history` emptied (8214 to 0 bytes) |

Three sources on the host record the same acts independently: the sudo lines (syslog), the kernel audit trail, and file-integrity monitoring. Each tampering step is seen twice: `auditctl -e 0` by sudo and by the audit configuration record, the daemon stop by sudo and by `DAEMON_END`, the truncation by sudo and by the file-integrity shrink. The sudo line for the truncation reached Wazuh before the file was emptied, which is why it survives.

## Technique IDs

The CASA reference table is ATT&CK 19.2 (`skills/standards/references/attack-techniques.json`): Disable or Modify Linux Audit System Log is **T1685.004**, Clear Linux or Mac System Logs is **T1685.006** (both defense-impairment), Clear Command History is **T1070.003** (stealth), and SSH is **T1021.004**. A brief citing the pre-19 IDs (T1562.012, T1070.002) fails the lint: neither is in the intake or the table.

## Must identify

- [ ] One session on `corplnx73`, oldest to newest as above, under three minutes long.
- [ ] Deliberate defense impairment and indicator removal (T1685.004, T1685.006, T1070.003) in an SSH session (T1021.004), not routine administration.
- [ ] **The telemetry gap.** The kernel audit trail ends with the auditd stop at 02:42:31Z, auth.log was emptied on the host, and the account's history is gone. No later alert from the host is **not** evidence of no later activity (standards §3). What still reports from the host is narrow: sudo lines and changes to files under integrity monitoring; anything else the session did after 02:42:31Z is invisible to the host's own telemetry.
- [ ] Data requests to sources the actor did not touch: network-side telemetry for `corplnx73` after the auditd stop (IDS alerts, flow or firewall records), and the workstation at `198.51.100.58` for what opened the SSH session. A strong brief also notes that the auth.log lines Wazuh collected before the truncation survive off the host, on the manager; that point is not required.
- [ ] Options: isolate `corplnx73`; restrict or reset `adm-infra62` (or turn off password logon for it); hunt the account's other logons.

## Must NOT do

- [ ] Explain the sequence as log rotation, disk cleanup, maintenance or troubleshooting. The wrong turn this scenario invites is rotation: logrotate can truncate a log in place, but here the truncation is a `sudo truncate` by the logged-on account, under a minute after it switched auditing off, not a rotation job. The account's sudo rights are not a reason to lower the verdict.
- [ ] Say or imply the host went quiet because nothing follows the emptied history.

## Confidence

- [ ] **High.** Standards §5: direct evidence in the input, documented techniques (T1685.004, T1685.006, T1070.003), at least two independent sources on the same acts (sudo in auth.log, the kernel audit trail, file-integrity monitoring), and no plausible benign reading of switching auditing off, wiping auth.log and emptying shell history within three minutes of a logon. No modifier applies: the meaning of the tampering does not depend on what is normal here, so missing baseline would not apply even without the recon baseline (which is present), and the window is not truncated; the absence of an account history or change record is not a modifier either. Containment options are therefore allowed (§7). One thread: one host, one account, one session.
