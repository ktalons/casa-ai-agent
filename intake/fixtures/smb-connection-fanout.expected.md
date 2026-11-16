# Ground truth — smb-connection-fanout (held out)

Hand-authored synthetic intake. Machine-checkable form: `smb-connection-fanout.expected.json`. A binary named `svchost.exe` runs from `C:\Users\Public\Libraries` on the workstation `corpws63` and sweeps the internal network for SMB and RDP. The lab also runs a scheduled recon scan, which this sweep is not. The test is whether CASA checks the recon delta instead of assuming any internal scan is the scheduled one.

## The story

All times 2026-08-17, Z:

| Time | Rule | Source | What it shows |
|---|---|---|---|
| 15:42:10.553 | `100980` | Sysmon 1 on `corpws63` | `cmd.exe /c start "" /b C:\Users\Public\Libraries\svchost.exe -k netsvcs` starts the binary as `CORP\u-fin22`, Medium integrity |
| 15:43:02.118734 | `100981` | Sysmon 3 on `corpws63` | that process connects `198.51.100.63` to `198.51.100.12:445` |
| 15:43:02.640 | `100981` | Sysmon 3 | to `198.51.100.14:3389` |
| 15:43:03.077 | `100981` | Sysmon 3 | to `198.51.100.21:445` |
| 15:43:31.905 | `100982` (Suricata SID `1000210`) | network sensor `corpids14` | SMB sweep: one internal source to 20 or more internal hosts on 445/tcp within 60 seconds, source `198.51.100.63` |
| 15:43:44.360218 | `100983` (Suricata SID `1000211`) | network sensor `corpids14` | RDP sweep, the same on 3389/tcp |

The recon delta records the scheduled run `internal-nightly` from the scanner `corpscan11` (`192.0.2.11`), 02:00Z to 02:41Z on 2026-08-18, with no new or removed listeners against the 2026-08-11 baseline.

## Must identify

- [ ] One chain on `corpws63` / `198.51.100.63`: process creation, then the Sysmon connections, then the two Suricata sweep alerts.
- [ ] **Masquerading** (T1036.005): `svchost.exe` outside System32, parent `cmd.exe`, a user account, Medium integrity. The real service host lives in `C:\Windows\System32` and is started by the service control manager.
- [ ] **Network service discovery** (T1046) over 445/tcp and 3389/tcp, the usual precursor to lateral movement over SMB or RDP.
- [ ] **Not the scheduled scan**: the recon delta's run came from a different host (`corpscan11`), a different address (`192.0.2.11`) and a different time (02:00Z to 02:41Z the next day).
- [ ] Next steps: the binary's hash or a copy; what started the parent `cmd.exe`; whether any swept host accepted an SMB or RDP session from `198.51.100.63`; an option to isolate `corpws63`.

## Must NOT do

- [ ] Dismiss or downgrade the sweep as the scheduled recon scan, authorized scanning or an inventory job.
- [ ] Treat the process as the legitimate Windows `svchost.exe`.

## Confidence

- [ ] **High.** Standards §5: direct evidence in the input; documented techniques (T1046, T1036.005); two independent sources corroborate (Sysmon on `corpws63` and the Suricata sensor `corpids14`, which sees the same source address sweeping both ports); no plausible benign explanation fits, because the one benign candidate, the scheduled recon scan, is ruled out by the recon delta on host, address and time, and a scanner masquerading as `svchost.exe` in a public folder has no administrative reading. No modifier applies: the recon baseline is present and the window is not truncated. Containment options are therefore allowed (§7). One thread: one source host, all events within two minutes.
