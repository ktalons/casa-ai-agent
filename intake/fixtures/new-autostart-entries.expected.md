# Ground truth — new-autostart-entries

Hand-authored v3 intake. Machine-checkable form: `new-autostart-entries.expected.json`. The filter floor is level 10 and the include list names rule `100938`, so its level-7 file-write detection is in the intake despite the floor. Within six seconds on `corpws58`, Sysmon recorded `WINWORD.EXE` (opening `shipping-notice-0816.docm`) spawning a hidden PowerShell (rule `100935`, event 1); that PowerShell writing `C:\ProgramData\WinSvcCache\svcupd.exe` (rule `100938`, event 11) and setting `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WinSvcCache` to it (rule `100937`, event 13); the System log recording service `WinSvcCache` installed with that image and auto start (rule `100939`, event 7045); and `services.exe` starting `svcupd.exe` as SYSTEM (rule `100936`, event 1). The next recon run found a new listener, `corpws58:9443/tcp`, absent from the 2026-08-10 baseline. A correct CASA analysis must land the points below.

## Must identify

- [ ] **One persistence chain** on `corpws58`, tied by the PowerShell process and the `svcupd.exe` path.
- [ ] **Two persistence mechanisms** for the same binary: the Run key value (T1547.001) and the auto-start service (T1543.003).
- [ ] The new `corpws58:9443/tcp` listener is **corroboration**, with the owning process requested rather than asserted.
- [ ] Confidence **High**, justified by detections plus a recon change and no plausible benign reading.
- [ ] Options: **isolate `corpws58`** (containment, with its trade-off); collect `svcupd.exe` and the document before removing the Run key value and the service; search other hosts for the hash, the path and `dl.media-share.test`.

## Must not

- [ ] Discount the level-7 file-write detection (`100938`) as noise or below threshold.
- [ ] State what `svcupd.exe` does or what serves 9443/tcp; the intake shows neither.

## Must cite

- [ ] Rule IDs `100935`, `100936`, `100937`, `100938`, `100939`; the host `corpws58`.
- [ ] MITRE: T1059.001 (PowerShell), T1547.001 (Registry Run Keys / Startup Folder), T1543.003 (Windows Service).

## Must map / recommend

- [ ] NIST CSF 2.0: **DETECT** and **RESPOND** (containment is in scope at High).
- [ ] Route to `casa:endpoint-analyst` (process, registry and service detail), `casa:network-analyst` (the new listener), `casa:detection-engineer` (a supported finding at High).

## Confidence

- [ ] **High.** Direct evidence (process, file, registry and service-install events with the same path); documented techniques (T1059.001, T1547.001, T1543.003); corroboration of the kind the rubric names, detections plus a recon change on the same host; and no plausible benign reading of an Office document whose PowerShell child installs one binary under a new ProgramData folder as both a Run key value and an auto-start service. The window is not truncated and the baseline is present, so no minus modifier applies.
