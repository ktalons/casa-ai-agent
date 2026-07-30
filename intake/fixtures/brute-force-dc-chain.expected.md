# Ground truth — brute-force-dc-chain

Hand-authored representative intake. The TalonSocLab AD environment (Phase C) is not built yet, so `talondc01` is synthetic; the alert shapes, rule-ID namespace, and MITRE mappings mirror what the deployed pipeline will emit. A correct CASA analysis of this intake must land the points below.

## Must identify

- [ ] The four detections form **one attack chain**, not four unrelated alerts — ordered oldest→newest: failed-auth burst → burst-then-success → lateral logon to the DC → directory replication.
- [ ] The chain **escalates in severity and scope**: workstation (`talondellbox`) → domain controller (`talondc01`), levels 12 → 15.
- [ ] Detection `100220` (DRSUAPI replication from a non-DC host) is a **DCSync attempt** and is the most critical item — treat as active credential-theft of domain hashes, not a routine event.
- [ ] The new `talondellbox:3389/tcp` (RDP) exposure in the recon delta is **corroborating attack surface**, plausibly the lateral-movement vector; it must be connected to the detections, not reported in isolation.

## Must cite

- [ ] Rule IDs `100200`, `100210`, `100215`, `100220` and the agents `talondellbox` / `talondc01`.
- [ ] MITRE: T1110 / T1110.001 (Brute Force), T1021.002 (SMB/Windows Admin Shares), T1078 (Valid Accounts), T1003.006 (OS Credential Dumping: DCSync).

## Must map / recommend

- [ ] NIST CSF 2.0: **DETECT** (the chain fired) and **RESPOND** (containment now).
- [ ] Concrete next steps: isolate `talondellbox`, force-reset the successfully-authenticated account, hunt for `krbtgt` / replication abuse on `talondc01`, close the new RDP exposure.
- [ ] Route to **LogAnalyst** (auth chain) and **NetworkAnalyst** (RDP/SMB paths); synthesize via **PurpleTeamMapper**.

## Confidence

- [ ] **High** — the evidence chain is internally consistent and self-corroborating (recon delta + escalating auth alerts). CASA should say High and justify it with the chain, not hedge.
