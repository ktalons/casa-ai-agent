# Ground truth — brute-force-dc-chain

Hand-authored representative intake. Machine-checkable form: `brute-force-dc-chain.expected.json`. The TalonSocLab AD environment (Phase C) is not built yet, so `talondc01` is synthetic; the alert shapes, rule-ID namespace, and MITRE mappings mirror what the deployed pipeline will emit. A correct CASA analysis of this intake must land the points below.

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
- [ ] Concrete next steps: isolate `talondellbox`; request `TargetUserName` for rules `100210` / `100215` from the raw alerts (v1 carries no account field) and then reset that account; hunt for `krbtgt` / replication abuse on `talondc01`; close the new RDP exposure.
- [ ] Route to `casa:log-analyst` (auth chain), `casa:endpoint-analyst` (4662 and replication detail) and `casa:network-analyst` (RDP/SMB paths); map via `casa:purple-team-mapper`.

## Confidence

- [ ] **High** for the claim the rubric can support: the four detections are one escalating chain and `100220` is DCSync-class. Two independent sources corroborate it (the time-ordered alert chain across two hosts, and the recon delta on the first host). CASA should say High for that claim and name the account and source address as data requests, without downgrading the chain itself.
