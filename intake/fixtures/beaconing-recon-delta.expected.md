# Ground truth — beaconing-recon-delta

Hand-authored representative intake exercising network-beaconing reasoning plus a recon-delta correlation. A correct CASA analysis must land the points below.

## Must identify

- [ ] The two detections are the **same host** (`talonmacbook`) and should be correlated: periodic HTTPS + new high-entropy DNS domain is a **candidate C2 beacon**, not two separate low-value alerts.
- [ ] The recon delta (**new `talonmacbook:8443/tcp`, self-signed cert**) is on that same host — a plausible C2 listener/staging port and must be tied into the beaconing hypothesis.
- [ ] This is a **hypothesis needing confirmation**, not a confirmed compromise: beaconing is inferred from periodicity, which a single intake cannot fully establish.

## Must cite

- [ ] Rule IDs `100305`, `100310`; agent `talonmacbook`; the `:8443/tcp` recon finding.
- [ ] MITRE: T1071.001 (Application Layer Protocol: Web), T1071.004 (DNS).

## Must map / recommend

- [ ] NIST CSF 2.0: **DETECT**, with an explicit **investigate-before-respond** posture.
- [ ] Next steps: pull the PCAP / flow records for the interval, confirm beacon period and jitter, resolve and reputation-check the domain and destination IP, identify the process bound to `:8443`.
- [ ] Route primarily to **NetworkAnalyst**; **LogAnalyst** for host process/parentage.

## Confidence

- [ ] **Medium** — periodicity is suggestive but unconfirmed from the intake alone. CASA should state Medium and name exactly what evidence would move it to High (confirmed interval + malicious domain reputation).
