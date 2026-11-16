# Ground truth — suricata-scan-burst

Hand-authored v3 intake. Machine-checkable form: `suricata-scan-burst.expected.json`. The network sensor `corpnsm02` raised five Suricata scan alerts (Wazuh rules `100901` to `100903`, SIDs `1000101` to `1000103`), all from one internal address, `198.51.100.25`, against three hosts on the `192.0.2.0/24` segment. The recon delta for the same night records the lab's scheduled recon run `recon-weekly-tcp` from `corpscan03` at that address, 02:00:00Z to 02:41:37Z on 2026-07-28, scanning TCP 22, 80, 135, 139, 443, 445, 3389 and 5985. Every alert falls inside that span, every destination port is in that set, and nothing goes past scanning: no exploit signature, no detection on a scanned host, and the recon delta shows no new or removed service. A correct CASA analysis must land the points below.

## Must identify

- [ ] The five alerts are **one scanning activity** from one source (`198.51.100.25`, fixed source port 61834) against `192.0.2.14`, `192.0.2.31` and `192.0.2.52` on several ports, in one thread.
- [ ] The hypothesis "hostile internal reconnaissance" is **refuted**, because the alerts match the scheduled run from `corpscan03` on source address, time span and port set.
- [ ] Nothing in the intake goes **past scanning**.
- [ ] Confidence is **Medium**, and the brief names what would raise it: analyst confirmation that `corpscan03` is the sanctioned scanner and that its schedule is real.
- [ ] A **data request** to confirm the scanner and its schedule from a source outside the alerts.
- [ ] A **tuning option** that scopes the scheduled scanner (its address, optionally its run window) out of the scan rules, rather than disabling them.

## Must not

- [ ] Call the activity a confirmed attack or confirmed hostile reconnaissance.
- [ ] Recommend isolating, blocking or shutting down `corpscan03`.
- [ ] Recommend disabling or deleting the scan rules for every source.

## Must cite

- [ ] Rule IDs `100901`, `100902`, `100903`; the scanner host `corpscan03`.
- [ ] MITRE: T1046 (Network Service Discovery).

## Must map / recommend

- [ ] NIST CSF 2.0: **DETECT**. No containment option (`forbid_option_kinds: contain`).
- [ ] Route to `casa:network-analyst` (scan shape against the recon record).

## Confidence

- [ ] **Medium.** The refutation rests on direct evidence: the alert fields match the recon record exactly, and the record carries a baseline, so no minus modifier applies. It cannot be High, because the claim that the run is the lab's own sanctioned scan comes from the recon delta, which is telemetry (standards §2), not analyst-confirmed environment context; §5 puts incomplete environment context at Medium. Analyst confirmation of the scanner and its schedule is the one plus modifier that would make it High.
