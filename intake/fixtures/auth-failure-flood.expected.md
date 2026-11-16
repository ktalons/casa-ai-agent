# Ground truth — auth-failure-flood

Hand-authored v3 intake. Machine-checkable form: `auth-failure-flood.expected.json`. The export cap is 5 and `truncated` is true: 42 alerts matched the filter in the window (29 on 2026-08-03, 13 on 2026-08-04) and only the 5 newest are included. Those five show a password spray from `192.0.2.77` against the domain controller `corpdc02`: rule `100912` fires on 4625 network-logon failures for `svc-print`, `adm-helpdesk` and `u-frontdesk`; rule `100914` fires on a successful type 3 logon (4624) for `svc-print` from the same source; and the network sensor `corpnsm05` raised a Suricata alert (rule `100916`, SID `1000121`) on SMB NTLMSSP failures for many accounts from that address to the DC. A correct CASA analysis must land the points below.

## Must identify

- [ ] The intake is **truncated**: 5 of 42 matched alerts are included, and all 29 that matched on 2026-08-03 are among the 37 dropped.
- [ ] A **password spray followed by a success**: failures across several accounts from `192.0.2.77`, then a type 3 logon for `svc-print`, an account that also failed, so `svc-print` is likely compromised (T1078).
- [ ] The Suricata alert on the same source is an **independent second source** next to the DC's logon events.
- [ ] Confidence is **Medium**, with truncation named as the reason it is not High.
- [ ] A **data request** for the 37 dropped alerts (the full matched set for the window).
- [ ] Conclusions are **scoped to the included alerts**: the start of the spray, the full account list and any other success are unknown.

## Must not

- [ ] Claim the spray began at the oldest included alert (2026-08-04T01:09:58Z) or give any start time.
- [ ] Claim nothing else happened: no other success, no other target.
- [ ] Offer containment (isolating a host, disabling or resetting `svc-print`, blocking the source), under any option kind.

## Must cite

- [ ] Rule IDs `100912`, `100914`, `100916`; the domain controller `corpdc02`.
- [ ] MITRE: T1110.003 (Password Spraying), T1078 (Valid Accounts).

## Must map / recommend

- [ ] NIST CSF 2.0: **DETECT**. No containment option at Medium (`forbid_option_kinds: contain`); the options are investigate options that would raise confidence.
- [ ] Route to `casa:log-analyst` (the auth chain) and `casa:endpoint-analyst` (what `svc-print` did after the logon, as a data request).

## Confidence

- [ ] **Medium.** On the included evidence alone this is High: direct evidence (4625 and 4624 events on the DC), documented techniques (T1110.003, T1078), two independent sources (the DC's Security log through Wazuh and the network sensor's Suricata alert on the same address), and no plausible benign reading of failures across many accounts from one source followed by a success for one of them. The baseline is present, so no other modifier applies. The truncated window is a minus modifier (standards §5), which lowers High one level to Medium.
