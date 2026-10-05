# Data exfiltration: volume, destination, encoding, staging

## 1. Applies when

- Technique IDs: T1041 (Exfiltration Over C2 Channel), T1048 (Exfiltration Over Alternative
  Protocol; .003 unencrypted non-C2), T1567 (Exfiltration Over Web Service; .002 to cloud
  storage), T1020 (Automated Exfiltration), T1074 (Data Staged), T1560 (Archive Collected Data).
- Wazuh rule descriptions naming large outbound transfers, inverted upload ratios, uploads to
  cloud or file-sharing services, archive creation in unusual locations, or DNS queries with
  unusually long labels.

## 2. Hypotheses

- H1: `<host>` sent an unusual volume of data to `<destination>` in the window.
- H2: the data left over a covert channel (DNS labels, encoded HTTP bodies) rather than a
  plain upload.
- H3: data was staged on `<host>` (archives, temp directories) before the transfer.
- H4 (benign): a backup job, a cloud sync client, a software update mirror, or a user's
  legitimate upload.

## 3. Intake-only decision rules

- An exfiltration-tactic detection makes H1 `supported` at **Medium** at most: v1 carries no
  byte counts, destination, user or file names.
- A staging detection (T1074 or T1560) on the same host preceding the transfer detection
  within an hour makes one thread and keeps **Medium** with stronger corroboration.
- H2 requires DNS or proxy evidence the intake does not carry; mark undetermined.
- H4 is the default alternative for every finding here. Business hours, destination
  category and the host's role decide it, none of which v1 carries.
- **High** needs the data in section 4: measured volume against a baseline, a destination
  outside approved services, and a staging artifact or a user action that explains it.

## 4. Data requests

| Need | Source | Fields |
|---|---|---|
| Volume and ratio | Zeek `conn.log`, NetFlow | `orig_bytes`, `resp_bytes`, `duration`, per host and destination, against a 7-day baseline |
| Destination category | proxy or web gateway logs, `ssl.log` | URL host, `server_name`, category, bytes uploaded |
| Covert channel signs | `dns.log` | query length, label entropy, `qtype_name` (`TXT`), distinct subdomains per domain |
| Staging | Sysmon event 11 (file create), 4663 (object access) | archive extensions in temp paths, bulk reads of sensitive shares |
| Who and when | 4624 session for the host, file-server audit | `TargetUserName`, logon time against business hours |
| Policy context | DLP alerts, approved-service list | policy name, action taken |

## 5. Raw-telemetry mode

```
# outbound bytes per destination for the host
zeek-cut id.orig_h id.resp_h id.resp_p orig_bytes resp_bytes < conn.log | grep '^<host ip>' | sort -k4 -n -r | head

# upload-heavy sessions (orig_bytes much larger than resp_bytes)
zeek-cut ts id.orig_h id.resp_h orig_bytes resp_bytes < conn.log | jq -R -s 'split("\n")|map(select(length>0)|split("\t"))|map(select((.[3]|tonumber) > 10*(.[4]|tonumber) and (.[3]|tonumber) > 10000000))'

# long DNS labels
zeek-cut ts query < dns.log | jq -R -s 'split("\n")|map(select(length>0)|split("\t"))|map(select(.[1]|length > 60))'

# large POSTs from a capture
tshark -r <capture.pcap> -Y 'http.request.method == "POST" && http.content_length > 1000000' -T fields -e frame.time -e ip.src -e http.host -e http.content_length
```

Thresholds worth stating: outbound volume above two standard deviations of the host's
baseline; an inverted upload-to-download ratio; archive creation followed by transfer within
the hour; DNS labels longer than 60 characters at volume.

## 6. Confidence ladder

| Level | Requires |
|---|---|
| Low | A volume rule alone, or a destination that is an approved service |
| Medium | A transfer detection plus a staging detection on the same host, or a destination outside approved services asserted by a rule |
| High | Measured volume against baseline, an unapproved destination, and a staging artifact or user action that explains the transfer, all cited |

CSF 2.0: DE.CM-01, DE.CM-03, DE.AE-02, DE.AE-04; hardening PR.DS-01, PR.DS-02, PR.PS-05;
response RS.AN-03, RS.AN-08, RS.MI-01.
