# Data Exfiltration Analysis Workflow

**Triggers**: Large outbound transfers, unusual upload/download ratios, data encoded in DNS/HTTP, transfers to cloud storage or file-sharing services, off-hours bulk data movement.

## MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|-----|--------|
| Exfiltration Over C2 Channel | T1041 | Exfiltration |
| Exfiltration Over Alternative Protocol | T1048 | Exfiltration |
| Exfiltration Over Web Service | T1567 | Exfiltration |
| Data Staged | T1074 | Collection |
| Archive Collected Data | T1560 | Collection |
| Automated Exfiltration | T1020 | Exfiltration |

## Agent Routing

```
Analyst Query
     |
     v
[Overseer] — classify as exfiltration investigation
     |
     +------ parallel ------+
     |                      |
     v                      v
[NetworkAnalyst]      [LogAnalyst]
  | Volume analysis     | File access logs
  | Destination review   | User activity
  | Protocol inspection  | Data staging indicators
  | Encoding detection   | DLP alerts
     |                      |
     +----------+-----------+
                |
                v
       [PurpleTeamMapper]
         | Map to NIST CSF 2.0
         | Identify DLP gaps
         | Recommend controls
                |
                v
          [Overseer] — synthesize
```

**Both agents run in parallel** because exfiltration typically leaves traces in both network traffic and system/application logs.

## NetworkAnalyst Task Template

```
INVESTIGATION: Data Exfiltration — Network Analysis

CONTEXT
| Query: [analyst's original question]
| Environment: [network architecture, egress points]
| Timeframe: [period of interest]
| Available Data: [PCAP, NetFlow, proxy logs, DLP alerts]

ANALYSIS STEPS

1. VOLUME ANALYSIS
   - Calculate outbound data volume per source host
   - Compare to historical baseline for each host
   - Identify hosts with volume >2 standard deviations above mean
   - Look for gradual volume increases (slow exfiltration)
   - Check upload-to-download ratio per host (normal is heavily download-favored)

2. DESTINATION ANALYSIS
   - Categorize outbound destinations:
     * Known cloud storage (AWS S3, Azure Blob, Google Cloud, Dropbox, etc.)
     * File sharing services (Mega, WeTransfer, etc.)
     * Personal email services
     * Unknown/uncategorized external hosts
   - Flag destinations not in approved service list
   - Check domain registration age and reputation

3. TIMING ANALYSIS
   - Identify transfers occurring outside business hours
   - Look for scheduled/automated transfer patterns
   - Detect burst transfers (large volume in short window)
   - Identify "low and slow" patterns (small transfers over long periods)

4. PROTOCOL AND ENCODING ANALYSIS
   - DNS: check for unusually long subdomain labels (data in DNS)
   - HTTP/S: look for base64 or other encoding in URLs, headers, or POST bodies
   - ICMP: check for data in echo request/reply payloads
   - Unusual protocols on standard ports (tunneling)
   - Encrypted traffic volume spikes to new destinations

5. DATA CHARACTERISTICS
   - Payload entropy analysis (compressed/encrypted data has high entropy)
   - File type indicators in traffic (document headers, archive signatures)
   - Chunked transfer patterns (large file split across many small transfers)
   - Session persistence patterns

OUTPUT FORMAT: Use standard NetworkAnalyst output format.
```

## LogAnalyst Task Template

```
INVESTIGATION: Data Exfiltration — Log Analysis

CONTEXT
| Query: [analyst's original question]
| Environment: [systems, applications, DLP tools]
| Timeframe: [period of interest]
| Available Data: [system logs, application logs, DLP alerts]

ANALYSIS STEPS

1. FILE ACCESS ANALYSIS
   - Identify bulk file access patterns (many files in short timeframe)
   - Look for access to sensitive directories or classified data stores
   - Check for file copy/move operations to staging locations
   - Identify access by accounts that don't normally touch those resources

2. USER ACTIVITY ANALYSIS
   - Correlate file access with user login sessions
   - Identify after-hours file access activity
   - Look for privilege escalation preceding data access
   - Check for new or unusual application usage (archiving tools, cloud sync)

3. DATA STAGING INDICATORS
   - Temporary file creation in unusual locations
   - Archive creation (zip, 7z, rar, tar) especially of sensitive directories
   - Renaming files with innocuous extensions
   - Clipboard/print activity anomalies

4. DLP AND APPLICATION LOGS
   - DLP policy violations or near-misses
   - Email attachment analysis (size, frequency, recipients)
   - Cloud application upload events
   - USB/removable media events
   - Print job anomalies (volume, content)

5. CORRELATION WITH NETWORK FINDINGS
   - Match file access timestamps to network transfer timestamps
   - Correlate user sessions with outbound connection sources
   - Link staged data volumes to observed transfer volumes

OUTPUT FORMAT: Use standard LogAnalyst output format with NIST 800-92 references.
```

## PurpleTeamMapper Task Template

```
MAPPING REQUEST: Data Exfiltration Findings

FINDINGS FROM NETWORKANALYST:
[Insert NetworkAnalyst findings]

FINDINGS FROM LOGANALYST:
[Insert LogAnalyst findings]

MAP TO:
1. NIST CSF 2.0 — focus on:
   - PR.DS (Data Security)
   - PR.AA (Identity Management and Access Control)
   - DE.CM-01 (Network monitoring)
   - DE.CM-03 (Personnel activity monitored)
   - DE.AE (Adverse Event Analysis)
   - RS.MI (Incident Mitigation)

2. Detection Opportunities:
   - DLP rules for identified exfiltration vectors
   - Network volume anomaly detection thresholds
   - User behavior analytics for file access patterns
   - Cloud service usage monitoring rules

3. Improvement Actions:
   - Data classification and labeling gaps
   - Egress filtering and inspection coverage
   - DLP policy updates for identified vectors
   - Network segmentation for sensitive data stores
   - User awareness for data handling procedures
```

## Expected Data Sources

| Source | Key Fields | Priority |
|--------|-----------|----------|
| NetFlow / IPFIX | Volume, duration, src/dst pairs | Critical |
| Proxy / Web Gateway Logs | URLs, upload volume, cloud service access | Critical |
| DLP Alerts and Logs | Policy matches, data classification, action taken | Critical |
| File Server Audit Logs | File access, copy, move, delete events | High |
| Email Gateway Logs | Attachment size, external recipients, frequency | High |
| Endpoint Logs (EDR) | Process activity, file operations, USB events | High |
| DNS Logs | Query patterns, response sizes | Medium |
| Cloud Application Logs (CASB) | Upload events, sharing activity | Medium |

## Key Indicators Checklist

- [ ] Outbound data volume >2 standard deviations above host baseline
- [ ] Upload-to-download ratio inverted or significantly elevated
- [ ] Bulk file access preceding outbound transfers
- [ ] Transfers to uncategorized/unapproved cloud services
- [ ] Off-hours data movement to external destinations
- [ ] Archive creation in staging directories before transfer
- [ ] DNS queries with unusually long subdomain labels
- [ ] DLP policy violations correlated with network transfers
- [ ] New or unusual application usage (cloud sync, archive tools)
