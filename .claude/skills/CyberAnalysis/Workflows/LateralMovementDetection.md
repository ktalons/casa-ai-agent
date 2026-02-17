# Lateral Movement Detection Workflow

**Triggers**: Internal host-to-host connections on management protocols, credential reuse across systems, internal port scanning, remote service exploitation, pass-the-hash/ticket activity.

## MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|-----|--------|
| Remote Services (RDP, SSH, SMB, WinRM) | T1021 | Lateral Movement |
| Lateral Tool Transfer | T1570 | Lateral Movement |
| Use Alternate Authentication Material | T1550 | Defense Evasion, Lateral Movement |
| Internal Proxy | T1090.001 | Command and Control |
| Remote Service Session Hijacking | T1563 | Lateral Movement |
| Exploitation of Remote Services | T1210 | Lateral Movement |

## Agent Routing

```
Analyst Query
     |
     v
[Overseer] — classify as lateral movement investigation
     |
     +------ parallel ------+
     |                      |
     v                      v
[NetworkAnalyst]      [LogAnalyst]
  | Internal traffic     | Auth logs across hosts
  | East-west flows      | Remote service usage
  | Port scan detection  | Privilege escalation
  | Protocol analysis    | Process execution chains
     |                      |
     +----------+-----------+
                |
                v
       [PurpleTeamMapper]
         | Map to NIST CSF 2.0
         | Segmentation gaps
         | Detection improvements
                |
                v
          [Overseer] — synthesize
```

**Both agents run in parallel** because lateral movement leaves traces in both network traffic (east-west connections) and host logs (authentication, process execution).

## NetworkAnalyst Task Template

```
INVESTIGATION: Lateral Movement — Network Analysis

CONTEXT
| Query: [analyst's original question]
| Environment: [network segments, VLAN structure if known]
| Timeframe: [period of interest]
| Available Data: [internal PCAP, east-west NetFlow, switch logs]

ANALYSIS STEPS

1. INTERNAL CONNECTION MAPPING
   - Map all internal host-to-host connections in the timeframe
   - Identify connections on management/remote access protocols:
     * RDP (3389), SSH (22), WinRM (5985/5986)
     * SMB (445), WMI (135 + dynamic), PsExec patterns
     * VNC (5900+), telnet (23)
   - Compare connection graph to known/expected baselines
   - Flag new host-to-host pairs not seen in baseline period

2. PORT SCANNING DETECTION
   - Identify hosts connecting to many ports on single targets
   - Identify hosts connecting to same port across many internal targets
   - Look for sequential port access patterns
   - Check for ICMP sweep patterns (host discovery)
   - Detect service enumeration (multiple protocol probes)

3. PROTOCOL ANALYSIS
   - Verify protocol compliance on management ports
   - Check for tunneling (non-standard protocol on standard port)
   - Examine SMB traffic for file staging or tool transfer
   - Look for PsExec service installation patterns
   - Identify named pipe activity over SMB

4. TRAFFIC VOLUME AND TIMING
   - Internal transfer volume anomalies (tool staging, data collection)
   - Connections outside business hours between workstations
   - Rapid sequential connections to multiple hosts (automated movement)
   - Connection duration patterns (brief auth attempts vs persistent sessions)

5. NETWORK SEGMENTATION ASSESSMENT
   - Identify cross-segment traffic that violates expected flow
   - Flag connections from user segments to server management interfaces
   - Check for traffic between segments with no business justification

OUTPUT FORMAT: Use standard NetworkAnalyst output format.
```

## LogAnalyst Task Template

```
INVESTIGATION: Lateral Movement — Log Analysis

CONTEXT
| Query: [analyst's original question]
| Environment: [domain structure, authentication infrastructure]
| Timeframe: [period of interest]
| Available Data: [Windows event logs, Linux auth, AD logs, EDR]

ANALYSIS STEPS

1. AUTHENTICATION CHAIN ANALYSIS
   - Trace authentication events across multiple hosts
   - Build timeline: Host A login → Host B login → Host C login
   - Identify the initial compromise point (first anomalous auth)
   - Look for logon type patterns:
     * Type 3 (Network) — SMB, mapped drives
     * Type 7 (Unlock) — screen unlock after remote session
     * Type 10 (RemoteInteractive) — RDP
   - Check for Kerberos ticket anomalies (pass-the-ticket indicators)

2. CREDENTIAL REUSE DETECTION
   - Same account authenticating to multiple hosts in short timeframe
   - Service accounts used for interactive logins
   - Admin accounts used on non-admin workstations
   - NTLM authentication where Kerberos is expected (pass-the-hash indicator)
   - Look for Windows Event IDs: 4624, 4625, 4648, 4768, 4769, 4771

3. REMOTE SERVICE AND EXECUTION LOGS
   - PsExec: service installation events (Event ID 7045), pipe creation
   - WMI: process creation via WMI (Event ID 4688 with WmiPrvSE parent)
   - PowerShell remoting: WinRM connection events
   - Scheduled task creation on remote hosts (Event ID 4698)
   - SSH key-based auth to new hosts

4. PROCESS EXECUTION CHAINS
   - Identify tools commonly used in lateral movement:
     * PsExec, PAExec, RemCom
     * WMI queries and process creation
     * PowerShell with -ComputerName or Invoke-Command
     * mstsc.exe (RDP), ssh, putty
   - Look for reconnaissance tools: net.exe, nltest, dsquery, AdFind
   - Track parent-child process relationships

5. TIMELINE CONSTRUCTION
   Build a unified timeline correlating:
   - Authentication events across hosts
   - Process execution on each host
   - Network connections between hosts (from NetworkAnalyst)
   - File access and modification events

OUTPUT FORMAT: Use standard LogAnalyst output format with NIST 800-92 references.
```

## PurpleTeamMapper Task Template

```
MAPPING REQUEST: Lateral Movement Findings

FINDINGS FROM NETWORKANALYST:
[Insert NetworkAnalyst findings]

FINDINGS FROM LOGANALYST:
[Insert LogAnalyst findings]

MAP TO:
1. NIST CSF 2.0 — focus on:
   - PR.AA (Identity Management and Access Control)
   - PR.AC (Access Control) — network segmentation, least privilege
   - DE.CM-01 (Network monitoring — east-west visibility)
   - DE.CM-03 (Personnel activity monitoring)
   - DE.AE-02 (Adverse event analysis)
   - RS.AN (Incident Analysis — scope determination)

2. Detection Opportunities:
   - East-west traffic anomaly rules (new host pairs, unusual protocols)
   - Authentication chain correlation rules
   - Credential reuse detection (same account, multiple hosts, short window)
   - Remote service usage monitoring for workstation-to-workstation connections
   - Internal port scan detection thresholds

3. Improvement Actions:
   - Network segmentation enforcement and monitoring
   - Privileged access management (PAM) for admin credentials
   - Credential hygiene (tiered admin accounts, LAPS)
   - East-west network visibility gaps
   - Endpoint detection coverage for lateral movement tools
   - Microsegmentation for critical assets
```

## Expected Data Sources

| Source | Key Fields | Priority |
|--------|-----------|----------|
| Windows Security Event Logs | Event IDs 4624/4625/4648/4768/4769, logon type | Critical |
| Internal NetFlow / East-West Traffic | Src/dst IP:port, bytes, session duration | Critical |
| EDR / Endpoint Telemetry | Process chains, network connections, file events | Critical |
| Active Directory Logs | Authentication, group changes, Kerberos events | High |
| Linux auth.log / secure | SSH connections, sudo usage, su events | High |
| DNS Logs (internal) | Internal host resolution patterns | Medium |
| Switch/Router Logs | MAC table changes, VLAN traffic, ARP events | Medium |
| Firewall Logs (internal segments) | Inter-VLAN traffic, blocked connections | Medium |

## Key Indicators Checklist

- [ ] Single account authenticating to >3 hosts within 1 hour
- [ ] Network logon (Type 3) from workstation to workstation
- [ ] RDP connection (Type 10) between hosts that have no prior RDP history
- [ ] Service accounts used for interactive or remote interactive logons
- [ ] NTLM authentication where Kerberos is the norm (pass-the-hash)
- [ ] New service installations (Event 7045) on multiple hosts
- [ ] Internal host connecting to >10 other hosts on port 445 in short period
- [ ] PowerShell remoting or WMI from non-admin workstation
- [ ] Reconnaissance tool execution (net.exe, nltest, AdFind)
- [ ] Cross-segment traffic violating expected network flow
