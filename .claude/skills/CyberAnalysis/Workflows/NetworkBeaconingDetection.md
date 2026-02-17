# Network Beaconing Detection Workflow

**Triggers**: Periodic outbound connections, regular-interval DNS queries, encrypted traffic to unknown/suspicious IPs, heartbeat-like traffic patterns, callback behavior.

## MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|-----|--------|
| Application Layer Protocol | T1071 | Command and Control |
| Encrypted Channel | T1573 | Command and Control |
| Non-Standard Port | T1571 | Command and Control |
| DNS (C2 over DNS) | T1071.004 | Command and Control |
| Protocol Tunneling | T1572 | Command and Control |
| Ingress Tool Transfer | T1105 | Command and Control |

## Agent Routing

```
Analyst Query
     |
     v
[Overseer] — classify as beaconing investigation
     |
     v
[NetworkAnalyst] — primary analysis
     | Analyze traffic for periodicity
     | Examine DNS patterns
     | Inspect connection metadata
     | Identify suspicious destinations
     |
     v
[PurpleTeamMapper] — improvement mapping
     | Map to NIST CSF 2.0
     | Identify network monitoring gaps
     | Recommend detection rules
     |
     v
[Overseer] — synthesize and present
```

**Note**: If the analyst also has endpoint logs (process → network correlation), route to LogAnalyst in parallel to correlate process activity with network connections.

## NetworkAnalyst Task Template

```
INVESTIGATION: Network Beaconing Detection

CONTEXT
| Query: [analyst's original question]
| Environment: [network architecture if known]
| Timeframe: [capture/flow period]
| Available Data: [PCAP, NetFlow, DNS logs, proxy logs]

ANALYSIS STEPS

1. CONNECTION INVENTORY
   - Enumerate all outbound connections in the dataset
   - Group by source host → destination IP:port pairs
   - Calculate connection frequency and duration for each pair
   - Identify long-running or persistent connections

2. PERIODICITY ANALYSIS
   For each connection pair, calculate:
   - Inter-arrival time (time between consecutive connections)
   - Jitter (standard deviation of inter-arrival times)
   - Beaconing score: low jitter + regular interval = high score
   - Thresholds: jitter < 15% of interval suggests beaconing
   - Account for common legitimate periodic traffic (NTP, updates, monitoring)

3. DNS ANALYSIS
   Examine DNS query patterns for:
   - High-entropy domain names (DGA indicators)
   - Regular-interval queries to same domain
   - TXT record queries (potential DNS tunneling)
   - Unusual query lengths (data encoded in subdomain)
   - Queries to recently registered domains
   - NXDOMAIN response clustering

4. TRAFFIC CHARACTERISTICS
   For suspicious connections, examine:
   - Payload sizes: small + consistent = C2 heartbeat; large = data transfer
   - Protocol compliance: is HTTP actually HTTP? Is DNS well-formed?
   - TLS certificate details: self-signed, unusual issuer, mismatched CN
   - User-Agent strings: unusual, missing, or known malware signatures
   - Request/response ratio: C2 often has asymmetric patterns

5. DESTINATION ANALYSIS
   For flagged destinations:
   - Geolocation and ASN
   - Domain registration age and registrar
   - Reverse DNS and WHOIS
   - Known threat intelligence matches
   - Hosting provider (bulletproof hosting indicators)

6. EVIDENCE DOCUMENTATION
   For each finding:
   - Specific packets or flow records with timestamps
   - Statistical analysis (interval, jitter, volume)
   - Visualization data (timeline of connections)
   - Comparison to baseline traffic patterns

OUTPUT FORMAT: Use standard NetworkAnalyst output format.
```

## PurpleTeamMapper Task Template

```
MAPPING REQUEST: Beaconing Detection Findings

FINDINGS FROM NETWORKANALYST:
[Insert NetworkAnalyst findings here]

MAP TO:
1. NIST CSF 2.0 — focus on:
   - DE.CM-01 (Networks monitored for cybersecurity events)
   - DE.CM-06 (External service provider activity monitored)
   - DE.AE-02 (Potentially adverse events analyzed for impact)
   - RS.AN-01 (Investigation notifications from detection sources)

2. Detection Opportunities:
   - Network-based beaconing detection rules (interval + jitter thresholds)
   - DNS anomaly monitoring (entropy, query frequency, record types)
   - TLS inspection policy for suspicious destinations
   - Proxy/firewall log correlation rules

3. Improvement Actions:
   - Network visibility gaps (encrypted traffic, east-west visibility)
   - DNS monitoring coverage
   - Threat intelligence feed integration
   - Network segmentation recommendations
```

## Expected Data Sources

| Source | Key Fields | Priority |
|--------|-----------|----------|
| PCAP / Full Packet Capture | All packet data, timing, payloads | Critical |
| NetFlow / IPFIX | Src/dst IP:port, bytes, packets, timestamps | Critical |
| DNS Query Logs | Query name, type, response, source IP | Critical |
| Proxy / Web Gateway Logs | URL, user-agent, response code, bytes | High |
| Firewall Connection Logs | Src/dst, action, bytes, session duration | High |
| TLS/SSL Inspection Logs | Certificate details, SNI, cipher suite | Medium |
| Threat Intelligence Feeds | IP/domain reputation, known C2 infrastructure | Medium |

## Key Indicators Checklist

- [ ] Outbound connections with inter-arrival jitter < 15% of mean interval
- [ ] Connections at regular intervals (30s, 60s, 300s, 600s, 3600s common)
- [ ] DNS queries to high-entropy domains or recently registered domains
- [ ] TXT/NULL DNS record queries at regular intervals
- [ ] Small, consistent payload sizes on periodic connections
- [ ] HTTPS to IP addresses (no domain name) or self-signed certificates
- [ ] Connections to known bulletproof hosting or suspicious ASNs
- [ ] Protocol non-compliance (HTTP headers missing, DNS malformed)
