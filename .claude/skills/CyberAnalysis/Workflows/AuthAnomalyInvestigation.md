# Authentication Anomaly Investigation Workflow

**Triggers**: Brute force indicators, credential stuffing, impossible travel, unusual login times/locations, privilege escalation, account lockout storms.

## MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|-----|--------|
| Brute Force | T1110 | Credential Access |
| Valid Accounts | T1078 | Defense Evasion, Persistence, Privilege Escalation, Initial Access |
| Account Manipulation | T1098 | Persistence, Privilege Escalation |

## Agent Routing

```
Analyst Query
     |
     v
[Overseer] — classify as auth anomaly
     |
     v
[LogAnalyst] — primary analysis
     | Analyze authentication logs
     | Establish login baselines
     | Identify anomalous patterns
     | Correlate across log sources
     |
     v
[PurpleTeamMapper] — improvement mapping
     | Map findings to NIST CSF 2.0
     | Identify detection gaps
     | Recommend monitoring improvements
     |
     v
[Overseer] — synthesize and present
```

**Note**: If the analyst mentions network-level indicators (e.g., source IPs from unusual geolocations, VPN/proxy detection), also route to NetworkAnalyst in parallel with LogAnalyst.

## LogAnalyst Task Template

```
INVESTIGATION: Authentication Anomaly Analysis

CONTEXT
| Query: [analyst's original question]
| Environment: [systems, OS, auth provider if known]
| Timeframe: [period of interest]
| Available Data: [log sources provided]

ANALYSIS STEPS (follow NIST SP 800-92 methodology)

1. BASELINE ESTABLISHMENT
   - What are normal login patterns for this environment?
   - Typical login times, source IPs, user agents
   - Expected failure rates
   - Account lockout thresholds

2. ANOMALY IDENTIFICATION
   Examine logs for:
   - Failed login volume: count by source IP, target account, time window
   - Failed-then-success patterns: brute force followed by successful auth
   - Geographic anomalies: logins from unusual locations or impossible travel
   - Temporal anomalies: logins outside normal business hours
   - Account lockout clusters: multiple accounts locked simultaneously
   - Privilege changes: role assignments, group membership changes after auth
   - Service account anomalies: interactive logins on service accounts

3. PATTERN CLASSIFICATION
   Classify observed patterns:
   - Password spraying: few attempts per account, many accounts
   - Brute force: many attempts against single account
   - Credential stuffing: varied credentials, often from distributed sources
   - Lateral credential reuse: same credentials across multiple systems
   - Privilege escalation chain: auth → priv change → resource access

4. CORRELATION
   Cross-reference with:
   - Source IP reputation and geolocation
   - Prior successful logins from same accounts
   - System logs for post-auth activity
   - Network logs if lateral movement suspected

5. EVIDENCE DOCUMENTATION
   For each finding, provide:
   - Specific log entries (timestamps, event IDs, accounts, source IPs)
   - Statistical summary (counts, rates, timeframes)
   - Baseline comparison
   - NIST SP 800-92 reference

OUTPUT FORMAT: Use standard LogAnalyst output format with NIST 800-92 references.
```

## PurpleTeamMapper Task Template

```
MAPPING REQUEST: Authentication Anomaly Findings

FINDINGS FROM LOGANALYST:
[Insert LogAnalyst findings here]

MAP TO:
1. NIST CSF 2.0 — focus on:
   - PR.AA (Identity Management, Authentication, and Access Control)
   - DE.CM (Continuous Monitoring)
   - DE.AE (Adverse Event Analysis)
   - RS.AN (Incident Analysis)

2. Detection Opportunities:
   - SIEM correlation rules for identified patterns
   - Alert thresholds based on baseline data
   - Log source gaps that limited analysis

3. Improvement Actions:
   - Authentication hardening (MFA, lockout policies)
   - Monitoring coverage for auth events
   - Response playbook updates for credential attacks
```

## Expected Data Sources

| Source | Key Fields | Priority |
|--------|-----------|----------|
| Windows Security Event Log | Event IDs 4624, 4625, 4648, 4672, 4768, 4771 | Critical |
| Linux auth.log / secure | sshd, PAM messages, sudo events | Critical |
| Azure AD / Entra ID Sign-in Logs | Sign-in status, location, device, risk level | Critical |
| VPN/Remote Access Logs | Source IP, auth result, session duration | High |
| MFA Provider Logs | Challenge results, bypass events | High |
| Active Directory Changes | Group membership, password resets, account enables | Medium |
| Web Application Auth Logs | Login attempts, session tokens, API auth | Medium |

## Key Indicators Checklist

- [ ] Failed login count exceeds baseline by >3x in analysis window
- [ ] Failed-then-success pattern from same source
- [ ] Logins from >2 geographic regions within impossible travel time
- [ ] Logins outside established business hours for the account
- [ ] Multiple account lockouts within a short timeframe
- [ ] Privilege changes within 30 minutes of successful auth
- [ ] Service account used for interactive login
- [ ] Password reset followed by immediate login from new source
