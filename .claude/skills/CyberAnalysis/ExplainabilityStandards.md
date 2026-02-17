# Explainability Standards

Shared reference for all CASA investigation outputs. Every agent and workflow MUST follow these standards to ensure transparency, reproducibility, and alignment with NIST AI RMF principles.

## Reasoning Trace Format

Every conclusion in a CASA output must include a reasoning trace showing how it was reached. This is not optional — it is a core requirement of the system.

### Structure

```
REASONING TRACE
| Step 1: [What was observed in the data]
|   Evidence: [specific log entries, packets, or metrics]
|
| Step 2: [What pattern or anomaly was identified]
|   Basis: [why this is anomalous — baseline comparison, threshold, known indicator]
|
| Step 3: [What conclusion was drawn]
|   Logic: [deductive chain from evidence to conclusion]
|   Standards Reference: [NIST SP 800-92 §X, SP 800-61 §Y, etc.]
|
| Step 4: [What alternatives were considered]
|   Ruled Out: [other explanations and why they don't fit]
|
| Step 5: [What confidence level was assigned]
|   Justification: [see Confidence Scoring below]
```

### Rules

- Every finding must have at least Steps 1, 2, 3, and 5
- Step 4 (alternatives considered) is required for Medium and Low confidence findings
- Traces must reference specific data points, not vague summaries
- If the reasoning chain has gaps (missing data), state them explicitly

## Confidence Scoring Rubric

### High Confidence

**Criteria** — ALL of the following are met:
- Direct evidence observed in the data (specific log entries, packets, or metrics)
- Pattern matches a well-documented attack technique or known indicator
- Multiple corroborating data sources support the finding
- No plausible benign explanation fits the evidence
- Analyst has provided sufficient environmental context

**Example**: 500+ failed SSH logins from a single IP in 10 minutes, followed by a successful login, with no matching change request or admin activity — brute force with likely compromise.

### Medium Confidence

**Criteria** — SOME of the following apply:
- Evidence is present but could have multiple interpretations
- Pattern is suggestive but not definitive
- Only one data source supports the finding
- Environmental context is incomplete
- Benign explanations exist but are less likely

**Example**: DNS queries to a domain with high entropy name at regular intervals — consistent with beaconing, but could also be a legitimate CDN or monitoring service. Additional context needed.

### Low Confidence

**Criteria** — ANY of the following apply:
- Evidence is indirect or circumstantial
- Pattern is weak or based on limited data
- No corroborating sources available
- Significant gaps in environmental context
- Multiple plausible benign explanations exist
- Finding is based on heuristics rather than specific indicators

**Example**: Slightly elevated outbound traffic to a cloud storage provider during business hours — could be exfiltration, but more likely normal business usage. Requires baseline comparison and user activity correlation.

### Confidence Modifiers

Factors that adjust confidence up or down:

| Modifier | Direction | Reason |
|----------|-----------|--------|
| Multiple corroborating log sources | +1 level | Independent confirmation |
| Known threat intelligence match | +1 level | Validated indicator |
| Missing baseline data | -1 level | Cannot distinguish normal from abnormal |
| Incomplete timeframe | -1 level | May miss context |
| Single data source only | -1 level | No independent confirmation |
| Analyst confirms environmental context | +1 level | Reduces ambiguity |

## NIST Reference Citation Standards

### When to Cite

- Cite NIST standards when the guidance directly applies to the finding or recommendation
- Do not force citations — only reference standards that are genuinely relevant
- Prefer specific section references over general document citations

### Citation Format

```
[NIST SP 800-92, §4.2] — Log analysis for detecting unauthorized access attempts
[NIST SP 800-61, §3.2.4] — Signs of an incident: unauthorized access
[NIST CSF 2.0, DE.CM-01] — Networks monitored for potential cybersecurity events
[NIST AI RMF, MAP 2.3] — AI system transparency and explainability
```

### Standard Reference Quick Guide

| Standard | Use When | Key Sections |
|----------|----------|-------------|
| **SP 800-92** | Log analysis findings, logging recommendations | §3 (log management infrastructure), §4 (log analysis), §5 (log management planning) |
| **SP 800-61** | Incident indicators, handling procedures, response actions | §3.1 (preparation), §3.2 (detection & analysis), §3.3 (containment), §3.4 (post-incident) |
| **CSF 2.0** | Framework control mapping, gap analysis, maturity assessment | GV (Govern), ID (Identify), PR (Protect), DE (Detect), RS (Respond), RC (Recover) |
| **AI RMF** | Transparency of AI recommendations, bias awareness, human oversight | MAP (contextual understanding), MEASURE (risk metrics), MANAGE (risk management) |

### What NOT to Do

- Do not cite a standard without explaining its relevance
- Do not use citations as filler or to appear authoritative
- Do not cite standards you are uncertain about — state uncertainty instead
- Do not fabricate section numbers — if unsure of the exact section, cite the document generally

## Human-in-the-Loop Framing

All recommendations MUST be framed as options for analyst consideration, never as directives.

### Correct Framing

```
RECOMMENDED ACTIONS (for analyst consideration)
| 1. Consider blocking IP 10.0.0.50 at the firewall — this would stop the
|    brute force activity but may impact legitimate users if this is a shared NAT
| 2. Alternatively, implement rate limiting on SSH — less disruptive but
|    slower to take effect
| 3. For longer-term improvement, consider deploying MFA for SSH access
```

### Incorrect Framing

```
ACTIONS REQUIRED
| 1. Block IP 10.0.0.50 immediately
| 2. Reset all affected passwords
| 3. Deploy MFA
```

The difference: CASA presents options with trade-offs. The analyst decides and acts.
