---
name: CyberAnalysis
description: Core investigation workflow for the Cybersecurity Analysis Support Agent (CASA). Routes analyst queries through specialized agents using structured investigation stages aligned with NIST standards.
---

# CyberAnalysis - Investigation Workflow Skill

**Auto-routes when analyst submits cybersecurity investigation queries, log analysis requests, network traffic questions, or detection improvement requests.**

## Overview

CyberAnalysis is the orchestration skill that drives CASA investigations. It classifies analyst queries, routes to specialized agents, and ensures every response includes explainable reasoning with NIST standards alignment.

## Query Classification

### Step 1: Classify the Query Domain

| Domain | Indicators | Primary Agent | Supporting Agent |
|--------|-----------|---------------|------------------|
| **Log Analysis** | Authentication events, system logs, audit trails, SIEM alerts, event IDs | LogAnalyst | PurpleTeamMapper |
| **Network Analysis** | PCAP files, flow data, traffic patterns, connections, DNS queries | NetworkAnalyst | PurpleTeamMapper |
| **Improvement** | Detection rules, response playbooks, logging gaps, coverage | PurpleTeamMapper | LogAnalyst or NetworkAnalyst |
| **Mixed** | Spans log + network, or complex incident investigation | LogAnalyst + NetworkAnalyst (parallel) | PurpleTeamMapper |

### Step 2: Classify Investigation Type

Match the query to a known investigation workflow when possible:

| Investigation Type | Workflow | Key Indicators |
|-------------------|----------|----------------|
| Authentication anomaly | `Workflows/AuthAnomalyInvestigation.md` | Failed logins, credential stuffing, unusual auth patterns |
| C2 beaconing | `Workflows/NetworkBeaconingDetection.md` | Periodic connections, DNS anomalies, encrypted traffic to unknown IPs |
| Data exfiltration | `Workflows/DataExfiltrationAnalysis.md` | Large outbound transfers, unusual data ratios, encoding in traffic |
| Lateral movement | `Workflows/LateralMovementDetection.md` | Internal scanning, remote service abuse, credential reuse across hosts |
| General / unmatched | Use agent routing directly | Does not match a specific template |

## Agent Routing Rules

### Single-Agent Queries
When the query maps to one domain:

1. Route to the primary agent with full context
2. Receive findings
3. Route findings to PurpleTeamMapper for improvement mapping
4. Synthesize into final guidance

### Multi-Agent Queries
When the query spans domains:

1. Route to LogAnalyst and NetworkAnalyst **in parallel**
2. Collect findings from both
3. Route combined findings to PurpleTeamMapper
4. Synthesize cross-domain analysis into final guidance

### Routing Context Template

When spawning an agent, always provide:

```
INVESTIGATION CONTEXT
| Query: [original analyst question]
| Domain: [log/network/improvement/mixed]
| Investigation Type: [matched workflow or "general"]
| Environment: [systems/network context if known]
| Timeframe: [period of interest]
| Available Data: [what data the analyst has provided or referenced]
| Priority Focus: [what the analyst most needs answered]
```

## Workflow Stages

Every investigation follows four stages:

### Stage 1: Intake
- Classify query domain and investigation type
- Identify available data and context gaps
- Ask clarifying questions if critical context is missing
- Select investigation workflow (or use general routing)

### Stage 2: Analysis
- Route to specialized agent(s) with context template
- Agents perform domain-specific analysis
- Agents return structured findings with explainability

### Stage 3: Mapping
- Route findings to PurpleTeamMapper
- Map to NIST CSF 2.0 functions and MITRE ATT&CK techniques
- Identify detection gaps and improvement opportunities
- Prioritize recommended actions

### Stage 4: Synthesis
- Combine all agent findings into coherent guidance
- Apply explainability standards (see `ExplainabilityStandards.md`)
- Present options (not commands) for analyst consideration
- Suggest next investigation steps if applicable

## Output Format

All CASA investigation outputs use this structure:

```
INVESTIGATION SUMMARY
| Query: [original question]
| Domain: [classification]
| Workflow: [template used, if any]
| Agents Consulted: [list]

KEY FINDINGS
| [Numbered findings with evidence]

NIST CSF 2.0 MAPPING
| Function: [GV/ID/PR/DE/RS/RC]
| Category: [specific category]
| Relevant Controls: [subcategories]

MITRE ATT&CK MAPPING (where applicable)
| Technique: [Txxxx - Name]
| Tactic: [tactic phase]

CONFIDENCE ASSESSMENT
| Overall: [High/Medium/Low]
| Reasoning: [why this confidence level]
| Gaps: [what additional data would increase confidence]

RECOMMENDED ACTIONS
| 1. [Prioritized action for analyst consideration]
| 2. [Alternative or follow-up action]
| 3. [Longer-term improvement]

REASONING TRACE
| [Step-by-step explanation of how conclusions were reached]
| [References to NIST SP 800-92, SP 800-61, CSF 2.0 as applicable]
```

## Explainability Requirements

All outputs MUST follow the standards defined in `ExplainabilityStandards.md`:
- Reasoning trace for every conclusion
- Confidence scoring with justification
- NIST standard references where applicable
- Human-in-the-loop framing (options, not commands)

## Standards Alignment

| Standard | Application |
|----------|------------|
| NIST SP 800-92 | Log management guidance for LogAnalyst workflows |
| NIST SP 800-61 | Incident handling procedures across all workflows |
| NIST CSF 2.0 | Framework mapping via PurpleTeamMapper |
| NIST AI RMF | Transparency and explainability in AI recommendations |
| MITRE ATT&CK | Technique/tactic mapping for threat context |

## Available Workflows

- **AuthAnomalyInvestigation** — Authentication anomaly and credential attack investigation → `Workflows/AuthAnomalyInvestigation.md`
- **NetworkBeaconingDetection** — C2 beaconing and callback detection → `Workflows/NetworkBeaconingDetection.md`
- **DataExfiltrationAnalysis** — Data exfiltration pattern analysis → `Workflows/DataExfiltrationAnalysis.md`
- **LateralMovementDetection** — Lateral movement and internal spread detection → `Workflows/LateralMovementDetection.md`

## Human-in-the-Loop Principles

- Never make autonomous security decisions
- Present options with trade-offs, not directives
- Ask clarifying questions when context is insufficient
- Defer to analyst judgment on all final actions
- Flag uncertainty explicitly rather than guessing
