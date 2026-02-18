# CASA — Cybersecurity Analysis Support Agent

AI-assisted cybersecurity analysis agent for SME/MSP security operations. Guides investigative workflows with explainable reasoning aligned to NIST standards.

## Overview

Security analysts in small-to-medium enterprise (SME) and managed service provider (MSP) environments face constant challenges analyzing large volumes of logs and network telemetry. CASA is an AI-assisted agent that supports analysis tasks while maintaining human-in-the-loop decision-making.

Rather than fully autonomous threat detection, CASA guides investigative workflows, suggests appropriate tools and steps, and explains its reasoning aligned with established cybersecurity standards.

## Quick Start

### Prerequisites

Install these before running `setup.sh`:

| Tool | Required | Notes |
|------|----------|-------|
| **Claude Code** | Yes | [Install guide](https://docs.anthropic.com/en/docs/claude-code) — Anthropic's CLI |
| **Python 3** | Yes | Pre-installed on macOS and most Linux |
| **Bun** | Auto | `setup.sh` installs Bun automatically if missing |
| **ElevenLabs API key** | Optional | Required only for voice synthesis — [elevenlabs.io](https://elevenlabs.io) |

### 1. Clone

```bash
gh repo clone CASA-Capstone-AI-Research-Project/CASA
cd CASA
```

### 2. Validate (Recommended)

Verify the repo is complete before installing:

```bash
bash setup.sh --validate
```

This runs all structural checks — agents, skills, hooks, workflows — without making any changes. All checks should show `✓` before proceeding.

### 3. Install

```bash
bash setup.sh
```

The setup script will:
1. Check prerequisites (Claude Code, Python 3, Bun)
2. Create a symlink: `~/.claude` → `<repo>/.claude/`
3. Back up any existing `~/.claude/` if present
4. Collect your name, timezone, AI assistant name, and voice preference
5. Generate `settings.json` and a documented `.env` template
6. Start the voice server automatically if an ElevenLabs key is provided
7. Validate all CASA agents, skills, hooks, and workflows

### 4. Configure (Optional)

After install, open `.claude/.env` to configure optional features:

```bash
# .claude/.env — gitignored, stays local

# Voice synthesis (get a free key at elevenlabs.io)
ELEVENLABS_API_KEY=your_key_here

# Timezone for log timestamps (IANA format — defaults to America/Los_Angeles)
TIME_ZONE=America/New_York

# Voice ID override (optional — overrides voice selected during setup)
# Rachel (female): 21m00Tcm4TlvDq8ikWAM  |  Adam (male): pNInz6obpgDQGcFmaJgB
PAI_VOICE_ID=
```

### 5. Launch

```bash
claude
```

Try a query to get started:

```
Analyze these auth logs for brute force indicators
Investigate this PCAP for C2 beaconing activity
Search OSINT for this IP address: 192.168.1.100
Run a prompt injection assessment on this chatbot endpoint
```

### Update

Because `~/.claude` is a symlink to the repo, updating is just:

```bash
cd CASA
git pull
```

All changes are live immediately — no re-install needed.

## How the Install Works

```
~/.claude  ──symlink──▶  CASA/.claude/
                              │
                              ├── settings.json      ← your config (gitignored)
                              ├── .env               ← API keys (gitignored)
                              ├── agents/            ← tracked in git
                              ├── skills/            ← tracked in git
                              ├── hooks/             ← tracked in git
                              └── MEMORY/            ← contents gitignored
```

- **Tracked files** (agents, skills, hooks, workflows) update with `git pull`
- **User files** (`settings.json`, `.env`, MEMORY contents) are gitignored and stay local
- Re-running `setup.sh` is safe — it detects existing symlinks and skips if already configured

## Architecture

Built on [Daniel Miessler's Personal AI Infrastructure (PAI)](https://github.com/danielmiessler/Personal_AI_Infrastructure) framework.

### Agents

| Agent | Role | Standards |
|-------|------|-----------|
| **Overseer** | Routes analyst queries to specialized agents | NIST AI RMF |
| **LogAnalyst** | Guides log investigation with step-by-step reasoning | NIST SP 800-92 |
| **NetworkAnalyst** | Assists with PCAP and network flow analysis | Network security best practices |
| **PurpleTeamMapper** | Maps findings to detection/response improvements | NIST CSF 2.0, MITRE ATT&CK |
| **Pentester** | Authorized vulnerability assessment and security testing | OWASP, PTES |

### Investigation Workflows

| Workflow | Triggers | Agents Used |
|----------|----------|-------------|
| Auth Anomaly | Brute force, credential stuffing, impossible travel | LogAnalyst → PurpleTeamMapper |
| Network Beaconing | Periodic connections, DNS anomalies, C2 callbacks | NetworkAnalyst → PurpleTeamMapper |
| Data Exfiltration | Large outbound transfers, encoding in traffic | LogAnalyst + NetworkAnalyst → PurpleTeamMapper |
| Lateral Movement | Internal scanning, credential reuse, RDP/SMB abuse | LogAnalyst + NetworkAnalyst → PurpleTeamMapper |

### Workflow Stages

```
Analyst Query → Intake → Analysis → Mapping → Synthesis → Analyst Guidance
                  ↓         ↓          ↓          ↓
              Classify   Route to   Map to      Combine
              query &    specialist NIST CSF &   findings,
              gather     agents     MITRE        explain
              context               ATT&CK       reasoning
```

## Standards Alignment

| Standard | Application |
|----------|------------|
| **NIST SP 800-92** | Log management guidance for log analysis workflows |
| **NIST SP 800-61** | Incident handling procedures across all workflows |
| **NIST CSF 2.0** | Framework function mapping (Govern, Identify, Protect, Detect, Respond, Recover) |
| **NIST AI RMF** | Transparency and explainability in AI recommendations |
| **MITRE ATT&CK** | Technique and tactic mapping for threat context |

## Explainability

Every CASA recommendation includes:
- **Reasoning trace** — step-by-step explanation of how conclusions were reached
- **Confidence scoring** — High/Medium/Low with specific justification criteria
- **NIST references** — citations to relevant standard sections
- **Human-in-the-loop framing** — options with trade-offs, never directives

## Project Structure

```
CASA/
├── setup.sh                          ← Run this after cloning
├── README.md
├── LICENSE
└── .claude/                          ← Symlinked to ~/.claude
    ├── settings.template.json        ← Default config (tracked)
    ├── settings.json                 ← Your config (gitignored)
    ├── .env                          ← API keys + timezone (gitignored)
    ├── CLAUDE.md                     ← Entry point for Claude
    ├── INSTALL.ts                    ← PAI personalization wizard
    ├── agents/
    │   ├── Overseer.md               ← Query routing orchestrator
    │   ├── LogAnalyst.md             ← NIST SP 800-92 log analysis
    │   ├── NetworkAnalyst.md         ← PCAP/flow analysis
    │   ├── PurpleTeamMapper.md       ← NIST CSF 2.0 mapping
    │   └── Pentester.md              ← Authorized vulnerability assessment
    ├── skills/
    │   ├── CyberAnalysis/
    │   │   ├── SKILL.md              ← Core investigation skill
    │   │   ├── ExplainabilityStandards.md
    │   │   └── Workflows/
    │   │       ├── AuthAnomalyInvestigation.md
    │   │       ├── NetworkBeaconingDetection.md
    │   │       ├── DataExfiltrationAnalysis.md
    │   │       └── LateralMovementDetection.md
    │   ├── PromptInjection/          ← AI/LLM security assessment
    │   ├── Recon/                    ← Reconnaissance workflows
    │   ├── WebAssessment/            ← Web application security
    │   ├── OSINT/                    ← Open source intelligence
    │   ├── SECUpdates/               ← Security news aggregation
    │   ├── AnnualReports/            ← Threat report analysis
    │   └── PAI/                      ← PAI framework core
    ├── hooks/                        ← Lifecycle event handlers (10 active)
    ├── VoiceServer/                  ← ElevenLabs TTS server
    └── MEMORY/                       ← Learning and pattern storage (gitignored)
```

## Reconfiguring

To re-run personalization:
```bash
rm CASA/.claude/settings.json
bash setup.sh
```

To uninstall (removes only the symlink, repo stays intact):
```bash
rm ~/.claude
```

## Tech Stack

- **Claude** — LLM backbone (via Claude Code CLI)
- **TypeScript / Bun** — PAI framework runtime
- **Python** — Analysis scripting

## Status

Senior Capstone Project — In Development

## License

MIT
