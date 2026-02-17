# CASA — Cybersecurity Analysis Support Agent

AI-assisted cybersecurity analysis agent for SME/MSP security operations. Guides investigative workflows with explainable reasoning aligned to NIST standards.

## Overview

Security analysts in small-to-medium enterprise (SME) and managed service provider (MSP) environments face constant challenges analyzing large volumes of logs and network telemetry. CASA is an AI-assisted agent that supports analysis tasks while maintaining human-in-the-loop decision-making.

Rather than fully autonomous threat detection, CASA guides investigative workflows, suggests appropriate tools and steps, and explains its reasoning aligned with established cybersecurity standards.

## Quick Start

### Prerequisites

- **Claude Code** — Anthropic's CLI ([install guide](https://docs.anthropic.com/en/docs/claude-code))
  ```bash
  npm install -g @anthropic-ai/claude-code
  ```
- **Bun** — TypeScript runtime (setup.sh will install this if missing)
- **Python 3** — Used by setup.sh for JSON configuration (pre-installed on macOS/most Linux)

### Install

```bash
git clone https://github.com/<your-username>/CASA.git
cd CASA
bash setup.sh
```

The setup script will:
1. Verify prerequisites (Claude Code, Bun, Python 3)
2. Create a symlink: `~/.claude` → `<repo>/.claude/`
3. Back up any existing `~/.claude/` if present
4. Generate `settings.json` with your name, timezone, and preferences
5. Validate all CASA agents, skills, and workflows

### Launch

```bash
claude
```

Then try a query:
> "Analyze these authentication logs for brute force indicators"

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
    ├── .env                          ← API keys (gitignored)
    ├── CLAUDE.md                     ← Entry point for Claude
    ├── INSTALL.ts                    ← PAI personalization wizard
    ├── agents/
    │   ├── Overseer.md               ← Query routing orchestrator
    │   ├── LogAnalyst.md             ← NIST SP 800-92 log analysis
    │   ├── NetworkAnalyst.md         ← PCAP/flow analysis
    │   └── PurpleTeamMapper.md       ← NIST CSF 2.0 mapping
    ├── skills/
    │   ├── CyberAnalysis/
    │   │   ├── SKILL.md              ← Core investigation skill
    │   │   ├── ExplainabilityStandards.md
    │   │   └── Workflows/
    │   │       ├── AuthAnomalyInvestigation.md
    │   │       ├── NetworkBeaconingDetection.md
    │   │       ├── DataExfiltrationAnalysis.md
    │   │       └── LateralMovementDetection.md
    │   └── PAI/                      ← PAI framework skills
    ├── hooks/                        ← Lifecycle event handlers
    └── MEMORY/                       ← Learning and pattern storage (gitignored contents)
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
