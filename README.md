# CASA — Cybersecurity Analysis Support Agent

AI-assisted SOC analysis for SME/MSP environments. CASA guides log and network investigations with explainable, NIST-aligned reasoning and keeps the analyst in the loop — it does not act on its own.

## Status

| Capability | State |
|---|---|
| Five specialist agents + four investigation workflows | ✅ Working |
| `soc-intake/v1` contract + fixtures + offline validator | ✅ Working |
| Intake-triage workflow (fixtures → reasoning → graded) | ✅ Working |
| Live TalonSocLab telemetry feed | 🔴 Gated — needs the lab pipeline deployed and workflows validated against real log volume |

Personal project, separate from my group senior capstone. Actively iterating.

## Two planes

CASA is one half of a two-plane design. [TalonSocLab](https://github.com/ktalons/talonsoclab) is the deterministic **data plane** — it collects, filters, and cites SOC telemetry, then emits a structured intake artifact. It does not reason or decide. CASA is the separate **reasoning plane** that consumes that artifact and produces explainable, human-in-the-loop analysis. The contract between them is a JSON schema (`talonsoclab.soc-intake/v1`), not a shared API — see [`intake/`](intake/README.md). The two repos stay decoupled until CASA is validated against representative log volume.

## Quick start

Prerequisites: [Claude Code](https://docs.anthropic.com/en/docs/claude-code) and [Bun](https://bun.sh).

```bash
git clone https://github.com/ktalons/casa-ai-agent
cd casa-ai-agent
bash setup.sh --validate   # optional: check structure, change nothing
bash setup.sh              # symlink ~/.claude, generate local config
claude
```

`setup.sh` symlinks `~/.claude` → `<repo>/.claude/`, so updates are just `git pull`. An existing `~/.claude` is backed up first, never deleted. Local config (`settings.json`, `.env`) stays gitignored.

Try:

```
Analyze these auth logs for brute force indicators
Triage this intake: intake/fixtures/brute-force-dc-chain.intake.json
```

## Agents

| Agent | Role | Standards |
|---|---|---|
| Overseer | Routes queries to specialists | NIST AI RMF |
| LogAnalyst | Log investigation, step by step | NIST SP 800-92 |
| NetworkAnalyst | PCAP and network flow analysis | Network security best practice |
| PurpleTeamMapper | Maps findings to detections/response | NIST CSF 2.0, MITRE ATT&CK |
| Pentester | Authorized vulnerability assessment | OWASP, PTES |

## Workflows

| Workflow | Triggers |
|---|---|
| Auth Anomaly | Brute force, credential stuffing, impossible travel |
| Network Beaconing | Periodic connections, DNS anomalies, C2 callbacks |
| Data Exfiltration | Large outbound transfers, encoded traffic |
| Lateral Movement | Internal scanning, credential reuse, RDP/SMB abuse |
| Intake Triage | A `soc-intake/v1` artifact — classifies and routes to the above |

Every recommendation carries a reasoning trace, a confidence level with justification, citations to the evidence used, and options rather than directives.

## Why

I'm building the reasoning layer I want in a SOC: one that shows its work. CASA is a personal project that grew out of my senior capstone research. It's where I study when agentic AI actually helps a defender and when it fails. It's deliberately human-in-the-loop — the analyst decides, the agent explains.

## Follow along

- Site: <https://ktalons.github.io/>
- Data plane: <https://github.com/ktalons/talonsoclab>
- LinkedIn: <https://www.linkedin.com/in/ktalons/>

## License

MIT — see [LICENSE](LICENSE). Derived from [Daniel Miessler's PAI](https://github.com/danielmiessler/Personal_AI_Infrastructure) (also MIT).
