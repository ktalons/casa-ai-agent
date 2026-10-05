# CASA — Cybersecurity Analysis Support Agent

AI-assisted SOC analysis for SME/MSP environments, packaged as a Claude Code plugin. CASA
guides log, network and endpoint investigations with explainable, NIST-aligned reasoning and
keeps the analyst in the loop. It does not act on its own.

## Status

| Capability | State |
|---|---|
| Plugin: eight specialist agents, `/casa:investigate` loop, standards preloaded into every agent | 🟡 v5 rebuild in progress (Phase 1 of 6) |
| `soc-intake/v1` contract + fixtures + offline validator | ✅ Working |
| Fabrication lint and fixture grader (`evals/`) | 🔴 Phase 2–4 |
| Live TalonSocLab telemetry feed | 🔴 Gated on the lab pipeline and a graded run |

Personal project. v4 (the PAI-derived tree) is preserved at tag `v4.0.0-pai-legacy`.

## Two planes

[TalonSocLab](https://github.com/ktalons/talonsoclab) is the deterministic **data plane**: it
collects, filters and cites SOC telemetry, then emits a structured intake artifact. CASA is the
separate **reasoning plane** that consumes that artifact and produces explainable,
human-in-the-loop analysis. The contract between them is a JSON schema
(`talonsoclab.soc-intake/v1`), not a shared API — see [`intake/`](intake/README.md).

## Install

Prerequisites: [Claude Code](https://docs.anthropic.com/en/docs/claude-code) and [Bun](https://bun.sh).

As a plugin, in any project:

```
/plugin marketplace add ktalons/casa-ai-agent
/plugin install casa@casa
```

From this checkout, for development:

```bash
git clone https://github.com/ktalons/casa-ai-agent && cd casa-ai-agent
bun install
bun run dev          # claude --plugin-dir .
```

Then:

```
/casa:investigate intake/fixtures/brute-force-dc-chain.intake.json
```

Permissions do not travel with a plugin. The repo's `.claude/settings.json` is the recommended
allowlist (read-only analysis commands, destructive commands denied, secrets unreadable);
copy it into projects where you install CASA.

## How it works

`/casa:investigate` runs one loop on the main thread: **OBSERVE** (validate the intake, count,
flag injected text) → **HYPOTHESIZE** (thread detections into chains) → **INVESTIGATE** (fan
out to specialists in parallel) → **VERIFY** (every citation must trace to the intake) →
**MAP** (CSF 2.0 / ATT&CK) → **BRIEF** (one analyst brief under `briefs/`) → **LEARN**
(candidates the analyst approves or discards). An empty intake short-circuits to a liveness
check; it never invents findings.

| Agent | Lane |
|---|---|
| log-analyst | alert chains and timelines across hosts |
| network-analyst | flows, DNS, TLS, ports, beaconing, recon-delta exposure |
| endpoint-analyst | single-host behaviour, event IDs, process ancestry, data requests |
| purple-team-mapper | NIST CSF 2.0 and ATT&CK mapping, visibility gaps |
| detection-engineer | Sigma + Wazuh rule drafts for supported findings |
| threat-intel | technique and indicator context, offline first |
| evaluator | grades a brief against fixture ground truth |
| pentester | authorized-assessment pointers; refuses without an engagement scope |

Every specialist returns one `casa.finding/v1` record: verdict, confidence with what would
raise it, evidence references, alternatives, data requests, options with trade-offs, and a
reasoning trace. The rules live in [`skills/standards/SKILL.md`](skills/standards/SKILL.md).

## Development

```bash
bun run typecheck && bun test && bun run validate:fixtures && bun run validate:plugin
```

Layout: `agents/` · `skills/` · `intake/` (contract, fixtures, validator) · `evals/`
(lint, grader, tests) · `briefs/` (run output, gitignored). Developer notes are in
[`.claude/CLAUDE.md`](.claude/CLAUDE.md).

## License

MIT — see [LICENSE](LICENSE). The v4 tree was derived from
[Daniel Miessler's PAI](https://github.com/danielmiessler/Personal_AI_Infrastructure) (also MIT).
