# CASA — Cybersecurity Analysis Support Agent

AI-assisted SOC analysis for SME/MSP environments, packaged as a Claude Code plugin. CASA
guides log, network and endpoint investigations with explainable, NIST-aligned reasoning and
keeps the analyst in the loop. It does not act on its own.

## Status

| Capability | State |
|---|---|
| Plugin: eight specialist agents, `/casa:investigate`, `/casa:evaluate`, `/casa:learn`, standards preloaded into every agent, write guard | ✅ Working |
| `soc-intake/v1` and `v2` contracts, schema-driven and semantic validator, six fixtures plus ten invalid ones | ✅ Working |
| Fabrication lint (`evals/Lint.ts`), verified NIST and ATT&CK reference tables | ✅ Working |
| Fixture grader (`evals/Grade.ts`), machine-checkable ground truth, `/casa:evaluate` with the evaluator agent | ✅ Working: every real brief grades 9/9 |
| Live TalonSocLab telemetry feed | 🔴 Gated: the lab's digest must emit v2, then a graded run on real volume |

Personal project. v5.0.0 is the first release on the plugin layout. v4 (the PAI-derived
tree) is preserved at tag `v4.0.0-pai-legacy`.

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
(a candidate note under `learn/pending/`, promoted only through `/casa:learn` with the
analyst's approval). An empty intake short-circuits to a liveness check; with a v2 intake it
names the failing pipeline check. It never invents findings.

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

## Running CASA elsewhere

Install from the marketplace into the project where the telemetry lives (a TalonSocLab
checkout, or an empty working directory), merge `docs/settings.recommended.json` into that
project's `.claude/settings.json`, and run `/casa:investigate <path to intake.json>`. Briefs,
proposed detections, grades and learn candidates are written under that project, never into
the plugin. The write guard that limits what agents may write travels with the plugin; the
Bash allowlist does not, which is why the settings snippet exists.

## Development

```bash
bun run typecheck && bun test && bun run validate:fixtures && bun run validate:plugin
```

To run the fixtures end to end from this checkout, install it in place once with
`bun run plugin:link` (local scope, gitignored), then:

```bash
claude -p "/casa:investigate intake/fixtures/brute-force-dc-chain.intake.json" --permission-mode acceptEdits
bun evals/Lint.ts --brief briefs/<file>.brief.md --intake intake/fixtures/brute-force-dc-chain.intake.json
```

Then grade it against the fixture's ground truth, or let `/casa:evaluate <fixture>` do both
halves (the deterministic checks and the evaluator agent's rubric) and merge them:

```bash
bun evals/Grade.ts --brief briefs/<file>.brief.md --expected intake/fixtures/brute-force-dc-chain.expected.json --intake intake/fixtures/brute-force-dc-chain.intake.json
claude -p "/casa:evaluate brute-force-dc-chain" --permission-mode acceptEdits
bun evals/RunFull.ts     # the whole loop on every fixture; also the manual eval-full CI job
```

Do not use `--plugin-dir .` for this: Claude Code protects a plugin directory, so the brief
cannot be written into the same checkout. Real briefs from the three fixtures are kept under
`evals/samples/*.run1.brief.md`; the test suite lints and grades every one of them.

Layout: `agents/` · `skills/` · `intake/` (contract, fixtures, validator) · `evals/`
(lint, grader, tests) · `briefs/` (run output, gitignored). Developer notes are in
[`.claude/CLAUDE.md`](.claude/CLAUDE.md).

## License

MIT — see [LICENSE](LICENSE). The v4 tree was derived from
[Daniel Miessler's PAI](https://github.com/danielmiessler/Personal_AI_Infrastructure) (also MIT).
