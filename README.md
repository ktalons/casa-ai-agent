# CASA

[![ci](https://github.com/ktalons/casa-ai-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/ktalons/casa-ai-agent/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![NIST CSF](https://img.shields.io/badge/NIST-CSF%202.0-blue)](https://www.nist.gov/cyberframework)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org/)

Cybersecurity Analysis Support Agent. A Claude Code plugin for SOC investigations.

Give it one intake JSON file of alerts. It returns one analyst brief: alert chains threaded
across hosts, a verdict and a confidence level for each, the evidence behind every claim,
alternatives, data requests, and options with trade-offs.

CASA does not act. A human makes every decision.

## Measured

Scores come from fixtures. A fixture is an intake file plus ground truth written with it. Each
brief is graded two ways.

- **Machine.** Nine deterministic checks per brief. The brief parses. Every cited token traces
  to the intake or a reference table. Status, thread count, confidence, CSF functions, option
  kinds, required citations and forbidden citations match the ground truth.
- **Rubric.** A separate evaluator agent judges what the brief had to identify and what it
  must not claim. Each verdict quotes the brief. A quote that is not in the brief does not count.

| Set | Variants | Machine | Rubric |
|---|---|---|---|
| Held-out | 4 | 36/36 | 30/30 |
| Authoring | 15 | 135/135 | 98/99 |

Run on 2026-11-22 on the tree committed as `09cd139`. One run per variant. Opus on the main thread, Sonnet
for the specialists.

The held-out number is the one that matters. Prompt text is tuned against the authoring set
only. The held-out set stays unseen in four ways.

- Tests fail if a held-out fixture's name, values or story appear in any skill, agent or card
  file.
- Each investigate run gets its own new, empty project that holds only its intake. It can read
  the plugin's `skills/` and nothing else in this repo: no ground truth, no earlier brief, no
  other fixture.
- After a run, `bun run eval:scan` reads every child transcript. It fails if a tool call
  outside the run's lane was not refused.
- A held-out fixture that shapes a change moves to the authoring set and is replaced. Two have
  moved so far.

What these numbers do not show:

- The held-out set is four fixtures. Every fixture is synthetic and written by one author.
- Each variant ran once. Model output varies between runs.
- There is no score on live alert volume yet.
- The lost held-out point is recorded and has not been tuned on.

Grade records stay on the machine that ran them. To reproduce the table, see
[Development](#development).

## What CASA does not do

- **Act.** No containment, blocking, ticketing or rule deployment. Options come with
  trade-offs. Containment options appear only for a supported finding at High confidence.
- **Deploy detections.** The detection engineer writes Sigma and Wazuh drafts under
  `detections/proposed/` with test criteria. Nothing reaches `detections/accepted/` without
  the analyst.
- **Collect telemetry.** CASA reads one intake file. The bundled producer builds that file
  from Wazuh alerts. Any other SIEM needs its own producer for the same schema.
- **Query anything on its own.** The specialists have no shell. A query they need comes back
  as an exact command in a data request, for the analyst to run or decline.
- **Prove a conclusion.** The lint proves that every host, address, user, rule, event, port,
  hash and technique in a brief exists in the intake or a reference table. It does not prove
  the reasoning is right. Read the brief.
- **Trust the input.** Text inside an alert is data. An instruction found there is flagged and
  not followed. A benign verdict that rests only on the input's own account of sanctioned
  activity is held at Medium.
- **Look up indicators online by default.** Threat intel is offline first. External lookups
  need API keys you configure.
- **Run offensive tooling.** The pentester agent is a stub. It returns methodology pointers
  for a written engagement scope and refuses without one. No scanning, no exploitation.
- **Guarantee redaction.** The producer's `--redact` flag is a second layer. The first is an
  output root outside any public repository.
- **Run on a live lab yet.** The producer's live mode is tested against a mock indexer only.
  The TalonSocLab feed is not wired.

## Install and first run

Prerequisites: [Claude Code](https://docs.anthropic.com/en/docs/claude-code) 2.1.289 or later
and [Bun](https://bun.sh).

As a plugin, in any project:

```text
/plugin marketplace add ktalons/casa-ai-agent
/plugin install casa@casa
```

A plugin cannot set a project's permissions. Copy
[`docs/settings.recommended.json`](docs/settings.recommended.json) into the project's
`.claude/settings.json`, or run `scripts/install-into-project.sh` from the project root. The
script installs the plugin, merges the permission block, creates the output directories and
needs `jq`.

To try a bundled fixture, work from a clone:

```bash
git clone https://github.com/ktalons/casa-ai-agent && cd casa-ai-agent
bun install
bun run plugin:link
claude
```

```text
/casa:investigate intake/fixtures/brute-force-dc-chain.v3.intake.json
```

The brief is written under `briefs/`.

To build an intake from your own Wazuh alerts, replay an export and validate the result:

```bash
bun intake/producers/wazuh.ts --replay <alerts.jsonl> --out intake.json
bun intake/Validate.ts intake.json
```

| Command | What it does |
|---|---|
| `/casa:investigate <intake.json \| question>` | Runs an investigation and writes one brief |
| `/casa:evaluate <fixture>` | Grades a brief against a fixture's ground truth |
| `/casa:learn` | Reviews lesson candidates and keeps the ones the analyst approves |

The current release is `v5.2.0`. Everything measured above is in it. See
[CHANGELOG.md](CHANGELOG.md).

## How it works

`/casa:investigate` runs one loop on the main thread.

| Step | What happens |
|---|---|
| OBSERVE | Validate the intake, count the alerts, flag injected text |
| HYPOTHESIZE | Thread detections into chains, one hypothesis per chain |
| INVESTIGATE | Fan out to the specialists in parallel |
| VERIFY | Check that every citation traces to the intake |
| MAP | Map findings to NIST CSF 2.0 and ATT&CK |
| BRIEF | Write one analyst brief |
| LEARN | Write a candidate lesson, kept only if the analyst approves it |

An empty intake short-circuits to a liveness check. CASA never invents findings to fill a
quiet day.

| Agent | Lane |
|---|---|
| log-analyst | alert chains and timelines across hosts |
| network-analyst | flows, DNS, TLS, ports, beaconing, recon changes |
| endpoint-analyst | single-host behavior, event IDs, process ancestry |
| purple-team-mapper | NIST CSF 2.0 and ATT&CK mapping, visibility gaps |
| detection-engineer | Sigma and Wazuh rule drafts for supported findings |
| threat-intel | technique and indicator context, offline first |
| evaluator | grades a brief against fixture ground truth |
| pentester | methodology pointers, only with an engagement scope |

Each specialist returns one `casa.finding/v1` record: verdict, confidence with what would
raise it, evidence references, alternatives, data requests, options with trade-offs and a
reasoning trace.

Nine workflow cards carry the method for each technique family: authentication anomalies, C2
beaconing, credential theft and DCSync, exfiltration, internal discovery and scanning, lateral
movement, log and defense tampering, script and proxy execution, and service and autostart
persistence.

Three controls hold the rules in place.

- **Standards.** [`skills/standards/SKILL.md`](skills/standards/SKILL.md) is preloaded into
  every agent: scope, untrusted data, anti-fabrication, confidence, citations and
  human-in-the-loop framing.
- **Lint.** `evals/Lint.ts` fails a brief when a cited token does not trace. The reference
  tables are NIST CSF 2.0 and ATT&CK 19.2.
- **Write guard.** A hook keeps each agent in its lane and fails closed. Only the detection
  engineer and the evaluator can write files, each to one directory. No specialist can run a
  shell command.

## Two planes

[TalonSocLab](https://github.com/ktalons/talonsoclab) is the data plane. It collects, filters
and cites SOC telemetry. CASA is the reasoning plane. It reads a structured intake and writes
the analysis.

The contract between them is a JSON schema, `talonsoclab.soc-intake`, not a shared API. Versions
1 and 2 are frozen. Version 3 is current and carries Sysmon, Suricata and engine fields. See
[`intake/README.md`](intake/README.md).

Briefs, drafts, lessons and grades are written under the plugin's `output_root` option, never
into the plugin. The runbook for the lab is
[`docs/talonsoclab-integration.md`](docs/talonsoclab-integration.md).

## Other agents

Agents that cannot load a Claude Code plugin can use the pack in
[`portable/`](portable/README.md): three skills in the [Agent Skills](https://agentskills.io)
format, generated from the same rule text. They carry the rules and the method. Nothing in them
enforces either: no lint in code, no write guard, no parallel specialists.

## Development

```bash
bun run check        # typecheck, tests, fixture validation, plugin validation
```

To reproduce the scores, link the plugin once with `bun run plugin:link`, then:

```bash
bun run eval:full                      # investigate, then evaluate, on every fixture
bun evals/RunFull.ts --set held-out    # one set only
bun evals/Grade.ts --summary           # newest grade per variant, sets kept apart
bun run eval:scan                      # fail on any tool call outside a run's lane
```

A full run starts one headless Claude Code session per step and counts against your usage.

Fixture sets are listed in `evals/fixture-sets.json`. Fixtures use documentation addresses,
`corp*` host names and RFC 2606 domains. Do not use `bun run dev` (`--plugin-dir .`) for eval
runs: Claude Code protects a plugin directory, so a headless run cannot write its brief.

Layout: `agents/` · `skills/` · `hooks/` (write guard) · `intake/` (schemas, fixtures,
validator, producer) · `evals/` (lint, grader, runner, scan) · `portable/` (generated skill
pack; rebuild with `bun run build:portable`). Developer notes are in
[`.claude/CLAUDE.md`](.claude/CLAUDE.md).

## License

MIT. See [LICENSE](LICENSE). The v4 tree was derived from
[Daniel Miessler's PAI](https://github.com/danielmiessler/Personal_AI_Infrastructure), also MIT,
and is preserved at tag `v4.0.0-pai-legacy`.
