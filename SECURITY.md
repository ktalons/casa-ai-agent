# Security

## Model

CASA is a Claude Code plugin that reasons over SOC telemetry. Three things follow:

1. **Telemetry is attacker-controlled input.** Alert descriptions, hostnames, usernames, DNS
   names and the recon delta can contain text written by an adversary. Every CASA agent
   preloads `skills/standards/SKILL.md`, which treats all such content as data, never
   instruction, and records anything instruction-shaped in `injection_flags` without acting on
   it. Specialist agents have explicit, minimal `tools:` lists; the analysis agents have no
   Write or Edit tool and cannot fetch from the web. The three that carry Bash are confined by
   the permission allowlist to read-only analysis commands; that allowlist is a prefix match
   and lives in settings, so a project that widens it widens what those agents can run.
2. **Nothing is auto-remediated, and nothing is learned without sign-off.** Outputs are
   options with trade-offs under `briefs/`. The only agents that write are the detection
   engineer (`detections/proposed/`) and the evaluator (`evals/results/`). The LEARN phase
   writes candidates under `learn/pending/`; only `/casa:learn`, driven by the analyst,
   promotes one into the lessons file the standards skill reads.
3. **Permissions do not travel with a plugin.** The repo's `.claude/settings.json` denies
   destructive commands and secret reads and allowlists read-only analysis tools. Copy it into
   any project where CASA is installed. Phase 3 adds a write-path guard hook that does travel
   with the plugin.

Neither the agent prompts nor the permission rules are a sandbox. Run CASA where a mistake
is recoverable, and use Claude Code's sandbox settings where the host supports them.

## What is never committed

Briefs, grades, proposed detections, learn candidates, engagement scopes, `.env`, keys and
logs are gitignored. `intake/raw/*.jsonl` is the one tracked JSONL path, for hand-authored
fixtures only. CI runs gitleaks over full history.

## Reporting

Open a private security advisory on the GitHub repository, or contact the maintainer
directly. Please do not open a public issue for a vulnerability.
