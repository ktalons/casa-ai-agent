# CASA portable skills

Three skills in the [Agent Skills](https://agentskills.io) format, generated from the CASA
plugin's own rule text at version {{version}}. They are for agents that read that format and
cannot load the plugin.

{{skill-table}}

Install `casa-soc-standards` with either of the other two. It holds the rules and the tables
they cite.

## Install

Copy the three folders into the directory your agent reads skills from.

| Agent | Directory |
|---|---|
| Codex CLI | `.agents/skills/` in the project |
| Claude Code | `.claude/skills/` in the project |

In Claude Code the full plugin is the better choice. See the [repository README]({{repo-url}}).

## What the pack leaves out

The plugin runs each lens as its own agent in parallel, checks every citation with a lint written in
code, keeps each agent in its lane with a write guard, builds its input from Wazuh alerts and
measures itself on held-out fixtures. The pack carries the rules and the method only. Nothing
in it enforces them.

## Tested

On 2026-11-22, Codex CLI on `gpt-6-sol` ran the triage skill on the repository's 15 authoring
fixtures, one run each, with only this pack installed. The repository's grader scored the briefs.

| Set | Variants | Machine | Rubric |
|---|---|---|---|
| Authoring | 15 | 134/135 | 95/99 |

Machine is nine deterministic checks per brief, the lint among them. Rubric is the plugin's
evaluator agent judging what each brief had to identify and what it must not claim.

This is not a held-out score. The authoring fixtures are the set the plugin's prompts are tuned
on, and two sentences of this pack were tightened after an earlier partial run on the same set.
The pack has not been run on the held-out fixtures. The scores in the repository README belong
to the plugin, not to this pack.

## These files are generated

Do not edit them here. Change the plugin sources or the templates under
`scripts/portable-src/`, then run:

```bash
bun scripts/build-portable.ts
```

CI fails when this folder differs from what the sources generate.
