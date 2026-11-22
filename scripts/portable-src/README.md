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

One trial run is on record. On 2026-11-21, Codex CLI on `gpt-6-sol` loaded the pack and triaged
one of the repository's authoring fixtures. The brief passed the repository's lint and all nine
machine checks of its grader. The judged rubric was not run.

One run on one fixture is a smoke test, not a score. The scores in the repository README belong
to the plugin, not to this pack.

## These files are generated

Do not edit them here. Change the plugin sources or the templates under
`scripts/portable-src/`, then run:

```bash
bun scripts/build-portable.ts
```

CI fails when this folder differs from what the sources generate.
