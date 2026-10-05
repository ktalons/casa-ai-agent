# casa-ai-agent developer notes

This repository *is* the CASA plugin for Claude Code (v5, rebuilt in six phases; the PAI-era
tree is preserved at tag `v4.0.0-pai-legacy`). The investigation rules, agents and
skills live at the repo root (`agents/`, `skills/`, `hooks/`) and load only when the plugin
is loaded; they are not project-scope components. The SOC non-negotiables live in
`skills/standards/SKILL.md`, which every CASA agent preloads, not here.

## Working on CASA

- Two ways to load this checkout as the plugin:
  - `bun run plugin:link` once (adds this directory as a local-scope marketplace and installs
    `casa@casa` in place; both land in the gitignored `.claude/settings.local.json`). Claude Code
    then reads agents and skills live from the checkout. Use this for fixture runs and for
    headless `claude -p` evals.
  - `bun run dev` (`claude --plugin-dir .`). Claude Code protects a `--plugin-dir` directory, so
    every write into the repo prompts and headless runs cannot write `briefs/`. Fine for a
    quick interactive check, wrong for evals. Do not combine the two: run
    `claude plugin disable casa` first.
- `bun run validate:plugin` — `claude plugin validate --strict .` (CI runs this).
- `bun run typecheck` · `bun test` · `bun run validate:fixtures` — the fast checks; run all before pushing.
- Plugin components are namespaced: agents are `casa:log-analyst` etc., skills are
  `/casa:investigate`, `/casa:evaluate`, `/casa:learn`.
- Eval loop: `bun run eval:full` (investigate then evaluate on every fixture, headless, needs
  the plugin linked and the workspace trusted); `bun evals/Grade.ts` alone for the deterministic
  half; real briefs worth keeping go to `evals/samples/<fixture>.runN.brief.md`.
- `claude plugin eval` is not used; the manifest points it at the empty `evals/plugin-eval/`.

## Conventions

- Agent files: kebab-case name matching the filename; explicit `tools:`; no `memory`, no
  `permissions`, no `voiceId`. `evals/lib/agents.test.ts` enforces this.
- Agent and skill bodies are harness-neutral prompts. Frontmatter is the only Claude-specific
  line. Anything deterministic belongs in a script under `intake/` or `evals/`, not in prose.
- Never put example telemetry (hosts, IPs, rule IDs) in agent or skill text. Placeholders only.
- `intake/schema/soc-intake.v1.schema.json` is frozen. Field changes mean a v2 schema and fixtures.
- Zero runtime dependencies. Bun + TypeScript, `strict: true`.
