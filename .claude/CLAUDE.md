# casa-ai-agent — developer notes

This repository *is* the CASA plugin for Claude Code. The investigation rules, agents and
skills live at the repo root (`agents/`, `skills/`, `hooks/`) and load only when the plugin
is loaded; they are not project-scope components. The SOC non-negotiables live in
`skills/standards/SKILL.md`, which every CASA agent preloads, not here.

## Working on CASA

- `bun run dev` — start Claude Code with this checkout loaded as the plugin (`--plugin-dir .`).
  If you also have `casa` installed from the marketplace, run `claude plugin disable casa` first.
- `bun run validate:plugin` — `claude plugin validate --strict .` (CI runs this).
- `bun run typecheck` · `bun test` · `bun run validate:fixtures` — the fast checks; run all before pushing.
- Plugin components are namespaced: agents are `casa:log-analyst` etc., skills are `/casa:investigate`.

## Conventions

- Agent files: kebab-case name matching the filename; explicit `tools:`; no `memory`, no
  `permissions`, no `voiceId`. `evals/lib/agents.test.ts` enforces this.
- Agent and skill bodies are harness-neutral prompts. Frontmatter is the only Claude-specific
  line. Anything deterministic belongs in a script under `intake/` or `evals/`, not in prose.
- Never put example telemetry (hosts, IPs, rule IDs) in agent or skill text. Placeholders only.
- `intake/schema/soc-intake.v1.schema.json` is frozen. Field changes mean a v2 schema and fixtures.
- Zero runtime dependencies. Bun + TypeScript, `strict: true`.
