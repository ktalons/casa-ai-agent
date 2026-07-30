# Hooks

TypeScript lifecycle handlers that run at Claude Code events. CASA keeps a small set: one security gate plus a lightweight voice/audit trail. All are non-blocking except the security validator, and all fail safe — an error in a hook never crashes the session.

## Registry

| Event | Hook | Does |
|---|---|---|
| PreToolUse (Bash/Edit/Write/Read) | `SecurityValidator.hook.ts` | Checks the command/path against `../security/patterns.example.yaml` (or the user copy at `USER/PAISECURITYSYSTEM/patterns.yaml`). Blocks catastrophic ops, asks on dangerous ones, allows the rest. |
| SessionStart | `StartupGreeting.hook.ts` | Prints a short identity banner; fires an optional voice greeting only if a voice ID is configured. |
| Stop | `StopOrchestrator.hook.ts` | Parses the transcript once, then runs the Voice and Capture handlers (`handlers/`). |
| SessionEnd | `SessionSummary.hook.ts` | Writes a session summary under `../MEMORY/`. |
| SubagentStop | `AgentOutputCapture.hook.ts` | Captures subagent output under `../MEMORY/RESEARCH/`. |

Wiring lives in `settings.template.json` under `hooks` (setup.sh copies it to `settings.json` and resolves `${PAI_DIR}`).

## Shared libraries (`lib/`)

| Library | Purpose |
|---|---|
| `identity.ts` | DA + principal identity from settings.json (with safe defaults) |
| `time.ts` | IANA-timezone timestamps via `Intl.DateTimeFormat` (DST-safe) |
| `paths.ts` | Canonical path resolution under `PAI_DIR` |
| `TranscriptParser.ts` | Parse a session transcript into structured turns |
| `notifications.ts` | Voice-server / notification helpers |
| `response-format.ts` | Voice-completion validation |
| `observability.ts`, `learning-utils.ts`, `metadata-extraction.ts` | Capture-handler support |

## Conventions

- Shebang `#!/usr/bin/env bun`; keep the header comment describing trigger, input, and failure behavior.
- Never write secrets or session content to tracked paths — captures go under `../MEMORY/`, which is gitignored.
- After changing the hook set, update this table and `settings.template.json` together, then run `bash setup.sh --validate` (CI does too) to confirm every wired command resolves.
