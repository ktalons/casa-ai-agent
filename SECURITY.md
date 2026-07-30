# Security Policy

## Scope and intent

CASA is a defensive, human-in-the-loop analysis assistant. It guides investigations and explains its reasoning; it does not take autonomous response actions, and its Pentester agent is for **authorized** assessment only. Use it within engagements you are permitted to test.

## Reporting a vulnerability

Report privately through GitHub's [security advisories](https://github.com/ktalons/casa-ai-agent/security/advisories/new) for this repo. Please do not open a public issue for anything exploitable. Include repro steps and impact; expect an initial response within a week.

## Handling secrets

- Secrets live only in `.claude/.env` (created by `setup.sh`, gitignored). Never commit API keys.
- `~/.claude` is a symlink into this repo, so Claude Code runtime files (OAuth credentials, session logs, local settings) land in the working tree. The `.gitignore` is an **allowlist** — everything under `.claude/` is ignored except the tracked source directories — so runtime credentials cannot be committed by accident. Keep it that way when adding files.
- CI runs [gitleaks](https://github.com/gitleaks/gitleaks) on every push as a backstop.

## Permission posture

The bundled `settings.template.json` allows only read-only tools outright, denies destructive commands (`rm -rf /`, disk erase, force-push, …), and prompts for sensitive reads. `SecurityValidator.hook.ts` is a second `PreToolUse` layer that checks Bash/Edit/Write/Read against `security/patterns.example.yaml`. Neither is a sandbox — review actions before approving them.
