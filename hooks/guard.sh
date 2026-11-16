#!/bin/sh
# ******************************************************************************
# *Title: CASA Guard Launcher*
# *Author: Kyle Versluis*
# *Description: Runs the write guard and blocks CASA agents if it cannot run.*
# ******************************************************************************

# Claude Code treats any exit other than 0 and 2 as non-blocking, so a missing or
# crashing bun would let a CASA subagent through. This POSIX sh wrapper turns that
# case into exit 2 for CASA callers and leaves everyone else alone.

# *--- Helper Functions ---*

# SECURITY: in-string quotes are always escaped in JSON, so a key match after { or , is a real key.
is_casa_caller() {
  flat=$(printf '%s' "$payload" | tr '\n\r\t' '   ')
  key='[{,][[:space:]]*"'
  sep='"[[:space:]]*:[[:space:]]*'
  # Names match case-insensitively, as guard-write-path.ts lowercases them.
  if printf '%s' "$flat" | grep -Eiq "${key}agent_type${sep}\"casa:"; then
    return 0
  fi
  # Bare names and a missing agent_type count only for subagents, which carry agent_id.
  printf '%s' "$flat" | grep -Eq "${key}agent_id${sep}" || return 1
  printf '%s' "$flat" | grep -Eq "${key}agent_type${sep}" || return 0
  bare='(detection-engineer|endpoint-analyst|evaluator|log-analyst|network-analyst|pentester|purple-team-mapper|threat-intel)'
  printf '%s' "$flat" | grep -Eiq "${key}agent_type${sep}\"${bare}\""
}

# *--- Entry Point ---*

payload=$(cat) || { echo "casa guard: cannot read hook input" >&2; exit 2; }

# SECURITY: bun reads bunfig.toml (preload) and .env from its working directory, which is
# the project under review. Run it from this hook's own directory instead.
if ! command -v bun >/dev/null 2>&1; then
  reason="bun is not on PATH"
elif ! cd "${0%/*}"; then
  reason="cannot enter the hook directory"
else
  printf '%s' "$payload" | bun ./guard-write-path.ts
  rc=$?
  if [ "$rc" -eq 0 ] || [ "$rc" -eq 2 ]; then
    exit "$rc"
  fi
  reason="the guard exited $rc"
fi

if is_casa_caller; then
  echo "casa guard: $reason; refusing this CASA agent call because it cannot be checked" >&2
  exit 2
fi
exit 0
