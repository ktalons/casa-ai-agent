#!/usr/bin/env bash
# CASA setup — links the Cybersecurity Analysis Support Agent into ~/.claude/
#
# The install model: ~/.claude is a symlink to <repo>/.claude/, so `git pull`
# is the update mechanism and user config (settings.json, .env) stays local
# and gitignored.
#
# Usage:
#   git clone https://github.com/ktalons/casa-ai-agent
#   cd casa-ai-agent && bash setup.sh
#
# Flags:
#   --validate    Check repo structure without making any changes
#   --help        Show usage
#
# Non-interactive runs (no TTY, or CASA_ASSUME_DEFAULTS=1) take safe defaults:
# analyst name "Analyst", autodetected IANA timezone, voice disabled.
#
# Compatible with macOS /bin/bash 3.2. Every variable is declared before use;
# re-running is a safe no-op.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDE_SRC="${REPO_DIR}/.claude"
TARGET="${HOME}/.claude"
MODE="install"
FAILURES=0
BACKUP_PATH=""
SYMLINK_CREATED=0

BOLD='\033[1m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
RESET='\033[0m'

ok()   { printf "  ${GREEN}✓${RESET} %s\n" "$1"; }
bad()  { printf "  ${RED}✗${RESET} %s\n" "$1"; FAILURES=$((FAILURES + 1)); }
note() { printf "  ${YELLOW}·${RESET} %s\n" "$1"; }

usage() {
    printf "Usage: bash setup.sh [--validate | --help]\n"
    printf "  (no flags)   install: symlink ~/.claude and generate config\n"
    printf "  --validate   check repo structure, change nothing\n"
    printf "  --help       this message\n"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --validate) MODE="validate" ;;
        -h|--help)  usage; exit 0 ;;
        *)          printf "Unknown argument: %s\n" "$1"; usage; exit 1 ;;
    esac
    shift
done

# ── validation ──────────────────────────────────────────────────────────────
check_file() { if [ -f "$1" ]; then ok "$2"; else bad "$2 (missing: $1)"; fi }
check_dir()  { if [ -d "$1" ]; then ok "$2"; else bad "$2 (missing: $1)"; fi }

validate_repo() {
    printf "${BOLD}Validating CASA repo structure${RESET}\n"

    printf "Agents\n"
    local agent
    for agent in Overseer LogAnalyst NetworkAnalyst PurpleTeamMapper Pentester; do
        check_file "${CLAUDE_SRC}/agents/${agent}.md" "agents/${agent}.md"
    done

    printf "Skills\n"
    local skill
    for skill in CyberAnalysis PromptInjection Recon WebAssessment OSINT SECUpdates AnnualReports VoiceServer; do
        check_dir "${CLAUDE_SRC}/skills/${skill}" "skills/${skill}/"
    done

    printf "Workflows\n"
    local wf
    for wf in AuthAnomalyInvestigation NetworkBeaconingDetection DataExfiltrationAnalysis LateralMovementDetection IntakeTriage; do
        check_file "${CLAUDE_SRC}/skills/CyberAnalysis/Workflows/${wf}.md" "CyberAnalysis/Workflows/${wf}.md"
    done

    printf "Hooks\n"
    local hook
    for hook in SecurityValidator StartupGreeting SessionSummary StopOrchestrator AgentOutputCapture; do
        check_file "${CLAUDE_SRC}/hooks/${hook}.hook.ts" "hooks/${hook}.hook.ts"
    done
    check_file "${CLAUDE_SRC}/hooks/lib/TranscriptParser.ts" "hooks/lib/TranscriptParser.ts"
    check_file "${CLAUDE_SRC}/security/patterns.example.yaml" "security/patterns.example.yaml"

    printf "Voice server\n"
    check_file "${CLAUDE_SRC}/VoiceServer/server.ts" "VoiceServer/server.ts"
    check_file "${CLAUDE_SRC}/VoiceServer/com.casa.voiceserver.plist" "VoiceServer/com.casa.voiceserver.plist"

    printf "Intake contract\n"
    check_file "${REPO_DIR}/intake/schema/soc-intake.v1.schema.json" "intake/schema/soc-intake.v1.schema.json"
    check_file "${REPO_DIR}/intake/Validate.ts" "intake/Validate.ts"
    check_dir  "${REPO_DIR}/intake/fixtures" "intake/fixtures/"

    printf "Config\n"
    check_file "${CLAUDE_SRC}/settings.template.json" "settings.template.json"
    check_file "${CLAUDE_SRC}/CLAUDE.md" "CLAUDE.md"
    check_file "${REPO_DIR}/package.json" "package.json"

    if command -v bun >/dev/null 2>&1; then
        # Template must parse, and every wired hook command must resolve to a
        # real file once ${PAI_DIR} points at the repo's .claude/.
        if bun -e '
            const src = process.argv[1];
            const s = JSON.parse(await Bun.file(src + "/settings.template.json").text());
            const missing = [];
            for (const event of Object.values(s.hooks ?? {})) {
                for (const matcher of event) {
                    for (const h of matcher.hooks ?? []) {
                        const p = h.command.replace("${PAI_DIR}", src);
                        if (!(await Bun.file(p).exists())) missing.push(h.command);
                    }
                }
            }
            if (missing.length) { console.error("unresolved hook commands:", missing.join(", ")); process.exit(1); }
        ' "$CLAUDE_SRC" 2>&1; then
            ok "settings.template.json parses; all hook commands resolve"
        else
            bad "settings.template.json hook commands do not all resolve"
        fi
    else
        note "bun not installed — skipped settings JSON/hook-path checks"
    fi

    if [ "$FAILURES" -gt 0 ]; then
        printf "${RED}${BOLD}%d check(s) failed${RESET}\n" "$FAILURES"
        exit 1
    fi
    printf "${GREEN}${BOLD}All checks passed${RESET}\n"
}

if [ "$MODE" = "validate" ]; then
    validate_repo
    exit 0
fi

# ── install ─────────────────────────────────────────────────────────────────
# If anything fails after we move an existing ~/.claude aside and before the
# symlink exists, put the original back — never leave the user with nothing.
# This runs via `trap ... EXIT` below, which shellcheck's reachability analysis
# does not follow: 0.11+ reports SC2329 on the definition, older versions report
# SC2317 on the body. Both are false positives; disable both so any version passes.
# shellcheck disable=SC2329,SC2317
restore_on_failure() {
    local code=$?
    if [ "$code" -ne 0 ] && [ -n "$BACKUP_PATH" ] && [ "$SYMLINK_CREATED" -eq 0 ] && [ ! -e "$TARGET" ]; then
        mv "$BACKUP_PATH" "$TARGET"
        printf "${YELLOW}Setup failed — restored your previous ~/.claude from backup.${RESET}\n"
    fi
    return "$code"
}
trap restore_on_failure EXIT

printf "${BOLD}CASA setup${RESET} (repo: %s)\n\n" "$REPO_DIR"

printf "${BOLD}Prerequisites${RESET}\n"
if command -v bun >/dev/null 2>&1; then
    ok "bun $(bun --version)"
else
    bad "bun is required. Install it from https://bun.sh (e.g. 'brew install oven-sh/bun/bun'), then re-run."
fi
if command -v git >/dev/null 2>&1; then ok "git"; else bad "git is required."; fi
if command -v claude >/dev/null 2>&1; then
    ok "claude"
else
    note "Claude Code CLI not found — install it before launching CASA: https://docs.anthropic.com/en/docs/claude-code"
fi
[ "$FAILURES" -gt 0 ] && exit 1

printf "\n${BOLD}Linking ~/.claude${RESET}\n"
if [ -L "$TARGET" ]; then
    CURRENT_LINK="$(readlink "$TARGET")"
    if [ "$CURRENT_LINK" = "$CLAUDE_SRC" ]; then
        ok "Already linked to this repo — nothing to relink"
    else
        bad "The Claude config symlink points elsewhere: ${CURRENT_LINK}"
        printf "    CASA will not overwrite it. Remove the link yourself if you want CASA here:\n"
        printf "    rm %s && bash setup.sh\n" "$TARGET"
        exit 1
    fi
elif [ -e "$TARGET" ]; then
    BACKUP_PATH="${HOME}/.claude.backup.$(date +%Y%m%d-%H%M%S)"
    mv "$TARGET" "$BACKUP_PATH"
    ok "existing ~/.claude backed up to ${BACKUP_PATH}"
    ln -s "$CLAUDE_SRC" "$TARGET"
    SYMLINK_CREATED=1
    ok "linked ~/.claude → ${CLAUDE_SRC}"
else
    ln -s "$CLAUDE_SRC" "$TARGET"
    SYMLINK_CREATED=1
    ok "linked ~/.claude → ${CLAUDE_SRC}"
fi

# ── interactive answers (defaults when no TTY) ──────────────────────────────
INTERACTIVE=1
if [ ! -t 0 ] || [ "${CASA_ASSUME_DEFAULTS:-0}" = "1" ]; then
    INTERACTIVE=0
fi

detect_timezone() {
    # IANA name only. Abbreviations like MST/PDT crash the timestamp code.
    local tz=""
    if [ -L /etc/localtime ]; then
        tz="$(readlink /etc/localtime | sed 's|.*zoneinfo/||')"
    elif [ -r /etc/timezone ]; then
        tz="$(cat /etc/timezone)"
    fi
    if [ -n "$tz" ] && command -v bun >/dev/null 2>&1; then
        if ! bun -e 'new Intl.DateTimeFormat("en-US",{timeZone:process.argv[1]})' "$tz" 2>/dev/null; then
            tz=""
        fi
    fi
    printf "%s" "${tz:-UTC}"
}

printf "\n${BOLD}Configuration${RESET}\n"
SETTINGS_JSON="${CLAUDE_SRC}/settings.json"
if [ -f "$SETTINGS_JSON" ]; then
    ok "settings.json already exists — keeping it (delete it and re-run to reconfigure)"
else
    ANALYST_NAME="Analyst"
    DETECTED_TZ="$(detect_timezone)"
    VOICE_ID=""
    if [ "$INTERACTIVE" -eq 1 ]; then
        printf "  Analyst name [Analyst]: "
        read -r REPLY_NAME || REPLY_NAME=""
        [ -n "$REPLY_NAME" ] && ANALYST_NAME="$REPLY_NAME"
        printf "  Timezone (IANA) [%s]: " "$DETECTED_TZ"
        read -r REPLY_TZ || REPLY_TZ=""
        [ -n "$REPLY_TZ" ] && DETECTED_TZ="$REPLY_TZ"
        printf "  Voice: 1) none  2) Sarah (female)  3) Adam (male)  [1]: "
        read -r REPLY_VOICE || REPLY_VOICE=""
        case "${REPLY_VOICE:-1}" in
            2) VOICE_ID="EXAVITQu4vr4xnSDxMaL" ;;
            3) VOICE_ID="pNInz6obpgDQGcFmaJgB" ;;
            *) VOICE_ID="" ;;
        esac
    fi
    bun -e '
        const [templatePath, outPath, paiDir, name, tz, voiceId] = process.argv.slice(1);
        const s = JSON.parse(await Bun.file(templatePath).text());
        s.env = s.env ?? {};
        s.env.PAI_DIR = paiDir;
        s.principal = { ...(s.principal ?? {}), name, timezone: tz };
        s.daidentity = { ...(s.daidentity ?? {}), voiceId };
        for (const event of Object.values(s.hooks ?? {})) {
            for (const matcher of event) {
                for (const h of matcher.hooks ?? []) {
                    h.command = h.command.replace("${PAI_DIR}", paiDir);
                }
            }
        }
        JSON.parse(JSON.stringify(s)); // final sanity parse before writing
        await Bun.write(outPath, JSON.stringify(s, null, 2) + "\n");
    ' "${CLAUDE_SRC}/settings.template.json" "$SETTINGS_JSON" "$TARGET" "$ANALYST_NAME" "$DETECTED_TZ" "$VOICE_ID"
    ok "settings.json generated (analyst: ${ANALYST_NAME}, tz: ${DETECTED_TZ}, voice: ${VOICE_ID:-disabled})"
fi

ENV_FILE="${CLAUDE_SRC}/.env"
if [ -f "$ENV_FILE" ]; then
    ok ".env already exists — keeping it"
else
    printf '# CASA local secrets — gitignored, never committed\n\n# Voice synthesis (optional): https://elevenlabs.io\nELEVENLABS_API_KEY=\n' > "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    ok ".env template created (add your ElevenLabs key to enable voice)"
fi

PATTERNS_FILE="${CLAUDE_SRC}/USER/PAISECURITYSYSTEM/patterns.yaml"
if [ -f "$PATTERNS_FILE" ]; then
    ok "security patterns.yaml already exists — keeping it"
else
    mkdir -p "${CLAUDE_SRC}/USER/PAISECURITYSYSTEM"
    cp "${CLAUDE_SRC}/security/patterns.example.yaml" "$PATTERNS_FILE"
    ok "security patterns.yaml generated from template (customize: ${PATTERNS_FILE})"
fi

printf "\n${BOLD}Dependencies${RESET}\n"
if (cd "$REPO_DIR" && bun install --frozen-lockfile >/dev/null 2>&1); then
    ok "bun install (yaml pinned via bun.lock)"
else
    bad "bun install failed — run 'bun install' in ${REPO_DIR} manually"
fi

printf "\n${BOLD}Done${RESET}\n"
printf "  Launch:        claude\n"
printf "  Validate:      bash setup.sh --validate\n"
printf "  Update:        git pull\n"
printf "  Voice server:  bun %s/VoiceServer/server.ts   (needs ELEVENLABS_API_KEY in .claude/.env)\n" "$TARGET"
if [ "$FAILURES" -gt 0 ]; then
    exit 1
fi
exit 0
