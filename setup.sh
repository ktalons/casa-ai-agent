#!/usr/bin/env bash
# CASA Setup Script
# Links the Cybersecurity Analysis Support Agent (CASA) into ~/.claude/
#
# This creates a symlink from ~/.claude → <repo>/.claude/ so that:
#   - git pull updates CASA automatically
#   - Your user config (settings.json, .env) stays local and gitignored
#
# Usage:
#   git clone <repo-url> && cd CASA && bash setup.sh

set -euo pipefail

# ─────────────────────────────────────────────────────────────
# Colors
# ─────────────────────────────────────────────────────────────
BOLD='\033[1m'
RESET='\033[0m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'

ok()   { echo -e "  ${GREEN}✓${RESET} $1"; }
warn() { echo -e "  ${YELLOW}!${RESET} $1"; }
err()  { echo -e "  ${RED}✗${RESET} $1"; }
info() { echo -e "  ${GRAY}→${RESET} $1"; }

# ─────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_CLAUDE_DIR="${REPO_DIR}/.claude"
TARGET="${HOME}/.claude"
BACKUP_DIR=""

# ─────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${RESET}"
echo -e "${CYAN}${BOLD}┃${RESET}                   ${BOLD}CASA Setup${RESET}                                  ${CYAN}${BOLD}┃${RESET}"
echo -e "${CYAN}${BOLD}┃${RESET}      ${GRAY}Cybersecurity Analysis Support Agent v1.0${RESET}               ${CYAN}${BOLD}┃${RESET}"
echo -e "${CYAN}${BOLD}┃${RESET}      ${GRAY}Built on PAI v2.5 Framework${RESET}                             ${CYAN}${BOLD}┃${RESET}"
echo -e "${CYAN}${BOLD}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${RESET}"
echo ""

# ─────────────────────────────────────────────────────────────
# Step 1: Verify repo structure
# ─────────────────────────────────────────────────────────────
echo -e "${BOLD}Step 1/5 — Checking repository${RESET}"
echo -e "${GRAY}─────────────────────────────────────────────────${RESET}"

if [ ! -d "${REPO_CLAUDE_DIR}" ]; then
    err "No .claude/ directory found in ${REPO_DIR}"
    err "Are you running this from the CASA repository root?"
    exit 1
fi
ok "Repository: ${REPO_DIR}"

for agent in Overseer LogAnalyst NetworkAnalyst PurpleTeamMapper; do
    if [ -f "${REPO_CLAUDE_DIR}/agents/${agent}.md" ]; then
        ok "Agent: ${agent}"
    else
        err "Missing agent: agents/${agent}.md"
        exit 1
    fi
done

if [ -d "${REPO_CLAUDE_DIR}/skills/CyberAnalysis" ]; then
    ok "Skill: CyberAnalysis"
else
    err "Missing skill: skills/CyberAnalysis/"
    exit 1
fi

if [ -f "${REPO_CLAUDE_DIR}/settings.template.json" ]; then
    ok "Settings template found"
else
    err "Missing settings.template.json"
    exit 1
fi

# ─────────────────────────────────────────────────────────────
# Step 2: Check prerequisites
# ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Step 2/5 — Checking prerequisites${RESET}"
echo -e "${GRAY}─────────────────────────────────────────────────${RESET}"

# Check for Claude Code
if command -v claude &> /dev/null; then
    CLAUDE_VERSION=$(claude --version 2>/dev/null || echo "unknown")
    ok "Claude Code: ${CLAUDE_VERSION}"
else
    err "Claude Code not found"
    echo ""
    info "Install Claude Code first:"
    info "  npm install -g @anthropic-ai/claude-code"
    info "  or: brew install claude-code"
    echo ""
    exit 1
fi

# Check for Bun (install if missing)
if command -v bun &> /dev/null; then
    BUN_VERSION=$(bun --version 2>/dev/null || echo "unknown")
    ok "Bun: ${BUN_VERSION}"
else
    warn "Bun not found — installing..."
    curl -fsSL https://bun.sh/install | bash
    export PATH="${HOME}/.bun/bin:${PATH}"
    if command -v bun &> /dev/null; then
        ok "Bun: $(bun --version) (just installed)"
    else
        err "Bun installation failed"
        info "Install manually: curl -fsSL https://bun.sh/install | bash"
        exit 1
    fi
fi

# ─────────────────────────────────────────────────────────────
# Step 3: Link ~/.claude → repo/.claude/
# ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Step 3/5 — Linking ~/.claude${RESET}"
echo -e "${GRAY}─────────────────────────────────────────────────${RESET}"

NEEDS_LINK=true

# Check if already linked to this repo
if [ -L "${TARGET}" ]; then
    CURRENT_LINK=$(readlink "${TARGET}")
    if [ "${CURRENT_LINK}" = "${REPO_CLAUDE_DIR}" ]; then
        ok "Already linked: ~/.claude → ${REPO_CLAUDE_DIR}"
        NEEDS_LINK=false
    else
        warn "~/.claude is a symlink to: ${CURRENT_LINK}"
        echo ""
        echo -e "  ${BOLD}Options:${RESET}"
        echo -e "    ${CYAN}1${RESET}) Re-link to this CASA repo (recommended)"
        echo -e "    ${CYAN}2${RESET}) Abort — I'll handle it manually"
        echo ""
        read -rp "  Choose [1/2]: " CHOICE
        case "${CHOICE}" in
            1)
                rm "${TARGET}"
                ok "Removed old symlink"
                ;;
            *)
                info "Aborting. Remove ~/.claude symlink and re-run setup.sh"
                exit 0
                ;;
        esac
    fi
elif [ -d "${TARGET}" ]; then
    warn "Existing ~/.claude/ directory detected (not a symlink)"
    echo ""
    echo -e "  ${BOLD}Options:${RESET}"
    echo -e "    ${CYAN}1${RESET}) Back up to ~/.claude-backup-<timestamp> and link (recommended)"
    echo -e "    ${CYAN}2${RESET}) Remove existing ~/.claude and link"
    echo -e "    ${CYAN}3${RESET}) Abort — I'll handle it manually"
    echo ""
    read -rp "  Choose [1/2/3]: " CHOICE
    case "${CHOICE}" in
        1)
            BACKUP_DIR="${HOME}/.claude-backup-$(date +%Y%m%d-%H%M%S)"
            mv "${TARGET}" "${BACKUP_DIR}"
            ok "Backed up to ${BACKUP_DIR}"
            ;;
        2)
            warn "Removing existing ~/.claude/"
            rm -rf "${TARGET}"
            ok "Removed"
            ;;
        3)
            info "Aborting. Move or rename ~/.claude and re-run setup.sh"
            exit 0
            ;;
        *)
            err "Invalid choice. Aborting."
            exit 1
            ;;
    esac
elif [ -e "${TARGET}" ]; then
    err "~/.claude exists but is not a directory or symlink. Remove it and re-run."
    exit 1
fi

if [ "${NEEDS_LINK}" = true ]; then
    ln -s "${REPO_CLAUDE_DIR}" "${TARGET}"
    ok "Linked: ~/.claude → ${REPO_CLAUDE_DIR}"
fi

info "Git pull will now update CASA automatically"

# ─────────────────────────────────────────────────────────────
# Step 4: Generate user config
# ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Step 4/5 — Personalization${RESET}"
echo -e "${GRAY}─────────────────────────────────────────────────${RESET}"

# Ensure runtime directories exist (gitignored, user-specific)
for dir in MEMORY/STATE MEMORY/LEARNING MEMORY/WORK MEMORY/RESEARCH Plans WORK; do
    mkdir -p "${REPO_CLAUDE_DIR}/${dir}"
done
ok "Created runtime directories"

# Set permissions on scripts
find "${REPO_CLAUDE_DIR}" -name "*.ts" -exec chmod 755 {} \;
find "${REPO_CLAUDE_DIR}" -name "*.sh" -exec chmod 755 {} \;
ok "Set script permissions"

# Generate settings.json if it doesn't exist
SETTINGS_FILE="${REPO_CLAUDE_DIR}/settings.json"

if [ -f "${SETTINGS_FILE}" ]; then
    ok "settings.json already exists (keeping current config)"
    info "To reconfigure, delete .claude/settings.json and re-run setup.sh"
else
    echo ""
    echo -e "  ${BOLD}Let's personalize CASA for you.${RESET}"
    echo ""

    # Analyst name
    read -rp "  Your name (for analyst identity) [Analyst]: " USER_NAME
    USER_NAME="${USER_NAME:-Analyst}"

    # Timezone (auto-detect)
    if command -v python3 &> /dev/null; then
        DETECTED_TZ=$(python3 -c "import datetime; print(datetime.datetime.now().astimezone().tzinfo)" 2>/dev/null || echo "")
    fi
    # Fallback: try system timezone
    if [ -z "${DETECTED_TZ:-}" ]; then
        if [ -f /etc/timezone ]; then
            DETECTED_TZ=$(cat /etc/timezone)
        elif [ -L /etc/localtime ]; then
            DETECTED_TZ=$(readlink /etc/localtime | sed 's|.*/zoneinfo/||')
        else
            DETECTED_TZ="UTC"
        fi
    fi
    read -rp "  Timezone [${DETECTED_TZ}]: " USER_TZ
    USER_TZ="${USER_TZ:-${DETECTED_TZ}}"

    # AI name
    read -rp "  Name your AI assistant [CASA]: " AI_NAME
    AI_NAME="${AI_NAME:-CASA}"

    # Build settings.json from template using sed replacements
    # The template uses placeholder values that we replace
    cp "${REPO_CLAUDE_DIR}/settings.template.json" "${SETTINGS_FILE}"

    # Patch in user values using Python for reliable JSON manipulation
    python3 -c "
import json, sys

with open('${SETTINGS_FILE}', 'r') as f:
    settings = json.load(f)

# Set PAI_DIR to the actual repo path (resolves through symlink)
settings['env']['PAI_DIR'] = '${REPO_CLAUDE_DIR}'

# Set user identity
settings['principal']['name'] = '${USER_NAME}'
settings['principal']['timezone'] = '${USER_TZ}'

# Set AI identity
settings['daidentity']['name'] = '${AI_NAME}'
settings['daidentity']['fullName'] = '${AI_NAME} - Cybersecurity Analysis Support Agent'
settings['daidentity']['displayName'] = '${AI_NAME}'
settings['daidentity']['startupCatchphrase'] = '${AI_NAME} ready. How can I assist your investigation?'

with open('${SETTINGS_FILE}', 'w') as f:
    json.dump(settings, f, indent=2)
    f.write('\n')
"

    ok "Generated settings.json"
    info "Analyst: ${USER_NAME}"
    info "AI Name: ${AI_NAME}"
    info "Timezone: ${USER_TZ}"
    info "PAI_DIR: ${REPO_CLAUDE_DIR}"
fi

# Handle .env for optional API keys
ENV_FILE="${REPO_CLAUDE_DIR}/.env"
if [ ! -f "${ENV_FILE}" ]; then
    echo ""
    echo -e "  ${BOLD}Optional: Voice support (ElevenLabs)${RESET}"
    echo -e "  ${GRAY}Voice is optional. Press Enter to skip.${RESET}"
    read -rp "  ElevenLabs API key [skip]: " ELEVENLABS_KEY
    if [ -n "${ELEVENLABS_KEY}" ]; then
        echo "ELEVENLABS_API_KEY=${ELEVENLABS_KEY}" > "${ENV_FILE}"
        ok "Saved API key to .claude/.env (gitignored)"
    else
        # Create empty .env so hooks don't error
        touch "${ENV_FILE}"
        info "Skipped voice setup (add ELEVENLABS_API_KEY to .claude/.env later)"
    fi
else
    ok ".env already exists (keeping current keys)"
fi

# ─────────────────────────────────────────────────────────────
# Step 5: Validate
# ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Step 5/5 — Validating installation${RESET}"
echo -e "${GRAY}─────────────────────────────────────────────────${RESET}"

PASS=true

# Symlink
if [ -L "${TARGET}" ] && [ "$(readlink "${TARGET}")" = "${REPO_CLAUDE_DIR}" ]; then
    ok "Symlink: ~/.claude → repo"
else
    err "Symlink not set correctly"
    PASS=false
fi

# Core files
for f in settings.json CLAUDE.md INSTALL.ts settings.template.json statusline-command.sh; do
    if [ -f "${REPO_CLAUDE_DIR}/${f}" ]; then
        ok "File: ${f}"
    else
        err "Missing: ${f}"
        PASS=false
    fi
done

# CASA agents
for agent in Overseer LogAnalyst NetworkAnalyst PurpleTeamMapper; do
    if [ -f "${REPO_CLAUDE_DIR}/agents/${agent}.md" ]; then
        ok "Agent: ${agent}"
    else
        err "Agent missing: ${agent}"
        PASS=false
    fi
done

# CyberAnalysis skill + workflows
if [ -f "${REPO_CLAUDE_DIR}/skills/CyberAnalysis/SKILL.md" ]; then
    ok "Skill: CyberAnalysis"
else
    err "Skill missing: CyberAnalysis"
    PASS=false
fi

for wf in AuthAnomalyInvestigation NetworkBeaconingDetection DataExfiltrationAnalysis LateralMovementDetection; do
    if [ -f "${REPO_CLAUDE_DIR}/skills/CyberAnalysis/Workflows/${wf}.md" ]; then
        ok "Workflow: ${wf}"
    else
        err "Workflow missing: ${wf}"
        PASS=false
    fi
done

# PAI framework
if [ -f "${REPO_CLAUDE_DIR}/skills/PAI/SKILL.md" ]; then
    ok "PAI framework: present"
else
    err "PAI framework: missing skills/PAI/SKILL.md"
    PASS=false
fi

# Key directories
for dir in skills agents hooks MEMORY; do
    if [ -d "${REPO_CLAUDE_DIR}/${dir}" ]; then
        ok "Directory: ${dir}/"
    else
        err "Directory missing: ${dir}/"
        PASS=false
    fi
done

# settings.json PAI_DIR check
if command -v python3 &> /dev/null; then
    PAI_DIR_VAL=$(python3 -c "
import json
with open('${REPO_CLAUDE_DIR}/settings.json') as f:
    print(json.load(f).get('env', {}).get('PAI_DIR', ''))
" 2>/dev/null || echo "")
    if [ "${PAI_DIR_VAL}" = "${REPO_CLAUDE_DIR}" ]; then
        ok "PAI_DIR points to repo"
    else
        warn "PAI_DIR in settings.json: ${PAI_DIR_VAL}"
        warn "Expected: ${REPO_CLAUDE_DIR}"
    fi
fi

# ─────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────
echo ""
if [ "${PASS}" = true ]; then
    echo -e "${GREEN}${BOLD}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${RESET}"
    echo -e "${GREEN}${BOLD}┃${RESET}  ${GREEN}✓ CASA installed successfully!${RESET}                              ${GREEN}${BOLD}┃${RESET}"
    echo -e "${GREEN}${BOLD}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${RESET}"
    echo ""
    echo -e "  ${BOLD}How it works:${RESET}"
    echo -e "    ~/.claude → ${REPO_CLAUDE_DIR}"
    echo -e "    Updates:  ${CYAN}cd ${REPO_DIR} && git pull${RESET}"
    echo ""
    echo -e "  ${BOLD}Start CASA:${RESET}"
    echo -e "    ${CYAN}claude${RESET}"
    echo ""
    echo -e "  ${BOLD}Example queries:${RESET}"
    echo -e "    ${GRAY}\"Analyze these auth logs for brute force indicators\"${RESET}"
    echo -e "    ${GRAY}\"Investigate this PCAP for C2 beaconing activity\"${RESET}"
    echo -e "    ${GRAY}\"Check network flows for data exfiltration patterns\"${RESET}"
    echo ""
    echo -e "  ${BOLD}Agents available:${RESET}"
    echo -e "    ${GREEN}Overseer${RESET}         — Routes queries to specialized agents"
    echo -e "    ${CYAN}LogAnalyst${RESET}       — Log investigation (NIST SP 800-92)"
    echo -e "    ${CYAN}NetworkAnalyst${RESET}   — PCAP and flow analysis"
    echo -e "    ${CYAN}PurpleTeamMapper${RESET} — Maps findings to NIST CSF 2.0"
    echo ""
    if [ -n "${BACKUP_DIR}" ] && [ -d "${BACKUP_DIR}" ]; then
        info "Previous ~/.claude backed up to: ${BACKUP_DIR}"
    fi
else
    echo -e "${RED}${BOLD}✗ Installation has issues — review errors above${RESET}"
    exit 1
fi
