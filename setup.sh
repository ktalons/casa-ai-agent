#!/usr/bin/env bash
# CASA Setup Script
# Links the Cybersecurity Analysis Support Agent (CASA) into ~/.claude/
#
# This creates a symlink from ~/.claude → <repo>/.claude/ so that:
#   - git pull updates CASA automatically
#   - Your user config (settings.json, .env) stays local and gitignored
#
# Usage:
#   gh repo clone CASA-Capstone-AI-Research-Project/CASA
#   cd CASA && bash setup.sh
#
# Flags:
#   --validate    Check repo structure without making any changes (dry run)

set -euo pipefail

# ─────────────────────────────────────────────────────────────
# Flags
# ─────────────────────────────────────────────────────────────
VALIDATE_ONLY=false
if [ "${1:-}" = "--validate" ]; then
    VALIDATE_ONLY=true
fi

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
# Helpers
# ─────────────────────────────────────────────────────────────

# Cross-platform check: is port 8888 already in use?
port_in_use() {
    if command -v lsof &>/dev/null; then
        lsof -ti:8888 &>/dev/null 2>&1
    elif command -v nc &>/dev/null; then
        nc -z 127.0.0.1 8888 &>/dev/null 2>&1
    else
        return 1  # Can't determine; assume not running
    fi
}

# ─────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${RESET}"
echo -e "${CYAN}${BOLD}┃${RESET}                   ${BOLD}CASA Setup${RESET}                                  ${CYAN}${BOLD}┃${RESET}"
echo -e "${CYAN}${BOLD}┃${RESET}      ${GRAY}Cybersecurity Analysis Support Agent v3.0${RESET}               ${CYAN}${BOLD}┃${RESET}"
echo -e "${CYAN}${BOLD}┃${RESET}      ${GRAY}Built on PAI Framework (Algorithm v1.2.0)${RESET}               ${CYAN}${BOLD}┃${RESET}"
echo -e "${CYAN}${BOLD}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${RESET}"
echo ""

if [ "${VALIDATE_ONLY}" = true ]; then
    echo -e "  ${YELLOW}${BOLD}[VALIDATE MODE]${RESET} ${YELLOW}Checking structure only — no changes will be made${RESET}"
    echo ""
fi

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

# Core CASA agents (v3.0: includes Pentester)
for agent in Overseer LogAnalyst NetworkAnalyst PurpleTeamMapper Pentester; do
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

# CyberAnalysis explainability doc (v3.0)
if [ -f "${REPO_CLAUDE_DIR}/skills/CyberAnalysis/ExplainabilityStandards.md" ]; then
    ok "CyberAnalysis: ExplainabilityStandards.md"
else
    err "Missing: skills/CyberAnalysis/ExplainabilityStandards.md"
    exit 1
fi

# Cybersecurity-specific skills (v3.0 additions — warn only)
for skill in PromptInjection Recon WebAssessment SECUpdates OSINT AnnualReports; do
    if [ -d "${REPO_CLAUDE_DIR}/skills/${skill}" ]; then
        ok "Skill: ${skill}"
    else
        warn "Skill missing: skills/${skill}/ (expected in v3.0)"
    fi
done

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
    info "  See: https://docs.anthropic.com/en/docs/claude-code"
    info "  or:  npm install -g @anthropic-ai/claude-code"
    echo ""
    exit 1
fi

# Check for Python 3 (used for JSON config generation)
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1)
    ok "Python 3: ${PYTHON_VERSION}"
else
    err "Python 3 not found (required for settings.json generation)"
    info "Install python3 via your system package manager:"
    info "  macOS:  brew install python3   (or it ships with Xcode CLI tools)"
    info "  Debian: sudo apt install python3"
    info "  RHEL:   sudo dnf install python3"
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

# Early exit for validate mode — Steps 3 & 4 are skipped
if [ "${VALIDATE_ONLY}" = true ]; then
    echo ""
    info "Validate mode: skipping symlink and personalization (Steps 3–4)"
    echo ""
    # Jump directly to Step 5 validation
    # (use current TARGET if it exists, otherwise check repo structure only)
    EFFECTIVE_TARGET="${TARGET}"
    if [ ! -L "${EFFECTIVE_TARGET}" ] && [ ! -d "${EFFECTIVE_TARGET}" ]; then
        EFFECTIVE_TARGET="${REPO_CLAUDE_DIR}"
    fi
else
    EFFECTIVE_TARGET="${TARGET}"
fi

# ─────────────────────────────────────────────────────────────
# Step 3: Link ~/.claude → repo/.claude/
# ─────────────────────────────────────────────────────────────
if [ "${VALIDATE_ONLY}" = false ]; then
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
fi

# ─────────────────────────────────────────────────────────────
# Step 4: Generate user config
# ─────────────────────────────────────────────────────────────
if [ "${VALIDATE_ONLY}" = false ]; then
    echo ""
    echo -e "${BOLD}Step 4/5 — Personalization${RESET}"
    echo -e "${GRAY}─────────────────────────────────────────────────${RESET}"

    # Ensure runtime directories exist (gitignored, user-specific)
    for dir in MEMORY/STATE MEMORY/LEARNING MEMORY/WORK MEMORY/RESEARCH Plans WORK; do
        mkdir -p "${REPO_CLAUDE_DIR}/${dir}"
    done
    ok "Created runtime directories"

    # Set permissions on scripts
    find "${REPO_CLAUDE_DIR}" -name "*.ts" -exec chmod 755 {} +
    find "${REPO_CLAUDE_DIR}" -name "*.sh" -exec chmod 755 {} +
    ok "Set script permissions"

    # Generate settings.json if it doesn't exist
    SETTINGS_FILE="${REPO_CLAUDE_DIR}/settings.json"

    if [ -f "${SETTINGS_FILE}" ]; then
        ok "settings.json already exists (keeping current config)"
        info "To reconfigure: rm .claude/settings.json && bash setup.sh"
    else
        echo ""
        echo -e "  ${BOLD}Let's personalize CASA for you.${RESET}"
        echo ""

        # Analyst name
        read -rp "  Your name (for analyst identity) [Analyst]: " USER_NAME
        USER_NAME="${USER_NAME:-Analyst}"

        # Timezone (auto-detect then confirm)
        DETECTED_TZ=""
        if command -v python3 &> /dev/null; then
            DETECTED_TZ=$(python3 -c "import datetime; print(datetime.datetime.now().astimezone().tzinfo)" 2>/dev/null || echo "")
        fi
        if [ -z "${DETECTED_TZ}" ]; then
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

        # Voice type selection (v3.0 — ElevenLabs pre-made voices)
        echo ""
        echo -e "  ${BOLD}Voice Type${RESET} ${GRAY}(used when ElevenLabs is configured)${RESET}"
        echo -e "    ${CYAN}1${RESET}) Female — Rachel (default)"
        echo -e "    ${CYAN}2${RESET}) Male   — Adam"
        echo -e "    ${CYAN}3${RESET}) Neutral — Antoni"
        read -rp "  Choose [1/2/3]: " VOICE_CHOICE
        case "${VOICE_CHOICE:-1}" in
            2) VOICE_ID="pNInz6obpgDQGcFmaJgB" ; VOICE_NAME="Male (Adam)" ;;
            3) VOICE_ID="ErXwobaYiN019PkySvjV" ; VOICE_NAME="Neutral (Antoni)" ;;
            *) VOICE_ID="21m00Tcm4TlvDq8ikWAM" ; VOICE_NAME="Female (Rachel)" ;;
        esac

        # Build settings.json from CASA template
        cp "${REPO_CLAUDE_DIR}/settings.template.json" "${SETTINGS_FILE}"

        # Patch user values into settings.json using env vars (safe for special chars)
        SETUP_SETTINGS_FILE="${SETTINGS_FILE}" \
        SETUP_PAI_DIR="${REPO_CLAUDE_DIR}" \
        SETUP_USER_NAME="${USER_NAME}" \
        SETUP_USER_TZ="${USER_TZ}" \
        SETUP_AI_NAME="${AI_NAME}" \
        SETUP_VOICE_ID="${VOICE_ID}" \
        python3 << 'PYEOF'
import json, os

sf  = os.environ['SETUP_SETTINGS_FILE']
with open(sf, 'r') as f:
    s = json.load(f)

ai = os.environ['SETUP_AI_NAME']

s['env']['PAI_DIR']                      = os.environ['SETUP_PAI_DIR']
s['principal']['name']                   = os.environ['SETUP_USER_NAME']
s['principal']['timezone']               = os.environ['SETUP_USER_TZ']
s['daidentity']['name']                  = ai
s['daidentity']['fullName']              = f"{ai} - Cybersecurity Analysis Support Agent"
s['daidentity']['displayName']           = ai
s['daidentity']['voiceId']               = os.environ['SETUP_VOICE_ID']
s['daidentity']['startupCatchphrase']    = f"{ai} ready. How can I assist your investigation?"

with open(sf, 'w') as f:
    json.dump(s, f, indent=2)
    f.write('\n')
PYEOF

        # Validate the written file is valid JSON
        if python3 -c "import json; json.load(open('${SETTINGS_FILE}'))" 2>/dev/null; then
            ok "Generated settings.json (validated)"
        else
            err "settings.json write failed or produced invalid JSON"
            rm -f "${SETTINGS_FILE}"
            exit 1
        fi

        info "Analyst:  ${USER_NAME}"
        info "AI Name:  ${AI_NAME}"
        info "Timezone: ${USER_TZ}"
        info "Voice:    ${VOICE_NAME}"
        info "PAI_DIR:  ${REPO_CLAUDE_DIR}"
    fi

    # ── .env: create documented template for new users ─────────────
    ENV_FILE="${REPO_CLAUDE_DIR}/.env"
    ELEVENLABS_KEY=""

    if [ ! -f "${ENV_FILE}" ]; then
        echo ""
        echo -e "  ${BOLD}Optional: Voice support (ElevenLabs)${RESET}"
        echo -e "  ${GRAY}Voice is optional — press Enter to skip and configure later.${RESET}"
        read -rp "  ElevenLabs API key [skip]: " ELEVENLABS_KEY

        # Write documented .env template regardless of key entry
        cat > "${ENV_FILE}" << ENVEOF
# ─────────────────────────────────────────────────────────────────
# CASA Environment Configuration
# This file is gitignored. Set your personal API keys here.
# Hooks and services load this file automatically.
# ─────────────────────────────────────────────────────────────────

# ElevenLabs API key for voice synthesis (optional)
# Get yours at: https://elevenlabs.io
ELEVENLABS_API_KEY=${ELEVENLABS_KEY}

# Timezone for log timestamps in hooks
# Use IANA format: America/New_York, Europe/London, Asia/Tokyo, UTC
# Defaults to America/Los_Angeles if not set
TIME_ZONE=

# Voice ID override (optional — overrides the voice selected during setup)
# Pre-made voices: Rachel=21m00Tcm4TlvDq8ikWAM  Adam=pNInz6obpgDQGcFmaJgB
PAI_VOICE_ID=
ENVEOF

        if [ -n "${ELEVENLABS_KEY}" ]; then
            ok "Created .claude/.env with ElevenLabs API key"
        else
            ok "Created .claude/.env template (gitignored)"
            info "Add ELEVENLABS_API_KEY to .claude/.env when ready"
        fi
    else
        ok ".env already exists (keeping current config)"
        # Read existing key for voice server startup below
        if grep -q "^ELEVENLABS_API_KEY=." "${ENV_FILE}" 2>/dev/null; then
            ELEVENLABS_KEY=$(grep "^ELEVENLABS_API_KEY=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '[:space:]')
        fi
    fi

    # ── Voice server startup (v3.0) ─────────────────────────────────
    VOICE_START="${REPO_CLAUDE_DIR}/VoiceServer/start.sh"
    if [ -n "${ELEVENLABS_KEY}" ] && [ -f "${VOICE_START}" ]; then
        echo ""
        echo -e "  ${BOLD}Voice Server${RESET}"
        if port_in_use; then
            ok "Voice server already running on port 8888"
        else
            info "Starting voice server..."
            chmod +x "${VOICE_START}"
            bash "${VOICE_START}" &>/dev/null &
            sleep 2
            if port_in_use; then
                ok "Voice server started on port 8888"
            else
                warn "Voice server may still be starting"
                info "If voice isn't working: bash .claude/VoiceServer/start.sh"
            fi
        fi
    elif [ -n "${ELEVENLABS_KEY}" ] && [ ! -f "${VOICE_START}" ]; then
        warn "VoiceServer/start.sh not found — voice server not available"
    fi
fi  # end VALIDATE_ONLY=false

# ─────────────────────────────────────────────────────────────
# Step 5: Validate
# ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Step 5/5 — Validating installation${RESET}"
echo -e "${GRAY}─────────────────────────────────────────────────${RESET}"

PASS=true

# Symlink (skip check in validate mode if ~/.claude doesn't exist yet)
if [ "${VALIDATE_ONLY}" = false ]; then
    if [ -L "${TARGET}" ] && [ "$(readlink "${TARGET}")" = "${REPO_CLAUDE_DIR}" ]; then
        ok "Symlink: ~/.claude → repo"
    else
        err "Symlink not set correctly"
        PASS=false
    fi
else
    info "Symlink: skipped (validate mode)"
fi

# Core files (check in repo dir directly in validate mode)
CHECK_BASE="${REPO_CLAUDE_DIR}"
for f in CLAUDE.md INSTALL.ts settings.template.json statusline-command.sh; do
    if [ -f "${CHECK_BASE}/${f}" ]; then
        ok "File: ${f}"
    else
        err "Missing: ${f}"
        PASS=false
    fi
done

# settings.json (only exists post-install, skip in validate mode)
if [ "${VALIDATE_ONLY}" = false ]; then
    if [ -f "${CHECK_BASE}/settings.json" ]; then
        ok "File: settings.json"
    else
        err "Missing: settings.json"
        PASS=false
    fi
else
    info "File: settings.json (skipped — not yet generated)"
fi

# CASA agents (v3.0: includes Pentester)
for agent in Overseer LogAnalyst NetworkAnalyst PurpleTeamMapper Pentester; do
    if [ -f "${CHECK_BASE}/agents/${agent}.md" ]; then
        ok "Agent: ${agent}"
    else
        err "Agent missing: ${agent}"
        PASS=false
    fi
done

# CyberAnalysis skill + core docs
if [ -f "${CHECK_BASE}/skills/CyberAnalysis/SKILL.md" ]; then
    ok "Skill: CyberAnalysis"
else
    err "Skill missing: CyberAnalysis"
    PASS=false
fi

if [ -f "${CHECK_BASE}/skills/CyberAnalysis/ExplainabilityStandards.md" ]; then
    ok "CyberAnalysis: ExplainabilityStandards.md"
else
    err "Missing: skills/CyberAnalysis/ExplainabilityStandards.md"
    PASS=false
fi

# CyberAnalysis workflows
for wf in AuthAnomalyInvestigation NetworkBeaconingDetection DataExfiltrationAnalysis LateralMovementDetection; do
    if [ -f "${CHECK_BASE}/skills/CyberAnalysis/Workflows/${wf}.md" ]; then
        ok "Workflow: ${wf}"
    else
        err "Workflow missing: ${wf}"
        PASS=false
    fi
done

# PAI framework
if [ -f "${CHECK_BASE}/skills/PAI/SKILL.md" ]; then
    ok "PAI framework: present"
else
    err "PAI framework: missing skills/PAI/SKILL.md"
    PASS=false
fi

# Hooks referenced in settings.template.json (v3.0)
for hook in FormatReminder AutoWorkCreation ExplicitRatingCapture ImplicitSentimentCapture \
            UpdateTabTitle StartupGreeting LoadContext CheckVersion StopOrchestrator \
            AgentOutputCapture; do
    if [ -f "${CHECK_BASE}/hooks/${hook}.hook.ts" ]; then
        ok "Hook: ${hook}"
    else
        err "Hook missing: hooks/${hook}.hook.ts"
        PASS=false
    fi
done

# Cybersecurity-specific skills (v3.0 — warn only)
for skill in PromptInjection Recon WebAssessment SECUpdates OSINT AnnualReports; do
    if [ -d "${CHECK_BASE}/skills/${skill}" ]; then
        ok "Skill: ${skill}"
    else
        warn "Skill missing: skills/${skill}/"
    fi
done

# Key directories
for dir in skills agents hooks MEMORY; do
    if [ -d "${CHECK_BASE}/${dir}" ]; then
        ok "Directory: ${dir}/"
    else
        err "Directory missing: ${dir}/"
        PASS=false
    fi
done

# settings.json PAI_DIR check (only meaningful post-install)
if [ "${VALIDATE_ONLY}" = false ] && [ -f "${CHECK_BASE}/settings.json" ]; then
    PAI_DIR_VAL=$(python3 -c "
import json
with open('${CHECK_BASE}/settings.json') as f:
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
if [ "${VALIDATE_ONLY}" = true ]; then
    if [ "${PASS}" = true ]; then
        echo -e "${GREEN}${BOLD}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${RESET}"
        echo -e "${GREEN}${BOLD}┃${RESET}  ${GREEN}✓ CASA v3.0 repo is valid — ready to install!${RESET}               ${GREEN}${BOLD}┃${RESET}"
        echo -e "${GREEN}${BOLD}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${RESET}"
        echo ""
        info "Run ${CYAN}bash setup.sh${RESET} to complete the full installation"
    else
        echo -e "${RED}${BOLD}✗ Repo validation failed — review errors above${RESET}"
        exit 1
    fi
elif [ "${PASS}" = true ]; then
    echo -e "${GREEN}${BOLD}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${RESET}"
    echo -e "${GREEN}${BOLD}┃${RESET}  ${GREEN}✓ CASA v3.0 installed successfully!${RESET}                         ${GREEN}${BOLD}┃${RESET}"
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
    echo -e "    ${GRAY}\"Run a prompt injection assessment on this chatbot\"${RESET}"
    echo -e "    ${GRAY}\"Search OSINT for this IP / domain\"${RESET}"
    echo ""
    echo -e "  ${BOLD}Agents available:${RESET}"
    echo -e "    ${GREEN}Overseer${RESET}         — Routes queries to specialized agents"
    echo -e "    ${CYAN}LogAnalyst${RESET}       — Log investigation (NIST SP 800-92)"
    echo -e "    ${CYAN}NetworkAnalyst${RESET}   — PCAP and flow analysis"
    echo -e "    ${CYAN}PurpleTeamMapper${RESET} — Maps findings to NIST CSF 2.0"
    echo -e "    ${CYAN}Pentester${RESET}        — Authorized vulnerability assessment"
    echo ""
    echo -e "  ${BOLD}Configuration:${RESET}"
    echo -e "    ${GRAY}API keys / voice:  ${CYAN}.claude/.env${RESET}"
    echo -e "    ${GRAY}Reconfigure:       ${CYAN}rm .claude/settings.json && bash setup.sh${RESET}"
    echo -e "    ${GRAY}Full PAI wizard:   ${CYAN}bun .claude/INSTALL.ts${RESET}"
    echo -e "    ${GRAY}Voice server:      ${CYAN}bash .claude/VoiceServer/start.sh${RESET}"
    echo ""
    if [ -n "${BACKUP_DIR}" ] && [ -d "${BACKUP_DIR}" ]; then
        info "Previous ~/.claude backed up to: ${BACKUP_DIR}"
    fi
else
    echo -e "${RED}${BOLD}✗ Installation has issues — review errors above${RESET}"
    exit 1
fi
