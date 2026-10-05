#!/usr/bin/env bash
# install-into-project.sh: set up CASA in the project where the telemetry lives (for example a
# TalonSocLab checkout). Run it from that project's root. Idempotent: safe to run again.
#
#   bash install-into-project.sh [--scope project|local] [--source <marketplace source>] [--ref <tag>]
#
#   --scope   project (default): records the marketplace and plugin in .claude/settings.json, which
#             the project commits, so every clone gets CASA. local: .claude/settings.local.json only.
#   --source  ktalons/casa-ai-agent (default): install from GitHub. A directory path installs that
#             CASA checkout in place, so promoted lessons and reference edits land in the checkout
#             you version. Use the path on the machine where you maintain CASA.
#   --ref     tag or branch of docs/settings.recommended.json to fetch when --source is not a path
#             (default v5.0.1).
#
# What it does: adds the marketplace and installs casa@casa; merges CASA's recommended permission
# block into this project's .claude/settings.json (array union, backup first); creates the output
# directories the plugin writes to; appends a marked block to .gitignore; prints the smoke test.
set -euo pipefail

SCOPE="project"
SOURCE="ktalons/casa-ai-agent"
REF="v5.0.1"
while [ $# -gt 0 ]; do
  case "$1" in
    --scope) SCOPE="$2"; shift 2 ;;
    --source) SOURCE="$2"; shift 2 ;;
    --ref) REF="$2"; shift 2 ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
case "$SCOPE" in project|local) ;; *) echo "--scope must be project or local" >&2; exit 2 ;; esac

say() { printf '[casa] %s\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "[casa] missing: $1" >&2; exit 1; }; }
need claude; need bun; need jq
[ -d .git ] || say "warning: $(pwd) is not a git root; outputs and settings will still be created here"

# 1. Marketplace and plugin. A directory source is passed as an absolute path.
if [ -d "$SOURCE" ]; then
  SOURCE="$(cd "$SOURCE" && pwd)"
  [ -f "$SOURCE/.claude-plugin/plugin.json" ] || { echo "[casa] $SOURCE is not a CASA checkout" >&2; exit 1; }
  RECOMMENDED="$SOURCE/docs/settings.recommended.json"
else
  RECOMMENDED=""
fi
say "adding marketplace from $SOURCE (scope $SCOPE)"
if ! out="$(claude plugin marketplace add "$SOURCE" --scope "$SCOPE" 2>&1)"; then
  if printf '%s' "$out" | grep -qi "already"; then say "marketplace already known"; else printf '%s\n' "$out" >&2; exit 1; fi
fi
say "installing casa@casa"
claude plugin install casa@casa --scope "$SCOPE"

# 2. Permissions: merge the recommended block into .claude/settings.json.
mkdir -p .claude
tmp_rec="$(mktemp)"; trap 'rm -f "$tmp_rec"' EXIT
if [ -n "$RECOMMENDED" ]; then
  cp "$RECOMMENDED" "$tmp_rec"
else
  url="https://raw.githubusercontent.com/ktalons/casa-ai-agent/$REF/docs/settings.recommended.json"
  say "fetching $url"
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$url" -o "$tmp_rec"; else wget -qO "$tmp_rec" "$url"; fi
fi
jq -e '.permissions.allow and .permissions.deny' "$tmp_rec" >/dev/null || { echo "[casa] recommended settings file is not what was expected" >&2; exit 1; }
settings=".claude/settings.json"
[ -f "$settings" ] || printf '{}\n' > "$settings"
cp "$settings" "$settings.bak"
jq -s '
  def union(a; b): ((a // []) + (b // [])) | unique;
  .[0] as $cur | .[1].permissions as $rec
  | $cur
  | .permissions.allow = union($cur.permissions.allow; $rec.allow)
  | .permissions.ask   = union($cur.permissions.ask;   $rec.ask)
  | .permissions.deny  = union($cur.permissions.deny;  $rec.deny)
' "$settings.bak" "$tmp_rec" > "$settings"
# The skills read their own templates and reference tables from the plugin root, which sits
# outside this project, so reads there need an allow rule (the recommended block already
# covers ~/.claude/plugins; a checkout-path install needs its own path).
if [ -n "$RECOMMENDED" ]; then
  rule="Read(/$SOURCE/**)"
  jq --arg r "$rule" '.permissions.allow = ((.permissions.allow // []) + [$r] | unique)' "$settings" > "$settings.tmp" && mv "$settings.tmp" "$settings"
fi
say "permissions merged into $settings (previous copy at $settings.bak)"

# 3. Output directories and .gitignore. Everything CASA writes is run output, never committed,
#    except detections/accepted, which a human fills by hand.
mkdir -p briefs detections/proposed detections/accepted learn/pending learn/archive evals/results engagements
[ -f detections/accepted/.gitkeep ] || : > detections/accepted/.gitkeep
if ! grep -q '^# >>> casa outputs >>>' .gitignore 2>/dev/null; then
  cat >> .gitignore <<'BLOCK'
# >>> casa outputs >>>
briefs/
detections/proposed/
learn/
evals/results/
engagements/
.claude/settings.json.bak
.claude/settings.local.json
# <<< casa outputs <<<
BLOCK
  say "appended the casa block to .gitignore"
fi

# 4. Verify and point at the smoke test.
if claude plugin list 2>/dev/null | grep -q 'casa@casa'; then say "casa@casa is installed"; else echo "[casa] casa@casa not found in claude plugin list" >&2; exit 1; fi
cat <<MSG

Next, from this directory:
  claude -p "/casa:investigate <path to an intake.json>" --permission-mode acceptEdits
The brief lands under briefs/. Proposed detections go to detections/proposed/, learn candidates
to learn/pending/. See docs/talonsoclab-integration.md in the CASA repo for the daily loop.
MSG
