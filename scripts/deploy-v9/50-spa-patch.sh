#!/usr/bin/env bash
# 50-spa-patch.sh — deploy the sub13 admin SPA overlay over public/assets/admin.
#
# Seven files come from frontend-overlay/admin-dist-sub13/ (the same relative
# paths under public/assets/admin/):
#   index.html  manifest.json  w1nc-autorefresh.js
#   assets/index-CxNodesub13.js
#   locales/{zh-CN,en-US,ru-RU}.custom3.js
#
# The real admin entry is resources/views/admin.blade.php, which reads
# public/assets/admin/manifest.json and globs public/assets/admin/locales/*.js.
# Because it globs, the STOCK locales/{zh-CN,en-US,ru-RU}.js sort AFTER the
# *.custom3.js packs (en-US.custom3.js < en-US.js) and would win; they must be
# removed.  This script backs them up before deleting them.
#
# Impact : no restart.  Only a browser that is already open is affected: it
#          keeps the old bundle until the page is reloaded.  No server-side
#          cache is invalidated (no `view:clear` needed — the blade template is
#          unchanged).
# Rollback: restore every overwritten file and delete every added file from the
#          step's backup directory, plus the three stock locales.
#
# Usage:
#   scripts/deploy-v9/50-spa-patch.sh [--dry-run] [--yes]
#   scripts/deploy-v9/50-spa-patch.sh --rollback-only <stage-dir>
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
require_strict_mode

STAGE=""
ROLLBACK_ONLY=0
EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
    --stage)         STAGE="$2"; shift ;;
    --rollback-only) ROLLBACK_ONLY=1 ;;
    *)               EXTRA+=("$1") ;;
  esac
  shift
done
if [ "${#EXTRA[@]}" -gt 0 ]; then parse_common "${EXTRA[@]}"; else parse_common; fi

# local overlay dir -> remote dir mapping (paths are identical on both sides)
readonly SPA_SRC_REL="frontend-overlay/admin-dist-sub13"
readonly SPA_DST_REL="$PANEL_SPA_DIR"

readonly STOCK_LOCALES=(locales/zh-CN.js locales/en-US.js locales/ru-RU.js)

# ---------------------------------------------------------------------------
# rollback path
# ---------------------------------------------------------------------------
if [ "$ROLLBACK_ONLY" = "1" ]; then
  step_begin "50 rollback: admin SPA overlay"
  [ -n "$STAGE" ] || die "--rollback-only needs --stage <dir>"
  guard_path "$STAGE" "the step's backup directory"
  info "restoring $PANEL_ROOT/$SPA_DST_REL from $STAGE"
  restore_files "$PANEL_HOST" "$STAGE" "$PANEL_ROOT/$SPA_DST_REL"
  info "restoring the stock locale files the forward run deleted"
  rsh "$PANEL_HOST" "set -e
STAGE=$(printf '%q' "$STAGE")
BASE=$(printf '%q' "$PANEL_ROOT/$SPA_DST_REL")
for f in $(printf '%q' "${STOCK_LOCALES[*]}"); do
  if [ -f \"\$STAGE/backup/\$f\" ]; then
    mkdir -p \"\$BASE/\$(dirname \"\$f\")\"
    cp -a \"\$STAGE/backup/\$f\" \"\$BASE/\$f\"
    echo \"restored \$f\"
  else
    echo \"no backup for \$f (it was already absent)\"
  fi
done"
  rsh "$PANEL_HOST" "cd $(printf '%q' "$PANEL_ROOT") && chown -R www:www $(printf '%q' "$SPA_DST_REL") 2>/dev/null || true"
  ok "SPA overlay rolled back; hard-reload the admin page in the browser"
  ROLLBACK_HINT="already performed"
  step_end
  exit 0
fi

step_begin "50 admin SPA overlay (sub13)"

# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------
SRC_DIR="$PANEL_SRC/$SPA_SRC_REL"
[ -d "$SRC_DIR" ] || die "missing local overlay: $SRC_DIR"

info "overlay files (local -> remote)"
(cd "$SRC_DIR" && find . -type f | sed 's|^\./||' | sort) | while IFS= read -r f; do
  printf '  %s/%s -> %s/%s\n' "$SPA_SRC_REL" "$f" "$PANEL_ROOT/$SPA_DST_REL" "$f"
done

# The overlay only carries the files the patch changes; the rest of the dist
# (css, fonts, lazy chunks) must already be on the host.
info "the target must already carry the stock css and font the bundle references"
if ! probe_out "$PANEL_HOST" "B=$(printf '%q' "$PANEL_ROOT/$SPA_DST_REL")
for f in assets/index-DiYa-_z_.css assets/codicon-ngg6Pgfi.ttf; do
  printf '%-32s %s\n' \"\$f\" \"\$( [ -f \"\$B/\$f\" ] && echo present || echo MISSING )\"
done
printf 'current_manifest_entry=%s\n' \"\$(grep -oE 'assets/index-[A-Za-z0-9_-]+\\.js' \"\$B/manifest.json\" 2>/dev/null | head -1 || echo none)\"
printf 'stock_locales=%s\n' \"\$(ls -1 \"\$B\"/locales/*.js 2>/dev/null | xargs -n1 basename 2>/dev/null | grep -vE 'custom[0-9]+\\.js\$' | tr '\\n' ' ')\"
printf 'custom_locales=%s\n' \"\$(ls -1 \"\$B\"/locales/*.custom*.js 2>/dev/null | xargs -n1 basename 2>/dev/null | tr '\\n' ' ')\""; then
  die "cannot inspect $PANEL_ROOT/$SPA_DST_REL"
fi

if ! probe_out "$PANEL_HOST" "test -f $(printf '%q' "$PANEL_ROOT/$SPA_DST_REL/assets/index-DiYa-_z_.css")"; then
  warn "assets/index-DiYa-_z_.css is missing on the host: the sub13 layout will render broken."
  warn "copy it from the stock xboard-admin-dist before deploying (docs/PANEL-PATCHES.md §sub13)."
  confirm "Continue anyway?"
fi

# ---------------------------------------------------------------------------
# backup + copy
# ---------------------------------------------------------------------------
if [ -z "$STAGE" ]; then
  STAGE="$(new_stage spa-sub13)"
fi
guard_path "$STAGE" "the step's backup directory"
info "backup directory: $STAGE"

MANIFEST_LOCAL="$(mktemp)"
trap 'rm -f "$MANIFEST_LOCAL"' EXIT
(cd "$SRC_DIR" && find . -type f | sed 's|^\./||' | sort) > "$MANIFEST_LOCAL"
# The stock locales are part of the backup set even though they are not copied.
printf '%s\n' "${STOCK_LOCALES[@]}" >> "$MANIFEST_LOCAL"

confirm "Back up $(wc -l < "$MANIFEST_LOCAL" | tr -d ' ') paths, then copy the overlay and delete the stock locales?"

info "backing up"
backup_files "$PANEL_HOST" "$STAGE" "$PANEL_ROOT/$SPA_DST_REL" < "$MANIFEST_LOCAL"

info "copying the overlay"
tar_manifest "$SRC_DIR" "$PANEL_HOST" "$PANEL_ROOT/$SPA_DST_REL" < <(cd "$SRC_DIR" && find . -type f | sed 's|^\./||' | sort)

info "deleting the stock locales so the *.custom3.js packs win"
rsh "$PANEL_HOST" "set -e
B=$(printf '%q' "$PANEL_ROOT/$SPA_DST_REL")
for f in $(printf '%q' "${STOCK_LOCALES[*]}"); do
  if [ -f \"\$B/\$f\" ]; then rm -f \"\$B/\$f\"; echo \"deleted \$f\"; else echo \"already absent: \$f\"; fi
done
chown -R www:www \"\$B\" 2>/dev/null || true"

# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------
info "post-copy state"
if [ "${DRY_RUN:-0}" = "1" ]; then
  log "[dry-run] verify manifest points at sub13 and no stock locale remains"
else
  STATE="$(rsh "$PANEL_HOST" "B=$(printf '%q' "$PANEL_ROOT/$SPA_DST_REL")
printf 'manifest_entry=%s\n' \"\$(grep -oE 'assets/index-[A-Za-z0-9_-]+\\.js' \"\$B/manifest.json\" | head -1)\"
printf 'sub13_bundle=%s\n' \"\$( [ -f \"\$B/assets/index-CxNodesub13.js\" ] && echo present || echo MISSING )\"
printf 'autorefresh=%s\n' \"\$( [ -f \"\$B/w1nc-autorefresh.js\" ] && echo present || echo MISSING )\"
printf 'custom3_locales=%s\n' \"\$(ls -1 \"\$B\"/locales/*.custom3.js 2>/dev/null | wc -l)\"
printf 'stock_locales=%s\n' \"\$(ls -1 \"\$B\"/locales/zh-CN.js \"\$B\"/locales/en-US.js \"\$B\"/locales/ru-RU.js 2>/dev/null | wc -l)\"")"
  printf '%s\n' "$STATE"
  printf '%s\n' "$STATE" | grep -q 'manifest_entry=assets/index-CxNodesub13.js' || {
    fail "manifest.json does not point at index-CxNodesub13.js; rolling back"
    restore_files "$PANEL_HOST" "$STAGE" "$PANEL_ROOT/$SPA_DST_REL"
    rsh "$PANEL_HOST" "set -e
B=$(printf '%q' "$PANEL_ROOT/$SPA_DST_REL")
for f in $(printf '%q' "${STOCK_LOCALES[*]}"); do
  [ -f \"$(printf '%q' "$STAGE")/backup/\$f\" ] && cp -a \"$(printf '%q' "$STAGE")/backup/\$f\" \"\$B/\$f\" || true
done"
    die "SPA overlay incomplete; the step was rolled back"
  }
  printf '%s\n' "$STATE" | grep -q 'sub13_bundle=present' || die "the sub13 bundle is not on the host"
  printf '%s\n' "$STATE" | grep -q 'custom3_locales=3' || die "expected 3 *.custom3.js locale packs"
  printf '%s\n' "$STATE" | grep -q 'stock_locales=0' || die "a stock locale file survived and would override the patch"
  ok "manifest points at sub13, 3 custom3 packs, 0 stock locales"
fi

info "the referenced css and font must exist (they are NOT part of the overlay)"
probe_out "$PANEL_HOST" "B=$(printf '%q' "$PANEL_ROOT/$SPA_DST_REL"); ls -la \"\$B/assets/index-DiYa-_z_.css\" \"\$B/assets/codicon-ngg6Pgfi.ttf\" 2>&1" || warn "one of the referenced assets is missing"

ok "admin SPA overlay in place"
ROLLBACK_HINT="$HERE/50-spa-patch.sh --rollback-only --stage $STAGE"
ROLLBACK_SCRIPT="$HERE/50-spa-patch.sh --rollback-only --stage $STAGE"
step_end

log ""
log "next: 60-verify-panel.sh."
log "the operator must hard-reload the admin page (Ctrl-F5) to leave the old bundle behind."
