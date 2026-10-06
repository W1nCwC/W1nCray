#!/usr/bin/env bash
# 10-panel-files.sh — copy the panel-side PHP/JS delta into the panel checkout.
#
# Files come from scripts/deploy-v9/panel-files.txt (regenerate it with
# make-panel-manifest.sh).  Nothing is deleted: this step is additions and
# overwrites only.  The legacy UniProxy files that the new tree no longer has
# are handled separately and explicitly — see docs/DEPLOY-v9.md §7.
#
# Impact : no process restart inside this step.  The running Octane workers keep
#          serving the OLD code until step 20 restarts them, so the panel stays
#          up; a file that the old code reads at request time can still be seen
#          mid-copy, which is why the window is kept short (a few seconds).
# Rollback: restore the overwritten files and delete the added ones from the
#          step's backup directory (--rollback-only does exactly that).
#
# Usage:
#   scripts/deploy-v9/10-panel-files.sh [--dry-run] [--yes]
#   scripts/deploy-v9/10-panel-files.sh --rollback-only <stage-dir>
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
require_strict_mode

MANIFEST="$HERE/panel-files.txt"
STAGE=""
ROLLBACK_ONLY=0
EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
    --manifest)      MANIFEST="$2"; shift ;;
    --stage)         STAGE="$2"; shift ;;
    --rollback-only) ROLLBACK_ONLY=1 ;;
    *)               EXTRA+=("$1") ;;
  esac
  shift
done
if [ "${#EXTRA[@]}" -gt 0 ]; then
  parse_common "${EXTRA[@]}"
else
  parse_common
fi

# ---------------------------------------------------------------------------
# rollback path
# ---------------------------------------------------------------------------
if [ "$ROLLBACK_ONLY" = "1" ]; then
  step_begin "10 rollback: panel files"
  [ -n "$STAGE" ] || die "--rollback-only needs --stage <dir> (printed by the forward run)"
  guard_path "$STAGE" "the step's backup directory"
  info "restoring $PANEL_ROOT from $STAGE"
  restore_files "$PANEL_HOST" "$STAGE" "$PANEL_ROOT"
  # restore_files keeps the backed-up owners; never chown the whole tree
  # (.docker/.data/redis belongs to the redis container's user).
  ok "panel files restored; run: docker exec $PANEL_WEB_CONTAINER php artisan octane:reload"
  ROLLBACK_HINT="already performed"
  step_end
  exit 0
fi

step_begin "10 panel files -> $PANEL_ROOT"

# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------
[ -f "$MANIFEST" ] || die "manifest not found: $MANIFEST (run make-panel-manifest.sh)"
check_manifest_local "$PANEL_SRC" "$MANIFEST"

info "checking the remote checkout"
probe_out "$PANEL_HOST" "set -e
cd $(printf '%q' "$PANEL_ROOT")
[ -f artisan ] || { echo 'NOT-A-LARAVEL-CHECKOUT'; exit 1; }
printf 'head=%s\n' \"\$(git rev-parse --short HEAD 2>/dev/null || echo 'no-git')\"
printf 'free_kb=%s\n' \"\$(df -Pk . | awk 'NR==2{print \$4}')\"
printf 'disk_used_pct=%s\n' \"\$(df -P . | awk 'NR==2{print \$5}')\"
printf 'www_uid=%s\n' \"\$(id -u www 2>/dev/null || echo missing)\"" || die "panel checkout probe failed (is $PANEL_ROOT right?)"

# Informational before the copy: new files are expected to be missing here.
check_manifest_remote "$PANEL_HOST" "$PANEL_ROOT" "$MANIFEST" || true

# ---------------------------------------------------------------------------
# backup + copy
# ---------------------------------------------------------------------------
if [ -z "$STAGE" ]; then
  STAGE="$(new_stage panel-files)"
fi
guard_path "$STAGE" "the step's backup directory"
info "backup/staging directory: $STAGE"

confirm "Back up the affected files and copy $(read_manifest "$MANIFEST" | wc -l | tr -d ' ') files into $PANEL_ROOT?"

info "backing up every file of the list that already exists"
write_stage_marker "$PANEL_HOST" "$STAGE" "step 10 panel-files; manifest=$MANIFEST; host=$PANEL_HOST"
backup_files "$PANEL_HOST" "$STAGE" "$PANEL_ROOT" < <(read_manifest "$MANIFEST")

info "streaming the files"
tar_manifest "$PANEL_SRC" "$PANEL_HOST" "$PANEL_ROOT" < <(read_manifest "$MANIFEST")

info "fixing ownership of the copied files only (they are www:www on the host; never a recursive chown:"
info "  .docker/.data/redis belongs to the redis container's user)"
read_manifest "$MANIFEST" | rsh "$PANEL_HOST" "cd $(printf '%q' "$PANEL_ROOT") && while IFS= read -r f; do [ -n \"\$f\" ] && [ -f \"\$f\" ] && chown www:www \"\$f\"; done; echo chown-done"

# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------
info "every manifest entry must now exist on the host"
if [ "${OFFLINE:-0}" = "1" ]; then
  warn "offline: skipping the post-copy presence check"
elif ! check_manifest_remote "$PANEL_HOST" "$PANEL_ROOT" "$MANIFEST"; then
  fail "some files did not land; rolling back"
  restore_files "$PANEL_HOST" "$STAGE" "$PANEL_ROOT"
  die "copy incomplete; the step was rolled back"
fi

info "php -l on every copied .php file (inside the web container)"
PHP_FILES="$(read_manifest "$MANIFEST" | grep -E '\.php$' | sed "s|^|$PANEL_CODE/|" | tr '\n' ' ')"
if [ "${DRY_RUN:-0}" = "1" ]; then
  log "[dry-run] docker exec $PANEL_WEB_CONTAINER sh -c 'for f in ...; do php -l \$f; done'"
else
  # The list can be long; feed it on stdin so the command line stays short.
  if ! printf '%s\n' $PHP_FILES | rsh "$PANEL_HOST" "docker exec -i $(printf '%q' "$PANEL_WEB_CONTAINER") sh -c 'fail=0; while read -r f; do [ -n \"\$f\" ] || continue; php -l \"\$f\" >/dev/null 2>&1 || { echo \"SYNTAX-FAIL \$f\"; fail=1; }; done; exit \$fail'"; then
    fail "php -l rejected a copied file; rolling back"
    restore_files "$PANEL_HOST" "$STAGE" "$PANEL_ROOT"
    die "syntax error in the deployed files; the step was rolled back"
  fi
fi

info "the new artisan commands must be visible (they are not run here)"
probe_out "$PANEL_HOST" "docker exec $(printf '%q' "$PANEL_WEB_CONTAINER") php artisan list 2>&1 | grep -E 'w1ncray:ws-server|agent:manifest|w1ncray:prune-samples' || echo 'COMMANDS-MISSING'" || warn "artisan list failed"

ok "panel files in place; Octane/Horizon still serve the old code"
ROLLBACK_HINT="scripts/deploy-v9/10-panel-files.sh --rollback-only --stage $STAGE"
ROLLBACK_SCRIPT="$HERE/10-panel-files.sh --rollback-only --stage $STAGE"
step_end

log ""
log "next: 20-migrate.sh (adds the new tables/columns)."
log "the containers must NOT be restarted before the migrations are applied."
