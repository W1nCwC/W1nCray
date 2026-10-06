#!/usr/bin/env bash
# 20-migrate.sh — apply the four new migrations and prove they landed.
#
# Why this order (files first, migrations second, restart third): the running
# Octane/Horizon processes keep the route table and the compiled classes they
# booted with.  Copying new files under them is invisible until the restart in
# step 30, so there is no window where a live request hits a controller that
# needs a table which does not exist yet.
#
# Migrations applied here:
#   2026_10_06_100000_agent_telemetry
#   2026_10_07_000001_agent_terminal_sessions
#   2026_10_07_000002_agent_managed_files
#   2026_10_07_000003_agent_host_sample_extend
# All four are additive, guarded by hasTable/hasColumn, and all four define
# down(); see docs/DEPLOY-v9.md §2 for the column-level detail.
#
# Impact : no restart.  Additive DDL on the v2_agent_* tables only.
# Rollback: `php artisan migrate:rollback --step=4 --force` (drops
#          v2_agent_host_sample, v2_agent_terminal_session, v2_agent_file* and
#          the new columns) plus the operator's own database dump.
#
# A database dump is NOT taken here on purpose: this script must not have to
# guess where MySQL lives (container or host) or how the operator backs it up.
# Set DB_DUMP_CMD to a command that runs ON THE PANEL HOST and writes a dump;
# it is executed verbatim, and its output path is only printed.
#
# Usage:
#   scripts/deploy-v9/20-migrate.sh [--dry-run] [--yes]
#   DB_DUMP_CMD='docker exec xboard-web-1 mysqldump ... | gzip > /root/panel.sql.gz' \
#     scripts/deploy-v9/20-migrate.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
require_strict_mode
parse_common "$@"

: "${DB_DUMP_CMD:=}"

step_begin "20 database migrations"

MIGRATIONS=(
  2026_10_06_100000_agent_telemetry
  2026_10_07_000001_agent_terminal_sessions
  2026_10_07_000002_agent_managed_files
  2026_10_07_000003_agent_host_sample_extend
)

# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------
info "the four migration files must already be in the container (step 10)"
missing=0
for m in "${MIGRATIONS[@]}"; do
  if ! probe_out "$PANEL_HOST" "docker exec $(printf '%q' "$PANEL_WEB_CONTAINER") test -f $(printf '%q' "$PANEL_CODE/database/migrations/$m.php")"; then
    fail "missing in the container: $PANEL_CODE/database/migrations/$m.php"
    missing=$((missing + 1))
  fi
done
[ "$missing" -eq 0 ] || die "$missing migration file(s) missing — run 10-panel-files.sh first"
ok "all four migration files are in the container"

info "migrate:status before"
probe_out "$PANEL_HOST" "docker exec $(printf '%q' "$PANEL_WEB_CONTAINER") php artisan migrate:status 2>&1 | grep -E '2026_10_0[67]' || echo 'no 2026_10_06/07 rows yet'" || warn "migrate:status failed"

# ---------------------------------------------------------------------------
# operator-provided database dump
# ---------------------------------------------------------------------------
if [ -n "$DB_DUMP_CMD" ]; then
  info "operator database dump command: $DB_DUMP_CMD"
  confirm "Run the operator's database dump command on the panel host?"
  rsh "$PANEL_HOST" "$DB_DUMP_CMD" || warn "the dump command returned non-zero; decide before migrating"
else
  warn "no DB_DUMP_CMD set: no database dump is taken."
  warn "the rollback for this step is the migrations' own down() methods, which"
  warn "drop the two new tables and the new columns.  Set DB_DUMP_CMD if you"
  warn "want a data-level fallback as well."
fi

# ---------------------------------------------------------------------------
# migrate
# ---------------------------------------------------------------------------
confirm "Run 'php artisan migrate --force' in $PANEL_WEB_CONTAINER?"
info "migrating"
if [ "${DRY_RUN:-0}" = "1" ]; then
  log "[dry-run] docker exec $PANEL_WEB_CONTAINER php artisan migrate --force"
else
  if ! rsh "$PANEL_HOST" "docker exec $(printf '%q' "$PANEL_WEB_CONTAINER") php artisan migrate --force 2>&1 | tail -40"; then
    die "migrate --force returned non-zero; do NOT restart the containers, fix the cause first"
  fi
fi

# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------
info "migrate:status after (no 2026_10_06/07 row may still be pending)"
if [ "${DRY_RUN:-0}" = "1" ]; then
  log "[dry-run] docker exec $PANEL_WEB_CONTAINER php artisan migrate:status"
else
  STATUS="$(rsh "$PANEL_HOST" "docker exec $(printf '%q' "$PANEL_WEB_CONTAINER") php artisan migrate:status 2>&1 | grep -E '2026_10_0[67]' || true")"
  printf '%s\n' "$STATUS"
  if printf '%s\n' "$STATUS" | grep -qi 'pending'; then
    die "a 2026_10_06/07 migration is still pending"
  fi
  printf '%s\n' "$STATUS" | grep -q '2026_10_07_000003' || die "2026_10_07_000003 is not in migrate:status — did the file land?"
  ok "no pending 2026_10_06/07 migration"
fi

info "the new tables must answer a query"
if [ "${DRY_RUN:-0}" = "1" ]; then
  log "[dry-run] SELECT COUNT(*) FROM v2_agent_host_sample / v2_agent_terminal_session / v2_agent_file"
else
  rsh "$PANEL_HOST" "docker exec $(printf '%q' "$PANEL_WEB_CONTAINER") php artisan tinker --execute='
foreach ([\"v2_agent_host_sample\",\"v2_agent_terminal_session\",\"v2_agent_file\",\"v2_agent_file_blob\",\"v2_agent_file_version\"] as \$t) {
  try { \$n = \\DB::table(\$t)->count(); printf(\"table %-28s ok (%d rows)\\n\", \$t, \$n); }
  catch (\\Throwable \$e) { printf(\"table %-28s FAIL %s\\n\", \$t, \$e->getMessage()); }
}
printf(\"machine_state.kernel_entries %s\\n\", \\Schema::hasColumn(\"v2_agent_machine_state\",\"kernel_entries\") ? \"ok\" : \"MISSING\");
printf(\"host_sample.swap_total %s\\n\", \\Schema::hasColumn(\"v2_agent_host_sample\",\"swap_total\") ? \"ok\" : \"MISSING\");
' 2>&1 | grep -E 'ok|MISSING|FAIL'" || warn "table probe failed (inspect manually)"
fi

ok "migrations applied"
ROLLBACK_HINT="docker exec $PANEL_WEB_CONTAINER php artisan migrate:rollback --step=4 --force"
[ -n "$DB_DUMP_CMD" ] && ROLLBACK_HINT="$ROLLBACK_HINT   (plus the operator dump)"
ROLLBACK_SCRIPT="docker exec $PANEL_WEB_CONTAINER php artisan migrate:rollback --step=4 --force"
step_end

log ""
log "next: 30-gateway-service.sh (starts w1ncray-ws, restarts web+horizon)."
