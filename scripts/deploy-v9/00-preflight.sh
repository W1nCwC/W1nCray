#!/usr/bin/env bash
# 00-preflight.sh — read-only reconnaissance of the panel host and the landing
# host.  Changes nothing, needs no confirmation, and is safe to run at any time.
#
# It answers the questions the later steps assume answers to:
#   * are both hosts reachable through the SOCKS5 proxy at all,
#   * which compose services exist, is the legacy ws-server still on 8076,
#   * where is the panel nginx site config and does it already have /w1ncray-ws,
#   * how much free space is there (a deploy without headroom must not start),
#   * which migrations are still pending,
#   * which agent version and config layout the landing host has.
#
# Usage:
#   scripts/deploy-v9/00-preflight.sh [--dry-run] [--offline]
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
require_strict_mode
parse_common "$@"

step_begin "00 preflight (read-only)"

info "panel  : $PANEL_HOST"
info "landing: $LANDING_HOST"
info "proxy  : $PROXY_CMD"
log ""

# ---------------------------------------------------------------------------
# 1. Reachability (a hard gate: the rest of the runbook is meaningless without)
# ---------------------------------------------------------------------------
if probe_out "$PANEL_HOST" "printf 'PANEL-REACHABLE %s %s\n' \"\$(hostname)\" \"\$(date -u +%Y-%m-%dT%H:%M:%SZ)\""; then
  ok "panel host reachable"
else
  die "panel host NOT reachable through the proxy (check PROXY_CMD and the ssh key)"
fi

if probe_out "$LANDING_HOST" "printf 'LANDING-REACHABLE %s %s\n' \"\$(hostname)\" \"\$(date -u +%Y-%m-%dT%H:%M:%SZ)\""; then
  ok "landing host reachable"
else
  die "landing host NOT reachable through the proxy"
fi

if [ "${OFFLINE:-0}" = "1" ]; then
  warn "offline: only the reachability check ran"
  step_end
  exit 0
fi

# ---------------------------------------------------------------------------
# 2. Panel: layout, containers, compose, nginx, migrations
# ---------------------------------------------------------------------------
log ""
info "--- panel layout ---"
probe_out "$PANEL_HOST" "set -e
cd $(printf '%q' "$PANEL_ROOT")
printf 'pwd=%s\n' \"\$(pwd)\"
printf 'artisan=%s\n' \"\$( [ -f artisan ] && echo yes || echo NO )\"
printf 'compose_files=%s\n' \"\$(ls -1 docker-compose.y*ml compose.y*ml 2>/dev/null | tr '\n' ' ')\"
printf 'override_present=%s\n' \"\$( [ -f $(printf '%q' "$PANEL_WS_OVERRIDE") ] && echo yes || echo no )\"
printf 'disk=%s\n' \"\$(df -h . | awk 'NR==2{print \$4\" free, \"\$5\" used\"}')\"" || warn "panel layout probe returned non-zero"

log ""
info "--- containers ---"
probe_out "$PANEL_HOST" "docker ps --format '{{.Names}}|{{.Status}}|{{.Ports}}' | sort" || warn "docker ps failed"

log ""
info "--- compose services (the file the deploy will extend) ---"
probe_out "$PANEL_HOST" "cd $(printf '%q' "$PANEL_ROOT") && docker compose -f $(printf '%q' "$PANEL_COMPOSE_FILE") config --services 2>&1 | sort" || warn "compose config failed"

log ""
info "--- listeners 8076 (legacy, must stay) / 8077 (new gateway) ---"
probe_out "$PANEL_HOST" "ss -tlnp 2>/dev/null | grep -E ':(8076|8077)[[:space:]]' || echo 'neither 8076 nor 8077 is listening on the host'" || true

log ""
info "--- nginx site config ---"
probe_out "$PANEL_HOST" "C=$(printf '%q' "$PANEL_NGINX_CONF")
if [ -f \"\$C\" ]; then
  printf 'nginx_conf=%s (%s lines)\n' \"\$C\" \"\$(wc -l < \"\$C\")\"
  printf 'legacy_ws_location_blocks=%s\n' \"\$(grep -cE 'location[[:space:]]*=[[:space:]]*/ws[[:space:]]*\\{' \"\$C\" || true)\"
  printf 'w1ncray_ws_location_blocks=%s\n' \"\$(grep -cE 'location[[:space:]]*=[[:space:]]*/w1ncray-ws' \"\$C\" || true)\"
  printf 'proxy_pass_to_7001=%s\n' \"\$(grep -cE 'proxy_pass[^;]*127\\.0\\.0\\.1:7001' \"\$C\" || true)\"
  grep -nE '^[[:space:]]*(listen|server_name)' \"\$C\" || true
else
  printf 'nginx_conf=%s MISSING\n' \"\$C\"
  printf 'candidates:\n'
  ls -1 /www/server/panel/vhost/nginx/*.conf 2>/dev/null | head -20 || true
fi" || warn "nginx probe returned non-zero"

log ""
info "--- pending migrations ---"
probe_out "$PANEL_HOST" "docker exec $(printf '%q' "$PANEL_WEB_CONTAINER") php artisan migrate:status 2>&1 | grep -iE 'pending|2026_10' || echo 'no 2026_10 lines in migrate:status'" || warn "migrate:status failed (is $PANEL_WEB_CONTAINER running?)"

log ""
info "--- new artisan commands (absent before step 10) ---"
probe_out "$PANEL_HOST" "docker exec $(printf '%q' "$PANEL_WEB_CONTAINER") php artisan list 2>&1 | grep -E 'w1ncray|agent:' || echo 'NOT PRESENT YET (expected before step 10)'" || warn "artisan list failed"

log ""
info "--- redis cache driver seen by the web container ---"
probe_out "$PANEL_HOST" "docker exec $(printf '%q' "$PANEL_WEB_CONTAINER") php -r 'echo \"CACHE_DRIVER=\".(getenv(\"CACHE_DRIVER\")?:\"(unset)\").PHP_EOL;' 2>&1 || true
grep -nE '^[[:space:]]*CACHE_DRIVER' $(printf '%q' "$PANEL_ROOT")/.env 2>/dev/null || echo 'no CACHE_DRIVER line in .env'" || true

# ---------------------------------------------------------------------------
# 3. Landing: agent version, config layout, unit, listeners
# ---------------------------------------------------------------------------
log ""
info "--- landing agent ---"
probe_out "$LANDING_HOST" "printf 'version: '; $(printf '%q' "$LANDING_BIN") version 2>&1 | head -1 || echo 'binary missing'
printf 'unit: %s\n' \"\$(systemctl is-active $(printf '%q' "$LANDING_SERVICE") 2>&1 || true)\"
printf 'enabled: %s\n' \"\$(systemctl is-enabled $(printf '%q' "$LANDING_SERVICE") 2>/dev/null || true)\"
printf -- '--- config dir ---\n'
ls -la $(printf '%q' "$LANDING_CONF_DIR") 2>&1 | head -20
printf 'agent.yml=%s\n' \"\$( [ -f $(printf '%q' "$LANDING_CONF_DIR")/agent.yml ] && echo present || echo absent )\"
printf 'token_file=%s\n' \"\$( [ -f $(printf '%q' "$LANDING_TOKEN_FILE") ] && echo present || echo absent )\"
printf 'static_nodes=%s\n' \"\$(grep -cE '^[[:space:]]*Nodes:' $(printf '%q' "$LANDING_CONF_DIR")/config.yml 2>/dev/null || echo 0)\"
printf 'legacy_agent_block=%s\n' \"\$(grep -cE '^[[:space:]]*Agent:' $(printf '%q' "$LANDING_CONF_DIR")/config.yml 2>/dev/null || echo 0)\"
printf 'terminal_key=%s\n' \"\$(grep -cE '^[[:space:]]*Terminal:' $(printf '%q' "$LANDING_CONF_DIR")/agent.yml 2>/dev/null || echo 0)\"
df -h /usr/local /etc | awk 'NR==1 || /\\//{print}'" || warn "landing probe returned non-zero"

log ""
info "--- landing listeners (2083 / 65533 / 65535) ---"
probe_out "$LANDING_HOST" "ss -tlnp 2>/dev/null | grep -E ':(2083|65533|65535)[[:space:]]' || echo 'expected ports 2083/65533/65535 are NOT listening'" || true

# ---------------------------------------------------------------------------
# 4. Summary
# ---------------------------------------------------------------------------
log ""
log "preflight summary"
log "  panel   root : $PANEL_ROOT   (container code: $PANEL_CODE)"
log "  landing bin  : $LANDING_BIN"
log "  nginx conf   : $PANEL_NGINX_CONF"
log "  next         : answer the confirmations in docs/DEPLOY-v9.md section 0,"
log "                 then run 10-panel-files.sh"
log ""
ok "preflight finished (nothing was changed)"

ROLLBACK_HINT="none — this step is read-only"
step_end
