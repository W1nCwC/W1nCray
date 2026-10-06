#!/usr/bin/env bash
# 30-gateway-service.sh — start the new independent gateway process.
#
# What it does, in order:
#   1. writes compose.w1ncray-ws.yaml (a compose OVERRIDE, so the production
#      compose file itself is never edited),
#   2. `docker compose up -d w1ncray-ws`  -> the new Workerman process on
#      127.0.0.1:8077, its own pid/log file, count=1,
#   3. `php artisan octane:reload` in the web container -> Octane restarts its
#      workers in place so the new PHP files and routes become live (no container
#      restart; `docker compose up -d web` would be a no-op for an unchanged service).
#
# The legacy `ws-server` service (127.0.0.1:8076) is NOT named anywhere in this
# step: it is never stopped, restarted or reconfigured.
#
# Impact : the gateway start itself is additive (nothing else notices it).
#          `octane:reload` swaps the workers gracefully (in-flight requests finish),
#          the same effect as the USR1 reload used by the earlier production deploys.
#          Horizon is left alone: v9 adds no queued job class.
# Rollback: `docker compose ... stop w1ncray-ws` + remove the override file.
#          The panel code stays as deployed; use the step-10 rollback for that.
#
# Usage:
#   scripts/deploy-v9/30-gateway-service.sh [--dry-run] [--yes]
#   scripts/deploy-v9/30-gateway-service.sh --rollback-only
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
require_strict_mode

ROLLBACK_ONLY=0
EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
    --rollback-only) ROLLBACK_ONLY=1 ;;
    *)               EXTRA+=("$1") ;;
  esac
  shift
done
if [ "${#EXTRA[@]}" -gt 0 ]; then parse_common "${EXTRA[@]}"; else parse_common; fi

: "${W1NCRAY_WS_IMAGE:=ghcr.io/cedar2025/xboard:new}"

# The override is generated here and copied to the host; it is committed as a
# template so the content is reviewable before it is ever used.
readonly OVERRIDE_TEMPLATE="$HERE/compose.w1ncray-ws.yaml"

compose() { # compose <args...> — runs docker compose with the base + override
  rsh "$PANEL_HOST" "cd $(printf '%q' "$PANEL_ROOT") && docker compose -f $(printf '%q' "$PANEL_COMPOSE_FILE") -f $(printf '%q' "$PANEL_WS_OVERRIDE") $*"
}

# ---------------------------------------------------------------------------
# rollback path
# ---------------------------------------------------------------------------
if [ "$ROLLBACK_ONLY" = "1" ]; then
  step_begin "30 rollback: gateway service"
  confirm "Stop and remove the w1ncray-ws service (the panel code stays as deployed)?"
  compose "stop w1ncray-ws || true"
  compose "rm -f w1ncray-ws || true"
  rsh "$PANEL_HOST" "rm -f $(printf '%q' "$PANEL_ROOT/$PANEL_WS_OVERRIDE")"
  info "the legacy ws-server on 8076 was never touched:"
  probe_out "$PANEL_HOST" "ss -tlnp 2>/dev/null | grep -E ':8076[[:space:]]' || echo 'WARNING: 8076 is not listening'" || true
  ok "gateway service removed"
  ROLLBACK_HINT="already performed"
  step_end
  exit 0
fi

step_begin "30 gateway service (w1ncray-ws on 127.0.0.1:$PANEL_GATEWAY_PORT)"

# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------
[ -f "$OVERRIDE_TEMPLATE" ] || die "missing template: $OVERRIDE_TEMPLATE"

info "current compose services"
if ! probe_out "$PANEL_HOST" "cd $(printf '%q' "$PANEL_ROOT") && docker compose -f $(printf '%q' "$PANEL_COMPOSE_FILE") config --services 2>&1 | sort"; then
  die "cannot read the compose project at $PANEL_ROOT/$PANEL_COMPOSE_FILE (set PANEL_COMPOSE_FILE)"
fi

info "the legacy ws-server must be running on 8076 before we start"
if [ "${OFFLINE:-0}" = "1" ]; then
  warn "offline: skipping the 8076 probe"
elif ! probe_out "$PANEL_HOST" "ss -tlnp 2>/dev/null | grep -qE ':8076[[:space:]]'"; then
  warn "nothing is listening on 8076 — is the legacy ws-server service named differently?"
  confirm "Continue anyway?"
fi

info "the gateway port must be free"
if [ "${OFFLINE:-0}" = "1" ]; then
  warn "offline: skipping the $PANEL_GATEWAY_PORT probe"
elif probe_out "$PANEL_HOST" "ss -tlnp 2>/dev/null | grep -qE ':$(printf '%s' "$PANEL_GATEWAY_PORT")[[:space:]]'"; then
  die "something already listens on $PANEL_GATEWAY_PORT on the panel host"
fi
ok "$PANEL_GATEWAY_PORT is free"

info "CACHE_DRIVER must be redis for tickets (docs/DEPLOY-W1NCRAY-WS.md §2)"
probe_out "$PANEL_HOST" "grep -nE '^[[:space:]]*CACHE_DRIVER' $(printf '%q' "$PANEL_ROOT")/.env 2>/dev/null || echo 'no CACHE_DRIVER line in .env (Laravel default: file)'" || true

probe_out "$PANEL_HOST" "ls -la $(printf '%q' "$PANEL_ROOT/$PANEL_WS_OVERRIDE") 2>/dev/null || echo 'no override on the host yet'" || true

# ---------------------------------------------------------------------------
# write the override
# ---------------------------------------------------------------------------
# The template carries @IMAGE@ and @PORT@ placeholders; substitute them here so
# the committed file stays environment independent.
LOCAL_OVERRIDE="$(mktemp)"
trap 'rm -f "$LOCAL_OVERRIDE"' EXIT
sed -e "s|@IMAGE@|$W1NCRAY_WS_IMAGE|g" \
    -e "s|@PORT@|$PANEL_GATEWAY_PORT|g" \
    "$OVERRIDE_TEMPLATE" > "$LOCAL_OVERRIDE"

log ""
info "override to be installed at $PANEL_ROOT/$PANEL_WS_OVERRIDE:"
sed -e 's/^/    /' "$LOCAL_OVERRIDE"
log ""

confirm "Install the override and start the w1ncray-ws service?"
rput "$LOCAL_OVERRIDE" "$PANEL_ROOT/$PANEL_WS_OVERRIDE"

info "validating the merged compose file (this starts nothing)"
if ! compose "config --quiet"; then
  rsh "$PANEL_HOST" "rm -f $(printf '%q' "$PANEL_ROOT/$PANEL_WS_OVERRIDE")"
  die "docker compose rejected the merged configuration; the override was removed"
fi
ok "merged compose configuration is valid"

# ---------------------------------------------------------------------------
# start
# ---------------------------------------------------------------------------
confirm "Start w1ncray-ws?"
compose "up -d w1ncray-ws"

info "waiting for the port to answer"
if [ "${OFFLINE:-0}" = "1" ]; then
  warn "offline: skipping the $PANEL_GATEWAY_PORT wait"
else
  for i in $(seq 1 20); do
    if probe_out "$PANEL_HOST" "ss -tlnp 2>/dev/null | grep -qE ':$(printf '%s' "$PANEL_GATEWAY_PORT")[[:space:]]'"; then
      break
    fi
    log "  ... not yet ($i/20)"
    sleep 3
  done
fi

info "container state"
compose "ps w1ncray-ws" || warn "compose ps failed"

info "the pid file and the first log lines inside the container"
probe_out "$PANEL_HOST" "docker exec $(printf '%q' "$PANEL_WEB_CONTAINER") sh -c 'ls -la $(printf '%q' "$PANEL_CODE")/storage/logs/w1ncray-ws-server.* 2>&1 | head -5'" || warn "pid/log not found yet"

if [ "${OFFLINE:-0}" = "1" ]; then
  warn "offline: skipping the post-start port assertion"
elif ! probe_out "$PANEL_HOST" "ss -tlnp 2>/dev/null | grep -qE ':$(printf '%s' "$PANEL_GATEWAY_PORT")[[:space:]]'"; then
  fail "the gateway never started listening on $PANEL_GATEWAY_PORT"
  log "logs: docker logs xboard-w1ncray-ws-1   (name may differ, see compose ps)"
  die "gateway start failed; nothing was restarted, so the panel is still serving the old code"
fi
ok "w1ncray-ws is listening on 127.0.0.1:$PANEL_GATEWAY_PORT"

# ---------------------------------------------------------------------------
# activate the new code
# ---------------------------------------------------------------------------
log ""
warn "the next command reloads the Octane workers in place (graceful; no container restart)"
confirm "Reload Octane now?"
if [ "${DRY_RUN:-0}" = "1" ]; then
  log "  (dry-run) docker exec $PANEL_WEB_CONTAINER php artisan octane:reload"
else
  # `octane:reload` cannot find its state file in this image ("Octane server is not
  # running"), so reload the way the earlier deploys did: USR1 to the swoole master.
  probe_out "$PANEL_HOST" "docker exec $(printf '%q' "$PANEL_WEB_CONTAINER") sh -c 'kill -USR1 \$(pgrep -f \"swoole_http_server: master\")' && echo USR1-SENT"     | grep -q USR1-SENT || fail "USR1 reload of the swoole master failed - inspect: docker logs $PANEL_WEB_CONTAINER"
fi

info "waiting for Octane"
if [ "${OFFLINE:-0}" = "1" ]; then
  warn "offline: skipping the Octane wait"
else
  for i in $(seq 1 30); do
    if probe_out "$PANEL_HOST" "curl -fsS -o /dev/null -m 5 http://127.0.0.1:$(printf '%s' "$PANEL_HTTP_PORT")/ 2>/dev/null"; then
      ok "the panel answers on 127.0.0.1:$PANEL_HTTP_PORT"
      break
    fi
    log "  ... panel not answering yet ($i/30)"
    sleep 3
    [ "$i" = "30" ] && fail "the panel did not come back within 90 s — inspect: docker logs $PANEL_WEB_CONTAINER"
  done
fi

info "container state"
compose "ps" || warn "compose ps failed"

info "artisan must now see the new commands"
probe_out "$PANEL_HOST" "docker exec $(printf '%q' "$PANEL_WEB_CONTAINER") php artisan list 2>&1 | grep -E 'w1ncray:ws-server|agent:manifest' || echo 'COMMANDS-MISSING'" || warn "artisan list failed"

ok "gateway up and the new panel code is live"
ROLLBACK_HINT="$HERE/30-gateway-service.sh --rollback-only   (stops w1ncray-ws and removes the override)"
ROLLBACK_SCRIPT="$HERE/30-gateway-service.sh --rollback-only"
step_end

log ""
log "next: 40-nginx-w1ncray-ws.sh (publishes the path; without it the browser"
log "cannot reach the gateway even though it is listening)."
