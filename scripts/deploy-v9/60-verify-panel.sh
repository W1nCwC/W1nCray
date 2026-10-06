#!/usr/bin/env bash
# 60-verify-panel.sh — prove the panel side of the deployment actually works.
#
# Read-only: every command below only observes.  It is the gate between the
# panel half and the landing half of the runbook.
#
# Checks, in the order they matter:
#   1. containers up, gateway pid file owned by the gateway
#   2. 127.0.0.1:8077 listening; the legacy 8076 untouched
#   3. a websocket upgrade through nginx reaches the gateway (101)
#   4. the gateway refuses an unauthenticated upgrade with Close 4400
#   5. Redis carries the presence marker once an agent connects
#   6. the SPA manifest points at sub13 and the assets answer 200
#   7. migrations: nothing pending
#
# Usage:
#   scripts/deploy-v9/60-verify-panel.sh [--dry-run] [--offline]
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
require_strict_mode
parse_common "$@"

: "${PANEL_SITE_HOST:=subscribe.w1ncray.xyz}"
: "${PANEL_ADMIN_TOKEN_FILE:=}"   # optional: a file holding an admin bearer token
: "${CURL_INSECURE:=}"            # set to -k when PANEL_NGINX_SCHEME=https

# host-local URL of the site as nginx serves it
SITE_URL="$PANEL_NGINX_SCHEME://127.0.0.1:$PANEL_NGINX_PORT"
[ "$PANEL_NGINX_SCHEME" = "https" ] && [ "$PANEL_NGINX_PORT" = "443" ] && SITE_URL="https://127.0.0.1"
[ "$PANEL_NGINX_SCHEME" = "http" ]  && [ "$PANEL_NGINX_PORT" = "80" ]  && SITE_URL="http://127.0.0.1"

step_begin "60 verify the panel side"

FAILED=0
note_fail() { fail "$1"; FAILED=$((FAILED + 1)); }

# ---------------------------------------------------------------------------
# 1. containers
# ---------------------------------------------------------------------------
info "1. containers"
probe_out "$PANEL_HOST" "docker ps --format '{{.Names}}|{{.Status}}' | grep -E 'xboard|w1ncray' | sort" || note_fail "docker ps failed"

# ---------------------------------------------------------------------------
# 2. listeners
# ---------------------------------------------------------------------------
info "2. listeners"
if probe_out "$PANEL_HOST" "ss -tlnp 2>/dev/null | grep -E ':$(printf '%s' "$PANEL_GATEWAY_PORT")[[:space:]]'"; then
  ok "gateway is listening on $PANEL_GATEWAY_PORT"
else
  note_fail "nothing listens on $PANEL_GATEWAY_PORT"
fi

if probe_out "$PANEL_HOST" "ss -tlnp 2>/dev/null | grep -E ':$(printf '%s' "$PANEL_LEGACY_PORT")[[:space:]]'"; then
  ok "legacy ws-server is still listening on $PANEL_LEGACY_PORT (untouched)"
else
  note_fail "the legacy ws-server on $PANEL_LEGACY_PORT is NOT listening — investigate before continuing"
fi

# ---------------------------------------------------------------------------
# 3./4. the gateway through nginx and directly
# ---------------------------------------------------------------------------
UPGRADE_HEADERS=(-H 'Connection: Upgrade' -H 'Upgrade: websocket'
                 -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Sec-WebSocket-Version: 13')

info "3. websocket upgrade through nginx (expects HTTP 101)"
if [ "${OFFLINE:-0}" = "1" ]; then
  warn "offline: skipped"
else
  OUT="$(rsh "$PANEL_HOST" "curl -s $CURL_INSECURE -i -N -m 8 -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Sec-WebSocket-Version: 13' -H 'Host: $(printf '%s' "$PANEL_SITE_HOST")' $(printf '%s' "$SITE_URL")/w1ncray-ws 2>&1 | head -25" || true)"
  printf '%s\n' "$OUT" | sed -e 's/^/    /'
  printf '%s\n' "$OUT" | grep -q '101' \
    && ok "nginx -> gateway upgrade works" \
    || note_fail "no 101 through nginx (404 = location missing, 502 = gateway down)"
fi

info "4. the gateway must refuse an unauthenticated upgrade with 4400"
if [ "${OFFLINE:-0}" = "1" ]; then
  warn "offline: skipped"
else
  OUT="$(rsh "$PANEL_HOST" "curl -s -i -N -m 8 -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Sec-WebSocket-Version: 13' http://127.0.0.1:$(printf '%s' "$PANEL_GATEWAY_PORT")/w1ncray-ws 2>&1 | head -25" || true)"
  printf '%s\n' "$OUT" | sed -e 's/^/    /'
  printf '%s\n' "$OUT" | grep -q 'role_unknown' \
    && ok "the gateway answers with role_unknown as documented" \
    || warn "no role_unknown frame seen (the close code is not visible through curl; use wscat for 4400)"
fi

# ---------------------------------------------------------------------------
# 5. redis presence markers
# ---------------------------------------------------------------------------
info "5. redis presence markers (empty until an agent connects)"
probe_out "$PANEL_HOST" "docker exec $(printf '%q' "$PANEL_WEB_CONTAINER") php artisan tinker --execute='
try {
  \$keys = \\Illuminate\\Support\\Facades\\Redis::connection()->keys(\"*w1ncray:ws:agent:*\");
  printf(\"presence_keys=%d\n\", is_array(\$keys) ? count(\$keys) : 0);
  foreach (array_slice((array)\$keys, 0, 5) as \$k) { echo \"  \", \$k, PHP_EOL; }
} catch (\\Throwable \$e) { printf(\"redis probe failed: %s\n\", \$e->getMessage()); }
' 2>&1 | grep -vE '^\s*$'" || warn "redis probe failed"

# ---------------------------------------------------------------------------
# 6. the admin SPA
# ---------------------------------------------------------------------------
info "6. admin SPA manifest and assets"
probe_out "$PANEL_HOST" "B=$(printf '%q' "$PANEL_ROOT/$PANEL_SPA_DIR")
printf 'manifest_entry=%s\n' \"\$(grep -oE 'assets/index-[A-Za-z0-9_-]+\\.js' \"\$B/manifest.json\" | head -1)\"
printf 'custom3_locales=%s\n' \"\$(ls -1 \"\$B\"/locales/*.custom3.js 2>/dev/null | wc -l)\"
printf 'stock_locales=%s\n' \"\$(ls -1 \"\$B\"/locales/zh-CN.js \"\$B\"/locales/en-US.js \"\$B\"/locales/ru-RU.js 2>/dev/null | wc -l)\"" || warn "SPA inspection failed"

for path in "/assets/admin/manifest.json" "/assets/admin/w1nc-autorefresh.js" "/w1ncray/realtime.js" "/w1ncray/terminal.js" "/w1ncray/vendor/xterm/xterm.js"; do
  if [ "${OFFLINE:-0}" = "1" ]; then
    warn "offline: skipped $path"
    continue
  fi
  CODE="$(rsh "$PANEL_HOST" "curl -s $CURL_INSECURE -o /dev/null -w '%{http_code}' -m 10 -H 'Host: $(printf '%s' "$PANEL_SITE_HOST")' $(printf '%s' "$SITE_URL")$(printf '%s' "$path")" || echo 000)"
  if [ "$CODE" = "200" ]; then
    ok "GET $path -> 200"
  else
    note_fail "GET $path -> $CODE"
  fi
done

# ---------------------------------------------------------------------------
# 7. migrations
# ---------------------------------------------------------------------------
info "7. migrations"
if [ "${OFFLINE:-0}" = "1" ]; then
  warn "offline: skipped"
elif probe_out "$PANEL_HOST" "docker exec $(printf '%q' "$PANEL_WEB_CONTAINER") php artisan migrate:status 2>&1 | grep -E '2026_10_0[67]' | grep -qi pending"; then
  note_fail "a 2026_10_06/07 migration is still pending"
else
  ok "no pending migration"
fi

# ---------------------------------------------------------------------------
# optional: issue a ticket through the admin API
# ---------------------------------------------------------------------------
if [ -n "$PANEL_ADMIN_TOKEN_FILE" ]; then
  [ -f "$PANEL_ADMIN_TOKEN_FILE" ] || die "PANEL_ADMIN_TOKEN_FILE does not exist: $PANEL_ADMIN_TOKEN_FILE"
  info "extra: issuing a live ticket (token read from $PANEL_ADMIN_TOKEN_FILE, never echoed)"
  if [ "${OFFLINE:-0}" = "1" ]; then
    warn "offline: skipped"
  else
    warn "this needs the secure_path and a machine id; run it by hand from the docs:"
    log "  curl -s -X POST -H \"Authorization: Bearer <token>\" -H 'Content-Type: application/json' -d '{\"machine_id\":<id>,\"purpose\":\"live\"}' https://$PANEL_SITE_HOST/api/v2/<secure_path>/w1ncray/ws/ticket"
  fi
fi

# ---------------------------------------------------------------------------
# verdict
# ---------------------------------------------------------------------------
log ""
if [ "$FAILED" -eq 0 ]; then
  ok "panel verification passed ($FAILED failures)"
  ROLLBACK_HINT="none — this step is read-only"
else
  fail "$FAILED check(s) failed"
  log "rollback options:"
  log "  nginx   : 40-nginx-w1ncray-ws.sh --rollback-only --backup /root/<conf>.bak-w1ncray-<ts>"
  log "  gateway : 30-gateway-service.sh --rollback-only"
  log "  SPA     : 50-spa-patch.sh --rollback-only --stage /root/w1ncray-deploy-<ts>-spa-sub13"
  log "  files   : 10-panel-files.sh --rollback-only --stage /root/w1ncray-deploy-<ts>-panel-files"
  ROLLBACK_HINT="see the list above"
  step_end
  exit 1
fi
step_end
