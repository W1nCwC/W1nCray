#!/usr/bin/env bash
# 40-nginx-w1ncray-ws.sh — publish `location = /w1ncray-ws` in the panel's
# nginx site config.
#
# The exact-match location is inserted immediately BEFORE the existing legacy
# `location = /ws` (or, if that cannot be found, before the site's catch-all
# `location ^~ /`).  nginx picks the longest matching prefix, but exact `=`
# matches always win over any prefix, so the new path can never be swallowed by
# `/`; the ordering only matters for human readability.  The legacy block is
# copied byte for byte and is never edited.
#
# Impact : `nginx -t` + reload.  A reload is graceful: no dropped connections,
#          no measurable downtime.  The new path 404s until the reload.
# Rollback: restore the .bak file and reload again.
#
# Usage:
#   scripts/deploy-v9/40-nginx-w1ncray-ws.sh [--dry-run] [--yes]
#   scripts/deploy-v9/40-nginx-w1ncray-ws.sh --rollback-only <backup-file>
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
require_strict_mode

BACKUP_FILE=""
ROLLBACK_ONLY=0
EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
    --rollback-only) ROLLBACK_ONLY=1 ;;
    --backup)        BACKUP_FILE="$2"; shift ;;
    *)               EXTRA+=("$1") ;;
  esac
  shift
done
if [ "${#EXTRA[@]}" -gt 0 ]; then parse_common "${EXTRA[@]}"; else parse_common; fi

: "${NGINX_TEST_CMD:=/www/server/nginx/sbin/nginx -t}"
: "${NGINX_RELOAD_CMD:=/etc/init.d/nginx reload}"
: "${NGINX_BIN:=/www/server/nginx/sbin/nginx}"
: "${PANEL_SITE_HOST:=subscribe.w1ncray.xyz}"

SITE_URL="$PANEL_NGINX_SCHEME://127.0.0.1:$PANEL_NGINX_PORT"
[ "$PANEL_NGINX_SCHEME" = "https" ] && [ "$PANEL_NGINX_PORT" = "443" ] && SITE_URL="https://127.0.0.1"
[ "$PANEL_NGINX_SCHEME" = "http" ]  && [ "$PANEL_NGINX_PORT" = "80" ]  && SITE_URL="http://127.0.0.1"

# ---------------------------------------------------------------------------
# rollback path
# ---------------------------------------------------------------------------
if [ "$ROLLBACK_ONLY" = "1" ]; then
  step_begin "40 rollback: nginx location"
  [ -n "$BACKUP_FILE" ] || die "--rollback-only needs --backup <file> (printed by the forward run)"
  guard_path "$BACKUP_FILE" "the nginx config backup"
  confirm "Restore $PANEL_NGINX_CONF from $BACKUP_FILE and reload nginx?"
  rsh "$PANEL_HOST" "cp -a $(printf '%q' "$BACKUP_FILE") $(printf '%q' "$PANEL_NGINX_CONF")"
  rsh "$PANEL_HOST" "$NGINX_TEST_CMD"
  rsh "$PANEL_HOST" "$NGINX_RELOAD_CMD"
  ok "nginx config restored and reloaded"
  ROLLBACK_HINT="already performed"
  step_end
  exit 0
fi

step_begin "40 nginx: location = /w1ncray-ws"

# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------
info "site config: $PANEL_NGINX_CONF"
if ! probe_out "$PANEL_HOST" "test -f $(printf '%q' "$PANEL_NGINX_CONF")"; then
  fail "no such file: $PANEL_NGINX_CONF"
  log "candidates:"
  probe_out "$PANEL_HOST" "ls -1 /www/server/panel/vhost/nginx/*.conf 2>/dev/null | head -20" || true
  die "set PANEL_NGINX_CONF to the right file and re-run"
fi

info "current state of the file"
probe_out "$PANEL_HOST" "C=$(printf '%q' "$PANEL_NGINX_CONF")
printf 'lines=%s\n' \"\$(wc -l < \"\$C\")\"
printf 'legacy_ws_blocks=%s\n' \"\$(grep -cE 'location[[:space:]]*=[[:space:]]*/ws[[:space:]]*\\{' \"\$C\" || true)\"
printf 'w1ncray_ws_blocks=%s\n' \"\$(grep -cE 'location[[:space:]]*=[[:space:]]*/w1ncray-ws' \"\$C\" || true)\"
printf 'catch_all_blocks=%s\n' \"\$(grep -cE 'location[[:space:]]*\\^~[[:space:]]*/[[:space:]]*\\{' \"\$C\" || true)\"
printf 'proxy_pass_7001=%s\n' \"\$(grep -cE 'proxy_pass[^;]*127\\.0\\.0\\.1:7001' \"\$C\" || true)\"
grep -nE '^[[:space:]]*location' \"\$C\" | head -20" || die "cannot read $PANEL_NGINX_CONF"

if [ "${OFFLINE:-0}" != "1" ] && probe_out "$PANEL_HOST" "grep -qE 'location[[:space:]]*=[[:space:]]*/w1ncray-ws' $(printf '%q' "$PANEL_NGINX_CONF")"; then
  ok "the location already exists — nothing to insert (re-running this step is safe)"
  probe_out "$PANEL_HOST" "grep -n -A14 'location = /w1ncray-ws' $(printf '%q' "$PANEL_NGINX_CONF")" || true
  ROLLBACK_HINT="remove the block by hand (no backup was taken because nothing changed)"
  step_end
  exit 0
fi

info "nginx test command: $NGINX_TEST_CMD"
probe_out "$PANEL_HOST" "$NGINX_TEST_CMD" || warn "nginx -t is already failing BEFORE our change — fix that first"

# ---------------------------------------------------------------------------
# backup
# ---------------------------------------------------------------------------
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_FILE="/root/$(basename "$PANEL_NGINX_CONF").bak-w1ncray-$STAMP"
guard_path "$BACKUP_FILE" "the nginx config backup"
info "backup -> $BACKUP_FILE"
rsh "$PANEL_HOST" "cp -a $(printf '%q' "$PANEL_NGINX_CONF") $(printf '%q' "$BACKUP_FILE") && ls -la $(printf '%q' "$BACKUP_FILE")"

# ---------------------------------------------------------------------------
# insert
# ---------------------------------------------------------------------------
BLOCK_FILE="$(mktemp)"
trap 'rm -f "$BLOCK_FILE"' EXIT
cat > "$BLOCK_FILE" <<'NGINXBLOCK'

    # W1nCray agent gateway (PLAN v9 ruling 16).  Exact match, so it can never
    # be caught by the legacy /ws location or the catch-all below.
    # The browser ticket travels in the query string; access_log off keeps it
    # out of the log (design R9).  proxy_read_timeout must stay >= 75 s (the
    # protocol silence window is 70 s); 300 s leaves room for a terminal session.
    location = /w1ncray-ws {
        proxy_pass http://127.0.0.1:8077;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
        access_log off;
    }
NGINXBLOCK

log ""
info "block to insert:"
sed -e 's/^/    /' "$BLOCK_FILE"
log ""
confirm "Insert this block into $PANEL_NGINX_CONF and reload nginx?"

# awk inserts the block before the first matching anchor line.  Anchors, in
# order: the legacy `location = /ws {`, then the catch-all `location ^~ / {`.
# If neither exists the file is left alone and the step fails loudly.
if [ "${DRY_RUN:-0}" = "1" ]; then
  log "[dry-run] awk inserts the block before 'location = /ws {' (or 'location ^~ / {')"
  log "[dry-run] $NGINX_TEST_CMD && $NGINX_RELOAD_CMD"
else
  rput "$BLOCK_FILE" "/root/.w1ncray-ws-block.$$"
  if ! rsh "$PANEL_HOST" "set -e
C=$(printf '%q' "$PANEL_NGINX_CONF")
B=/root/.w1ncray-ws-block.$$
T=\$C.w1ncray-new.$$
awk -v blockfile=\"\$B\" '
  BEGIN { inserted = 0 }
  !inserted && /location[[:space:]]*=[[:space:]]*\\/ws[[:space:]]*\\{/ {
    while ((getline line < blockfile) > 0) print line
    close(blockfile); inserted = 1
  }
  !inserted && /location[[:space:]]*\\^~[[:space:]]*\\/[[:space:]]*\\{/ {
    while ((getline line < blockfile) > 0) print line
    close(blockfile); inserted = 1
  }
  { print }
  END { if (!inserted) { print \"ANCHOR-NOT-FOUND\" > \"/dev/stderr\"; exit 3 } }
' \"\$C\" > \"\$T\"
grep -qE 'location[[:space:]]*=[[:space:]]*/w1ncray-ws' \"\$T\"
[ \"\$(grep -cE 'location[[:space:]]*=[[:space:]]*/w1ncray-ws' \"\$T\")\" = \"1\" ] || { echo 'DUPLICATE-BLOCK'; rm -f \"\$T\" \"\$B\"; exit 4; }
cp -a \"\$C\" \"\$C.before-insert-$$\"
mv \"\$T\" \"\$C\"
rm -f \"\$B\" \"\$C.before-insert-$$\"
echo INSERTED"; then
    fail "the insert failed; restoring the backup"
    rsh "$PANEL_HOST" "cp -a $(printf '%q' "$BACKUP_FILE") $(printf '%q' "$PANEL_NGINX_CONF")"
    die "no anchor (neither 'location = /ws {' nor 'location ^~ / {') was found; insert the block by hand"
  fi
fi

# ---------------------------------------------------------------------------
# validate + reload
# ---------------------------------------------------------------------------
info "nginx -t"
if ! rsh "$PANEL_HOST" "$NGINX_TEST_CMD"; then
  fail "nginx -t rejected the new configuration; restoring the backup"
  rsh "$PANEL_HOST" "cp -a $(printf '%q' "$BACKUP_FILE") $(printf '%q' "$PANEL_NGINX_CONF")"
  rsh "$PANEL_HOST" "$NGINX_TEST_CMD" || true
  die "config rejected; the previous file is back in place and nginx was not reloaded"
fi
ok "nginx accepts the configuration"

confirm "Reload nginx (graceful, no dropped connections)?"
rsh "$PANEL_HOST" "$NGINX_RELOAD_CMD"
sleep 2

info "verifying through nginx: an unauthenticated upgrade must be refused"
if [ "${DRY_RUN:-0}" = "1" ]; then
  log "[dry-run] curl -s -i -N -m 8 -H 'Connection: Upgrade' -H 'Upgrade: websocket' ... https://<site>/w1ncray-ws"
else
  # A refused upgrade completes the handshake (101) and then sends an error
  # frame + Close 4400; see docs/DEPLOY-W1NCRAY-WS.md §7.  Any 101 here proves
  # nginx reached the gateway.
  OUT="$(rsh "$PANEL_HOST" "curl -s ${CURL_INSECURE:-} -i -N -m 8 -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Sec-WebSocket-Version: 13' -H 'Host: $(printf '%s' "$PANEL_SITE_HOST")' $(printf '%s' "$SITE_URL")/w1ncray-ws 2>&1 | head -20" || true)"
  printf '%s\n' "$OUT"
  if printf '%s\n' "$OUT" | grep -q '101'; then
    ok "the gateway answered a websocket upgrade through nginx"
  elif printf '%s\n' "$OUT" | grep -qE '404|502|504'; then
    fail "nginx answered $(printf '%s' "$OUT" | head -1) — the location or the upstream is wrong"
    log "check: $NGINX_TEST_CMD ; docker compose ... ps w1ncray-ws ; ss -tlnp | grep 8077"
  else
    warn "unexpected answer; inspect it above before continuing"
  fi
fi

info "the legacy /ws must still be its own thing"
probe_out "$PANEL_HOST" "grep -n -A6 'location = /ws' $(printf '%q' "$PANEL_NGINX_CONF") || grep -n -A6 'location /ws' $(printf '%q' "$PANEL_NGINX_CONF") || echo 'no legacy /ws block in this file'" || true

ok "location published and nginx reloaded"
ROLLBACK_HINT="$HERE/40-nginx-w1ncray-ws.sh --rollback-only --backup $BACKUP_FILE"
ROLLBACK_SCRIPT="$HERE/40-nginx-w1ncray-ws.sh --rollback-only --backup $BACKUP_FILE"
step_end

log ""
log "next: 50-spa-patch.sh (sub13 admin SPA overlay)."
