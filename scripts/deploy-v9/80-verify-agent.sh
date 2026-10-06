#!/usr/bin/env bash
# 80-verify-agent.sh — prove the panel sees the upgraded machine again.
#
# Read-only.  It is the last gate of the runbook: the panel half can be perfect
# and the deployment still failed if no agent reconnected.
#
# Online rule (PLAN v9 ruling 13): a machine is online when
#   now - max(last_poll_at, ws_last_seen_at)  is inside the matching window
#   (360 s for HTTP polling, 70 s for the websocket).
#
# Usage:
#   scripts/deploy-v9/80-verify-agent.sh [--dry-run] [--offline]
#   MACHINE_ID=3 scripts/deploy-v9/80-verify-agent.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
require_strict_mode
parse_common "$@"

: "${MACHINE_ID:=}"
: "${WAIT_S:=0}"     # set e.g. WAIT_S=120 to poll until the machine shows up

step_begin "80 verify the agent from the panel"

[ -n "$MACHINE_ID" ] || die "set MACHINE_ID to the panel machine id of the landing host"

FAILED=0
note_fail() { fail "$1"; FAILED=$((FAILED + 1)); }

# The probe runs inside the web container and prints one key=value block.
read -r -d '' STATE_PROBE <<PHP || true
try {
  \$s = \\App\\Models\\AgentMachineState::find($MACHINE_ID);
  if (!\$s) { echo "state=NO-ROW\n"; exit(0); }
  \$now = time();
  \$poll = \$s->last_poll_at ? \$now - \$s->last_poll_at : null;
  \$ws   = \$s->ws_last_seen_at ? \$now - \$s->ws_last_seen_at : null;
  printf("state=present\n");
  printf("agent_version=%s\n", \$s->agent_version ?: "(unknown)");
  printf("last_poll_age_s=%s\n", \$poll === null ? "(never)" : \$poll);
  printf("ws_last_seen_age_s=%s\n", \$ws === null ? "(never)" : \$ws);
  printf("ws_connected=%s\n", \$s->ws_connected_at ? "yes" : "no");
  printf("telemetry_age_s=%s\n", \$s->telemetry_at ? \$now - \$s->telemetry_at : "(never)");
  printf("applied_revision=%s desired_revision=%s apply_status=%s\n", \$s->applied_revision, \$s->desired_revision, \$s->apply_status ?: "-");
  printf("capabilities=%s\n", is_array(\$s->capabilities) ? implode(",", \$s->capabilities) : "(none)");
  \$policy = is_array(\$s->policy) ? \$s->policy : [];
  printf("policy_terminal=%s\n", array_key_exists("terminal", \$policy) ? var_export(\$policy["terminal"], true) : "(unreported)");
  \$host = is_array(\$s->host_info) ? \$s->host_info : [];
  printf("host=%s\n", \$host ? json_encode(array_intersect_key(\$host, array_flip(["hostname","os","arch","kernel","cpu_model","cores"]))) : "(none)");
  \$tel = is_array(\$s->telemetry) ? \$s->telemetry : [];
  printf("telemetry_keys=%s\n", \$tel ? implode(",", array_slice(array_keys(\$tel), 0, 12)) : "(none)");
  printf("online_by_rule=%s\n", ((\$poll !== null && \$poll <= 360) || (\$ws !== null && \$ws <= 70)) ? "yes" : "no");
} catch (\\Throwable \$e) {
  printf("state=ERROR %s\n", \$e->getMessage());
}
PHP

run_state_probe() {
  if [ "${OFFLINE:-0}" = "1" ]; then
    warn "offline: skipping the state probe"
    return 0
  fi
  rsh "$PANEL_HOST" "docker exec $(printf '%q' "$PANEL_WEB_CONTAINER") php artisan tinker --execute=$(printf '%q' "$STATE_PROBE") 2>&1 | grep -vE '^\s*$'"
}

info "machine $MACHINE_ID state on the panel"
if [ "$WAIT_S" -gt 0 ]; then
  info "waiting up to ${WAIT_S}s for the machine to appear online"
  deadline=$(( $(date +%s) + WAIT_S ))
  while :; do
    OUT="$(run_state_probe || true)"
    printf '%s\n' "$OUT" | sed -e 's/^/    /'
    printf '%s\n' "$OUT" | grep -q 'online_by_rule=yes' && break
    [ "$(date +%s)" -ge "$deadline" ] && { warn "still not online after ${WAIT_S}s"; break; }
    sleep 10
  done
else
  OUT="$(run_state_probe || true)"
  printf '%s\n' "$OUT" | sed -e 's/^/    /'
fi

if [ "${OFFLINE:-0}" = "1" ]; then
  warn "offline: skipping the state assertions"
else
  printf '%s\n' "$OUT" | grep -q 'state=present' || note_fail "no v2_agent_machine_state row for machine $MACHINE_ID"
  printf '%s\n' "$OUT" | grep -q 'online_by_rule=yes' || note_fail "machine $MACHINE_ID is NOT online by the ruling-13 rule"
fi

info "redis presence marker"
if [ "${OFFLINE:-0}" = "1" ]; then
  warn "offline: skipped"
else
  rsh "$PANEL_HOST" "docker exec $(printf '%q' "$PANEL_WEB_CONTAINER") php artisan tinker --execute='
try {
  \$k = \"w1ncray:ws:agent:$MACHINE_ID\";
  \$v = \\Illuminate\\Support\\Facades\\Redis::connection()->get(\$k);
  printf(\"marker %s = %s\n\", \$k, \$v === null ? \"(absent)\" : \"present\");
} catch (\\Throwable \$e) { printf(\"redis probe failed: %s\n\", \$e->getMessage()); }
' 2>&1 | grep -vE '^\s*$'" || warn "redis probe failed"
fi

info "the gateway process must still own its own pid file"
probe_out "$PANEL_HOST" "docker exec $(printf '%q' "$PANEL_WEB_CONTAINER") sh -c 'ls -la $(printf '%q' "$PANEL_CODE")/storage/logs/w1ncray-ws-server.pid 2>&1; echo ---; tail -12 $(printf '%q' "$PANEL_CODE")/storage/logs/w1ncray-ws-server.log 2>&1'" || warn "gateway log unavailable"

info "the legacy ws-server must be untouched"
probe_out "$PANEL_HOST" "docker exec $(printf '%q' "$PANEL_WEB_CONTAINER") sh -c 'ls -la $(printf '%q' "$PANEL_CODE")/storage/logs/xboard-ws-server.pid 2>&1' || true
ss -tlnp 2>/dev/null | grep -E ':$(printf '%s' "$PANEL_LEGACY_PORT")[[:space:]]' || echo 'legacy 8076 not listening'" || true

log ""
if [ "$FAILED" -eq 0 ]; then
  ok "the panel sees machine $MACHINE_ID online; deployment verified"
  ROLLBACK_HINT="none — this step is read-only"
else
  fail "$FAILED check(s) failed"
  log "if the agent never reconnects:"
  log "  landing : journalctl -u W1nCray -n 100 --no-pager"
  log "  landing : $LANDING_BIN check -c $LANDING_CONF_DIR/config.yml"
  log "  gateway : docker logs <w1ncray-ws container>  /  storage/logs/w1ncray-ws-server.log"
  log "  rollback: 70-agent-upgrade.sh --rollback-only --rollback-ts <ts>"
  ROLLBACK_HINT="see the list above"
  step_end
  exit 1
fi
step_end
