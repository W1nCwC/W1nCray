#!/usr/bin/env bash
# run-all.sh — drive the PLAN v9 deployment in order, one human confirmation
# between steps.
#
# It is a thin driver: every step is the same script you can run by hand, and
# each one is idempotent enough to re-run.  Between steps it prints the next
# command and waits for a literal `yes` on stdin.
#
# It refuses to start unless the environment it needs is set:
#   W1NCRAY_BINARY   path to the new linux/amd64 agent binary   (step 70)
#   MACHINE_ID       panel machine id of the landing host       (step 70/80)
#   PANEL_URL        e.g. https://subscribe.w1ncray.xyz         (step 70)
#   ENABLE_TERMINAL  yes|no, default no                         (step 70)
#
# Usage:
#   scripts/deploy-v9/run-all.sh [--dry-run] [--yes] [--from <step number>] [--to <step number>]
#   scripts/deploy-v9/run-all.sh --list
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
require_strict_mode

FROM=""; TO=""; LIST=0; PASS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --from) FROM="$2"; shift ;;
    --to)   TO="$2";   shift ;;
    --list) LIST=1 ;;
    *)      PASS+=("$1") ;;
  esac
  shift
done

# step number | script | label
STEPS=(
  "00|00-preflight.sh|preflight (read-only)"
  "10|10-panel-files.sh|panel files -> $PANEL_ROOT"
  "20|20-migrate.sh|database migrations"
  "30|30-gateway-service.sh|w1ncray-ws service + web/horizon restart"
  "40|40-nginx-w1ncray-ws.sh|nginx location = /w1ncray-ws"
  "50|50-spa-patch.sh|admin SPA overlay sub13"
  "60|60-verify-panel.sh|verify the panel side"
  "70|70-agent-upgrade.sh|landing agent upgrade + agent.yml split"
  "80|80-verify-agent.sh|verify the agent from the panel"
)

if [ "$LIST" = "1" ]; then
  for s in "${STEPS[@]}"; do
    IFS='|' read -r n script label <<<"$s"
    printf '  %s  %-28s %s\n' "$n" "$script" "$label"
  done
  exit 0
fi

step_begin "PLAN v9 deployment — sequential driver"

# ---------------------------------------------------------------------------
# environment gate
# ---------------------------------------------------------------------------
: "${ENABLE_TERMINAL:=no}"
: "${W1NCRAY_BINARY:=}"
: "${MACHINE_ID:=}"
: "${PANEL_URL:=}"

log "  panel        : $PANEL_HOST"
log "  landing      : $LANDING_HOST"
log "  terminal     : $ENABLE_TERMINAL"
log "  binary       : ${W1NCRAY_BINARY:-<unset>}"
log "  machine id   : ${MACHINE_ID:-<unset>}"
log "  panel url    : ${PANEL_URL:-<unset>}"
log "  dry-run      : $([ "${DRY_RUN:-0}" = "1" ] && echo yes || echo no)"
log ""

if [ -z "$W1NCRAY_BINARY" ] || [ -z "$MACHINE_ID" ] || [ -z "$PANEL_URL" ]; then
  fail "W1NCRAY_BINARY, MACHINE_ID and PANEL_URL must all be set before run-all starts."
  fail "steps 00-60 only need the hosts; set the three variables and re-run,"
  fail "or run the step scripts by hand (see docs/DEPLOY-v9.md §0)."
  exit 1
fi

export ENABLE_TERMINAL W1NCRAY_BINARY MACHINE_ID PANEL_URL

# ---------------------------------------------------------------------------
# confirmation between steps
# ---------------------------------------------------------------------------
gate() {
  local label="$1" script="$2"
  if [ "${ASSUME_YES:-0}" = "1" ] || [ "${DRY_RUN:-0}" = "1" ]; then
    info "gate: $label -> assumed yes"
    return 0
  fi
  log ""
  log "--------------------------------------------------------------------"
  log "  next step: $label"
  log "  script   : $HERE/$script"
  log "--------------------------------------------------------------------"
  printf 'type exactly "yes" to run it, anything else aborts the run: '
  local a=""
  read -r a || true
  [ "$a" = "yes" ] || { warn "aborted at the gate before '$label'"; exit 1; }
}

# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------
RAN=0
for s in "${STEPS[@]}"; do
  IFS='|' read -r n script label <<<"$s"
  if [ -n "$FROM" ] && [ "$n" \< "$FROM" ]; then
    log "skipping $n ($label)"
    continue
  fi
  if [ -n "$TO" ] && [ "$n" \> "$TO" ]; then
    log "stopping before $n (--to $TO)"
    break
  fi
  gate "$label" "$script"
  log ""
  info "running $script ${PASS[*]:-}"
  # shellcheck disable=SC2086
  if ! "$HERE/$script" ${PASS[@]+"${PASS[@]}"}; then
    fail "step $n ($script) failed — the deployment stops here."
    fail "each step printed its own rollback command; nothing further was run."
    exit 1
  fi
  RAN=$((RAN + 1))
done

log ""
ok "all $RAN step(s) finished."
log ""
log "post-deployment checklist (docs/DEPLOY-v9.md §8):"
log "  [ ] hard-reload the admin SPA (Ctrl-F5) and open the W1nCray page"
log "  [ ] the machine appears online and the overview tab shows live telemetry"
log "  [ ] the terminal tab reports the local switch correctly for this machine"
log "  [ ] the legacy /ws path still serves the old nodes"
log "  [ ] record the backup directories printed by each step"
