#!/usr/bin/env bash
# 70-agent-upgrade.sh — upgrade the W1nCray agent on the landing host and move
# it to the split agent.yml layout.
#
# What it does:
#   1. backup: /usr/local/W1nCray/W1nCray.bak-<ts> and /etc/W1nCray.bak-<ts>
#   2. upload the new binary to a temp path and prove it runs BEFORE stopping
#      anything (`version` + `check -c` against the live config)
#   3. stop -> atomic swap -> start, with the port checks the earlier runbooks
#      used (2083 / 65533 / 65535)
#   4. split layout: `W1nCray link --dry-run` first, then the real run, then
#      `systemctl restart` (link itself never restarts anything)
#
# ENABLE_TERMINAL (default: no) decides the local terminal switch.  The terminal
# is ON by default in this release (PLAN v9 ruling 17), so the default here is
# the conservative one: it passes --noterminal and agent.yml gets
# `Terminal: {Enabled: false}`.  Set ENABLE_TERMINAL=yes to keep the capability.
#
# Impact : one service restart, 3-10 s.  Every node on this host is down for
#          that window (the machine currently serves 3 nodes).
# Rollback: cp the .bak-<ts> binary back, restore /etc/W1nCray from
#          /etc/W1nCray.bak-<ts>, systemctl restart.  The script does this
#          automatically if the new binary does not come up.
#
# Usage:
#   ENABLE_TERMINAL=no W1NCRAY_BINARY=/path/W1nCray-linux-amd64 \
#     PANEL_URL=https://subscribe.w1ncray.xyz MACHINE_ID=3 TOKEN_FILE=/etc/W1nCray/agent.token \
#     scripts/deploy-v9/70-agent-upgrade.sh [--dry-run] [--yes]
#
#   scripts/deploy-v9/70-agent-upgrade.sh --rollback-only <timestamp>
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
require_strict_mode

ROLLBACK_TS=""
ROLLBACK_ONLY=0
SKIP_LINK=0
EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
    --rollback-only) ROLLBACK_ONLY=1 ;;
    --rollback-ts)   ROLLBACK_TS="$2"; shift ;;
    --skip-link)     SKIP_LINK=1 ;;
    *)               EXTRA+=("$1") ;;
  esac
  shift
done
if [ "${#EXTRA[@]}" -gt 0 ]; then parse_common "${EXTRA[@]}"; else parse_common; fi

: "${ENABLE_TERMINAL:=no}"
: "${W1NCRAY_BINARY:=}"
# Alternative to W1NCRAY_BINARY: the landing host downloads the release asset itself
# (much faster than an upload through the proxy) and checks it against SHA256SUMS.
: "${W1NCRAY_RELEASE_BASE:=}"   # e.g. https://github.com/W1nCwC/W1nCray/releases/download/v0.5.0
: "${PANEL_URL:=}"
: "${MACHINE_ID:=}"
: "${TOKEN_FILE:=$LANDING_TOKEN_FILE}"
: "${EXPECT_PORTS:=2083 65533 65535}"

VERSION_OUT="(dry-run)"
CHECK_OUT=""

# ---------------------------------------------------------------------------
# rollback path
# ---------------------------------------------------------------------------
if [ "$ROLLBACK_ONLY" = "1" ]; then
  step_begin "70 rollback: agent binary + config"
  [ -n "$ROLLBACK_TS" ] || die "--rollback-only needs --rollback-ts <timestamp printed by the forward run>"
  confirm "Restore the agent binary and /etc/W1nCray from $ROLLBACK_TS?"
  rsh "$LANDING_HOST" "set -e
D=$(printf '%q' "$(dirname "$LANDING_BIN")")
BIN=$(printf '%q' "$LANDING_BIN")
BAK=\"\$D/W1nCray.bak-$ROLLBACK_TS\"
[ -f \"\$BAK\" ] || { echo \"missing \$BAK\"; exit 1; }
systemctl stop $(printf '%q' "$LANDING_SERVICE") || true
cp -a \"\$BAK\" \"\$BIN\"
if [ -d $(printf '%q' "$LANDING_CONF_DIR.bak-$ROLLBACK_TS") ]; then
  rm -rf $(printf '%q' "$LANDING_CONF_DIR").rollback-$$
  mv $(printf '%q' "$LANDING_CONF_DIR") $(printf '%q' "$LANDING_CONF_DIR").rollback-$$
  cp -a $(printf '%q' "$LANDING_CONF_DIR.bak-$ROLLBACK_TS") $(printf '%q' "$LANDING_CONF_DIR")
fi
systemctl start $(printf '%q' "$LANDING_SERVICE")
sleep 10
systemctl is-active --quiet $(printf '%q' "$LANDING_SERVICE") && echo ROLLBACK-OK || echo ROLLBACK-FAILED"
  rsh "$LANDING_HOST" "$LANDING_BIN version | head -1" || true
  ok "rollback attempted"
  ROLLBACK_HINT="already performed"
  step_end
  exit 0
fi

step_begin "70 agent upgrade on $LANDING_HOST (terminal: $ENABLE_TERMINAL)"

# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------
if [ -z "$W1NCRAY_RELEASE_BASE" ]; then
  [ -n "$W1NCRAY_BINARY" ] || die "set W1NCRAY_BINARY (local linux/amd64 binary) or W1NCRAY_RELEASE_BASE (release download URL)"
  [ -f "$W1NCRAY_BINARY" ] || die "no such binary: $W1NCRAY_BINARY"
fi

case "$ENABLE_TERMINAL" in
  yes|no) : ;;
  *) die "ENABLE_TERMINAL must be 'yes' or 'no' (got '$ENABLE_TERMINAL')" ;;
esac
if [ "$ENABLE_TERMINAL" = "yes" ]; then
  warn "ENABLE_TERMINAL=yes: the machine will grant the panel an interactive shell."
  warn "that is the release default; the panel still needs an admin password per ticket."
else
  info "ENABLE_TERMINAL=no: --noterminal writes 'Terminal: {Enabled: false}' into agent.yml."
fi

if [ -n "$W1NCRAY_RELEASE_BASE" ]; then
  info "binary source: $W1NCRAY_RELEASE_BASE (downloaded and verified on the landing host)"
elif true; then
info "local binary"
ls -la "$W1NCRAY_BINARY"
fi
if [ -z "$W1NCRAY_RELEASE_BASE" ] && [ "${DRY_RUN:-0}" != "1" ]; then
  MAGIC="$(od -An -tx1 -N4 "$W1NCRAY_BINARY" | tr -d ' \n')"
  case "$MAGIC" in
    7f454c46) ok "ELF header present" ;;
    *) die "not an ELF binary (magic=$MAGIC) — a script or a Windows build would break the service" ;;
  esac
fi

info "landing host state"
probe_out "$LANDING_HOST" "set -e
printf 'version: '; $(printf '%q' "$LANDING_BIN") version 2>&1 | head -1
printf 'unit: %s\n' \"\$(systemctl is-active $(printf '%q' "$LANDING_SERVICE") 2>&1 || true)\"
printf 'free_kb_usr_local=%s\n' \"\$(df -Pk $(printf '%q' "$(dirname "$LANDING_BIN")") | awk 'NR==2{print \$4}')\"
printf 'free_kb_etc=%s\n' \"\$(df -Pk $(printf '%q' "$LANDING_CONF_DIR") | awk 'NR==2{print \$4}')\"
printf 'agent_yml=%s\n' \"\$( [ -f $(printf '%q' "$LANDING_CONF_DIR")/agent.yml ] && echo present || echo absent )\"
printf 'token_file=%s\n' \"\$( [ -f $(printf '%q' "$TOKEN_FILE") ] && echo present || echo MISSING )\"
printf 'static_nodes=%s\n' \"\$(grep -cE '^[[:space:]]*Nodes:' $(printf '%q' "$LANDING_CONF_DIR")/config.yml || echo 0)\"
printf 'legacy_agent_block=%s\n' \"\$(grep -cE '^[[:space:]]*Agent:' $(printf '%q' "$LANDING_CONF_DIR")/config.yml || echo 0)\"" || die "landing preflight failed"

if ! probe_out "$LANDING_HOST" "test -f $(printf '%q' "$TOKEN_FILE")"; then
  warn "the token file $TOKEN_FILE does not exist on the landing host"
  warn "it must already be there (0600, machine token) before the split migration;"
  warn "this script never creates it and never takes a token as an argument."
  confirm "Continue without the token file (link will fail)?"
fi

# ---------------------------------------------------------------------------
# backup
# ---------------------------------------------------------------------------
TS="$(date +%Y%m%d-%H%M%S)"
info "backup stamp: $TS"
confirm "Back up the binary to W1nCray.bak-$TS and /etc/W1nCray to /etc/W1nCray.bak-$TS?"
rsh "$LANDING_HOST" "set -e
D=$(printf '%q' "$(dirname "$LANDING_BIN")")
cp -a $(printf '%q' "$LANDING_BIN") \"\$D/W1nCray.bak-$TS\"
if [ -d $(printf '%q' "$LANDING_CONF_DIR.bak-$TS") ]; then
  echo 'WARNING: the config backup directory already exists; not overwriting it'
else
  cp -a $(printf '%q' "$LANDING_CONF_DIR") $(printf '%q' "$LANDING_CONF_DIR.bak-$TS")
fi
ls -la \"\$D/W1nCray.bak-$TS\"
du -sh $(printf '%q' "$LANDING_CONF_DIR.bak-$TS")"
ok "backup taken"

# ---------------------------------------------------------------------------
# upload + offline validation (nothing is stopped yet)
# ---------------------------------------------------------------------------
if [ -n "$W1NCRAY_RELEASE_BASE" ]; then
  info "downloading W1nCray-linux-amd64.gz + SHA256SUMS on the landing host and verifying"
  rsh "$LANDING_HOST" "set -e
T=\$(mktemp -d)
cd \"\$T\"
curl -fsSL -m 300 -o W1nCray-linux-amd64.gz $(printf '%q' "$W1NCRAY_RELEASE_BASE/W1nCray-linux-amd64.gz")
curl -fsSL -m 60 -o SHA256SUMS $(printf '%q' "$W1NCRAY_RELEASE_BASE/SHA256SUMS")
grep -E ' \*?W1nCray-linux-amd64\.gz\$' SHA256SUMS | sed 's/ \*/  /' | sha256sum -c -
gzip -dc W1nCray-linux-amd64.gz > $(printf '%q' "$LANDING_BIN.next")
cd / && rm -rf \"\$T\"
chmod 755 $(printf '%q' "$LANDING_BIN.next")
echo DOWNLOAD-VERIFIED" | tee /dev/stderr | grep -q DOWNLOAD-VERIFIED || die "download/verification failed; nothing was changed"
else
info "uploading to $LANDING_BIN.next"
rput "$W1NCRAY_BINARY" "$LANDING_BIN.next" "$LANDING_HOST"
rsh "$LANDING_HOST" "chmod 755 $(printf '%q' "$LANDING_BIN.next")"
fi

info "the new binary must run and accept the live config before anything stops"
if [ "${DRY_RUN:-0}" = "1" ]; then
  log "[dry-run] $LANDING_BIN.next version; $LANDING_BIN.next check -c $LANDING_CONF_DIR/config.yml"
else
  VERSION_OUT="$(rsh "$LANDING_HOST" "$LANDING_BIN.next version 2>&1 | head -1")"
  printf '%s\n' "$VERSION_OUT"
  printf '%s\n' "$VERSION_OUT" | grep -q 'W1nCray' || die "the new binary does not answer 'version'"
  CHECK_OUT="$(rsh "$LANDING_HOST" "$LANDING_BIN.next check -c $(printf '%q' "$LANDING_CONF_DIR/config.yml") 2>&1 | tail -25")"
  printf '%s\n' "$CHECK_OUT"
  if ! printf '%s\n' "$CHECK_OUT" | grep -q '检查通过'; then
    rsh "$LANDING_HOST" "rm -f $(printf '%q' "$LANDING_BIN.next")" || true
    die "the new binary rejects the current config; nothing was changed"
  fi
  ok "the new binary accepts the live config"
fi

# ---------------------------------------------------------------------------
# swap
# ---------------------------------------------------------------------------
confirm "Stop $LANDING_SERVICE, swap the binary, start again?"
if [ "${DRY_RUN:-0}" = "1" ]; then
  log "[dry-run] systemctl stop $LANDING_SERVICE; mv $LANDING_BIN.next $LANDING_BIN; systemctl start $LANDING_SERVICE"
else
  rsh "$LANDING_HOST" "systemctl stop $(printf '%q' "$LANDING_SERVICE")" || warn "stop returned non-zero"
  rsh "$LANDING_HOST" "set -e
mv $(printf '%q' "$LANDING_BIN.next") $(printf '%q' "$LANDING_BIN")
chmod 755 $(printf '%q' "$LANDING_BIN")
systemctl start $(printf '%q' "$LANDING_SERVICE")"
fi

info "waiting for the service"
STARTED=0
if [ "${OFFLINE:-0}" = "1" ]; then
  warn "offline: skipping the service wait"
  STARTED=1
else
  for i in $(seq 1 15); do
    if probe_out "$LANDING_HOST" "systemctl is-active --quiet $(printf '%q' "$LANDING_SERVICE")"; then
      STARTED=1
      break
    fi
    log "  ... not active yet ($i/15)"
    sleep 3
  done
fi

if [ "$STARTED" != "1" ]; then
  fail "the service did not come up; rolling back the binary and the config"
  rsh "$LANDING_HOST" "set -e
systemctl stop $(printf '%q' "$LANDING_SERVICE") || true
cp -a $(printf '%q' "$(dirname "$LANDING_BIN")/W1nCray.bak-$TS") $(printf '%q' "$LANDING_BIN")
if [ -d $(printf '%q' "$LANDING_CONF_DIR.bak-$TS") ]; then
  rm -rf $(printf '%q' "$LANDING_CONF_DIR").failed-$$
  mv $(printf '%q' "$LANDING_CONF_DIR") $(printf '%q' "$LANDING_CONF_DIR").failed-$$
  cp -a $(printf '%q' "$LANDING_CONF_DIR.bak-$TS") $(printf '%q' "$LANDING_CONF_DIR")
fi
systemctl start $(printf '%q' "$LANDING_SERVICE")
sleep 8
systemctl is-active $(printf '%q' "$LANDING_SERVICE")" || true
  rsh "$LANDING_HOST" "journalctl -u $(printf '%q' "$LANDING_SERVICE") --since '-90s' --no-pager | tail -30" || true
  die "upgrade failed; the previous binary and config are back in place"
fi
ok "the service is active"

info "expected listeners: $EXPECT_PORTS"
if [ "${DRY_RUN:-0}" = "1" ]; then
  log "[dry-run] ss -tlnp | grep for each of: $EXPECT_PORTS"
else
  for p in $EXPECT_PORTS; do
    if probe_out "$LANDING_HOST" "ss -tlnp 2>/dev/null | grep -qE ':$(printf '%s' "$p")[[:space:]]'"; then
      ok "port $p listening"
    else
      fail "port $p is NOT listening"
      rsh "$LANDING_HOST" "journalctl -u $(printf '%q' "$LANDING_SERVICE") --since '-60s' --no-pager | tail -20" || true
      die "the new binary does not listen on $p; roll back with --rollback-only --rollback-ts $TS"
    fi
  done
fi

# ---------------------------------------------------------------------------
# split layout (agent.yml) via `W1nCray link`
# ---------------------------------------------------------------------------
log ""
info "split layout migration (agent.yml)"
if [ "$SKIP_LINK" = "1" ]; then
  warn "--skip-link: agent.yml was left exactly as it is"
elif [ -z "$PANEL_URL" ] || [ -z "$MACHINE_ID" ]; then
  warn "PANEL_URL and/or MACHINE_ID are empty: skipping the split migration."
  warn "the machine keeps the legacy single-file layout (config.yml Agent: block)."
  warn "set PANEL_URL=https://... MACHINE_ID=<id> and re-run with --skip-link off."
else
  if [ "$ENABLE_TERMINAL" = "no" ]; then
    NOTERMINAL_ARG="--noterminal"
  else
    NOTERMINAL_ARG=""
  fi

  if probe_out "$LANDING_HOST" "test -f $(printf '%q' "$LANDING_CONF_DIR")/agent.yml"; then
    if probe_out "$LANDING_HOST" "sed -n '/^Panel:/,/^[^[:space:]#]/p' $(printf '%q' "$LANDING_CONF_DIR")/agent.yml | grep -q '^[[:space:]]*Enabled:[[:space:]]*true'"; then
      info "agent.yml already links a panel; link would refuse without --force."
      info "leaving it untouched — the binary upgrade alone is the change here."
      if [ "$ENABLE_TERMINAL" = "no" ]; then
        warn "ENABLE_TERMINAL=no, but this machine already has an agent.yml."
        warn "the terminal switch must be applied locally by hand:"
        warn "  add 'Terminal: {Enabled: false}' to $LANDING_CONF_DIR/agent.yml, or run"
        warn "  W1nCray link --panel $PANEL_URL --machine $MACHINE_ID --token-file $TOKEN_FILE --noterminal --force"
      fi
      SKIP_LINK=1
    fi
  fi

  if [ "$SKIP_LINK" != "1" ]; then
    info "step 1/2: link --dry-run (prints the plan, writes nothing)"
    if [ "${DRY_RUN:-0}" = "1" ]; then
      log "[dry-run] $LANDING_BIN link --panel $PANEL_URL --machine $MACHINE_ID --token-file $TOKEN_FILE $NOTERMINAL_ARG --dry-run"
    else
      rsh "$LANDING_HOST" "$(printf '%q' "$LANDING_BIN") link --panel $(printf '%q' "$PANEL_URL") --machine $(printf '%q' "$MACHINE_ID") --token-file $(printf '%q' "$TOKEN_FILE") $NOTERMINAL_ARG --dry-run 2>&1 | tail -40" || die "link --dry-run failed"
    fi

    confirm "The dry-run plan above looks right — apply it for real (link backs up config.yml and agent.yml itself)?"
    info "step 2/2: link (writes agent.yml + rewrites the legacy Agent: block)"
    if [ "${DRY_RUN:-0}" = "1" ]; then
      log "[dry-run] $LANDING_BIN link --panel $PANEL_URL --machine $MACHINE_ID --token-file $TOKEN_FILE $NOTERMINAL_ARG"
    else
      rsh "$LANDING_HOST" "$(printf '%q' "$LANDING_BIN") link --panel $(printf '%q' "$PANEL_URL") --machine $(printf '%q' "$MACHINE_ID") --token-file $(printf '%q' "$TOKEN_FILE") $NOTERMINAL_ARG 2>&1 | tail -40" || die "link failed (config.yml is backed up as config.yml.bak-link-*)"
      info "link never restarts the service; restarting now"
      rsh "$LANDING_HOST" "systemctl restart $(printf '%q' "$LANDING_SERVICE") && sleep 10 && systemctl is-active $(printf '%q' "$LANDING_SERVICE")"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------
log ""
info "verification"
probe_out "$LANDING_HOST" "set -e
printf 'version: '; $(printf '%q' "$LANDING_BIN") version 2>&1 | head -1
printf 'unit: %s\n' \"\$(systemctl is-active $(printf '%q' "$LANDING_SERVICE") 2>&1 || true)\"
printf 'agent_yml=%s\n' \"\$( [ -f $(printf '%q' "$LANDING_CONF_DIR")/agent.yml ] && echo present || echo absent )\"
printf 'terminal_key=%s\n' \"\$(grep -cE '^[[:space:]]*Terminal:' $(printf '%q' "$LANDING_CONF_DIR")/agent.yml 2>/dev/null || echo 0)\"
printf 'restarts_since_boot=%s\n' \"\$(systemctl show $(printf '%q' "$LANDING_SERVICE") -p NRestarts --value)\"
printf -- '--- last 40 log lines ---\n'
journalctl -u $(printf '%q' "$LANDING_SERVICE") --since '-3min' --no-pager | grep -E 'machine |panel|node applied|terminal|manifest|level=error|panic' | grep -viE 'drain|rejected' | tail -25 || true" || warn "verification probe failed"

if [ "${OFFLINE:-0}" != "1" ]; then
  info "the config must still pass the offline check"
  rsh "$LANDING_HOST" "$(printf '%q' "$LANDING_BIN") check -c $(printf '%q' "$LANDING_CONF_DIR/config.yml") 2>&1 | tail -15" || warn "check returned non-zero"
fi

if [ "$ENABLE_TERMINAL" = "no" ]; then
  info "terminal expectation: agent.yml must carry Terminal: {Enabled: false}"
  if probe_out "$LANDING_HOST" "grep -qE '^[[:space:]]*Terminal:[[:space:]]*\\{Enabled:[[:space:]]*false\\}' $(printf '%q' "$LANDING_CONF_DIR")/agent.yml 2>/dev/null"; then
    ok "terminal is off locally"
  else
    warn "no explicit Terminal: {Enabled: false} found — the terminal is ON for this machine."
    warn "apply it by hand: printf 'Terminal: {Enabled: false}\\n' >> $LANDING_CONF_DIR/agent.yml && systemctl restart $LANDING_SERVICE"
  fi
fi

ok "agent upgraded to $VERSION_OUT"
ROLLBACK_HINT="$HERE/70-agent-upgrade.sh --rollback-only --rollback-ts $TS"
ROLLBACK_SCRIPT="$HERE/70-agent-upgrade.sh --rollback-only --rollback-ts $TS"
step_end

log ""
log "next: 80-verify-agent.sh (panel side: is the machine back online?)."
