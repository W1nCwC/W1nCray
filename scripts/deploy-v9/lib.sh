#!/usr/bin/env bash
# scripts/deploy-v9/lib.sh — shared helpers for the PLAN v9 production runbook.
#
# Everything that touches a remote host goes through `rsh` (run) / `rput`
# (copy).  Nothing here is executed by sourcing alone; the step scripts call
# these functions after parsing their own arguments.
#
# Guarantees this file provides to every step script:
#   * `set -euo pipefail` is already on (the step scripts set it; we assert it),
#   * `--dry-run` is a global flag (`DRY_RUN=1`): mutating calls print the exact
#     remote command instead of running it.  Read-only probes still connect
#     unless `--offline` is given, because a preflight that cannot see the host
#     is worthless.
#   * every ssh/scp goes through the SOCKS5 proxy by default
#     (`connect.exe -S 127.0.0.1:7890 %h %p`, overridable with $PROXY_CMD).
#   * host names, paths and the key file live in this block and nowhere else.
#
# This file never contains a token, a password or an e-mail address.  Secrets
# are only ever read from files whose paths are passed on the command line.

# ---------------------------------------------------------------------------
# 1. Hosts, paths, key file — the single place to change them
# ---------------------------------------------------------------------------
# These are host addresses, not credentials.  Override per run with env vars,
# e.g.  PANEL_HOST=root@167.253.156.95 scripts/deploy-v9/10-panel-files.sh ...
: "${PANEL_HOST:=root@167.253.156.95}"
: "${LANDING_HOST:=root@82.152.167.105}"

# SSH identity.  Leave empty to use the agent / ~/.ssh/config default.
: "${SSH_KEY:=}"
: "${SSH_USER:=}"
: "${SSH_PORT:=22}"

# SOCKS5 proxy that both hosts are only reachable through.
: "${PROXY_HOST:=127.0.0.1}"
: "${PROXY_PORT:=7890}"
: "${PROXY_CMD:=connect.exe -S ${PROXY_HOST}:${PROXY_PORT} %h %p}"
: "${SSH_OPTS:=-o ConnectTimeout=25 -o ServerAliveInterval=30 -o ServerAliveCountMax=6 -o Compression=yes -o StrictHostKeyChecking=accept-new}"

# Remote layout (production).
: "${PANEL_ROOT:=/www/wwwroot/xboard}"        # host path of the panel checkout
: "${PANEL_CODE:=/www}"                        # in-container code path
: "${PANEL_WEB_CONTAINER:=xboard-web-1}"       # octane container
: "${PANEL_HORIZON_CONTAINER:=xboard-horizon-1}"
: "${PANEL_COMPOSE_FILE:=docker-compose.yml}"  # relative to PANEL_ROOT
: "${PANEL_WS_OVERRIDE:=compose.w1ncray-ws.yaml}"
: "${PANEL_NGINX_CONF:=/www/server/panel/vhost/nginx/subscribe.w1ncray.xyz.conf}"
: "${PANEL_NGINX_LOG:=/www/wwwlogs/subscribe.w1ncray.xyz.log}"
: "${PANEL_GATEWAY_PORT:=8077}"                # w1ncray-ws listen port
: "${PANEL_LEGACY_PORT:=8076}"                 # legacy /ws, never touched
: "${PANEL_HTTP_PORT:=7001}"                   # octane, published on 127.0.0.1
: "${PANEL_NGINX_SCHEME:=http}"                # scheme used by the host-local curls
: "${PANEL_NGINX_PORT:=80}"                    # port nginx listens on locally
: "${PANEL_SPA_DIR:=public/assets/admin}"
: "${PANEL_W1NCRAY_DIR:=public/w1ncray}"
: "${PANEL_BACKUP_BASE:=/root}"                # deployN dirs live here

: "${LANDING_BIN:=/usr/local/W1nCray/W1nCray}"
: "${LANDING_CONF_DIR:=/etc/W1nCray}"
: "${LANDING_SERVICE:=W1nCray.service}"
: "${LANDING_TOKEN_FILE:=/etc/W1nCray/agent.token}"

# Local checkout of the panel (the deploy copies FROM here).
: "${PANEL_SRC:=C:/W1nCBoard}"

# ---------------------------------------------------------------------------
# 2. Output + control flow
# ---------------------------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  _C_RED=$'\033[31m'; _C_GRN=$'\033[32m'; _C_YEL=$'\033[33m'; _C_BLU=$'\033[34m'; _C_OFF=$'\033[0m'
else
  _C_RED=''; _C_GRN=''; _C_YEL=''; _C_BLU=''; _C_OFF=''
fi

log()  { printf '%s\n' "$*"; }
info() { printf '%s[info]%s %s\n'  "$_C_BLU" "$_C_OFF" "$*"; }
ok()   { printf '%s[ ok ]%s %s\n'  "$_C_GRN" "$_C_OFF" "$*"; }
warn() { printf '%s[warn]%s %s\n'  "$_C_YEL" "$_C_OFF" "$*" >&2; }
fail() { printf '%s[fail]%s %s\n'  "$_C_RED" "$_C_OFF" "$*" >&2; }

die() { fail "$*"; exit 1; }

# step_begin NAME — prints the banner, the dry-run state and the rollback hint.
step_begin() {
  STEP_NAME="$1"
  log ""
  log "=============================================================="
  log "  ${STEP_NAME}"
  log "=============================================================="
  if [ "${DRY_RUN:-0}" = "1" ]; then
    warn "DRY-RUN: no remote change will be made; the exact commands are printed."
  fi
  if [ "${OFFLINE:-0}" = "1" ]; then
    warn "OFFLINE: read-only probes are skipped too."
  fi
}

step_end() {
  ok "${STEP_NAME}: done."
  if [ -n "${ROLLBACK_HINT:-}" ]; then
    log "rollback for this step: ${ROLLBACK_HINT}"
  fi
  if [ -n "${ROLLBACK_SCRIPT:-}" ]; then
    log "rollback script:        ${ROLLBACK_SCRIPT}"
  fi
}

# ---------------------------------------------------------------------------
# 3. Argument parsing shared by every step
# ---------------------------------------------------------------------------
# parse_common "$@" — sets DRY_RUN / OFFLINE, leaves everything else to the
# caller.  Unknown flags are collected in EXTRA_ARGS.
parse_common() {
  DRY_RUN=0
  OFFLINE=0
  EXTRA_ARGS=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --dry-run|-n) DRY_RUN=1 ;;
      --offline)    OFFLINE=1 ;;
      --yes|-y)     ASSUME_YES=1 ;;
      -h|--help)    usage_common; exit 0 ;;
      *)            EXTRA_ARGS+=("$1") ;;
    esac
    shift
  done
}

usage_common() {
  cat <<EOF
common flags:
  --dry-run | -n   print the remote commands, change nothing
  --offline        skip even the read-only probes (implies no ssh at all)
  --yes | -y       do not ask before destructive sub-steps
  -h | --help      this text
environment overrides:
  PANEL_HOST=$PANEL_HOST  LANDING_HOST=$LANDING_HOST
  SSH_KEY=${SSH_KEY:-<default>}  PROXY_CMD=$PROXY_CMD
  PANEL_ROOT=$PANEL_ROOT  PANEL_NGINX_CONF=$PANEL_NGINX_CONF
EOF
}

# ---------------------------------------------------------------------------
# 4. SSH / SCP
# ---------------------------------------------------------------------------
_ssh_cmd() { # _ssh_cmd <host> -> prints the full ssh command line
  local host="$1"
  local -a a=(ssh)
  [ -n "$SSH_KEY" ]  && a+=(-i "$SSH_KEY")
  [ -n "$SSH_PORT" ] && a+=(-p "$SSH_PORT")
  [ -n "${PROXY_CMD:-}" ] && a+=(-o "ProxyCommand=${PROXY_CMD}")
  # shellcheck disable=SC2206
  [ -n "$SSH_OPTS" ] && a+=($SSH_OPTS)
  a+=("$host")
  printf '%q ' "${a[@]}"
}

# rsh HOST 'remote command'
# Mutating by default: honours DRY_RUN.
rsh() {
  local host="$1"; shift
  local cmd="$*"
  if [ "${DRY_RUN:-0}" = "1" ]; then
    log "[dry-run] $(_ssh_cmd "$host") $(printf '%q' "$cmd")"
    return 0
  fi
  local -a a=(ssh)
  [ -n "$SSH_KEY" ]  && a+=(-i "$SSH_KEY")
  [ -n "$SSH_PORT" ] && a+=(-p "$SSH_PORT")
  [ -n "${PROXY_CMD:-}" ] && a+=(-o "ProxyCommand=${PROXY_CMD}")
  # shellcheck disable=SC2206
  [ -n "$SSH_OPTS" ] && a+=($SSH_OPTS)
  a+=("$host" "$cmd")
  "${a[@]}"
}

# probe HOST 'read-only command' — same, but also runs under --dry-run and is
# skipped under --offline.  Use it only for commands that change nothing.
probe() {
  local host="$1"; shift
  local cmd="$*"
  if [ "${OFFLINE:-0}" = "1" ]; then
    log "[offline] skipped probe on $host: $cmd"
    return 0
  fi
  if [ "${DRY_RUN:-0}" = "1" ]; then
    log "[dry-run] probe: $(_ssh_cmd "$host") $(printf '%q' "$cmd")"
  fi
  local -a a=(ssh)
  [ -n "$SSH_KEY" ]  && a+=(-i "$SSH_KEY")
  [ -n "$SSH_PORT" ] && a+=(-p "$SSH_PORT")
  [ -n "${PROXY_CMD:-}" ] && a+=(-o "ProxyCommand=${PROXY_CMD}")
  # shellcheck disable=SC2206
  [ -n "$SSH_OPTS" ] && a+=($SSH_OPTS)
  a+=("$host" "$cmd")
  "${a[@]}"
}

# probe_out HOST 'read-only command' — like probe, but prints the remote output
# and returns the remote exit status (ssh's own status is 255).  Under
# --offline it prints a marker and returns 0 so callers can keep going.
probe_out() {
  local host="$1"; shift
  local cmd="$*"
  if [ "${OFFLINE:-0}" = "1" ]; then
    log "[offline] skipped probe on $host: $cmd"
    return 0
  fi
  if [ "${DRY_RUN:-0}" = "1" ]; then
    log "[dry-run] probe: $(_ssh_cmd "$host") $(printf '%q' "$cmd")"
  fi
  local -a a=(ssh)
  [ -n "$SSH_KEY" ]  && a+=(-i "$SSH_KEY")
  [ -n "$SSH_PORT" ] && a+=(-p "$SSH_PORT")
  [ -n "${PROXY_CMD:-}" ] && a+=(-o "ProxyCommand=${PROXY_CMD}")
  # shellcheck disable=SC2206
  [ -n "$SSH_OPTS" ] && a+=($SSH_OPTS)
  a+=("$host" "$cmd")
  "${a[@]}"
}

# remote_ok HOST 'read-only command' — true when the remote command exits 0.
remote_ok() {
  local host="$1"; shift
  probe_out "$host" "$@" >/dev/null 2>&1
}

# rsh_stdin HOST 'remote command' — like rsh, but the local stdin is forwarded
# to the remote command.  Use it to pipe a small script or a file list into the
# host without quoting it into the command line.
rsh_stdin() {
  local host="$1"; shift
  local cmd="$*"
  if [ "${DRY_RUN:-0}" = "1" ]; then
    log "[dry-run] <stdin> | $(_ssh_cmd "$host") $(printf '%q' "$cmd")"
    return 0
  fi
  local -a a=(ssh)
  [ -n "$SSH_KEY" ]  && a+=(-i "$SSH_KEY")
  [ -n "$SSH_PORT" ] && a+=(-p "$SSH_PORT")
  [ -n "${PROXY_CMD:-}" ] && a+=(-o "ProxyCommand=${PROXY_CMD}")
  # shellcheck disable=SC2206
  [ -n "$SSH_OPTS" ] && a+=($SSH_OPTS)
  a+=("$host" "$cmd")
  "${a[@]}"
}

# rput LOCAL REMOTE  (scp, same proxy settings, honours DRY_RUN)
rput() {
  local local_path="$1" remote="$2" host="${3:-$PANEL_HOST}"
  if [ "${DRY_RUN:-0}" = "1" ]; then
    log "[dry-run] scp $(printf '%q' "$local_path") -> ${host}:${remote}"
    return 0
  fi
  local -a a=(scp)
  [ -n "$SSH_KEY" ]  && a+=(-i "$SSH_KEY")
  [ -n "$SSH_PORT" ] && a+=(-P "$SSH_PORT")
  [ -n "${PROXY_CMD:-}" ] && a+=(-o "ProxyCommand=${PROXY_CMD}")
  # shellcheck disable=SC2206
  [ -n "$SSH_OPTS" ] && a+=($SSH_OPTS)
  a+=("$local_path" "${host}:${remote}")
  "${a[@]}"
}

# rtar STAGE LOCAL_BASE < FILELIST — stream a tar of the listed files into
# REMOTE_DIR on HOST.  The list is newline separated relative paths.
# Usage:  tar_manifest "$LOCAL_BASE" "$PANEL_HOST" "$STAGE" < panel-files.txt
tar_manifest() {
  local base="$1" host="$2" remote_dir="$3"
  if [ "${DRY_RUN:-0}" = "1" ]; then
    log "[dry-run] tar -C $(printf '%q' "$base") -cf - -T - | ssh $host 'tar -C $(printf '%q' "$remote_dir") -xf -'"
    return 0
  fi
  local -a a=(ssh)
  [ -n "$SSH_KEY" ]  && a+=(-i "$SSH_KEY")
  [ -n "$SSH_PORT" ] && a+=(-p "$SSH_PORT")
  [ -n "${PROXY_CMD:-}" ] && a+=(-o "ProxyCommand=${PROXY_CMD}")
  # shellcheck disable=SC2206
  [ -n "$SSH_OPTS" ] && a+=($SSH_OPTS)
  a+=("$host" "tar -C $(printf '%q' "$remote_dir") -xf -")
  tar -C "$base" -cf - -T - | "${a[@]}"
}

# ---------------------------------------------------------------------------
# 5. Backup / rollback primitives (host side, run over rsh)
# ---------------------------------------------------------------------------
# A step's backup directory holds the pristine copies plus two lists:
#   overwritten.txt  files that existed before  -> restore from backup/
#   added.txt        files that did not exist   -> delete on rollback
new_stage() { # new_stage <label> -> prints the remote staging dir
  local label="$1"
  printf '%s/w1ncray-deploy-%s-%s' "$PANEL_BACKUP_BASE" "$(date +%Y%m%d-%H%M%S)" "$label"
}

# backup_files HOST STAGE REMOTE_BASE < FILELIST
# Creates STAGE/{backup,added.txt,overwritten.txt} and copies every existing
# file out of REMOTE_BASE into STAGE/backup preserving relative paths.
backup_files() {
  local host="$1" stage="$2" remote_base="$3"
  if [ "${DRY_RUN:-0}" = "1" ]; then
    log "[dry-run] backup every existing file of the list from ${remote_base} into ${stage}/backup"
    return 0
  fi
  local list; list="$(cat)"
  local payload
  payload="$(cat <<REMOTE
set -euo pipefail
STAGE=$(printf '%q' "$stage")
BASE=$(printf '%q' "$remote_base")
mkdir -p "\$STAGE/backup"
: > "\$STAGE/added.txt"
: > "\$STAGE/overwritten.txt"
while IFS= read -r f; do
  [ -n "\$f" ] || continue
  if [ -e "\$BASE/\$f" ]; then
    mkdir -p "\$STAGE/backup/\$(dirname "\$f")"
    cp -a "\$BASE/\$f" "\$STAGE/backup/\$f"
    printf '%s\n' "\$f" >> "\$STAGE/overwritten.txt"
  else
    printf '%s\n' "\$f" >> "\$STAGE/added.txt"
  fi
done <<'FILELIST_EOF'
$list
FILELIST_EOF
printf 'backed up %s file(s), %s new\n' "\$(wc -l < "\$STAGE/overwritten.txt")" "\$(wc -l < "\$STAGE/added.txt")"
REMOTE
)"
  rsh "$host" "$payload"
}

# restore_files HOST STAGE REMOTE_BASE — the inverse of backup_files.
restore_files() {
  local host="$1" stage="$2" remote_base="$3"
  if [ "${DRY_RUN:-0}" = "1" ]; then
    log "[dry-run] restore overwritten.txt from ${stage}/backup and delete added.txt under ${remote_base}"
    return 0
  fi
  local payload
  payload="$(cat <<REMOTE
set -euo pipefail
STAGE=$(printf '%q' "$stage")
BASE=$(printf '%q' "$remote_base")
if [ -d "\$STAGE/backup" ]; then
  while IFS= read -r f; do
    [ -n "\$f" ] || continue
    mkdir -p "\$BASE/\$(dirname "\$f")"
    cp -a "\$STAGE/backup/\$f" "\$BASE/\$f"
  done < "\$STAGE/overwritten.txt"
fi
while IFS= read -r f; do
  [ -n "\$f" ] || continue
  rm -f "\$BASE/\$f"
done < "\$STAGE/added.txt"
echo "restored \$(wc -l < "\$STAGE/overwritten.txt") file(s), removed \$(wc -l < "\$STAGE/added.txt")"
REMOTE
)"
  rsh "$host" "$payload"
}

# write_stage_marker HOST STAGE TEXT — a breadcrumb for the operator.
write_stage_marker() {
  local host="$1" stage="$2" text="$3"
  rsh "$host" "mkdir -p $(printf '%q' "$stage") && printf '%s\n' $(printf '%q' "$text") > $(printf '%q' "$stage/STEP.txt")"
}

# ---------------------------------------------------------------------------
# 6. Manifest helpers (local side)
# ---------------------------------------------------------------------------
# read_manifest FILE -> validates and echoes the entries (one per line),
# skipping comments and blank lines.  Every entry must be a relative path.
read_manifest() {
  local file="$1"
  [ -f "$file" ] || die "manifest not found: $file"
  grep -v -E '^[[:space:]]*(#|$)' "$file" | sed -e 's/[[:space:]]*$//' | sort -u
}

# check_manifest_local BASE FILE — every entry must exist under BASE.
check_manifest_local() {
  local base="$1" file="$2" missing=0 n=0
  while IFS= read -r f; do
    n=$((n + 1))
    if [ ! -f "$base/$f" ]; then
      fail "manifest entry missing locally: $f"
      missing=$((missing + 1))
    fi
  done < <(read_manifest "$file")
  [ "$missing" -eq 0 ] || die "$missing of $n manifest entries are missing under $base"
  ok "manifest $file: $n file(s), all present under $base"
}

# check_manifest_remote HOST BASE FILE — prints how many already exist there and
# returns 1 when any entry is still missing.
check_manifest_remote() {
  local host="$1" base="$2" file="$3"
  local list; list="$(read_manifest "$file")"
  local payload
  payload="$(cat <<REMOTE
set -euo pipefail
BASE=$(printf '%q' "$base")
have=0; miss=0
while IFS= read -r f; do
  [ -n "\$f" ] || continue
  if [ -e "\$BASE/\$f" ]; then have=\$((have+1)); else miss=\$((miss+1)); fi
done <<'FILELIST_EOF'
$list
FILELIST_EOF
printf 'existing=%s new=%s\n' "\$have" "\$miss"
[ "\$miss" -eq 0 ]
REMOTE
)"
  probe_out "$host" "$payload"
}

# ---------------------------------------------------------------------------
# 7. Local file inventory
# ---------------------------------------------------------------------------
# panel_files() -> the exact list this deployment copies (see panel-files.txt).
manifest_path() { printf '%s/%s' "$(dirname "${BASH_SOURCE[0]}")" "$1"; }

# ---------------------------------------------------------------------------
# 8. Guards
# ---------------------------------------------------------------------------
# A step script must never run without the shell options it relies on.
require_strict_mode() {
  case "$-" in
    *e*) : ;;
    *) die "this script must run with 'set -euo pipefail' (source it, do not exec it)" ;;
  esac
}

# Refuse to touch a path that is obviously wrong.  Called before any rm -rf.
guard_path() {
  local p="$1" what="$2"
  case "$p" in
    ""|/|/root|/etc|/www|/usr|/usr/local|"$HOME") die "refusing to operate on $what: '$p' looks like a system path" ;;
  esac
  case "$p" in
    /*) : ;;
    *) die "refusing to operate on $what: '$p' is not an absolute path" ;;
  esac
}

# confirm QUESTION — asks unless ASSUME_YES=1 or DRY_RUN=1.
confirm() {
  local q="$1"
  if [ "${ASSUME_YES:-0}" = "1" ] || [ "${DRY_RUN:-0}" = "1" ]; then
    info "$q -> assumed yes"
    return 0
  fi
  printf '%s [yes/no] ' "$q"
  local a=""
  read -r a || true
  [ "$a" = "yes" ] || die "aborted by the operator"
}
