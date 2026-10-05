#!/bin/sh
# Tests for install.sh. Works with dash, busybox ash and bash:
#
#   sh tests/install_test.sh
#
# install.sh is sourced (W1NCRAY_LIB=1) and run against a temporary root
# (W1NCRAY_ROOT) with a mock service backend and a mock `download`, so nothing
# on the machine is touched and no network is used.

HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/../install.sh"
TMPROOT="$(mktemp -d)"
RESULTS="$TMPROOT/results"
: >"$RESULTS"
trap 'rm -rf "$TMPROOT"' EXIT INT TERM

pass() {
	printf 'PASS %s\n' "$1"
	printf 'PASS\n' >>"$RESULTS"
}
fail() {
	printf 'FAIL %s\n' "$1"
	printf 'FAIL\n' >>"$RESULTS"
}
check() { # message command...
	_m="$1"
	shift
	if "$@" >/dev/null 2>&1; then pass "$_m"; else fail "$_m"; fi
}
refute() { # message command...  (the command must fail)
	_m="$1"
	shift
	if "$@" >/dev/null 2>&1; then fail "$_m"; else pass "$_m"; fi
}
eq() { # message got want
	if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi
}
has() { # message haystack needle
	case "$2" in *"$3"*) pass "$1" ;; *) fail "$1 (missing '$3')" ;; esac
}
hasnt() { # message haystack needle
	case "$2" in *"$3"*) fail "$1 (found '$3')" ;; *) pass "$1" ;; esac
}
new_root() {
	_r="$(mktemp -d "$TMPROOT/root.XXXXXX")"
	mkdir -p "$_r/state"
	echo "$_r"
}

# lib ROOT sources install.sh against ROOT in the current (sub)shell.
lib() {
	W1NCRAY_LIB=1
	W1NCRAY_ROOT="$1"
	W1NCRAY_SKIP_SPACE_CHECK=1
	W1NCRAY_WAIT=0
	export W1NCRAY_LIB W1NCRAY_ROOT W1NCRAY_SKIP_SPACE_CHECK W1NCRAY_WAIT
	# shellcheck disable=SC1090
	. "$SCRIPT"
	set +eu
	ASSUME_YES=1
	AS_MANAGER=0
	load_env
}

# ---- fixtures ---------------------------------------------------------------

make_fake_bin() { # path [flavor]
	cat >"$1" <<'EOF'
#!/bin/sh
case "$1" in
version) echo "W1nCray vTEST (Xray-core 26.3.27, ${FAKE_FLAVOR:-full})" ;;
init) mkdir -p "$3" && echo "Nodes: []" >"$3/config.yml" && echo "init $3" ;;
migrate) [ -n "$FAKE_NOWRITE" ] && { echo "ARGS: $*"; exit 0; }; mkdir -p "$5" && echo "migrated" >"$5/config.yml" && echo "migrate $*" ;;
check) echo "check ok ARGS: $*"; exit "${FAKE_CHECK_RC:-0}" ;;
*) echo "ARGS: $*" ;;
esac
EOF
	chmod 755 "$1"
}

make_broken_bin() { # a binary that cannot run on this CPU
	printf '#!/bin/sh\nexit 1\n' >"$1"
	chmod 755 "$1"
}

elf_fixture() { # path endian(l|b)
	if [ "$2" = l ]; then
		printf '\177ELF\001\001\001\000' >"$1"
	else
		printf '\177ELF\001\002\001\000' >"$1"
	fi
}

# Mock service backend; state lives in $W1NCRAY_ROOT/state.
mock_backend() {
	CALLS="$W1NCRAY_ROOT/calls.log"
	ST="$W1NCRAY_ROOT/state"
	: >"$CALLS"
	W1NCRAY_BACKEND=mock
	BACKEND=mock
	be_mock_install() {
		echo "install W1nCray" >>"$CALLS"
		: >"$ST/W1nCray.exists"
	}
	be_mock_remove() {
		echo "remove $1" >>"$CALLS"
		rm -f "$ST/$1.exists"
	}
	be_mock_exists() { [ -e "$ST/$1.exists" ]; }
	be_mock_active() { [ -e "$ST/$1.active" ]; }
	be_mock_enabled() { [ -e "$ST/$1.enabled" ]; }
	be_mock_start() {
		echo "start $1" >>"$CALLS"
		[ -e "$ST/$1.failstart" ] || : >"$ST/$1.active"
	}
	be_mock_stop() {
		echo "stop $1" >>"$CALLS"
		rm -f "$ST/$1.active"
	}
	be_mock_restart() {
		echo "restart $1" >>"$CALLS"
		: >"$ST/$1.active"
	}
	be_mock_enable() {
		echo "enable $1 ${2:-}" >>"$CALLS"
		: >"$ST/$1.enabled"
	}
	be_mock_disable() {
		echo "disable $1" >>"$CALLS"
		rm -f "$ST/$1.enabled"
	}
	be_mock_log() { echo "mock log of $1: level=error boom websocket connected"; }
	be_mock_follow() { echo "follow $1" >>"$CALLS"; }
	be_mock_levels() { [ -f "$ST/$1.levels" ] && cat "$ST/$1.levels"; return 0; }
}

# Release downloads: serve fixtures from $W1NCRAY_ROOT/release for a tag.
mock_downloads() {
	DL_LOG="$W1NCRAY_ROOT/downloads.log"
	: >"$DL_LOG"
	download() { # url dest
		echo "$1" >>"$DL_LOG"
		case "$1" in
		*"api.github.com"*) [ -f "$W1NCRAY_ROOT/release/api.json" ] && cp "$W1NCRAY_ROOT/release/api.json" "$2" ;;
		*releases.atom) [ -f "$W1NCRAY_ROOT/release/atom.xml" ] && cp "$W1NCRAY_ROOT/release/atom.xml" "$2" ;;
		*/releases/download/*/*)
			_f="$W1NCRAY_ROOT/release/${1##*/}"
			[ -f "$_f" ] && cp "$_f" "$2"
			;;
		*geoip.dat | *geosite.dat) echo geo >"$2" ;;
		*raw.githubusercontent.com*) [ -f "$W1NCRAY_ROOT/release/install.sh" ] && cp "$W1NCRAY_ROOT/release/install.sh" "$2" ;;
		*) return 1 ;;
		esac
	}
}

# publish ASSETNAME BINFILE adds <asset>.gz and its SHA256SUMS line.
publish() {
	mkdir -p "$W1NCRAY_ROOT/release"
	gzip -c "$2" >"$W1NCRAY_ROOT/release/$1"
	printf '%s *%s\n' "$(sha256sum "$W1NCRAY_ROOT/release/$1" | awk '{print $1}')" "$1" >>"$W1NCRAY_ROOT/release/SHA256SUMS"
}

# ---- tests --------------------------------------------------------------------

t_arch() {
	probe="$W1NCRAY_ROOT/probe"
	cpuinfo="$W1NCRAY_ROOT/cpuinfo"
	export W1NCRAY_ELF_PROBE="$probe" W1NCRAY_CPUINFO="$cpuinfo"
	arch_of() {
		W1NCRAY_UNAME_M="$1"
		export W1NCRAY_UNAME_M
		detect_arch 2>&1
	}
	for pair in x86_64:amd64 amd64:amd64 i386:386 i686:386 aarch64:arm64 arm64:arm64 riscv64:riscv64 loongarch64:loong64 armv5tel:armv5 armv5tejl:armv5; do
		eq "uname -m ${pair%%:*} -> ${pair##*:}" "$(arch_of "${pair%%:*}")" "${pair##*:}"
	done
	for case_ in "armv7l|half thumb fastmult vfp edsp neon vfpv3 tls vfpv4|armv7" \
		"armv7l|half thumb vfp edsp vfpv3d16 tls|armv7" \
		"armv8l|half thumb vfp neon vfpv3 vfpv4 idiva|armv7" \
		"armv7l|half thumb fastmult vfp edsp|armv6" \
		"armv7l|half thumb fastmult edsp|armv5" \
		"armv6l|half thumb fastmult vfp edsp tls|armv6" \
		"armv6l|half thumb fastmult edsp|armv5"; do
		m="${case_%%|*}"
		rest="${case_#*|}"
		feat="${rest%|*}"
		want="${rest##*|}"
		printf 'Processor\t: ARMv7\nFeatures\t: %s\nCPU implementer\t: 0x41\n' "$feat" >"$cpuinfo"
		eq "$m [$feat] -> $want" "$(arch_of "$m")" "$want"
	done
	elf_fixture "$probe" b
	eq "mips big endian -> mips" "$(arch_of mips)" mips
	eq "mips64 big endian -> mips64" "$(arch_of mips64)" mips64
	elf_fixture "$probe" l
	eq "mips little endian -> mipsle" "$(arch_of mips)" mipsle
	eq "mips64 little endian -> mips64le" "$(arch_of mips64)" mips64le
	has "ppc64le is refused" "$(arch_of ppc64le)" "不支持"
	has "armv4tl is refused" "$(arch_of armv4tl)" "不支持"
	W1NCRAY_UNAME_M=mips
	rm -f "$probe"
	W1NCRAY_ELF_PROBE=""
	export W1NCRAY_ELF_PROBE
	has "mips without a readable ELF probe says so" "$(detect_arch 2>&1)" "字节序"
	eq "arm fallbacks v7" "$(arch_fallbacks armv7)" "armv7 armv6 armv5"
	eq "arm fallbacks v6" "$(arch_fallbacks armv6)" "armv6 armv5"
	eq "no fallbacks for amd64" "$(arch_fallbacks amd64)" "amd64"
	eq "asset full" "$(asset_name armv7 full)" "W1nCray-linux-armv7.gz"
	eq "asset lite" "$(asset_name mipsle lite)" "W1nCray-linux-mipsle-lite.gz"
}

t_endian_dd_and_hexdump() {
	elf_fixture "$W1NCRAY_ROOT/le" l
	elf_fixture "$W1NCRAY_ROOT/be" b
	eq "elf_endian little" "$(elf_endian "$W1NCRAY_ROOT/le")" l
	eq "elf_endian big" "$(elf_endian "$W1NCRAY_ROOT/be")" b
	refute "elf_endian of a missing file fails" elf_endian "$W1NCRAY_ROOT/missing"
}

t_flavor_and_backend() {
	eq "default flavor off OpenWRT" "$(default_flavor)" full
	mkdir -p "$W1NCRAY_ROOT/etc"
	echo "DISTRIB_ID='OpenWrt'" >"$W1NCRAY_ROOT/etc/openwrt_release"
	eq "default flavor on OpenWRT" "$(default_flavor)" lite
	eq "OpenWRT manager lives in /usr/bin" "$(load_env && echo "$MGR")" "$W1NCRAY_ROOT/usr/bin/W1nCray"
	eq "OpenWRT backend is procd" "$(detect_backend)" procd
	rm -f "$W1NCRAY_ROOT/etc/openwrt_release"
	eq "no init system -> none" "$(detect_backend)" none
	mkdir -p "$W1NCRAY_ROOT/run/systemd/system"
	eq "systemd detected" "$(detect_backend)" systemd
	rm -rf "$W1NCRAY_ROOT/run"
	mkdir -p "$W1NCRAY_ROOT/sbin"
	printf '#!/bin/sh\n' >"$W1NCRAY_ROOT/sbin/openrc-run"
	chmod 755 "$W1NCRAY_ROOT/sbin/openrc-run"
	mkdir -p "$W1NCRAY_ROOT/fakepath"
	printf '#!/bin/sh\n' >"$W1NCRAY_ROOT/fakepath/rc-service"
	chmod 755 "$W1NCRAY_ROOT/fakepath/rc-service"
	_oldpath="$PATH"
	PATH="$W1NCRAY_ROOT/fakepath:$PATH"
	eq "OpenRC detected" "$(detect_backend)" openrc
	PATH="$_oldpath"
	eq "an unknown backend can be forced" "$(W1NCRAY_BACKEND=mock detect_backend)" mock
}

t_latest_tag() {
	mock_downloads
	mkdir -p "$W1NCRAY_ROOT/release"
	printf '[\n  {\n    "tag_name": "v0.3.0",\n    "prerelease": true\n  }\n]\n' >"$W1NCRAY_ROOT/release/api.json"
	eq "tag from the releases API" "$(latest_tag)" v0.3.0
	rm -f "$W1NCRAY_ROOT/release/api.json"
	printf '<feed><entry><link rel="alternate" href="https://github.com/W1nCwC/W1nCray/releases/tag/v0.2.7"/></entry><entry><link href="https://github.com/W1nCwC/W1nCray/releases/tag/v0.1.0"/></entry></feed>\n' >"$W1NCRAY_ROOT/release/atom.xml"
	eq "tag from the atom feed when the API fails" "$(latest_tag)" v0.2.7
	rm -f "$W1NCRAY_ROOT/release/atom.xml"
	refute "no tag when both fail" latest_tag
}

t_verify() {
	mock_downloads
	echo "payload" >"$W1NCRAY_ROOT/f.gz"
	h="$(sha256sum "$W1NCRAY_ROOT/f.gz" | awk '{print $1}')"
	mkdir -p "$W1NCRAY_ROOT/release"
	printf '%s *W1nCray-linux-amd64.gz\n0000 *other.gz\n' "$h" >"$W1NCRAY_ROOT/release/SHA256SUMS"
	check "matching checksum passes" verify_sha256 "$W1NCRAY_ROOT/f.gz" W1nCray-linux-amd64.gz v1
	echo tampered >>"$W1NCRAY_ROOT/f.gz"
	( verify_sha256 "$W1NCRAY_ROOT/f.gz" W1nCray-linux-amd64.gz v1 ) >/dev/null 2>&1 && fail "tampered file accepted" || pass "tampered file is rejected"
	( verify_sha256 "$W1NCRAY_ROOT/f.gz" W1nCray-linux-nothere.gz v1 ) >/dev/null 2>&1 && fail "missing entry accepted" || pass "missing checksum entry is rejected"
	rm -f "$W1NCRAY_ROOT/release/SHA256SUMS"
	check "a release without SHA256SUMS is let through with a notice" verify_sha256 "$W1NCRAY_ROOT/f.gz" W1nCray-linux-amd64.gz v1
}

t_generated_scripts() {
	BIN=/usr/local/W1nCray/W1nCray
	CONF=/etc/W1nCray/config.yml
	CONF_DIR=/etc/W1nCray
	systemctl() { :; }
	mkdir -p "$W1NCRAY_ROOT/etc/systemd/system" "$W1NCRAY_ROOT/etc/init.d" "$W1NCRAY_ROOT/proc"

	be_systemd_install
	u="$(cat "$W1NCRAY_ROOT/etc/systemd/system/W1nCray.service")"
	has "systemd unit runs the binary with the config" "$u" "ExecStart=/usr/local/W1nCray/W1nCray -c /etc/W1nCray/config.yml"
	has "systemd unit restarts on failure" "$u" "Restart=on-failure"
	has "systemd unit raises the file limit" "$u" "LimitNOFILE=1048576"
	hasnt "systemd unit has no placeholders left" "$u" "@"

	be_openrc_install
	f="$W1NCRAY_ROOT/etc/init.d/W1nCray"
	o="$(cat "$f")"
	has "OpenRC script uses supervise-daemon" "$o" 'supervisor="supervise-daemon"'
	has "OpenRC script runs the binary" "$o" 'command="/usr/local/W1nCray/W1nCray"'
	has "OpenRC script respawns forever" "$o" "respawn_max=0"
	has "OpenRC script raises the file limit" "$o" 'rc_ulimit="-n 1048576"'
	has "OpenRC script logs to a file" "$o" 'output_log="/var/log/W1nCray.log"'
	hasnt "OpenRC script has no placeholders left" "$o" "@BIN@"
	hasnt "OpenRC script has no placeholders left (conf)" "$o" "@CONF"
	check "OpenRC script is a valid shell script" sh -n "$f"
	check "OpenRC script is executable" test -x "$f"

	printf 'MemTotal:         262144 kB\n' >"$W1NCRAY_ROOT/proc/meminfo"
	be_procd_install
	p="$(cat "$f")"
	has "procd script uses procd" "$p" "USE_PROCD=1"
	has "procd script respawns forever" "$p" "procd_set_param respawn 3600 10 0"
	has "procd script logs to syslog" "$p" "procd_set_param stdout 1"
	has "procd script runs the binary" "$p" 'procd_set_param command "/usr/local/W1nCray/W1nCray" -c "/etc/W1nCray/config.yml"'
	has "procd script limits Go memory on a 256 MB router" "$p" "GOMEMLIMIT=102MiB"
	has "procd script sets the geo location" "$p" "XRAY_LOCATION_ASSET=/etc/W1nCray"
	hasnt "procd script has no placeholders left" "$p" "@"
	check "procd script is a valid shell script" sh -n "$f"
	printf 'MemTotal:        4194304 kB\n' >"$W1NCRAY_ROOT/proc/meminfo"
	be_procd_install
	hasnt "no memory limit on a big machine" "$(cat "$f")" "GOMEMLIMIT"
}

t_install_fresh() {
	mock_backend
	mock_downloads
	make_fake_bin "$W1NCRAY_ROOT/fakebin"
	W1NCRAY_SELF="$SCRIPT"
	out="$(cmd_install --binary "$W1NCRAY_ROOT/fakebin" 2>&1)"
	check "binary installed and executable" test -x "$BIN"
	has "installer reports the version" "$out" "W1nCray vTEST"
	eq "install.env records the prefix" "$(grep '^BIN_DIR=' "$ENVFILE")" "BIN_DIR=$BIN_DIR"
	eq "install.env records the flavor" "$(grep '^FLAVOR=' "$ENVFILE")" "FLAVOR=full"
	check "manager command installed" test -x "$MGR"
	eq "manager is a copy of the installer" "$(cat "$MGR")" "$(cat "$SCRIPT")"
	check "installer copy kept next to the binary" test -f "$BIN_DIR/install.sh"
	check "default config created with init when XrayR is absent" grep -q "Nodes" "$CONF"
	has "service installed, enabled and started" "$(cat "$CALLS")" "install W1nCray"
	has "service enabled" "$(cat "$CALLS")" "enable W1nCray"
	has "service started" "$(cat "$CALLS")" "start W1nCray"
	check "geo files downloaded off OpenWRT" test -s "$CONF_DIR/geoip.dat"
	hasnt "no temp download dir left behind" "$(ls -a "$BIN_DIR")" ".dl."
}

t_install_xrayr_present() {
	mock_backend
	mock_downloads
	make_fake_bin "$W1NCRAY_ROOT/fakebin"
	W1NCRAY_SELF="$SCRIPT"
	mkdir -p "$XRAYR_DIR"
	echo "Nodes: []" >"$XRAYR_DIR/config.yml"
	: >"$ST/XrayR.exists"
	: >"$ST/XrayR.active"
	: >"$ST/XrayR.enabled"
	out="$(cmd_install --binary "$W1NCRAY_ROOT/fakebin" 2>&1)"
	has "XrayR config is migrated" "$out" "migrate migrate --from"
	check "migrated config in place" grep -q migrated "$CONF"
	hasnt "W1nCray is not started while XrayR runs" "$(cat "$CALLS")" "start W1nCray"
	hasnt "W1nCray is not enabled while XrayR runs" "$(cat "$CALLS")" "enable W1nCray"
	hasnt "XrayR is never stopped by install" "$(cat "$CALLS")" "stop XrayR"
	has "user is told how to switch" "$out" "W1nCray switch"
	check "XrayR config untouched" grep -q "Nodes" "$XRAYR_DIR/config.yml"
}

t_install_check_fails() {
	mock_backend
	make_fake_bin "$W1NCRAY_ROOT/fakebin"
	W1NCRAY_SELF="$SCRIPT"
	FAKE_CHECK_RC=1
	export FAKE_CHECK_RC
	out="$(cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo 2>&1)"
	hasnt "failed check -> service not started" "$(cat "$CALLS")" "start W1nCray"
	has "failed check is reported" "$out" "配置检查未通过"
}

t_install_openwrt() {
	mock_backend
	mock_downloads
	make_fake_bin "$W1NCRAY_ROOT/fakebin"
	W1NCRAY_SELF="$SCRIPT"
	mkdir -p "$W1NCRAY_ROOT/etc"
	echo "DISTRIB_ID='OpenWrt'" >"$W1NCRAY_ROOT/etc/openwrt_release"
	load_env
	mock_backend
	out="$(cmd_install --binary "$W1NCRAY_ROOT/fakebin" 2>&1)"
	eq "OpenWRT installs the lite build by default" "$(grep '^FLAVOR=' "$ENVFILE")" "FLAVOR=lite"
	check "manager in /usr/bin on OpenWRT" test -x "$W1NCRAY_ROOT/usr/bin/W1nCray"
	refute "geo files are not downloaded on OpenWRT" test -e "$CONF_DIR/geoip.dat"
	has "OpenWRT says how to get geo files" "$out" "--with-geo"
	sc="$(cat "$W1NCRAY_ROOT/etc/sysupgrade.conf")"
	has "sysupgrade keeps the config" "$sc" "/etc/W1nCray/"
	has "sysupgrade keeps the init script" "$sc" "/etc/init.d/W1nCray"
	cmd_install --binary "$W1NCRAY_ROOT/fakebin" >/dev/null 2>&1
	eq "sysupgrade.conf has no duplicates" "$(grep -c '^/etc/W1nCray/$' "$W1NCRAY_ROOT/etc/sysupgrade.conf")" 1
	has "firmware upgrade hint" "$out" "sysupgrade"
	cmd_install --binary "$W1NCRAY_ROOT/fakebin" --with-geo >/dev/null 2>&1
	check "--with-geo downloads geo files on OpenWRT" test -s "$CONF_DIR/geoip.dat"
}

t_install_flavor_prefix_upgrade() {
	mock_backend
	make_fake_bin "$W1NCRAY_ROOT/fakebin"
	W1NCRAY_SELF="$SCRIPT"
	cmd_install --binary "$W1NCRAY_ROOT/fakebin" --lite --prefix "$W1NCRAY_ROOT/ext/W1nCray" --no-geo >/dev/null 2>&1
	check "--prefix installs there" test -x "$W1NCRAY_ROOT/ext/W1nCray/W1nCray"
	eq "install.env remembers the prefix" "$(grep '^BIN_DIR=' "$ENVFILE")" "BIN_DIR=$W1NCRAY_ROOT/ext/W1nCray"
	eq "install.env remembers --lite" "$(grep '^FLAVOR=' "$ENVFILE")" "FLAVOR=lite"
	# A later run (as the installed manager would) finds the same prefix and flavor.
	load_env
	eq "load_env picks up the prefix" "$BIN" "$W1NCRAY_ROOT/ext/W1nCray/W1nCray"
	eq "load_env picks up the flavor" "$FLAVOR" lite
	# Upgrade of a running service restarts it and keeps the flavor.
	: >"$ST/W1nCray.active"
	: >"$CALLS"
	cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo >/dev/null 2>&1
	eq "upgrade keeps the flavor" "$(grep '^FLAVOR=' "$ENVFILE")" "FLAVOR=lite"
	has "upgrade restarts a running service" "$(cat "$CALLS")" "restart W1nCray"
	eq "upgrade does not start it a second time" "$(grep -c '^start ' "$CALLS")" 0
	cmd_install --binary "$W1NCRAY_ROOT/fakebin" --full --no-geo >/dev/null 2>&1
	eq "--full overrides" "$(grep '^FLAVOR=' "$ENVFILE")" "FLAVOR=full"
}

t_install_from_release() {
	mock_backend
	mock_downloads
	W1NCRAY_SELF="$SCRIPT"
	W1NCRAY_UNAME_M=armv7l
	W1NCRAY_CPUINFO="$W1NCRAY_ROOT/cpuinfo"
	export W1NCRAY_UNAME_M W1NCRAY_CPUINFO
	printf 'Features\t: half thumb fastmult vfp edsp vfpv3 tls\n' >"$W1NCRAY_CPUINFO"
	make_broken_bin "$W1NCRAY_ROOT/b7"
	make_fake_bin "$W1NCRAY_ROOT/b6"
	publish W1nCray-linux-armv7.gz "$W1NCRAY_ROOT/b7"
	publish W1nCray-linux-armv6.gz "$W1NCRAY_ROOT/b6"
	mkdir -p "$W1NCRAY_ROOT/release"
	printf '[{"tag_name": "v9.9.9"}]\n' >"$W1NCRAY_ROOT/release/api.json"
	out="$(cmd_install --no-geo 2>&1)"
	d="$(cat "$DL_LOG")"
	has "newest release tag is used" "$d" "/releases/download/v9.9.9/W1nCray-linux-armv7.gz"
	has "falls back to a lower GOARM when the binary cannot run" "$d" "/releases/download/v9.9.9/W1nCray-linux-armv6.gz"
	has "checksums are fetched" "$d" "/releases/download/v9.9.9/SHA256SUMS"
	has "fallback is announced" "$out" "尝试更低要求"
	check "armv6 binary installed" test -x "$BIN"
	eq "installed binary runs" "$("$BIN" version | head -n1 | cut -c1-13)" "W1nCray vTEST"

	# A specific version and the lite build use the matching asset names.
	W1NCRAY_UNAME_M=x86_64
	export W1NCRAY_UNAME_M
	make_fake_bin "$W1NCRAY_ROOT/bl"
	publish W1nCray-linux-amd64-lite.gz "$W1NCRAY_ROOT/bl"
	: >"$DL_LOG"
	cmd_install --version v1.2.3 --lite --no-geo >/dev/null 2>&1
	has "--version and --lite pick the asset" "$(cat "$DL_LOG")" "/releases/download/v1.2.3/W1nCray-linux-amd64-lite.gz"

	# Tampered download: nothing is installed over the working binary.
	printf 'tampered' >>"$W1NCRAY_ROOT/release/W1nCray-linux-amd64-lite.gz"
	before="$(cat "$BIN")"
	( cmd_install --version v1.2.3 --lite --no-geo ) >/dev/null 2>&1 && fail "tampered release installed" || pass "tampered release is refused"
	eq "binary unchanged after a refused install" "$(cat "$BIN")" "$before"
	hasnt "no temp download dir left after a failure" "$(ls -a "$BIN_DIR")" ".dl."
}

t_space_check() {
	unset W1NCRAY_SKIP_SPACE_CHECK
	df() { printf 'Filesystem 1024-blocks Used Available Capacity Mounted\n/dev/x 1000000 990000 5000 99%% /\n'; }
	( check_space "$W1NCRAY_ROOT" lite ) >"$W1NCRAY_ROOT/out" 2>&1 && fail "low space accepted" || pass "low free space is refused"
	has "refusal explains --prefix" "$(cat "$W1NCRAY_ROOT/out")" "--prefix"
	df() { printf 'Filesystem 1024-blocks Used Available Capacity Mounted\n/dev/x 1000000 100000 900000 10%% /\n'; }
	check "enough space passes" check_space "$W1NCRAY_ROOT" full
	mkdir -p "$W1NCRAY_ROOT/etc"
	echo x >"$W1NCRAY_ROOT/etc/openwrt_release"
	df() { printf 'Filesystem 1024-blocks Used Available Capacity Mounted\n/dev/x 1000000 990000 5000 99%% /\n'; }
	( check_space "$W1NCRAY_ROOT" lite ) >"$W1NCRAY_ROOT/out" 2>&1
	has "OpenWRT refusal mentions extroot" "$(cat "$W1NCRAY_ROOT/out")" "extroot"
}

t_switch_rollback() {
	mock_backend
	make_fake_bin "$BIN_DIR.tmp" 2>/dev/null
	mkdir -p "$BIN_DIR"
	make_fake_bin "$BIN"
	mkdir -p "$CONF_DIR"
	echo "Nodes: []" >"$CONF"
	: >"$ST/XrayR.exists"
	: >"$ST/XrayR.active"
	: >"$ST/XrayR.enabled"
	: >"$ST/W1nCray.exists"
	echo xrayr >"$ST/XrayR.levels"
	out="$(cmd_switch 2>&1)"
	calls="$(cat "$CALLS")"
	has "switch stops XrayR" "$calls" "stop XrayR"
	has "switch disables XrayR" "$calls" "disable XrayR"
	has "switch enables W1nCray" "$calls" "enable W1nCray"
	has "switch starts W1nCray" "$calls" "start W1nCray"
	has "switch reports success" "$out" "切换完成"
	eq "XrayR's runlevel is remembered" "$(cat "$CONF_DIR/xrayr.levels")" xrayr
	check "W1nCray is running after the switch" be_mock_active W1nCray
	refute "XrayR is stopped after the switch" be_mock_active XrayR

	cmd_rollback >/dev/null 2>&1
	has "rollback re-enables XrayR in its old runlevel" "$(cat "$CALLS")" "enable XrayR xrayr"
	check "XrayR is running again" be_mock_active XrayR
	refute "W1nCray stopped after rollback" be_mock_active W1nCray
	refute "W1nCray disabled after rollback" be_mock_enabled W1nCray

	# A W1nCray that does not stay up is rolled back automatically.
	: >"$ST/W1nCray.failstart"
	rm -f "$ST/W1nCray.active"
	: >"$CALLS"
	( cmd_switch ) >"$W1NCRAY_ROOT/out" 2>&1 && fail "failed switch reported success" || pass "failed switch exits non-zero"
	has "failed switch rolls back" "$(cat "$W1NCRAY_ROOT/out")" "自动回滚"
	check "XrayR restored after a failed switch" be_mock_active XrayR

	# A failing check blocks the switch before anything is stopped.
	rm -f "$ST/W1nCray.failstart"
	: >"$CALLS"
	FAKE_CHECK_RC=1
	export FAKE_CHECK_RC
	( cmd_switch ) >/dev/null 2>&1 && fail "switch ignored a failing check" || pass "switch stops at a failing check"
	hasnt "nothing stopped when the check fails" "$(cat "$CALLS")" "stop XrayR"
}

t_manager_dispatch() {
	mock_backend
	mkdir -p "$BIN_DIR"
	make_fake_bin "$BIN"
	AS_MANAGER=1
	FAKE_NOWRITE=1
	export FAKE_NOWRITE
	eq "unknown command goes to the program" "$(dispatch x25519 2>&1)" "ARGS: x25519"
	eq "migrate with arguments goes to the program" "$(dispatch migrate --from /a --to /b 2>&1)" "ARGS: migrate --from /a --to /b"
	eq "check with arguments goes to the program" "$(dispatch check -c /x.yml 2>&1)" "check ok ARGS: check -c /x.yml"
	eq "flags go to the program" "$(dispatch -c /x.yml 2>&1)" "ARGS: -c /x.yml"
	: >"$ST/W1nCray.exists"
	: >"$ST/W1nCray.active"
	out="$(dispatch status 2>&1)"
	has "status shows the version" "$out" "W1nCray vTEST"
	has "status shows the backend" "$out" "服务管理器: mock"
	has "status shows running" "$out" "运行中"
	has "status shows recent log errors" "$out" "level=error"
	mkdir -p "$CONF_DIR"
	printf 'Nodes:\n  - ApiConfig:\n      ApiHost: "a"\n  - ApiConfig:\n      ApiHost: "b"\n' >"$CONF"
	has "status counts the nodes" "$(dispatch status 2>&1)" "2 个节点"
	dispatch stop >/dev/null 2>&1
	refute "stop stops the service" be_mock_active W1nCray
	dispatch start >/dev/null 2>&1
	check "start starts the service" be_mock_active W1nCray
	dispatch restart >/dev/null 2>&1
	has "restart restarts" "$(cat "$CALLS")" "restart W1nCray"
	dispatch enable >/dev/null 2>&1
	check "enable" be_mock_enabled W1nCray
	dispatch disable >/dev/null 2>&1
	refute "disable" be_mock_enabled W1nCray
	dispatch log >/dev/null 2>&1
	has "log follows" "$(cat "$CALLS")" "follow W1nCray"
	has "log -n shows lines" "$(dispatch log -n 5 2>&1)" "mock log of W1nCray"
	has "help lists the shortcuts" "$(dispatch help 2>&1)" "W1nCray status"

	AS_MANAGER=0
	( dispatch x25519 ) >/dev/null 2>&1 && fail "installer accepted an unknown command" || pass "installer script rejects unknown commands"
	has "installer without arguments prints usage" "$(dispatch </dev/null 2>&1)" "W1nCray 管理命令"
}

t_menu() {
	mock_backend
	mkdir -p "$BIN_DIR"
	make_fake_bin "$BIN"
	: >"$ST/W1nCray.exists"
	: >"$ST/W1nCray.active"
	out="$(printf '4\n99\n0\n' | menu 2>&1)"
	has "menu shows the title" "$out" "W1nCray 管理菜单"
	has "menu shows the state" "$out" "运行中"
	has "choice 4 runs status" "$out" "服务管理器: mock"
	has "invalid choices are rejected" "$out" "无效的选择"
	out="$(printf '2\n0\n' | menu 2>&1)"
	refute "choice 2 stops the service" be_mock_active W1nCray
	eq "menu ends on EOF" "$(printf '' | menu >/dev/null 2>&1; echo $?)" 0
}

t_uninstall() {
	mock_backend
	make_fake_bin "$W1NCRAY_ROOT/fakebin"
	W1NCRAY_SELF="$SCRIPT"
	cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo >/dev/null 2>&1
	check "installed before uninstall" test -x "$BIN"
	cmd_uninstall -y >/dev/null 2>&1
	refute "binary removed" test -e "$BIN"
	refute "manager removed" test -e "$MGR"
	refute "installer copy removed" test -e "$BIN_DIR/install.sh"
	refute "install dir removed when empty" test -d "$BIN_DIR"
	check "config kept without --purge" test -f "$CONF"
	has "service removed" "$(cat "$CALLS")" "remove W1nCray"
	has "service stopped and disabled first" "$(cat "$CALLS")" "disable W1nCray"
	cmd_uninstall --purge -y >/dev/null 2>&1
	refute "--purge removes the config directory" test -d "$CONF_DIR"
}

t_uninstall_openwrt_sysupgrade() {
	mock_backend
	make_fake_bin "$W1NCRAY_ROOT/fakebin"
	W1NCRAY_SELF="$SCRIPT"
	mkdir -p "$W1NCRAY_ROOT/etc"
	echo "DISTRIB_ID='OpenWrt'" >"$W1NCRAY_ROOT/etc/openwrt_release"
	printf '/etc/mine.conf\n' >"$W1NCRAY_ROOT/etc/sysupgrade.conf"
	load_env
	mock_backend
	cmd_install --binary "$W1NCRAY_ROOT/fakebin" >/dev/null 2>&1
	has "install added the entries" "$(cat "$W1NCRAY_ROOT/etc/sysupgrade.conf")" "/etc/init.d/W1nCray"
	cmd_uninstall -y >/dev/null 2>&1
	sc="$(cat "$W1NCRAY_ROOT/etc/sysupgrade.conf")"
	hasnt "uninstall drops the init script entry" "$sc" "/etc/init.d/W1nCray"
	has "uninstall keeps the config entry while the config stays" "$sc" "/etc/W1nCray/"
	has "uninstall keeps the user's own entries" "$sc" "/etc/mine.conf"
	cmd_uninstall --purge -y >/dev/null 2>&1
	sc="$(cat "$W1NCRAY_ROOT/etc/sysupgrade.conf")"
	hasnt "purge drops the config entry" "$sc" "/etc/W1nCray/"
	has "purge keeps the user's own entries" "$sc" "/etc/mine.conf"
}

t_uninstall_refuses_odd_paths() {
	mock_backend
	CONF_DIR="/home/someone/data"
	( cmd_uninstall --purge -y ) >/dev/null 2>&1 && fail "purged an unexpected directory" || pass "purge refuses a path that is not .../etc/W1nCray"
}

t_none_backend() {
	W1NCRAY_BACKEND=none
	BACKEND=none
	make_fake_bin "$W1NCRAY_ROOT/fakebin"
	W1NCRAY_SELF="$SCRIPT"
	out="$(cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo 2>&1)"
	check "binary and config are still installed" test -x "$BIN"
	has "user is told to run it by hand" "$out" "前台运行"
	has "start explains the missing init system" "$( (cmd_start) 2>&1)" "没有检测到可用的服务管理器"
}

# ---- run ------------------------------------------------------------------------

run() { # name
	R="$(new_root)"
	printf '== %s\n' "$1"
	(
		lib "$R"
		"$1"
	)
}

for t in t_arch t_endian_dd_and_hexdump t_flavor_and_backend t_latest_tag t_verify t_generated_scripts \
	t_install_fresh t_install_xrayr_present t_install_check_fails t_install_openwrt \
	t_install_flavor_prefix_upgrade t_install_from_release t_space_check t_switch_rollback \
	t_manager_dispatch t_menu t_uninstall t_uninstall_openwrt_sysupgrade t_uninstall_refuses_odd_paths t_none_backend; do
	run "$t"
done

passes="$(grep -c '^PASS' "$RESULTS" || true)"
fails="$(grep -c '^FAIL' "$RESULTS" || true)"
echo
echo "passed: $passes, failed: $fails"
[ "${fails:-0}" -eq 0 ]
