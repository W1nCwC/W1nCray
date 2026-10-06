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
	# Fail closed: anything that prevents a real check is a refusal.
	printf '%s *short.gz\n%s *bad.gz\n%s *empty.gz\n' abc zzzz "" >"$W1NCRAY_ROOT/release/SHA256SUMS"
	( verify_sha256 "$W1NCRAY_ROOT/f.gz" short.gz v1 ) >/dev/null 2>&1 && fail "truncated checksum accepted" || pass "truncated checksum value is rejected"
	( verify_sha256 "$W1NCRAY_ROOT/f.gz" bad.gz v1 ) >/dev/null 2>&1 && fail "non-hex checksum accepted" || pass "non-hex checksum value is rejected"
	( verify_sha256 "$W1NCRAY_ROOT/f.gz" empty.gz v1 ) >/dev/null 2>&1 && fail "empty checksum accepted" || pass "empty checksum value is rejected"
	rm -f "$W1NCRAY_ROOT/release/SHA256SUMS"
	( verify_sha256 "$W1NCRAY_ROOT/f.gz" W1nCray-linux-amd64.gz v1 ) >"$W1NCRAY_ROOT/out" 2>&1 && fail "missing SHA256SUMS accepted" || pass "a release without SHA256SUMS is refused"
	has "the refusal names the opt-out" "$(cat "$W1NCRAY_ROOT/out")" "--insecure-skip-verify"
	h="$(sha256sum "$W1NCRAY_ROOT/f.gz" | awk '{print $1}')"
	printf '%s *W1nCray-linux-amd64.gz\n' "$h" >"$W1NCRAY_ROOT/release/SHA256SUMS"
	( have_sha256sum() { return 1; }; verify_sha256 "$W1NCRAY_ROOT/f.gz" W1nCray-linux-amd64.gz v1 ) >"$W1NCRAY_ROOT/out" 2>&1 && fail "missing sha256sum accepted" || pass "a missing sha256sum is refused"
	has "the refusal names sha256sum" "$(cat "$W1NCRAY_ROOT/out")" "sha256sum"
	# Upper-case hex digests are accepted when they match.
	printf '%s *W1nCray-linux-amd64.gz\n' "$(printf '%s' "$h" | tr 'a-f' 'A-F')" >"$W1NCRAY_ROOT/release/SHA256SUMS"
	check "an upper-case digest that matches passes" verify_sha256 "$W1NCRAY_ROOT/f.gz" W1nCray-linux-amd64.gz v1
}

t_verify_opt_out() {
	mock_downloads
	echo "payload" >"$W1NCRAY_ROOT/f.gz"
	# No SHA256SUMS at all, and the file would not match anyway.
	INSECURE_SKIP_VERIFY=1
	out="$(verify_sha256 "$W1NCRAY_ROOT/f.gz" W1nCray-linux-amd64.gz v1 2>&1)"
	eq "--insecure-skip-verify skips the check" "$?" 0
	has "the skip is announced as a warning" "$out" "警告"
	has "the warning names the flag" "$out" "--insecure-skip-verify"
	hasnt "nothing is downloaded when skipping" "$(cat "$DL_LOG")" "SHA256SUMS"
	mkdir -p "$W1NCRAY_ROOT/release"
	printf '%s *W1nCray-linux-amd64.gz\n' 0000000000000000000000000000000000000000000000000000000000000000 >"$W1NCRAY_ROOT/release/SHA256SUMS"
	check "a mismatching file passes only with the opt-out" verify_sha256 "$W1NCRAY_ROOT/f.gz" W1nCray-linux-amd64.gz v1
	INSECURE_SKIP_VERIFY=0
	( verify_sha256 "$W1NCRAY_ROOT/f.gz" W1nCray-linux-amd64.gz v1 ) >/dev/null 2>&1 && fail "mismatch accepted without the opt-out" || pass "the same file is refused without the opt-out"
	# The environment variable is read when the script is sourced.
	env_opt_out() { # value of W1NCRAY_INSECURE_SKIP_VERIFY ("-" = unset)
		if [ "$1" = - ]; then
			( unset W1NCRAY_INSECURE_SKIP_VERIFY; . "$SCRIPT"; echo "$INSECURE_SKIP_VERIFY" )
		else
			( W1NCRAY_INSECURE_SKIP_VERIFY="$1"; . "$SCRIPT"; echo "$INSECURE_SKIP_VERIFY" )
		fi
	}
	eq "env opt-out is off by default" "$(env_opt_out -)" 0
	eq "W1NCRAY_INSECURE_SKIP_VERIFY=1 opts out" "$(env_opt_out 1)" 1
	eq "any other value does not opt out" "$(env_opt_out yes)" 0
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

t_install_verify_policy() {
	mock_backend
	mock_downloads
	W1NCRAY_SELF="$SCRIPT"
	W1NCRAY_UNAME_M=x86_64
	export W1NCRAY_UNAME_M
	make_fake_bin "$W1NCRAY_ROOT/fakebin"
	cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo >/dev/null 2>&1
	before="$(cat "$BIN")"
	# The release has the asset but no SHA256SUMS.
	mkdir -p "$W1NCRAY_ROOT/release"
	printf '#!/bin/sh\necho "W1nCray vNEW"\n' >"$W1NCRAY_ROOT/newbin"
	gzip -c "$W1NCRAY_ROOT/newbin" >"$W1NCRAY_ROOT/release/W1nCray-linux-amd64.gz"

	( cmd_install --version v1.2.3 --no-geo ) >"$W1NCRAY_ROOT/out" 2>&1 && fail "unverifiable release installed" || pass "a release without SHA256SUMS is refused"
	has "the refusal names the opt-out" "$(cat "$W1NCRAY_ROOT/out")" "--insecure-skip-verify"
	eq "binary unchanged after the refusal" "$(cat "$BIN")" "$before"
	hasnt "no temp download dir left after the refusal" "$(ls -a "$BIN_DIR")" ".dl."

	( cmd_update --version v1.2.3 --no-geo ) >/dev/null 2>&1 && fail "update installed an unverifiable release" || pass "update refuses it as well"
	eq "binary unchanged after the refused update" "$(cat "$BIN")" "$before"

	( cmd_install --version v1.2.3 --no-geo --insecure-skip-verify ) >"$W1NCRAY_ROOT/out" 2>&1
	eq "--insecure-skip-verify installs it" "$?" 0
	has "and warns loudly" "$(cat "$W1NCRAY_ROOT/out")" "警告"
	eq "the new binary is in place" "$("$BIN" version)" "W1nCray vNEW"

	# The opt-out can also come from the environment.
	printf '%s' "$before" >"$BIN"
	( INSECURE_SKIP_VERIFY=1; cmd_install --version v1.2.3 --no-geo ) >/dev/null 2>&1
	eq "the environment opt-out installs it" "$("$BIN" version)" "W1nCray vNEW"

	# Files given by the user (--binary) were never checked and still work.
	printf '%s' "$before" >"$BIN"
	cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo >/dev/null 2>&1
	eq "--binary needs no checksum" "$("$BIN" version | head -n1 | cut -c1-13)" "W1nCray vTEST"
	has "help documents the flag" "$(usage)" "--insecure-skip-verify"
}

t_update_version_shorthand() {
	mock_backend
	mock_downloads
	W1NCRAY_SELF="$SCRIPT"
	W1NCRAY_UNAME_M=x86_64
	export W1NCRAY_UNAME_M
	make_fake_bin "$W1NCRAY_ROOT/fakebin"
	cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo >/dev/null 2>&1
	publish W1nCray-linux-amd64.gz "$W1NCRAY_ROOT/fakebin"
	: >"$DL_LOG"
	cmd_update v1.2.3 --no-geo >/dev/null 2>&1
	has "update vX.Y.Z downloads that version" "$(cat "$DL_LOG")" "/releases/download/v1.2.3/W1nCray-linux-amd64.gz"
	: >"$DL_LOG"
	cmd_update --version v1.2.4 --no-geo >/dev/null 2>&1
	has "update --version still works" "$(cat "$DL_LOG")" "/releases/download/v1.2.4/W1nCray-linux-amd64.gz"
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
	CONF_DIR="$W1NCRAY_ROOT/home/someone/data"
	mkdir -p "$CONF_DIR"
	printf 'secret' >"$CONF_DIR/agent.token"
	( cmd_uninstall --purge -y ) >/dev/null 2>&1 && fail "purged an unexpected directory" || pass "purge refuses a path that is not .../etc/W1nCray"
	check "an unexpected config dir keeps its agent.token" test -f "$CONF_DIR/agent.token"
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

# ---- panel machine mode ------------------------------------------------------

mode_of() { ls -l "$1" | awk '{print $1}'; }

# fs_keeps_modes: true when a 0600 file really reads back as -rw-------. Git
# Bash / MSYS reports 644 for everything, so there the mode assertion is
# skipped; the installer's umask/chmod calls are still checked.
fs_keeps_modes() {
	_p="$TMPROOT/modeprobe"
	: >"$_p"
	chmod 600 "$_p" 2>/dev/null || return 1
	[ "$(mode_of "$_p")" = "-rw-------" ]
}

# spy_perms: record every umask/chmod call the installer makes, then still run
# the real thing. The logs go to $UMASK_LOG / $CHMOD_LOG.
spy_perms() {
	UMASK_LOG="$W1NCRAY_ROOT/umask.log"
	CHMOD_LOG="$W1NCRAY_ROOT/chmod.log"
	: >"$UMASK_LOG"
	: >"$CHMOD_LOG"
	umask() { printf 'umask %s\n' "$*" >>"$UMASK_LOG"; command umask "$@"; }
	chmod() { printf 'chmod %s\n' "$*" >>"$CHMOD_LOG"; command chmod "$@"; }
}

t_install_panel() {
	mock_backend
	mock_downloads
	make_fake_bin "$W1NCRAY_ROOT/fakebin"
	W1NCRAY_SELF="$SCRIPT"
	spy_perms
	tok="panel-secret-token-42"
	out="$(cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo \
		--panel https://panel.example.com/ --machine 3 --token "$tok" 2>&1)"
	eq "a panel install succeeds" "$?" 0
	check "binary installed" test -x "$BIN"
	check "token file created" test -f "$CONF_DIR/agent.token"
	has "the token is written under umask 077" "$(cat "$UMASK_LOG")" "umask 077"
	has "the token file is chmod 600" "$(cat "$CHMOD_LOG")" "chmod 600 $CONF_DIR/agent.token"
	if fs_keeps_modes; then
		eq "token file mode is 0600" "$(mode_of "$CONF_DIR/agent.token")" "-rw-------"
	else
		pass "token file mode is 0600 (skipped: this filesystem does not store Unix modes)"
	fi
	eq "the token is written verbatim" "$(cat "$CONF_DIR/agent.token")" "$tok"
	eq "the token file has no trailing newline" \
		"$(wc -c <"$CONF_DIR/agent.token" | tr -d '[:space:]')" \
		"$(printf '%s' "$tok" | wc -c | tr -d '[:space:]')"
	cfg="$(cat "$CONF")"
	check "config enables the agent" grep -qx 'Agent:' "$CONF"
	check "config enables the panel" grep -qx '  Panel:' "$CONF"
	check "config has the state dir" grep -qx "  StateDir: \"$CONF_DIR/state\"" "$CONF"
	check "config has the default port range" grep -qx '    PortRange: \[20000, 40000\]' "$CONF"
	refute "config does not restrict the engines" grep -q 'AllowEngines' "$CONF"
	check "config listens on all addresses" grep -qx '    AllowListen: \["0.0.0.0"\]' "$CONF"
	check "the trailing slash is stripped from the URL" grep -qx '    URL: "https://panel.example.com"' "$CONF"
	check "config has the machine id" grep -qx '    MachineID: 3' "$CONF"
	check "config points at the token file" grep -qx "    TokenFile: \"$CONF_DIR/agent.token\"" "$CONF"
	check "config turns on machine nodes" grep -qx '    MachineNodes: true' "$CONF"
	hasnt "config never contains the token" "$cfg" "$tok"
	hasnt "the installer never prints the token" "$out" "$tok"
	has "the installer reports the panel link" "$out" "已关联面板"
	has "the installer points at the log" "$out" "查看日志"
	has "the panel install checks the config offline" "$out" "check ok ARGS: check -c"
	hasnt "the panel is not contacted at install time" "$out" "--online"
	has "the service is started as usual" "$(cat "$CALLS")" "start W1nCray"
}

t_install_panel_missing_args() {
	mock_backend
	mock_downloads
	make_fake_bin "$W1NCRAY_ROOT/fakebin"
	W1NCRAY_SELF="$SCRIPT"
	( cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo --panel https://p.example.com ) >"$W1NCRAY_ROOT/out" 2>&1 && fail "--panel without --machine accepted" || pass "--panel without --machine is refused"
	has "the refusal names --machine" "$(cat "$W1NCRAY_ROOT/out")" "--machine"
	( cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo --panel https://p.example.com --machine 3 ) >"$W1NCRAY_ROOT/out" 2>&1 && fail "--panel without a token accepted" || pass "--panel without a token is refused"
	has "the refusal names the token" "$(cat "$W1NCRAY_ROOT/out")" "令牌"
	( cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo --machine 3 --token x ) >"$W1NCRAY_ROOT/out" 2>&1 && fail "--machine without --panel accepted" || pass "--machine without --panel is refused"
	has "the refusal names --panel" "$(cat "$W1NCRAY_ROOT/out")" "--panel"
	( cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo --panel https://p.example.com --machine 3 --token a --token-file "$W1NCRAY_ROOT/x" ) >"$W1NCRAY_ROOT/out" 2>&1 && fail "both token sources accepted" || pass "both --token and --token-file are refused"
	has "the refusal explains the choice" "$(cat "$W1NCRAY_ROOT/out")" "只能提供一个"
	( cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo --panel https://p.example.com --token a ) >"$W1NCRAY_ROOT/out" 2>&1 && fail "--panel without --machine (token given) accepted" || pass "a missing --machine is refused even with a token"
	has "that refusal also names --machine" "$(cat "$W1NCRAY_ROOT/out")" "--machine"
	# --port-range / --allow-http are meaningless without --panel.
	( cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo --port-range 20000-30000 ) >"$W1NCRAY_ROOT/out" 2>&1 && fail "--port-range without --panel accepted" || pass "--port-range without --panel is refused"
	has "the refusal explains the scope" "$(cat "$W1NCRAY_ROOT/out")" "--panel"
	( cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo --allow-http ) >"$W1NCRAY_ROOT/out" 2>&1 && fail "--allow-http without --panel accepted" || pass "--allow-http without --panel is refused"
	refute "nothing is installed after a bad invocation" test -e "$BIN"
	refute "no token file after a bad invocation" test -e "$CONF_DIR/agent.token"
}

t_install_panel_bad_id() {
	mock_backend
	mock_downloads
	make_fake_bin "$W1NCRAY_ROOT/fakebin"
	W1NCRAY_SELF="$SCRIPT"
	for bad in abc 0 -3 1.5 1e3; do
		( cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo --panel https://p.example.com --machine "$bad" --token t ) >"$W1NCRAY_ROOT/out" 2>&1 && fail "machine id '$bad' accepted" || pass "machine id '$bad' is refused"
	done
	has "the refusal says positive integer" "$(cat "$W1NCRAY_ROOT/out")" "正整数"
	( cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo --panel https://p.example.com --machine "" --token t ) >"$W1NCRAY_ROOT/out" 2>&1 && fail "an empty machine id accepted" || pass "an empty machine id is refused"
	has "an empty machine id is reported as missing" "$(cat "$W1NCRAY_ROOT/out")" "--machine"
	refute "nothing is installed after a bad id" test -e "$BIN"
}

t_install_panel_http() {
	mock_backend
	mock_downloads
	make_fake_bin "$W1NCRAY_ROOT/fakebin"
	W1NCRAY_SELF="$SCRIPT"
	( cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo --panel http://panel.example.com --machine 3 --token t ) >"$W1NCRAY_ROOT/out" 2>&1 && fail "plain http accepted" || pass "plain http to a remote host is refused"
	has "the refusal names --allow-http" "$(cat "$W1NCRAY_ROOT/out")" "--allow-http"
	has "the refusal explains the plaintext risk" "$(cat "$W1NCRAY_ROOT/out")" "明文"
	refute "nothing is installed after an http refusal" test -e "$BIN"
	out="$(cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo --panel http://panel.example.com --machine 3 --token t --allow-http 2>&1)"
	eq "--allow-http installs" "$?" 0
	check "the config records the insecure-http opt-in" grep -qx '    AllowInsecureHTTP: true' "$CONF"
	# A loopback http panel is allowed without the opt-in.
	rm -f "$CONF"
	out="$(cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo --panel http://127.0.0.1:8080 --machine 3 --token t 2>&1)"
	eq "loopback http is allowed" "$?" 0
	check "the loopback URL is kept" grep -qx '    URL: "http://127.0.0.1:8080"' "$CONF"
	refute "loopback http needs no opt-in" grep -qx '    AllowInsecureHTTP: true' "$CONF"
	# Other schemes are refused.
	( cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo --panel ftp://panel.example.com --machine 3 --token t ) >"$W1NCRAY_ROOT/out" 2>&1 && fail "ftp accepted" || pass "a non-http scheme is refused"
	has "the refusal asks for https" "$(cat "$W1NCRAY_ROOT/out")" "https://"
}

t_install_panel_token_file() {
	mock_backend
	mock_downloads
	make_fake_bin "$W1NCRAY_ROOT/fakebin"
	W1NCRAY_SELF="$SCRIPT"
	tok="token-from-a-file-99"
	printf '%s\n' "$tok" >"$W1NCRAY_ROOT/token.txt"
	out="$(cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo \
		--panel https://panel.example.com --machine 7 --token-file "$W1NCRAY_ROOT/token.txt" 2>&1)"
	eq "--token-file installs" "$?" 0
	eq "the token file's content is used (newline stripped)" "$(cat "$CONF_DIR/agent.token")" "$tok"
	eq "the copied token has no newline" \
		"$(wc -c <"$CONF_DIR/agent.token" | tr -d '[:space:]')" \
		"$(printf '%s' "$tok" | wc -c | tr -d '[:space:]')"
	check "config points at the copied token" grep -qx "    TokenFile: \"$CONF_DIR/agent.token\"" "$CONF"
	hasnt "the config never holds the token" "$(cat "$CONF")" "$tok"
	hasnt "the output never holds the token" "$out" "$tok"
	# A missing token file is refused before anything is installed.
	rm -rf "$BIN_DIR" "$CONF_DIR"
	( cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo --panel https://p.example.com --machine 7 --token-file "$W1NCRAY_ROOT/nope" ) >"$W1NCRAY_ROOT/out" 2>&1 && fail "a missing token file was accepted" || pass "a missing token file is refused"
	has "the refusal names the file" "$(cat "$W1NCRAY_ROOT/out")" "--token-file"
	refute "nothing is installed with a missing token file" test -e "$BIN"
	# An empty token is refused too.
	printf '\n' >"$W1NCRAY_ROOT/empty.txt"
	( cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo --panel https://p.example.com --machine 7 --token-file "$W1NCRAY_ROOT/empty.txt" ) >"$W1NCRAY_ROOT/out" 2>&1 && fail "an empty token was accepted" || pass "an empty token is refused"
	has "the refusal says the token is empty" "$(cat "$W1NCRAY_ROOT/out")" "令牌为空"
	# A token with embedded whitespace is refused: the agent's reader would
	# reject it, so the installer says so up front.
	( cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo --panel https://p.example.com --machine 7 --token 'a b' ) >"$W1NCRAY_ROOT/out" 2>&1 && fail "a token with a space was accepted" || pass "a token with whitespace is refused"
	has "the refusal explains the whitespace" "$(cat "$W1NCRAY_ROOT/out")" "空白"
}

t_install_panel_keeps_config() {
	mock_backend
	mock_downloads
	make_fake_bin "$W1NCRAY_ROOT/fakebin"
	W1NCRAY_SELF="$SCRIPT"
	mkdir -p "$CONF_DIR"
	# An existing config without static `Nodes:` entries: the machine-mode
	# config still goes to config.panel.yml.new for a manual merge.
	printf 'Log: {Level: info}\nAgent:\n  Enabled: false\n' >"$CONF"
	before="$(cat "$CONF")"
	out="$(cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo \
		--panel https://panel.example.com --machine 9 --token t --port-range 30000-31000 2>&1)"
	eq "an existing config does not fail the install" "$?" 0
	eq "the existing config is untouched" "$(cat "$CONF")" "$before"
	new="$CONF_DIR/config.panel.yml.new"
	check "the new config goes to config.panel.yml.new" test -f "$new"
	check ".new has the requested port range" grep -qx '    PortRange: \[30000, 31000\]' "$new"
	check ".new has the machine id" grep -qx '    MachineID: 9' "$new"
	check ".new points at the token file" grep -qx "    TokenFile: \"$CONF_DIR/agent.token\"" "$new"
	refute ".new does not restrict the engines" grep -q 'AllowEngines' "$new"
	has "the admin is warned the config was kept" "$out" "未覆盖"
	has "the admin is told how to merge" "$out" "合并"
	has "the pending hint says the link is not active yet" "$out" "配置尚未生效"
	check "the token file is written even then" test -f "$CONF_DIR/agent.token"
	has "the service still starts" "$(cat "$CALLS")" "start W1nCray"
	# A malformed range is refused.
	( cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo --panel https://p.example.com --machine 9 --token t --port-range 40000-20000 ) >"$W1NCRAY_ROOT/out" 2>&1 && fail "a backwards port range was accepted" || pass "a backwards port range is refused"
	has "the refusal explains the range" "$(cat "$W1NCRAY_ROOT/out")" "--port-range"
	( cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo --panel https://p.example.com --machine 9 --token t --port-range 20000 ) >"$W1NCRAY_ROOT/out" 2>&1 && fail "a range without '-' was accepted" || pass "a range without '-' is refused"
	( cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo --panel https://p.example.com --machine 9 --token t --port-range 0-100 ) >"$W1NCRAY_ROOT/out" 2>&1 && fail "a zero port was accepted" || pass "a zero port is refused"
	# A '#' in the URL must survive YAML quoting.
	rm -f "$CONF"
	cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo --panel 'https://panel.example.com/x#y' --machine 9 --token t >/dev/null 2>&1
	check "a # in the URL is quoted so YAML keeps it" grep -qx '    URL: "https://panel.example.com/x#y"' "$CONF"
}

t_install_panel_static_nodes() {
	mock_backend
	mock_downloads
	make_fake_bin "$W1NCRAY_ROOT/fakebin"
	W1NCRAY_SELF="$SCRIPT"
	mkdir -p "$CONF_DIR"
	printf 'Nodes:\n  - ApiConfig: {ApiHost: "https://x", ApiKey: k, NodeID: 173}\n  - ApiConfig: {ApiHost: "https://y", ApiKey: k, NodeID: 119}\n  - ApiConfig: {ApiHost: "https://z", ApiKey: k, NodeID: 138}\nAgent:\n  Enabled: false\n' >"$CONF"
	before="$(cat "$CONF")"
	# Detection helpers.
	check "a static Nodes block is detected" has_static_nodes "$CONF"
	eq "the NodeIDs are read in order" "$(static_node_ids "$CONF")" "173 119 138"
	printf 'Nodes: []\nAgent:\n  Enabled: true\n' >"$W1NCRAY_ROOT/empty.yml"
	refute "Nodes: [] is not a static node list" has_static_nodes "$W1NCRAY_ROOT/empty.yml"
	eq "Nodes: [] yields no NodeIDs" "$(static_node_ids "$W1NCRAY_ROOT/empty.yml")" ""
	refute "a missing config has no static nodes" has_static_nodes "$W1NCRAY_ROOT/nope.yml"
	printf 'Log: {Level: info}\n' >"$W1NCRAY_ROOT/plain.yml"
	refute "a config without Nodes has no static nodes" has_static_nodes "$W1NCRAY_ROOT/plain.yml"

	out="$(cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo \
		--panel https://panel.example.com --machine 5 --token t 2>&1)"
	eq "a panel install over static nodes succeeds" "$?" 0
	eq "the static config is untouched" "$(cat "$CONF")" "$before"
	refute "no .new config is written for static nodes" test -e "$CONF_DIR/config.panel.yml.new"
	has "the admin is warned the config was kept" "$out" "未覆盖"
	has "the static NodeIDs are listed" "$out" "配置里的静态节点 NodeID: 173 119 138"
	has "the admin is told to bind them on the panel" "$out" "绑定到机器 5"
	has "the dry-run link command is shown" "$out" "  W1nCray link --panel https://panel.example.com --machine 5 --token-file $CONF_DIR/agent.token --dry-run"
	eq "both the dry-run and the real command are shown" \
		"$(printf '%s\n' "$out" | grep -c 'W1nCray link --panel https://panel.example.com --machine 5 --token-file')" 2
	has "the admin is told to drop --dry-run" "$out" "去掉 --dry-run"
	has "the admin is told to restart" "$out" "W1nCray restart"
	has "the admin is told no merge is needed" "$out" "无需手工合并"
	has "the pending hint says the link is not active yet" "$out" "配置尚未生效"
	hasnt "link is never run by the installer" "$out" "ARGS: link"
	check "the token file is written" test -f "$CONF_DIR/agent.token"
	has "the service still starts" "$(cat "$CALLS")" "start W1nCray"
}

t_install_without_panel_unchanged() {
	mock_backend
	mock_downloads
	make_fake_bin "$W1NCRAY_ROOT/fakebin"
	W1NCRAY_SELF="$SCRIPT"
	out="$(cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo 2>&1)"
	eq "a plain install still uses init" "$(cat "$CONF")" "Nodes: []"
	eq "the config dir holds only the old artifacts" "$(ls "$CONF_DIR" | sort | tr '\n' ' ')" "config.yml install.env "
	eq "install.env keeps the prefix" "$(grep '^BIN_DIR=' "$ENVFILE")" "BIN_DIR=$BIN_DIR"
	eq "install.env keeps the flavor" "$(grep '^FLAVOR=' "$ENVFILE")" "FLAVOR=full"
	refute "no token file without --panel" test -e "$CONF_DIR/agent.token"
	refute "no .new config without --panel" test -e "$CONF_DIR/config.panel.yml.new"
	has "the service is started as before" "$(cat "$CALLS")" "start W1nCray"
	has "a plain install still checks online" "$out" "--online"
	hasnt "the output does not mention a panel link" "$out" "已关联面板"
	# A repeat install is still a no-op upgrade that adds no files.
	cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo >/dev/null 2>&1
	eq "a repeat install adds nothing" "$(ls "$CONF_DIR" | sort | tr '\n' ' ')" "config.yml install.env "
}

t_uninstall_removes_agent_token() {
	mock_backend
	mock_downloads
	make_fake_bin "$W1NCRAY_ROOT/fakebin"
	W1NCRAY_SELF="$SCRIPT"
	cmd_install --binary "$W1NCRAY_ROOT/fakebin" --no-geo --panel https://panel.example.com --machine 1 --token t >/dev/null 2>&1
	check "token file exists before uninstall" test -f "$CONF_DIR/agent.token"
	cmd_uninstall -y >/dev/null 2>&1
	refute "uninstall removes agent.token" test -e "$CONF_DIR/agent.token"
	check "uninstall still keeps the rest of the config" test -f "$CONF"
	refute "uninstall removed the binary" test -e "$BIN"
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

for t in t_arch t_endian_dd_and_hexdump t_flavor_and_backend t_latest_tag t_verify t_verify_opt_out t_generated_scripts \
	t_install_fresh t_install_xrayr_present t_install_check_fails t_install_openwrt \
	t_install_flavor_prefix_upgrade t_install_from_release t_install_verify_policy t_update_version_shorthand t_space_check t_switch_rollback \
	t_manager_dispatch t_menu t_uninstall t_uninstall_openwrt_sysupgrade t_uninstall_refuses_odd_paths t_none_backend \
	t_install_panel t_install_panel_missing_args t_install_panel_bad_id t_install_panel_http \
	t_install_panel_token_file t_install_panel_keeps_config t_install_panel_static_nodes t_install_without_panel_unchanged t_uninstall_removes_agent_token; do
	run "$t"
done

passes="$(grep -c '^PASS' "$RESULTS" || true)"
fails="$(grep -c '^FAIL' "$RESULTS" || true)"
echo
echo "passed: $passes, failed: $fails"
[ "${fails:-0}" -eq 0 ]
