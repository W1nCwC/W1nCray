#!/usr/bin/env bash
# Mirrors the upstream gost / realm / frp Linux builds into the W1nCray asset
# names the panel pins for the manifest-free direct install path:
#
#   dist-kernels/W1nCray-gost-linux-<arch>.gz    single-file gzip of `gost`
#   dist-kernels/W1nCray-realm-linux-<arch>.gz   single-file gzip of `realm`
#   dist-kernels/W1nCray-frp-linux-<arch>.tar.gz tar.gz holding frpc and frps
#   dist-kernels/SHA256SUMS                      one line per artifact
#   dist-kernels/UPSTREAM-VERIFY.txt             which upstream asset, which
#                                                hash, and how it was checked
#
# A complete run also rewrites kernel/install/ownkernels_gen.go, the Go table
# the agent installs these kernels from without a signed manifest (URL, sha256,
# size, archive format, variant and members of every artifact). GEN_ONLY=1
# regenerates that file from an existing dist-kernels without downloading or
# packaging anything.
#
# Only the upstream release is the source of bytes; every asset is verified
# against the upstream checksum file (gost, frp) or the GitHub API asset digest
# (realm, which ships no checksum file) before anything is unpacked. The
# archive is treated as untrusted: entries must be relative and free of `..`,
# only the wanted member is extracted, and the result must be a non-empty ELF
# regular file. Any failure prints the kernel/asset/expected/actual to stderr
# and exits non-zero; SHA256SUMS is only written once every artifact exists.
#
# Usage: bash release/build-kernels.sh
#   KERNELS="gost realm frp"  build only these (default: all three)
#   KEEP_WORK=1               keep dist-kernels/.work on success
#   REUSE_WORK=1              reuse an already downloaded upstream file
#                             (still fully re-verified)
#   GEN_ONLY=1                only regenerate kernel/install/ownkernels_gen.go
#                             from the dist-kernels already on disk (no
#                             download, no packaging, nothing written there);
#                             it requires the complete, verified 30 artifacts
# A proxy is honoured only through the environment (curl reads HTTPS_PROXY);
# nothing here hardcodes one, and no token is read or written.
set -euo pipefail

cd "$(dirname "$0")/.."

out=dist-kernels
work="$out/.work"
all_kernels="gost realm frp"
kernels="${KERNELS:-$all_kernels}"
# The fixed mtime of every tar member keeps the artifacts reproducible. GNU tar
# 1.35 (Git Bash) supports --mtime; the script degrades gracefully if not.
tar_mtime="2026-01-01 00:00:00 UTC"
verify_file="$out/UPSTREAM-VERIFY.txt"

gost_ver=3.3.0
realm_ver=2.9.6
frp_ver=0.71.0

# ---- platform maps (copied from tools/manifestgen/kernels.example.yaml) ------
# An empty value means the platform is null in the manifest: no artifact.
arch_order="386 amd64 arm64 armv5 armv6 armv7 loong64 mips mipsle mips64 mips64le riscv64"
declare -A gost_assets=(
	["386"]=gost_3.3.0_linux_386.tar.gz
	["amd64"]=gost_3.3.0_linux_amd64.tar.gz
	["arm64"]=gost_3.3.0_linux_arm64.tar.gz
	["armv5"]=gost_3.3.0_linux_armv5.tar.gz
	["armv6"]=gost_3.3.0_linux_armv6.tar.gz
	["armv7"]=gost_3.3.0_linux_armv7.tar.gz
	["loong64"]=gost_3.3.0_linux_loong64.tar.gz
	["mips"]=gost_3.3.0_linux_mips_softfloat.tar.gz
	["mipsle"]=gost_3.3.0_linux_mipsle_softfloat.tar.gz
	["mips64"]=gost_3.3.0_linux_mips64_hardfloat.tar.gz
	["mips64le"]=gost_3.3.0_linux_mips64le_hardfloat.tar.gz
	["riscv64"]=gost_3.3.0_linux_riscv64.tar.gz
)
declare -A realm_assets=(
	["386"]=""
	["amd64"]=realm-x86_64-unknown-linux-musl.tar.gz
	["arm64"]=realm-aarch64-unknown-linux-musl.tar.gz
	["armv5"]=""
	["armv6"]=realm-arm-unknown-linux-musleabihf.tar.gz
	["armv7"]=realm-armv7-unknown-linux-musleabihf.tar.gz
	["loong64"]=""
	["mips"]=realm-mips-unknown-linux-musl.tar.gz
	["mipsle"]=realm-mipsel-unknown-linux-musl.tar.gz
	["mips64"]=realm-mips64-unknown-linux-muslabi64.tar.gz
	["mips64le"]=realm-mips64el-unknown-linux-muslabi64.tar.gz
	["riscv64"]=""
)
declare -A frp_assets=(
	["386"]=""
	["amd64"]=frp_0.71.1_linux_amd64.tar.gz
	["arm64"]=frp_0.71.1_linux_arm64.tar.gz
	["armv5"]=frp_0.71.1_linux_arm.tar.gz
	["armv6"]=""
	["armv7"]=frp_0.71.1_linux_arm_hf.tar.gz
	["loong64"]=frp_0.71.1_linux_loong64.tar.gz
	["mips"]=frp_0.71.1_linux_mips.tar.gz
	["mipsle"]=frp_0.71.1_linux_mipsle.tar.gz
	["mips64"]=frp_0.71.1_linux_mips64.tar.gz
	["mips64le"]=frp_0.71.1_linux_mips64le.tar.gz
	["riscv64"]=frp_0.71.1_linux_riscv64.tar.gz
)

# ---- variant map (copied from tools/manifestgen/kernels.example.yaml) --------
# The variant tokens the manifest carries for a target; an absent key means no
# tokens. They decide whether a build can run on a machine (the agent's
# platform.Info.Compatible refuses "hardfloat"/"sse2" on a softfloat build and
# "glibc" on a musl host), and they travel into the built-in Go table.
declare -A gost_variants=(
	["386"]=sse2
	["mips"]=softfloat
	["mipsle"]=softfloat
	["mips64"]=hardfloat
	["mips64le"]=hardfloat
)
declare -A realm_variants=(
	["amd64"]=musl-full
	["arm64"]=musl-full
	["armv6"]=musl-full
	["armv7"]=musl-full
	["mips"]="musl-full softfloat"
	["mipsle"]="musl-full softfloat"
	["mips64"]="musl-full hardfloat"
	["mips64le"]="musl-full hardfloat"
)
declare -A frp_variants=(
	["mips"]=softfloat
	["mipsle"]=softfloat
	["mips64"]=hardfloat
	["mips64le"]=hardfloat
)

# ---- helpers -----------------------------------------------------------------

die() { printf 'build-kernels: %s\n' "$*" >&2; exit 1; }

usage() {
	cat >&2 <<'EOF'
usage: bash release/build-kernels.sh
  KERNELS="gost realm frp"  kernels to build (default: all)
  KEEP_WORK=1               keep dist-kernels/.work after a successful run
  REUSE_WORK=1              reuse already downloaded upstream files (re-verified)
  GEN_ONLY=1                only regenerate kernel/install/ownkernels_gen.go
                            from the dist-kernels already on disk
EOF
}

fetch() {
	curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL \
		--retry 3 --connect-timeout 20 "$@"
}

# map_of KERNEL prints the asset map name for a kernel.
map_of() {
	case "$1" in
	gost) printf 'gost_assets\n' ;;
	realm) printf 'realm_assets\n' ;;
	frp) printf 'frp_assets\n' ;;
	*) die "unknown kernel $1" ;;
	esac
}

repo_of() {
	case "$1" in
	gost) printf 'go-gost/gost\n' ;;
	realm) printf 'zhboner/realm\n' ;;
	frp) printf 'fatedier/frp\n' ;;
	*) die "unknown kernel $1" ;;
	esac
}

tag_of() {
	case "$1" in
	gost) printf 'v%s\n' "$gost_ver" ;;
	realm) printf 'v%s\n' "$realm_ver" ;;
	frp) printf 'v%s\n' "$frp_ver" ;;
	*) die "unknown kernel $1" ;;
	esac
}

# asset_of KERNEL ARCH prints the upstream asset name, or nothing for null.
asset_of() {
	local -n _map="$(map_of "$1")"
	printf '%s\n' "${_map[$2]:-}"
}

# ver_of KERNEL prints the kernel version without the leading v.
ver_of() {
	case "$1" in
	gost) printf '%s\n' "$gost_ver" ;;
	realm) printf '%s\n' "$realm_ver" ;;
	frp) printf '%s\n' "$frp_ver" ;;
	*) die "unknown kernel $1" ;;
	esac
}

# release_tag KERNEL prints the W1nCray release tag of a kernel (gost-v3.3.0).
release_tag() {
	printf '%s-v%s\n' "$1" "$(ver_of "$1")"
}

# variant_of KERNEL ARCH prints the variant tokens of one build ("" = none).
variant_of() {
	local -n _v="${1}_variants"
	printf '%s\n' "${_v[$2]:-}"
}

# product_of KERNEL ARCH prints the W1nCray asset name built for that platform.
product_of() {
	case "$1" in
	frp) printf 'W1nCray-frp-linux-%s.tar.gz\n' "$2" ;;
	*) printf 'W1nCray-%s-linux-%s.gz\n' "$1" "$2" ;;
	esac
}

# archive_of KERNEL prints the archive format of its W1nCray asset.
archive_of() {
	case "$1" in
	frp) printf 'tar.gz\n' ;;
	*) printf 'gz\n' ;;
	esac
}

# single_member KERNEL prints the one binary its upstream archive holds.
single_member() {
	case "$1" in
	gost) printf 'gost\n' ;;
	realm) printf 'realm\n' ;;
	*) die "$1 is not a single-binary kernel" ;;
	esac
}

# fetch_checksums KERNEL DIR downloads the upstream checksum file (gost, frp).
fetch_checksums() {
	local kernel="$1" dir="$2" url repo tag
	repo="$(repo_of "$kernel")"
	tag="$(tag_of "$kernel")"
	case "$kernel" in
	gost) url="https://github.com/$repo/releases/download/$tag/checksums.txt" ;;
	frp) url="https://github.com/$repo/releases/download/$tag/frp_sha256_checksums.txt" ;;
	*) return 0 ;;
	esac
	printf 'build-kernels: %s: fetching the upstream checksum file\n' "$kernel" >&2
	fetch "$url" >"$dir/checksums.txt"
	[ -s "$dir/checksums.txt" ] || die "$kernel: the upstream checksum file is empty"
}

# checksum_for KERNEL DIR ASSET prints the expected sha256 of one asset.
checksum_for() {
	local kernel="$1" dir="$2" asset="$3" n sha
	n="$(awk -v a="$asset" '$2 == a { print $1 }' "$dir/checksums.txt" | wc -l)"
	[ "$n" -eq 1 ] || die "$kernel: $asset has $n lines in the upstream checksum file, want exactly 1"
	sha="$(awk -v a="$asset" '$2 == a { print $1 }' "$dir/checksums.txt" | head -n 1 | tr 'A-F' 'a-f')"
	printf '%s\n' "$sha"
}

# fetch_api_digests KERNEL DIR downloads the release JSON used for realm, whose
# release carries no checksum file: each asset object has a "digest" field of
# the form "sha256:<64 hex>".
fetch_api_digests() {
	local kernel="$1" dir="$2" repo tag
	repo="$(repo_of "$kernel")"
	tag="$(tag_of "$kernel")"
	printf 'build-kernels: %s: fetching the release metadata for the asset digests\n' "$kernel" >&2
	fetch "https://api.github.com/repos/$repo/releases/tags/$tag" >"$dir/release.json"
	[ -s "$dir/release.json" ] || die "$kernel: the release metadata is empty"
}

# digest_for KERNEL DIR ASSET prints the API digest of one asset. The asset
# name and its digest are fields of the same JSON object, so the match walks
# one object at a time and never reads a digest from a neighbouring asset.
digest_for() {
	local kernel="$1" dir="$2" asset="$3" n dig
	n="$(awk -v want="$asset" '
		BEGIN { q = sprintf("%c", 34) }
		index($0, q "name" q) { seen = (index($0, q want q) > 0); next }
		seen && index($0, q "digest" q) { seen = 0; print $0 }
	' "$dir/release.json" | wc -l)"
	[ "$n" -eq 1 ] || die "$kernel: $asset has $n digest fields in the release metadata, want exactly 1"
	dig="$(awk -v want="$asset" '
		BEGIN { q = sprintf("%c", 34) }
		index($0, q "name" q) { seen = (index($0, q want q) > 0); next }
		seen && index($0, q "digest" q) {
			seen = 0
			v = $0
			sub(/^.*"digest"[[:space:]]*:[[:space:]]*"/, "", v)
			sub(/".*$/, "", v)
			print v
		}
	' "$dir/release.json" | head -n 1)"
	case "$dig" in
	sha256:*) ;;
	*) die "$kernel: $asset has no sha256 digest in the release metadata (got \"$dig\")" ;;
	esac
	dig="${dig#sha256:}"
	case "$dig" in
	*[!0-9a-fA-F]* | "") die "$kernel: $asset digest is not 64 hex characters" ;;
	esac
	[ "${#dig}" -eq 64 ] || die "$kernel: $asset digest is ${#dig} characters, want 64"
	printf '%s\n' "$(printf '%s' "$dig" | tr 'A-F' 'a-f')"
}

# expected_sha KERNEL DIR ASSET dispatches to the right verification source.
expected_sha() {
	case "$1" in
	realm) digest_for "$1" "$2" "$3" ;;
	*) checksum_for "$1" "$2" "$3" ;;
	esac
}

source_label() {
	case "$1" in
	gost) printf 'checksums.txt\n' ;;
	frp) printf 'frp_sha256_checksums.txt\n' ;;
	realm) printf 'api-digest\n' ;;
	*) die "unknown kernel $1" ;;
	esac
}

# verify_asset KERNEL ASSET FILE EXPECTED: any mismatch is fatal, no skip.
verify_asset() {
	local kernel="$1" asset="$2" file="$3" want="$4" got
	got="$(sha256sum "$file" | awk '{ print $1 }' | tr 'A-F' 'a-f')"
	[ "$got" = "$want" ] || die "$kernel: $asset: expected sha256 $want, got $got"
}

# verify_archive_paths KERNEL ASSET ARCHIVE refuses absolute and parent paths.
verify_archive_paths() {
	local kernel="$1" asset="$2" archive="$3" bad
	bad="$(tar -tzf "$archive" | grep -E '(^|/)\.\.(/|$)|^/|\\' || true)"
	[ -z "$bad" ] || die "$kernel: $asset: unsafe path in archive: $bad"
}

# assert_elf KERNEL ASSET FILE: non-empty regular file with the ELF magic.
assert_elf() {
	local kernel="$1" asset="$2" file="$3" magic
	[ -f "$file" ] || die "$kernel: $asset: the extracted member is not a regular file"
	[ ! -L "$file" ] || die "$kernel: $asset: the extracted member is a symbolic link"
	[ -s "$file" ] || die "$kernel: $asset: the extracted member is empty"
	magic="$(od -An -N4 -tx1 "$file" | tr -d ' \n')"
	[ "$magic" = "7f454c46" ] || die "$kernel: $asset: the extracted member is not an ELF file (magic $magic)"
}

# tar_has_mtime tests once whether this tar understands --mtime.
tar_has_mtime=0
if tar --help 2>/dev/null | grep -q -- '--mtime'; then
	tar_has_mtime=1
fi

tar_create() {
	if [ "$tar_has_mtime" = 1 ]; then
		tar --owner=0 --group=0 --numeric-owner --mode=0755 \
			--mtime="$tar_mtime" "$@"
	else
		tar --owner=0 --group=0 --numeric-owner --mode=0755 "$@"
	fi
}

# ---- the built-in Go table ----------------------------------------------------
#
# kernel/install/ownkernels_gen.go mirrors the mirrored assets: one row per
# artifact with its URL, sha256, size, archive format, variant and members. The
# agent installs gost/realm/frp from it without a signed manifest. It is only
# ever written from a complete, fully verified dist-kernels; a partial KERNELS
# set prints one line and leaves the file alone.

go_table=kernel/install/ownkernels_gen.go

# gen_go_table rewrites $go_table from the artifacts in $out. It downloads
# nothing, never writes into $out, and replaces $go_table only after every
# check has passed.
gen_go_table() {
	local sums="$out/SHA256SUMS"
	local dest="$go_table" tmp="$go_table.tmp.$$"
	local kernel arch product hex file members rc n

	if [ "$kernels" != "$all_kernels" ]; then
		printf 'build-kernels: KERNELS is not the full set (%s); %s is not generated\n' \
			"$all_kernels" "$dest" >&2
		return 0
	fi

	[ -f "$sums" ] || die "$sums is missing; nothing to generate the built-in table from"
	n="$(wc -l <"$sums" | tr -d ' ')"
	[ "$n" -eq 30 ] || die "$sums has $n lines, want 30"

	# Every line must name exactly one expected artifact with a well-formed
	# digest; the file may use either sha256sum output form ("<hex>  <file>"
	# or the binary form "<hex> *<file>").
	local -A sha_of
	local -A seen
	while read -r hex file; do
		# sha256sum writes "<hex>  <file>", or "<hex> *<file>" in binary
		# mode; a line that is not of that shape is reported by its name.
		if [ -z "$file" ]; then
			file="$hex"
			hex=""
		fi
		file="${file#\*}"
		case "$file" in
		W1nCray-gost-linux-*) kernel=gost ;;
		W1nCray-realm-linux-*) kernel=realm ;;
		W1nCray-frp-linux-*) kernel=frp ;;
		*) die "$sums: unexpected artifact name \"$file\"" ;;
		esac
		arch="${file#W1nCray-$kernel-linux-}"
		case "$arch" in
		*.tar.gz) arch="${arch%.tar.gz}" ;;
		*.gz) arch="${arch%.gz}" ;;
		*) die "$sums: \"$file\" is not a W1nCray-<kernel>-linux-<arch> artifact" ;;
		esac
		[ -n "$(asset_of "$kernel" "$arch")" ] ||
			die "$sums: \"$file\" is a platform the maps do not build ($kernel $arch)"
		[ "$(product_of "$kernel" "$arch")" = "$file" ] ||
			die "$sums: \"$file\" is not the artifact name of $kernel $arch"
		case "$hex" in
		*[!0-9a-f]* | "") die "$sums: \"$hex\" is not 64 lowercase hex characters" ;;
		esac
		[ "${#hex}" -eq 64 ] || die "$sums: \"$hex\" is not 64 lowercase hex characters"
		[ -z "${seen[$file]:-}" ] || die "$sums: \"$file\" appears more than once"
		seen[$file]=1
		sha_of[$file]="$hex"
	done <"$sums"

	# ... and every artifact the maps expect must be there, with its digest.
	for kernel in $all_kernels; do
		for arch in $arch_order; do
			[ -n "$(asset_of "$kernel" "$arch")" ] || continue
			product="$(product_of "$kernel" "$arch")"
			[ -f "$out/$product" ] || die "$out/$product is missing"
			[ -n "${sha_of[$product]:-}" ] || die "$sums has no line for $product"
		done
	done

	# The digests must really match the bytes on disk.
	(cd "$out" && sha256sum -c SHA256SUMS >/dev/null) ||
		die "$sums does not verify against the artifacts in $out"

	rc=0
	{
		printf '// Code generated by release/build-kernels.sh, do not edit. DO NOT EDIT.\n'
		printf '\n'
		printf 'package install\n'
		printf '\n'
		printf '// ownKernelTable is the built-in W1nCray release table: the mirrored\n'
		printf '// gost, realm and frp assets the agent installs without a manifest.\n'
		printf 'var ownKernelTable = []ownKernel{\n'
		for kernel in $all_kernels; do
			for arch in $arch_order; do
				[ -n "$(asset_of "$kernel" "$arch")" ] || continue
				product="$(product_of "$kernel" "$arch")"
				members=""
				[ "$kernel" = frp ] && members=", Members: ownFrpMembers"
				printf '\t{Name: "%s", Version: "%s", Platform: "linux/%s", Variant: "%s", URL: "https://github.com/W1nCwC/W1nCray/releases/download/%s/%s", SHA256: "%s", Size: %s, Archive: "%s"%s},\n' \
					"$kernel" "$(ver_of "$kernel")" "$arch" "$(variant_of "$kernel" "$arch")" \
					"$(release_tag "$kernel")" "$product" "${sha_of[$product]}" \
					"$(wc -c <"$out/$product" | tr -d ' ')" "$(archive_of "$kernel")" "$members"
			done
		done
		printf '}\n'
	} >"$tmp" || rc=$?
	if [ "$rc" -ne 0 ]; then
		rm -f "$tmp"
		die "writing $tmp failed"
	fi
	mv -f "$tmp" "$dest"
	printf 'build-kernels: wrote %s (%s entries)\n' "$dest" "$(grep -c '{Name: ' "$dest")" >&2
}

# ---- argument sanity ---------------------------------------------------------

for k in $kernels; do
	case " $all_kernels " in
	*" $k "*) ;;
	*) usage; die "unknown kernel \"$k\" in KERNELS" ;;
	esac
done

# ---- GEN_ONLY: regenerate the Go table from the dist-kernels on disk ---------

if [ "${GEN_ONLY:-0}" = 1 ]; then
	gen_go_table
	exit 0
fi

# ---- build -------------------------------------------------------------------

# REUSE_WORK keeps the previously downloaded upstream files in place; the
# metadata (checksum file / release JSON) is fetched again, and every file goes
# through the full verification below either way. SHA256SUMS and the upstream
# record are always dropped first: they may only exist after a complete run.
if [ "${REUSE_WORK:-0}" = 1 ]; then
	mkdir -p "$out"
else
	rm -rf "$out"
	mkdir -p "$out"
fi
rm -f "$out/SHA256SUMS" "$verify_file"
mkdir -p "$work"

for kernel in $kernels; do
	dir="$work/$kernel"
	mkdir -p "$dir"
	if [ "${REUSE_WORK:-0}" != 1 ]; then
		rm -rf "$dir"
		mkdir -p "$dir"
	fi
	repo="$(repo_of "$kernel")"
	tag="$(tag_of "$kernel")"
	case "$kernel" in
	realm) fetch_api_digests "$kernel" "$dir" ;;
	*) fetch_checksums "$kernel" "$dir" ;;
	esac
	for arch in $arch_order; do
		asset="$(asset_of "$kernel" "$arch")"
		if [ -z "$asset" ]; then
			continue
		fi
		file="$dir/$asset"
		# Fetch the expected hash before touching the network for the asset.
		want="$(expected_sha "$kernel" "$dir" "$asset")"
		if [ -f "$file" ] && [ "${REUSE_WORK:-0}" = 1 ]; then
			printf 'build-kernels: %s: reusing %s\n' "$kernel" "$asset" >&2
		else
			printf 'build-kernels: %s: downloading %s\n' "$kernel" "$asset" >&2
			fetch "https://github.com/$repo/releases/download/$tag/$asset" >"$file"
		fi
		verify_asset "$kernel" "$asset" "$file" "$want"
		verify_archive_paths "$kernel" "$asset" "$file"

		ex="$dir/extract-$arch"
		rm -rf "$ex"
		mkdir -p "$ex"
		if [ "$kernel" = frp ]; then
			base="${asset%.tar.gz}"
			tar -xzf "$file" -C "$ex" "$base/frpc" "$base/frps"
			assert_elf "$kernel" "$asset" "$ex/$base/frpc"
			assert_elf "$kernel" "$asset" "$ex/$base/frps"
			frpc_sha="$(sha256sum "$ex/$base/frpc" | awk '{ print $1 }' | tr 'A-F' 'a-f')"
			frps_sha="$(sha256sum "$ex/$base/frps" | awk '{ print $1 }' | tr 'A-F' 'a-f')"

			stage="$dir/stage-$arch"
			rm -rf "$stage"
			mkdir -p "$stage"
			cp "$ex/$base/frpc" "$stage/frpc"
			cp "$ex/$base/frps" "$stage/frps"
			chmod 0755 "$stage/frpc" "$stage/frps"
			product="W1nCray-frp-linux-$arch.tar.gz"
			tar_create -czf "$out/$product" -C "$stage" frpc frps
			rm -rf "$stage"

			# Self-check: the packed members are byte-identical to the
			# extracted ones, and the archive holds exactly the two names.
			names="$(tar -tzf "$out/$product" | tr '\n' ' ')"
			[ "$names" = "frpc frps " ] || die "$kernel: $asset: packed members are \"$names\", want \"frpc frps\""
			rm -rf "$dir/check-$arch"
			mkdir -p "$dir/check-$arch"
			tar -xzf "$out/$product" -C "$dir/check-$arch" frpc frps
			[ "$(sha256sum "$dir/check-$arch/frpc" | awk '{ print $1 }' | tr 'A-F' 'a-f')" = "$frpc_sha" ] ||
				die "$kernel: $asset: the packed frpc differs from the extracted one"
			[ "$(sha256sum "$dir/check-$arch/frps" | awk '{ print $1 }' | tr 'A-F' 'a-f')" = "$frps_sha" ] ||
				die "$kernel: $asset: the packed frps differs from the extracted one"
			rm -rf "$dir/check-$arch"

			printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$product" "$asset" "$want" "$(source_label "$kernel")" "$frpc_sha" "$frps_sha" >>"$verify_file"
		else
			member="$(single_member "$kernel")"
			tar -xzf "$file" -C "$ex" "$member"
			assert_elf "$kernel" "$asset" "$ex/$member"
			bin_sha="$(sha256sum "$ex/$member" | awk '{ print $1 }' | tr 'A-F' 'a-f')"
			product="W1nCray-$kernel-linux-$arch.gz"
			gzip -n -9 -c "$ex/$member" >"$out/$product"
			# Self-check: the product decompresses back to the very bytes.
			[ "$(gzip -dc "$out/$product" | sha256sum | awk '{ print $1 }')" = "$bin_sha" ] ||
				die "$kernel: $asset: $product does not decompress to the extracted binary"
			printf '%s\t%s\t%s\t%s\t%s\n' "$product" "$asset" "$want" "$(source_label "$kernel")" "$bin_sha" >>"$verify_file"
		fi
		rm -rf "$ex"
	done
done

# ---- checksums and the upstream record (only after every artifact exists) ----

# expected_products counts the non-null platforms of the kernels being built:
# 30 for the full set (gost 12 + realm 8 + frp 10).
expected_products=0
for kernel in $kernels; do
	for arch in $arch_order; do
		if [ -n "$(asset_of "$kernel" "$arch")" ]; then
			expected_products=$((expected_products + 1))
		fi
	done
done
if [ "$kernels" = "$all_kernels" ] && [ "$expected_products" -ne 30 ]; then
	die "the platform map lists $expected_products artifacts, want 30 for the full set"
fi

products="$(cd "$out" && ls -1 | grep -c '\.\(gz\|tar\.gz\)$' || true)"
[ "$products" -eq "$expected_products" ] || die "built $products artifacts, want $expected_products"

(cd "$out" && sha256sum -- *.gz >SHA256SUMS)
lines="$(wc -l <"$out/SHA256SUMS" | tr -d ' ')"
[ "$lines" -eq "$expected_products" ] || die "SHA256SUMS has $lines lines, want $expected_products"

if [ "${KEEP_WORK:-0}" = 1 ]; then
	printf 'build-kernels: keeping the work directory\n' >&2
else
	rm -rf "$work"
fi

printf 'build-kernels: ok (%s artifacts)\n' "$products"

# The built-in table is the last step of a complete build: the artifacts above
# are the bytes it describes. A partial KERNELS set only prints one line.
gen_go_table
