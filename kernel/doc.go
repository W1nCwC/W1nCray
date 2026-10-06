// Package kernel is the home of everything that decides which external kernel
// binaries (gost, frp, realm, xray) the agent may run, and installs them.
// Sub-packages:
//
//	kernel/manifest   signed manifest: types, canonical JSON, signature verify
//	kernel/platform   machine -> manifest target key, variant compatibility
//	kernel/install    download, verify, extract, self-check, switch, rollback
//	kernel/netutil    HTTP client (proxy env incl. ALL_PROXY and socks5/socks5h)
//
// This package itself only holds the shared error kinds (see errors.go).
//
// # Trust model (non-negotiable)
//
// The agent trusts exactly one thing: a kernel manifest signed with an
// ed25519 key whose public half is compiled into the agent (at least two keys
// are kept so one can be rotated; see manifest.DefaultKeys). It does not trust
// GitHub, mirrors, the panel, or any checksum file that travels with a
// download.
//
//   - The panel can only pin {name, version}. It cannot supply a URL or a
//     hash (spec.KernelPin has no such fields).
//   - Every SHA-256 (archive and each extracted file) is written into the
//     manifest by the release CI (tools/manifestgen), which cross-checks
//     GitHub's asset digest, the upstream checksum file and its own download.
//     The agent never calls the GitHub API.
//   - Download URLs are an ordered list of transport sources (our mirror,
//     third-party mirrors, upstream). They are untrusted pipes: bytes that do
//     not hash to archive_sha256 are discarded and the next source is tried.
//     There is no switch that skips verification (fail-closed).
//   - The manifest carries a strictly increasing sequence (the agent persists
//     the highest it ever accepted and refuses lower ones: rollback
//     protection), an expires_at (freeze protection) and revocation lists.
//
// Known limitation: expiry needs a sane clock. A router that boots with the
// clock at 1970 and has not yet synced gets kernel.ErrClock (never an
// installation) once the manifest's issued_at lies more than 24 h in its
// future; with a clock that is wrong in the other direction, expiry
// protection is weakened to the device's clock accuracy.
//
// # Directory layout
//
//	<Dir>/kernels/                       0755
//	    state.json                       0600  {max_sequence, bad{name@ver: back-off}}
//	    manifest.json                    0600  last accepted signed manifest
//	    <name>/                          0755
//	        <version>/                   0755  one directory per installed version
//	            <to files>               mode taken from the manifest ("0755" binaries, "0644"/"0600" data)
//	            .installed.json          0600  install record (target, archive sha256, files)
//	        current                      symlink -> <version> (unix); text file with the
//	        previous                     version on Windows or where symlinks fail (vfat)
//	        .partial/                    0700  downloads (<archive_sha256>.part, resumable)
//	                                           and staging dirs; always on the same filesystem
//	                                           as the final location, never /tmp (RAM on OpenWrt)
//
// driver.Installed.Path is <Dir>/kernels/<name>/<version>/<run.binary>, a
// stable per-version path (not the "current" link), so a running process is
// never affected by a later switch. Sibling files (e.g. frps next to frpc)
// are in the same directory.
//
// # Manifest fields
//
//	schema (1), sequence (int, monotonic), issued_at, expires_at (RFC 3339)
//	kernels[]:
//	  name, version (no leading "v"), channel, min_agent
//	  license{spdx, file, source_url}        shipped with any mirrored copy
//	  capabilities{...}                       free-form, only displayed by the panel
//	  run{binary, version_cmd[], version_regex}
//	  targets{ "<os>/<arch>": null | {        null = no build for this platform
//	      variant                             softfloat | hardfloat | sse2 | musl-full | glibc ...
//	      urls[], archive (tar.gz|zip), archive_sha256, archive_size,
//	      extract[{from, to, sha256, size, mode}], installed_size } }
//	  revoked[{version, sha256, reason}]      applies to all entries of that kernel name
//	signature{alg:"ed25519", key_id, sig}     over the canonical JSON without "signature"
//
// Target keys: linux/386 amd64 arm64 armv5 armv6 armv7 loong64 mips mipsle
// mips64 mips64le riscv64. Canonical JSON: keys sorted bytewise, no
// whitespace, integers only, duplicate keys rejected (manifest.Canonicalize).
//
// # API for the reconciler
//
//	in, err := install.New(install.Config{Dir: prefix, AgentVersion: version})
//	err = in.LoadManifest(rawSignedManifest)      // verify + persist; keeps old on error
//	inst, err := in.Ensure(ctx, spec.KernelPin{Name: "gost", Version: "3.3.0"}) // driver.Installed
//	inst, err := in.Current("gost")                // Detect: offline
//	inst, err := in.Rollback("gost")               // previous version becomes current
//	err = in.Remove("gost", "3.2.0")               // refuses the current version
//	list, err := in.List()                         // installed versions
//	cat, err := in.Catalog()                       // manifest kernels + availability here
//	inst, err := in.Import(ctx, "/mnt/usb/gost_3.3.0_linux_mipsle_softfloat.tar.gz") // offline
//
// Ensure never leaves a half-installed kernel: on any failure the previously
// current version is still current. Error kinds (errors.Is) and the stable
// string from kernel.Code for reporting to the panel:
//
//	ErrUnavailable  unavailable      manifest knows the kernel but has no (compatible) build here:
//	                                 grey it out. ErrUnknownKernel (unknown_kernel) means the
//	                                 manifest has no such name/version at all.
//	ErrNoSpace      no_space         refused before any deletion; message names --prefix/extroot.
//	ErrRevoked      revoked          version or hash revoked.
//	ErrAgentTooOld  agent_too_old    min_agent not met.
//	ErrVerify       verify_failed    hash/size/archive-structure mismatch (also: archive tricks).
//	ErrCheck        check_failed     binary does not report the pinned version.
//	ErrBackoff      backoff          failed recently; retry time in the message.
//	ErrDownload     download_failed  every source unreachable (network only).
//	ErrSignature, ErrStaleManifest, ErrExpired, ErrClock, ErrNoManifest,
//	ErrNoTrustedKeys, ErrManifestInvalid come from LoadManifest/Ensure when the
//	manifest itself cannot be trusted or is too old.
//
// Failed installs are remembered per name@version with exponential back-off
// (BackoffBase doubling up to BackoffMax) so a reconcile loop cannot hammer
// mirrors; no-space, revoked and unavailable are not remembered (cheap to
// re-evaluate, fixable at once).
package kernel
