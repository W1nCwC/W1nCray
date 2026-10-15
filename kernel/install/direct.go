// This file adds the manifest-free direct path (v0.8.0): a kernel or the
// agent's own build that is described entirely by the caller — a URL, an
// optional archive sha256 and size, an optional archive format and the
// extract rule — with no signed manifest involved (plan 24, "Nezha-style"
// GitHub direct download).
//
// Trust: HTTPS to the release host is the anchor, tightened by the archive
// sha256 when the caller supplies one (the panel pins it from the release
// asset). The version self-check then runs the binary, and the on-disk result
// is produced by the same commit() as a manifest or local install, so the
// kernel directory still has one format.
//
// Everything reuses the existing pipeline: the download honours the same
// scheme rules as the manifest path, the extraction shares the archive code
// path's size budget, the self-check is DefaultCheck, and the switch is
// commit(). Nothing here reads or requires a manifest, and the manifest code
// stays untouched as the fallback for agents that predate this path.

package install

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/kernel"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
)

// AgentRun is the run block of the agent's own build. It is the same block
// the manifestgen agent config lists (binary W1nCray, `version` command, the
// version_regex every release asset must satisfy), so the direct self-update
// self-checks the staged binary exactly like a manifest entry does.
var AgentRun = manifest.Run{
	Binary:       "W1nCray",
	VersionCmd:   []string{"version"},
	VersionRegex: "W1nCray v?([0-9][0-9.]*)",
}

// DefaultKernelRun returns the built-in run block of a known kernel name, so a
// direct install needs no manifest (and no panel-supplied run config) to
// self-check the binary. An unknown name returns a zero Run: the caller must
// then name the installed file itself.
func DefaultKernelRun(name string) manifest.Run {
	switch name {
	case "gost":
		return manifest.Run{Binary: "gost", VersionCmd: []string{"-V"}}
	case "realm":
		return manifest.Run{Binary: "realm", VersionCmd: []string{"-v"}}
	case "frp":
		return manifest.Run{Binary: "frpc", VersionCmd: []string{"-v"}}
	case "xray":
		return manifest.Run{Binary: "xray", VersionCmd: []string{"version"}}
	}
	return manifest.Run{}
}

// AgentDirect describes one agent build for a manifest-free self-update.
type AgentDirect struct {
	// Version is the target version (without the leading v).
	Version string
	// URL is the release asset (the conventional w1ncray-v<ver>-<goos>-<goarch>.gz).
	URL string
	// SHA256, when set, is the required hex sha256 of the archive (the release
	// asset file itself, exactly what a manifest's archive_sha256 pins).
	SHA256 string
}

// StageAgentDirect downloads ad.URL into archiveDir and extracts its single
// gzip member into dest, self-checking that the binary reports ad.Version. It
// is the direct-path counterpart of DownloadFor + VerifyArchiveFor: nothing
// outside the two directories is touched and dest must be empty, so every
// refusal (bad scheme, hash mismatch, wrong version) leaves the agent
// untouched. It returns the absolute path of the staged binary.
func (in *Installer) StageAgentDirect(ctx context.Context, ad AgentDirect, archiveDir, dest string) (string, error) {
	version := manifest.NormalizeVersion(ad.Version)
	if version == "" {
		return "", errors.New("install: a version is required")
	}
	if err := os.MkdirAll(archiveDir, privDir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dest, dirMode); err != nil {
		return "", err
	}
	archive := filepath.Join(archiveDir, "agent-"+version+".gz")
	if err := in.downloadDirect(ctx, "agent", version, ad.URL, ad.SHA256, 0, archive); err != nil {
		return "", err
	}
	bin := filepath.Join(dest, AgentRun.Binary)
	if err := writeLocalBinary(archive, bin); err != nil {
		return "", kernel.Wrap(kernel.ErrVerify, "agent", version, err, "unpacking %s", filepath.Base(archive))
	}
	check := in.cfg.Check
	if check == nil {
		check = DefaultCheck(AgentRun)
	}
	got, err := check(bin)
	if err != nil {
		return "", kernel.Wrap(kernel.ErrCheck, "agent", version, err, "running version check")
	}
	if manifest.NormalizeVersion(got) != version {
		_ = os.Remove(bin)
		return "", kernel.Newf(kernel.ErrCheck, "agent", version,
			"binary reports version %q, expected %q", got, ad.Version)
	}
	return bin, nil
}

// DirectMember is one file a multi-file tar.gz installs: From is its path
// inside the archive, To the installed file name inside the version directory.
type DirectMember struct {
	// From is the member path inside the archive. Empty means To.
	From string
	// To is the installed file name in the version directory: a plain file
	// name, never a path.
	To string
}

// DirectInstall describes one kernel build downloaded straight from a URL,
// without a signed manifest. It is what kernel_install carries in its args
// when the panel pins the asset itself.
type DirectInstall struct {
	// Name is the kernel name ("gost", "realm", "frp", ...).
	Name string
	// Version, when set, must equal what the self-check reports; when empty
	// the self-check decides the installed version (as a local install does).
	Version string
	// URL is the asset to download (https, or http with AllowHTTP).
	URL string
	// SHA256, when set, is the required hex sha256 of the archive.
	SHA256 string
	// Size, when set, is the required archive size in bytes.
	Size int64
	// Archive is the format: manifest.ArchiveGz (default) or
	// manifest.ArchiveTarGz. A gz stream carries exactly one file.
	Archive string
	// To is the installed file name; empty means Run.Binary, which in turn
	// defaults to DefaultKernelRun(Name).
	To string
	// From is the archive member a tar.gz takes the binary from; empty means
	// To. A gz stream has no member name and ignores it.
	From string
	// Members, when non-empty, selects the multi-file tar.gz form: the archive
	// is required to be tar.gz, From/To must stay empty, and every member is
	// extracted under its own installed file name in one commit (frp ships
	// frpc and frps in a single archive). An empty Members keeps the
	// single-file behaviour of From/To byte for byte.
	Members []DirectMember
	// Run overrides the version self-check; empty means DefaultKernelRun(Name).
	Run manifest.Run
}

// InstallDirect downloads di.URL, verifies it against di.SHA256/di.Size when
// given, extracts the binary, self-checks it and switches it in through the
// same commit() as a manifest install. The result is indistinguishable from a
// manifest install: list, upgrade, rollback and remove all work on it.
func (in *Installer) InstallDirect(ctx context.Context, di DirectInstall) (driver.Installed, error) {
	in.mu.Lock()
	defer in.mu.Unlock()

	name := di.Name
	if err := validName(name); err != nil {
		return driver.Installed{}, err
	}
	format := di.Archive
	if format == "" {
		format = manifest.ArchiveGz
	}
	if format != manifest.ArchiveGz && format != manifest.ArchiveTarGz {
		return driver.Installed{}, kernel.Newf(kernel.ErrVerify, name, "",
			"unsupported archive format %q (the direct path carries gz and tar.gz)", format)
	}
	run := di.Run
	if run.Binary == "" && len(run.VersionCmd) == 0 {
		run = DefaultKernelRun(name)
	}
	bin := di.To
	if bin == "" {
		bin = run.Binary
	}
	if bin == "" {
		return driver.Installed{}, kernel.Newf(kernel.ErrVerify, name, "",
			"no installed file name (set To or a run block for %q)", name)
	}
	if !manifest.SafeArchivePath(bin) || bin != path.Base(bin) || bin == ".installed.json" {
		return driver.Installed{}, kernel.Newf(kernel.ErrVerify, name, "", "invalid installed file name %q", bin)
	}
	if err := checkDirectSHA256(name, di.SHA256); err != nil {
		return driver.Installed{}, err
	}
	// A member list is a whole-archive description: it must be validated (and
	// refused) before the download, so a malformed request never touches the
	// disk and never reaches the network.
	var members []directMember
	if len(di.Members) > 0 {
		if di.Archive != manifest.ArchiveTarGz {
			return driver.Installed{}, kernel.Newf(kernel.ErrVerify, name, "",
				"members require tar.gz, got archive format %q", format)
		}
		if di.From != "" || di.To != "" {
			return driver.Installed{}, kernel.Newf(kernel.ErrVerify, name, "",
				"members cannot be combined with from/to")
		}
		checked, err := checkDirectMembers(name, run.Binary, di.Members)
		if err != nil {
			return driver.Installed{}, err
		}
		members = checked
	}
	if err := ctx.Err(); err != nil {
		return driver.Installed{}, err
	}
	version := manifest.NormalizeVersion(di.Version)

	stage, err := in.newStage(name, "direct")
	if err != nil {
		return driver.Installed{}, err
	}
	defer func() { _ = os.RemoveAll(stage) }()

	// The archive never enters the stage (commit renames the stage into the
	// version directory): it is downloaded into a sibling directory instead.
	tmp, err := os.MkdirTemp(in.partialDir(name), "direct-")
	if err != nil {
		return driver.Installed{}, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	archive := filepath.Join(tmp, "asset.bin")
	if err := in.downloadDirect(ctx, name, version, di.URL, di.SHA256, di.Size, archive); err != nil {
		return driver.Installed{}, err
	}

	binPath := filepath.Join(stage, bin)
	if len(members) > 0 {
		if err := extractDirectTarGzMembers(archive, members, stage, name, version); err != nil {
			return driver.Installed{}, err
		}
	} else if format == manifest.ArchiveGz {
		if err := writeLocalBinary(archive, binPath); err != nil {
			return driver.Installed{}, kernel.Wrap(kernel.ErrVerify, name, version, err, "unpacking %s", filepath.Base(archive))
		}
	} else if err := extractDirectTarGz(archive, di.From, bin, binPath, name, version); err != nil {
		return driver.Installed{}, err
	}

	// The version self-check names the installation, exactly like a local
	// install: a file that does not run on this machine is refused before
	// anything is switched in.
	check := in.cfg.Check
	if check == nil {
		check = DefaultCheck(run)
	}
	got, err := check(binPath)
	if err != nil {
		return driver.Installed{}, kernel.Wrap(kernel.ErrCheck, name, version, err, "running version check")
	}
	gotVersion := manifest.NormalizeVersion(got)
	if di.Version != "" && gotVersion != version {
		return driver.Installed{}, kernel.Newf(kernel.ErrCheck, name, gotVersion,
			"binary reports version %q, expected %q", got, di.Version)
	}
	if !reVersionDir.MatchString(gotVersion) {
		return driver.Installed{}, kernel.Newf(kernel.ErrCheck, name, gotVersion, "binary reports an unusable version %q", got)
	}

	binSum, binSize, err := hashFile(binPath)
	if err != nil {
		return driver.Installed{}, err
	}
	archiveSum, archiveSize, err := hashFile(archive)
	if err != nil {
		return driver.Installed{}, err
	}
	target := in.plat.Key()
	k := &manifest.Kernel{
		Name: name, Version: gotVersion,
		Run: manifest.Run{Binary: bin, VersionCmd: run.VersionCmd, VersionRegex: run.VersionRegex},
	}
	t := &manifest.Target{
		Archive: format, ArchiveSHA256: archiveSum, ArchiveSize: archiveSize,
		Extract:       []manifest.Extract{{From: path.Base(archive), To: bin, SHA256: binSum, Size: binSize, Mode: "0755"}},
		InstalledSize: binSize,
	}
	if len(members) > 0 {
		// One extract entry per member, in the member order the caller gave;
		// the archive hash and size stay those of the whole archive.
		extracts := make([]manifest.Extract, 0, len(members))
		var total int64
		for _, m := range members {
			sum, size, err := hashFile(filepath.Join(stage, m.to))
			if err != nil {
				return driver.Installed{}, err
			}
			extracts = append(extracts, manifest.Extract{
				From: m.from, To: m.to, SHA256: sum, Size: size, Mode: "0755",
			})
			total += size
		}
		t.Extract = extracts
		t.InstalledSize = total
	}
	if err := in.commit(stage, k, target, t); err != nil {
		return driver.Installed{}, err
	}
	in.clearFailure(name, gotVersion)
	return in.installedOf(name, gotVersion, in.readMarker(name, gotVersion)), nil
}

// directMember is a validated member of the multi-file form: from is the
// cleaned archive path, to the installed file name.
type directMember struct {
	from string
	to   string
}

// maxDirectMembers bounds a member list. frp ships two files; the limit is a
// guard against a panel sending a whole archive listing, not a feature.
const maxDirectMembers = 8

// checkDirectMembers validates the member list of the multi-file form and
// returns the cleaned members. It runs before the download: a malformed list
// is refused without touching the disk or the network.
func checkDirectMembers(name, runBinary string, list []DirectMember) ([]directMember, error) {
	if len(list) == 0 || len(list) > maxDirectMembers {
		return nil, kernel.Newf(kernel.ErrVerify, name, "",
			"a member list must hold 1 to %d files, got %d", maxDirectMembers, len(list))
	}
	members := make([]directMember, 0, len(list))
	seenTo := make(map[string]bool, len(list))
	seenFrom := make(map[string]bool, len(list))
	for _, m := range list {
		if m.To == "" {
			return nil, kernel.Newf(kernel.ErrVerify, name, "", "a member needs an installed file name")
		}
		if !manifest.SafeArchivePath(m.To) || m.To != path.Base(m.To) || m.To == ".installed.json" {
			return nil, kernel.Newf(kernel.ErrVerify, name, "", "invalid installed file name %q", m.To)
		}
		from := m.From
		if from == "" {
			from = m.To
		}
		clean, ok := cleanMember(from)
		if !ok {
			return nil, kernel.Newf(kernel.ErrVerify, name, "", "invalid archive member %q", m.From)
		}
		if seenTo[m.To] {
			return nil, kernel.Newf(kernel.ErrVerify, name, "", "duplicate installed file name %q", m.To)
		}
		if seenFrom[clean] {
			return nil, kernel.Newf(kernel.ErrVerify, name, "", "duplicate archive member %q", from)
		}
		seenTo[m.To] = true
		seenFrom[clean] = true
		members = append(members, directMember{from: clean, to: m.To})
	}
	if runBinary == "" {
		return nil, kernel.Newf(kernel.ErrVerify, name, "", "no run binary to self-check the members with")
	}
	for _, m := range members {
		if m.to == runBinary {
			return members, nil
		}
	}
	return nil, kernel.Newf(kernel.ErrVerify, name, "",
		"the run binary %q is not one of the installed members", runBinary)
}

// downloadDirect streams one URL into dst while hashing it, enforcing the
// same scheme rules as the manifest download (https, or http with AllowHTTP)
// and the same sha256 mismatch semantics. The archive sha256 and size, when
// the caller supplied them, are verified before anything is extracted.
//
// Unlike the manifest download there is no Range resume: a release asset is a
// single redirect to a CDN object and a failed attempt is simply retried by
// the caller's command flow. The decompressed/unpacked budget is enforced
// during extraction; the streamed archive itself is capped at maxLocalBinary.
func (in *Installer) downloadDirect(ctx context.Context, name, version, rawURL, sha string, size int64, dst string) error {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "https" && !(u.Scheme == "http" && in.cfg.AllowHTTP)) {
		return kernel.Newf(kernel.ErrVerify, name, version, "%s: scheme not allowed", redactURL(rawURL))
	}
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, stateMode)
	if err != nil {
		return err
	}
	rctx, cancel := context.WithTimeout(ctx, in.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := in.cfg.HTTPClient.Do(req)
	if err != nil {
		return kernel.Wrap(kernel.ErrDownload, name, version, err, "fetching %s", redactURL(rawURL))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return kernel.Newf(kernel.ErrDownload, name, version, "%s: HTTP %d", redactURL(rawURL), resp.StatusCode)
	}
	// Stall watchdog: abort the request if no byte arrives for StallTimeout.
	wd := newWatchdog(in.cfg.StallTimeout, cancel)
	defer wd.stop()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(&watchReader{r: resp.Body, wd: wd}, maxLocalBinary+1))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(dst)
		return kernel.Wrap(kernel.ErrDownload, name, version, err, "downloading %s", redactURL(rawURL))
	}
	if n > maxLocalBinary {
		_ = os.Remove(dst)
		return kernel.Newf(kernel.ErrVerify, name, version, "archive expands beyond %d bytes", int64(maxLocalBinary))
	}
	if size > 0 && n != size {
		return kernel.Newf(kernel.ErrVerify, name, version, "archive is %d bytes, %d expected", n, size)
	}
	if sum := hex.EncodeToString(h.Sum(nil)); sha != "" && sum != strings.ToLower(strings.TrimSpace(sha)) {
		_ = os.Remove(dst)
		return kernel.Newf(kernel.ErrVerify, name, version, "archive sha256 %s does not match the expected %s from %s",
			sum, sha, redactURL(rawURL))
	}
	return nil
}

// checkDirectSHA256 validates the optional archive sha256 argument the same
// way the local install's --sha256 flag is validated, but lets it stay empty:
// a direct install without a hash relies on HTTPS alone.
func checkDirectSHA256(name, sha string) error {
	sha = strings.TrimSpace(sha)
	if sha == "" {
		return nil
	}
	if len(sha) != 64 {
		return kernel.Newf(kernel.ErrVerify, name, "", "sha256 must be 64 hex characters, got %d", len(sha))
	}
	if _, err := hex.DecodeString(sha); err != nil {
		return kernel.Newf(kernel.ErrVerify, name, "", "sha256 is not hexadecimal: %v", err)
	}
	return nil
}

// extractDirectTarGz writes the one member from/to dst. It is the direct-path
// counterpart of extractTarGz: the archive hash is the anchor, so the member
// hash is computed (and recorded by commit) rather than pre-declared. Paths
// and the decompressed budget are checked exactly like the manifest path.
func extractDirectTarGz(archivePath, from, to, dst, name, version string) error {
	member := from
	if member == "" {
		member = to
	}
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return verifyErr(name, version, "not a gzip stream: %v", err)
	}
	defer gz.Close()
	// The budget matches the manifest path's default for a single member.
	tr := tar.NewReader(&countingReader{r: gz, max: 64 << 20})
	found := false
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if errors.Is(err, errBudget) {
			return verifyErr(name, version, "archive expands beyond the decompression budget")
		}
		if err != nil {
			return verifyErr(name, version, "reading tar: %v", err)
		}
		clean, ok := cleanMember(hdr.Name)
		if !ok {
			return verifyErr(name, version, "unsafe path %q in archive", hdr.Name)
		}
		if clean != path.Clean(strings.TrimPrefix(member, "./")) {
			continue
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA { //nolint:staticcheck // TypeRegA appears in old archives
			return verifyErr(name, version, "%q is not a regular file: links and special files are refused", hdr.Name)
		}
		out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
		if err != nil {
			return err
		}
		keep := false
		defer func() {
			if !keep {
				_ = os.Remove(dst)
			}
		}()
		n, err := io.Copy(out, tr)
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err == nil && n != hdr.Size {
			err = fmt.Errorf("%q: extracted %d bytes, archive says %d", hdr.Name, n, hdr.Size)
		}
		if err == nil && runtime.GOOS != "windows" {
			err = os.Chmod(dst, 0o755)
		}
		if err != nil {
			return verifyErr(name, version, "extracting %q: %v", hdr.Name, err)
		}
		keep = true
		found = true
		break
	}
	if !found {
		return verifyErr(name, version, "%q is missing from the archive", member)
	}
	return nil
}

// extractDirectTarGzMembers writes every member of a multi-file tar.gz into
// stage under its installed file name (the multi-member counterpart of
// extractDirectTarGz; the single-file function is left untouched). One pass
// over the archive: an unsafe path anywhere is refused, a wanted member must
// be a regular file and must appear exactly once, and every listed member must
// be found. The decompressed budget is the same 64 MiB as the single-file
// path, counted over the whole stream.
func extractDirectTarGzMembers(archivePath string, members []directMember, stage, name, version string) error {
	byFrom := make(map[string]string, len(members))
	for _, m := range members {
		byFrom[m.from] = m.to
	}
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return verifyErr(name, version, "not a gzip stream: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(&countingReader{r: gz, max: 64 << 20})
	done := make(map[string]bool, len(members))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if errors.Is(err, errBudget) {
			return verifyErr(name, version, "archive expands beyond the decompression budget")
		}
		if err != nil {
			return verifyErr(name, version, "reading tar: %v", err)
		}
		clean, ok := cleanMember(hdr.Name)
		if !ok {
			return verifyErr(name, version, "unsafe path %q in archive", hdr.Name)
		}
		to, isWanted := byFrom[clean]
		if !isWanted {
			continue
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA { //nolint:staticcheck // TypeRegA appears in old archives
			return verifyErr(name, version, "%q is not a regular file: links and special files are refused", hdr.Name)
		}
		if done[clean] {
			return verifyErr(name, version, "%q appears twice in archive", hdr.Name)
		}
		dst := filepath.Join(stage, to)
		out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
		if err != nil {
			return err
		}
		n, err := io.Copy(out, tr)
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err == nil && n != hdr.Size {
			err = fmt.Errorf("%q: extracted %d bytes, archive says %d", hdr.Name, n, hdr.Size)
		}
		if err == nil && runtime.GOOS != "windows" {
			err = os.Chmod(dst, 0o755)
		}
		if err != nil {
			_ = os.Remove(dst)
			return verifyErr(name, version, "extracting %q: %v", hdr.Name, err)
		}
		done[clean] = true
	}
	for _, m := range members {
		if !done[m.from] {
			return verifyErr(name, version, "%q is missing from the archive", m.from)
		}
	}
	return nil
}
