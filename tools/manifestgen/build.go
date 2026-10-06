package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/W1nCwC/W1nCray/kernel/manifest"
)

// buildOptions parameterise Build.
type buildOptions struct {
	Cfg   *Config
	GH    *github
	Cache string // download cache directory
	Now   time.Time
	Log   func(format string, args ...any)
}

// Build resolves every configured kernel against its upstream release and
// returns the unsigned manifest.
//
// For each asset three independent hash sources must agree: GitHub's
// asset.digest, the upstream checksum file (when configured) and the SHA-256
// of the bytes we actually downloaded. A disagreement aborts the build; at
// least one upstream source is required. The hashes of the extracted files
// are computed from the archive itself. Nothing in the result is taken on
// trust from a single source.
func Build(ctx context.Context, o buildOptions) (*manifest.Manifest, error) {
	cfg := o.Cfg
	if cfg.Sequence <= 0 {
		return nil, errors.New("sequence must be set (config or -sequence) and positive")
	}
	valid := cfg.ValidDays
	if valid <= 0 {
		valid = 90
	}
	issued := o.Now.UTC().Truncate(time.Second)
	m := &manifest.Manifest{
		Schema: manifest.SchemaVersion, Sequence: cfg.Sequence,
		IssuedAt: issued, ExpiresAt: issued.Add(time.Duration(valid) * 24 * time.Hour),
	}
	for i := range cfg.Kernels {
		k, err := buildKernel(ctx, o, &cfg.Kernels[i])
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", cfg.Kernels[i].Name, cfg.Kernels[i].Version, err)
		}
		m.Kernels = append(m.Kernels, *k)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("generated manifest is invalid: %w", err)
	}
	return m, nil
}

func buildKernel(ctx context.Context, o buildOptions, kc *KernelCfg) (*manifest.Kernel, error) {
	// A kernel may be backed by GitHub assets, by local files, or both. The
	// release lookup only happens when a remote target needs it, so a purely
	// local kernel (the agent itself) needs no repository and no network.
	needsRelease := false
	for _, tc := range kc.Targets {
		if tc != nil {
			needsRelease = true
			break
		}
	}
	var rel *ghRelease
	if needsRelease {
		if o.GH == nil {
			return nil, errors.New("no GitHub client configured for a GitHub-backed kernel")
		}
		var err error
		rel, err = o.GH.release(ctx, kc.Repo, kc.Tag)
		if err != nil {
			return nil, err
		}
		o.Log("%s %s: release %s has %d assets", kc.Name, kc.Version, rel.Tag, len(rel.Assets))
	}

	// upstream checksum file, if configured
	var sums map[string]string
	if kc.Checksums != nil && kc.Checksums.Asset != "" {
		if rel == nil {
			return nil, fmt.Errorf("checksums are only available for GitHub-backed kernels")
		}
		a := rel.asset(kc.Checksums.Asset)
		if a == nil {
			return nil, fmt.Errorf("checksums asset %q not in release", kc.Checksums.Asset)
		}
		b, err := o.GH.fetchSmall(ctx, a)
		if err != nil {
			return nil, err
		}
		if sums = parseSumFile(b); len(sums) == 0 {
			return nil, fmt.Errorf("checksums asset %q has no sha256 lines", a.Name)
		}
		// the checksum file's own GitHub digest must match what we got
		if d, ok := digestHex(a.Digest); ok {
			if got := sha256Hex(b); got != d {
				return nil, fmt.Errorf("checksums asset %q: downloaded sha256 %s != GitHub digest %s", a.Name, got, d)
			}
		}
	}

	k := &manifest.Kernel{
		Name: kc.Name, Version: kc.Version, Channel: kc.Channel, MinAgent: kc.MinAgent,
		License:      manifest.License{SPDX: kc.License.SPDX, File: kc.License.File, SourceURL: kc.License.SourceURL},
		Capabilities: kc.Capabilities,
		Run:          manifest.Run{Binary: kc.Run.Binary, VersionCmd: kc.Run.VersionCmd, VersionRegex: kc.Run.VersionRegex},
		Targets:      map[string]*manifest.Target{},
	}
	for _, r := range kc.Revoked {
		k.Revoked = append(k.Revoked, manifest.Revocation{Version: r.Version, SHA256: r.SHA256, Reason: r.Reason})
	}

	keys := make([]string, 0, len(kc.Targets))
	for key := range kc.Targets {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		tc := kc.Targets[key]
		if tc == nil {
			k.Targets[key] = nil
			o.Log("%s %s: %s -> unavailable (null)", kc.Name, kc.Version, key)
			continue
		}
		t, err := buildTarget(ctx, o, kc, rel, sums, tc)
		if err != nil {
			return nil, fmt.Errorf("target %s: %w", key, err)
		}
		k.Targets[key] = t
		o.Log("%s %s: %s -> %s sha256=%s size=%d", kc.Name, kc.Version, key, tc.Asset, t.ArchiveSHA256[:16], t.ArchiveSize)
	}
	for i := range kc.Local {
		la := kc.Local[i]
		t, err := buildLocalTarget(o, kc, la)
		if err != nil {
			return nil, fmt.Errorf("local target %s: %w", la.Target, err)
		}
		k.Targets[la.Target] = t
		o.Log("%s %s: %s -> %s (local) sha256=%s size=%d", kc.Name, kc.Version, la.Target, la.File, t.ArchiveSHA256[:16], t.ArchiveSize)
	}
	return k, nil
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func buildTarget(ctx context.Context, o buildOptions, kc *KernelCfg, rel *ghRelease, sums map[string]string, tc *TargetCfg) (*manifest.Target, error) {
	a := rel.asset(tc.Asset)
	if a == nil {
		return nil, fmt.Errorf("asset %q not in release %s", tc.Asset, rel.Tag)
	}
	format := tc.Archive
	if format == "" {
		switch {
		case strings.HasSuffix(a.Name, ".tar.gz"), strings.HasSuffix(a.Name, ".tgz"):
			format = manifest.ArchiveTarGz
		case strings.HasSuffix(a.Name, ".zip"):
			format = manifest.ArchiveZip
		case strings.HasSuffix(a.Name, ".gz"):
			// After .tar.gz on purpose: a .tar.gz must never be read as a raw
			// gzip stream.
			format = manifest.ArchiveGz
		default:
			return nil, fmt.Errorf("cannot infer archive type of %q", a.Name)
		}
	}

	// ---- collect the upstream hash claims ----
	claims := map[string]string{} // source -> hex
	if d, ok := digestHex(a.Digest); ok {
		claims["GitHub asset.digest"] = d
	}
	if sums != nil {
		h, ok := sums[a.Name]
		if !ok {
			return nil, fmt.Errorf("checksums file has no entry for %q", a.Name)
		}
		claims["checksums file"] = h
	}
	if kc.Checksums != nil && kc.Checksums.Dgst {
		da := rel.asset(a.Name + ".dgst")
		if da == nil {
			return nil, fmt.Errorf("%s.dgst not in release", a.Name)
		}
		b, err := o.GH.fetchSmall(ctx, da)
		if err != nil {
			return nil, err
		}
		h, ok := parseDgst(b)
		if !ok {
			return nil, fmt.Errorf("%s has no SHA2-256 line", da.Name)
		}
		claims[".dgst file"] = h
	}
	if len(claims) == 0 {
		return nil, fmt.Errorf("no upstream hash for %q (no asset.digest, no checksum file): refusing to trust a bare download", a.Name)
	}

	// ---- download and compare ----
	dst := filepath.Join(o.Cache, strings.ReplaceAll(kc.Repo, "/", "_"), rel.Tag, a.Name)
	got, n, err := o.GH.fetch(ctx, a, dst)
	if err != nil {
		return nil, err
	}
	if a.Size != 0 && n != a.Size {
		return nil, fmt.Errorf("downloaded %d bytes, GitHub says %d", n, a.Size)
	}
	for src, want := range claims {
		if got != want {
			return nil, fmt.Errorf("HASH MISMATCH for %s: downloaded sha256 %s but %s says %s", a.Name, got, src, want)
		}
	}
	// the claims must also agree with each other (covered transitively: each equals got)

	// ---- extract list ----
	wantFiles := tc.Extract
	if len(wantFiles) == 0 {
		wantFiles = kc.Extract
	}
	if len(wantFiles) == 0 {
		return nil, errors.New("no extract list (set extract: on the kernel or the target)")
	}
	base := archiveBase(a.Name)
	var ex []manifest.Extract
	for _, w := range wantFiles {
		from := strings.NewReplacer("{asset_base}", base, "{version}", kc.Version).Replace(w.From)
		mode := w.Mode
		if mode == "" {
			mode = "0755"
		}
		ex = append(ex, manifest.Extract{From: from, To: w.To, Mode: mode})
	}
	if err := hashMembers(dst, format, ex); err != nil {
		return nil, err
	}

	t := &manifest.Target{
		Variant: tc.Variant, Archive: format, ArchiveSHA256: got, ArchiveSize: n, Extract: ex,
	}
	for _, e := range ex {
		t.InstalledSize += e.Size
	}
	for _, mtpl := range o.Cfg.Mirrors {
		t.URLs = append(t.URLs, strings.NewReplacer("{name}", kc.Name, "{version}", kc.Version, "{asset}", a.Name).Replace(mtpl))
	}
	if !o.Cfg.NoUpstream {
		t.URLs = append(t.URLs, a.URL)
	}
	return t, nil
}

// archiveBase is the asset name without its archive suffix; {asset_base} is
// substituted with it and a raw gz stream's only member carries this name.
func archiveBase(name string) string {
	switch {
	case strings.HasSuffix(name, ".tar.gz"):
		return strings.TrimSuffix(name, ".tar.gz")
	case strings.HasSuffix(name, ".tgz"):
		return strings.TrimSuffix(name, ".tgz")
	case strings.HasSuffix(name, ".zip"):
		return strings.TrimSuffix(name, ".zip")
	case strings.HasSuffix(name, ".gz"):
		return strings.TrimSuffix(name, ".gz")
	}
	return name
}

// buildLocalTarget describes one build that already exists on this machine
// (release/build.sh writes dist/W1nCray-linux-<arch>.gz). Unlike a GitHub
// asset there is no upstream hash claim: the archive hash, the member size and
// the member sha256 are all computed from the file. The URLs still come from
// the mirrors template, because the manifest is what the agent downloads from.
func buildLocalTarget(o buildOptions, kc *KernelCfg, la LocalAssetCfg) (*manifest.Target, error) {
	fi, err := os.Stat(la.File)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", la.File)
	}
	format := la.Archive
	if format == "" {
		switch {
		case strings.HasSuffix(la.File, ".tar.gz"), strings.HasSuffix(la.File, ".tgz"):
			format = manifest.ArchiveTarGz
		case strings.HasSuffix(la.File, ".zip"):
			format = manifest.ArchiveZip
		case strings.HasSuffix(la.File, ".gz"):
			format = manifest.ArchiveGz
		default:
			return nil, fmt.Errorf("cannot infer archive type of %q", la.File)
		}
	}
	asset := filepath.Base(la.File)
	to := la.To
	if to == "" {
		to = kc.Run.Binary
	}
	if to == "" {
		return nil, errors.New("no installed name: set local.to or run.binary")
	}
	from := la.From
	if from == "" {
		if format != manifest.ArchiveGz {
			return nil, errors.New("a local tar.gz/zip build needs an explicit extract list (from)")
		}
		from = asset
	}
	mode := la.Mode
	if mode == "" {
		mode = "0755"
	}
	ex := []manifest.Extract{{From: from, To: to, Mode: mode}}
	if err := hashMembers(la.File, format, ex); err != nil {
		return nil, err
	}
	sum, n, err := hashLocalFile(la.File)
	if err != nil {
		return nil, err
	}
	t := &manifest.Target{
		Variant: la.Variant, Archive: format, ArchiveSHA256: sum, ArchiveSize: n, Extract: ex,
		InstalledSize: ex[0].Size,
	}
	for _, mtpl := range o.Cfg.Mirrors {
		t.URLs = append(t.URLs, strings.NewReplacer("{name}", kc.Name, "{version}", kc.Version, "{asset}", asset).Replace(mtpl))
	}
	if len(t.URLs) == 0 {
		return nil, fmt.Errorf("a local build has no upstream URL: list at least one mirror for %s@%s", kc.Name, kc.Version)
	}
	return t, nil
}

// hashLocalFile returns the hex sha256 and size of a file on disk.
func hashLocalFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// hashMembers fills SHA256 and Size of each wanted member by reading the
// archive. Members must be regular files; a missing or duplicated member is
// an error.
func hashMembers(archivePath, format string, ex []manifest.Extract) error {
	idx := map[string]int{}
	for i, e := range ex {
		if !manifest.SafeArchivePath(e.From) {
			return fmt.Errorf("extract from %q is unsafe", e.From)
		}
		idx[path.Clean(strings.TrimPrefix(e.From, "./"))] = i
	}
	seen := map[string]bool{}
	record := func(name string, r io.Reader, isReg bool) error {
		member := path.Clean(strings.TrimPrefix(name, "./"))
		i, ok := idx[member]
		if !ok {
			return nil
		}
		if !isReg {
			return fmt.Errorf("member %q is not a regular file", name)
		}
		if seen[member] {
			return fmt.Errorf("member %q appears twice", name)
		}
		h := sha256.New()
		n, err := io.Copy(h, r)
		if err != nil {
			return err
		}
		ex[i].SHA256, ex[i].Size = hex.EncodeToString(h.Sum(nil)), n
		seen[member] = true
		return nil
	}
	switch format {
	case manifest.ArchiveTarGz:
		f, err := os.Open(archivePath)
		if err != nil {
			return err
		}
		defer f.Close()
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gz.Close()
		tr := tar.NewReader(gz)
		for {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return err
			}
			if err := record(hdr.Name, tr, hdr.Typeflag == tar.TypeReg || hdr.Typeflag == tar.TypeRegA); err != nil {
				return err
			}
		}
	case manifest.ArchiveZip:
		zr, err := zip.OpenReader(archivePath)
		if err != nil {
			return err
		}
		defer zr.Close()
		for _, zf := range zr.File {
			rc, err := zf.Open()
			if err != nil {
				return err
			}
			err = record(zf.Name, rc, zf.Mode().IsRegular())
			rc.Close()
			if err != nil {
				return err
			}
		}
	case manifest.ArchiveGz:
		// A raw gzip stream has exactly one member and no name: the manifest
		// entry's "from" is the archive's base name, so it must be a plain
		// file name.
		if len(ex) != 1 {
			return fmt.Errorf("a gz archive must list exactly one extract entry, got %d", len(ex))
		}
		if from := ex[0].From; from != path.Base(from) {
			return fmt.Errorf("gz extract.from %q must be a plain file name", from)
		}
		f, err := os.Open(archivePath)
		if err != nil {
			return err
		}
		defer f.Close()
		gz, err := gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("not a gzip stream: %w", err)
		}
		defer gz.Close()
		if err := record(ex[0].From, gz, true); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported archive %q", format)
	}
	for member := range idx {
		if !seen[member] {
			return fmt.Errorf("member %q not found in %s", member, filepath.Base(archivePath))
		}
	}
	return nil
}
