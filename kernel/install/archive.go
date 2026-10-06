package install

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/W1nCwC/W1nCray/kernel"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
)

// This file exports the download/verify/extract/self-check pipeline for callers
// that need a verified binary outside the kernel tree. The only such caller is
// agent/selfupdate: it stages the agent's own next version next to the running
// executable instead of under <Dir>/kernels/<name>/<version>. Everything the
// kernel path enforces (manifest presence, expiry, revocation, min_agent,
// platform target, archive_sha256/archive_size, member size/sha256, the
// manifest's version self-check) is enforced here too, because both callers go
// through the same resolve/extract/selfCheck code.

// DownloadFor resolves name@version in the loaded manifest and downloads its
// archive into dir, verifying archive_sha256 and archive_size while streaming.
// It returns the manifest target and the path of the verified archive inside
// dir. dir is created when missing; nothing is written outside it.
func (in *Installer) DownloadFor(ctx context.Context, name, version, dir string) (manifest.Target, string, error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	k, key, t, err := in.resolve(name, version)
	if err != nil {
		return manifest.Target{}, "", err
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return manifest.Target{}, "", err
	}
	if err := os.MkdirAll(abs, privDir); err != nil {
		return manifest.Target{}, "", err
	}
	part := filepath.Join(abs, t.ArchiveSHA256+".part")
	if err := in.checkSpace(name, k.Version, key, t, part, true); err != nil {
		return manifest.Target{}, "", err
	}
	dctx, cancel := context.WithTimeout(ctx, in.cfg.Timeout)
	err = in.download(dctx, name, k.Version, t, part)
	cancel()
	if err != nil {
		return manifest.Target{}, "", err
	}
	// download() hashed the whole stream against t.ArchiveSHA256; the size is
	// checked again so a short read cannot slip through.
	fi, err := os.Stat(part)
	if err != nil {
		return manifest.Target{}, "", err
	}
	if fi.Size() != t.ArchiveSize {
		return manifest.Target{}, "", kernel.Newf(kernel.ErrVerify, name, k.Version,
			"archive is %d bytes, manifest says %d", fi.Size(), t.ArchiveSize)
	}
	final := filepath.Join(abs, t.ArchiveSHA256+".archive")
	if err := os.Rename(part, final); err != nil {
		return manifest.Target{}, "", err
	}
	in.logf("kernel %s@%s: staged archive %s", name, k.Version, final)
	return *t, final, nil
}

// VerifyArchiveFor verifies an already downloaded archive against the manifest
// entry for name@version, extracts the listed members into dest and runs the
// manifest's version self-check on the main binary. dest must exist (or is
// created) and must be empty: extraction refuses to overwrite a file. It
// returns the manifest target and the absolute path of the staged main binary.
//
// A manifest-level refusal (unknown version, revoked, min_agent, no target for
// this platform, expired manifest), an archive hash/size mismatch, a member
// size/sha256 mismatch and a binary that reports the wrong version all fail
// here, before the caller touches the running executable.
func (in *Installer) VerifyArchiveFor(ctx context.Context, name, version, archivePath, dest string) (manifest.Target, string, error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	k, key, t, err := in.resolve(name, version)
	if err != nil {
		return manifest.Target{}, "", err
	}
	if err := ctx.Err(); err != nil {
		return manifest.Target{}, "", err
	}
	sum, size, err := hashFile(archivePath)
	if err != nil {
		return manifest.Target{}, "", err
	}
	if sum != t.ArchiveSHA256 {
		e := kernel.Newf(kernel.ErrVerify, name, k.Version, "archive sha256 %s does not match manifest %s", sum, t.ArchiveSHA256)
		e.Target = key
		return manifest.Target{}, "", e
	}
	if size != t.ArchiveSize {
		e := kernel.Newf(kernel.ErrVerify, name, k.Version, "archive is %d bytes, manifest says %d", size, t.ArchiveSize)
		e.Target = key
		return manifest.Target{}, "", e
	}
	if err := os.MkdirAll(dest, dirMode); err != nil {
		return manifest.Target{}, "", err
	}
	if err := extractArchive(archivePath, t.Archive, t.Extract, dest, in.limitsFor(t.Extract), name, k.Version); err != nil {
		return manifest.Target{}, "", err
	}
	check := in.cfg.Check
	if check == nil {
		check = DefaultCheck(k.Run)
	}
	bin := filepath.Join(dest, k.Run.Binary)
	if err := in.selfCheck(check, bin, k); err != nil {
		return manifest.Target{}, "", err
	}
	if _, err := os.Stat(bin); err != nil {
		return manifest.Target{}, "", fmt.Errorf("install: the self-checked binary %s is missing: %w", k.Run.Binary, err)
	}
	return *t, bin, nil
}
