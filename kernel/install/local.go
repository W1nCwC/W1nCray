// This file adds the offline install path: a kernel build that is already on
// the machine, described by the operator instead of by the signed manifest. It
// is what `W1nCray xray install --file <file|.gz> --sha256 <hex>` uses, for
// install.sh and for machines whose panel or manifest is unreachable.
//
// Trust: the operator supplies the sha256 of the file, which pins the bytes
// exactly like a manifest's archive_sha256; the version self-check then runs
// the binary, and the on-disk result is produced by the same commit() as a
// manifest install. The kernel directory therefore has one format: list,
// upgrade, rollback and remove cannot tell the two apart.

package install

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/kernel"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
)

// maxLocalBinary bounds what one --file may expand to. The release assets are
// tens of MiB; the limit only stops a corrupt or hostile gzip stream from
// filling the disk, since the compressed size is already pinned by sha256.
const maxLocalBinary = 1 << 30

// LocalInstall describes one kernel build that is already on this machine.
type LocalInstall struct {
	// Name is the kernel name in the manifest ("xray").
	Name string
	// Archive is the path of the file: a raw gzip stream or the bare binary.
	Archive string
	// ArchiveSHA256 is the required hex sha256 of Archive, exactly as the
	// release SHA256SUMS lists it.
	ArchiveSHA256 string
	// To is the installed file name; empty means Run.Binary.
	To string
	// Run is the version self-check: Binary is the installed name (used when
	// To is empty), VersionCmd the arguments and VersionRegex the optional
	// extractor for the version.
	Run manifest.Run
	// Version, when set, must equal what the self-check reports.
	Version string
	// Target is the marker's target key; empty means the detected platform key.
	Target string
	// Variant is the marker's variant token ("" for a generic build).
	Variant string
}

// InstallLocal installs a kernel from a local file without network access and
// without a signed manifest. The file's sha256 must match li.ArchiveSHA256 and
// the binary's own `version` output decides the installed version.
func (in *Installer) InstallLocal(ctx context.Context, li LocalInstall) (driver.Installed, error) {
	in.mu.Lock()
	defer in.mu.Unlock()

	name := li.Name
	if err := validName(name); err != nil {
		return driver.Installed{}, err
	}
	if err := checkSHA256Flag(li.ArchiveSHA256); err != nil {
		return driver.Installed{}, err
	}
	bin := li.To
	if bin == "" {
		bin = li.Run.Binary
	}
	if bin == "" {
		return driver.Installed{}, kernel.Newf(kernel.ErrVerify, name, "", "no installed file name (set To or Run.Binary)")
	}
	if !manifest.SafeArchivePath(bin) || bin != path.Base(bin) || bin == ".installed.json" {
		return driver.Installed{}, kernel.Newf(kernel.ErrVerify, name, "", "invalid installed file name %q", bin)
	}
	if err := ctx.Err(); err != nil {
		return driver.Installed{}, err
	}

	want := strings.ToLower(strings.TrimSpace(li.ArchiveSHA256))
	sum, size, err := hashFile(li.Archive)
	if err != nil {
		return driver.Installed{}, err
	}
	if sum != want {
		return driver.Installed{}, kernel.Newf(kernel.ErrVerify, name, "",
			"archive sha256 %s does not match the expected %s", sum, want)
	}

	stage, err := in.newStage(name, "local")
	if err != nil {
		return driver.Installed{}, err
	}
	// The stage is renamed into the version directory by commit; on any error
	// this removes what is left of it.
	defer func() { _ = os.RemoveAll(stage) }()

	if err := ctx.Err(); err != nil {
		return driver.Installed{}, err
	}
	binPath := filepath.Join(stage, bin)
	if err := writeLocalBinary(li.Archive, binPath); err != nil {
		return driver.Installed{}, kernel.Wrap(kernel.ErrVerify, name, "", err, "unpacking %s", filepath.Base(li.Archive))
	}

	// The version self-check is what names the installation: the operator does
	// not have to know it, and a file that does not run on this machine is
	// refused before anything is switched in.
	check := in.cfg.Check
	if check == nil {
		check = DefaultCheck(li.Run)
	}
	got, err := check(binPath)
	if err != nil {
		return driver.Installed{}, kernel.Wrap(kernel.ErrCheck, name, "", err, "running version check")
	}
	version := manifest.NormalizeVersion(got)
	if li.Version != "" && version != manifest.NormalizeVersion(li.Version) {
		return driver.Installed{}, kernel.Newf(kernel.ErrCheck, name, version,
			"binary reports version %q, expected %q", got, li.Version)
	}
	if !reVersionDir.MatchString(version) {
		return driver.Installed{}, kernel.Newf(kernel.ErrCheck, name, version, "binary reports an unusable version %q", got)
	}

	binSum, binSize, err := hashFile(binPath)
	if err != nil {
		return driver.Installed{}, err
	}
	target := li.Target
	if target == "" {
		target = in.plat.Key()
	}
	k := &manifest.Kernel{
		Name: name, Version: version,
		Run: manifest.Run{Binary: bin, VersionCmd: li.Run.VersionCmd, VersionRegex: li.Run.VersionRegex},
	}
	t := &manifest.Target{
		Variant: li.Variant, Archive: manifest.ArchiveGz,
		ArchiveSHA256: sum, ArchiveSize: size,
		Extract: []manifest.Extract{{
			From: path.Base(li.Archive), To: bin, SHA256: binSum, Size: binSize, Mode: "0755",
		}},
		InstalledSize: binSize,
	}
	if err := in.commit(stage, k, target, t); err != nil {
		return driver.Installed{}, err
	}
	in.clearFailure(name, version)
	return in.installedOf(name, version, in.readMarker(name, version)), nil
}

// checkSHA256Flag refuses a missing or malformed --sha256 before any file is
// touched.
func checkSHA256Flag(s string) error {
	s = strings.TrimSpace(s)
	switch {
	case s == "":
		return kernel.Newf(kernel.ErrVerify, "", "", "--sha256 is required: pass the hex sha256 of the file")
	case len(s) != 64:
		return kernel.Newf(kernel.ErrVerify, "", "", "--sha256 must be 64 hex characters, got %d", len(s))
	}
	if _, err := hex.DecodeString(s); err != nil {
		return kernel.Newf(kernel.ErrVerify, "", "", "--sha256 is not hexadecimal: %v", err)
	}
	return nil
}

// writeLocalBinary copies src to dst (mode 0755), gunzipping it first when it
// is a gzip stream. Release assets are raw .gz streams, but a bare binary is
// accepted too, so an operator can point --file at either form.
func writeLocalBinary(src, dst string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	br := bufio.NewReader(f)
	var r io.Reader = br
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return fmt.Errorf("%s: %w", src, err)
		}
		defer gz.Close()
		r = gz
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		return err
	}
	n, err := io.Copy(out, io.LimitReader(r, maxLocalBinary+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > maxLocalBinary {
		err = fmt.Errorf("expands beyond %d bytes", int64(maxLocalBinary))
	}
	if err != nil {
		_ = os.Remove(dst)
		return err
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(dst, 0o755); err != nil {
			return err
		}
	}
	return nil
}
