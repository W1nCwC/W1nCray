package install

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/W1nCwC/W1nCray/kernel"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
)

// limits bound what an archive may make us do. They exist for archives that
// already matched archive_sha256, as defence in depth against a mistaken or
// malicious manifest and against bugs in the hash step.
type limits struct {
	MaxEntries int   // archive members scanned
	MaxBytes   int64 // decompressed bytes read from a tar stream / declared by a zip
}

func (in *Installer) limitsFor(files []manifest.Extract) limits {
	var sum int64
	for _, f := range files {
		sum += f.Size
	}
	l := limits{MaxEntries: in.cfg.MaxEntries, MaxBytes: in.cfg.MaxExtractBytes}
	if l.MaxBytes == 0 {
		l.MaxBytes = 2*sum + 64<<20
	}
	return l
}

func verifyErr(name, version, format string, args ...any) error {
	return kernel.Newf(kernel.ErrVerify, name, version, format, args...)
}

// extractArchive writes only the listed files into dest (which must exist
// and be empty), taking the mode from the manifest and verifying size and
// sha256 of every file. Anything unexpected is kernel.ErrVerify.
func extractArchive(archivePath, format string, files []manifest.Extract, dest string, lim limits, name, version string) error {
	switch format {
	case manifest.ArchiveTarGz:
		return extractTarGz(archivePath, files, dest, lim, name, version)
	case manifest.ArchiveZip:
		return extractZip(archivePath, files, dest, lim, name, version)
	case manifest.ArchiveGz:
		return extractGz(archivePath, files, dest, lim, name, version)
	}
	return verifyErr(name, version, "unsupported archive format %q", format)
}

// wanted maps a normalised archive path to its extract entry.
func wanted(files []manifest.Extract) map[string]manifest.Extract {
	m := make(map[string]manifest.Extract, len(files))
	for _, f := range files {
		m[path.Clean(strings.TrimPrefix(f.From, "./"))] = f
	}
	return m
}

func cleanMember(n string) (string, bool) {
	if !manifest.SafeArchivePath(n) {
		return "", false
	}
	return path.Clean(strings.TrimPrefix(n, "./")), true
}

// countingReader enforces the decompressed-size budget.
type countingReader struct {
	r   io.Reader
	n   int64
	max int64
}

var errBudget = errors.New("decompressed size exceeds limit")

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.n > c.max {
		return n, errBudget
	}
	return n, err
}

func extractTarGz(archivePath string, files []manifest.Extract, dest string, lim limits, name, version string) error {
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
	tr := tar.NewReader(&countingReader{r: gz, max: lim.MaxBytes})

	want := wanted(files)
	done := map[string]bool{}
	for entries := 0; ; entries++ {
		if entries >= lim.MaxEntries {
			return verifyErr(name, version, "archive has more than %d entries", lim.MaxEntries)
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if errors.Is(err, errBudget) {
				return verifyErr(name, version, "archive expands beyond %d bytes (decompression bomb?)", lim.MaxBytes)
			}
			return verifyErr(name, version, "reading tar: %v", err)
		}
		member, ok := cleanMember(hdr.Name)
		if !ok {
			return verifyErr(name, version, "unsafe path %q in archive", hdr.Name)
		}
		ex, isWanted := want[member]
		switch hdr.Typeflag {
		case tar.TypeReg, tar.TypeRegA: //nolint:staticcheck // TypeRegA appears in old archives
			if !isWanted {
				continue
			}
		case tar.TypeDir:
			continue
		default:
			if isWanted {
				return verifyErr(name, version, "%q is not a regular file (type %q): links and special files are refused", hdr.Name, string(hdr.Typeflag))
			}
			continue
		}
		if done[member] {
			return verifyErr(name, version, "%q appears twice in archive", hdr.Name)
		}
		if hdr.Size != ex.Size {
			return verifyErr(name, version, "%q has size %d, manifest says %d", hdr.Name, hdr.Size, ex.Size)
		}
		if err := writeVerified(tr, ex, dest, name, version); err != nil {
			return err
		}
		done[member] = true
	}
	return allDone(want, done, name, version)
}

func extractZip(archivePath string, files []manifest.Extract, dest string, lim limits, name, version string) error {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		if errors.Is(err, zip.ErrInsecurePath) {
			return verifyErr(name, version, "archive contains an unsafe path")
		}
		return verifyErr(name, version, "not a zip file: %v", err)
	}
	defer zr.Close()
	if len(zr.File) > lim.MaxEntries {
		return verifyErr(name, version, "archive has %d entries (limit %d)", len(zr.File), lim.MaxEntries)
	}
	var declared uint64
	for _, zf := range zr.File {
		declared += zf.UncompressedSize64
		if declared > uint64(lim.MaxBytes) || declared < zf.UncompressedSize64 {
			return verifyErr(name, version, "archive declares more than %d uncompressed bytes (decompression bomb?)", lim.MaxBytes)
		}
	}
	want := wanted(files)
	done := map[string]bool{}
	for _, zf := range zr.File {
		member, ok := cleanMember(zf.Name)
		if !ok {
			return verifyErr(name, version, "unsafe path %q in archive", zf.Name)
		}
		ex, isWanted := want[member]
		if !isWanted {
			continue
		}
		if !zf.Mode().IsRegular() {
			return verifyErr(name, version, "%q is not a regular file: links and special files are refused", zf.Name)
		}
		if done[member] {
			return verifyErr(name, version, "%q appears twice in archive", zf.Name)
		}
		if zf.UncompressedSize64 != uint64(ex.Size) {
			return verifyErr(name, version, "%q has size %d, manifest says %d", zf.Name, zf.UncompressedSize64, ex.Size)
		}
		rc, err := zf.Open()
		if err != nil {
			return verifyErr(name, version, "opening %q: %v", zf.Name, err)
		}
		err = writeVerified(rc, ex, dest, name, version)
		rc.Close()
		if err != nil {
			return err
		}
		done[member] = true
	}
	return allDone(want, done, name, version)
}

// extractGz writes the single file of a raw gzip stream. The stream carries no
// member name, so the manifest's one extract entry names it (its "from" is the
// archive's base name) and writeVerified applies the same size and sha256
// checks as for tar.gz/zip members.
func extractGz(archivePath string, files []manifest.Extract, dest string, lim limits, name, version string) error {
	if len(files) != 1 {
		return verifyErr(name, version, "a gz archive must list exactly one extract entry, got %d", len(files))
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
	return writeVerified(&countingReader{r: gz, max: lim.MaxBytes}, files[0], dest, name, version)
}

func allDone(want map[string]manifest.Extract, done map[string]bool, name, version string) error {
	for m := range want {
		if !done[m] {
			return verifyErr(name, version, "%q listed in manifest but missing from archive", m)
		}
	}
	return nil
}

// writeVerified copies exactly ex.Size bytes from r into dest/ex.To with the
// manifest's mode, hashing on the way, and fails if size or sha256 differ.
// ex.To is a validated plain file name, so it cannot leave dest.
func writeVerified(r io.Reader, ex manifest.Extract, dest, name, version string) error {
	mode, err := manifest.ParseMode(ex.Mode)
	if err != nil {
		return verifyErr(name, version, "%v", err)
	}
	target := filepath.Join(dest, ex.To)
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(mode))
	if err != nil {
		return err
	}
	// A member that fails its size or hash check must not be left behind: the
	// caller may be staging an executable (agent/selfupdate), and a partial
	// file in the staging directory must never look like a finished one.
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(target)
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(r, ex.Size+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return verifyErr(name, version, "extracting %q: %v", ex.To, err)
	}
	if n != ex.Size {
		return verifyErr(name, version, "%q: extracted %d bytes, manifest says %d", ex.To, n, ex.Size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != ex.SHA256 {
		return verifyErr(name, version, "%q: sha256 %s does not match manifest %s", ex.To, got, ex.SHA256)
	}
	if runtime.GOOS != "windows" {
		// Re-apply: the creation mode is filtered by the umask.
		if err := os.Chmod(target, os.FileMode(mode)); err != nil {
			return err
		}
	}
	keep = true
	return nil
}

// hashFile returns the hex sha256 and size of a file.
func hashFile(p string) (string, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), n, nil
}
