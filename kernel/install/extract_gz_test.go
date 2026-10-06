package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/W1nCwC/W1nCray/kernel"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
)

// gzFiles is the single-member extract list of a raw gzip target.
func gzFiles(data []byte, sha string, size int64) []manifest.Extract {
	return []manifest.Extract{{From: "W1nCray-linux-amd64", To: "W1nCray", SHA256: sha, Size: size, Mode: "0755"}}
}

func gzLimits(n int64) limits { return limits{MaxEntries: 64, MaxBytes: n + 1<<20} }

func writeArchive(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "archive.gz")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestExtractGzWritesTheSingleMember is the happy path of acceptance item 3.
func TestExtractGzWritesTheSingleMember(t *testing.T) {
	data := fakeBin("1.0.0", 128)
	archive := mkGz(t, data)
	dest := t.TempDir()
	files := gzFiles(data, sum(data), int64(len(data)))
	if err := extractArchive(writeArchive(t, archive), manifest.ArchiveGz, files, dest, gzLimits(int64(len(data))), "agent", "1.0.0"); err != nil {
		t.Fatalf("extractArchive: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "W1nCray"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(data) {
		t.Fatalf("extracted %d bytes, want %d", len(got), len(data))
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(filepath.Join(dest, "W1nCray"))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o755 {
			t.Errorf("mode = %v, want 0755", fi.Mode().Perm())
		}
	}
}

// TestExtractGzRefusesNonGzip covers the first refusal of acceptance item 3.
func TestExtractGzRefusesNonGzip(t *testing.T) {
	data := []byte("#!/bin/sh\necho hi\n")
	dest := t.TempDir()
	files := gzFiles(data, sum(data), int64(len(data)))
	err := extractArchive(writeArchive(t, []byte("this is not gzip at all")), manifest.ArchiveGz, files, dest, gzLimits(int64(len(data))), "agent", "1.0.0")
	if !errors.Is(err, kernel.ErrVerify) {
		t.Fatalf("err = %v, want ErrVerify", err)
	}
	if _, statErr := os.Stat(filepath.Join(dest, "W1nCray")); !errors.Is(statErr, os.ErrNotExist) {
		t.Error("a refused archive must not leave a file behind")
	}
}

// TestExtractGzRefusesSizeMismatch covers the second refusal of acceptance
// item 3: the decompressed size must match the manifest exactly.
func TestExtractGzRefusesSizeMismatch(t *testing.T) {
	data := fakeBin("1.0.0", 64)
	for _, size := range []int64{int64(len(data)) - 1, int64(len(data)) + 1} {
		dest := t.TempDir()
		files := gzFiles(data, sum(data), size)
		err := extractArchive(writeArchive(t, mkGz(t, data)), manifest.ArchiveGz, files, dest, gzLimits(int64(len(data))), "agent", "1.0.0")
		if !errors.Is(err, kernel.ErrVerify) {
			t.Fatalf("size %d: err = %v, want ErrVerify", size, err)
		}
		if _, statErr := os.Stat(filepath.Join(dest, "W1nCray")); !errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("size %d: a refused archive must not leave a file behind", size)
		}
	}
}

// TestExtractGzRefusesSHA256Mismatch covers the third refusal of acceptance
// item 3.
func TestExtractGzRefusesSHA256Mismatch(t *testing.T) {
	data := fakeBin("1.0.0", 64)
	dest := t.TempDir()
	files := gzFiles(data, sum([]byte("something else")), int64(len(data)))
	err := extractArchive(writeArchive(t, mkGz(t, data)), manifest.ArchiveGz, files, dest, gzLimits(int64(len(data))), "agent", "1.0.0")
	if !errors.Is(err, kernel.ErrVerify) {
		t.Fatalf("err = %v, want ErrVerify", err)
	}
	if _, statErr := os.Stat(filepath.Join(dest, "W1nCray")); !errors.Is(statErr, os.ErrNotExist) {
		t.Error("a refused archive must not leave a file behind")
	}
}

// TestExtractGzRefusesDecompressionBomb covers the budget: a gzip stream that
// expands far beyond the declared size is stopped by the counting reader.
func TestExtractGzRefusesDecompressionBomb(t *testing.T) {
	data := make([]byte, 4<<20) // compresses to a few KiB
	dest := t.TempDir()
	files := gzFiles(data, sum(data), int64(len(data)))
	err := extractArchive(writeArchive(t, mkGz(t, data)), manifest.ArchiveGz, files, dest, limits{MaxEntries: 64, MaxBytes: 1024}, "agent", "1.0.0")
	if !errors.Is(err, kernel.ErrVerify) {
		t.Fatalf("err = %v, want ErrVerify", err)
	}
}

// TestExtractGzRefusesMultipleMembers covers the manifest rule at the
// extraction layer too: a raw gzip stream cannot satisfy two extract entries.
func TestExtractGzRefusesMultipleMembers(t *testing.T) {
	data := fakeBin("1.0.0", 8)
	files := append(gzFiles(data, sum(data), int64(len(data))),
		manifest.Extract{From: "extra", To: "extra", SHA256: sum(data), Size: int64(len(data)), Mode: "0644"})
	err := extractArchive(writeArchive(t, mkGz(t, data)), manifest.ArchiveGz, files, t.TempDir(), gzLimits(int64(len(data))), "agent", "1.0.0")
	if !errors.Is(err, kernel.ErrVerify) {
		t.Fatalf("err = %v, want ErrVerify", err)
	}
}

// ---- VerifyArchiveFor --------------------------------------------------------

func gzKern(data []byte) kern {
	return kern{
		Name: "agent", Version: "1.0.0", Format: manifest.ArchiveGz,
		Members: map[string][]byte{"W1nCray-linux-amd64": data},
		Extract: map[string]string{"W1nCray-linux-amd64": "gost"}, // run.binary of the fixture
	}
}

// TestVerifyArchiveForStagesAndSelfChecks covers the exported staging path the
// updater uses: verify the archive, extract the member, run the version check.
func TestVerifyArchiveForStagesAndSelfChecks(t *testing.T) {
	f := newFixture(t)
	data := fakeBin("1.0.0", 256)
	mk, archive := f.build(gzKern(data))
	in := f.installer(t.TempDir())
	if err := in.LoadManifest(f.sign(mk)); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "staged")
	tgt, _, err := in.VerifyArchiveFor(context.Background(), "agent", "1.0.0", writeArchive(t, archive), dest)
	if err != nil {
		t.Fatalf("VerifyArchiveFor: %v", err)
	}
	if tgt.Archive != manifest.ArchiveGz || len(tgt.Extract) != 1 {
		t.Fatalf("target = %+v", tgt)
	}
	got, err := os.ReadFile(filepath.Join(dest, "gost"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(data) {
		t.Error("the staged binary differs from the archive member")
	}
}

// TestVerifyArchiveForRefusesWrongArchiveAndVersion covers the two refusals
// that keep a bad binary out of the executable path.
func TestVerifyArchiveForRefusesWrongArchiveAndVersion(t *testing.T) {
	f := newFixture(t)
	data := fakeBin("1.0.0", 128)

	t.Run("archive sha256 mismatch", func(t *testing.T) {
		mk, archive := f.build(gzKern(data))
		in := f.installer(t.TempDir())
		if err := in.LoadManifest(f.sign(mk)); err != nil {
			t.Fatal(err)
		}
		tampered := append([]byte(nil), archive...)
		tampered[len(tampered)-1] ^= 0xff
		dest := filepath.Join(t.TempDir(), "staged")
		_, _, err := in.VerifyArchiveFor(context.Background(), "agent", "1.0.0", writeArchive(t, tampered), dest)
		if !errors.Is(err, kernel.ErrVerify) {
			t.Fatalf("err = %v, want ErrVerify", err)
		}
		if _, statErr := os.Stat(filepath.Join(dest, "gost")); !errors.Is(statErr, os.ErrNotExist) {
			t.Error("a refused archive must not be staged")
		}
	})

	t.Run("archive size mismatch", func(t *testing.T) {
		mk, archive := f.build(gzKern(data))
		mk.Targets[f.plat.Key()].ArchiveSize++ // sha still matches, size does not
		in := f.installer(t.TempDir())
		if err := in.LoadManifest(f.sign(mk)); err != nil {
			t.Fatal(err)
		}
		_, _, err := in.VerifyArchiveFor(context.Background(), "agent", "1.0.0", writeArchive(t, archive), filepath.Join(t.TempDir(), "staged"))
		if !errors.Is(err, kernel.ErrVerify) {
			t.Fatalf("err = %v, want ErrVerify", err)
		}
	})

	t.Run("self-check reports another version", func(t *testing.T) {
		mk, archive := f.build(gzKern(fakeBin("2.0.0", 128))) // manifest says 1.0.0
		in := f.installer(t.TempDir())
		if err := in.LoadManifest(f.sign(mk)); err != nil {
			t.Fatal(err)
		}
		dest := filepath.Join(t.TempDir(), "staged")
		_, _, err := in.VerifyArchiveFor(context.Background(), "agent", "1.0.0", writeArchive(t, archive), dest)
		if !errors.Is(err, kernel.ErrCheck) {
			t.Fatalf("err = %v, want ErrCheck", err)
		}
	})
}

// TestDownloadForVerifiesTheStreamedArchive covers the download half: the
// archive lands in the given directory only after archive_sha256 matched.
func TestDownloadForVerifiesTheStreamedArchive(t *testing.T) {
	f := newFixture(t)
	data := fakeBin("1.0.0", 512)
	mk, archive := f.build(gzKern(data))
	fs := newFileServer(t)
	url := fs.put("/agent.gz", archive)
	mk.Targets[f.plat.Key()].URLs = []string{url}

	in := f.installer(t.TempDir())
	if err := in.LoadManifest(f.sign(mk)); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "dl")
	tgt, path, err := in.DownloadFor(context.Background(), "agent", "1.0.0", dir)
	if err != nil {
		t.Fatalf("DownloadFor: %v", err)
	}
	if tgt.ArchiveSHA256 != sum(archive) {
		t.Errorf("target sha = %s", tgt.ArchiveSHA256)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if sum(got) != sum(archive) {
		t.Error("the downloaded archive differs")
	}
}
