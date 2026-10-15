package kernelx

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/kernel/install"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
	"github.com/W1nCwC/W1nCray/kernel/platform"
)

// kxManifest builds and signs a minimal valid manifest with seq.
func kxManifest(t *testing.T, seq int64, priv ed25519.PrivateKey) []byte {
	t.Helper()
	arch := sha256.Sum256([]byte("archive"))
	bin := sha256.Sum256([]byte("binary"))
	now := time.Now()
	raw, err := manifest.Sign(&manifest.Manifest{
		Schema: manifest.SchemaVersion, Sequence: seq,
		IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(24 * time.Hour),
		Kernels: []manifest.Kernel{{
			Name: "gost", Version: "3.3.0",
			License: manifest.License{SPDX: "MIT"},
			Run:     manifest.Run{Binary: "gost", VersionCmd: []string{"-V"}},
			Targets: map[string]*manifest.Target{
				"linux/amd64": {
					URLs: []string{"https://example.invalid/gost.tar.gz"}, Archive: manifest.ArchiveTarGz,
					ArchiveSHA256: hex.EncodeToString(arch[:]), ArchiveSize: 10,
					Extract:       []manifest.Extract{{From: "gost", To: "gost", SHA256: hex.EncodeToString(bin[:]), Size: 3, Mode: "0755"}},
					InstalledSize: 3,
				},
			},
		}},
	}, priv)
	if err != nil {
		t.Fatalf("sign manifest: %v", err)
	}
	return raw
}

func newKXEnsurer(t *testing.T) (*Ensurer, ed25519.PrivateKey) {
	t.Helper()
	dir := t.TempDir()
	keysPath := filepath.Join(dir, "keys.txt")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keysPath, []byte(hex.EncodeToString(pub)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := New(Options{Dir: filepath.Join(dir, "kernels"), KeysPath: keysPath})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e, priv
}

func TestEnsurerLoadManifestAndSequence(t *testing.T) {
	e, priv := newKXEnsurer(t)
	if _, ok := e.ManifestSequence(); ok {
		t.Fatal("a fresh Ensurer must have no manifest")
	}
	if err := e.LoadManifest(kxManifest(t, 7, priv)); err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if seq, ok := e.ManifestSequence(); !ok || seq != 7 {
		t.Fatalf("sequence = %d (ok=%v), want 7", seq, ok)
	}

	// A rollback is refused and the manifest in force survives.
	if err := e.LoadManifest(kxManifest(t, 6, priv)); err == nil {
		t.Error("a lower sequence was accepted")
	}
	if seq, _ := e.ManifestSequence(); seq != 7 {
		t.Errorf("sequence after the rollback = %d, want 7", seq)
	}

	// A signature the local keys do not vouch for is refused.
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.LoadManifest(kxManifest(t, 8, other)); err == nil {
		t.Error("a manifest signed by an untrusted key was accepted")
	}
	if seq, _ := e.ManifestSequence(); seq != 7 {
		t.Errorf("sequence after the bad signature = %d, want 7", seq)
	}
}

// TestEnsurerLoadManifestIsConcurrencySafe exercises the documented contract:
// the Ensurer delegates to install.Installer, which serialises its methods.
func TestEnsurerLoadManifestIsConcurrencySafe(t *testing.T) {
	e, priv := newKXEnsurer(t)
	raw := kxManifest(t, 7, priv)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = e.LoadManifest(raw)
			_, _ = e.ManifestSequence()
			_, _ = e.Available("gost")
		}()
	}
	wg.Wait()
	if seq, ok := e.ManifestSequence(); !ok || seq != 7 {
		t.Fatalf("sequence = %d (ok=%v), want 7", seq, ok)
	}
}

// --- the built-in W1nCray release table (A7-4) ------------------------------

// kxManifestFor builds and signs a minimal valid manifest holding one kernel.
func kxManifestFor(t *testing.T, seq int64, priv ed25519.PrivateKey, name, version string) []byte {
	t.Helper()
	arch := sha256.Sum256([]byte("archive-" + name + version))
	bin := sha256.Sum256([]byte("binary-" + name + version))
	now := time.Now()
	raw, err := manifest.Sign(&manifest.Manifest{
		Schema: manifest.SchemaVersion, Sequence: seq,
		IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(24 * time.Hour),
		Kernels: []manifest.Kernel{{
			Name: name, Version: version,
			License: manifest.License{SPDX: "MIT"},
			Run:     manifest.Run{Binary: name, VersionCmd: []string{"-V"}},
			Targets: map[string]*manifest.Target{
				"linux/amd64": {
					URLs: []string{"https://example.invalid/" + name + ".tar.gz"}, Archive: manifest.ArchiveTarGz,
					ArchiveSHA256: hex.EncodeToString(arch[:]), ArchiveSize: 10,
					Extract:       []manifest.Extract{{From: name, To: name, SHA256: hex.EncodeToString(bin[:]), Size: 3, Mode: "0755"}},
					InstalledSize: 3,
				},
			},
		}},
	}, priv)
	if err != nil {
		t.Fatalf("sign manifest: %v", err)
	}
	return raw
}

// kxEnsurerWith builds an Ensurer pinned to one platform.
func kxEnsurerWith(t *testing.T, plat platform.Info) (*Ensurer, ed25519.PrivateKey) {
	t.Helper()
	dir := t.TempDir()
	keysPath := filepath.Join(dir, "keys.txt")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keysPath, []byte(hex.EncodeToString(pub)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := New(Options{Dir: filepath.Join(dir, "kernels"), KeysPath: keysPath, Platform: &plat})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e, priv
}

// TestDefaultVersionUsesOwnKernelTable: kernelx asks the built-in table first,
// so a manifest listing a newer gost must not override our own mirror.
func TestDefaultVersionUsesOwnKernelTable(t *testing.T) {
	amd64 := platform.Info{GOOS: "linux", GOARCH: "amd64", Libc: "glibc"}
	e, priv := kxEnsurerWith(t, amd64)
	want, ok := install.OwnKernelLatest("gost", amd64)
	if !ok {
		t.Fatal("the built-in table has no gost build for linux/amd64")
	}
	if want != "3.3.0" {
		t.Fatalf("built-in gost version = %q, want 3.3.0", want)
	}
	got, err := e.defaultVersion("gost")
	if err != nil || got != want {
		t.Fatalf("defaultVersion(gost) without a manifest = %q (err %v), want %q", got, err, want)
	}

	// xray is not served by the table: without a manifest it still fails.
	if _, err := e.defaultVersion("xray"); err == nil {
		t.Fatal("defaultVersion(xray) without a manifest must fail")
	}

	// A manifest that lists only a newer gost must not win.
	if err := e.LoadManifest(kxManifestFor(t, 7, priv, "gost", "9.9.9")); err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	got, err = e.defaultVersion("gost")
	if err != nil || got != want {
		t.Fatalf("defaultVersion(gost) with a manifest = %q (err %v), want the table's %q", got, err, want)
	}
}

// TestDefaultVersionFallsBackOffTable: a platform the table does not cover
// keeps the manifest behaviour, with and without a manifest.
func TestDefaultVersionFallsBackOffTable(t *testing.T) {
	windows := platform.Info{GOOS: "windows", GOARCH: "amd64"}
	e, priv := kxEnsurerWith(t, windows)
	if _, ok := install.OwnKernelLatest("gost", windows); ok {
		t.Fatal("the built-in table must not hold a windows build")
	}
	if _, err := e.defaultVersion("gost"); err == nil {
		t.Fatal("defaultVersion(gost) without a manifest must fail on an uncovered platform")
	}
	if err := e.LoadManifest(kxManifestFor(t, 7, priv, "gost", "9.9.9")); err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	got, err := e.defaultVersion("gost")
	if err != nil || got != "9.9.9" {
		t.Fatalf("defaultVersion(gost) = %q (err %v), want the manifest's 9.9.9", got, err)
	}
}
