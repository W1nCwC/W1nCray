package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/kernel/manifest"
)

// bootSignedManifest builds and signs a minimal valid manifest with seq.
func bootSignedManifest(t *testing.T, seq int64, priv ed25519.PrivateKey) []byte {
	t.Helper()
	arch := sha256.Sum256([]byte("archive"))
	bin := sha256.Sum256([]byte("binary"))
	now := time.Now()
	m := &manifest.Manifest{
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
	}
	raw, err := manifest.Sign(m, priv)
	if err != nil {
		t.Fatalf("sign manifest: %v", err)
	}
	return raw
}

// bootWithPersistedManifest boots a runtime whose state directory already holds
// raw as manifest.json, and no explicit Agent.ManifestPath.
func bootWithPersistedManifest(t *testing.T, raw []byte, log *recLog) *Runtime {
	t.Helper()
	useFake(t, newFakeDriver())
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	keysPath := filepath.Join(dir, "keys.txt")
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keysPath, []byte(hex.EncodeToString(pub)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(PersistedManifestPath(stateDir), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	rt, err := Boot(Options{
		StateDir:         stateDir,
		KernelsDir:       filepath.Join(dir, "kernels"),
		ManifestKeysPath: keysPath,
		Log:              log,
	}, nil)
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	t.Cleanup(func() { _ = rt.Shutdown(context.Background()) })
	return rt
}

func TestBootRestoresPersistedManifest(t *testing.T) {
	// The key the agent trusts; bootWithPersistedManifest writes its public
	// half, so this test needs its own layout.
	useFake(t, newFakeDriver())
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	keysPath := filepath.Join(dir, "keys.txt")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keysPath, []byte(hex.EncodeToString(pub)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(PersistedManifestPath(stateDir), bootSignedManifest(t, 4, priv), 0o600); err != nil {
		t.Fatal(err)
	}

	rt, err := Boot(Options{
		StateDir:         stateDir,
		KernelsDir:       filepath.Join(dir, "kernels"),
		ManifestKeysPath: keysPath,
	}, nil)
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	t.Cleanup(func() { _ = rt.Shutdown(context.Background()) })

	seq, ok := rt.Kernels.ManifestSequence()
	if !ok || seq != 4 {
		t.Fatalf("restored sequence = %d (ok=%v), want 4", seq, ok)
	}
}

func TestBootIgnoresRejectedPersistedManifest(t *testing.T) {
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"untrusted signature": bootSignedManifest(t, 4, other),
		"garbage":             []byte("this is not a manifest"),
	} {
		t.Run(name, func(t *testing.T) {
			log := &recLog{}
			rt := bootWithPersistedManifest(t, raw, log)
			if _, ok := rt.Kernels.ManifestSequence(); ok {
				t.Error("a rejected persisted manifest must not be in force")
			}
			if !strings.Contains(log.warnText(), "rejected") {
				t.Errorf("the rejection was not warned about: %s", log.warnText())
			}
		})
	}
}

func TestPersistedManifestPath(t *testing.T) {
	if got := PersistedManifestPath(""); got != "" {
		t.Errorf("empty state dir = %q", got)
	}
	if got := PersistedManifestPath("/srv/w1n"); got != filepath.Join("/srv/w1n", ManifestFileName) {
		t.Errorf("path = %q", got)
	}
}
