//go:build e2e

package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/reconcile"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
	"github.com/W1nCwC/W1nCray/kernel/platform"
)

// TestAgentGostEndToEnd boots the whole agent against a real gost binary and a
// self-signed manifest. It needs W1NCRAY_TEST_AGENT_GOST_BIN; without it the
// test is skipped.
//
// The kernel is pre-seeded in the installer's on-disk layout so Ensure takes
// its fast path (marker matches the manifest target): no network, no archive,
// no version self-check. This exercises the agent assembly, not the installer
// (which has its own tests).
func TestAgentGostEndToEnd(t *testing.T) {
	bin := os.Getenv("W1NCRAY_TEST_AGENT_GOST_BIN")
	if bin == "" {
		t.Skip("W1NCRAY_TEST_AGENT_GOST_BIN is not set")
	}
	abs, err := filepath.Abs(bin)
	if err != nil {
		t.Fatal(err)
	}
	binBytes, err := os.ReadFile(abs)
	if err != nil {
		t.Fatalf("read gost binary: %v", err)
	}
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	binName := "gost" + ext
	const version = "3.3.0"

	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	kernelsDir := filepath.Join(dir, "kernels")
	manifestPath := filepath.Join(dir, "manifest.json")
	keysPath := filepath.Join(dir, "keys.txt")
	desiredPath := filepath.Join(dir, "desired.json")

	plat := platform.Detect()
	now := time.Now()

	// ---- build and sign the manifest ----
	binSum := sha256.Sum256(binBytes)
	archSum := sha256.Sum256([]byte("w1ncray-e2e-archive"))
	m := &manifest.Manifest{
		Schema: manifest.SchemaVersion, Sequence: 1,
		IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(24 * time.Hour),
		Kernels: []manifest.Kernel{{
			Name: "gost", Version: version,
			License: manifest.License{SPDX: "MIT"},
			Run:     manifest.Run{Binary: binName, VersionCmd: []string{"-V"}},
			Targets: map[string]*manifest.Target{
				plat.Key(): {
					URLs: []string{"https://example.invalid/gost.tar.gz"}, Archive: manifest.ArchiveTarGz,
					ArchiveSHA256: hex.EncodeToString(archSum[:]), ArchiveSize: 10,
					Extract:       []manifest.Extract{{From: binName, To: binName, SHA256: hex.EncodeToString(binSum[:]), Size: int64(len(binBytes)), Mode: "0755"}},
					InstalledSize: 3,
				},
			},
		}},
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := manifest.Sign(m, priv)
	if err != nil {
		t.Fatalf("sign manifest: %v", err)
	}
	if err := os.WriteFile(manifestPath, signed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keysPath, []byte(hex.EncodeToString(pub)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// ---- pre-seed the installed kernel ----
	root := filepath.Join(kernelsDir, "kernels") // install.New appends "kernels"
	verDir := filepath.Join(root, "gost", version)
	if err := os.MkdirAll(verDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(verDir, binName), binBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	marker := map[string]any{
		"name": "gost", "version": version, "target": plat.Key(), "binary": binName,
		"archive_sha256": hex.EncodeToString(archSum[:]),
		"installed_at":   now.UTC().Format(time.RFC3339Nano),
		"files":          []map[string]any{{"to": binName, "size": len(binBytes), "mode": "0755"}},
	}
	mb, _ := json.MarshalIndent(marker, "", "  ")
	if err := os.WriteFile(filepath.Join(verDir, ".installed.json"), mb, 0o600); err != nil {
		t.Fatal(err)
	}

	// ---- boot the agent ----
	rt, err := Boot(Options{
		StateDir:         stateDir,
		KernelsDir:       kernelsDir,
		ManifestPath:     manifestPath,
		ManifestKeysPath: keysPath,
	})
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	if ok, why := rt.Kernels.Available("gost"); !ok {
		t.Fatalf("gost must be available: %s", why)
	}

	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	writeDesired(t, desiredPath, fmt.Sprintf(`{"id":"fwd1","enabled":true,"engine":"gost","kind":"forward","listen":{"addr":"127.0.0.1","ports":"%d"},"targets":[{"host":"1.1.1.1","ports":"80"}]}`, port))

	rep, err := rt.ApplyFile(desiredPath)
	if err != nil {
		t.Fatalf("ApplyFile: %v (report %+v)", err, rep)
	}
	if rep.Status != reconcile.StatusApplied {
		t.Fatalf("status = %s, want applied (%s)", rep.Status, rep.Message)
	}
	waitDial(t, addr, true, 20*time.Second, "gost listen port reachable")

	// ---- remove the instance: the port must close ----
	writeDesired(t, desiredPath, "")
	rep2, err := rt.ApplyFile(desiredPath)
	if err != nil {
		t.Fatalf("second ApplyFile: %v (report %+v)", err, rep2)
	}
	if rep2.Status != reconcile.StatusApplied {
		t.Fatalf("second status = %s, want applied (%s)", rep2.Status, rep2.Message)
	}
	waitDial(t, addr, false, 20*time.Second, "gost listen port closed after removal")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := rt.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func waitDial(t *testing.T, addr string, wantOpen bool, timeout time.Duration, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		open := err == nil
		if open {
			c.Close()
		}
		if open == wantOpen {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s (open=%v)", what, open)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
