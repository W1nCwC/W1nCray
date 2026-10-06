//go:build unix

package selfupdate

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestRespawnFallsBackToSetsid covers the non-systemd path: when systemd-run
// cannot be used, the watchdog is still started — detached in its own session,
// with an argv array and without blocking the caller.
func TestRespawnFallsBackToSetsid(t *testing.T) {
	oldLook := lookSystemdRun
	lookSystemdRun = func(string) (string, error) { return "", exec.ErrNotFound }
	t.Cleanup(func() { lookSystemdRun = oldLook })

	dir := t.TempDir()
	marker := filepath.Join(dir, "started")
	script := filepath.Join(dir, "watchdog")
	// A stand-in for the watchdog: it records that it ran and exits, so the
	// test does not leave a process behind.
	body := "#!/bin/sh\necho ok > " + marker + "\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	h := HelperOptions{
		ExePath: "/usr/bin/W1nCray", StateDir: dir, LockPath: filepath.Join(dir, "config.yml.lock"),
	}
	if err := respawn(script, h, nopLog{}); err != nil {
		t.Fatalf("respawn: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(marker); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the watchdog was never started")
}
