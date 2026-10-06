//go:build linux || darwin || freebsd || openbsd || netbsd

package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// With the real flock: while the service (here: this process) holds the lock
// of a config, agent-apply refuses to run and names the holder.
func TestAgentApplyRefusesWhileTheServiceHoldsTheLock(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfg, []byte("Agent:\n  Enabled: true\n  StateDir: "+filepath.Join(dir, "state")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	service, err := acquireInstanceLock(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = runAgentApply(cfg, filepath.Join(dir, "desired.json"), &out)
	if err == nil {
		t.Fatal("agent-apply ran while the service holds the lock")
	}
	if !strings.Contains(err.Error(), "已有 W1nCray 实例") || !strings.Contains(err.Error(), "PID "+strconv.Itoa(os.Getpid())) {
		t.Errorf("unhelpful error: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "state")); statErr == nil {
		t.Error("the state directory was touched although the lock was refused")
	}

	// After the service is gone the lock is free again, and agent-apply gets
	// past it (it then fails on the missing desired file, which is fine).
	service.release()
	err = runAgentApply(cfg, filepath.Join(dir, "desired.json"), &out)
	if err == nil || strings.Contains(err.Error(), "已有 W1nCray 实例") {
		t.Fatalf("err = %v, want a failure after the lock", err)
	}
	// And agent-apply released its own lock on the way out.
	l, err := acquireInstanceLock(cfg)
	if err != nil {
		t.Fatalf("agent-apply left the lock held: %v", err)
	}
	l.release()
}
