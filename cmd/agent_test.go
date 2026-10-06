package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// agent-apply must take the service's single-instance lock before it reads the
// config or touches the state directory.
func TestAgentApplyTakesTheInstanceLockFirst(t *testing.T) {
	orig := acquireLock
	t.Cleanup(func() { acquireLock = orig })

	var asked []string
	acquireLock = func(path string) (*instanceLock, error) {
		asked = append(asked, path)
		return nil, errors.New("已有 W1nCray 实例在使用 " + path + " 运行（PID 4242）")
	}

	// The config does not exist: if the lock were not taken first, the error
	// would be about reading the config instead.
	cfg := filepath.Join(t.TempDir(), "missing.yml")
	var out bytes.Buffer
	err := runAgentApply(cfg, filepath.Join(t.TempDir(), "desired.json"), &out)
	if err == nil {
		t.Fatal("agent-apply ran although the lock is held")
	}
	if len(asked) != 1 || asked[0] != cfg {
		t.Fatalf("lock requested for %v, want exactly the config path %q", asked, cfg)
	}
	for _, want := range []string{"PID 4242", "stop the service"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	if out.Len() != 0 {
		t.Errorf("nothing may be printed when the lock is refused, got %q", out.String())
	}
}

// With the lock free the command proceeds to the config; here it stops at the
// missing Agent section, which proves the lock was acquired and released
// around the real work.
func TestAgentApplyProceedsWhenTheLockIsFree(t *testing.T) {
	orig := acquireLock
	t.Cleanup(func() { acquireLock = orig })
	calls := 0
	acquireLock = func(path string) (*instanceLock, error) {
		calls++
		return &instanceLock{}, nil
	}

	cfg := filepath.Join(t.TempDir(), "config.yml")
	// Nodes configured, Agent absent: valid config, but nothing to apply with.
	if err := os.WriteFile(cfg, []byte("Nodes:\n  - ApiConfig: {ApiHost: \"https://p.example.com\", ApiKey: k, NodeID: 1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runAgentApply(cfg, "unused.json", &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "no enabled Agent section") {
		t.Fatalf("err = %v, want the missing Agent section", err)
	}
	if calls != 1 {
		t.Errorf("lock acquired %d times, want 1", calls)
	}
}
