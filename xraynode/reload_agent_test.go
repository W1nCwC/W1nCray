package xraynode

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// agentOnlyConfig is a config.yml with the agent enabled and no static nodes.
// The Agent block is only what makes the file valid without Nodes; xraynode no
// longer owns the agent lifecycle.
func agentOnlyConfig(stateDir string) string {
	return "Log: {Level: warning}\nAgent:\n  Enabled: true\n  StateDir: " + stateDir + "\n"
}

// TestReloadValidatesBeforeTouchingTheInstance covers ruling 2: a config.yml
// that does not load is refused, the running instance is kept, and the good
// case asks for a rebuild without shutting anything down in-process. The split
// renamed panel.ReloadForAgent to Service.Reload (it is the filesync.Reloader
// now); the agent restart it used to drive belongs to agentd.
func TestReloadValidatesBeforeTouchingTheInstance(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(configPath, []byte(agentOnlyConfig(filepath.Join(dir, "state-one"))), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	s := New(configPath, cfg)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// A broken config.yml: an error, and nothing is torn down.
	if err := os.WriteFile(configPath, []byte("Agent: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(context.Background(), "managed files applied"); err == nil {
		t.Fatal("a broken config.yml was accepted")
	} else if !strings.Contains(err.Error(), "reload refused") {
		t.Errorf("error = %v, want a refusal", err)
	}
	s.mu.Lock()
	running := s.running
	s.mu.Unlock()
	if !running {
		t.Fatal("the instance was shut down by a refused reload")
	}

	// A cancelled context never starts anything.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Reload(ctx, "managed files applied"); err == nil {
		t.Error("a cancelled context was accepted")
	}

	// The good case: the reload is requested and the running instance survives
	// the call itself.
	if err := os.WriteFile(configPath, []byte(agentOnlyConfig(filepath.Join(dir, "state-two"))), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(context.Background(), "managed files applied"); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	s.mu.Lock()
	running = s.running
	s.mu.Unlock()
	if !running {
		t.Error("Reload shut the instance down before returning")
	}

	// The rebuild picks the new configuration up, so the request really went
	// through the reload path.
	want := filepath.Join(dir, "state-two")
	deadline := time.Now().Add(30 * time.Second)
	for {
		s.mu.Lock()
		got := ""
		if s.cfg != nil && s.cfg.Agent != nil {
			got = s.cfg.Agent.StateDir
		}
		s.mu.Unlock()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the reload never applied the new config (state = %q, want %q)", got, want)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestReloadIsSerialisedWithTheWatcher: two reload requests in a row must not
// run two rebuilds at once. The second request is remembered and served after
// the first, so the final configuration is the last one written.
func TestReloadIsSerialisedWithTheWatcher(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(configPath, []byte(agentOnlyConfig(filepath.Join(dir, "s1"))), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	s := New(configPath, cfg)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := os.WriteFile(configPath, []byte(agentOnlyConfig(filepath.Join(dir, "s2"))), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(context.Background(), "managed files applied"); err != nil {
		t.Fatal(err)
	}
	// A second request while the first may still be running.
	if err := os.WriteFile(configPath, []byte(agentOnlyConfig(filepath.Join(dir, "s3"))), 0o600); err != nil {
		t.Fatal(err)
	}
	s.requestReload("a second reason")

	want := filepath.Join(dir, "s3")
	deadline := time.Now().Add(40 * time.Second)
	for {
		s.mu.Lock()
		got := ""
		if s.cfg != nil && s.cfg.Agent != nil {
			got = s.cfg.Agent.StateDir
		}
		s.mu.Unlock()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the second reload request was lost (state = %q, want %q)", got, want)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
