package panel

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// agentOnlyConfig is a config.yml with the agent enabled and no static nodes.
func agentOnlyConfig(stateDir string) string {
	return "Log: {Level: warning}\nAgent:\n  Enabled: true\n  StateDir: " + stateDir + "\n"
}

// TestReloadForAgentValidatesBeforeTouchingTheInstance covers ruling 2: a
// config.yml that does not load is refused, the running instance is kept, and
// the good case asks for a rebuild without shutting anything down in-process.
func TestReloadForAgentValidatesBeforeTouchingTheInstance(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(configPath, []byte(agentOnlyConfig(filepath.Join(dir, "state-one"))), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	p := New(configPath, cfg)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	// A broken config.yml: an error, and nothing is torn down.
	if err := os.WriteFile(configPath, []byte("Agent: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.ReloadForAgent(context.Background(), "managed files applied"); err == nil {
		t.Fatal("a broken config.yml was accepted")
	} else if !strings.Contains(err.Error(), "reload refused") {
		t.Errorf("error = %v, want a refusal", err)
	}
	p.mu.Lock()
	running := p.running
	p.mu.Unlock()
	if !running {
		t.Fatal("the instance was shut down by a refused reload")
	}

	// A cancelled context never starts anything.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.ReloadForAgent(ctx, "managed files applied"); err == nil {
		t.Error("a cancelled context was accepted")
	}

	// The good case: the reload is requested and the running instance survives
	// the call itself.
	if err := os.WriteFile(configPath, []byte(agentOnlyConfig(filepath.Join(dir, "state-two"))), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.ReloadForAgent(context.Background(), "managed files applied"); err != nil {
		t.Fatalf("ReloadForAgent: %v", err)
	}
	p.mu.Lock()
	running = p.running
	p.mu.Unlock()
	if !running {
		t.Error("ReloadForAgent shut the instance down before returning")
	}

	// The rebuild picks the new configuration up, so the request really went
	// through the reload path.
	want := filepath.Join(dir, "state-two")
	deadline := time.Now().Add(30 * time.Second)
	for {
		p.mu.Lock()
		got := ""
		if p.cfg != nil && p.cfg.Agent != nil {
			got = p.cfg.Agent.StateDir
		}
		p.mu.Unlock()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the reload never applied the new config (state = %q, want %q)", got, want)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestReloadForAgentIsSerialisedWithTheWatcher: two reload requests in a row
// must not run two rebuilds at once. The second request is remembered and
// served after the first, so the final configuration is the last one written.
func TestReloadForAgentIsSerialisedWithTheWatcher(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(configPath, []byte(agentOnlyConfig(filepath.Join(dir, "s1"))), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	p := New(configPath, cfg)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	if err := os.WriteFile(configPath, []byte(agentOnlyConfig(filepath.Join(dir, "s2"))), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.ReloadForAgent(context.Background(), "managed files applied"); err != nil {
		t.Fatal(err)
	}
	// A second request while the first may still be running.
	if err := os.WriteFile(configPath, []byte(agentOnlyConfig(filepath.Join(dir, "s3"))), 0o600); err != nil {
		t.Fatal(err)
	}
	p.requestReload("a second reason")

	want := filepath.Join(dir, "s3")
	deadline := time.Now().Add(40 * time.Second)
	for {
		p.mu.Lock()
		got := ""
		if p.cfg != nil && p.cfg.Agent != nil {
			got = p.cfg.Agent.StateDir
		}
		p.mu.Unlock()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the second reload request was lost (state = %q, want %q)", got, want)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
