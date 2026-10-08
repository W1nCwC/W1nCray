package agentd

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/bootstrap"
)

// waitAgent waits until the daemon's agent satisfies ok. The old helper watched
// panel.Panel; agentd only owns the agent half now, so it watches d.mu/d.agent.
func waitAgent(t *testing.T, d *Daemon, ok func(rt *bootstrap.Runtime) bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		d.mu.Lock()
		rt := d.agent
		d.mu.Unlock()
		if ok(rt) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the agent never reached the expected state")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestAgentYMLChangeRestartsOnlyTheAgent: editing agent.yml restarts the agent;
// disabling the agent stops it; re-enabling it starts a new Runtime. There is no
// in-process Xray core in agentd any more (the Xray instance is the separate
// W1nCray-xray program), so the old assertions about p.core / a rebuilt core
// belong to xraynode and are gone: only the agent lifecycle is asserted.
func TestAgentYMLChangeRestartsOnlyTheAgent(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yml")
	agentYML := filepath.Join(dir, "agent.yml")
	stateDir := filepath.Join(dir, "state")

	// config.yml carries no Agent block: agent.yml is the effective source, so
	// editing it is exactly what the watcher reacts to. The agentd loader is
	// agent-only, so no Nodes entry is needed to keep a disabled agent valid.
	if err := os.WriteFile(configPath, []byte("Log: {Level: warning}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeAgentYML := func(enabled bool, extra string) {
		t.Helper()
		text := fmt.Sprintf("Enabled: %v\nStateDir: %q\n%s", enabled, stateDir, extra)
		if err := os.WriteFile(agentYML, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeAgentYML(true, "")

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	d := New(configPath, cfg, Options{})
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	d.mu.Lock()
	rt1 := d.agent
	d.mu.Unlock()
	if rt1 == nil {
		t.Fatal("agent is not running, want it running")
	}

	// 1. A change of the agent configuration restarts the agent.
	writeAgentYML(true, "Terminal: {Enabled: false}\n")
	waitAgent(t, d, func(rt *bootstrap.Runtime) bool { return rt != nil && rt != rt1 })

	// 2. Disabling the agent stops it.
	writeAgentYML(false, "")
	waitAgent(t, d, func(rt *bootstrap.Runtime) bool { return rt == nil })

	// 3. Re-enabling it starts a new Runtime.
	writeAgentYML(true, "")
	waitAgent(t, d, func(rt *bootstrap.Runtime) bool { return rt != nil && rt != rt1 })
}

// TestUnchangedWatchedFilesDoNotRebuild: the watcher fires on every write of a
// watched file. Rewriting identical config.yml / agent.yml content must not
// restart the agent (the daemon compares the resolved agent configuration), a
// real agent.yml change still must. There is no Xray core to observe, so the
// agent Runtime is the subject.
func TestUnchangedWatchedFilesDoNotRebuild(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yml")
	agentYML := filepath.Join(dir, "agent.yml")
	stateDir := filepath.Join(dir, "state")

	configBody := "Log: {Level: warning}\n"
	agentBody := fmt.Sprintf("Enabled: true\nStateDir: %q\n", stateDir)
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(agentYML, []byte(agentBody), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	d := New(configPath, cfg, Options{})
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	d.mu.Lock()
	rt1 := d.agent
	d.mu.Unlock()
	if rt1 == nil {
		t.Fatal("the agent did not start")
	}

	// Same bytes in both watched files: the watcher fires, nothing restarts.
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(agentYML, []byte(agentBody), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second) // longer than the watcher debounce
	d.mu.Lock()
	same := d.agent == rt1
	d.mu.Unlock()
	if !same {
		t.Fatal("identical content restarted the agent")
	}

	// Different agent.yml bytes: the agent is restarted.
	if err := os.WriteFile(agentYML, []byte(agentBody+"Terminal: {Enabled: false}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitAgent(t, d, func(rt *bootstrap.Runtime) bool { return rt != nil && rt != rt1 })
}
