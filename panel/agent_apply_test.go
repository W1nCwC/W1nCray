package panel

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestAgentNoNodesConfigIsValid is the D-F regression: a config with no Nodes
// is accepted when the agent is enabled.
func TestAgentNoNodesConfigIsValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	os.WriteFile(path, []byte(`
Log: {Level: warning}
Agent:
  Enabled: true
  DesiredPath: desired.json
`), 0o600)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("empty Nodes with Agent.Enabled must load: %v", err)
	}
	if cfg.Agent == nil || !cfg.Agent.Enabled {
		t.Fatal("agent section not parsed")
	}
	// Path defaults resolve relative to the config file.
	if cfg.Agent.StateDir != filepath.Join(dir, "state") {
		t.Errorf("StateDir = %q, want %q", cfg.Agent.StateDir, filepath.Join(dir, "state"))
	}
	if cfg.Agent.KernelsDir != filepath.Join(dir, "state", "kernels") {
		t.Errorf("KernelsDir = %q, want %q", cfg.Agent.KernelsDir, filepath.Join(dir, "state", "kernels"))
	}
}

// TestAgentDesiredFileHotReload drives the panel's agent end to end with the
// builtin xray engine (no external kernel needed): the DesiredPath file is
// applied at start-up and re-applied when it changes.
func TestAgentDesiredFileHotReload(t *testing.T) {
	port := freePort(t)
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yml")
	desiredPath := filepath.Join(dir, "desired.json")

	writeConfig := func() {
		os.WriteFile(configPath, []byte(fmt.Sprintf(`
Log: {Level: warning}
Agent:
  Enabled: true
  StateDir: %q
  DesiredPath: %q
`, filepath.Join(dir, "state"), desiredPath)), 0o600)
	}
	writeDesired := func(instances string) {
		body := fmt.Sprintf(`{"version":1,"revision":1,"instances":[%s]}`, instances)
		if err := os.WriteFile(desiredPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	writeConfig()
	// Write the desired state before Start so the initial apply is exercised.
	writeDesired(fmt.Sprintf(`{"id":"fwd1","enabled":true,"engine":"xray","kind":"forward","listen":{"addr":"127.0.0.1","ports":"%d"},"targets":[{"host":"1.1.1.1","ports":"80"}]}`, port))

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	p := New(configPath, cfg)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	waitDial(t, addr, true, 15*time.Second, "port open after initial apply")

	// Change the desired state: the instance is removed. The watcher must apply
	// it and close the port.
	writeDesired("")
	waitDial(t, addr, false, 20*time.Second, "port closed after removal")
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
