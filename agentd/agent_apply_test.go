package agentd

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/spec"
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

// TestAgentDesiredFileHotReload drives the daemon's desired-state watcher: the
// DesiredPath file is handed to the agent runtime at start-up and re-applied
// when it changes.
//
// The old test drove the builtin xray engine and watched its listening port.
// agentd no longer links an Xray core (the Xray instance is the separate
// W1nCray-xray program) and the external engines need a signed manifest and an
// installed kernel, so the daemon's own contract is observed instead: the
// desired state the reconciler was last asked to apply. The apply itself (and
// the listening port) now belongs to the engine side, xraynode / bootstrap e2e.
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
	writeDesired := func(revision int, instances string) {
		body := fmt.Sprintf(`{"version":1,"revision":%d,"instances":[%s]}`, revision, instances)
		if err := os.WriteFile(desiredPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	writeConfig()
	// Write the desired state before Start so the initial apply is exercised.
	writeDesired(1, fmt.Sprintf(`{"id":"fwd1","enabled":true,"engine":"gost","kind":"forward","listen":{"addr":"127.0.0.1","ports":"%d"},"targets":[{"host":"1.1.1.1","ports":"80"}]}`, port))

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	d := New(configPath, cfg, Options{})
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	// The file was applied at start-up: the reconciler recorded revision 1 with
	// its instance.
	waitDesired(t, d, func(ds spec.Desired) bool { return ds.Revision == 1 && len(ds.Instances) == 1 })

	// Change the desired state: the instance is removed. The watcher must
	// re-apply it.
	writeDesired(2, "")
	waitDesired(t, d, func(ds spec.Desired) bool { return ds.Revision == 2 && len(ds.Instances) == 0 })
}

// waitDesired waits until the daemon's runtime has been asked to apply a
// desired state satisfying ok.
func waitDesired(t *testing.T, d *Daemon, ok func(spec.Desired) bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		d.mu.Lock()
		rt := d.agent
		d.mu.Unlock()
		if rt != nil && ok(rt.Reconciler.LastDesired()) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the daemon never applied the expected desired state")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
