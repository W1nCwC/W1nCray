package xraynode

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/core"
	"github.com/W1nCwC/W1nCray/node"
)

// waitCoreChanged waits until the service runs a core different from old.
func waitCoreChanged(t *testing.T, s *Service, old *core.Core) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		s.mu.Lock()
		c := s.core
		s.mu.Unlock()
		if c != nil && c != old {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the xray core was not rebuilt")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestXrayRebuildReplacesCoreAndNodes is the xraynode half of the old
// single-process decoupling test: a rebuild swaps s.core and s.nodes and the
// node controllers of the previous instance are closed. Each controller's
// Close removes its rules from the core it was running on, so an empty rule
// list on the old core is the direct observable of "the old set was closed".
// (The old file also asserted that the agent and the panel link survived the
// rebuild; that coupling is gone with the split and the agentd package now
// owns those tests.)
func TestXrayRebuildReplacesCoreAndNodes(t *testing.T) {
	port1, port2 := freePort(t), freePort(t)
	fp := newMachineFakePanel(t)
	fp.staticPort = port1

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	write := func(level string) {
		t.Helper()
		body := fmt.Sprintf(`Log: {Level: %s}
Nodes:
  - PanelType: Xboard
    ApiConfig: {ApiHost: %q, ApiKey: k, NodeID: 1}
    ControllerConfig: {ListenIP: 127.0.0.1}
`, level, fp.srv.URL)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("warning")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	s := New(path, cfg)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.mu.Lock()
	oldCore, oldNodes := s.core, append([]*node.Controller(nil), s.nodes...)
	s.mu.Unlock()
	if oldCore == nil || len(oldNodes) != 1 {
		t.Fatalf("core=%v nodes=%d, want a running instance with one node", oldCore != nil, len(oldNodes))
	}
	// The node's rules (at least the fallback rule of its inbound tag) were
	// applied to the first core.
	if n := len(oldCore.Rules.Rules()); n == 0 {
		t.Fatal("the node controller never applied its rules to the first core")
	}

	// An xray-file change rebuilds the instance; the panel hands the node a new
	// port so the new controller is distinguishable from the old one.
	fp.staticPort = port2
	write("info")
	s.requestReload("test: node port changed")
	waitCoreChanged(t, s, oldCore)

	s.mu.Lock()
	newCore, newNodes := s.core, append([]*node.Controller(nil), s.nodes...)
	s.mu.Unlock()
	if newCore == nil || newCore == oldCore {
		t.Fatalf("core was not replaced (new=%v old=%v)", newCore != nil, oldCore)
	}
	if len(newNodes) != 1 || newNodes[0] == oldNodes[0] {
		t.Fatalf("nodes were not replaced: %d controller(s), same pointer=%v", len(newNodes), len(newNodes) == 1 && newNodes[0] == oldNodes[0])
	}
	if got := len(oldCore.Rules.Rules()); got != 0 {
		t.Fatalf("the old node controllers were not closed: %d rule(s) left on the old core", got)
	}
	waitDial(t, fmt.Sprintf("127.0.0.1:%d", port2), true, 15*time.Second, "the rebuilt node listens on its new port")
}

// TestUnchangedWatchedFilesDoNotRebuild: a managed-file write asks for the
// rebuild itself and the watcher then sees the same write. Rewriting identical
// content must not rebuild xray a second time (the fingerprint is unchanged); a
// real change still must. The agent half of the old test is gone: xraynode only
// rebuilds the xray instance.
func TestUnchangedWatchedFilesDoNotRebuild(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yml")
	agent := fmt.Sprintf("Agent:\n  Enabled: true\n  StateDir: %q\n", filepath.Join(dir, "state"))
	body := "Log: {Level: warning}\n" + agent
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
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
	s.mu.Lock()
	core1 := s.core
	s.mu.Unlock()
	fp1 := s.Fingerprint()

	// Same bytes: the watcher fires, the fingerprint is unchanged and nothing
	// is rebuilt.
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second) // longer than the watcher debounce
	s.mu.Lock()
	same := s.core == core1
	s.mu.Unlock()
	if !same {
		t.Fatal("identical content rebuilt xray")
	}
	if got := s.Fingerprint(); got != fp1 {
		t.Fatalf("the fingerprint changed without a rebuild: %q -> %q", fp1, got)
	}

	// Different bytes: rebuilt, and the fingerprint follows the new content.
	// The fingerprint is published just after the core swap (applyReload's
	// defer), so poll for both instead of reading it once.
	if err := os.WriteFile(configPath, []byte("Log: {Level: info}\n"+agent), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		s.mu.Lock()
		rebuilt := s.core != core1
		s.mu.Unlock()
		if rebuilt && s.Fingerprint() != fp1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("a real content change did not rebuild xray and update the fingerprint")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
