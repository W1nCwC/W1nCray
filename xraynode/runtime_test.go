package xraynode

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// runtimeBody is a runtime profile as the panel serves it (handoff 44).
func runtimeBody(version, outboundTag string) string {
	return fmt.Sprintf(`{"version":%q,`+
		`"outbounds":[{"tag":%q,"protocol":"freedom","settings":{"domainStrategy":"UseIPv4v6"}},{"tag":"blocked","protocol":"blackhole","settings":{}}],`+
		`"routing":{"domainStrategy":"AsIs","rules":[{"type":"field","domain":["domain:example.com","keyword:tracker"],"outboundTag":"blocked"}]},`+
		`"dns":null}`, version, outboundTag)
}

// brokenFiles writes a config whose route/outbound/dns files are invalid JSON:
// files mode cannot build from them, panel mode must not read them.
func brokenFiles(t *testing.T, dir string) string {
	t.Helper()
	bad := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("DnsConfigPath: %q\nRouteConfigPath: %q\nOutboundConfigPath: %q\nInboundConfigPath: %q\n", bad, bad, bad, bad)
}

func startMachine(t *testing.T, fp *machineFakePanel, extra string) *Service {
	t.Helper()
	dir := t.TempDir()
	if extra == "broken" {
		extra = brokenFiles(t, dir)
	}
	path := writeMachineConfig(t, dir, fp.srv.URL, extra)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	p := New(path, cfg)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func hasOutbound(p *Service, tag string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.core != nil && p.core.HasOutbound(tag)
}

func waitRuntime(t *testing.T, p *Service, mode, version string, msg string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		st := p.Status()
		if st.Runtime == mode && st.RuntimeVersion == version && st.Running {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: runtime=%q version=%q running=%v, want %q %q", msg, st.Runtime, st.RuntimeVersion, st.Running, mode, version)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// A panel that predates the profile answers 404: the kernel stays in files
// mode, exactly as before, and still announces that it could do more.
func TestMachineRuntimeOldPanelKeepsFiles(t *testing.T) {
	port := freePort(t)
	fp := newMachineFakePanel(t)
	fp.ports = map[int]int{1: port}
	fp.setNodes([]map[string]any{machineNodeJSON(1, "a", 1)}, "v1")

	p := startMachine(t, fp, "")
	if n := len(panelNodes(t, p)); n != 1 {
		t.Fatalf("%d controllers, want 1", n)
	}
	waitRuntime(t, p, "files", "", "old panel")
	if !hasOutbound(p, "direct") {
		t.Fatal("files mode lost the default direct outbound")
	}
	fp.mu.Lock()
	hdr := fp.runtimeHeader
	fp.mu.Unlock()
	if hdr != "1" {
		t.Fatalf("node list request carried X-W1nCray-Runtime=%q", hdr)
	}
	waitDial(t, fmt.Sprintf("127.0.0.1:%d", port), true, 15*time.Second, "node listens")
}

// Panel mode builds from the profile and never touches the four files: they
// are invalid JSON here, so reading any of them would fail the start.
func TestMachineRuntimePanelModeIgnoresFiles(t *testing.T) {
	port := freePort(t)
	fp := newMachineFakePanel(t)
	fp.ports = map[int]int{1: port}
	fp.setNodes([]map[string]any{machineNodeJSON(1, "a", 1)}, "v1")
	fp.setRuntime(http.StatusOK, runtimeBody("r1", "direct4"))

	p := startMachine(t, fp, "broken")
	waitRuntime(t, p, "panel", "r1", "panel mode")
	if !hasOutbound(p, "direct4") || !hasOutbound(p, "blocked") {
		t.Fatal("profile outbounds missing")
	}
	if hasOutbound(p, "direct") {
		t.Fatal("the default direct outbound must not be added when the profile has outbounds")
	}
	waitDial(t, fmt.Sprintf("127.0.0.1:%d", port), true, 15*time.Second, "node listens in panel mode")
}

// 204 is "profile off": files mode, and with broken files the start fails —
// the proof that the files really are read in that mode.
func TestMachineRuntimeOffReadsFiles(t *testing.T) {
	fp := newMachineFakePanel(t)
	fp.ports = map[int]int{1: freePort(t)}
	fp.setNodes([]map[string]any{machineNodeJSON(1, "a", 1)}, "v1")
	fp.setRuntime(http.StatusNoContent, "")

	dir := t.TempDir()
	path := writeMachineConfig(t, dir, fp.srv.URL, brokenFiles(t, dir))
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	p := New(path, cfg)
	err = p.Start()
	if err == nil {
		p.Close()
		t.Fatal("start succeeded although files mode had invalid files")
	}
}

// The first fetch fails and nothing is cached: the mode is unknown, so the
// machine nodes are not started (no fallback to files) and discovery is
// retried; once the panel answers, the nodes come up in panel mode.
func TestMachineRuntimeFirstFetchFailsThenRecovers(t *testing.T) {
	old := machineRetryDelay
	machineRetryDelay = 200 * time.Millisecond
	t.Cleanup(func() { machineRetryDelay = old })

	port := freePort(t)
	fp := newMachineFakePanel(t)
	fp.ports = map[int]int{1: port}
	fp.setNodes([]map[string]any{machineNodeJSON(1, "a", 1)}, "v1")
	fp.setRuntime(http.StatusBadGateway, `{"error":"upstream"}`)

	p := startMachine(t, fp, "broken")
	if n := len(panelNodes(t, p)); n != 0 {
		t.Fatalf("%d machine controllers started with an unknown runtime mode", n)
	}
	fp.setRuntime(http.StatusOK, runtimeBody("r1", "direct4"))
	waitNodes(t, p, 1, "nodes after the profile became reachable")
	waitRuntime(t, p, "panel", "r1", "recovered")
	waitDial(t, fmt.Sprintf("127.0.0.1:%d", port), true, 15*time.Second, "node listens after recovery")
}

// A profile Xray refuses never replaces the working one: the rebuild keeps the
// previous profile, the status names the refusal, and the refused version does
// not cause further rebuilds. A corrected profile is then picked up.
func TestMachineRuntimeRefusedProfileKeepsWorkingOne(t *testing.T) {
	oldPoll, oldWindow := machinePollInterval, machineDebounceWindow
	machinePollInterval, machineDebounceWindow = 100*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { machinePollInterval, machineDebounceWindow = oldPoll, oldWindow })

	port := freePort(t)
	fp := newMachineFakePanel(t)
	fp.ports = map[int]int{1: port}
	fp.setNodes([]map[string]any{machineNodeJSON(1, "a", 1)}, "v1")
	fp.setRuntime(http.StatusOK, runtimeBody("r1", "direct4"))
	p := startMachine(t, fp, "broken")
	waitRuntime(t, p, "panel", "r1", "initial")

	// r2: an outbound protocol Xray does not know.
	fp.setRuntime(http.StatusOK, `{"version":"r2","outbounds":[{"tag":"x","protocol":"no-such-protocol"}],"routing":{"rules":[]},"dns":null}`)
	fp.setNodes([]map[string]any{machineNodeJSON(1, "a", 1)}, "v2") // the panel folds r2 into the version
	deadline := time.Now().Add(20 * time.Second)
	for p.Status().RuntimeError == "" {
		if time.Now().After(deadline) {
			t.Fatal("refused profile not reported")
		}
		time.Sleep(50 * time.Millisecond)
	}
	st := p.Status()
	if st.RuntimeVersion != "r1" || !hasOutbound(p, "direct4") {
		t.Fatalf("refused profile replaced the working one: %+v", st)
	}
	if !strings.Contains(st.RuntimeError, "r2 refused by xray") {
		t.Fatalf("runtime error = %q", st.RuntimeError)
	}
	waitDial(t, fmt.Sprintf("127.0.0.1:%d", port), true, 15*time.Second, "node keeps listening on the working profile")
	reloads := p.lastReloadAt.Load()
	time.Sleep(600 * time.Millisecond) // several retry polls
	if p.lastReloadAt.Load() != reloads {
		t.Fatal("the refused profile kept triggering rebuilds")
	}

	fp.setRuntime(http.StatusOK, runtimeBody("r3", "direct6"))
	waitRuntime(t, p, "panel", "r3", "corrected profile")
	if p.Status().RuntimeError != "" {
		t.Fatalf("error not cleared: %q", p.Status().RuntimeError)
	}
}

// A rebuild while the profile endpoint fails keeps the profile in use (never
// the files); when the endpoint answers again with a new profile, the kernel
// rebuilds from it.
func TestMachineRuntimeStaleKeepsModeThenUpdates(t *testing.T) {
	oldPoll, oldWindow := machinePollInterval, machineDebounceWindow
	machinePollInterval, machineDebounceWindow = 100*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { machinePollInterval, machineDebounceWindow = oldPoll, oldWindow })

	fp := newMachineFakePanel(t)
	fp.ports = map[int]int{1: freePort(t), 2: freePort(t)}
	fp.setNodes([]map[string]any{machineNodeJSON(1, "a", 1)}, "v1")
	fp.setRuntime(http.StatusOK, runtimeBody("r1", "direct4"))

	p := startMachine(t, fp, "broken")
	waitRuntime(t, p, "panel", "r1", "initial")

	// The profile endpoint breaks, then the node list changes: the rebuild
	// must keep r1 (the broken files would fail it otherwise).
	fp.setRuntime(http.StatusInternalServerError, `{}`)
	fp.setNodes([]map[string]any{machineNodeJSON(1, "a", 1), machineNodeJSON(2, "b", 2)}, "v2")
	waitNodes(t, p, 2, "rebuild with a stale profile")
	waitRuntime(t, p, "panel", "r1", "stale profile kept")
	if !hasOutbound(p, "direct4") {
		t.Fatal("stale rebuild lost the profile outbounds")
	}

	// The endpoint answers again with a new profile: the retry rebuilds.
	fp.setRuntime(http.StatusOK, runtimeBody("r2", "direct6"))
	waitRuntime(t, p, "panel", "r2", "profile updated after recovery")
	if !hasOutbound(p, "direct6") || hasOutbound(p, "direct4") {
		t.Fatal("rebuild did not switch to the new profile")
	}
}

// 204 is an explicit "no profile": a machine that never had one keeps files
// mode, and the fallback is reported instead of being silent.
func TestMachineRuntimeNoProfileReportsFilesFallback(t *testing.T) {
	port := freePort(t)
	fp := newMachineFakePanel(t)
	fp.ports = map[int]int{1: port}
	fp.setNodes([]map[string]any{machineNodeJSON(1, "a", 1)}, "v1")
	fp.setRuntime(http.StatusNoContent, "")

	p := startMachine(t, fp, "")
	waitRuntime(t, p, "files", "", "no profile")
	if err := p.Status().RuntimeError; !strings.Contains(err, "降级读本机文件") {
		t.Fatalf("RuntimeError = %q, want the degraded fallback", err)
	}
	if !hasOutbound(p, "direct") {
		t.Fatal("files mode lost its default direct outbound")
	}
	waitDial(t, fmt.Sprintf("127.0.0.1:%d", port), true, 15*time.Second, "node listens on files")
}

// A profile that was in use is never dropped to files because the panel now
// answers 204: the last profile is kept and retried as stale.
func TestMachineRuntimeNoProfileAfterUseKeepsProfile(t *testing.T) {
	oldPoll, oldWindow := machinePollInterval, machineDebounceWindow
	machinePollInterval, machineDebounceWindow = 100*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { machinePollInterval, machineDebounceWindow = oldPoll, oldWindow })

	fp := newMachineFakePanel(t)
	fp.ports = map[int]int{1: freePort(t), 2: freePort(t)}
	fp.setNodes([]map[string]any{machineNodeJSON(1, "a", 1)}, "v1")
	fp.setRuntime(http.StatusOK, runtimeBody("r1", "direct4"))

	p := startMachine(t, fp, "broken")
	waitRuntime(t, p, "panel", "r1", "initial")

	fp.setRuntime(http.StatusNoContent, "")
	fp.setNodes([]map[string]any{machineNodeJSON(1, "a", 1), machineNodeJSON(2, "b", 2)}, "v2")
	waitNodes(t, p, 2, "rebuild after the profile disappeared")
	waitRuntime(t, p, "panel", "r1", "profile kept after 204")
	if !hasOutbound(p, "direct4") {
		t.Fatal("204 dropped the profile that was in use")
	}
	if err := p.Status().RuntimeError; !strings.Contains(err, "保留上一版") {
		t.Fatalf("RuntimeError = %q, want the keep notice", err)
	}
}

// In panel mode the four files are not read, so changing one must not rebuild
// the core.
func TestMachineRuntimePanelModeIgnoresFileChanges(t *testing.T) {
	port := freePort(t)
	fp := newMachineFakePanel(t)
	fp.ports = map[int]int{1: port}
	fp.setNodes([]map[string]any{machineNodeJSON(1, "a", 1)}, "v1")
	fp.setRuntime(http.StatusOK, runtimeBody("r1", "direct4"))

	dir := t.TempDir()
	extra := brokenFiles(t, dir)
	path := writeMachineConfig(t, dir, fp.srv.URL, extra)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	p := New(path, cfg)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	waitRuntime(t, p, "panel", "r1", "panel mode")

	reloads := p.lastReloadAt.Load()
	if err := os.WriteFile(filepath.Join(dir, "broken.json"), []byte("{still not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3500 * time.Millisecond) // the watcher debounces for 2 s
	if got := p.lastReloadAt.Load(); got != reloads {
		t.Fatalf("a change of an unread file rebuilt the core in panel mode (%d -> %d)", reloads, got)
	}
	if st := p.Status(); !st.Running || st.Runtime != "panel" {
		t.Fatalf("status = running %v, runtime %q", st.Running, st.Runtime)
	}
}
