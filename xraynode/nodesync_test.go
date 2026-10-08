package xraynode

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/xrayapi"
)

// callNodesSync sends one request to the kernel's /nodes/sync route over the
// platform's transport (a Unix socket, or the loopback address on Windows) and
// returns the response and its body.
func callNodesSync(t *testing.T, srv *StatusServer, method string) (*http.Response, []byte) {
	t.Helper()
	network := "unix"
	if runtime.GOOS == "windows" {
		network = "tcp"
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, srv.addr)
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	req, err := http.NewRequest(method, "http://xray"+NodesSyncPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, NodesSyncPath, err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read %s body: %v", NodesSyncPath, err)
	}
	return resp, body
}

// nodesSync sends one GET and decodes the answer, failing the test on anything
// but 200.
func nodesSync(t *testing.T, srv *StatusServer) xrayapi.NodesSyncResult {
	t.Helper()
	resp, body := callNodesSync(t, srv, http.MethodGet)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d, body %s", NodesSyncPath, resp.StatusCode, body)
	}
	var res xrayapi.NodesSyncResult
	if err := json.Unmarshal(body, &res); err != nil {
		t.Fatalf("decode %s (%s): %v", NodesSyncPath, body, err)
	}
	return res
}

// startMachineService starts a machine-mode service against fp and serves the
// local endpoint next to its config. The machine poll interval is pushed out of
// the way, so only the route under test can pick a change up.
func startMachineService(t *testing.T, fp *machineFakePanel) (*Service, *StatusServer) {
	t.Helper()
	old := machinePollInterval
	machinePollInterval = time.Hour
	t.Cleanup(func() { machinePollInterval = old })

	t.Setenv(xrayapi.RuntimeDirEnv, t.TempDir())
	dir := t.TempDir()
	path := writeMachineConfig(t, dir, fp.srv.URL, "")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	p := New(path, cfg)
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(p.Close)
	srv, err := NewStatusServer(p, dir)
	if err != nil {
		t.Fatalf("NewStatusServer: %v", err)
	}
	t.Cleanup(srv.Close)
	return p, srv
}

// TestNodesSyncRouteReloadsOnAChangedVersion: the agent's hint makes the kernel
// re-fetch the machine's node list immediately; a changed version triggers the
// same reload the 60 s watcher would have requested, so the newly bound node
// runs without waiting for the poll.
func TestNodesSyncRouteReloadsOnAChangedVersion(t *testing.T) {
	port1, port2 := freePort(t), freePort(t)
	fp := newMachineFakePanel(t)
	fp.ports = map[int]int{1: port1, 2: port2}
	fp.setNodes([]map[string]any{machineNodeJSON(1, "a", 1)}, "v1")
	p, srv := startMachineService(t, fp)
	waitNodes(t, p, 1, "initial discovery")
	before := panelNodes(t, p)[0]

	// The panel binds a second node; the poll cannot pick it up in this test.
	fp.setNodes([]map[string]any{machineNodeJSON(1, "a", 1), machineNodeJSON(2, "b", 2)}, "v2")

	res := nodesSync(t, srv)
	if !res.Changed {
		t.Fatalf("changed = false, want true (version %q)", res.Version)
	}
	if res.Version != "v2" {
		t.Errorf("version = %q, want v2", res.Version)
	}
	waitNodes(t, p, 2, "after the nodes hint")
	if got := panelNodes(t, p)[0]; got == before {
		t.Error("the instance was not rebuilt: the controller is the same pointer")
	}
	waitDial(t, fmt.Sprintf("127.0.0.1:%d", port2), true, 15*time.Second, "the bound node listens after the hint")
}

// TestNodesSyncRouteIsIdleWhenTheVersionIsUnchanged: an idle hint (the list did
// not change) is answered changed=false and must not rebuild the instance.
func TestNodesSyncRouteIsIdleWhenTheVersionIsUnchanged(t *testing.T) {
	port := freePort(t)
	fp := newMachineFakePanel(t)
	fp.ports = map[int]int{1: port}
	fp.setNodes([]map[string]any{machineNodeJSON(1, "a", 1)}, "v1")
	p, srv := startMachineService(t, fp)
	waitNodes(t, p, 1, "initial discovery")
	before := panelNodes(t, p)[0]
	lastReload := p.lastReloadAt.Load()
	hits := fp.hits()

	for i := 0; i < 2; i++ {
		res := nodesSync(t, srv)
		if res.Changed {
			t.Fatalf("hint %d reported a change for an unchanged list", i)
		}
		if res.Version != "v1" {
			t.Errorf("hint %d version = %q, want v1", i, res.Version)
		}
	}
	// The route really asked the panel (it is not a no-op)...
	if got := fp.hits(); got <= hits {
		t.Errorf("the panel was not asked again (%d -> %d requests)", hits, got)
	}
	// ...and the idle answer rebuilt nothing.
	time.Sleep(300 * time.Millisecond)
	if got := panelNodes(t, p)[0]; got != before {
		t.Error("an idle hint rebuilt the instance")
	}
	if got := p.lastReloadAt.Load(); got != lastReload {
		t.Errorf("an idle hint reloaded the instance (last_reload_at %d -> %d)", lastReload, got)
	}
}

// TestNodesSyncRouteConcurrentHints: hints may arrive together (a panel retry,
// a burst of bindings). They are serialised, exactly one reports the change, and
// the instance ends up with the new list.
func TestNodesSyncRouteConcurrentHints(t *testing.T) {
	port1, port2 := freePort(t), freePort(t)
	fp := newMachineFakePanel(t)
	fp.ports = map[int]int{1: port1, 2: port2}
	fp.setNodes([]map[string]any{machineNodeJSON(1, "a", 1)}, "v1")
	p, srv := startMachineService(t, fp)
	waitNodes(t, p, 1, "initial discovery")

	fp.setNodes([]map[string]any{machineNodeJSON(1, "a", 1), machineNodeJSON(2, "b", 2)}, "v2")

	const n = 8
	results := make([]xrayapi.NodesSyncResult, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, body := callNodesSync(t, srv, http.MethodGet)
			if resp.StatusCode != http.StatusOK {
				errs[i] = fmt.Errorf("status %d: %s", resp.StatusCode, body)
				return
			}
			errs[i] = json.Unmarshal(body, &results[i])
		}(i)
	}
	wg.Wait()

	changed := 0
	for i := range results {
		if errs[i] != nil {
			t.Fatalf("concurrent hint %d: %v", i, errs[i])
		}
		if results[i].Changed {
			changed++
		}
	}
	if changed != 1 {
		t.Errorf("%d of %d concurrent hints reported the change, want exactly 1", changed, n)
	}
	waitNodes(t, p, 2, "after the concurrent hints")
}

// TestNodesSyncRouteWithoutMachineMode: a configuration without machine mode has
// no node list to refresh. The hint is answered changed=false instead of an
// error, and nothing is reloaded.
func TestNodesSyncRouteWithoutMachineMode(t *testing.T) {
	t.Setenv(xrayapi.RuntimeDirEnv, t.TempDir())
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(configPath, []byte("Log: {Level: warning}\nAgent:\n  Enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	p := New(configPath, cfg)
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()
	srv, err := NewStatusServer(p, dir)
	if err != nil {
		t.Fatalf("NewStatusServer: %v", err)
	}
	defer srv.Close()

	res := nodesSync(t, srv)
	if res.Changed {
		t.Error("changed = true without machine mode")
	}
	if res.Version != "" {
		t.Errorf("version = %q, want empty", res.Version)
	}
	time.Sleep(200 * time.Millisecond)
	if got := p.lastReloadAt.Load(); got != 0 {
		t.Errorf("last_reload_at = %d, want 0", got)
	}
}

// TestNodesSyncRouteRejectsOtherMethods: the route triggers a reload, so it
// stays a read-only GET with no payload; anything else is refused.
func TestNodesSyncRouteRejectsOtherMethods(t *testing.T) {
	fp := newMachineFakePanel(t)
	fp.setNodes([]map[string]any{machineNodeJSON(1, "a", 1)}, "v1")
	_, srv := startMachineService(t, fp)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		resp, body := callNodesSync(t, srv, method)
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: status %d, want %d", method, NodesSyncPath, resp.StatusCode, http.StatusMethodNotAllowed)
		}
		if strings.TrimSpace(string(body)) == "" {
			t.Errorf("%s %s: empty body", method, NodesSyncPath)
		}
	}
}
