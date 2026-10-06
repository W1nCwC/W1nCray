package panel

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/ws"
)

// pathRecorder is a loopback stand-in for the panel that records the request
// paths it was asked for and answers the legacy node API.
type pathRecorder struct {
	srv      *httptest.Server
	nodePort int

	mu    sync.Mutex
	paths map[string]int
}

func newPathRecorder(t *testing.T, nodePort int) *pathRecorder {
	t.Helper()
	p := &pathRecorder{nodePort: nodePort, paths: map[string]int{}}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.paths[r.URL.Path]++
		p.mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/config"):
			fmt.Fprintf(w, `{"protocol":"vmess","server_port":%d,"network":"tcp","tls":0,"routes":[],"base_config":{"push_interval":60,"pull_interval":60}}`, p.nodePort)
		case strings.HasSuffix(r.URL.Path, "/user"):
			io.WriteString(w, `{"users":[{"id":1,"uuid":"7f6fd2d2-9a3d-4a8e-9f5b-1c2d3e4f5a6b"}]}`)
		default:
			io.WriteString(w, `{"data":true}`)
		}
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *pathRecorder) count(path string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.paths[path]
}

func (p *pathRecorder) anyPathSuffix(suffix string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for path := range p.paths {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestLegacyNodeModeNeverOpensTheAgentWebSocket is the compatibility guard of
// the task: a machine in the legacy node mode (static Nodes, no agent panel
// link) must behave exactly as before, i.e. never open /w1ncray-ws.
func TestLegacyNodeModeNeverOpensTheAgentWebSocket(t *testing.T) {
	nodePort := freePort(t)
	rec := newPathRecorder(t, nodePort)

	path := filepath.Join(t.TempDir(), "config.yml")
	body := fmt.Sprintf(`
Log: {Level: warning}
Nodes:
  - PanelType: Xboard
    ApiConfig: {ApiHost: "%s", ApiKey: k, NodeID: 1}
    ControllerConfig: {ListenIP: 127.0.0.1}
`, rec.srv.URL)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Agent != nil {
		t.Fatalf("the fixture must not configure an agent: %+v", cfg.Agent)
	}

	p := New(path, cfg)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	// The node is running and talking to the panel; only then is "no socket"
	// a meaningful statement.
	waitUntil(t, "the node's first config fetch", func() bool { return rec.anyPathSuffix("/config") })
	time.Sleep(300 * time.Millisecond)
	if n := rec.count(ws.WSPath); n != 0 {
		t.Fatalf("the legacy node mode opened %d agent WebSocket(s)", n)
	}
}

// TestPanelLinkOpensTheAgentWebSocket is the other half: a usable machine mode
// (panel enabled, machine id and token) does open the channel. The upgrade is
// refused by the fake panel (it answers 200, not 101), which is exactly the
// retry path; the point is that the agent asked.
func TestPanelLinkOpensTheAgentWebSocket(t *testing.T) {
	rec := newPathRecorder(t, freePort(t))
	dir := t.TempDir()
	path := writeAgentConfig(t, dir, fmt.Sprintf(`    Enabled: true
    URL: %s
    MachineID: 7
    Token: t
`, rec.srv.URL))

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	p := New(path, cfg)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	waitUntil(t, "the agent WebSocket request", func() bool { return rec.count(ws.WSPath) >= 1 })
}
