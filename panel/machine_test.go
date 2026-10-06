package panel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/node"
)

const machineToken = "panel-machine-token-0123456789"

// machineFakePanel is a fake panel that serves both the V1 UniProxy endpoints (for
// static nodes) and the V2 machine endpoints (header auth, node list).
type machineFakePanel struct {
	srv  *httptest.Server
	test *testing.T

	mu      sync.Mutex
	nodes   []map[string]any // the machine's node list
	version string
	// ports maps a machine node id to the port its config listens on.
	ports map[int]int
	// staticPort is the port of the V1 node (NodeID 1).
	staticPort int
	// denyNodes is how many upcoming /nodes requests are refused with 401.
	denyNodes int
	// nodesHits counts /nodes requests, configHits the V2 config requests.
	nodesHits  int
	configHits map[int]int
}

func newMachineFakePanel(t *testing.T) *machineFakePanel {
	m := &machineFakePanel{test: t, ports: map[int]int{}, configHits: map[int]int{}}
	m.srv = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.srv.Close)
	return m
}

// auth checks the machine credentials and fails the test if the token ever
// reached the URL.
func (m *machineFakePanel) auth(w http.ResponseWriter, r *http.Request) bool {
	if q := r.URL.Query(); q.Get("token") != "" {
		m.test.Errorf("machine request leaked the token into the query: %s?%s", r.URL.Path, r.URL.RawQuery)
	}
	if r.Header.Get("X-Machine-Id") == "9" && r.Header.Get("Authorization") == "Bearer "+machineToken {
		return true
	}
	w.WriteHeader(http.StatusUnauthorized)
	io.WriteString(w, `{"error":"bad_credentials"}`)
	return false
}

func (m *machineFakePanel) nodeConfig(w http.ResponseWriter, id int) {
	m.mu.Lock()
	port := m.ports[id]
	m.configHits[id]++
	m.mu.Unlock()
	fmt.Fprintf(w, `{"protocol":"vmess","server_port":%d,"network":"tcp","tls":0,"routes":[],"base_config":{"push_interval":60,"pull_interval":60}}`, port)
}

func (m *machineFakePanel) handle(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case p == "/api/v2/server/machine/agent/nodes":
		if !m.auth(w, r) {
			return
		}
		m.mu.Lock()
		deny := m.denyNodes
		if deny > 0 {
			m.denyNodes--
		}
		m.nodesHits++
		nodes, version := m.nodes, m.version
		m.mu.Unlock()
		if deny > 0 {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"error":"bad_credentials"}`)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"nodes": nodes, "version": version})
	case strings.HasPrefix(p, "/api/v2/server/machine/agent/node/"):
		if !m.auth(w, r) {
			return
		}
		name := strings.TrimPrefix(p, "/api/v2/server/machine/agent/node/")
		id, _ := strconv.Atoi(r.URL.Query().Get("node_id"))
		switch name {
		case "config":
			m.nodeConfig(w, id)
		case "user":
			io.WriteString(w, `{"users":[{"id":1,"uuid":"7f6fd2d2-9a3d-4a8e-9f5b-1c2d3e4f5a6b"}]}`)
		default:
			io.WriteString(w, `{"data":true}`)
		}
	case strings.HasPrefix(p, "/api/v1/server/UniProxy/"):
		if r.URL.Query().Get("token") != "k" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		switch strings.TrimPrefix(p, "/api/v1/server/UniProxy/") {
		case "config":
			fmt.Fprintf(w, `{"protocol":"vmess","server_port":%d,"network":"tcp","tls":0,"routes":[],"base_config":{"push_interval":60,"pull_interval":60}}`, m.staticPort)
		case "user":
			io.WriteString(w, `{"users":[{"id":1,"uuid":"7f6fd2d2-9a3d-4a8e-9f5b-1c2d3e4f5a6b"}]}`)
		default:
			io.WriteString(w, `{"data":true}`)
		}
	default:
		// The agent link (config/report/ack) shares the machine credentials.
		// Anything else (e.g. the static node's V2 WebSocket handshake) is not
		// part of this fake.
		if !strings.HasPrefix(p, "/api/v2/server/machine/agent/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if !m.auth(w, r) {
			return
		}
		io.WriteString(w, `{"schema":1,"unchanged":true}`)
	}
}

func (m *machineFakePanel) setNodes(nodes []map[string]any, version string) {
	m.mu.Lock()
	m.nodes, m.version = nodes, version
	m.mu.Unlock()
}

func (m *machineFakePanel) hits() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.nodesHits
}

func (m *machineFakePanel) configHitsFor(id int) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.configHits[id]
}

// writeMachineConfig writes a config with an Agent.Panel in machine mode.
// extra is inserted before the Agent block (used for static Nodes).
func writeMachineConfig(t *testing.T, dir, panelURL, extra string) string {
	t.Helper()
	path := filepath.Join(dir, "config.yml")
	body := fmt.Sprintf(`Log: {Level: warning}
%sAgent:
  Enabled: true
  StateDir: %q
  Panel:
    Enabled: true
    URL: %q
    MachineID: 9
    Token: %q
    MachineNodes: true
    NodeController: {ListenIP: 127.0.0.1}
`, extra, filepath.Join(dir, "state"), panelURL, machineToken)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func machineNodeJSON(id int, name string, updated int) map[string]any {
	return map[string]any{"id": id, "type": "vmess", "name": name, "updated_at": updated}
}

func panelNodes(t *testing.T, p *Panel) []*node.Controller {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*node.Controller(nil), p.nodes...)
}

func waitNodes(t *testing.T, p *Panel, want int, msg string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if n := len(panelNodes(t, p)); n == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %d node(s), want %d", msg, len(panelNodes(t, p)), want)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestPanelMachineNodesDiscover: the panel's list becomes one controller per
// node, tagged with the machine.
func TestPanelMachineNodesDiscover(t *testing.T) {
	port1, port2 := freePort(t), freePort(t)
	fp := newMachineFakePanel(t)
	fp.ports = map[int]int{1: port1, 2: port2}
	fp.setNodes([]map[string]any{machineNodeJSON(1, "a", 1), machineNodeJSON(2, "b", 2)}, "v1")

	path := writeMachineConfig(t, t.TempDir(), fp.srv.URL, "")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	p := New(path, cfg)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	nodes := panelNodes(t, p)
	if len(nodes) != 2 {
		t.Fatalf("%d controllers, want 2", len(nodes))
	}
	tags := map[string]bool{}
	for _, n := range nodes {
		tags[n.Tag()] = true
	}
	if !tags["node1@machine9"] || !tags["node2@machine9"] {
		t.Fatalf("tags = %v", tags)
	}
	waitDial(t, fmt.Sprintf("127.0.0.1:%d", port1), true, 15*time.Second, "machine node 1 listens")
	waitDial(t, fmt.Sprintf("127.0.0.1:%d", port2), true, 15*time.Second, "machine node 2 listens")
}

// TestPanelMachineNodesVersionReload: a new version of the node list triggers a
// reload that picks up the added node.
func TestPanelMachineNodesVersionReload(t *testing.T) {
	old := machinePollInterval
	machinePollInterval = 100 * time.Millisecond
	t.Cleanup(func() { machinePollInterval = old })

	port1, port2 := freePort(t), freePort(t)
	fp := newMachineFakePanel(t)
	fp.ports = map[int]int{1: port1, 2: port2}
	fp.setNodes([]map[string]any{machineNodeJSON(1, "a", 1)}, "v1")

	path := writeMachineConfig(t, t.TempDir(), fp.srv.URL, "")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	p := New(path, cfg)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	waitNodes(t, p, 1, "initial discovery")

	// The panel adds a node; the version changes.
	fp.setNodes([]map[string]any{machineNodeJSON(1, "a", 1), machineNodeJSON(2, "b", 2)}, "v2")
	waitNodes(t, p, 2, "after the version change")
	if fp.configHitsFor(2) == 0 {
		t.Error("the added node was never fetched")
	}
	waitDial(t, fmt.Sprintf("127.0.0.1:%d", port2), true, 15*time.Second, "added machine node listens")
}

// TestPanelMachineNodesDiscoveryFailure: a 401 during discovery does not keep
// the static node from starting, and the background retry picks up the machine
// node once the panel accepts it.
func TestPanelMachineNodesDiscoveryFailure(t *testing.T) {
	old := machineRetryDelay
	machineRetryDelay = 100 * time.Millisecond
	t.Cleanup(func() { machineRetryDelay = old })

	staticPort, machinePort := freePort(t), freePort(t)
	fp := newMachineFakePanel(t)
	fp.staticPort = staticPort
	fp.ports = map[int]int{5: machinePort}
	fp.setNodes([]map[string]any{machineNodeJSON(5, "m", 1)}, "v1")
	fp.mu.Lock()
	fp.denyNodes = 1 // the first discovery is refused
	fp.mu.Unlock()

	dir := t.TempDir()
	extra := fmt.Sprintf(`Nodes:
  - PanelType: Xboard
    ApiConfig: {ApiHost: %q, ApiKey: k, NodeID: 1}
    ControllerConfig: {ListenIP: 127.0.0.1}
`, fp.srv.URL)
	path := writeMachineConfig(t, dir, fp.srv.URL, extra)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	p := New(path, cfg)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	// The static node runs even though the machine discovery failed.
	waitDial(t, fmt.Sprintf("127.0.0.1:%d", staticPort), true, 15*time.Second, "static node runs after a failed discovery")

	// The retry discovers the machine node.
	waitNodes(t, p, 2, "after the discovery retry")
	waitDial(t, fmt.Sprintf("127.0.0.1:%d", machinePort), true, 15*time.Second, "machine node runs after the retry")
}

// TestPanelMachineNodesShutdown: Close joins the machine tasks (it would hang
// otherwise) and the watcher stops polling.
func TestPanelMachineNodesShutdown(t *testing.T) {
	old := machinePollInterval
	machinePollInterval = 50 * time.Millisecond
	t.Cleanup(func() { machinePollInterval = old })

	port := freePort(t)
	fp := newMachineFakePanel(t)
	fp.ports = map[int]int{1: port}
	fp.setNodes([]map[string]any{machineNodeJSON(1, "a", 1)}, "v1")

	path := writeMachineConfig(t, t.TempDir(), fp.srv.URL, "")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	p := New(path, cfg)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	waitDial(t, fmt.Sprintf("127.0.0.1:%d", port), true, 15*time.Second, "machine node listens")

	// Wait until the watcher has polled at least once.
	deadline := time.Now().Add(10 * time.Second)
	for fp.hits() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("the watcher never polled (%d requests)", fp.hits())
		}
		time.Sleep(20 * time.Millisecond)
	}

	closed := make(chan struct{})
	go func() {
		p.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(20 * time.Second):
		t.Fatal("Close did not return: the machine tasks did not exit")
	}
	hits := fp.hits()
	time.Sleep(300 * time.Millisecond)
	if got := fp.hits(); got != hits {
		t.Fatalf("the machine watcher kept polling after Close (%d -> %d)", hits, got)
	}
	p.mu.Lock()
	cancel := p.machineCancel
	p.mu.Unlock()
	if cancel != nil {
		t.Fatal("machineCancel was not cleared by shutdown")
	}
}

// ---- config validation ---------------------------------------------------

func TestMachineNodesConfig(t *testing.T) {
	const valid = `Log: {Level: warning}
Agent:
  Enabled: true
  Panel:
    Enabled: true
    URL: "http://127.0.0.1:8080"
    MachineID: 9
    Token: t
    MachineNodes: true
`
	cases := []struct {
		name string
		body string
		want string // error substring; "" = valid
	}{
		{
			name: "machine mode without nodes",
			body: valid,
			want: "",
		},
		{
			name: "machine nodes require the panel",
			body: `Log: {Level: warning}
Nodes:
  - ApiConfig: {ApiHost: "http://a", ApiKey: k, NodeID: 1}
Agent:
  Enabled: true
  Panel:
    URL: "http://127.0.0.1:8080"
    MachineID: 9
    Token: t
    MachineNodes: true
`,
			want: "MachineNodes requires Agent.Panel.Enabled",
		},
		{
			name: "machine nodes require the agent",
			body: `Log: {Level: warning}
Nodes:
  - ApiConfig: {ApiHost: "http://a", ApiKey: k, NodeID: 1}
Agent:
  Enabled: false
  Panel: {Enabled: true, URL: "http://127.0.0.1:8080", MachineID: 9, Token: t, MachineNodes: true}
`,
			want: "requires Agent.Enabled",
		},
		{
			name: "machine nodes need a token",
			body: `Log: {Level: warning}
Agent:
  Enabled: true
  Panel:
    Enabled: true
    URL: "http://127.0.0.1:8080"
    MachineID: 9
    MachineNodes: true
`,
			want: "needs Token or TokenFile",
		},
		{
			name: "machine nodes and static nodes coexist",
			body: `Log: {Level: warning}
Nodes:
  - ApiConfig: {ApiHost: "http://a", ApiKey: k, NodeID: 1}
Agent:
  Enabled: true
  Panel:
    Enabled: true
    URL: "http://127.0.0.1:8080"
    MachineID: 9
    Token: t
    MachineNodes: true
`,
			want: "",
		},
		{
			name: "machine mode needs a valid url",
			body: `Log: {Level: warning}
Agent:
  Enabled: true
  Panel:
    Enabled: true
    URL: "http://panel.example.com"
    MachineID: 9
    Token: t
    MachineNodes: true
`,
			want: "https",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yml")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadConfig(path)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.want != "" && err == nil:
				t.Fatal("accepted")
			case tc.want != "" && !strings.Contains(err.Error(), tc.want):
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
			if err != nil {
				return
			}
			if machinePanel(cfg) == nil {
				t.Fatal("machinePanel() = nil for a machine-mode config")
			}
			// The shared template gets the node defaults, so a machine node
			// never listens on an empty address.
			cc := cfg.Agent.Panel.NodeController
			if cc == nil || cc.ListenIP != "0.0.0.0" || cc.SendIP != "0.0.0.0" || cc.DNSType != "AsIs" {
				t.Fatalf("NodeController defaults = %+v", cc)
			}
		})
	}
}

func TestNodeControllerTemplateMerged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	body := `Log: {Level: warning}
Agent:
  Enabled: true
  Panel:
    Enabled: true
    URL: "http://127.0.0.1:8080"
    MachineID: 9
    Token: t
    MachineNodes: true
    NodeController:
      ListenIP: 127.0.0.1
      UpdatePeriodic: 30
      CertConfig: {CertMode: none}
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	cc := cfg.Agent.Panel.NodeController
	if cc.ListenIP != "127.0.0.1" || cc.UpdatePeriodic != 30 {
		t.Fatalf("template not applied: %+v", cc)
	}
	if cc.SendIP != "0.0.0.0" || cc.DNSType != "AsIs" {
		t.Fatalf("defaults not merged: %+v", cc)
	}
	if cc.CertConfig == nil || cc.CertConfig.CertMode != "none" {
		t.Fatalf("cert config lost: %+v", cc.CertConfig)
	}
	// Each controller gets its own copy.
	if machineControllerConfig(cc) == cc {
		t.Fatal("machineControllerConfig returned the shared template")
	}
}

func TestMachinePanelDisabled(t *testing.T) {
	cfg := &Config{}
	if machinePanel(cfg) != nil {
		t.Fatal("machinePanel() without an agent")
	}
	cfg.Agent = &AgentConfig{Enabled: true, Panel: &AgentPanelConfig{Enabled: true, MachineNodes: false}}
	if machinePanel(cfg) != nil {
		t.Fatal("machinePanel() with MachineNodes off")
	}
	cfg.Agent.Panel.MachineNodes = true
	if machinePanel(cfg) == nil {
		t.Fatal("machinePanel() with machine mode on")
	}
}

// TestMachineFieldsNotFromYAML: the machine credentials are internal. They come
// from Agent.Panel only, so a Nodes entry cannot smuggle them in.
func TestMachineFieldsNotFromYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	body := `Log: {Level: warning}
Nodes:
  - ApiConfig: {ApiHost: "http://a", ApiKey: k, NodeID: 1, MachineID: 9, MachineToken: secret}
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	a := cfg.NodesConfig[0].ApiConfig
	if a.MachineID != 0 || a.MachineToken != "" {
		t.Fatalf("machine credentials came from the YAML: %+v", a)
	}
}

// ---- check output --------------------------------------------------------

// TestCheckMachineNodesOffline: the offline report names the machine and never
// touches the panel (the URL is unreachable, so a network call would fail).
func TestCheckMachineNodesOffline(t *testing.T) {
	path := writeMachineConfig(t, t.TempDir(), "http://127.0.0.1:1", "")
	var w bytes.Buffer
	if err := Check(path, false, &w); err != nil {
		t.Fatalf("%v\n%s", err, w.String())
	}
	out := w.String()
	if !strings.Contains(out, "机器 ID 9") || !strings.Contains(out, "--online") {
		t.Errorf("report:\n%s", out)
	}
	if strings.Contains(out, machineToken) {
		t.Errorf("the report prints the token:\n%s", out)
	}
}

func TestCheckMachineNodesOnline(t *testing.T) {
	pc := func(url string) *AgentPanelConfig {
		return &AgentPanelConfig{Enabled: true, URL: url, MachineID: 9, Token: machineToken, MachineNodes: true}
	}
	t.Run("lists the nodes", func(t *testing.T) {
		fp := newMachineFakePanel(t)
		fp.setNodes([]map[string]any{machineNodeJSON(1, "a", 1), machineNodeJSON(2, "b", 2)}, "v1")
		var w bytes.Buffer
		if err := checkMachineNodes(&w, pc(fp.srv.URL), true); err != nil {
			t.Fatalf("%v\n%s", err, w.String())
		}
		out := w.String()
		if !strings.Contains(out, "2 个节点") || !strings.Contains(out, "版本 v1") || !strings.Contains(out, "机器 ID 9") {
			t.Errorf("report:\n%s", out)
		}
		if strings.Contains(out, machineToken) {
			t.Errorf("the report prints the token:\n%s", out)
		}
	})
	t.Run("empty list is called out", func(t *testing.T) {
		fp := newMachineFakePanel(t)
		fp.setNodes(nil, "v0")
		var w bytes.Buffer
		if err := checkMachineNodes(&w, pc(fp.srv.URL), true); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(w.String(), "没有给这台机器分配节点") {
			t.Errorf("report:\n%s", w.String())
		}
	})
	t.Run("401 fails the check without the token", func(t *testing.T) {
		fp := newMachineFakePanel(t)
		fp.mu.Lock()
		fp.denyNodes = 100
		fp.mu.Unlock()
		var w bytes.Buffer
		if err := checkMachineNodes(&w, pc(fp.srv.URL), true); err == nil || !strings.Contains(w.String(), "✗") {
			t.Fatalf("err = %v\n%s", err, w.String())
		}
		if strings.Contains(w.String(), machineToken) {
			t.Errorf("the report prints the token:\n%s", w.String())
		}
	})
}
