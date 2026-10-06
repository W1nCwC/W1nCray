package panel

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/W1nCwC/W1nCray/api/xboard"
	"github.com/W1nCwC/W1nCray/common/cert"
	"github.com/W1nCwC/W1nCray/node"
)

// writeNodeControllersConfig writes a machine-mode config with a NodeController
// template and the given (already indented) NodeControllers body.
func writeNodeControllersConfig(t *testing.T, dir, nodeControllers string) string {
	t.Helper()
	path := filepath.Join(dir, "config.yml")
	body := fmt.Sprintf(`Log: {Level: warning}
Agent:
  Enabled: true
  StateDir: %q
  Panel:
    Enabled: true
    URL: "http://127.0.0.1:8080"
    MachineID: 9
    Token: t
    MachineNodes: true
    NodeController: {ListenIP: 127.0.0.1}
    NodeControllers:
%s`, filepath.Join(dir, "state"), nodeControllers)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// logCapture records logrus entries; it is safe for concurrent use, so it can
// watch a whole Panel lifetime.
type logCapture struct {
	mu   sync.Mutex
	msgs []string
}

func (c *logCapture) Levels() []log.Level { return log.AllLevels }

func (c *logCapture) Fire(e *log.Entry) error {
	c.mu.Lock()
	c.msgs = append(c.msgs, e.Message)
	c.mu.Unlock()
	return nil
}

func (c *logCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.msgs, "\n")
}

// captureLogs installs a log hook and restores the logger afterwards.
func captureLogs(t *testing.T) *logCapture {
	t.Helper()
	c := &logCapture{}
	oldHooks := log.StandardLogger().ReplaceHooks(make(log.LevelHooks))
	oldLevel := log.GetLevel()
	log.SetLevel(log.InfoLevel)
	log.AddHook(c)
	t.Cleanup(func() {
		log.StandardLogger().ReplaceHooks(oldHooks)
		log.SetLevel(oldLevel)
	})
	return c
}

// TestNodeControllersOverrideSelection: an override is used as a whole (it does
// not inherit the template field by field), a node without an entry uses the
// template, and the override itself is completed with the node defaults.
func TestNodeControllersOverrideSelection(t *testing.T) {
	path := writeNodeControllersConfig(t, t.TempDir(), `      173:
        EnableProxyProtocol: true
        CertConfig:
          CertMode: dns
          CertDomain: node173.example.com
          Provider: cloudflare
          DNSEnv:
            CF_DNS_API_TOKEN: local-secret
      138:
        EnableDNS: true
        DNSType: UseIPv4
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	pc := cfg.Agent.Panel
	if len(pc.NodeControllers) != 2 {
		t.Fatalf("%d overrides, want 2", len(pc.NodeControllers))
	}

	// 173: the override wins as a whole. ListenIP is the node default, not the
	// template's 127.0.0.1: the two are never merged field by field.
	o := machineNodeConfig(pc, 173)
	if !o.EnableProxyProtocol {
		t.Errorf("173: EnableProxyProtocol not applied: %+v", o)
	}
	if o.ListenIP != "0.0.0.0" || o.SendIP != "0.0.0.0" || o.DNSType != "AsIs" {
		t.Errorf("173: defaults not applied / template leaked: %+v", o)
	}
	if o.CertConfig == nil || o.CertConfig.CertMode != "dns" ||
		(o.CertConfig.DNSEnv["CF_DNS_API_TOKEN"] != "local-secret" && o.CertConfig.DNSEnv["cf_dns_api_token"] != "local-secret") {
		t.Errorf("173: CertConfig lost: %+v", o.CertConfig)
	}

	// 138: the override is complete too.
	o = machineNodeConfig(pc, 138)
	if !o.EnableDNS || o.DNSType != "UseIPv4" || o.ListenIP != "0.0.0.0" {
		t.Errorf("138: %+v", o)
	}
	if o.EnableProxyProtocol {
		t.Errorf("138 inherited 173's override: %+v", o)
	}

	// 119: no entry, so the shared template applies.
	o = machineNodeConfig(pc, 119)
	if o.ListenIP != "127.0.0.1" || o.EnableProxyProtocol || o.EnableDNS {
		t.Errorf("119 should use the template: %+v", o)
	}
}

// TestNodeControllerIDList: the report helper lists ids only, sorted.
func TestNodeControllerIDList(t *testing.T) {
	pc := &AgentPanelConfig{NodeControllers: map[int]*node.Config{138: {}, 173: {}, 5: {}}}
	if got := pc.NodeControllerIDList(); got != "5, 138, 173" {
		t.Errorf("NodeControllerIDList() = %q, want %q", got, "5, 138, 173")
	}
	if got := (&AgentPanelConfig{}).NodeControllerIDList(); got != "" {
		t.Errorf("empty overrides = %q, want empty", got)
	}
}

// TestNodeControllersCopiesAreIsolated: every controller gets its own copy, so
// mutating one never reaches the config or another controller.
func TestNodeControllersCopiesAreIsolated(t *testing.T) {
	pc := &AgentPanelConfig{
		NodeController: &node.Config{ListenIP: "127.0.0.1"},
		NodeControllers: map[int]*node.Config{
			173: {ListenIP: "10.0.0.1", UpdatePeriodic: 30},
		},
	}
	a, b := machineNodeConfig(pc, 173), machineNodeConfig(pc, 173)
	if a == b || a == pc.NodeControllers[173] {
		t.Fatal("the override was not copied")
	}
	a.ListenIP, a.UpdatePeriodic = "192.0.2.1", 999
	if pc.NodeControllers[173].ListenIP != "10.0.0.1" || pc.NodeControllers[173].UpdatePeriodic != 30 {
		t.Errorf("the stored override changed: %+v", pc.NodeControllers[173])
	}
	if b.ListenIP != "10.0.0.1" || b.UpdatePeriodic != 30 {
		t.Errorf("the second controller shares state with the first: %+v", b)
	}

	x, y := machineNodeConfig(pc, 7), machineNodeConfig(pc, 7)
	if x == y || x == pc.NodeController {
		t.Fatal("the template was not copied")
	}
	x.ListenIP = "192.0.2.2"
	if y.ListenIP != "127.0.0.1" || pc.NodeController.ListenIP != "127.0.0.1" {
		t.Errorf("the template copy is shared: y=%+v template=%+v", y, pc.NodeController)
	}
}

// TestNodeControllersValidation: a bad key or an empty entry is a config error,
// and the error never prints the configuration behind it.
func TestNodeControllersValidation(t *testing.T) {
	t.Run("yaml key must be positive", func(t *testing.T) {
		path := writeNodeControllersConfig(t, t.TempDir(), "      0:\n        ListenIP: 127.0.0.1\n")
		_, err := LoadConfig(path)
		if err == nil || !strings.Contains(err.Error(), "positive number") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("negative key", func(t *testing.T) {
		pc := &AgentPanelConfig{
			Enabled: true, URL: "http://127.0.0.1:8080", MachineID: 9, Token: "t", MachineNodes: true,
			NodeControllers: map[int]*node.Config{-1: {}},
		}
		if err := pc.Validate(); err == nil || !strings.Contains(err.Error(), "positive number") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("nil value", func(t *testing.T) {
		pc := &AgentPanelConfig{
			Enabled: true, URL: "http://127.0.0.1:8080", MachineID: 9, Token: "t", MachineNodes: true,
			NodeControllers: map[int]*node.Config{173: nil},
		}
		err := pc.Validate()
		if err == nil || !strings.Contains(err.Error(), "must not be empty") {
			t.Fatalf("err = %v", err)
		}
		if strings.Contains(fmt.Sprint(err), "local-secret") {
			t.Errorf("the error leaks configuration: %v", err)
		}
	})
}

// TestNodeControllersUnassignedLogged: an override the panel did not assign is
// an info line, never an error, and the assigned node is not reported.
func TestNodeControllersUnassignedLogged(t *testing.T) {
	c := captureLogs(t)

	pc := &AgentPanelConfig{NodeControllers: map[int]*node.Config{173: {}, 5: {}}}
	logUnassignedNodeControllers(pc, []xboard.MachineNode{{ID: 173}, {ID: 138}})

	out := c.String()
	want := "NodeControllers[5] is configured but the panel did not assign that node"
	if !strings.Contains(out, want) {
		t.Errorf("missing %q in:\n%s", want, out)
	}
	if strings.Contains(out, "NodeControllers[173]") {
		t.Errorf("the assigned node was reported as unassigned:\n%s", out)
	}
}

// TestNodeControllersNotInCheckOutput: check names the overridden node ids but
// never their content, so the DNS credentials stay off the terminal.
func TestNodeControllersNotInCheckOutput(t *testing.T) {
	const secret = "cf-dns-api-token-must-not-print"
	pc := func() *AgentPanelConfig {
		return &AgentPanelConfig{
			Enabled: true, URL: "http://127.0.0.1:1", MachineID: 9, Token: machineToken, MachineNodes: true,
			NodeController: &node.Config{ListenIP: "127.0.0.1"},
			NodeControllers: map[int]*node.Config{173: {CertConfig: &cert.Config{
				CertMode: "dns", CertDomain: "node173.example.com", Provider: "cloudflare",
				DNSEnv: map[string]string{"CF_DNS_API_TOKEN": secret},
			}}},
		}
	}

	t.Run("offline", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yml")
		body := fmt.Sprintf(`Log: {Level: warning}
Agent:
  Enabled: true
  Panel:
    Enabled: true
    URL: "http://127.0.0.1:1"
    MachineID: 9
    Token: %q
    MachineNodes: true
    NodeController: {ListenIP: 127.0.0.1}
    NodeControllers:
      173:
        EnableProxyProtocol: true
        CertConfig:
          CertMode: dns
          CertDomain: node173.example.com
          Provider: cloudflare
          DNSEnv:
            CF_DNS_API_TOKEN: %q
`, machineToken, secret)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		var w bytes.Buffer
		if err := Check(path, false, &w); err != nil {
			t.Fatalf("%v\n%s", err, w.String())
		}
		out := w.String()
		if strings.Contains(out, secret) {
			t.Errorf("check prints the DNS credentials:\n%s", out)
		}
		if !strings.Contains(out, "本地覆盖") || !strings.Contains(out, "节点 173") {
			t.Errorf("check does not list the overridden node id:\n%s", out)
		}
	})

	t.Run("online", func(t *testing.T) {
		fp := newMachineFakePanel(t)
		fp.setNodes([]map[string]any{machineNodeJSON(173, "a", 1)}, "v1")
		c := pc()
		c.URL = fp.srv.URL
		var w bytes.Buffer
		if err := checkMachineNodes(&w, c, true); err != nil {
			t.Fatalf("%v\n%s", err, w.String())
		}
		out := w.String()
		if strings.Contains(out, secret) {
			t.Errorf("the online report prints the DNS credentials:\n%s", out)
		}
		if !strings.Contains(out, "节点 173") {
			t.Errorf("the online report does not name the overridden node:\n%s", out)
		}
	})
}

// TestMachineNodeDiscoveryUsesOverrides runs the whole discovery path: the
// assigned node starts with its override and the stale override is logged.
func TestMachineNodeDiscoveryUsesOverrides(t *testing.T) {
	port := freePort(t)
	fp := newMachineFakePanel(t)
	fp.ports = map[int]int{173: port}
	fp.setNodes([]map[string]any{machineNodeJSON(173, "a", 1)}, "v1")

	c := captureLogs(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	body := fmt.Sprintf(`Log: {Level: warning}
Agent:
  Enabled: true
  StateDir: %q
  Panel:
    Enabled: true
    URL: %q
    MachineID: 9
    Token: %q
    MachineNodes: true
    NodeController: {ListenIP: 127.0.0.1}
    NodeControllers:
      173:
        EnableProxyProtocol: true
      5:
        ListenIP: 127.0.0.1
`, filepath.Join(dir, "state"), fp.srv.URL, machineToken)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cc := cfg.Agent.Panel.NodeControllers[173]; cc == nil || !cc.EnableProxyProtocol {
		t.Fatalf("the override did not survive LoadConfig: %+v", cc)
	}
	p := New(path, cfg)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	waitNodes(t, p, 1, "the assigned node")
	waitDial(t, fmt.Sprintf("127.0.0.1:%d", port), true, 15*time.Second, "the node with an override listens")

	deadline := time.Now().Add(5 * time.Second)
	want := "NodeControllers[5] is configured but the panel did not assign that node"
	for !strings.Contains(c.String(), want) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(c.String(), want) {
		t.Errorf("missing %q in:\n%s", want, c.String())
	}
	if strings.Contains(c.String(), "NodeControllers[173]") {
		t.Errorf("the assigned node was reported as unassigned:\n%s", c.String())
	}
}
