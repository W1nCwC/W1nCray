package panel

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/bootstrap"
	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/reconcile"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/core"
)

// fakeGost is a minimal non-xray driver for the decoupling tests: it keeps the
// instance ids it runs and counts what happens to them, so a test can prove
// that an xray rebuild never stops the other engines.
type fakeGost struct {
	mu      sync.Mutex
	running map[string]string // instance id -> artifact hash
	stops   int
	applies int
}

func newFakeGost() *fakeGost { return &fakeGost{running: map[string]string{}} }

func (f *fakeGost) Caps() driver.Caps {
	return driver.Caps{
		Name: "gost", Kinds: []spec.Kind{spec.KindForward}, Network: []string{"tcp"},
		ProxyIn: true, ProxyOut: true, Stats: "none", Reload: "hot",
	}
}

func (f *fakeGost) Validate(spec.Instance) error { return nil }

func (f *fakeGost) Render(in spec.Instance) (driver.Artifact, error) {
	return driver.Artifact{
		Files: map[string][]byte{in.ID + ".json": []byte("{}")},
		Hash:  "fake-" + in.ID,
	}, nil
}

func (f *fakeGost) Apply(ctx context.Context, rt driver.Runtime, set []driver.Rendered) (driver.ApplyResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applies++
	res := driver.ApplyResult{Failed: map[string]string{}}
	next := map[string]string{}
	for _, r := range set {
		next[r.Instance.ID] = r.Artifact.Hash
		res.Running = append(res.Running, r.Instance.ID)
	}
	f.running = next
	return res, nil
}

func (f *fakeGost) Rollback(ctx context.Context, rt driver.Runtime) error { return nil }

func (f *fakeGost) Stop(ctx context.Context, rt driver.Runtime, ids ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stops++
	if len(ids) == 0 {
		f.running = map[string]string{}
		return nil
	}
	for _, id := range ids {
		delete(f.running, id)
	}
	return nil
}

func (f *fakeGost) Stats(ctx context.Context, rt driver.Runtime) ([]driver.Counter, error) {
	return nil, nil
}

func (f *fakeGost) Health(ctx context.Context, rt driver.Runtime) driver.Health {
	f.mu.Lock()
	defer f.mu.Unlock()
	h := driver.Health{Instances: map[string]driver.InstanceHealth{}}
	for id, hash := range f.running {
		h.Instances[id] = driver.InstanceHealth{Running: true, Listening: true, ConfigHash: hash}
	}
	return h
}

// snapshot returns the running instance ids and the number of Stop calls.
func (f *fakeGost) snapshot() (map[string]bool, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]bool{}
	for id := range f.running {
		out[id] = true
	}
	return out, f.stops
}

// fwdInstance builds a TCP forward on 127.0.0.1:port for the given engine.
func fwdInstance(id, engine string, port int) spec.Instance {
	return spec.Instance{
		ID: id, Enabled: true, Engine: engine, Kind: spec.KindForward,
		Listen:  &spec.Listen{Addr: "127.0.0.1", Ports: strconv.Itoa(port)},
		Targets: []spec.Target{{Host: "198.51.100.10", Ports: "443"}},
	}
}

// waitCoreChanged waits until the panel runs a core different from old.
func waitCoreChanged(t *testing.T, p *Panel, old *core.Core) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		p.mu.Lock()
		core := p.core
		p.mu.Unlock()
		if core != nil && core != old {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the xray core was not rebuilt")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitAgent waits until the agent of the panel satisfies ok.
func waitAgent(t *testing.T, p *Panel, ok func(rt *bootstrap.Runtime) bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		p.mu.Lock()
		rt := p.agent
		p.mu.Unlock()
		if ok(rt) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the agent never reached the expected state")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestXrayRebuildKeepsTheAgent is the WP-A decoupling test: an xray file change
// rebuilds the core, recreates the engine=xray instances on it and leaves the
// agent Runtime and the instances of the other engines running.
func TestXrayRebuildKeepsTheAgent(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yml")
	xrayPort, gostPort := freePort(t), freePort(t)

	body := fmt.Sprintf(`Log: {Level: warning}
Agent:
  Enabled: true
  StateDir: %q
`, filepath.Join(dir, "state"))
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
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

	p.mu.Lock()
	rt, core1 := p.agent, p.core
	p.mu.Unlock()
	if rt == nil || core1 == nil {
		t.Fatalf("agent=%v core=%v, want both running", rt != nil, core1 != nil)
	}

	// A non-xray engine the runtime knows: a fake that records what happens to
	// it. This panel has no panel link, so nothing else reads the driver map.
	fake := newFakeGost()
	rt.Reconciler.Drivers[spec.EngineGost] = fake

	d := spec.Desired{Version: spec.Version, Revision: 1, Instances: []spec.Instance{
		fwdInstance("x1", spec.EngineXray, xrayPort),
		fwdInstance("g1", spec.EngineGost, gostPort),
	}}
	rep, err := rt.Apply(context.Background(), d)
	if err != nil || rep.Status != reconcile.StatusApplied {
		t.Fatalf("apply: %v / %s", err, rep.Status)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", xrayPort)
	waitDial(t, addr, true, 10*time.Second, "the xray forward after apply")

	// Change config.yml (an xray file) and rebuild.
	if err := os.WriteFile(configPath, []byte(strings.Replace(body, "Level: warning", "Level: info", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	p.requestReload("test: xray change")
	waitCoreChanged(t, p, core1)

	p.mu.Lock()
	sameAgent := p.agent == rt
	agentRunning := p.agent != nil
	p.mu.Unlock()
	if !agentRunning || !sameAgent {
		t.Fatal("the xray rebuild restarted the agent")
	}
	running, stops := fake.snapshot()
	if !running["g1"] {
		t.Error("the xray rebuild stopped the non-xray instance")
	}
	if stops != 0 {
		t.Errorf("the non-xray engine was stopped %d time(s)", stops)
	}
	// The engine=xray instance is back on the new core.
	waitDial(t, addr, true, 20*time.Second, "the xray forward after the rebuild")
}

// TestXrayRebuildKeepsThePanelLink: the panel link is not restarted by an xray
// rebuild. A restart would poll /config again at once, and the 300s pull
// interval rules out a scheduled poll inside the test window.
func TestXrayRebuildKeepsThePanelLink(t *testing.T) {
	dir := t.TempDir()
	fp := newFakePanelServer(t)
	tokenFile := filepath.Join(dir, "panel.token")
	if err := os.WriteFile(tokenFile, []byte(testPanelToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yml")
	body := fmt.Sprintf(`Log: {Level: warning}
Agent:
  Enabled: true
  StateDir: %q
  Panel:
    Enabled: true
    URL: %s
    MachineID: 7
    TokenFile: %q
    PullIntervalSec: 300
`, filepath.Join(dir, "state"), fp.srv.URL, tokenFile)
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
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

	p.mu.Lock()
	rt, core1, remote := p.agent, p.core, p.remoteStop
	p.mu.Unlock()
	if rt == nil || core1 == nil || remote == nil {
		t.Fatalf("agent=%v core=%v remote=%v, want all running", rt != nil, core1 != nil, remote != nil)
	}

	deadline := time.Now().Add(15 * time.Second)
	for fp.count("config") == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the agent never polled the panel")
		}
		time.Sleep(10 * time.Millisecond)
	}
	polls := fp.count("config")

	if err := os.WriteFile(configPath, []byte(strings.Replace(body, "Level: warning", "Level: info", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	p.requestReload("test: xray change")
	waitCoreChanged(t, p, core1)

	p.mu.Lock()
	sameAgent, linkUp := p.agent == rt, p.remoteStop != nil
	p.mu.Unlock()
	if !sameAgent {
		t.Fatal("the xray rebuild restarted the agent")
	}
	if !linkUp {
		t.Fatal("the xray rebuild ended the panel link")
	}
	// No new /config request: the link was never torn down and re-established.
	time.Sleep(300 * time.Millisecond)
	if got := fp.count("config"); got != polls {
		t.Errorf("the panel link was restarted (%d -> %d /config requests)", polls, got)
	}
}

// TestAgentYMLChangeRestartsOnlyTheAgent: editing agent.yml restarts the agent
// and leaves the xray core running; enabling and disabling the agent in
// agent.yml starts and stops it accordingly, still without touching xray.
func TestAgentYMLChangeRestartsOnlyTheAgent(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yml")
	agentYML := filepath.Join(dir, "agent.yml")
	stateDir := filepath.Join(dir, "state")

	// config.yml carries a node so the agent may be disabled later: a config
	// with neither Nodes nor an enabled agent is invalid.
	body := `Log: {Level: warning}
Nodes:
  - ApiConfig: {ApiHost: "http://127.0.0.1:1", ApiKey: k, NodeID: 1}
`
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
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
	p := New(configPath, cfg)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	p.mu.Lock()
	rt1, core1 := p.agent, p.core
	p.mu.Unlock()
	if rt1 == nil || core1 == nil {
		t.Fatalf("agent=%v core=%v, want both running", rt1 != nil, core1 != nil)
	}

	// 1. A change of the agent configuration restarts the agent and leaves the
	// xray core alone.
	writeAgentYML(true, "Terminal: {Enabled: false}\n")
	waitAgent(t, p, func(rt *bootstrap.Runtime) bool { return rt != nil && rt != rt1 })
	p.mu.Lock()
	core2 := p.core
	p.mu.Unlock()
	if core2 != core1 {
		t.Fatal("an agent.yml-only change rebuilt the xray core")
	}

	// 2. Disabling the agent stops it, still without touching xray.
	writeAgentYML(false, "")
	waitAgent(t, p, func(rt *bootstrap.Runtime) bool { return rt == nil })
	p.mu.Lock()
	core3 := p.core
	p.mu.Unlock()
	if core3 != core1 {
		t.Fatal("disabling the agent rebuilt the xray core")
	}

	// 3. Re-enabling it starts a new Runtime on the same core.
	writeAgentYML(true, "")
	waitAgent(t, p, func(rt *bootstrap.Runtime) bool { return rt != nil && rt != rt1 })
	p.mu.Lock()
	core4 := p.core
	p.mu.Unlock()
	if core4 != core1 {
		t.Fatal("re-enabling the agent rebuilt the xray core")
	}
}

// TestConfigYMLAgentChangeRebuildsXrayAndRestartsTheAgent: the Agent block of
// config.yml belongs to an xray file, so a change there rebuilds xray and, when
// the agent configuration really changed, restarts the agent too.
func TestConfigYMLAgentChangeRebuildsXrayAndRestartsTheAgent(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yml")
	body := func(terminalOff bool) string {
		extra := ""
		if terminalOff {
			extra = "  Terminal: {Enabled: false}\n"
		}
		return fmt.Sprintf(`Log: {Level: warning}
Agent:
  Enabled: true
  StateDir: %q
%s`, filepath.Join(dir, "state"), extra)
	}
	if err := os.WriteFile(configPath, []byte(body(false)), 0o600); err != nil {
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

	p.mu.Lock()
	rt1, core1 := p.agent, p.core
	p.mu.Unlock()
	if rt1 == nil || core1 == nil {
		t.Fatalf("agent=%v core=%v, want both running", rt1 != nil, core1 != nil)
	}

	if err := os.WriteFile(configPath, []byte(body(true)), 0o600); err != nil {
		t.Fatal(err)
	}
	p.requestReload("test: config.yml Agent block changed")

	deadline := time.Now().Add(30 * time.Second)
	for {
		p.mu.Lock()
		rt, core := p.agent, p.core
		p.mu.Unlock()
		if rt != nil && rt != rt1 && core != nil && core != core1 {
			return
		}
		if time.Now().After(deadline) {
			p.mu.Lock()
			rt, core = p.agent, p.core
			p.mu.Unlock()
			t.Fatalf("agent restarted=%v, core rebuilt=%v; want both", rt != rt1, core != core1)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
