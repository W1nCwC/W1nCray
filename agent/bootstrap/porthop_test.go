package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/agentcfg"
	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/portledger"
	"github.com/W1nCwC/W1nCray/agent/reconcile"
	"github.com/W1nCwC/W1nCray/agent/wsproto"
	"github.com/W1nCwC/W1nCray/api/xboard"
)

// hopFirewall is an in-memory nftables: it records every command and keeps the
// table bodies the commands would have produced.
type hopFirewall struct {
	mu        sync.Mutex
	calls     []string
	nftOK     bool
	installed map[string]string // family -> table body
}

func newHopFirewall() *hopFirewall {
	return &hopFirewall{nftOK: true, installed: map[string]string{}}
}

func (f *hopFirewall) count(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func (f *hopFirewall) tables() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.installed)
}

func (f *hopFirewall) flush() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.installed = map[string]string{}
}

func (f *hopFirewall) Run(_ context.Context, name string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if name != "nft" || !f.nftOK {
		return "", errors.New("not found")
	}
	switch args[0] {
	case "-c", "-f":
		b, err := os.ReadFile(args[len(args)-1])
		if err != nil {
			return "", err
		}
		if args[0] == "-f" {
			c := string(b)
			for _, fam := range []string{"ip", "ip6"} {
				if strings.Contains(c, "table "+fam+" w1ncray_porthop {") {
					f.installed[fam] = c
				} else if strings.Contains(c, "delete table "+fam+" ") {
					delete(f.installed, fam)
				}
			}
		}
		return "", nil
	case "list":
		if c, ok := f.installed[args[2]]; ok {
			return c, nil
		}
		return "Error: No such file or directory", errors.New("exit 1")
	}
	return "", errors.New("unexpected " + name)
}

func (f *hopFirewall) RunWithStdinFile(context.Context, string, string, ...string) (string, error) {
	return "", errors.New("unexpected stdin file")
}

// hopPanelFake answers like the panel: 200 with the document, 304 when the
// caller holds its version, or an error.
type hopPanelFake struct {
	mu    sync.Mutex
	doc   *xboard.PortHop
	err   error
	calls int
	etags []string
}

func (p *hopPanelFake) PortHop(_ context.Context, etag string) (*xboard.PortHop, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	p.etags = append(p.etags, etag)
	if p.err != nil {
		return nil, p.err
	}
	if etag != "" && etag == p.doc.Version {
		return nil, xboard.ErrNotModified
	}
	return p.doc, nil
}

func (p *hopPanelFake) set(doc *xboard.PortHop, err error) {
	p.mu.Lock()
	p.doc, p.err = doc, err
	p.mu.Unlock()
}

func (p *hopPanelFake) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

func hopDoc(version string, rules ...xboard.PortHopRule) *xboard.PortHop {
	if rules == nil {
		rules = []xboard.PortHopRule{}
	}
	return &xboard.PortHop{Version: version, Rules: rules}
}

var hopRule12 = xboard.PortHopRule{NodeID: 12, Proto: "udp", Ports: "20000-20100", To: 443}

func hopConfig(portHop *bool) *agentcfg.Config {
	c := &agentcfg.Config{
		Enabled: true,
		Panel:   &agentcfg.PanelConfig{Enabled: true, MachineNodes: true},
	}
	if portHop != nil {
		c.Firewall = &agentcfg.FirewallConfig{PortHop: portHop}
	}
	return c
}

type hopRig struct {
	rt    *Runtime
	fw    *hopFirewall
	panel *hopPanelFake
	opts  RemoteOptions
}

func newHopRig(t *testing.T, stateDir string, cfg *agentcfg.Config, every time.Duration) *hopRig {
	t.Helper()
	fw, panel := newHopFirewall(), &hopPanelFake{doc: hopDoc("v0")}
	rt := &Runtime{
		log:             nopLog{},
		stateDir:        stateDir,
		Reconciler:      &reconcile.Reconciler{Ports: portledger.New()},
		portHopExec:     fw,
		portHopPanel:    panel,
		portHopPlatform: func(bool) bool { return true },
		portHopEvery:    every,
	}
	return &hopRig{rt: rt, fw: fw, panel: panel, opts: RemoteOptions{AgentConfig: cfg}}
}

func (g *hopRig) start(t *testing.T) func() {
	t.Helper()
	stop := g.rt.startPortHop(context.Background(), g.opts, nopLog{})
	t.Cleanup(stop)
	return stop
}

func waitHop(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func hasCap(caps []string, want string) bool {
	for _, c := range caps {
		if c == want {
			return true
		}
	}
	return false
}

func TestPortHopApplyThenNotModifiedDoesNotApplyAgain(t *testing.T) {
	g := newHopRig(t, t.TempDir(), hopConfig(nil), 10*time.Millisecond)
	g.panel.set(hopDoc("v1", hopRule12), nil)
	g.start(t)

	waitHop(t, "the rules to be installed", func() bool { return g.fw.tables() > 0 })
	waitHop(t, "several polls", func() bool { return g.panel.callCount() >= 5 })

	if n := g.fw.count("nft -f"); n != 1 {
		t.Fatalf("nft -f ran %d times, want 1 (a 304 must not apply again)", n)
	}
	g.panel.mu.Lock()
	last := g.panel.etags[len(g.panel.etags)-1]
	g.panel.mu.Unlock()
	if last != "v1" {
		t.Fatalf("the next request carried etag %q, want v1", last)
	}
	if !hasCap(runtimeStreams{rt: g.rt}.Capabilities(), wsproto.CapPortHop) {
		t.Fatal("port_hop was not declared after the probe passed")
	}
}

func TestPortHopRestoresWithoutThePanel(t *testing.T) {
	dir := t.TempDir()
	first := newHopRig(t, dir, hopConfig(nil), time.Hour)
	first.panel.set(hopDoc("v1", hopRule12), nil)
	stop := first.start(t)
	waitHop(t, "the first install", func() bool { return first.fw.tables() > 0 })
	stop()
	if first.fw.tables() == 0 {
		t.Fatal("stopping the controller removed the rules; it must keep forwarding")
	}

	// A new process after a reboot: empty firewall, panel unreachable.
	second := newHopRig(t, dir, hopConfig(nil), time.Hour)
	second.panel.set(nil, errors.New("connection refused"))
	second.start(t)

	if second.fw.tables() == 0 {
		t.Fatal("the rules were not restored from state.json at start")
	}
	if !hasCap(runtimeStreams{rt: second.rt}.Capabilities(), wsproto.CapPortHop) {
		t.Fatal("port_hop missing")
	}
	waitHop(t, "the failing fetch", func() bool { return second.panel.callCount() >= 1 })
	if second.fw.tables() == 0 {
		t.Fatal("a network error removed the rules")
	}
}

func TestPortHopOldPanelAnswerClearsTheRules(t *testing.T) {
	g := newHopRig(t, t.TempDir(), hopConfig(nil), 10*time.Millisecond)
	g.panel.set(hopDoc("v1", hopRule12), nil)
	g.start(t)
	waitHop(t, "install", func() bool { return g.fw.tables() > 0 })

	// GetMachinePortHop turns a 404 into an empty document with no version.
	g.panel.set(hopDoc(""), nil)
	waitHop(t, "the table to be deleted", func() bool { return g.fw.tables() == 0 })
}

func TestPortHopEmptyRuleSetRemovesTheTable(t *testing.T) {
	g := newHopRig(t, t.TempDir(), hopConfig(nil), 10*time.Millisecond)
	g.panel.set(hopDoc("v1", hopRule12), nil)
	g.start(t)
	waitHop(t, "install", func() bool { return g.fw.tables() > 0 })

	g.panel.set(hopDoc("v2"), nil)
	waitHop(t, "the table to be deleted", func() bool { return g.fw.tables() == 0 })
}

func TestPortHopHintFetchesAtOnce(t *testing.T) {
	g := newHopRig(t, t.TempDir(), hopConfig(nil), time.Hour)
	g.panel.set(hopDoc("v1"), nil)
	g.start(t)
	waitHop(t, "the first fetch", func() bool { return g.panel.callCount() == 1 })

	g.panel.set(hopDoc("v2", hopRule12), nil)
	g.rt.hintPortHop()

	waitHop(t, "the hint to install the rules", func() bool { return g.fw.tables() > 0 })
	if g.panel.callCount() != 2 {
		t.Fatalf("panel calls = %d, want 2", g.panel.callCount())
	}
}

func TestPortHopNodesHintReachesTheController(t *testing.T) {
	g := newHopRig(t, t.TempDir(), hopConfig(nil), time.Hour)
	g.panel.set(hopDoc("v1"), nil)
	g.start(t)
	waitHop(t, "the first fetch", func() bool { return g.panel.callCount() == 1 })
	g.panel.set(hopDoc("v2", hopRule12), nil)

	h := xrayNodeHint{enabled: true, log: nopLog{}, rt: g.rt}
	if err := h.SyncXrayNodes(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitHop(t, "the nodes hint to install the rules", func() bool { return g.fw.tables() > 0 })
}

func TestPortHopHealsAnExternalFlush(t *testing.T) {
	g := newHopRig(t, t.TempDir(), hopConfig(nil), 10*time.Millisecond)
	g.panel.set(hopDoc("v1", hopRule12), nil)
	g.start(t)
	waitHop(t, "install", func() bool { return g.fw.tables() > 0 })

	g.fw.flush()

	waitHop(t, "the rules to come back", func() bool { return g.fw.tables() > 0 })
}

func TestPortHopLocalSwitchOffClearsAndDeclaresNothing(t *testing.T) {
	dir := t.TempDir()
	on := newHopRig(t, dir, hopConfig(nil), time.Hour)
	on.panel.set(hopDoc("v1", hopRule12), nil)
	stop := on.start(t)
	waitHop(t, "install", func() bool { return on.fw.tables() > 0 })
	stop()
	state := filepath.Join(dir, "porthop", "state.json")
	if _, err := os.Stat(state); err != nil {
		t.Fatalf("state.json missing: %v", err)
	}

	off := newHopRig(t, dir, hopConfig(boolPtr(false)), time.Hour)
	off.fw.installed = on.fw.installed // the firewall the previous run left
	off.start(t)

	if off.fw.tables() != 0 {
		t.Fatal("the local switch is off but the rules were not cleared at start")
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatalf("state.json still there: %v", err)
	}
	if hasCap(runtimeStreams{rt: off.rt}.Capabilities(), wsproto.CapPortHop) {
		t.Fatal("port_hop declared with the local switch off")
	}
	if off.rt.portHopComponent() != nil {
		t.Fatal("a component is reported with the local switch off")
	}
	time.Sleep(30 * time.Millisecond)
	if off.panel.callCount() != 0 {
		t.Fatal("the panel was asked for rules with the local switch off")
	}
}

func TestPortHopProbeFailureDeclaresNothingAndChangesNothing(t *testing.T) {
	g := newHopRig(t, t.TempDir(), hopConfig(nil), 10*time.Millisecond)
	g.fw.nftOK = false
	g.start(t)
	time.Sleep(50 * time.Millisecond)

	if hasCap(runtimeStreams{rt: g.rt}.Capabilities(), wsproto.CapPortHop) {
		t.Fatal("port_hop declared without a usable backend")
	}
	if g.rt.PortHop != nil || g.rt.portHopComponent() != nil {
		t.Fatal("a controller or component exists without a backend")
	}
	if g.panel.callCount() != 0 {
		t.Fatal("the panel was polled without a backend")
	}
	g.fw.mu.Lock()
	defer g.fw.mu.Unlock()
	for _, c := range g.fw.calls {
		// Only the dry-run check and tool probes are allowed.
		if strings.HasPrefix(c, "nft -f") || strings.Contains(c, "restore") || strings.Contains(c, " -I ") || strings.Contains(c, " -A ") || strings.Contains(c, " delete ") {
			t.Fatalf("a state-changing command ran without a backend: %q", c)
		}
	}
}

func TestPortHopNotOfferedOnAnUnsupportedPlatform(t *testing.T) {
	g := newHopRig(t, t.TempDir(), hopConfig(nil), time.Hour)
	g.rt.portHopPlatform = func(bool) bool { return false }
	g.start(t)

	if len(g.fw.calls) != 0 || g.rt.PortHop != nil || hasCap(runtimeStreams{rt: g.rt}.Capabilities(), wsproto.CapPortHop) {
		t.Fatalf("port hopping started on an unsupported platform (calls %v)", g.fw.calls)
	}
}

func TestPortHopNotOfferedWithoutMachineNodes(t *testing.T) {
	cfg := hopConfig(nil)
	cfg.Panel.MachineNodes = false
	g := newHopRig(t, t.TempDir(), cfg, time.Hour)
	g.start(t)

	if len(g.fw.calls) != 0 || g.rt.PortHop != nil {
		t.Fatal("port hopping started without machine nodes")
	}
}

func TestPortHopComponentShape(t *testing.T) {
	g := newHopRig(t, t.TempDir(), hopConfig(nil), 10*time.Millisecond)
	g.panel.set(hopDoc("v1", hopRule12), nil)
	g.start(t)
	waitHop(t, "install", func() bool { return g.fw.tables() > 0 })
	waitHop(t, "the status snapshot", func() bool {
		c := g.rt.portHopComponent()
		return c != nil && len(c.Instances) == 1
	})

	comps := runtimeProbe{rt: g.rt}.ServiceComponents()
	var got *wsproto.Component
	for i := range comps {
		if comps[i].Name == "porthop" {
			got = &comps[i]
		}
	}
	if got == nil {
		t.Fatalf("no porthop component in %+v", comps)
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["name"] != "porthop" || m["kind"] != "firewall" || m["state"] != "running" || m["runtime_version"] != "nftables" {
		t.Fatalf("component = %s", b)
	}
	insts, _ := m["instances"].([]any)
	if len(insts) != 1 {
		t.Fatalf("instances = %s", b)
	}
	in, _ := insts[0].(map[string]any)
	if in["id"] != "node12" || in["state"] != "running" {
		t.Fatalf("instance = %v", in)
	}
	if _, has := m["last_error"]; has {
		t.Fatalf("last_error on a healthy component: %s", b)
	}
}

func TestPortHopRefusedRuleIsAFailedInstance(t *testing.T) {
	g := newHopRig(t, t.TempDir(), hopConfig(nil), 10*time.Millisecond)
	// A local forward owns UDP port 20005 inside the hop range.
	g.rt.Reconciler.Ports.Commit([]driver.PortClaim{{Proto: "udp", Addr: "0.0.0.0", Port: 20005, Owner: "fwd1"}})
	g.panel.set(hopDoc("v1", hopRule12), nil)
	g.start(t)

	waitHop(t, "the refusal to be reported", func() bool {
		c := g.rt.portHopComponent()
		return c != nil && len(c.Instances) == 1
	})
	c := g.rt.portHopComponent()
	if c.Instances[0].ID != "node12" || c.Instances[0].State != wsproto.StateFailed {
		t.Fatalf("instance = %+v", c.Instances[0])
	}
	if !strings.Contains(c.LastError, "node 12") || !strings.Contains(c.LastError, "20005") {
		t.Fatalf("last_error = %q", c.LastError)
	}
	if g.fw.tables() != 0 {
		t.Fatal("a refused rule was installed")
	}
}

func TestPortHopCapabilityIsInTheClosedSet(t *testing.T) {
	if !hasCap(wsproto.CapabilitiesAll, wsproto.CapPortHop) || wsproto.CapPortHop != "port_hop" {
		t.Fatalf("CapPortHop = %q not in CapabilitiesAll", wsproto.CapPortHop)
	}
}
