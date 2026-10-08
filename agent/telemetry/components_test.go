package telemetry

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// fakeProbe is the runtime side of the components message.
type fakeProbe struct {
	procs      []SupervisedProcess
	kernels    []wsproto.KernelEntry
	services   []wsproto.Component
	panicProcs bool
	panicKern  bool
	panicSvc   bool
}

func (p *fakeProbe) SupervisedProcesses() []SupervisedProcess {
	if p.panicProcs {
		panic("probe exploded")
	}
	return p.procs
}

func (p *fakeProbe) InstalledKernels() []wsproto.KernelEntry {
	if p.panicKern {
		panic("kernel list exploded")
	}
	return p.kernels
}

func (p *fakeProbe) ServiceComponents() []wsproto.Component {
	if p.panicSvc {
		panic("service components exploded")
	}
	return p.services
}

func TestComponentsWithNilProbeReportsTheAgent(t *testing.T) {
	swap(t, &selfRSSBytes, func() (uint64, bool) { return 4096, true })
	got := New(Options{AgentVersion: "1.2.3"}).Components(context.Background())
	if len(got.Items) != 1 {
		t.Fatalf("items = %+v, want only the agent", got.Items)
	}
	agent := got.Items[0]
	if agent.Name != "agent" || agent.Kind != "agent" || agent.State != wsproto.StateRunning {
		t.Fatalf("agent component = %+v", agent)
	}
	if agent.Version != "1.2.3" || agent.RSS != 4096 {
		t.Fatalf("agent version/rss = %q/%d", agent.Version, agent.RSS)
	}
	if agent.PID != 0 {
		t.Fatalf("agent PID = %d, want 0: the contract does not ask for it", agent.PID)
	}
}

func TestComponentsWithoutRSSProbe(t *testing.T) {
	swap(t, &selfRSSBytes, func() (uint64, bool) { return 0, false })
	got := New(Options{}).Components(context.Background())
	if len(got.Items) != 1 || got.Items[0].RSS != 0 {
		t.Fatalf("items = %+v, want one agent without RSS", got.Items)
	}
}

func TestComponentForStates(t *testing.T) {
	now := time.Unix(1000, 0)
	cases := []struct {
		name  string
		procs []SupervisedProcess
		inst  wsproto.KernelEntry
		want  string
	}{
		{"running", []SupervisedProcess{{InstanceID: "a", Running: true}}, wsproto.KernelEntry{}, wsproto.StateRunning},
		{"stopped", []SupervisedProcess{{InstanceID: "a"}}, wsproto.KernelEntry{}, wsproto.StateStopped},
		{"installed but not selected", nil, wsproto.KernelEntry{Name: "gost", Version: "3.3"}, wsproto.StateStopped},
		{"unknown", nil, wsproto.KernelEntry{}, wsproto.StateNotInstalled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := componentFor("gost", tc.procs, tc.inst, now)
			if got.State != tc.want {
				t.Fatalf("state = %q, want %q", got.State, tc.want)
			}
			if got.Kind != "kernel" || got.Name != "gost" {
				t.Fatalf("component = %+v", got)
			}
			if got.Instances == nil {
				t.Fatal("instances = nil, want an empty list on the wire")
			}
		})
	}
}

// R7: the embedded engine has no process of its own, so it must not claim a
// PID, CPU or RSS.
func TestComponentForEmbeddedEngineHasNoProcessResources(t *testing.T) {
	now := time.Unix(1000, 0)
	procs := []SupervisedProcess{{
		InstanceID: "xray-main",
		Driver:     "xray",
		Version:    "builtin",
		Running:    true,
		PID:        0,
		Since:      now.Add(-time.Minute),
	}}
	got := componentFor("xray", procs, wsproto.KernelEntry{}, now)
	if got.State != wsproto.StateRunning || got.Version != "builtin" {
		t.Fatalf("component = %+v", got)
	}
	if got.PID != 0 || got.RSS != 0 || got.CPUPct != 0 {
		t.Fatalf("embedded engine claims process resources: %+v", got)
	}
	if got.UptimeS != 60 {
		t.Fatalf("uptime = %d, want 60", got.UptimeS)
	}
}

func TestComponentForExternalProcess(t *testing.T) {
	now := time.Unix(1000, 0)
	procs := []SupervisedProcess{{
		InstanceID: "gost-1",
		Driver:     "gost",
		Version:    "3.3.0",
		Running:    true,
		PID:        4242,
		Restarts:   3,
		Since:      now.Add(-90 * time.Second),
		Conns:      11,
		UpBytes:    1000,
		DownBytes:  2000,
	}}
	got := componentFor("gost", procs, wsproto.KernelEntry{}, now)
	if got.PID != 4242 || got.Restarts != 3 || got.UptimeS != 90 || got.Version != "3.3.0" {
		t.Fatalf("component = %+v", got)
	}
	if len(got.Instances) != 1 {
		t.Fatalf("instances = %+v", got.Instances)
	}
	inst := got.Instances[0]
	if inst.ID != "gost-1" || inst.State != wsproto.StateRunning {
		t.Fatalf("instance = %+v", inst)
	}
	if inst.Conns != 11 || inst.UpBytes != 1000 || inst.DownBytes != 2000 {
		t.Fatalf("instance counters = %+v", inst)
	}
}

func TestComponentCountersClampOn32Bit(t *testing.T) {
	got := componentFor("frp", []SupervisedProcess{{
		InstanceID: "frps-1",
		Running:    true,
		Conns:      math.MaxUint64,
	}}, wsproto.KernelEntry{}, time.Unix(1000, 0))
	if got.Instances[0].Conns != math.MaxInt {
		t.Fatalf("conns = %d, want the int maximum %d", got.Instances[0].Conns, math.MaxInt)
	}
}

func TestComponentsAreSortedAndIncludeInstalledKernels(t *testing.T) {
	p := &fakeProbe{
		procs: []SupervisedProcess{
			{InstanceID: "z", Driver: "xray", SupervisorID: "b", Running: true},
			{InstanceID: "a", Driver: "xray", SupervisorID: "a"},
			{InstanceID: "g", Driver: "gost", SupervisorID: "gost/main", Running: true},
		},
		kernels: []wsproto.KernelEntry{
			{Name: "realm", Version: "2.0"},
			{Name: "xray", Version: "should-not-override"},
		},
	}
	got := New(Options{AgentVersion: "v", Components: p}).Components(context.Background())

	var names []string
	for _, item := range got.Items {
		names = append(names, item.Name)
	}
	want := []string{"agent", "gost", "realm", "xray"}
	if len(names) != len(want) {
		t.Fatalf("component names = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("component names = %v, want %v", names, want)
		}
	}

	// xray is running, so its component version comes from the process, not
	// from the installed-kernel list.
	for _, item := range got.Items {
		if item.Name == "xray" {
			if item.State != wsproto.StateRunning {
				t.Fatalf("xray state = %q", item.State)
			}
			if len(item.Instances) != 2 || item.Instances[0].ID != "a" || item.Instances[1].ID != "z" {
				t.Fatalf("xray instances = %+v, want sorted by id", item.Instances)
			}
		}
		if item.Name == "realm" && item.State != wsproto.StateStopped {
			t.Fatalf("realm state = %q, want stopped (installed, not selected)", item.State)
		}
	}
}

// TestServiceComponentComesFromTheServiceManager covers the Xray kernel, which
// runs as its own service: its component is the one the service manager and the
// kernel's status endpoint describe, not the supervised-process view.
func TestServiceComponentComesFromTheServiceManager(t *testing.T) {
	p := &fakeProbe{
		kernels: []wsproto.KernelEntry{{Name: "xray", Version: "0.6.0", Current: true}},
		services: []wsproto.Component{{
			Name: "xray", Kind: "kernel", Version: "0.6.0", State: wsproto.StateRunning, UptimeS: 12,
			Instances: []wsproto.ComponentInstance{{ID: "node1@m1", State: wsproto.StateRunning, Conns: 3}},
		}},
	}
	got := New(Options{AgentVersion: "v", Components: p}).Components(context.Background())
	byName := map[string]wsproto.Component{}
	for _, it := range got.Items {
		byName[it.Name] = it
	}
	x, ok := byName["xray"]
	if !ok {
		t.Fatalf("no xray component: %+v", got.Items)
	}
	if x.State != wsproto.StateRunning || x.Version != "0.6.0" || x.UptimeS != 12 {
		t.Fatalf("xray component = %+v", x)
	}
	if len(x.Instances) != 1 || x.Instances[0].ID != "node1@m1" || x.Instances[0].Conns != 3 {
		t.Fatalf("xray instances = %+v", x.Instances)
	}

	// A kernel that is not installed at all is still reported (state
	// not_installed) because the service manager knows about it.
	p2 := &fakeProbe{services: []wsproto.Component{{
		Name: "xray", Kind: "kernel", State: wsproto.StateNotInstalled,
		Instances: []wsproto.ComponentInstance{},
	}}}
	got = New(Options{AgentVersion: "v", Components: p2}).Components(context.Background())
	found := false
	for _, it := range got.Items {
		if it.Name == "xray" {
			found = true
			if it.State != wsproto.StateNotInstalled {
				t.Fatalf("xray state = %q", it.State)
			}
		}
	}
	if !found {
		t.Fatalf("an uninstalled service kernel must still be listed: %+v", got.Items)
	}
}

func TestPanicInInstalledKernelsKeepsSupervisedDrivers(t *testing.T) {
	log := &fakeLogger{}
	p := &fakeProbe{
		procs:     []SupervisedProcess{{InstanceID: "g", Driver: "gost", Running: true}},
		panicKern: true,
	}
	got := New(Options{Log: log, Components: p}).Components(context.Background())
	var names []string
	for _, item := range got.Items {
		names = append(names, item.Name)
	}
	if len(names) != 2 || names[0] != "agent" || names[1] != "gost" {
		t.Fatalf("components = %v, want [agent gost]", names)
	}
	if !log.contains("installed kernels") {
		t.Fatalf("no warning for the panicking probe: %v", log.warns)
	}
}

func TestComponentsTimestamp(t *testing.T) {
	c := New(Options{Now: func() time.Time { return time.Unix(1234, 0) }})
	if got := c.Components(context.Background()); got.TS != 1234 {
		t.Fatalf("ts = %d, want 1234", got.TS)
	}
}
