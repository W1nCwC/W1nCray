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

// indexComponents maps the reported components by name and fails when a name
// is reported twice: the contract allows exactly one Component per name.
func indexComponents(t *testing.T, items []wsproto.Component) map[string]wsproto.Component {
	t.Helper()
	byName := make(map[string]wsproto.Component, len(items))
	for _, it := range items {
		if _, dup := byName[it.Name]; dup {
			t.Fatalf("component %q reported twice: %+v", it.Name, items)
		}
		byName[it.Name] = it
	}
	return byName
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

// A service kernel is listed once per installed version, but the contract
// allows one component per name: the installed-kernel list must not duplicate
// the service component the service manager already describes.
func TestComponentsReportOneComponentPerServiceKernelName(t *testing.T) {
	p := &fakeProbe{
		kernels: []wsproto.KernelEntry{
			{Name: "xray", Version: "0.8.2", Current: true},
			{Name: "xray", Version: "0.6.0", Previous: true},
		},
		services: []wsproto.Component{{
			Name: "xray", Kind: "kernel", Version: "0.8.2", State: wsproto.StateRunning, UptimeS: 30,
			Instances: []wsproto.ComponentInstance{{ID: "node1@m1", State: wsproto.StateRunning, Conns: 3}},
		}},
	}
	got := New(Options{AgentVersion: "v", Components: p}).Components(context.Background())

	byName := indexComponents(t, got.Items) // fails on the duplicated xray
	if len(got.Items) != 2 {
		t.Fatalf("items = %+v, want the agent and one xray", got.Items)
	}
	if got.Items[0].Name != "agent" || got.Items[1].Name != "xray" {
		t.Fatalf("component order = %v, want [agent xray]", []string{got.Items[0].Name, got.Items[1].Name})
	}
	x := byName["xray"]
	if x.State != wsproto.StateRunning || x.Version != "0.8.2" || x.UptimeS != 30 {
		t.Fatalf("xray component = %+v, want the service-manager view", x)
	}
	if len(x.Instances) != 1 || x.Instances[0].ID != "node1@m1" {
		t.Fatalf("xray instances = %+v", x.Instances)
	}
}

// One name, one component: the version shown is the one the current pointer
// selects, and without a current pointer the highest installed version.
func TestComponentsPreferCurrentThenHighestInstalledVersion(t *testing.T) {
	cases := []struct {
		name    string
		kernels []wsproto.KernelEntry
		want    string
	}{
		{
			// The installed list is version-descending, so the current
			// version comes first and the older one must not win.
			"current beats an older version",
			[]wsproto.KernelEntry{
				{Name: "gost", Version: "3.1.0", Current: true},
				{Name: "gost", Version: "3.0.0", Previous: true},
			},
			"3.1.0",
		},
		{
			// Numeric, not lexicographic: 2.10.0 > 2.9.0.
			"highest version when nothing is current",
			[]wsproto.KernelEntry{
				{Name: "realm", Version: "2.10.0"},
				{Name: "realm", Version: "2.9.0"},
			},
			"2.10.0",
		},
		{
			"current beats a higher version",
			[]wsproto.KernelEntry{
				{Name: "frp", Version: "1.2.0", Current: true},
				{Name: "frp", Version: "1.3.0"},
			},
			"1.2.0",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name := tc.kernels[0].Name
			p := &fakeProbe{kernels: tc.kernels}
			got := New(Options{AgentVersion: "v", Components: p}).Components(context.Background())

			byName := indexComponents(t, got.Items)
			if len(got.Items) != 2 {
				t.Fatalf("items = %+v, want the agent and one %s", got.Items, name)
			}
			comp, ok := byName[name]
			if !ok {
				t.Fatalf("no %s component: %+v", name, got.Items)
			}
			if comp.State != wsproto.StateStopped {
				t.Fatalf("%s state = %q, want %q (installed, not selected)", name, comp.State, wsproto.StateStopped)
			}
			if comp.Version != tc.want {
				t.Fatalf("%s version = %q, want %q", name, comp.Version, tc.want)
			}
			if comp.Instances == nil || len(comp.Instances) != 0 {
				t.Fatalf("%s instances = %+v, want an empty list", name, comp.Instances)
			}
		})
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
