package telemetry

import (
	"math"
	"sort"
	"time"

	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// ComponentProbe is what telemetry needs from the agent runtime. bootstrap
// implements it; the interface exists so telemetry never imports bootstrap,
// which imports panelclient and would make the dependency circular.
type ComponentProbe interface {
	// SupervisedProcesses lists the kernel processes the agent started.
	SupervisedProcesses() []SupervisedProcess
	// InstalledKernels lists the kernel binaries installed on this machine.
	InstalledKernels() []wsproto.KernelEntry
	// ServiceComponents lists the kernels that run as their own service (the
	// Xray kernel), with the state the service manager reports and the node
	// list the kernel's status endpoint reports. A machine without such a
	// kernel returns nil.
	ServiceComponents() []wsproto.Component
}

// SupervisedProcess is one kernel instance as the agent runtime sees it.
// Driver, SupervisorID and Version are computed by bootstrap: telemetry must
// not hardcode the per-driver supervisor id prefixes ("gost/main", "realm/<id>",
// "frp/frps-<id>") or the version of the embedded engine.
type SupervisedProcess struct {
	InstanceID   string
	Driver       string // xray | gost | frp | realm
	SupervisorID string
	Version      string // kernel version; empty when unknown
	Running      bool
	// PID is 0 for a process that lives inside the agent (the embedded xray
	// engine): such a component must not claim a PID, CPU or RSS of its own
	// (design R7).
	PID      int
	Restarts int
	Since    time.Time
	// Counters are the per-instance traffic counters the reconciler observed.
	// Their zero values stay off the wire (omitempty on ComponentInstance).
	Conns     uint64
	UpBytes   uint64
	DownBytes uint64
}

// componentsFrom builds the whole component list: the agent itself first, then
// one component per kernel the runtime knows about, in a stable order.
func (c *Collector) componentsFrom(now time.Time) []wsproto.Component {
	items := make([]wsproto.Component, 0, 5)
	c.field("component agent", func() {
		comp := wsproto.Component{
			Name:      "agent",
			Kind:      "agent",
			Version:   c.agentVersion,
			State:     wsproto.StateRunning,
			Instances: []wsproto.ComponentInstance{}, // an array on the wire, never null
		}
		if rss, ok := selfRSSBytes(); ok {
			comp.RSS = rss
		}
		items = append(items, comp)
	})

	if c.probe == nil {
		return items
	}

	var procs []SupervisedProcess
	c.field("supervised processes", func() { procs = c.probe.SupervisedProcesses() })
	var kernels []wsproto.KernelEntry
	c.field("installed kernels", func() { kernels = c.probe.InstalledKernels() })

	byDriver := make(map[string][]SupervisedProcess, len(procs))
	var names []string
	for _, p := range procs {
		if p.Driver == "" {
			continue
		}
		if _, ok := byDriver[p.Driver]; !ok {
			names = append(names, p.Driver)
		}
		byDriver[p.Driver] = append(byDriver[p.Driver], p)
	}

	installed := make(map[string]wsproto.KernelEntry, len(kernels))
	for _, k := range kernels {
		if k.Name == "" {
			continue
		}
		installed[k.Name] = k
		if _, ok := byDriver[k.Name]; !ok {
			names = append(names, k.Name)
		}
	}

	// A kernel that runs as its own service (the Xray kernel) has no
	// supervised process; its component comes from the service manager and the
	// kernel's status endpoint instead.
	var services []wsproto.Component
	c.field("service components", func() { services = c.probe.ServiceComponents() })
	serviceByName := make(map[string]wsproto.Component, len(services))
	for _, comp := range services {
		if comp.Name == "" {
			continue
		}
		serviceByName[comp.Name] = comp
		if _, ok := byDriver[comp.Name]; !ok {
			if _, ok := installed[comp.Name]; !ok {
				names = append(names, comp.Name)
			}
		}
	}

	sort.Strings(names)
	for _, name := range names {
		c.field("component "+name, func() {
			if comp, ok := serviceByName[name]; ok {
				items = append(items, comp)
				return
			}
			items = append(items, componentFor(name, byDriver[name], installed[name], now))
		})
	}
	return items
}

// componentFor folds the supervised processes of one driver into the single
// Component the contract allows per name.
func componentFor(name string, procs []SupervisedProcess, inst wsproto.KernelEntry, now time.Time) wsproto.Component {
	comp := wsproto.Component{Name: name, Kind: "kernel"}
	instances := make([]wsproto.ComponentInstance, 0, len(procs))
	running := false

	sorted := append([]SupervisedProcess(nil), procs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].SupervisorID < sorted[j].SupervisorID })

	for _, p := range sorted {
		state := wsproto.StateStopped
		if p.Running {
			state = wsproto.StateRunning
			running = true
		}
		instances = append(instances, wsproto.ComponentInstance{
			ID:        p.InstanceID,
			State:     state,
			Conns:     clampInt(p.Conns),
			UpBytes:   p.UpBytes,
			DownBytes: p.DownBytes,
		})
		if comp.Version == "" {
			comp.Version = p.Version
		}
		if comp.PID == 0 && p.PID > 0 {
			comp.PID = p.PID
		}
		if p.Restarts > comp.Restarts {
			comp.Restarts = p.Restarts
		}
		if p.Running && comp.UptimeS == 0 && !p.Since.IsZero() {
			if up := int64(now.Sub(p.Since).Seconds()); up > 0 {
				comp.UptimeS = up
			}
		}
	}
	sort.Slice(instances, func(i, j int) bool { return instances[i].ID < instances[j].ID })
	if instances == nil {
		instances = []wsproto.ComponentInstance{} // the contract says an array, never null
	}
	comp.Instances = instances

	switch {
	case running:
		comp.State = wsproto.StateRunning
	case len(procs) > 0:
		comp.State = wsproto.StateStopped
	case inst.Name != "":
		// Installed but never selected by desired: present and not running,
		// which is "stopped", not "not installed".
		comp.State = wsproto.StateStopped
		comp.Version = inst.Version
	default:
		comp.State = wsproto.StateNotInstalled
	}
	return comp
}

// clampInt narrows a counter to int for the wire type; a 32-bit agent must not
// wrap a large connection count into a negative one.
func clampInt(v uint64) int {
	if v > math.MaxInt {
		return math.MaxInt
	}
	return int(v)
}
