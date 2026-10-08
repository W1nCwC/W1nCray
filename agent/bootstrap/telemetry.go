// This file adapts a booted Runtime to what the WebSocket channel needs: the
// telemetry streams (device, load, components), the local policy the panel may
// display, and the capability list. It is in bootstrap because bootstrap is the
// only layer that sees the reconciler, the supervisor and the kernel manager at
// once (design section 2.11).

package bootstrap

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/W1nCwC/W1nCray/agent/agentcfg"
	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/opscmd"
	"github.com/W1nCwC/W1nCray/agent/panelclient"
	"github.com/W1nCwC/W1nCray/agent/reconcile"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/agent/telemetry"
	"github.com/W1nCwC/W1nCray/agent/ws"
	"github.com/W1nCwC/W1nCray/agent/wsproto"
	"github.com/W1nCwC/W1nCray/agent/xrayapi"
)

// Supervisor id prefixes used by the engine drivers. The drivers keep their
// own ids unexported, so bootstrap recomputes them here; telemetry never sees
// them (design section 2.11).
const (
	gostSupervisorID      = "gost/main" // driver/gost/state.go
	realmSupervisorPrefix = "realm/"    // driver/realm/realm.go
	frpSupervisorPrefix   = "frp/frp"   // driver/frp/apply.go: frps-<id> / frpc-<id>
)

// errXrayNodesDisabled is returned by the nodes hint when the local module gate
// is off. A remote hint can never turn the module on (protocol ruling 13).
var errXrayNodesDisabled = errors.New("xray nodes are disabled locally (Modules.XrayNodes)")

// Streams adapts a booted Runtime to ws.Streams. The device and load samples
// come from the shared Collector, the policy from the local agent.yml, and the
// kernel list from the runtime's kernel manager. A nil Collector builds one
// (the same runtime adapters are used either way).
func (r *Runtime) Streams(c *telemetry.Collector, cfg *agentcfg.Config) ws.Streams {
	if c == nil {
		c = telemetry.New(telemetry.Options{
			Log:        r.log,
			Components: r.ComponentProbe(),
		})
	}
	return runtimeStreams{rt: r, collector: c, cfg: cfg}
}

// runtimeStreams implements ws.Streams on top of a booted Runtime.
type runtimeStreams struct {
	rt        *Runtime
	collector *telemetry.Collector
	cfg       *agentcfg.Config
}

var _ ws.Streams = runtimeStreams{}

func (s runtimeStreams) HostInfo(ctx context.Context) wsproto.HostInfo {
	return s.collector.HostInfo(ctx)
}

func (s runtimeStreams) Telemetry(ctx context.Context) wsproto.Telemetry {
	return s.collector.Telemetry(ctx)
}

func (s runtimeStreams) Components(ctx context.Context) wsproto.Components {
	return s.collector.Components(ctx)
}

// Kernels lists the installed external kernels. The embedded xray engine is not
// a kernel and is not listed (it is a component of the agent).
func (s runtimeStreams) Kernels() []wsproto.KernelEntry { return s.rt.installedKernels() }

// Policy is the part of the LOCAL policy the panel may display. The panel can
// never relax it (protocol ruling 13).
func (s runtimeStreams) Policy() wsproto.Policy { return localPolicy(s.cfg, s.openWrtPlatform()) }

// openWrtPlatform reports the platform fact the policy report needs. A runtime
// built without Boot (tests) is treated as non-OpenWrt, which is the
// conservative answer: the firewall automation is reported off.
func (s runtimeStreams) openWrtPlatform() bool { return s.rt != nil && s.rt.openWrt }

// Capabilities returns a copy: the caller must not be able to mutate the list
// the hello is built from. It is computed on every call, because the list can
// change while the agent runs: a signed manifest arriving later is what makes
// the kernel commands servable, and the panel must see the new list without a
// restart.
func (s runtimeStreams) Capabilities() []string {
	caps := capabilities(s.cfg, s.rt.kernelCapable(), s.rt.TerminalSupported(), s.rt.filesCapable())
	// upgrade is a promise that self_update is served here: the command is
	// registered only when the executable is replaceable in place, a service
	// manager runs it and the process has a restart hook (protocol ruling 11).
	if s.rt.upgradeCapable() {
		caps = append(caps, wsproto.CapUpgrade)
	}
	return caps
}

// TerminalSupported reports whether this machine can really serve a terminal
// session: the local switch is on and a PTY exists (WP-G6 acceptance 3).
func (s runtimeStreams) TerminalSupported() bool { return s.rt.TerminalSupported() }

// TerminalSessions is the optional ws.SessionCounter extension: the number of
// live interactive terminal sessions. The capability watchdog uses it to defer
// a reconnect that would interrupt a user's shell until the session ends
// (CAP-RESEND). A runtime without a terminal manager reports none.
func (s runtimeStreams) TerminalSessions() int {
	if s.rt == nil || s.rt.Terminal == nil {
		return 0
	}
	return len(s.rt.Terminal.Sessions())
}

// capabilities lists what this machine can really do; the panel must not offer
// anything else (protocol ruling 1). telemetry is always there; xray_nodes only
// when the local module gate allows it (ruling 6); kernel only when the kernel
// installer can actually serve kernel_* commands; terminal only when the local
// switch is on and the platform has a PTY (ruling 17 + design section 6.8);
// files only when BOTH file features can be served (see filesCapable).
func capabilities(cfg *agentcfg.Config, kernel, term, files bool) []string {
	caps := []string{wsproto.CapTelemetry}
	if cfg.XrayNodesEnabled() {
		caps = append(caps, wsproto.CapXrayNodes)
	}
	if kernel {
		caps = append(caps, wsproto.CapKernel)
	}
	if term {
		caps = append(caps, wsproto.CapTerminal)
	}
	if files {
		caps = append(caps, wsproto.CapFiles)
	}
	return caps
}

// fileCapable reports whether the managed-file commands can really be served on
// this machine (ruling 1: a capability is a promise). It requires the file
// layer to be wired, a local Files policy that can reach the xray directory
// (at least one root, or Files.Unrestricted), and — because the panel must
// never overwrite the agent's own configuration — the separated agent.yml
// layout when config.yml is part of the set. The capability is about the xray
// files the panel manages, so the separated layout is required: with the
// single-file layout the panel would be handed a write path to the agent's own
// settings (ruling 2).
func (r *Runtime) fileCapable() bool {
	if r == nil || r.Files == nil || !r.Files.Enabled() {
		return false
	}
	if r.cfg == nil || r.cfg.Files == nil {
		return false
	}
	if len(r.cfg.Files.Roots) == 0 && !r.cfg.UnrestrictedEnabled() {
		return false
	}
	return r.Files.LayoutSeparated()
}

// kernelCapable reports whether the kernel installer can serve the kernel_*
// commands: an installer is wired and a signed manifest is in force. Without a
// manifest kernel_install cannot resolve a version and the catalog is empty, so
// the capability is not promised (a capability is a promise, ruling 1).
func (r *Runtime) kernelCapable() bool {
	if r == nil || r.Kernels == nil {
		return false
	}
	_, ok := r.Kernels.ManifestSequence()
	return ok
}

// upgradeCapable reports whether self_update is actually served here: the
// command is registered on the registry. Registration happens in StartRemote,
// and only when the machine can replace its own executable and the process
// owner supplied a restart hook, so the capability is never a promise the agent
// cannot keep.
func (r *Runtime) upgradeCapable() bool {
	return r != nil && r.Ops != nil && r.Ops.Has(panelclient.CmdSelfUpdate)
}

// TerminalSupported reports whether the runtime has a live terminal manager.
// The manager is nil when the local switch is off or the platform has no PTY,
// so this single check covers both (WP-G6 acceptance 3).
func (r *Runtime) TerminalSupported() bool {
	return r != nil && r.Terminal != nil && r.Terminal.Available()
}

// filesCapable reports whether the single contract capability "files" may be
// declared. The contract has ONE "files" name for two unrelated features:
//
//   - the managed xray files the panel puts in a revision (desired.files,
//     files_apply / files_validate / files_rollback, D4/D5), and
//   - the confined file_* commands (file_list / file_read / file_write /
//     file_delete, D9/WP-G6).
//
// The panel gates the desired.files key on this capability (protocol ruling 1)
// and the agent decodes a revision strictly, so declaring "files" when the
// managed layer is not wired would let the panel publish a key this machine
// cannot apply. The capability is therefore the CONJUNCTION: it is declared
// only when the managed layer is servable (fileCapable) AND the file_*
// commands are registered (fileCmdsCapable). In the panel's wiring the second
// condition is implied by the first (both read cfg.Files.Roots), so this only
// withholds the declaration where the managed layout is deliberately off.
//
// The contract has no field that tells the two apart (capabilities is a set,
// policy.files carries only roots/unrestricted), so this is the conservative
// stopgap: it never over-promises, and it is recorded in the merge report as
// the open protocol question.
func (r *Runtime) filesCapable() bool {
	return r.fileCapable() && r.fileCmdsCapable()
}

// fileCmdsCapable reports whether the file_* commands can be served: a manager
// exists and it can reach something — at least one root, or Files.Unrestricted
// (PLAN v10), where an empty root list is normal because the panel names
// absolute paths. A machine that can serve neither must not declare the
// capability, and the commands are not registered either.
func (r *Runtime) fileCmdsCapable() bool {
	return r != nil && r.FileOps != nil && (len(r.FileOps.RootNames()) > 0 || r.FileOps.Unrestricted())
}

// localPolicy maps the agent.yml local policy onto the wire type. A nil config
// keeps the accessors' defaults (the terminal gate off for a nil receiver, no
// file roots, the xray-nodes module on); a running agent always has a non-nil
// Config, whose terminal default is on. Files.Unrestricted is reported as the
// EFFECTIVE value (agentcfg resolves "not written" against the terminal gate
// and ResolveLocalPolicy materialises it), so the panel never has to redo the
// three-state rule. openWrt is the detected platform, which decides the
// effective Firewall.AutoOpen default.
func localPolicy(cfg *agentcfg.Config, openWrt bool) wsproto.Policy {
	pol := wsproto.Policy{
		Terminal: cfg.TerminalEnabled(),
		Modules:  wsproto.ModulePolicy{XrayNodes: cfg.XrayNodesEnabled()},
		Firewall: wsproto.FirewallPolicy{AutoOpen: cfg.FirewallAutoOpen(openWrt)},
		Kernels:  wsproto.KernelsPolicy{AllowHTTP: cfg.KernelsAllowHTTP()},
	}
	if cfg != nil && cfg.Files != nil {
		pol.Files = wsproto.FilesPolicy{
			Roots:        append([]string(nil), cfg.Files.Roots...),
			Unrestricted: cfg.UnrestrictedEnabled(),
		}
	}
	if cfg != nil {
		sp := cfg.PolicySpec()
		pol.Instances = &wsproto.InstancePolicy{
			AllowListen:     append([]string(nil), sp.AllowListen...),
			PortRange:       sp.PortRange,
			PrivilegedPorts: sp.PrivilegedPorts,
			DenyPorts:       append([]int(nil), sp.DenyPorts...),
			MaxInstances:    sp.MaxInstances,
			AllowEngines:    append([]string(nil), sp.AllowEngines...),
		}
	}
	return pol
}

// xrayNodeHint is the xray-nodes hook. A "nodes" hint makes the running kernel
// re-fetch this machine's node list from the panel now instead of at its next
// 60 s poll, and the kernel asks for a reload only when the list changed. The
// local module gate is enforced here: a hint can never turn the module on
// (protocol ruling 13).
//
// Every other outcome degrades to the poll instead of failing: a machine
// without the kernel (nil Service), a kernel that predates the route (HTTP 404)
// and an unreachable panel are all logged as a warning and return nil, so the
// hint never turns into a command failure or an agent crash.
type xrayNodeHint struct {
	enabled bool
	xray    xrayapi.Service
	log     driver.Logger
}

func (h xrayNodeHint) SyncXrayNodes(ctx context.Context) error {
	if !h.enabled {
		h.log.Warnf("bootstrap: xray nodes hint refused: Modules.XrayNodes is false on this machine")
		return errXrayNodesDisabled
	}
	if h.xray == nil {
		h.log.Warnf("bootstrap: xray nodes hint: the Xray kernel is not installed; falling back to its 60s machine-node poll")
		return nil
	}
	changed, err := h.xray.SyncMachineNodes(ctx)
	if err != nil {
		h.log.Warnf("bootstrap: xray nodes hint: %v; falling back to the kernel's 60s machine-node poll", err)
		return nil
	}
	if changed {
		h.log.Infof("bootstrap: xray nodes hint: the kernel's machine node list changed, reloading it now")
	} else {
		h.log.Infof("bootstrap: xray nodes hint: the kernel's machine node list is unchanged")
	}
	return nil
}

// ComponentProbe adapts a booted Runtime to telemetry.ComponentProbe.
func (r *Runtime) ComponentProbe() telemetry.ComponentProbe { return runtimeProbe{rt: r} }

type runtimeProbe struct{ rt *Runtime }

var _ telemetry.ComponentProbe = runtimeProbe{}

// InstalledKernels lists every installed kernel version. It reads the kernel
// directory, so it is only called by the hello and the components cadence.
func (p runtimeProbe) InstalledKernels() []wsproto.KernelEntry {
	return p.rt.installedKernels()
}

// SupervisedProcesses maps the instances of the last apply onto the supervisor.
// The reconciler reports what is running; the supervisor supplies the process
// details. The embedded xray engine shares the agent process and therefore
// reports no PID of its own (protocol ruling 2).
func (p runtimeProbe) SupervisedProcesses() []telemetry.SupervisedProcess {
	if p.rt == nil || p.rt.Reconciler == nil {
		return nil
	}
	rep, ok := p.rt.Reconciler.Last()
	if !ok {
		return nil
	}
	out := make([]telemetry.SupervisedProcess, 0, len(rep.Instances))
	for _, in := range rep.Instances {
		if in.State != reconcile.StateRunning {
			continue
		}
		sp := telemetry.SupervisedProcess{
			InstanceID: in.ID,
			Driver:     in.Engine,
			Version:    kernelVersion(rep, in.Engine),
			// The reconciler reported this instance running; the supervisor
			// below refines it when it knows the process.
			Running: true,
		}
		switch in.Engine {
		case spec.EngineGost:
			sp.SupervisorID = gostSupervisorID
		case spec.EngineRealm:
			sp.SupervisorID = realmSupervisorPrefix + in.ID
		case spec.EngineFrp:
			sp.SupervisorID = p.frpSupervisorID(in.ID)
		}
		if sp.SupervisorID != "" && p.rt.Sup != nil {
			if st := p.rt.Sup.Status(sp.SupervisorID); st.PID > 0 || st.Running || st.Restarts > 0 || !st.Since.IsZero() {
				sp.PID, sp.Restarts, sp.Since = st.PID, st.Restarts, st.Since
			}
		}
		out = append(out, sp)
	}
	return out
}

// ServiceComponents returns one component per kernel that runs as its own
// service (the Xray kernel). The state and backend come from the service
// manager, the version, node list, online users and last error from the
// kernel's status endpoint. A machine without such a kernel returns nil.
func (p runtimeProbe) ServiceComponents() []wsproto.Component {
	if p.rt == nil || p.rt.XrayManager == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	st, err := p.rt.XrayManager.Status(ctx)
	if err != nil {
		return nil
	}
	comp := wsproto.Component{
		Name:      xrayapi.KernelName,
		Kind:      "kernel",
		Version:   st.Version,
		State:     st.State,
		Instances: []wsproto.ComponentInstance{},
	}
	if p.rt.Xray != nil {
		if ks, kerr := p.rt.Xray.Status(ctx); kerr == nil {
			if comp.Version == "" {
				comp.Version = ks.Version
			}
			if ks.StartedAt > 0 {
				if up := time.Now().Unix() - ks.StartedAt; up > 0 {
					comp.UptimeS = up
				}
			}
			insts := make([]wsproto.ComponentInstance, 0, len(ks.Nodes))
			for _, n := range ks.Nodes {
				state := wsproto.StateRunning
				if n.Error != "" {
					state = wsproto.StateFailed
				}
				insts = append(insts, wsproto.ComponentInstance{
					ID:    n.Tag,
					State: state,
					// Conns carries the node's online-user count: the wire
					// instance has no user field, and this is the number the
					// panel shows next to a node.
					Conns: n.Online,
				})
			}
			comp.Instances = insts
			comp.LastError = ks.LastError
			if !ks.Running {
				comp.State = wsproto.StateFailed
			}
		}
	}
	return []wsproto.Component{comp}
}

// frpSupervisorID finds the supervisor id of one frp instance. The role (portal
// vs bridge) decides between the frps- and frpc- prefixes and is not part of
// the report, so the supervisor's own id list is searched instead of guessing.
func (p runtimeProbe) frpSupervisorID(instanceID string) string {
	if p.rt.Sup == nil {
		return ""
	}
	suffix := "-" + instanceID
	for _, id := range p.rt.Sup.IDs() {
		if strings.HasPrefix(id, frpSupervisorPrefix) && strings.HasSuffix(id, suffix) {
			return id
		}
	}
	return ""
}

// kernelVersion returns the kernel version in use by an engine. The embedded
// engine's "builtin" marker is not a version and is left out.
func kernelVersion(rep reconcile.Report, engine string) string {
	v := rep.Kernels[engine]
	if v == reconcile.BuiltinVersion {
		return ""
	}
	return v
}

// KernelEntries lists the installed kernels in the contract's structured shape
// (hello.kernels, /config and /report's "kernel_entries"). "In use" is the
// version a live managed process executes when the platform can verify it, and
// otherwise falls back to the current pointer (design section 3.2). A runtime
// without a kernel manager yields no entries.
func (r *Runtime) KernelEntries() ([]wsproto.KernelEntry, error) {
	if r == nil || r.Kernels == nil {
		return nil, nil
	}
	list, err := r.Kernels.List()
	if err != nil {
		return nil, err
	}
	out := make([]wsproto.KernelEntry, 0, len(list))
	running := map[string]string{}
	exact := map[string]bool{}
	for _, e := range list {
		if _, seen := exact[e.Name]; !seen {
			v, ex := r.Kernels.RunningVersion(e.Name)
			running[e.Name], exact[e.Name] = v, ex
		}
		entry := wsproto.KernelEntry{
			Name:      e.Name,
			Version:   e.Version,
			Current:   e.Current,
			Previous:  e.Previous,
			Path:      e.Path,
			SizeBytes: e.Size,
			// One rule for kernel_list and hello/report (opscmd.InUse).
			InUse: opscmd.InUse(e, running[e.Name], exact[e.Name]),
		}
		if e.Name == xrayapi.KernelName && r.XrayManager != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			if st, serr := r.XrayManager.Status(ctx); serr == nil {
				entry.Service = &wsproto.KernelService{Backend: st.Backend, State: st.State, ManagedBy: st.ManagedBy}
			}
			cancel()
		}
		if !e.InstalledAt.IsZero() {
			entry.InstalledAt = e.InstalledAt.Unix()
		}
		out = append(out, entry)
	}
	return out, nil
}

// installedKernels is the hello/components view of KernelEntries: a collection
// failure is logged and reported as an empty list, never as an invented entry.
func (r *Runtime) installedKernels() []wsproto.KernelEntry {
	entries, err := r.KernelEntries()
	if err != nil {
		r.warnf("bootstrap: listing the installed kernels: %v", err)
		return nil
	}
	return entries
}

// warnf logs through the runtime's logger, tolerating a Runtime built without
// Boot (tests).
func (r *Runtime) warnf(format string, args ...any) {
	if r.log != nil {
		r.log.Warnf(format, args...)
	}
}
