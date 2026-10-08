package bootstrap

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/agentcfg"
	"github.com/W1nCwC/W1nCray/agent/telemetry"
	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

func boolPtr(v bool) *bool { return &v }

// capabilitiesOf is the capability list the hello would carry for cfg.
func capabilitiesOf(t *testing.T, rt *Runtime, cfg *agentcfg.Config) []string {
	t.Helper()
	return rt.Streams(nil, cfg).Capabilities()
}

// TestCapabilitiesOnlyDeclareWhatIsImplemented covers protocol ruling 1: the
// hello capability list is a promise. The local gates decide what is promised:
// xray_nodes follows Modules.XrayNodes (ruling 6), kernel needs a usable
// installer, terminal needs the local switch on AND a PTY on this machine
// (ruling 17 plus design section 6.8), upgrade needs a registered self_update
// (ruling 11) and files needs both file features (managed xray files, D4/D5,
// and the file_* commands, D9; see filesCapable). A capability must never
// appear for something the machine cannot serve.
func TestCapabilitiesOnlyDeclareWhatIsImplemented(t *testing.T) {
	rt, _ := bootCycle(t, t.TempDir(), false, nil)

	// The pure decision: only the local gates differ.
	pure := []struct {
		name             string
		cfg              *agentcfg.Config
		kernel, term, fl bool
		want             []string
	}{
		{"nothing but telemetry", &agentcfg.Config{Modules: &agentcfg.ModuleConfig{XrayNodes: boolPtr(false)}}, false, false, false,
			[]string{wsproto.CapTelemetry}},
		{"module on", &agentcfg.Config{}, false, false, false,
			[]string{wsproto.CapTelemetry, wsproto.CapXrayNodes}},
		{"all gates on", &agentcfg.Config{}, true, true, true,
			[]string{wsproto.CapTelemetry, wsproto.CapXrayNodes, wsproto.CapKernel, wsproto.CapTerminal, wsproto.CapFiles}},
		{"terminal only", &agentcfg.Config{Modules: &agentcfg.ModuleConfig{XrayNodes: boolPtr(false)}}, false, true, false,
			[]string{wsproto.CapTelemetry, wsproto.CapTerminal}},
		{"files only", &agentcfg.Config{Modules: &agentcfg.ModuleConfig{XrayNodes: boolPtr(false)}}, false, false, true,
			[]string{wsproto.CapTelemetry, wsproto.CapFiles}},
	}
	for _, tc := range pure {
		t.Run("pure/"+tc.name, func(t *testing.T) {
			got := capabilities(tc.cfg, tc.kernel, tc.term, tc.fl)
			if !sameStrings(got, tc.want) {
				t.Fatalf("capabilities = %v, want %v", got, tc.want)
			}
		})
	}

	// The wired runtime: the terminal gate is the platform, and files follows
	// the configured roots. The test asserts the invariant, not a fixed list,
	// so it holds on a Windows machine without a PTY and on Linux alike.
	cfg := &agentcfg.Config{}
	got := capabilitiesOf(t, rt, cfg)
	if hasCapability(got, wsproto.CapTerminal) != rt.TerminalSupported() {
		t.Errorf("terminal capability = %v but TerminalSupported = %v", hasCapability(got, wsproto.CapTerminal), rt.TerminalSupported())
	}
	if hasCapability(got, wsproto.CapFiles) != rt.filesCapable() {
		t.Errorf("files capability = %v but filesCapable = %v", hasCapability(got, wsproto.CapFiles), rt.filesCapable())
	}
	if hasCapability(got, wsproto.CapKernel) {
		t.Error("kernel declared without a signed manifest")
	}
	if hasCapability(got, wsproto.CapUpgrade) {
		t.Error("upgrade is declared although no self_update command is registered")
	}
	for _, cap := range got {
		switch cap {
		case wsproto.CapTelemetry, wsproto.CapXrayNodes, wsproto.CapTerminal, wsproto.CapFiles:
		default:
			t.Errorf("declared capability %q, which nothing implements", cap)
		}
	}

	// The panel must not be able to mutate the list the hello is built from.
	if len(got) > 0 {
		got[0] = "mutated"
		if again := capabilitiesOf(t, rt, cfg); again[0] == "mutated" {
			t.Error("Capabilities() returned a shared slice")
		}
	}
}

// sameStrings compares two string slices element by element.
func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestPolicyComesFromTheLocalAgentConfig checks that hello.policy reports the
// local gates verbatim; the panel may display them but never relax them.
func TestPolicyComesFromTheLocalAgentConfig(t *testing.T) {
	rt, _ := bootCycle(t, t.TempDir(), false, nil)

	// A nil config uses the accessors' zero behaviour: terminal off, no file
	// roots, the xray-nodes module on (its own default). A zero Config (what a
	// running agent always has) reports terminal on.
	pol := rt.Streams(nil, nil).Policy()
	if pol.Terminal || !pol.Modules.XrayNodes || pol.Files.Unrestricted || len(pol.Files.Roots) != 0 {
		t.Errorf("nil-config policy = %+v", pol)
	}
	// The firewall automation is only ever on on OpenWrt (PLAN v11 D2); the
	// test host is not one, so the effective value is false even when the
	// configuration asks for it.
	if pol.Firewall.AutoOpen {
		t.Errorf("firewall.auto_open must be false off OpenWrt: %+v", pol)
	}
	asked := rt.Streams(nil, &agentcfg.Config{Firewall: &agentcfg.FirewallConfig{AutoOpen: boolPtr(true)}}).Policy()
	if asked.Firewall.AutoOpen {
		t.Errorf("firewall.auto_open must stay false off OpenWrt even when requested: %+v", asked)
	}
	if zero := rt.Streams(nil, &agentcfg.Config{}).Policy(); !zero.Terminal {
		t.Errorf("zero-config policy must keep the terminal default on: %+v", zero)
	}

	cfg := &agentcfg.Config{
		Terminal: &agentcfg.TerminalConfig{Enabled: boolPtr(false)},
		Files:    &agentcfg.FilesConfig{Roots: []string{"/etc/W1nCray"}, Unrestricted: boolPtr(true)},
		Modules:  &agentcfg.ModuleConfig{XrayNodes: boolPtr(false)},
	}
	pol = rt.Streams(nil, cfg).Policy()
	if pol.Terminal {
		t.Error("terminal must follow Terminal.Enabled")
	}
	if !pol.Files.Unrestricted || len(pol.Files.Roots) != 1 || pol.Files.Roots[0] != "/etc/W1nCray" {
		t.Errorf("files policy = %+v", pol.Files)
	}
	if pol.Modules.XrayNodes {
		t.Error("xray_nodes must follow Modules.XrayNodes")
	}
	// The instance policy is reported so the panel can plan ports (PLAN v10).
	withPolicy := &agentcfg.Config{Policy: &agentcfg.Policy{AllowListen: []string{"0.0.0.0"}, PortRange: []int{30001, 39999}}}
	ip := rt.Streams(nil, withPolicy).Policy().Instances
	if ip == nil || ip.PortRange != [2]int{30001, 39999} || len(ip.AllowListen) != 1 || ip.AllowListen[0] != "0.0.0.0" {
		t.Errorf("instances policy = %+v", ip)
	}
	// Mutating the reported roots must not reach into the config.
	pol.Files.Roots[0] = "/tmp"
	if again := rt.Streams(nil, cfg).Policy(); again.Files.Roots[0] != "/etc/W1nCray" {
		t.Error("Policy() aliased the config's roots")
	}
}

// TestPolicyReportsTheLocalKernelSwitch covers D-M1's reporting half:
// hello.policy.kernels.allow_http is the machine's own Kernels.AllowHTTP value,
// so the panel can display it (and must never try to turn it on remotely).
func TestPolicyReportsTheLocalKernelSwitch(t *testing.T) {
	rt, _ := bootCycle(t, t.TempDir(), false, nil)

	if pol := rt.Streams(nil, nil).Policy(); pol.Kernels.AllowHTTP {
		t.Errorf("a nil config must report allow_http false: %+v", pol.Kernels)
	}
	if pol := rt.Streams(nil, &agentcfg.Config{}).Policy(); pol.Kernels.AllowHTTP {
		t.Errorf("a zero config must report allow_http false: %+v", pol.Kernels)
	}
	on := &agentcfg.Config{Kernels: &agentcfg.KernelsConfig{AllowHTTP: true}}
	if pol := rt.Streams(nil, on).Policy(); !pol.Kernels.AllowHTTP {
		t.Errorf("Kernels.AllowHTTP: true must be reported: %+v", pol.Kernels)
	}
	off := &agentcfg.Config{Kernels: &agentcfg.KernelsConfig{AllowHTTP: false}}
	if pol := rt.Streams(nil, off).Policy(); pol.Kernels.AllowHTTP {
		t.Errorf("Kernels.AllowHTTP: false must be reported: %+v", pol.Kernels)
	}
}

// TestComponentsReportTheRunningInstances wires the runtime probe: the fake
// engine's running instance must show up as a component next to the agent, and
// the embedded xray engine must never claim a PID of its own (ruling 2).
func TestComponentsReportTheRunningInstances(t *testing.T) {
	dir := t.TempDir()
	rt, _ := bootCycle(t, dir, false, nil)
	port := freePort(t)
	desiredPath := filepath.Join(dir, "d.json")
	writeDesired(t, desiredPath, fwdInstance(port))
	if _, err := rt.ApplyFile(desiredPath); err != nil {
		t.Fatal(err)
	}

	collector := telemetry.New(telemetry.Options{Components: rt.ComponentProbe(), AgentVersion: "1.2.3"})
	comps := rt.Streams(collector, nil).Components(context.Background())
	byName := map[string]wsproto.Component{}
	for _, c := range comps.Items {
		byName[c.Name] = c
	}
	agent, ok := byName["agent"]
	if !ok || agent.Kind != "agent" || agent.State != wsproto.StateRunning || agent.Version != "1.2.3" {
		t.Errorf("agent component = %+v (present=%v)", agent, ok)
	}
	gost, ok := byName["gost"]
	if !ok {
		t.Fatalf("no gost component in %+v", comps.Items)
	}
	if gost.Kind != "kernel" || gost.State != wsproto.StateRunning {
		t.Errorf("gost component = %+v", gost)
	}
	if len(gost.Instances) != 1 || gost.Instances[0].ID != "fwd1" || gost.Instances[0].State != wsproto.StateRunning {
		t.Errorf("gost instances = %+v", gost.Instances)
	}
	// The embedded engine is not a separate process: no PID may be invented.
	for _, c := range comps.Items {
		if c.Name == "xray" && c.PID != 0 {
			t.Errorf("embedded xray claims pid %d", c.PID)
		}
	}
}

// TestKernelsAreEmptyWithoutAnInstalledKernel keeps the hello.kernels path
// honest: no manifest, no installed kernel, no entry (never an invented one).
func TestKernelsAreEmptyWithoutAnInstalledKernel(t *testing.T) {
	rt, _ := bootCycle(t, t.TempDir(), false, nil)
	if got := rt.Streams(nil, nil).Kernels(); len(got) != 0 {
		t.Errorf("kernels = %+v, want none", got)
	}
	// A runtime without a kernel manager must not panic either.
	empty := &Runtime{}
	if got := empty.Streams(nil, nil).Kernels(); got != nil {
		t.Errorf("kernels without a manager = %+v, want nil", got)
	}
}
