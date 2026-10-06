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

// TestCapabilitiesOnlyDeclareWhatThisBatchImplements covers protocol ruling 1:
// the hello capability list is a promise. This batch serves telemetry only, so
// terminal, files, kernel and upgrade must never appear; xray_nodes appears
// only when the local module gate allows it (ruling 6).
func TestCapabilitiesOnlyDeclareWhatThisBatchImplements(t *testing.T) {
	rt, _ := bootCycle(t, t.TempDir(), false, nil)

	cases := []struct {
		name string
		cfg  *agentcfg.Config
		want []string
	}{
		{"no agent.yml", nil, []string{wsproto.CapTelemetry, wsproto.CapXrayNodes}},
		{"defaults (module on)", &agentcfg.Config{}, []string{wsproto.CapTelemetry, wsproto.CapXrayNodes}},
		{"module off", &agentcfg.Config{Modules: &agentcfg.ModuleConfig{XrayNodes: boolPtr(false)}}, []string{wsproto.CapTelemetry}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := capabilitiesOf(t, rt, tc.cfg)
			if len(got) != len(tc.want) {
				t.Fatalf("capabilities = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("capabilities = %v, want %v", got, tc.want)
				}
			}
			for _, cap := range got {
				switch cap {
				case wsproto.CapTelemetry, wsproto.CapXrayNodes:
				default:
					t.Errorf("declared capability %q, which nothing in this batch implements", cap)
				}
			}
			for _, forbidden := range []string{wsproto.CapTerminal, wsproto.CapFiles, wsproto.CapKernel, wsproto.CapUpgrade} {
				for _, cap := range got {
					if cap == forbidden {
						t.Errorf("declared unimplemented capability %q", forbidden)
					}
				}
			}
			// The panel must not be able to mutate the list the hello is built
			// from.
			if len(got) > 0 {
				got[0] = "mutated"
				if again := capabilitiesOf(t, rt, tc.cfg); again[0] == "mutated" {
					t.Error("Capabilities() returned a shared slice")
				}
			}
		})
	}
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
	if zero := rt.Streams(nil, &agentcfg.Config{}).Policy(); !zero.Terminal {
		t.Errorf("zero-config policy must keep the terminal default on: %+v", zero)
	}

	cfg := &agentcfg.Config{
		Terminal: &agentcfg.TerminalConfig{Enabled: boolPtr(false)},
		Files:    &agentcfg.FilesConfig{Roots: []string{"/etc/W1nCray"}, Unrestricted: true},
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
	// Mutating the reported roots must not reach into the config.
	pol.Files.Roots[0] = "/tmp"
	if again := rt.Streams(nil, cfg).Policy(); again.Files.Roots[0] != "/etc/W1nCray" {
		t.Error("Policy() aliased the config's roots")
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
