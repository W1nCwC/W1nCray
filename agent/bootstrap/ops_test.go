package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/agentcfg"
	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/supervisor"
	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

func hasCapability(caps []string, want string) bool {
	for _, c := range caps {
		if c == want {
			return true
		}
	}
	return false
}

// bootWithManifest boots a runtime whose kernel installer has a signed manifest
// in force (a persisted one, restored at start-up).
func bootWithManifest(t *testing.T) *Runtime {
	t.Helper()
	useFake(t, newFakeDriver())
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(dir, "state")
	keysPath := filepath.Join(dir, "keys.txt")
	if err := os.WriteFile(keysPath, []byte(hex.EncodeToString(pub)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(PersistedManifestPath(stateDir), bootSignedManifest(t, 7, priv), 0o600); err != nil {
		t.Fatal(err)
	}
	rt, err := Boot(Options{
		StateDir:         stateDir,
		KernelsDir:       filepath.Join(dir, "kernels"),
		ManifestKeysPath: keysPath,
	}, nil)
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	t.Cleanup(func() { _ = rt.Shutdown(context.Background()) })
	return rt
}

// TestCapabilitiesDeclareKernelOnlyWithAUsableInstaller covers ruling 1 for the
// kernel capability: it is a promise, so it is only made when the kernel
// commands can really be served (an installer with a signed manifest).
func TestCapabilitiesDeclareKernelOnlyWithAUsableInstaller(t *testing.T) {
	// The pure decision: the installer flag is the only difference.
	without := capabilities(&agentcfg.Config{}, false, false, false)
	if len(without) != 2 || without[0] != wsproto.CapTelemetry || without[1] != wsproto.CapXrayNodes {
		t.Fatalf("capabilities without an installer = %v", without)
	}
	with := capabilities(&agentcfg.Config{}, true, false, false)
	if len(with) != 3 || with[2] != wsproto.CapKernel {
		t.Fatalf("capabilities with an installer = %v", with)
	}
	if moduleOff := capabilities(&agentcfg.Config{Modules: &agentcfg.ModuleConfig{XrayNodes: boolPtr(false)}}, true, false, false); hasCapability(moduleOff, wsproto.CapXrayNodes) {
		t.Errorf("the local module gate must still win: %v", moduleOff)
	}
	if withFiles := capabilities(&agentcfg.Config{}, true, false, true); !hasCapability(withFiles, wsproto.CapFiles) {
		t.Errorf("capabilities = %v, want files", withFiles)
	}

	// A runtime without a kernel manager can never declare it.
	if (&Runtime{}).kernelCapable() {
		t.Error("a runtime without a kernel manager claims the kernel capability")
	}
	// The installer exists but no signed manifest is loaded: kernel_install
	// could not resolve a version, so the capability is not promised.
	rt, _ := bootCycle(t, t.TempDir(), false, nil)
	if rt.Kernels == nil {
		t.Fatal("the booted runtime has no kernel installer")
	}
	if rt.kernelCapable() {
		t.Error("kernel declared without a signed manifest")
	}
	if got := rt.Streams(nil, &agentcfg.Config{}).Capabilities(); hasCapability(got, wsproto.CapKernel) {
		t.Errorf("capabilities = %v, want no kernel", got)
	}

	// With a manifest in force the kernel commands are served, so the
	// capability is declared.
	rt2 := bootWithManifest(t)
	if !rt2.kernelCapable() {
		t.Fatal("a runtime with a signed manifest does not claim the kernel capability")
	}
	if got := rt2.Streams(nil, &agentcfg.Config{}).Capabilities(); !hasCapability(got, wsproto.CapKernel) {
		t.Errorf("capabilities = %v, want kernel", got)
	}
}

// TestBootstrapHelperProcess is not a test: it is the supervised child the
// component-restart test starts (it must stay alive long enough to be
// restarted).
func TestBootstrapHelperProcess(t *testing.T) {
	if os.Getenv("W1NCRAY_SUP_HELPER") != "1" {
		return
	}
	time.Sleep(30 * time.Second)
	os.Exit(0)
}

// TestComponentRestartReachesOnlySupervisedKernels covers the production
// component_restart hook: it restarts a running kernel process and refuses
// anything the supervisor does not own (the agent is never supervised).
func TestComponentRestartReachesOnlySupervisedKernels(t *testing.T) {
	sup := supervisor.New(supervisor.Options{Log: nopLog{}, PIDDir: t.TempDir()})
	t.Cleanup(func() { _ = sup.Shutdown(context.Background()) })
	cr := componentRestarter{rt: &Runtime{Sup: sup, log: nopLog{}}}
	ctx := context.Background()

	if _, err := cr.Restart(ctx, "gost"); err == nil {
		t.Fatal("restarting a component that is not running must fail")
	}

	spec := driver.ProcSpec{
		ID:   "gost/main",
		Path: os.Args[0],
		Args: []string{"-test.run=TestBootstrapHelperProcess"},
		Env:  []string{"W1NCRAY_SUP_HELPER=1"},
	}
	if err := sup.Start(ctx, spec); err != nil {
		t.Fatalf("starting the helper: %v", err)
	}
	old := sup.Status("gost/main").PID
	if old == 0 {
		t.Fatal("the helper did not start")
	}

	n, err := cr.Restart(ctx, "gost")
	if err != nil {
		t.Fatalf("componentRestarter.Restart: %v", err)
	}
	if n != 1 {
		t.Errorf("restarted %d process(es), want 1", n)
	}
	st := sup.Status("gost/main")
	if !st.Running || st.PID == 0 {
		t.Errorf("after the restart: %+v", st)
	}
	if st.PID == old {
		t.Errorf("the pid did not change (%d): the process was not restarted", old)
	}

	// The agent is never a supervised process, so it can never be restarted.
	if _, err := cr.Restart(ctx, "agent"); err == nil {
		t.Error("component_restart must not find an agent process")
	}
}
