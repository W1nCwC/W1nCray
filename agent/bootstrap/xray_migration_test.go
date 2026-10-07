package bootstrap

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/agent/xrayapi"
	"github.com/W1nCwC/W1nCray/agent/xraysvc"
	"github.com/W1nCwC/W1nCray/kernel/install"
)

// migrationKernels is the kernel manager surface xraysvc needs.
type migrationKernels struct {
	current driver.Installed
	err     error
}

func (k migrationKernels) Ensure(context.Context, spec.KernelPin) (driver.Installed, error) {
	return k.current, k.err
}
func (k migrationKernels) Current(string) (driver.Installed, error)  { return k.current, k.err }
func (k migrationKernels) Rollback(string) (driver.Installed, error) { return k.current, k.err }
func (k migrationKernels) Remove(string, string) error               { return nil }
func (k migrationKernels) List() ([]install.Entry, error)            { return nil, nil }

// migrationStatus is the kernel status endpoint.
type migrationStatus struct{ running bool }

func (s migrationStatus) Status(context.Context) (xrayapi.Status, error) {
	return xrayapi.Status{Running: s.running}, nil
}
func (s migrationStatus) CheckStaged(context.Context, string, []string) (xrayapi.StagedResult, error) {
	return xrayapi.StagedResult{OK: true}, nil
}
func (s migrationStatus) WaitReloaded(context.Context, string) error { return nil }

// migrationSup is the supervisor of the fallback backend.
type migrationSup struct {
	started []driver.ProcSpec
	running bool
}

func (s *migrationSup) Start(_ context.Context, p driver.ProcSpec) error {
	s.started = append(s.started, p)
	s.running = true
	return nil
}
func (s *migrationSup) Stop(context.Context, string) error { s.running = false; return nil }
func (s *migrationSup) Status(string) driver.ProcStatus    { return driver.ProcStatus{Running: s.running} }

// TestBootDefersTheXrayMigrationUntilTheUpdateIsConfirmed is the PLAN v11 §2.6
// ordering rule: a process that came out of a committed self_update must not
// start the Xray service before the panel confirmed the update, because a
// rollback to the in-process 0.5.x agent must not find the service holding the
// ports.
func TestBootDefersTheXrayMigrationUntilTheUpdateIsConfirmed(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(filepath.Join(stateDir, "update"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "update", "pending.json"), []byte(`{"version":"0.6.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	orig := bootXrayStart
	defer func() { bootXrayStart = orig }()
	calls := 0
	bootXrayStart = func(*Runtime) { calls++ }

	rt, err := Boot(Options{
		StateDir:       stateDir,
		KernelsDir:     filepath.Join(dir, "kernels"),
		XrayConfigPath: filepath.Join(dir, "config.yml"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("Boot started the Xray migration before the self-update was confirmed")
	}
	if !rt.xrayStartupDeferred() {
		t.Fatal("the runtime must know a self-update is pending")
	}
	// The confirmed hook (StartRemote's OnConnected, or the local command)
	// triggers it.
	bootXrayStart(rt)
	if calls != 1 {
		t.Fatalf("after the confirm the migration ran %d time(s), want once", calls)
	}
}

// TestBootStartsTheXrayMigrationImmediatelyWithoutAPendingUpdate is the other
// half: nothing to confirm, so the migration runs at start-up.
func TestBootStartsTheXrayMigrationImmediatelyWithoutAPendingUpdate(t *testing.T) {
	dir := t.TempDir()
	orig := bootXrayStart
	defer func() { bootXrayStart = orig }()
	calls := 0
	bootXrayStart = func(*Runtime) { calls++ }

	rt, err := Boot(Options{
		StateDir:       filepath.Join(dir, "state"),
		KernelsDir:     filepath.Join(dir, "kernels"),
		XrayConfigPath: filepath.Join(dir, "config.yml"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if rt.xrayStartupDeferred() {
		t.Fatal("nothing is pending, the migration must not be deferred")
	}
	if calls != 1 {
		t.Fatalf("the migration ran %d time(s), want once", calls)
	}
}

// TestEnsureXrayRunsOnceAndOnlyWhenNeeded covers the runtime side of the
// migration: it is gated by the configuration and runs at most once per
// process.
func TestEnsureXrayRunsOnceAndOnlyWhenNeeded(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "kernels", "xray", "0.6.0", "W1nCray-xray")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "config.yml")
	if err := os.WriteFile(configPath, []byte("Log: {Level: warning}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sup := &migrationSup{}
	mgr, err := xraysvc.New(xraysvc.Options{
		Root:       root,
		Kernels:    migrationKernels{current: driver.Installed{Path: bin, Version: "0.6.0"}},
		ConfigPath: configPath,
		StateDir:   filepath.Join(root, "state"),
		Status:     migrationStatus{running: true},
		Sup:        sup,
		Backend:    xraysvc.BackendAgent,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Not needed: nothing happens.
	rt := &Runtime{XrayManager: mgr}
	if err := rt.EnsureXray(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sup.started) != 0 {
		t.Fatalf("a machine that does not need Xray started it: %v", sup.started)
	}

	// Needed: the kernel is started once, and a second call is a no-op.
	rt.xrayNeeded = true
	if err := rt.EnsureXray(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := rt.EnsureXray(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sup.started) != 1 {
		t.Fatalf("the migration ran %d time(s), want once", len(sup.started))
	}
}
