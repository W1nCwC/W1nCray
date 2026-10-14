package install

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/driver/frp"
)

// nopSupervisor satisfies driver.Supervisor without running anything. Apply
// with an empty instance set never starts a process, it only has to get past
// the kernel-path check that this test is about.
type nopSupervisor struct{}

func (nopSupervisor) Start(context.Context, driver.ProcSpec) error { return nil }
func (nopSupervisor) Stop(context.Context, string) error           { return nil }
func (nopSupervisor) Signal(string, os.Signal) error               { return nil }
func (nopSupervisor) Status(string) driver.ProcStatus              { return driver.ProcStatus{} }

type nopLogger struct{}

func (nopLogger) Debugf(string, ...any) {}
func (nopLogger) Infof(string, ...any)  {}
func (nopLogger) Warnf(string, ...any)  {}
func (nopLogger) Errorf(string, ...any) {}

// TestFrpInstalledPathFeedsDriver is the D-M6 regression test. It reproduces
// the real installation product: kernel/install unpacks an frp archive that
// holds both frpc and frps (the shape of the signed frp manifest, where
// run.binary is frpc), returns driver.Installed.Path = <verDir>/frpc, and that
// value is handed to the frp driver exactly like agent/reconcile does.
//
// Before the fix frp.Binaries refused anything but frps, so the portal engine
// failed with "frp: kernel path must point at the frps binary" and the whole
// desired state was rolled back.
func TestFrpInstalledPathFeedsDriver(t *testing.T) {
	f := newFixture(t)
	fs := newFileServer(t)
	k := publish(t, f, fs, kern{
		Name: "frp", Version: "0.71.0", RunBinary: "frpc",
		Members: map[string][]byte{
			"frpc": fakeBin("0.71.0", 512),
			"frps": fakeBin("0.71.0", 512),
		},
		Extract: map[string]string{"frpc": "frpc", "frps": "frps"},
	})
	in := f.installer(t.TempDir())
	if err := in.LoadManifest(f.sign(k)); err != nil {
		t.Fatal(err)
	}

	inst, err := in.Ensure(context.Background(), pin("frp", "0.71.0"))
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if filepath.Base(inst.Path) != "frpc" {
		t.Fatalf("installed path = %q, want the manifest run.binary frpc", inst.Path)
	}
	// Both binaries must really be on disk where the driver looks for them.
	frpsWant := filepath.Join(filepath.Dir(inst.Path), "frps")
	for _, p := range []string{inst.Path, frpsWant} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("installed binary missing: %v", err)
		}
	}

	frps, frpc, err := frp.Binaries(inst.Path)
	if err != nil {
		t.Fatalf("frp.Binaries(%q): %v", inst.Path, err)
	}
	if frps != frpsWant || frpc != inst.Path {
		t.Fatalf("Binaries = (%q, %q), want (%q, %q)", frps, frpc, frpsWant, inst.Path)
	}

	// The driver's Apply path must accept the same runtime object.
	d := frp.New(frp.Options{})
	rt := driver.Runtime{
		Kernel:   inst,
		StateDir: t.TempDir(),
		Sup:      nopSupervisor{},
		Log:      nopLogger{},
	}
	if _, err := d.Apply(context.Background(), rt, nil); err != nil {
		t.Fatalf("frp Apply with the installed kernel: %v", err)
	}
}
