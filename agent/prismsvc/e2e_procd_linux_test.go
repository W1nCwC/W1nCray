//go:build e2e && linux

// This is the Linux integration test of the procd (OpenWrt) backend: it writes
// a real /etc/init.d/W1nCray-prism, starts a fake kernel (this test binary
// re-invoked as "run --socket unix:<path> --state <dir>", see TestMain in
// e2e_openrc_linux_test.go) under procd and drives the manager's Ensure, Stop
// and Remove.
//
// It needs root on an OpenWrt machine and refuses to run when a real
// W1nCray-prism service is already installed. It has not been run against a
// real OpenWrt yet; it is kept compiling so the first run can happen on one.
//
//	go test -tags e2e -run TestProcdServiceE2E ./agent/prismsvc/
package prismsvc

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/prismapi"
)

// TestProcdServiceE2E writes, starts, stops and removes the real procd service.
func TestProcdServiceE2E(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	for _, f := range []string{"/sbin/procd", "/etc/rc.common"} {
		if _, err := os.Stat(f); err != nil {
			t.Skipf("%s is missing: not an OpenWrt machine", f)
		}
	}
	if _, err := os.Stat(e2eScriptFile); err == nil {
		t.Skipf("%s already exists; refusing to disturb a real install", e2eScriptFile)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("W1NCRAY_PRISM_RUNTIME_DIR", e2eRuntimeDir)
	t.Setenv("W1NCRAY_PRISM_STATE_DIR", e2eStateDir)
	client, err := prismapi.New("unix:" + SocketPath())
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := New(Options{
		Kernels:       e2eKernels{bin: exe},
		StateDir:      filepath.Join(t.TempDir(), "state"),
		Status:        client.Status,
		HealthTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if mgr.Backend() != BackendProcd {
		t.Skipf("backend is %q, not procd", mgr.Backend())
	}
	// Always clean up what this test wrote, even after a failure.
	defer func() {
		_ = exec.Command(e2eScriptFile, "stop").Run()
		_ = exec.Command(e2eScriptFile, "disable").Run()
		_ = os.Remove(e2eScriptFile)
		_ = os.RemoveAll(e2eRuntimeDir)
		_ = os.RemoveAll(e2eStateDir)
	}()

	ctx := context.Background()
	if err := mgr.Ensure(ctx); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	fi, err := os.Stat(e2eScriptFile)
	if err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("init script: %v %v", fi, err)
	}
	if err := exec.Command(e2eScriptFile, "running").Run(); err != nil {
		t.Fatalf("running after Ensure: %v", err)
	}
	st := mgr.Status(ctx)
	if st.State != StateRunning || st.ManagedBy != ManagedByService || st.Backend != BackendProcd {
		t.Fatalf("status = %+v, want running/service/procd", st)
	}
	// A second pass with nothing changed must not disturb the process.
	before, err := client.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.Ensure(ctx); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	after, err := client.Status(ctx)
	if err != nil || after.StartedAt != before.StartedAt {
		t.Fatalf("status after the idle Ensure: %+v %v", after, err)
	}

	if err := mgr.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := exec.Command(e2eScriptFile, "running").Run(); err == nil {
		t.Fatal("the service still runs after Stop")
	}
	if err := mgr.Remove(ctx); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(e2eScriptFile); !os.IsNotExist(err) {
		t.Fatalf("the init script was not removed: %v", err)
	}
}
