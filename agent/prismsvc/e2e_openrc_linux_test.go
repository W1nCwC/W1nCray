//go:build e2e && linux

// This is the Linux integration test of the OpenRC backend: it writes a real
// /etc/init.d/W1nCray-prism, starts a fake kernel (this test binary re-invoked
// as "run --socket unix:<path> --state <dir>") under supervise-daemon and
// drives the manager's Ensure, Stop and Remove against OpenRC.
//
// It needs root and a running OpenRC, and it refuses to run when a real
// W1nCray-prism service is already installed: the point is to exercise the
// production code paths, not to disturb a machine that serves traffic.
//
//	go test -tags e2e -run TestOpenRCServiceE2E ./agent/prismsvc/
package prismsvc

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/prismapi"
)

// e2eScriptFile is the production path the test writes to.
const e2eScriptFile = "/etc/init.d/" + ServiceName

// The runtime and state directories of the fake kernel: not the production
// ones, so a stray kernel of this machine is never touched.
const (
	e2eRuntimeDir = "/run/W1nCray-prism-e2e"
	e2eStateDir   = "/var/lib/W1nCray-prism-e2e"
)

// TestMain lets the test binary act as the fake kernel: OpenRC starts it with
// "run --socket unix:<path> --state <dir>", which the testing framework would
// reject, so it is intercepted before the tests run.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "run" {
		os.Exit(fakeKernelMain())
	}
	os.Exit(m.Run())
}

// fakeKernelMain answers GET /v1/status on the --socket path, like the real
// kernel, and blocks until it is signalled.
func fakeKernelMain() int {
	socket := ""
	for i, a := range os.Args {
		if a == "--socket" && i+1 < len(os.Args) {
			socket = os.Args[i+1]
		}
	}
	const prefix = "unix:"
	if len(socket) <= len(prefix) || socket[:len(prefix)] != prefix {
		return 2
	}
	path := socket[len(prefix):]
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return 3
	}
	defer ln.Close()
	_ = os.Chmod(path, 0o600)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/status", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(prismapi.Status{
			API: prismapi.APIVersion, Version: "0.1.0", State: "running", StartedAt: time.Now().Unix(),
		})
	})
	srv := &http.Server{Handler: mux}
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return 4
	}
	return 0
}

// e2eKernels reports the running test binary as the installed kernel.
type e2eKernels struct{ bin string }

func (k e2eKernels) Current(string) (driver.Installed, error) {
	return driver.Installed{Path: k.bin, Version: "0.1.0"}, nil
}

// TestOpenRCServiceE2E writes, starts, stops and removes the real OpenRC
// service.
func TestOpenRCServiceE2E(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := os.Stat("/run/openrc/softlevel"); err != nil {
		t.Skip("OpenRC is not the running init system (/run/openrc/softlevel is missing)")
	}
	for _, tool := range []string{"rc-service", "rc-update", "supervise-daemon"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not in PATH", tool)
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
	if mgr.Backend() != BackendOpenRC {
		t.Skipf("backend is %q, not openrc", mgr.Backend())
	}
	// Always clean up what this test wrote, even after a failure.
	defer func() {
		_ = exec.Command("rc-service", ServiceName, "stop").Run()
		_ = exec.Command("rc-update", "del", ServiceName, "default").Run()
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
	if err := exec.Command("rc-service", ServiceName, "status").Run(); err != nil {
		t.Fatalf("rc-service status after Ensure: %v", err)
	}
	st := mgr.Status(ctx)
	if st.State != StateRunning || st.ManagedBy != ManagedByService || st.Backend != BackendOpenRC {
		t.Fatalf("status = %+v, want running/service/openrc", st)
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
	if err := exec.Command("rc-service", ServiceName, "status").Run(); err == nil {
		t.Fatal("the service still runs after Stop")
	}
	if err := mgr.Remove(ctx); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(e2eScriptFile); !os.IsNotExist(err) {
		t.Fatalf("the init script was not removed: %v", err)
	}
}
