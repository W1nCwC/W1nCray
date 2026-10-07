//go:build e2e && linux

// This is the Linux integration test of the systemd backend: it writes a real
// /etc/systemd/system/W1nCray-xray.service, starts a fake W1nCray-xray kernel
// (this test binary re-invoked as "run -c <config>") and drives the manager's
// install, restart and remove against systemd.
//
// It needs root and a running systemd, and it refuses to run when a real
// W1nCray-xray service is already installed: the point is to exercise the
// production code paths, not to disturb a machine that serves traffic.
//
//	go test -tags e2e -run TestSystemdServiceE2E ./agent/xraysvc/
package xraysvc

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
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/agent/xrayapi"
	"github.com/W1nCwC/W1nCray/agent/xraykern"
	"github.com/W1nCwC/W1nCray/kernel/install"
)

// systemdUnitFile is the production path the test writes to.
const systemdUnitFile = "/etc/systemd/system/" + ServiceName + ".service"

// TestMain lets the test binary act as the fake kernel: systemd starts it with
// "run -c <config.yml>", which the testing framework would reject, so it is
// intercepted before the tests run.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "run" {
		os.Exit(fakeKernelMain())
	}
	os.Exit(m.Run())
}

// fakeKernelMain serves GET /status on <configDir>/xray.sock, like the real
// kernel, and blocks until it is signalled.
func fakeKernelMain() int {
	configPath := ""
	for i, a := range os.Args {
		if a == "-c" && i+1 < len(os.Args) {
			configPath = os.Args[i+1]
		}
	}
	if configPath == "" {
		return 2
	}
	dir := filepath.Dir(configPath)
	sock := filepath.Join(dir, xrayapi.StatusSocketName)
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return 3
	}
	defer ln.Close()
	_ = os.Chmod(sock, 0o600)
	mux := http.NewServeMux()
	mux.HandleFunc(xrayapi.StatusPath, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(xrayapi.Status{
			Version: "0.6.0", Running: true, StartedAt: time.Now().Unix(),
		})
	})
	srv := &http.Server{Handler: mux}
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return 4
	}
	return 0
}

// e2eKernels reports the running test binary as the installed kernel.
type e2eKernels struct {
	bin string
}

func (k e2eKernels) Ensure(context.Context, spec.KernelPin) (driver.Installed, error) {
	return driver.Installed{Path: k.bin, Version: "0.6.0"}, nil
}
func (k e2eKernels) Current(string) (driver.Installed, error) {
	return driver.Installed{Path: k.bin, Version: "0.6.0"}, nil
}
func (k e2eKernels) Rollback(string) (driver.Installed, error) {
	return driver.Installed{Path: k.bin, Version: "0.6.0"}, nil
}
func (k e2eKernels) Remove(string, string) error    { return nil }
func (k e2eKernels) List() ([]install.Entry, error) { return nil, nil }

// TestSystemdServiceE2E installs, restarts and removes the real systemd unit.
func TestSystemdServiceE2E(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		t.Skip("systemd is not running (/run/systemd/system is missing)")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		t.Skip("systemctl is not in PATH")
	}
	if _, err := os.Stat(systemdUnitFile); err == nil {
		t.Skipf("%s already exists; refusing to disturb a real install", systemdUnitFile)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(configPath, []byte("Log: {Level: warning}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	client, err := xraykern.New(xraykern.Options{ConfigPath: configPath, Kernels: e2eKernels{bin: exe}})
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := New(Options{
		Kernels:       e2eKernels{bin: exe},
		ConfigPath:    configPath,
		KernelsDir:    filepath.Join(dir, "kernels"),
		StateDir:      filepath.Join(dir, "state"),
		Status:        client,
		HealthTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if mgr.Backend() != BackendSystemd {
		t.Skipf("backend is %q, not systemd", mgr.Backend())
	}
	// Always clean up the unit this test wrote, even after a failure.
	defer func() {
		_ = exec.Command("systemctl", "disable", "--now", ServiceName).Run()
		_ = os.Remove(systemdUnitFile)
		_ = exec.Command("systemctl", "daemon-reload").Run()
	}()

	ctx := context.Background()
	if err := mgr.Install(ctx, "0.6.0"); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if _, err := os.Stat(systemdUnitFile); err != nil {
		t.Fatalf("unit file: %v", err)
	}
	if out, err := exec.Command("systemctl", "is-active", ServiceName).Output(); err != nil || string(out) == "" {
		t.Fatalf("systemctl is-active: %v (%s)", err, out)
	}
	st, err := mgr.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.State != StateRunning {
		t.Fatalf("status = %+v, want running", st)
	}
	if err := mgr.Restart(ctx); err != nil {
		t.Fatalf("Restart: %v", err)
	}
	if _, err := mgr.Remove(ctx); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(systemdUnitFile); !os.IsNotExist(err) {
		t.Fatalf("the unit file was not removed: %v", err)
	}
	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("Remove deleted the configuration: %v", err)
	}
}
