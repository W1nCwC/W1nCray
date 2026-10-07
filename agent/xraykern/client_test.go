package xraykern

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/xrayapi"
)

// fakeKernels is a kernel resolver with a scripted current version.
type fakeKernels struct {
	inst driver.Installed
	err  error
}

func (f fakeKernels) Current(string) (driver.Installed, error) { return f.inst, f.err }

// fakeRunner records commands and returns a scripted output.
type fakeRunner struct {
	args []string
	out  []byte
	err  error
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.args = append([]string{name}, args...)
	return f.out, f.err
}

// serveStatus publishes h on the kernel's status endpoint inside dir, using the
// platform's transport (a Unix socket, or the address file on Windows).
func serveStatus(t *testing.T, dir string, h http.Handler) {
	t.Helper()
	if runtime.GOOS == "windows" {
		srv := httptest.NewServer(h)
		t.Cleanup(srv.Close)
		u, err := url.Parse(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, xrayapi.StatusAddrName), []byte(u.Host+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	sock := filepath.Join(dir, xrayapi.StatusSocketName)
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("unix socket: %v", err)
	}
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
	})
}

// newClient builds a Client for a config file inside a fresh directory.
func newClient(t *testing.T, k CurrentKernel, r Runner) (*Client, string) {
	t.Helper()
	dir := t.TempDir()
	config := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(config, []byte("Log: {Level: warning}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := New(Options{ConfigPath: config, Kernels: k, Runner: r})
	if err != nil {
		t.Fatal(err)
	}
	return c, dir
}

func TestStatusReadsTheEndpoint(t *testing.T) {
	c, dir := newClient(t, fakeKernels{err: ErrNotInstalled}, nil)
	serveStatus(t, dir, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != xrayapi.StatusPath {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(xrayapi.Status{Version: "0.6.0", Running: true, ConfigFingerprint: "abc"})
	}))
	st, err := c.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !st.Running || st.Version != "0.6.0" || st.ConfigFingerprint != "abc" {
		t.Fatalf("status = %+v", st)
	}
}

func TestStatusWithoutKernel(t *testing.T) {
	c, _ := newClient(t, fakeKernels{err: ErrNotInstalled}, nil)
	if _, err := c.Status(context.Background()); err == nil {
		t.Fatal("Status without an endpoint must fail")
	}
}

func TestCheckStagedRunsTheInstalledBinary(t *testing.T) {
	run := &fakeRunner{out: []byte(`{"ok":false,"errors":[{"file":"route.json","message":"bad rule"}]}`), err: errors.New("exit status 1")}
	c, _ := newClient(t, fakeKernels{inst: driver.Installed{Path: "/kernels/xray/1.0.0/W1nCray-xray", Version: "1.0.0"}}, run)
	res, err := c.CheckStaged(context.Background(), "/staged", []string{"route.json", "dns.json"})
	if err != nil {
		t.Fatalf("CheckStaged: %v", err)
	}
	if res.OK || len(res.Errors) != 1 || res.Errors[0].File != "route.json" {
		t.Fatalf("result = %+v", res)
	}
	want := []string{"/kernels/xray/1.0.0/W1nCray-xray", "check-staged", "-c", c.opts.ConfigPath, "--dir", "/staged", "--files", "route.json,dns.json"}
	if strings.Join(run.args, " ") != strings.Join(want, " ") {
		t.Fatalf("args = %v, want %v", run.args, want)
	}
}

func TestCheckStagedWithoutKernel(t *testing.T) {
	c, _ := newClient(t, fakeKernels{err: ErrNotInstalled}, &fakeRunner{})
	_, err := c.CheckStaged(context.Background(), "/staged", []string{"route.json"})
	if !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("err = %v, want ErrNotInstalled", err)
	}
}

func TestCheckStagedUnparsableOutput(t *testing.T) {
	c, _ := newClient(t, fakeKernels{inst: driver.Installed{Path: "/x", Version: "1"}}, &fakeRunner{out: []byte("boom"), err: errors.New("exit status 1")})
	if _, err := c.CheckStaged(context.Background(), "/staged", []string{"route.json"}); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v, want the command output", err)
	}
}

func TestWaitReloaded(t *testing.T) {
	c, dir := newClient(t, fakeKernels{err: ErrNotInstalled}, nil)
	c.opts.ReloadTimeout = time.Second
	c.opts.PollInterval = time.Millisecond
	fp := "fingerprint-1"
	serveStatus(t, dir, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(xrayapi.Status{Running: true, ConfigFingerprint: fp})
	}))
	if err := c.WaitReloaded(context.Background(), fp); err != nil {
		t.Fatalf("WaitReloaded: %v", err)
	}
	err := c.WaitReloaded(context.Background(), "other")
	if err == nil || !strings.Contains(err.Error(), "超时") {
		t.Fatalf("err = %v, want a timeout", err)
	}
}

func TestWaitReloadedEmptyFingerprint(t *testing.T) {
	c, _ := newClient(t, fakeKernels{err: ErrNotInstalled}, nil)
	if err := c.WaitReloaded(context.Background(), ""); err == nil {
		t.Fatal("an empty fingerprint must be refused")
	}
}
