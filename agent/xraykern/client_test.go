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
		if err := os.WriteFile(xrayapi.AddrPath(dir), []byte(u.Host+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	sock := xrayapi.SocketPath(dir)
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

// newClient builds a Client for a config file inside a fresh directory. The
// directory doubles as the kernel's runtime directory (W1NCRAY_RUNTIME_DIR), so
// the test never reads a real kernel's socket on the machine running it.
func newClient(t *testing.T, k CurrentKernel, r Runner) (*Client, string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(xrayapi.RuntimeDirEnv, dir)
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

// TestStatusFallsBackToTheLegacySocket lives in client_legacy_unix_test.go: the
// legacy location only exists on Unix.

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

// TestCheckStagedToleratesLogLinesAroundTheVerdict is R1-3: the verdict is the
// kernel's JSON on stdout, but the Xray-core loader it runs may log there too.
// The agent must pick the JSON object out of the mixed output instead of
// reporting a parse failure for a perfectly good answer.
func TestCheckStagedToleratesLogLinesAroundTheVerdict(t *testing.T) {
	for _, tc := range []struct {
		name  string
		out   string
		ok    bool
		files []string
	}{
		{
			name: "log line with braces before the verdict",
			out:  "2026/10/08 [Warning] route {odd} skipped\n{\"ok\":true}\n",
			ok:   true,
		},
		{
			name: "unbalanced brace in a log line before the verdict",
			out:  "warning: unexpected token {\n{\"ok\":true}\n",
			ok:   true,
		},
		{
			name: "log line after the verdict",
			out:  "{\"ok\":true}\n2026/10/08 done\n",
			ok:   true,
		},
		{
			name: "pretty-printed verdict between log lines",
			out: "2026/10/08 [Debug] loading\n{\n  \"ok\": false,\n" +
				"  \"errors\": [{\"file\": \"route.json\", \"message\": \"bad rule\"}]\n}\n",
			ok: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := &fakeRunner{out: []byte(tc.out), err: errors.New("exit status 1")}
			c, _ := newClient(t, fakeKernels{inst: driver.Installed{Path: "/x", Version: "1"}}, run)
			res, err := c.CheckStaged(context.Background(), "/staged", []string{"route.json"})
			if err != nil {
				t.Fatalf("CheckStaged: %v", err)
			}
			if res.OK != tc.ok {
				t.Fatalf("ok = %v, want %v (result %+v)", res.OK, tc.ok, res)
			}
			if !tc.ok && (len(res.Errors) != 1 || res.Errors[0].File != "route.json") {
				t.Fatalf("errors = %+v", res.Errors)
			}
		})
	}
}

// TestCheckStagedWithoutAnyJSON keeps the failure honest: output with no JSON
// object at all is still a parse error carrying the raw output.
func TestCheckStagedWithoutAnyJSON(t *testing.T) {
	c, _ := newClient(t, fakeKernels{inst: driver.Installed{Path: "/x", Version: "1"}}, &fakeRunner{out: []byte("no json here\n")})
	_, err := c.CheckStaged(context.Background(), "/staged", []string{"route.json"})
	if err == nil || !strings.Contains(err.Error(), "no json here") {
		t.Fatalf("err = %v, want a parse failure carrying the output", err)
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

// TestSyncMachineNodesReadsTheEndpoint: the nodes hint is one GET on the
// kernel's local endpoint, on the route the kernel serves next to /status.
func TestSyncMachineNodesReadsTheEndpoint(t *testing.T) {
	c, dir := newClient(t, fakeKernels{err: ErrNotInstalled}, nil)
	serveStatus(t, dir, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != xrayapi.NodesSyncPath {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.RawQuery != "" || r.ContentLength > 0 {
			t.Errorf("the request carries a parameter: query %q, content-length %d", r.URL.RawQuery, r.ContentLength)
		}
		_ = json.NewEncoder(w).Encode(xrayapi.NodesSyncResult{Changed: true, Version: "v2"})
	}))
	changed, err := c.SyncMachineNodes(context.Background())
	if err != nil {
		t.Fatalf("SyncMachineNodes: %v", err)
	}
	if !changed {
		t.Error("changed = false, want true")
	}
}

// TestSyncMachineNodesIdleList: an unchanged list is a successful (false, nil),
// not an error.
func TestSyncMachineNodesIdleList(t *testing.T) {
	c, dir := newClient(t, fakeKernels{err: ErrNotInstalled}, nil)
	serveStatus(t, dir, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != xrayapi.NodesSyncPath {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(xrayapi.NodesSyncResult{Changed: false, Version: "v1"})
	}))
	changed, err := c.SyncMachineNodes(context.Background())
	if err != nil {
		t.Fatalf("SyncMachineNodes: %v", err)
	}
	if changed {
		t.Error("changed = true for an idle list")
	}
}

// TestSyncMachineNodesOldKernelFallsBack: a kernel that predates the route
// answers 404 to everything but /status. The agent must report an error (so the
// caller degrades to the poll), not treat it as "unchanged".
func TestSyncMachineNodesOldKernelFallsBack(t *testing.T) {
	c, dir := newClient(t, fakeKernels{err: ErrNotInstalled}, nil)
	serveStatus(t, dir, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != xrayapi.StatusPath {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(xrayapi.Status{Version: "0.6.0", Running: true})
	}))
	// The old kernel is reachable: its status endpoint still answers.
	if _, err := c.Status(context.Background()); err != nil {
		t.Fatalf("Status on the old kernel: %v", err)
	}
	_, err := c.SyncMachineNodes(context.Background())
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("err = %v, want an HTTP 404 error", err)
	}
}

// TestSyncMachineNodesFailures: no endpoint, a failing kernel and a timeout are
// all errors the caller degrades on.
func TestSyncMachineNodesFailures(t *testing.T) {
	t.Run("no kernel", func(t *testing.T) {
		c, _ := newClient(t, fakeKernels{err: ErrNotInstalled}, nil)
		if _, err := c.SyncMachineNodes(context.Background()); err == nil {
			t.Fatal("SyncMachineNodes without an endpoint must fail")
		}
	})
	t.Run("kernel failure", func(t *testing.T) {
		c, dir := newClient(t, fakeKernels{err: ErrNotInstalled}, nil)
		serveStatus(t, dir, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "panel unreachable", http.StatusBadGateway)
		}))
		_, err := c.SyncMachineNodes(context.Background())
		if err == nil || !strings.Contains(err.Error(), "502") {
			t.Fatalf("err = %v, want an HTTP 502 error", err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		c, dir := newClient(t, fakeKernels{err: ErrNotInstalled}, nil)
		c.opts.SyncTimeout = 50 * time.Millisecond
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		serveStatus(t, dir, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-release:
			}
		}))
		_, err := c.SyncMachineNodes(context.Background())
		if err == nil {
			t.Fatal("SyncMachineNodes must time out")
		}
	})
}
