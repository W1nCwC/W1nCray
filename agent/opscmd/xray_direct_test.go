// The Xray half of the manifest-free kernel_install path (DEC-4): a URL in the
// args used to be silently ignored for the xray kernel, which kept resolving
// the version through the signed manifest. These tests drive the real command
// registry, the real service manager and the real kernel installer, so the
// whole chain (args -> direct download -> sha256 -> self-check -> activate) is
// what is being asserted, not a fake.

package opscmd

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/panelclient"
	"github.com/W1nCwC/W1nCray/agent/xrayapi"
	"github.com/W1nCwC/W1nCray/agent/xraysvc"
	"github.com/W1nCwC/W1nCray/kernel/install"
)

// reFakeXrayKernel reads the version out of a fake kernel "binary" (a text
// file), so no target binary has to be executed in the test.
var reFakeXrayKernel = regexp.MustCompile(`FAKEKRAY version=(\S+)`)

// xrayAssetGz is one gz release asset holding a fake W1nCray-xray binary that
// reports version. The file name inside the stream is irrelevant: a gz stream
// carries exactly one member.
func xrayAssetGz(t *testing.T, version string) []byte {
	t.Helper()
	bin := "#!/bin/sh\n# FAKEKRAY version=" + version + "\n" +
		"echo \"W1nCray-xray v" + version + " (Xray-core 26.3.27)\"\n" +
		strings.Repeat("x", 256)
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write([]byte(bin)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// xrayAssetServer serves one gz blob at path, standing in for the GitHub
// release asset the panel's URL points at.
func xrayAssetServer(t *testing.T, path string, blob []byte) string {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(blob)
	}))
	t.Cleanup(s.Close)
	return s.URL + path
}

func sha256Of(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// recordingRunner is the service manager of the test machine: it records the
// commands and can trigger a state change when one of them runs.
type recordingRunner struct {
	calls  []string
	onCall func(name string, args []string)
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	if r.onCall != nil {
		r.onCall(name, args)
	}
	return nil, nil
}

// scriptedStatus is the kernel's own status endpoint. running is read on every
// call, so a test can change the answer mid-install.
type scriptedStatus struct {
	running bool
	err     error
}

func (s *scriptedStatus) Status(context.Context) (xrayapi.Status, error) {
	if s.err != nil {
		return xrayapi.Status{}, s.err
	}
	return xrayapi.Status{Running: s.running}, nil
}

func (s *scriptedStatus) CheckStaged(context.Context, string, []string) (xrayapi.StagedResult, error) {
	return xrayapi.StagedResult{OK: true}, nil
}

func (s *scriptedStatus) WaitReloaded(context.Context, string) error { return nil }

func (s *scriptedStatus) SyncMachineNodes(context.Context) (bool, error) { return false, nil }

// xrayDirectFixture wires the production pieces of a systemd machine: the real
// kernel installer (with the version self-check replaced by a read of the fake
// binary) behind the real service manager.
type xrayDirectFixture struct {
	t     *testing.T
	root  string
	run   *recordingRunner
	stat  *scriptedStatus
	in    *install.Installer
	svc   *xraysvc.Manager
	late  chan string
	last  chan json.RawMessage
	fails chan json.RawMessage
}

func newXrayDirectFixture(t *testing.T) *xrayDirectFixture {
	t.Helper()
	root := t.TempDir()
	for _, m := range []string{"run/systemd/system/"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(strings.TrimSuffix(m, "/"))), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	config := filepath.Join(root, "config.yml")
	if err := os.WriteFile(config, []byte("Log: {Level: warning}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	in, err := install.New(install.Config{
		Dir:       t.TempDir(),
		AllowHTTP: true,
		Check: func(path string) (string, error) {
			b, err := os.ReadFile(path)
			if err != nil {
				return "", err
			}
			m := reFakeXrayKernel.FindSubmatch(b)
			if m == nil {
				return "", os.ErrInvalid
			}
			return string(m[1]), nil
		},
		FreeSpace: func(string) (uint64, bool) { return 1 << 40, true },
	})
	if err != nil {
		t.Fatalf("install.New: %v", err)
	}
	f := &xrayDirectFixture{
		t: t, root: root, run: &recordingRunner{}, stat: &scriptedStatus{running: true}, in: in,
		late: make(chan string, 4), last: make(chan json.RawMessage, 4), fails: make(chan json.RawMessage, 4),
	}
	svc, err := xraysvc.New(xraysvc.Options{
		Root:           root,
		Kernels:        xrayKernels{fakeKernels: fakeKernels{}, in: in},
		ConfigPath:     config,
		Status:         f.stat,
		Runner:         f.run,
		HealthTimeout:  100 * time.Millisecond,
		HealthInterval: time.Millisecond,
		StatusTimeout:  50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("xraysvc.New: %v", err)
	}
	f.svc = svc
	return f
}

// xrayKernels is the KernelOps surface (fakeKernels) plus the InstallDirect
// capability, delegating to a real installer. It is what the production
// *kernelx.Ensurer is: a manager that answers both the manifest and the direct
// path.
type xrayKernels struct {
	fakeKernels
	in *install.Installer
}

func (k xrayKernels) InstallDirect(ctx context.Context, di install.DirectInstall) (driver.Installed, error) {
	return k.in.InstallDirect(ctx, di)
}

// Current, List and Rollback delegate to the same installer: the service
// manager must see what the direct install really did.
func (k xrayKernels) Current(name string) (driver.Installed, error) { return k.in.Current(name) }

func (k xrayKernels) List() ([]install.Entry, error) { return k.in.List() }

func (k xrayKernels) Rollback(name string) (driver.Installed, error) { return k.in.Rollback(name) }

// registry builds the command registry with the fixture's installer and
// service manager, reporting the late (sink) outcome.
func (f *xrayDirectFixture) registry() *Registry {
	f.t.Helper()
	return mustRegistry(f.t, Deps{
		Kernels: xrayKernels{fakeKernels: fakeKernels{listFn: f.in.List}, in: f.in},
		Xray:    f.svc,
		Sink: SinkFunc(func(id, status string, data json.RawMessage) {
			f.late <- status
			if status == panelclient.ResultDone {
				f.last <- data
			} else {
				f.fails <- data
			}
		}),
	})
}

// install runs one kernel_install and waits for its late outcome.
func (f *xrayDirectFixture) install(id, args string) (string, json.RawMessage) {
	f.t.Helper()
	reg := f.registry()
	status, res := reg.Execute(context.Background(), panelclient.Command{
		ID: id, Type: panelclient.CmdKernelInstall, Args: json.RawMessage(args),
	})
	if status != panelclient.ResultAccepted {
		return status, res
	}
	select {
	case got := <-f.late:
		if got == panelclient.ResultDone {
			return got, <-f.last
		}
		return got, <-f.fails
	case <-time.After(30 * time.Second):
		f.t.Fatal("kernel_install xray (direct) never finished")
		return "", nil
	}
}

// unitFile is the service definition the fixture's root owns.
func (f *xrayDirectFixture) unitFile() string {
	return filepath.Join(f.root, "etc", "systemd", "system", xraysvc.ServiceName+".service")
}

// installArgs builds the kernel_install args of the panel.
func installArgs(url, sha string, size int, version string) string {
	b, _ := json.Marshal(map[string]any{
		"name": "xray", "version": version, "url": url, "sha256": sha, "size": size,
	})
	return string(b)
}

// TestKernelInstallXrayDirectInstallsFromTheReleaseAsset is the defect this
// work package fixes: before it, the xray branch short-circuited before the URL
// check, so url/sha256/size were ignored and the version was resolved through
// the (missing) manifest. Now the asset is installed straight away and the
// service is really activated.
func TestKernelInstallXrayDirectInstallsFromTheReleaseAsset(t *testing.T) {
	f := newXrayDirectFixture(t)
	asset := xrayAssetGz(t, "0.8.2")
	url := xrayAssetServer(t, "/W1nCray-xray-linux-amd64.gz", asset)

	status, res := f.install("x1", installArgs(url, sha256Of(asset), len(asset), "0.8.2"))
	if status != panelclient.ResultDone {
		t.Fatalf("kernel_install xray (direct) = (%q, %s), want done", status, res)
	}
	var out installedResult
	if err := json.Unmarshal(res, &out); err != nil {
		t.Fatalf("result %s: %v", res, err)
	}
	if out.Name != "xray" || out.Version != "0.8.2" || out.Path == "" {
		t.Errorf("result = %+v, want xray@0.8.2 with a path", out)
	}
	cur, err := f.in.Current("xray")
	if err != nil {
		t.Fatalf("Current after the direct install: %v", err)
	}
	if cur.Version != "0.8.2" || filepath.Base(cur.Path) != xraysvc.XrayBinaryName {
		t.Errorf("installed kernel = %+v, want 0.8.2 installed as %s", cur, xraysvc.XrayBinaryName)
	}
	// The activation is the service flow: the unit names the installed binary
	// and the service was enabled and started.
	raw, rerr := os.ReadFile(f.unitFile())
	if rerr != nil {
		t.Fatalf("the unit file was not written: %v", rerr)
	}
	if !strings.Contains(string(raw), cur.Path) {
		t.Errorf("the unit does not execute the installed binary:\n%s", string(raw))
	}
	seq := strings.Join(f.run.calls, "\n")
	for _, want := range []string{"systemctl enable " + xraysvc.ServiceName, "systemctl start " + xraysvc.ServiceName} {
		if !strings.Contains(seq, want) {
			t.Errorf("the direct install did not run %q:\n%s", want, seq)
		}
	}
}

// TestKernelInstallXrayDirectRequiresASHA256: a URL without a hash is a
// protocol error (the panel pins the asset from the release), refused before
// anything is downloaded and with the stable invalid_args code.
func TestKernelInstallXrayDirectRequiresASHA256(t *testing.T) {
	f := newXrayDirectFixture(t)
	asset := xrayAssetGz(t, "0.8.2")
	url := xrayAssetServer(t, "/W1nCray-xray-linux-amd64.gz", asset)

	status, res := f.install("x2", installArgs(url, "", len(asset), "0.8.2"))
	if status != panelclient.ResultFailed {
		t.Fatalf("kernel_install without a sha256 = (%q, %s), want failed", status, res)
	}
	if code := decodeFailure(t, res).Code; code != "invalid_args" {
		t.Errorf("code = %q, want invalid_args", code)
	}
	if _, err := f.in.Current("xray"); err == nil {
		t.Error("the refused install made a version current")
	}
	if _, err := os.Stat(f.unitFile()); !os.IsNotExist(err) {
		t.Errorf("the refused install wrote the service file: %v", err)
	}
}

// TestKernelInstallXrayDirectRefusesAWrongHash: a mismatching asset hash fails
// the command with the kernel error code and leaves the current pointer and the
// service untouched.
func TestKernelInstallXrayDirectRefusesAWrongHash(t *testing.T) {
	f := newXrayDirectFixture(t)
	asset := xrayAssetGz(t, "0.8.2")
	url := xrayAssetServer(t, "/W1nCray-xray-linux-amd64.gz", asset)

	status, res := f.install("x3", installArgs(url, strings.Repeat("ab", 32), len(asset), "0.8.2"))
	if status != panelclient.ResultFailed {
		t.Fatalf("kernel_install with a wrong sha256 = (%q, %s), want failed", status, res)
	}
	if code := decodeFailure(t, res).Code; code != "verify_failed" {
		t.Errorf("code = %q, want verify_failed", code)
	}
	if _, err := f.in.Current("xray"); err == nil {
		t.Error("the refused version was made current")
	}
	if _, err := os.Stat(f.unitFile()); !os.IsNotExist(err) {
		t.Errorf("the refused install wrote the service file: %v", err)
	}
}

// TestKernelInstallXrayDirectUpgradeRollsBack is requirement 1's "same
// activate/health/rollback flow as Install/Upgrade": with a version already
// installed and serving, a direct upgrade that does not come up healthy is
// rolled back to the version that was running and the service is repointed at
// it.
func TestKernelInstallXrayDirectUpgradeRollsBack(t *testing.T) {
	f := newXrayDirectFixture(t)
	oldAsset := xrayAssetGz(t, "0.8.2")
	newAsset := xrayAssetGz(t, "0.8.3")
	oldURL := xrayAssetServer(t, "/W1nCray-xray-linux-amd64.gz", oldAsset)

	if status, res := f.install("u1", installArgs(oldURL, sha256Of(oldAsset), len(oldAsset), "0.8.2")); status != panelclient.ResultDone {
		t.Fatalf("first install = (%q, %s), want done", status, res)
	}
	old, err := f.in.Current("xray")
	if err != nil {
		t.Fatal(err)
	}

	// The restart that replaces the running 0.8.2 leaves the kernel unhealthy;
	// the state is read before the install, so the machine still counts as
	// serving when the manager decides what to preserve.
	f.run.onCall = func(name string, args []string) {
		if name == "systemctl" && len(args) > 0 && args[0] == "restart" {
			f.stat.running = false
		}
	}
	newURL := xrayAssetServer(t, "/W1nCray-xray-0.8.3-linux-amd64.gz", newAsset)
	status, res := f.install("u2", installArgs(newURL, sha256Of(newAsset), len(newAsset), "0.8.3"))
	if status != panelclient.ResultFailed {
		t.Fatalf("the failing upgrade = (%q, %s), want failed", status, res)
	}
	if !strings.Contains(decodeFailure(t, res).Error, "已回滚") {
		t.Errorf("failure = %s, want a rollback report", res)
	}
	cur, cerr := f.in.Current("xray")
	if cerr != nil {
		t.Fatal(cerr)
	}
	if cur.Version != "0.8.2" || cur.Path != old.Path {
		t.Fatalf("current after the failed upgrade = %+v, want the running %+v", cur, old)
	}
	raw, rerr := os.ReadFile(f.unitFile())
	if rerr != nil {
		t.Fatalf("the unit file is gone after the rollback: %v", rerr)
	}
	if !strings.Contains(string(raw), old.Path) {
		t.Errorf("the unit was not repointed at the rolled-back version:\n%s", string(raw))
	}
}

// TestKernelInstallXrayDirectWithoutTheCapabilityIsRefused: a service manager
// that cannot install from a URL keeps the clear not_supported refusal instead
// of silently resolving the version through the manifest (the defect DEC-4
// fixes).
func TestKernelInstallXrayDirectWithoutTheCapabilityIsRefused(t *testing.T) {
	reg := mustRegistry(t, Deps{Xray: &fakeXray{}})
	status, res := reg.Execute(context.Background(), panelclient.Command{
		ID: "x4", Type: panelclient.CmdKernelInstall,
		Args: json.RawMessage(`{"name":"xray","version":"0.8.2","url":"https://example.com/x.gz","sha256":"` + strings.Repeat("01", 32) + `"}`),
	})
	if status != panelclient.ResultFailed {
		t.Fatalf("status = %q (%s), want failed", status, res)
	}
	if code := decodeFailure(t, res).Code; code != "not_supported" {
		t.Errorf("code = %q, want not_supported", code)
	}
}

// TestKernelInstallXrayWithoutURLKeepsTheManifestPath is requirement 2: an
// xray kernel_install without a url keeps exactly the historical behaviour
// (Install when nothing is installed, Upgrade when a version already is), so an
// older panel is unaffected.
func TestKernelInstallXrayWithoutURLKeepsTheManifestPath(t *testing.T) {
	for _, tc := range []struct {
		name string
		list []install.Entry
		want string
	}{
		{"fresh install", nil, "install 0.8.2"},
		{"already installed upgrades", []install.Entry{{Name: "xray", Version: "0.8.1", Current: true}}, "upgrade 0.8.2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := &fakeXray{}
			late := make(chan string, 1)
			reg := mustRegistry(t, Deps{
				Kernels: fakeKernels{list: tc.list},
				Xray:    x,
				Sink: SinkFunc(func(id, status string, data json.RawMessage) {
					late <- status
				}),
			})
			status, res := reg.Execute(context.Background(), panelclient.Command{
				ID: "m1", Type: panelclient.CmdKernelInstall,
				Args: json.RawMessage(`{"name":"xray","version":"0.8.2"}`),
			})
			if status != panelclient.ResultAccepted {
				t.Fatalf("kernel_install status = %q (%s), want accepted", status, res)
			}
			select {
			case got := <-late:
				if got != panelclient.ResultDone {
					t.Fatalf("late status = %q, want done", got)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("kernel_install delivered no late result")
			}
			if len(x.calls) != 1 || x.calls[0] != tc.want {
				t.Fatalf("service calls = %v, want [%s]", x.calls, tc.want)
			}
		})
	}
}

// TestKernelInstallXrayDirectWithoutTheServiceIsRefused: the xray kernel runs
// as a service, so a URL on a machine whose kernel manager has no direct
// installer is a clear refusal (covered in full by
// TestKernelInstallDirectRefusesXrayService in direct_test.go; this pins the
// same answer for a service manager that is present but cannot install from a
// URL).
func TestKernelInstallXrayDirectWithoutTheServiceIsRefused(t *testing.T) {
	reg := mustRegistry(t, Deps{Xray: &fakeXray{}})
	status, res := reg.Execute(context.Background(), panelclient.Command{
		ID: "x5", Type: panelclient.CmdKernelInstall,
		Args: json.RawMessage(`{"name":"xray","version":"0.8.2","url":"https://example.com/x.gz","sha256":"` + strings.Repeat("01", 32) + `"}`),
	})
	if status != panelclient.ResultFailed {
		t.Fatalf("status = %q (%s), want failed", status, res)
	}
	if code := decodeFailure(t, res).Code; code != "not_supported" {
		t.Errorf("code = %q, want not_supported", code)
	}
}
