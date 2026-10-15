// The manifest-free install path of the Xray kernel service (DEC-4): the
// panel pins a release asset (url + sha256) and the manager installs it
// straight away, then activates it through exactly the same service flow as a
// manifest install — including the health check and the rollback to the
// version that was running.

package xraysvc

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/kernel/install"
)

// reFakeXrayVersion reads the version out of a fake kernel "binary" (a text
// file, so no target binary has to be executed in the test).
var reFakeXrayVersion = regexp.MustCompile(`FAKEKRAY version=(\S+)`)

// fakeXrayAsset is one gz release asset holding a fake W1nCray-xray binary that
// reports version.
func fakeXrayAsset(t *testing.T, version string) []byte {
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

// serveXrayAsset serves one gz blob, standing in for the GitHub release asset
// (the direct downloader is what the panel's URL points at).
func serveXrayAsset(t *testing.T, blob []byte) string {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(blob)
	}))
	t.Cleanup(s.Close)
	return s.URL + "/W1nCray-xray-linux-amd64.gz"
}

func sha256Of(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// newRealInstaller is the production installer with the version self-check
// replaced by a read of the fake binary (the same trade the kernel/install
// tests make): the download, the sha256 check, the extraction and commit() are
// all the real code.
func newRealInstaller(t *testing.T) *install.Installer {
	t.Helper()
	in, err := install.New(install.Config{
		Dir:       t.TempDir(),
		AllowHTTP: true,
		Check: func(path string) (string, error) {
			b, err := os.ReadFile(path)
			if err != nil {
				return "", err
			}
			m := reFakeXrayVersion.FindSubmatch(b)
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
	return in
}

// directKernels is the service manager's Kernels surface (fakeKernels) plus the
// optional InstallDirect capability, delegating to a real installer so the
// direct install is exercised against the code that downloads, verifies,
// extracts and switches.
type directKernels struct {
	*fakeKernels
	in *install.Installer
}

func (d directKernels) InstallDirect(ctx context.Context, di install.DirectInstall) (driver.Installed, error) {
	return d.in.InstallDirect(ctx, di)
}

func (d directKernels) Current(name string) (driver.Installed, error) { return d.in.Current(name) }

func (d directKernels) List() ([]install.Entry, error) { return d.in.List() }

func (d directKernels) Rollback(name string) (driver.Installed, error) { return d.in.Rollback(name) }

// newDirectFixture builds a systemd machine whose kernel manager can install
// straight from a URL. The returned runner records the service-manager calls.
func newDirectFixture(t *testing.T) (*Manager, *fakeRunner, *fakeStatus, *install.Installer) {
	t.Helper()
	root := tmpRoot(t, "run/systemd/system/")
	config := filepath.Join(root, "config.yml")
	if err := os.WriteFile(config, []byte("Log: {Level: warning}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	in := newRealInstaller(t)
	status := &fakeStatus{running: true}
	run := &fakeRunner{}
	m, err := New(Options{
		Root:           root,
		Kernels:        directKernels{fakeKernels: &fakeKernels{curErr: errors.New("not installed")}, in: in},
		ConfigPath:     config,
		Status:         status,
		Runner:         run,
		HealthTimeout:  100 * time.Millisecond,
		HealthInterval: time.Millisecond,
		StatusTimeout:  50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return m, run, status, in
}

// unitPath is the service definition of the fixture's root.
func unitPath(root string) string {
	return filepath.Join(root, "etc", "systemd", "system", ServiceName+".service")
}

// TestInstallDirectInstallsFromAReleaseAssetAndActivates is the fresh-machine
// half of DEC-4: url + sha256 install the asset with no manifest at all, the
// installed file is the W1nCray-xray the unit executes (not the "xray" name
// install.DefaultKernelRun would pick), and the service is really written,
// enabled and started.
func TestInstallDirectInstallsFromAReleaseAssetAndActivates(t *testing.T) {
	m, run, _, in := newDirectFixture(t)
	asset := fakeXrayAsset(t, "0.8.2")
	url := serveXrayAsset(t, asset)

	err := m.InstallDirect(context.Background(), install.DirectInstall{
		Name:    "xray",
		Version: "0.8.2",
		URL:     url,
		SHA256:  sha256Of(asset),
		Size:    int64(len(asset)),
	})
	if err != nil {
		t.Fatalf("InstallDirect: %v", err)
	}

	cur, cerr := in.Current("xray")
	if cerr != nil {
		t.Fatalf("Current after the direct install: %v", cerr)
	}
	if cur.Version != "0.8.2" {
		t.Errorf("current version = %q, want 0.8.2", cur.Version)
	}
	if filepath.Base(cur.Path) != XrayBinaryName {
		t.Errorf("installed file = %q, want the %s the unit executes", cur.Path, XrayBinaryName)
	}
	if _, serr := os.Stat(cur.Path); serr != nil {
		t.Fatalf("the installed binary is missing: %v", serr)
	}

	// The activation is the service flow: unit written for the installed
	// binary, service enabled and started.
	raw, rerr := os.ReadFile(unitPath(m.opts.Root))
	if rerr != nil {
		t.Fatalf("the unit file was not written: %v", rerr)
	}
	if !strings.Contains(string(raw), cur.Path) {
		t.Errorf("the unit does not execute the installed binary:\n%s", string(raw))
	}
	seq := strings.Join(run.seq(), "\n")
	for _, want := range []string{"systemctl enable " + ServiceName, "systemctl start " + ServiceName} {
		if !strings.Contains(seq, want) {
			t.Errorf("the direct install did not run %q:\n%s", want, seq)
		}
	}
}

// TestInstallDirectRequiresASHA256: the asset hash is the anchor of the
// manifest-free path, so an empty one is refused before anything is downloaded
// or switched in.
func TestInstallDirectRequiresASHA256(t *testing.T) {
	m, run, _, in := newDirectFixture(t)
	asset := fakeXrayAsset(t, "0.8.2")
	url := serveXrayAsset(t, asset)

	err := m.InstallDirect(context.Background(), install.DirectInstall{
		Name: "xray", Version: "0.8.2", URL: url, Size: int64(len(asset)),
	})
	if err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("InstallDirect without a sha256 = %v, want a sha256 refusal", err)
	}
	if _, cerr := in.Current("xray"); cerr == nil {
		t.Error("a refused direct install left a current version behind")
	}
	if len(run.seq()) != 0 {
		t.Errorf("a refused direct install touched the service: %v", run.seq())
	}
}

// TestInstallDirectRefusesAWrongSHA256: a mismatching asset hash fails the
// install and leaves the service and the current pointer untouched.
func TestInstallDirectRefusesAWrongSHA256(t *testing.T) {
	m, run, _, in := newDirectFixture(t)
	asset := fakeXrayAsset(t, "0.8.2")
	url := serveXrayAsset(t, asset)

	err := m.InstallDirect(context.Background(), install.DirectInstall{
		Name: "xray", Version: "0.8.2", URL: url,
		SHA256: strings.Repeat("ab", 32), Size: int64(len(asset)),
	})
	if err == nil {
		t.Fatal("a wrong sha256 must fail the install")
	}
	if _, cerr := in.Current("xray"); cerr == nil {
		t.Error("the refused version was made current")
	}
	if _, serr := os.Stat(unitPath(m.opts.Root)); !os.IsNotExist(serr) {
		t.Errorf("the refused install wrote the service file: %v", serr)
	}
	if len(run.seq()) != 0 {
		t.Errorf("the refused install touched the service: %v", run.seq())
	}
}

// TestInstallDirectWithoutTheInstallerCapabilityIsRefused: the direct path is
// an optional capability of the kernel manager. A manager without it (an older
// wiring, a fake) answers a clear refusal instead of pretending the install
// happened.
func TestInstallDirectWithoutTheInstallerCapabilityIsRefused(t *testing.T) {
	root := tmpRoot(t, "run/systemd/system/")
	config := filepath.Join(root, "config.yml")
	if err := os.WriteFile(config, []byte("Log: {Level: warning}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := New(Options{
		Root:       root,
		Kernels:    &fakeKernels{curErr: errors.New("not installed")},
		ConfigPath: config,
		Status:     &fakeStatus{running: true},
		Runner:     &fakeRunner{},
	})
	if err != nil {
		t.Fatal(err)
	}
	asset := fakeXrayAsset(t, "0.8.2")
	err = m.InstallDirect(context.Background(), install.DirectInstall{
		Name: "xray", Version: "0.8.2", URL: serveXrayAsset(t, asset), SHA256: sha256Of(asset),
	})
	if err == nil || !strings.Contains(err.Error(), "直连内核安装器") {
		t.Fatalf("InstallDirect without the capability = %v, want a clear refusal", err)
	}
}

// TestInstallDirectUpgradeRollsBackWhenTheHealthCheckFails: with a version
// already installed and serving, the direct install is an upgrade, and a new
// version that does not come up healthy is rolled back to the one that was
// running — the same guarantee the manifest Upgrade gives.
func TestInstallDirectUpgradeRollsBackWhenTheHealthCheckFails(t *testing.T) {
	m, run, status, in := newDirectFixture(t)
	oldAsset := fakeXrayAsset(t, "0.8.2")
	newAsset := fakeXrayAsset(t, "0.8.3")

	// The machine is already serving 0.8.2.
	if err := m.InstallDirect(context.Background(), install.DirectInstall{
		Name: "xray", Version: "0.8.2", URL: serveXrayAsset(t, oldAsset),
		SHA256: sha256Of(oldAsset), Size: int64(len(oldAsset)),
	}); err != nil {
		t.Fatalf("first InstallDirect: %v", err)
	}
	old, err := in.Current("xray")
	if err != nil {
		t.Fatal(err)
	}

	// The upgrade installs, but the service never reports running again: the
	// restart that replaces the running 0.8.2 with the new binary leaves the
	// kernel unhealthy. The state is read *before* the install, so the machine
	// is still serving when InstallDirect decides what to preserve.
	run.onCall = func(name string, args []string) {
		if name == "systemctl" && len(args) > 0 && args[0] == "restart" {
			status.setRunning(false)
		}
	}
	err = m.InstallDirect(context.Background(), install.DirectInstall{
		Name: "xray", Version: "0.8.3", URL: serveXrayAsset(t, newAsset),
		SHA256: sha256Of(newAsset), Size: int64(len(newAsset)),
	})
	if err == nil || !strings.Contains(err.Error(), "已回滚") {
		t.Fatalf("InstallDirect upgrade error = %v, want a rollback report", err)
	}
	cur, cerr := in.Current("xray")
	if cerr != nil {
		t.Fatal(cerr)
	}
	if cur.Version != "0.8.2" || cur.Path != old.Path {
		t.Fatalf("current after the failed upgrade = %+v, want the running %+v", cur, old)
	}
	raw, rerr := os.ReadFile(unitPath(m.opts.Root))
	if rerr != nil {
		t.Fatalf("the unit file is gone after the rollback: %v", rerr)
	}
	if !strings.Contains(string(raw), old.Path) {
		t.Errorf("the unit was not repointed at the rolled-back version:\n%s", string(raw))
	}
	// The upgrade really tried: the service was restarted for the new version.
	if seq := strings.Join(run.seq(), "\n"); !strings.Contains(seq, "systemctl restart "+ServiceName) {
		t.Errorf("the upgrade never restarted the service:\n%s", seq)
	}
}
