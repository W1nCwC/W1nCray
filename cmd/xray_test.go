package cmd

import (
	"context"
	"errors"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/agentcfg"
	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/xrayapi"
	"github.com/W1nCwC/W1nCray/agentd"
	"github.com/W1nCwC/W1nCray/kernel/install"
)

// fakeXrayLocal records the LocalInstall the command builds.
type fakeXrayLocal struct {
	got  install.LocalInstall
	inst driver.Installed
	err  error
}

func (f *fakeXrayLocal) InstallLocal(_ context.Context, li install.LocalInstall) (driver.Installed, error) {
	f.got = li
	return f.inst, f.err
}

// TestXrayKernelVersionRegex pins the extraction the manifest entry and the
// local install share: the kernel banner must yield 0.6.0.
func TestXrayKernelVersionRegex(t *testing.T) {
	re, err := regexp.Compile(xrayKernelRun.VersionRegex)
	if err != nil {
		t.Fatalf("compile %q: %v", xrayKernelRun.VersionRegex, err)
	}
	m := re.FindStringSubmatch("W1nCray-xray v0.6.0 (Xray-core 26.3.27)")
	if len(m) < 2 || m[1] != "0.6.0" {
		t.Fatalf("regex on the banner = %v, want 0.6.0", m)
	}
	if xrayKernelRun.Binary != xrayBinaryName || len(xrayKernelRun.VersionCmd) != 1 || xrayKernelRun.VersionCmd[0] != "version" {
		t.Fatalf("xrayKernelRun = %+v", xrayKernelRun)
	}
}

// TestXrayKernelOptionsCarryTheLocalHTTPSwitch covers D-M1's `W1nCray xray
// install` half: the command builds its kernel installer from the machine's own
// configuration, so Kernels.AllowHTTP reaches it exactly as it reaches the
// service.
func TestXrayKernelOptionsCarryTheLocalHTTPSwitch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	if off := xrayKernelOptions(path, &agentd.Config{}); off.AllowHTTP {
		t.Errorf("a machine without the switch must stay https-only: %+v", off)
	}
	on := xrayKernelOptions(path, &agentd.Config{Agent: &agentcfg.Config{Kernels: &agentcfg.KernelsConfig{AllowHTTP: true}}})
	if !on.AllowHTTP {
		t.Error("Kernels.AllowHTTP: true did not reach the xray command's installer")
	}
	if want := filepath.Join(filepath.Dir(path), "state"); on.StateDir != want {
		t.Errorf("StateDir = %q, want %q", on.StateDir, want)
	}
	if want := filepath.Join(filepath.Dir(path), "state", "kernels"); on.KernelsDir != want {
		t.Errorf("KernelsDir = %q, want %q", on.KernelsDir, want)
	}
}

// TestXrayInstallLocalPinsTheFile checks the local install passes the file,
// its sha256 and the kernel's run block to the kernel installer.
func TestXrayInstallLocalPinsTheFile(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	f := &fakeXrayLocal{inst: driver.Installed{Version: "0.6.0", Path: "/kernels/xray/0.6.0/" + xrayBinaryName}}
	if err := xrayInstallLocal(context.Background(), f, "/tmp/W1nCray-xray-linux-amd64.gz", sha); err != nil {
		t.Fatalf("xrayInstallLocal: %v", err)
	}
	if f.got.Name != xrayapi.KernelName {
		t.Errorf("kernel name = %q, want %q", f.got.Name, xrayapi.KernelName)
	}
	if f.got.Archive != "/tmp/W1nCray-xray-linux-amd64.gz" || f.got.ArchiveSHA256 != sha {
		t.Errorf("archive/sha = %q/%q", f.got.Archive, f.got.ArchiveSHA256)
	}
	if f.got.To != xrayBinaryName {
		t.Errorf("installed name = %q, want %q", f.got.To, xrayBinaryName)
	}
	if f.got.Run.Binary != xrayBinaryName || len(f.got.Run.VersionCmd) != 1 {
		t.Errorf("run = %+v", f.got.Run)
	}
}

// TestXrayInstallLocalPropagatesErrors keeps the caller's error intact.
func TestXrayInstallLocalPropagatesErrors(t *testing.T) {
	boom := errors.New("sha256 mismatch")
	f := &fakeXrayLocal{err: boom}
	err := xrayInstallLocal(context.Background(), f, "/x", strings.Repeat("a", 64))
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
}

// TestXrayInstallFlagValidation covers the combinations refused before any
// configuration or file is touched.
func TestXrayInstallFlagValidation(t *testing.T) {
	sha := strings.Repeat("a", 64)
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"sha without file", []string{"--sha256", sha}, "--sha256 只能与 --file"},
		{"file without sha", []string{"--file", "/x/W1nCray-xray.gz"}, "--file 需要 --sha256"},
		{"file and version", []string{"--file", "/x/W1nCray-xray.gz", "--sha256", sha, "0.6.0"}, "--file 与版本号参数"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := xrayInstallCmd()
			c.SilenceUsage = true
			c.SilenceErrors = true
			c.SetArgs(tc.args)
			err := c.Execute()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
