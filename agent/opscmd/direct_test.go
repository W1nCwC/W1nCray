// The direct (manifest-free) paths of kernel_install and self_update, added
// with v0.8.0: the panel pins the asset in the command args and the manifest
// is never consulted. The manifest paths keep their own tests.

package opscmd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/panelclient"
	"github.com/W1nCwC/W1nCray/agent/selfupdate"
	"github.com/W1nCwC/W1nCray/kernel/install"
)

// directKernels is fakeKernels plus the InstallDirect capability, delegating
// to a real install.Installer so the direct install is exercised against the
// code that downloads, verifies and switches.
type directKernels struct {
	fakeKernels
	in *install.Installer
}

func (d directKernels) InstallDirect(ctx context.Context, di install.DirectInstall) (driver.Installed, error) {
	return d.in.InstallDirect(ctx, di)
}

// directServer serves one gz blob, standing in for the release asset.
func directServer(t *testing.T, path string, blob []byte) string {
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

// TestKernelInstallDirectInstallsFromTheArgs: a URL in the args installs the
// asset straight away — no manifest is loaded at all, which is the point of
// the path.
func TestKernelInstallDirectInstallsFromTheArgs(t *testing.T) {
	rig := newKernelRig(t)
	bin := []byte("#!/bin/sh\n# FAKEKERNEL version=3.0.0\n" + strings.Repeat("x", 512))
	// The kernel/install fixture checker reads the file, so a bare gz of the
	// text binary is enough (the direct path accepts the bare binary too).
	archive := gzBytes(t, bin)
	url := directServer(t, "/w1ncray-kernel-gost-3.0.0.gz", archive)

	calls := make(chan sinkCall, 4)
	reg := mustRegistry(t, Deps{
		Kernels: directKernels{fakeKernels: fakeKernels{}, in: rig.in},
		Sink: SinkFunc(func(id, status string, data json.RawMessage) {
			calls <- sinkCall{id: id, status: status, data: data}
		}),
	})
	args := `{"name":"gost","version":"3.0.0","url":"` + url + `","sha256":"` + sha256Hex(archive) + `","size":` +
		itoa(int64(len(archive))) + `}`
	status, res := reg.Execute(context.Background(), panelclient.Command{
		ID: "d1", Type: panelclient.CmdKernelInstall, Args: json.RawMessage(args),
	})
	if status != panelclient.ResultAccepted {
		t.Fatalf("first answer = (%q, %s), want accepted", status, res)
	}
	select {
	case c := <-calls:
		if c.status != panelclient.ResultDone {
			t.Fatalf("final = %+v, want done", c)
		}
		var out installedResult
		if err := json.Unmarshal(c.data, &out); err != nil {
			t.Fatalf("result %s: %v", c.data, err)
		}
		if out.Name != "gost" || out.Version != "3.0.0" || out.Path == "" {
			t.Errorf("result = %+v", out)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("kernel_install (direct) never finished")
	}
	entries, err := rig.in.List()
	if err != nil {
		t.Fatal(err)
	}
	var current bool
	for _, e := range entries {
		if e.Name == "gost" && e.Version == "3.0.0" && e.Current {
			current = true
		}
	}
	if !current {
		t.Errorf("gost@3.0.0 is not current: %+v", entries)
	}
}

// A bad sha256 fails the command and installs nothing.
func TestKernelInstallDirectRefusesWrongHash(t *testing.T) {
	rig := newKernelRig(t)
	url := directServer(t, "/gost.gz", gzBytes(t, []byte("#!/bin/sh\n# FAKEKERNEL version=3.0.0\n")))

	calls := make(chan sinkCall, 4)
	reg := mustRegistry(t, Deps{
		Kernels: directKernels{fakeKernels: fakeKernels{}, in: rig.in},
		Sink: SinkFunc(func(id, status string, data json.RawMessage) {
			calls <- sinkCall{id: id, status: status, data: data}
		}),
	})
	args := `{"name":"gost","version":"3.0.0","url":"` + url + `","sha256":"` + strings.Repeat("ab", 32) + `"}`
	reg.Execute(context.Background(), panelclient.Command{
		ID: "d2", Type: panelclient.CmdKernelInstall, Args: json.RawMessage(args),
	})
	select {
	case c := <-calls:
		if c.status != panelclient.ResultFailed {
			t.Fatalf("final = %+v, want failed", c)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the refusal never arrived")
	}
	if l, _ := rig.in.List(); len(l) != 0 {
		t.Errorf("a refused install must not touch the kernel directory: %+v", l)
	}
}

// A direct URL for the Xray kernel on a machine whose kernel manager has no
// direct installer is a clear refusal, never a silent downgrade to the manifest
// (DEC-4: the args used to be ignored and the manifest was consulted instead).
func TestKernelInstallDirectRefusesXrayService(t *testing.T) {
	reg := mustRegistry(t, Deps{Kernels: fakeKernels{}})
	status, res := reg.Execute(context.Background(), panelclient.Command{
		ID: "d3", Type: panelclient.CmdKernelInstall,
		Args: json.RawMessage(`{"name":"xray","version":"1.0.0","url":"https://example.com/x.gz","sha256":"` + strings.Repeat("01", 32) + `"}`),
	})
	if status != panelclient.ResultFailed {
		t.Fatalf("status = %q (%s), want failed", status, res)
	}
	if f := decodeFailure(t, res); f.Code != "not_supported" {
		t.Errorf("code = %q, want not_supported", f.Code)
	}
}

// directUpdater is fakeUpdater plus the StageDirect capability. It records
// what the command asked for so the routing (direct vs manifest) is observed.
type directUpdater struct {
	fakeUpdater
	got struct {
		version, url, sha256 string
	}
}

func (d *directUpdater) StageDirect(_ context.Context, version, url, sha256 string) (selfupdate.Staged, error) {
	d.got.version, d.got.url, d.got.sha256 = version, url, sha256
	return d.staged, d.stageErr
}

// TestSelfUpdateSha256RoutesDirect: args with a sha256 build the conventional
// GitHub release URL and stage through StageDirect; args without one keep the
// historical manifest path (Stage).
func TestSelfUpdateSha256RoutesDirect(t *testing.T) {
	up := &directUpdater{fakeUpdater: fakeUpdater{
		staged: selfupdate.Staged{Version: "0.8.0", Path: "/state/update/staged/0.8.0/W1nCray"},
	}}
	reg, calls := selfUpdateRegistry(t, up, func() {})
	status, _ := reg.Execute(context.Background(), panelclient.Command{
		ID: "s2", Type: panelclient.CmdSelfUpdate,
		Args: json.RawMessage(`{"version":"0.8.0","sha256":"` + strings.Repeat("01", 32) + `"}`),
	})
	if status != panelclient.ResultAccepted {
		t.Fatalf("status = %q, want accepted", status)
	}
	select {
	case c := <-calls:
		if c.status != panelclient.ResultDone {
			t.Fatalf("final = %+v, want done", c)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the final result never arrived")
	}
	if up.got.version != "0.8.0" || up.got.sha256 != strings.Repeat("01", 32) {
		t.Errorf("StageDirect got (%q, %q)", up.got.version, up.got.sha256)
	}
	want := "https://github.com/W1nCwC/W1nCray/releases/download/v0.8.0/w1ncray-v0.8.0-" + goosArch() + ".gz"
	if up.got.url != want {
		t.Errorf("url = %s, want %s", up.got.url, want)
	}
}

// TestSelfUpdateWithoutSha256KeepsTheManifestPath: the fallback stays exactly
// what it was — Stage resolves the version through the signed manifest.
func TestSelfUpdateWithoutSha256KeepsTheManifestPath(t *testing.T) {
	up := &directUpdater{fakeUpdater: fakeUpdater{
		staged: selfupdate.Staged{Version: "0.7.0", Path: "/state/update/staged/0.7.0/W1nCray"},
	}}
	reg, calls := selfUpdateRegistry(t, up, func() {})
	if status, _ := reg.Execute(context.Background(), panelclient.Command{
		ID: "s3", Type: panelclient.CmdSelfUpdate, Args: json.RawMessage(`{"version":"0.7.0"}`),
	}); status != panelclient.ResultAccepted {
		t.Fatal("expected accepted")
	}
	select {
	case c := <-calls:
		if c.status != panelclient.ResultDone {
			t.Fatalf("final = %+v, want done", c)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the final result never arrived")
	}
	if up.got.url != "" {
		t.Errorf("the manifest path must not consult a release URL: %s", up.got.url)
	}
}

// A sha256 sent to an updater without the direct capability is a clear
// refusal, not a silent manifest lookup.
func TestSelfUpdateSha256WithoutTheCapabilityIsRefused(t *testing.T) {
	reg, calls := selfUpdateRegistry(t, &fakeUpdater{}, func() {})
	if status, _ := reg.Execute(context.Background(), panelclient.Command{
		ID: "s4", Type: panelclient.CmdSelfUpdate,
		Args: json.RawMessage(`{"version":"0.8.0","sha256":"` + strings.Repeat("01", 32) + `"}`),
	}); status != panelclient.ResultAccepted {
		t.Fatal("expected accepted before the async refusal")
	}
	select {
	case c := <-calls:
		if c.status != panelclient.ResultFailed {
			t.Fatalf("final = %+v, want failed", c)
		}
		var f failure
		if err := json.Unmarshal(c.data, &f); err != nil {
			t.Fatalf("result %s: %v", c.data, err)
		}
		if f.Code != "not_supported" {
			t.Errorf("code = %q, want not_supported", f.Code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the refusal never arrived")
	}
}

// tarGzBytes builds the upstream frp archive shape: one tar.gz holding both
// binaries under a directory prefix.
func tarGzBytes(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, name := range []string{"frpc", "frps"} {
		data := entries[name]
		hdr := &tar.Header{Name: "frp_0.71.0_linux_amd64/" + name, Mode: 0o755, Size: int64(len(data))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestKernelInstallDirectMembersInstallsBothBinaries: the args carry a
// "members" list, so one frp tar.gz installs frpc and frps in one command.
// The JSON field is what the panel sends for an agent >= 0.8.7.
func TestKernelInstallDirectMembersInstallsBothBinaries(t *testing.T) {
	rig := newKernelRig(t)
	frpc := []byte("#!/bin/sh\n# FAKEKERNEL version=0.71.0\n" + strings.Repeat("x", 512))
	frps := []byte("#!/bin/sh\n# FAKEKERNEL version=0.71.0\n" + strings.Repeat("y", 640))
	archive := tarGzBytes(t, map[string][]byte{"frpc": frpc, "frps": frps})
	url := directServer(t, "/W1nCray-frp-linux-amd64.tar.gz", archive)

	calls := make(chan sinkCall, 4)
	reg := mustRegistry(t, Deps{
		Kernels: directKernels{fakeKernels: fakeKernels{}, in: rig.in},
		Sink: SinkFunc(func(id, status string, data json.RawMessage) {
			calls <- sinkCall{id: id, status: status, data: data}
		}),
	})
	args := `{"name":"frp","version":"0.71.0","url":"` + url + `","sha256":"` + sha256Hex(archive) +
		`","size":` + itoa(int64(len(archive))) +
		`,"archive":"tar.gz","members":[{"from":"frp_0.71.0_linux_amd64/frpc","to":"frpc"},` +
		`{"from":"frp_0.71.0_linux_amd64/frps","to":"frps"}]}`
	status, res := reg.Execute(context.Background(), panelclient.Command{
		ID: "dm1", Type: panelclient.CmdKernelInstall, Args: json.RawMessage(args),
	})
	if status != panelclient.ResultAccepted {
		t.Fatalf("first answer = (%q, %s), want accepted", status, res)
	}
	var out installedResult
	select {
	case c := <-calls:
		if c.status != panelclient.ResultDone {
			t.Fatalf("final = %+v, want done", c)
		}
		if err := json.Unmarshal(c.data, &out); err != nil {
			t.Fatalf("result %s: %v", c.data, err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("kernel_install (direct members) never finished")
	}
	if out.Name != "frp" || out.Version != "0.71.0" || out.Path == "" {
		t.Fatalf("result = %+v", out)
	}
	dir := filepath.Dir(out.Path)
	for _, want := range []struct {
		name string
		data []byte
	}{{"frpc", frpc}, {"frps", frps}} {
		b, err := os.ReadFile(filepath.Join(dir, want.name))
		if err != nil {
			t.Fatalf("%s: %v", want.name, err)
		}
		if string(b) != string(want.data) {
			t.Errorf("%s differs from the archive member", want.name)
		}
	}
	entries, err := rig.in.List()
	if err != nil {
		t.Fatal(err)
	}
	var current bool
	for _, e := range entries {
		if e.Name == "frp" && e.Version == "0.71.0" && e.Current {
			current = true
		}
	}
	if !current {
		t.Errorf("frp@0.71.0 is not current: %+v", entries)
	}
}

// TestKernelInstallArgsRejectUnknownFields: the strict decoder that makes
// "members" safe to add — an unknown field is still invalid_args, so an old
// agent refuses the field instead of ignoring it.
func TestKernelInstallArgsRejectUnknownFields(t *testing.T) {
	reg := mustRegistry(t, Deps{Kernels: fakeKernels{}})
	status, res := reg.Execute(context.Background(), panelclient.Command{
		ID: "dm2", Type: panelclient.CmdKernelInstall,
		Args: json.RawMessage(`{"name":"frp","version":"0.71.0","memberz":[]}`),
	})
	if status != panelclient.ResultFailed {
		t.Fatalf("status = %q (%s), want failed", status, res)
	}
	if code := decodeFailure(t, res).Code; code != "invalid_args" {
		t.Errorf("code = %q, want invalid_args", code)
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// gzBytes is a raw gzip stream of data, the release asset shape.
func gzBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func goosArch() string { return runtime.GOOS + "-" + runtime.GOARCH }
