package opscmd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/panelclient"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/kernel/install"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
	"github.com/W1nCwC/W1nCray/kernel/platform"
)

// kernelRig is a real kernel/install installer backed by a local HTTP server
// and a signed manifest. The kernel_* commands are exercised through it, so
// "refuses the current version", "clears the previous pointer" and "swaps the
// pointers" are proved against the code that actually does it, not against a
// fake.
type kernelRig struct {
	t    *testing.T
	in   *install.Installer
	srv  *httptest.Server
	priv ed25519.PrivateKey
	plat platform.Info
	seq  int64

	kernels []manifest.Kernel
	blobs   map[string][]byte
}

var reFakeVersion = regexp.MustCompile(`FAKEKERNEL version=(\S+)`)

func newKernelRig(t *testing.T) *kernelRig {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rig := &kernelRig{
		t:     t,
		priv:  priv,
		plat:  platform.Detect(),
		blobs: map[string][]byte{},
	}
	rig.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := rig.blobs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(rig.srv.Close)

	in, err := install.New(install.Config{
		Dir:       t.TempDir(),
		Keys:      []manifest.Key{manifest.NewKey(pub)},
		Platform:  &rig.plat,
		AllowHTTP: true,
		// The fake binary is a text file, not a runnable program; the version
		// it "reports" is embedded in it.
		Check: func(path string) (string, error) {
			b, err := os.ReadFile(path)
			if err != nil {
				return "", err
			}
			m := reFakeVersion.FindSubmatch(b)
			if m == nil {
				return "", os.ErrInvalid
			}
			return string(m[1]), nil
		},
		FreeSpace:  func(string) (uint64, bool) { return 1 << 40, true },
		Now:        time.Now,
		RetryDelay: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("install.New: %v", err)
	}
	rig.in = in
	return rig
}

// addVersion publishes one signed, downloadable version of the "gost" kernel.
func (r *kernelRig) addVersion(version string) {
	r.t.Helper()
	bin := []byte("#!/bin/sh\n# FAKEKERNEL version=" + version + "\n" + strings.Repeat("x", 512))
	archive := tarGz(r.t, "gost", bin)
	path := "/gost-" + version + ".tar.gz"
	r.blobs[path] = archive
	r.kernels = append(r.kernels, manifest.Kernel{
		Name: "gost", Version: version, Channel: "stable",
		License: manifest.License{SPDX: "MIT"},
		Run:     manifest.Run{Binary: "gost", VersionCmd: []string{"-V"}},
		Targets: map[string]*manifest.Target{
			r.plat.Key(): {
				URLs:          []string{r.srv.URL + path},
				Archive:       manifest.ArchiveTarGz,
				ArchiveSHA256: sha256Hex(archive),
				ArchiveSize:   int64(len(archive)),
				Extract: []manifest.Extract{{
					From: "gost", To: "gost", SHA256: sha256Hex(bin), Size: int64(len(bin)), Mode: "0755",
				}},
			},
		},
	})
	r.seq++
	raw, err := manifest.Sign(&manifest.Manifest{
		Schema: manifest.SchemaVersion, Sequence: r.seq,
		IssuedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(24 * time.Hour),
		Kernels: r.kernels,
	}, r.priv)
	if err != nil {
		r.t.Fatalf("sign manifest: %v", err)
	}
	if err := r.in.LoadManifest(raw); err != nil {
		r.t.Fatalf("LoadManifest: %v", err)
	}
}

func (r *kernelRig) ensure(version string) driver.Installed {
	r.t.Helper()
	inst, err := r.ensurePin(context.Background(), spec.KernelPin{Name: "gost", Version: version})
	if err != nil {
		r.t.Fatalf("Ensure %s: %v", version, err)
	}
	return inst
}

// ensurePin mirrors kernelx.Ensurer.Ensure: an empty version selects the newest
// version the manifest lists. (The real agent gets that behaviour from kernelx;
// this rig talks to kernel/install directly so the command layer is exercised
// against the installer that actually refuses and swaps.)
func (r *kernelRig) ensurePin(ctx context.Context, pin spec.KernelPin) (driver.Installed, error) {
	if pin.Version == "" {
		m := r.in.Manifest()
		if m == nil {
			return driver.Installed{}, errors.New("no signed manifest loaded")
		}
		best := ""
		for _, k := range m.Kernels {
			if k.Name != pin.Name {
				continue
			}
			if best == "" || manifest.CompareVersions(k.Version, best) > 0 {
				best = k.Version
			}
		}
		if best == "" {
			return driver.Installed{}, fmt.Errorf("manifest lists no version of kernel %q", pin.Name)
		}
		pin.Version = best
	}
	return r.in.Ensure(ctx, pin)
}

// ops exposes the installer through the opscmd surface. running/exact stand in
// for the process check: the rig never runs a kernel binary.
func (r *kernelRig) ops(running string, exact bool) KernelOps {
	return fakeKernels{
		running:   running,
		exact:     exact,
		listFn:    r.in.List,
		catalogFn: r.in.Catalog,
		ensureFn:  r.ensurePin,
		removeFn:  r.in.Remove,
		rollFn:    r.in.Rollback,
	}
}

// list returns the installer's current view.
func (r *kernelRig) list() []install.Entry {
	r.t.Helper()
	l, err := r.in.List()
	if err != nil {
		r.t.Fatalf("List: %v", err)
	}
	return l
}

func (r *kernelRig) entry(version string) (install.Entry, bool) {
	for _, e := range r.list() {
		if e.Version == version {
			return e, true
		}
	}
	return install.Entry{}, false
}

func tarGz(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// TestKernelInstallIsLongAndInstallsTheNewestVersion covers the accepted -> done
// two-phase delivery with a real installer: an empty version means "newest the
// manifest offers".
func TestKernelInstallIsLongAndInstallsTheNewestVersion(t *testing.T) {
	rig := newKernelRig(t)
	rig.addVersion("1.0.0")
	rig.addVersion("2.0.0")

	calls := make(chan sinkCall, 4)
	reg := mustRegistry(t, Deps{
		Kernels: rig.ops("", false),
		Sink: SinkFunc(func(id, status string, data json.RawMessage) {
			calls <- sinkCall{id: id, status: status, data: data}
		}),
	})
	status, res := reg.Execute(context.Background(), panelclient.Command{
		ID: "i1", Type: panelclient.CmdKernelInstall, Args: json.RawMessage(`{"name":"gost"}`),
	})
	if status != panelclient.ResultAccepted {
		t.Fatalf("kernel_install first answer = (%q, %s), want accepted", status, res)
	}
	select {
	case c := <-calls:
		if c.id != "i1" || c.status != panelclient.ResultDone {
			t.Fatalf("kernel_install final = %+v, want done", c)
		}
		var out installedResult
		if err := json.Unmarshal(c.data, &out); err != nil {
			t.Fatalf("install result %s: %v", c.data, err)
		}
		if out.Name != "gost" || out.Version != "2.0.0" || out.Path == "" {
			t.Errorf("install result = %+v, want gost@2.0.0 with a path", out)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("kernel_install never finished")
	}
	if e, ok := rig.entry("2.0.0"); !ok || !e.Current {
		t.Errorf("2.0.0 entry = %+v (present=%v), want current", e, ok)
	}
}

// TestKernelRemoveRefusesTheVersionInUseAndRemovesPrevious covers the removal
// contract against the real installer: the current version is refused with a
// recognisable code, the previous version is removed and its pointer cleared.
func TestKernelRemoveRefusesTheVersionInUseAndRemovesPrevious(t *testing.T) {
	rig := newKernelRig(t)
	rig.addVersion("1.0.0")
	rig.addVersion("2.0.0")
	rig.ensure("1.0.0")
	rig.ensure("2.0.0")
	reg := mustRegistry(t, Deps{Kernels: rig.ops("", false)})
	ctx := context.Background()

	status, res := reg.Execute(ctx, panelclient.Command{
		ID: "r1", Type: panelclient.CmdKernelRemove, Args: json.RawMessage(`{"name":"gost","version":"2.0.0"}`),
	})
	if status != panelclient.ResultFailed {
		t.Fatalf("removing the current version = (%q, %s), want failed", status, res)
	}
	if f := decodeFailure(t, res); f.Code != "in_use" {
		t.Errorf("failure = %+v, want code in_use", f)
	}
	if _, ok := rig.entry("2.0.0"); !ok {
		t.Error("the refused version was deleted anyway")
	}

	status, res = reg.Execute(ctx, panelclient.Command{
		ID: "r2", Type: panelclient.CmdKernelRemove, Args: json.RawMessage(`{"name":"gost","version":"1.0.0"}`),
	})
	if status != panelclient.ResultDone {
		t.Fatalf("removing the previous version = (%q, %s), want done", status, res)
	}
	var out panelclient.KernelRemoveResult
	if err := json.Unmarshal(res, &out); err != nil {
		t.Fatalf("remove result %s: %v", res, err)
	}
	if out.FreedBytes <= 0 {
		t.Errorf("freed_bytes = %d, want > 0", out.FreedBytes)
	}
	if _, ok := rig.entry("1.0.0"); ok {
		t.Error("the previous version is still installed")
	}
	if e, ok := rig.entry("2.0.0"); !ok || e.Previous {
		t.Errorf("2.0.0 = %+v (present=%v), want the previous pointer cleared", e, ok)
	}
}

// TestKernelRemoveRefusesAVersionThatIsStillRunning covers the process check:
// a rollback moves the pointer without restarting anything, so the version a
// live process executes must be refused even when it is no longer current.
func TestKernelRemoveRefusesAVersionThatIsStillRunning(t *testing.T) {
	rig := newKernelRig(t)
	rig.addVersion("1.0.0")
	rig.addVersion("2.0.0")
	rig.ensure("1.0.0")
	rig.ensure("2.0.0")
	// 1.0.0 is the previous version, but a process still executes it.
	reg := mustRegistry(t, Deps{Kernels: rig.ops("1.0.0", true)})

	status, res := reg.Execute(context.Background(), panelclient.Command{
		ID: "r3", Type: panelclient.CmdKernelRemove, Args: json.RawMessage(`{"name":"gost","version":"1.0.0"}`),
	})
	if status != panelclient.ResultFailed {
		t.Fatalf("removing a running version = (%q, %s), want failed", status, res)
	}
	if f := decodeFailure(t, res); f.Code != "in_use" {
		t.Errorf("failure = %+v, want code in_use", f)
	}
	if _, ok := rig.entry("1.0.0"); !ok {
		t.Error("the running version was deleted anyway")
	}
}

// TestKernelRollbackSwapsCurrentAndPrevious covers the rollback contract
// against the real installer.
func TestKernelRollbackSwapsCurrentAndPrevious(t *testing.T) {
	rig := newKernelRig(t)
	rig.addVersion("1.0.0")
	rig.addVersion("2.0.0")
	rig.ensure("1.0.0")
	rig.ensure("2.0.0")
	reg := mustRegistry(t, Deps{Kernels: rig.ops("", false)})

	status, res := reg.Execute(context.Background(), panelclient.Command{
		ID: "b1", Type: panelclient.CmdKernelRollback, Args: json.RawMessage(`{"name":"gost"}`),
	})
	if status != panelclient.ResultDone {
		t.Fatalf("kernel_rollback = (%q, %s), want done", status, res)
	}
	var out installedResult
	if err := json.Unmarshal(res, &out); err != nil {
		t.Fatalf("rollback result %s: %v", res, err)
	}
	if out.Version != "1.0.0" {
		t.Errorf("rollback result = %+v, want version 1.0.0", out)
	}
	cur, ok := rig.entry("1.0.0")
	if !ok || !cur.Current || cur.Previous {
		t.Errorf("1.0.0 = %+v (present=%v), want current", cur, ok)
	}
	prev, ok := rig.entry("2.0.0")
	if !ok || !prev.Previous || prev.Current {
		t.Errorf("2.0.0 = %+v (present=%v), want previous", prev, ok)
	}
}

// TestKernelEventsAreEmitted covers ruling 10: a successful install and a
// successful removal each report their event.
func TestKernelEventsAreEmitted(t *testing.T) {
	rig := newKernelRig(t)
	rig.addVersion("1.0.0")
	rig.addVersion("2.0.0")

	var mu sync.Mutex
	var kinds []string
	calls := make(chan sinkCall, 4)
	reg := mustRegistry(t, Deps{
		Kernels: rig.ops("", false),
		Events: EventFunc(func(kind, level, message string) {
			mu.Lock()
			kinds = append(kinds, kind)
			mu.Unlock()
		}),
		Sink: SinkFunc(func(id, status string, data json.RawMessage) {
			calls <- sinkCall{id: id, status: status, data: data}
		}),
	})
	ctx := context.Background()
	for i, version := range []string{"1.0.0", "2.0.0"} {
		status, res := reg.Execute(ctx, panelclient.Command{
			ID: "e" + version, Type: panelclient.CmdKernelInstall,
			Args: json.RawMessage(`{"name":"gost","version":"` + version + `"}`),
		})
		if status != panelclient.ResultAccepted {
			t.Fatalf("install %s = (%q, %s), want accepted", version, status, res)
		}
		select {
		case c := <-calls:
			if c.status != panelclient.ResultDone {
				t.Fatalf("install %s (call %d) = %+v, want done", version, i, c)
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("install %s never finished", version)
		}
	}
	status, res := reg.Execute(ctx, panelclient.Command{
		ID: "e-rm", Type: panelclient.CmdKernelRemove, Args: json.RawMessage(`{"name":"gost","version":"1.0.0"}`),
	})
	if status != panelclient.ResultDone {
		t.Fatalf("remove = (%q, %s), want done", status, res)
	}

	mu.Lock()
	got := strings.Join(kinds, ",")
	mu.Unlock()
	want := "kernel.installed,kernel.installed,kernel.removed"
	if got != want {
		t.Errorf("events = %q, want %q", got, want)
	}
}

// TestKernelListFromARealInstaller covers kernel_list with a loaded manifest:
// the catalog lists the available versions and the installed entry is current.
func TestKernelListFromARealInstaller(t *testing.T) {
	rig := newKernelRig(t)
	rig.addVersion("1.0.0")
	rig.addVersion("2.0.0")
	rig.ensure("2.0.0")
	reg := mustRegistry(t, Deps{Kernels: rig.ops("", false)})

	status, res := reg.Execute(context.Background(), panelclient.Command{ID: "l1", Type: panelclient.CmdKernelList})
	if status != panelclient.ResultDone {
		t.Fatalf("kernel_list = (%q, %s), want done", status, res)
	}
	var out panelclient.KernelListResult
	if err := json.Unmarshal(res, &out); err != nil {
		t.Fatalf("kernel_list result %s: %v", res, err)
	}
	if len(out.Kernels) != 1 || out.Kernels[0].Version != "2.0.0" || !out.Kernels[0].Current || !out.Kernels[0].InUse {
		t.Fatalf("kernels = %+v, want the installed 2.0.0 current and in use", out.Kernels)
	}
	if len(out.Catalog) != 1 || out.Catalog[0].Name != "gost" || len(out.Catalog[0].Versions) != 2 {
		t.Fatalf("catalog = %+v, want gost with two versions", out.Catalog)
	}
	if out.Kernels[0].SizeBytes <= 0 || out.Kernels[0].InstalledAt == 0 {
		t.Errorf("kernel entry = %+v, want a declared size and an install time", out.Kernels[0])
	}
}
