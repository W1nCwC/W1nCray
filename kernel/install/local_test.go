package install

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/W1nCwC/W1nCray/kernel"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
)

// localRun is the version self-check of a fake xray kernel: the fixture Check
// reads "FAKEKERNEL version=<v>" out of the installed file.
func localRun() manifest.Run {
	return manifest.Run{Binary: "W1nCray-xray", VersionCmd: []string{"version"}, VersionRegex: `version=([0-9][0-9.]*)`}
}

// writeLocal writes data to a temp file and returns its path.
func writeLocal(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestInstallLocalGzMatchesAManifestInstall is the core acceptance check: a raw
// gz release asset plus its sha256 lands in <kernels>/xray/<version>/ with the
// same marker a manifest install writes, so Current/List/Rollback/Remove all
// see it.
func TestInstallLocalGzMatchesAManifestInstall(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	in := f.installer(dir)

	bin := fakeBin("0.6.0", 2048)
	raw := mkGz(t, bin)
	path := writeLocal(t, "W1nCray-xray-linux-amd64.gz", raw)

	inst, err := in.InstallLocal(context.Background(), LocalInstall{
		Name: "xray", Archive: path, ArchiveSHA256: sum(raw), To: "W1nCray-xray", Run: localRun(),
	})
	if err != nil {
		t.Fatalf("InstallLocal: %v", err)
	}
	wantPath := filepath.Join(dir, "kernels", "xray", "0.6.0", "W1nCray-xray")
	if inst.Version != "0.6.0" || inst.Path != wantPath {
		t.Fatalf("installed = %+v, want 0.6.0 at %s", inst, wantPath)
	}
	got, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bin) {
		t.Errorf("installed file differs from the decompressed asset (%d vs %d bytes)", len(got), len(bin))
	}
	fi, err := os.Stat(wantPath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o111 == 0 {
		t.Errorf("installed file is not executable: %v", fi.Mode())
	}

	mk := in.readMarker("xray", "0.6.0")
	if mk == nil {
		t.Fatal("no .installed.json marker written")
	}
	if mk.Binary != "W1nCray-xray" || mk.ArchiveSHA256 != sum(raw) {
		t.Errorf("marker = %+v", mk)
	}
	if mk.Target != "linux/amd64" {
		t.Errorf("marker target = %q, want the platform key", mk.Target)
	}
	if len(mk.Files) != 1 || mk.Files[0].To != "W1nCray-xray" || mk.Files[0].Size != int64(len(bin)) {
		t.Errorf("marker files = %+v", mk.Files)
	}

	cur, err := in.Current("xray")
	if err != nil || cur.Version != "0.6.0" {
		t.Fatalf("Current = %+v, %v", cur, err)
	}
	entries, err := in.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !entries[0].Current || entries[0].Version != "0.6.0" {
		t.Fatalf("List = %+v", entries)
	}
}

// TestInstallLocalUpgradeAndRollback proves a local install is a first-class
// version: installing a second one moves the pointer and Rollback returns to
// the first.
func TestInstallLocalUpgradeAndRollback(t *testing.T) {
	f := newFixture(t)
	in := f.installer(t.TempDir())
	ctx := context.Background()

	installLocal := func(version string) {
		t.Helper()
		raw := mkGz(t, fakeBin(version, 1024))
		p := writeLocal(t, "W1nCray-xray.gz", raw)
		if _, err := in.InstallLocal(ctx, LocalInstall{
			Name: "xray", Archive: p, ArchiveSHA256: sum(raw), To: "W1nCray-xray", Run: localRun(),
		}); err != nil {
			t.Fatalf("InstallLocal %s: %v", version, err)
		}
	}
	installLocal("0.6.0")
	installLocal("0.6.1")

	cur, err := in.Current("xray")
	if err != nil || cur.Version != "0.6.1" {
		t.Fatalf("Current = %+v, %v", cur, err)
	}
	rb, err := in.Rollback("xray")
	if err != nil || rb.Version != "0.6.0" {
		t.Fatalf("Rollback = %+v, %v", rb, err)
	}
	// The whole kernel (including the current version) can be removed, which is
	// what xraysvc.Remove does.
	if err := in.Remove("xray", ""); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := in.Current("xray"); !errors.Is(err, kernel.ErrNotInstalled) {
		t.Fatalf("Current after Remove = %v, want ErrNotInstalled", err)
	}
}

// TestInstallLocalBareBinary accepts a file that is already the binary, not a
// gz stream, so an operator can point --file at either form.
func TestInstallLocalBareBinary(t *testing.T) {
	f := newFixture(t)
	in := f.installer(t.TempDir())
	bin := fakeBin("0.6.2", 64)
	p := writeLocal(t, "W1nCray-xray", bin)
	inst, err := in.InstallLocal(context.Background(), LocalInstall{
		Name: "xray", Archive: p, ArchiveSHA256: sum(bin), To: "W1nCray-xray", Run: localRun(),
	})
	if err != nil {
		t.Fatalf("InstallLocal: %v", err)
	}
	if inst.Version != "0.6.2" {
		t.Fatalf("version = %q", inst.Version)
	}
	got, err := os.ReadFile(inst.Path)
	if err != nil || !bytes.Equal(got, bin) {
		t.Fatalf("installed bytes differ: %v", err)
	}
}

// TestInstallLocalRefusesBadInput keeps the fail-closed rules: a wrong or
// missing sha256, an unexpected version and an unsafe installed name are all
// refused, and a refusal leaves nothing installed.
func TestInstallLocalRefusesBadInput(t *testing.T) {
	f := newFixture(t)
	in := f.installer(t.TempDir())
	raw := mkGz(t, fakeBin("0.6.0", 512))
	p := writeLocal(t, "W1nCray-xray.gz", raw)
	base := LocalInstall{Name: "xray", Archive: p, ArchiveSHA256: sum(raw), To: "W1nCray-xray", Run: localRun()}

	t.Run("missing sha256", func(t *testing.T) {
		li := base
		li.ArchiveSHA256 = ""
		if _, err := in.InstallLocal(context.Background(), li); !errors.Is(err, kernel.ErrVerify) {
			t.Fatalf("err = %v, want ErrVerify", err)
		}
	})
	t.Run("wrong sha256", func(t *testing.T) {
		li := base
		li.ArchiveSHA256 = sum([]byte("something else"))
		if _, err := in.InstallLocal(context.Background(), li); !errors.Is(err, kernel.ErrVerify) {
			t.Fatalf("err = %v, want ErrVerify", err)
		}
	})
	t.Run("version mismatch", func(t *testing.T) {
		li := base
		li.Version = "9.9.9"
		if _, err := in.InstallLocal(context.Background(), li); !errors.Is(err, kernel.ErrCheck) {
			t.Fatalf("err = %v, want ErrCheck", err)
		}
	})
	t.Run("unsafe installed name", func(t *testing.T) {
		li := base
		li.To = "../W1nCray-xray"
		if _, err := in.InstallLocal(context.Background(), li); !errors.Is(err, kernel.ErrVerify) {
			t.Fatalf("err = %v, want ErrVerify", err)
		}
	})
	if _, err := in.Current("xray"); !errors.Is(err, kernel.ErrNotInstalled) {
		t.Fatalf("something was installed by a refused call: %v", err)
	}
}

// TestInstallLocalKeepsTheRequestedTargetAndVariant: an explicit Target and
// Variant are written to the marker verbatim instead of being replaced by the
// detected platform key. The legacy "+openwrt" spelling is used here as the
// value to preserve; the current OpenWrt lite build is selected from the
// manifest's openwrt_targets field under a plain os/arch key (F10).
func TestInstallLocalKeepsTheRequestedTargetAndVariant(t *testing.T) {
	f := newFixture(t)
	in := f.installer(t.TempDir())
	raw := mkGz(t, fakeBin("0.6.0", 128))
	p := writeLocal(t, "W1nCray-xray-linux-amd64-lite.gz", raw)
	if _, err := in.InstallLocal(context.Background(), LocalInstall{
		Name: "xray", Archive: p, ArchiveSHA256: sum(raw), To: "W1nCray-xray", Run: localRun(),
		Target: "linux/amd64+openwrt", Variant: "fallbackroots",
	}); err != nil {
		t.Fatalf("InstallLocal: %v", err)
	}
	mk := in.readMarker("xray", "0.6.0")
	if mk == nil || mk.Target != "linux/amd64+openwrt" || mk.Variant != "fallbackroots" {
		t.Fatalf("marker = %+v", mk)
	}
}
