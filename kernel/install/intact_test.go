package install

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/W1nCwC/W1nCray/kernel"
)

// The sysupgrade-backup-overflow defect (handoff 89): a backup/restore that
// runs out of room leaves the current binary as a byte-prefix of itself while
// its marker still records the full size. The registry must answer "not
// installed" for such a version in Current/Files/List alike, say so in the
// log, and let a later Ensure reinstall it.

// installXray installs a fake xray kernel of the given version through the
// local path, so the tests run without a manifest or a server.
func installXray(t *testing.T, in *Installer, version string) {
	t.Helper()
	raw := mkGz(t, fakeBin(version, 2048))
	p := writeLocal(t, "W1nCray-xray.gz", raw)
	if _, err := in.InstallLocal(context.Background(), LocalInstall{
		Name: "xray", Archive: p, ArchiveSHA256: sum(raw), To: "W1nCray-xray", Run: localRun(),
	}); err != nil {
		t.Fatalf("InstallLocal %s: %v", version, err)
	}
}

// damage truncates the main binary of name@version to its first keep bytes,
// like the OpenWrt sysupgrade restore did.
func damage(t *testing.T, in *Installer, name, version string, keep int64) {
	t.Helper()
	mk := in.readMarker(name, version)
	if mk == nil {
		t.Fatal("no marker")
	}
	p := filepath.Join(in.verDir(name, version), mk.Binary)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(b)) <= keep {
		t.Fatalf("binary is only %d bytes, cannot truncate to %d", len(b), keep)
	}
	if err := os.WriteFile(p, b[:keep], 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestTruncatedCurrentIsNotInstalled(t *testing.T) {
	f := newFixture(t)
	in := f.installer(t.TempDir())
	installXray(t, in, "0.6.0")

	damage(t, in, "xray", "0.6.0", 1024)

	if _, err := in.Current("xray"); !errors.Is(err, kernel.ErrNotInstalled) {
		t.Fatalf("Current after truncation = %v, want ErrNotInstalled", err)
	}
	if _, err := in.Files("xray"); !errors.Is(err, kernel.ErrNotInstalled) {
		t.Fatalf("Files after truncation = %v, want ErrNotInstalled", err)
	}
}

func TestTruncatedVersionIsDroppedFromList(t *testing.T) {
	f := newFixture(t)
	in := f.installer(t.TempDir())
	installXray(t, in, "0.6.0")
	installXray(t, in, "0.6.1") // current
	damage(t, in, "xray", "0.6.1", 1024)

	list, err := in.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Version != "0.6.0" {
		t.Fatalf("List = %+v, want only the intact 0.6.0", list)
	}
	// The pointer still names 0.6.1, but that version is damaged: the list must
	// not advertise a damaged version as current, and Current must agree.
	if list[0].Current {
		t.Error("the surviving version must not be flagged current: Current() says not installed")
	}
	if _, err := in.Current("xray"); !errors.Is(err, kernel.ErrNotInstalled) {
		t.Fatalf("Current = %v, want ErrNotInstalled (pointer names the damaged 0.6.1)", err)
	}
}

func TestListAndCurrentAgreeOnIntactVersions(t *testing.T) {
	f := newFixture(t)
	in := f.installer(t.TempDir())
	installXray(t, in, "0.6.0")
	installXray(t, in, "0.6.1")

	cur, err := in.Current("xray")
	if err != nil || cur.Version != "0.6.1" {
		t.Fatalf("Current = %+v, %v", cur, err)
	}
	list, err := in.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("List = %+v", list)
	}
	for _, e := range list {
		switch e.Version {
		case "0.6.1":
			if !e.Current || e.Previous {
				t.Errorf("0.6.1 flags = current:%v previous:%v", e.Current, e.Previous)
			}
		case "0.6.0":
			if e.Current || !e.Previous {
				t.Errorf("0.6.0 flags = current:%v previous:%v", e.Current, e.Previous)
			}
		}
	}
}

func TestMissingFileIsNotInstalled(t *testing.T) {
	f := newFixture(t)
	in := f.installer(t.TempDir())
	installXray(t, in, "0.6.0")
	mk := in.readMarker("xray", "0.6.0")
	if err := os.Remove(filepath.Join(in.verDir("xray", "0.6.0"), mk.Binary)); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Current("xray"); !errors.Is(err, kernel.ErrNotInstalled) {
		t.Fatalf("Current after delete = %v, want ErrNotInstalled", err)
	}
	if list, _ := in.List(); len(list) != 0 {
		t.Fatalf("List after delete = %+v, want empty", list)
	}
}

func TestEnsureReinstallsTruncatedVersion(t *testing.T) {
	f := newFixture(t)
	fs := newFileServer(t)
	k := publish(t, f, fs, kern{Name: "gost", Version: "3.3.0"})
	in := f.installer(t.TempDir())
	if err := in.LoadManifest(f.sign(k)); err != nil {
		t.Fatal(err)
	}
	mustEnsure(t, in, "gost", "3.3.0")

	damage(t, in, "gost", "3.3.0", 128)
	if _, err := in.Current("gost"); !errors.Is(err, kernel.ErrNotInstalled) {
		t.Fatalf("Current after truncation = %v, want ErrNotInstalled", err)
	}
	// A truncated version must not sit out a retry back-off: Ensure right away
	// reinstalls it and the version is whole and current again.
	inst, err := in.Ensure(context.Background(), pin("gost", "3.3.0"))
	if err != nil {
		t.Fatalf("Ensure after truncation: %v", err)
	}
	if inst.Version != "3.3.0" {
		t.Fatalf("Ensure installed %q", inst.Version)
	}
	cur, err := in.Current("gost")
	if err != nil || cur.Version != "3.3.0" || cur.Path != inst.Path {
		t.Fatalf("Current after reinstall = %+v, %v", cur, err)
	}
}

func TestDamagedVersionClearsItsFailureRecord(t *testing.T) {
	// The damage itself was never an install attempt, so the version must not
	// sit out a back-off recorded for an earlier, unrelated failure: seeing the
	// damage clears the record so the next Ensure reinstalls right away.
	f := newFixture(t)
	fs := newFileServer(t)
	k := publish(t, f, fs, kern{Name: "gost", Version: "3.3.0"})
	in := f.installer(t.TempDir())
	if err := in.LoadManifest(f.sign(k)); err != nil {
		t.Fatal(err)
	}
	mustEnsure(t, in, "gost", "3.3.0")

	in.recordFailure("gost", "3.3.0", errors.New("earlier network failure"))
	damage(t, in, "gost", "3.3.0", 128)

	if _, err := in.Current("gost"); !errors.Is(err, kernel.ErrNotInstalled) {
		t.Fatalf("Current after damage = %v, want ErrNotInstalled", err)
	}
	if _, err := in.Ensure(context.Background(), pin("gost", "3.3.0")); err != nil {
		t.Fatalf("Ensure after damage+failure: %v", err)
	}
}

func TestIntactVersionIsUnaffected(t *testing.T) {
	f := newFixture(t)
	in := f.installer(t.TempDir())
	installXray(t, in, "0.6.0")

	if _, err := in.Current("xray"); err != nil {
		t.Fatalf("Current on an intact install: %v", err)
	}
	list, err := in.List()
	if err != nil || len(list) != 1 || !list[0].Current {
		t.Fatalf("List = %+v, %v", list, err)
	}
}

func TestMarkerWithoutFilesIsNotInstalled(t *testing.T) {
	f := newFixture(t)
	in := f.installer(t.TempDir())
	installXray(t, in, "0.6.0")

	mk := in.readMarker("xray", "0.6.0")
	mk.Files = nil
	b, err := json.Marshal(mk)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in.verDir("xray", "0.6.0"), ".installed.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := in.Current("xray"); !errors.Is(err, kernel.ErrNotInstalled) {
		t.Fatalf("Current with a file-less marker = %v, want ErrNotInstalled", err)
	}
	if list, _ := in.List(); len(list) != 0 {
		t.Fatalf("List with a file-less marker = %+v, want empty", list)
	}
}

func TestRollbackRefusesADamagedPrevious(t *testing.T) {
	f := newFixture(t)
	in := f.installer(t.TempDir())
	installXray(t, in, "0.6.0")
	installXray(t, in, "0.6.1")
	damage(t, in, "xray", "0.6.0", 1024)

	if _, err := in.Rollback("xray"); !errors.Is(err, kernel.ErrNotInstalled) {
		t.Fatalf("Rollback to a damaged previous = %v, want ErrNotInstalled", err)
	}
	// The current version is untouched by the refused rollback.
	if cur, err := in.Current("xray"); err != nil || cur.Version != "0.6.1" {
		t.Fatalf("Current after refused rollback = %+v, %v", cur, err)
	}
}

// Catalog used to answer from the marker alone, so a truncated version stayed
// "installed" there while Current/List already called it missing (handoff 96
// §0). All four now share one rule.
func TestCatalogAgreesWithListOnADamagedVersion(t *testing.T) {
	f := newFixture(t)
	fs := newFileServer(t)
	k := publish(t, f, fs, kern{Name: "gost", Version: "3.3.0"})
	in := f.installer(t.TempDir())
	if err := in.LoadManifest(f.sign(k)); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Ensure(context.Background(), pin("gost", "3.3.0")); err != nil {
		t.Fatal(err)
	}
	before, err := in.Catalog()
	if err != nil || len(before) != 1 || !before[0].Installed {
		t.Fatalf("catalog before damage = %+v err=%v", before, err)
	}

	damage(t, in, "gost", "3.3.0", 128)

	after, err := in.Catalog()
	if err != nil || len(after) != 1 {
		t.Fatalf("catalog after damage = %+v err=%v", after, err)
	}
	if after[0].Installed {
		t.Fatalf("catalog still reports the truncated version as installed: %+v", after[0])
	}
	if list, err := in.List(); err != nil || len(list) != 0 {
		t.Fatalf("List after damage = %+v err=%v, want it to drop the version too", list, err)
	}
}
