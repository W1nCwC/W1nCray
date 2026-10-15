package install

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/W1nCwC/W1nCray/kernel"
)

// TestRemoveCurrentSingleVersion covers the case that used to be impossible:
// the only installed version of a kernel is always the current one, and it can
// be removed once the caller established that nothing runs it. The version
// directory and the current pointer both go.
func TestRemoveCurrentSingleVersion(t *testing.T) {
	f := newFixture(t)
	fs := newFileServer(t)
	v := publish(t, f, fs, kern{Name: "gost", Version: "3.3.0"})
	in := f.installer(t.TempDir())
	if err := in.LoadManifest(f.sign(v)); err != nil {
		t.Fatal(err)
	}
	mustEnsure(t, in, "gost", "3.3.0")
	if cur := currentOf(t, in, "gost"); cur != "3.3.0" {
		t.Fatalf("current = %q, want 3.3.0", cur)
	}

	if err := in.RemoveCurrent("gost", "3.3.0"); err != nil {
		t.Fatalf("RemoveCurrent: %v", err)
	}
	if _, err := os.Stat(in.verDir("gost", "3.3.0")); !os.IsNotExist(err) {
		t.Errorf("the version directory survived: %v", err)
	}
	if cur := currentOf(t, in, "gost"); cur != "" {
		t.Errorf("current = %q, want the pointer gone", cur)
	}
	if prev, err := readPointer(in.prevPath("gost")); err == nil && prev != "" {
		t.Errorf("previous = %q, want the pointer gone", prev)
	}
	if _, err := os.Stat(in.nameDir("gost")); !os.IsNotExist(err) {
		t.Errorf("the empty kernel directory survived: %v", err)
	}
	if l, _ := in.List(); len(l) != 0 {
		t.Errorf("List = %+v, want nothing installed", l)
	}
	// Remove still refuses a current version, so the two paths stay distinct.
	if _, err := in.Ensure(context.Background(), pin("gost", "3.3.0")); err != nil {
		t.Fatalf("Ensure after the removal: %v", err)
	}
	if err := in.Remove("gost", "3.3.0"); !errors.Is(err, kernel.ErrInUse) {
		t.Errorf("Remove of the current version = %v, want ErrInUse (Remove must stay conservative)", err)
	}
	if err := in.RemoveCurrent("gost", "3.3.0"); err != nil {
		t.Errorf("RemoveCurrent again: %v", err)
	}
}

// TestRemoveCurrentPromotesPrevious covers the two-version machine: removing
// the current version hands the current pointer to the previous one and clears
// the previous pointer, because no other candidate is left.
func TestRemoveCurrentPromotesPrevious(t *testing.T) {
	f := newFixture(t)
	fs := newFileServer(t)
	v1 := publish(t, f, fs, kern{Name: "gost", Version: "3.2.0"})
	v2 := publish(t, f, fs, kern{Name: "gost", Version: "3.3.0"})
	in := f.installer(t.TempDir())
	if err := in.LoadManifest(f.sign(v1, v2)); err != nil {
		t.Fatal(err)
	}
	mustEnsure(t, in, "gost", "3.2.0")
	mustEnsure(t, in, "gost", "3.3.0")

	if err := in.RemoveCurrent("gost", "3.3.0"); err != nil {
		t.Fatalf("RemoveCurrent: %v", err)
	}
	if _, err := os.Stat(in.verDir("gost", "3.3.0")); !os.IsNotExist(err) {
		t.Errorf("the removed version survived: %v", err)
	}
	if cur := currentOf(t, in, "gost"); cur != "3.2.0" {
		t.Errorf("current = %q, want the previous version promoted to 3.2.0", cur)
	}
	if prev, err := readPointer(in.prevPath("gost")); err == nil && prev != "" {
		t.Errorf("previous = %q, want the pointer cleared", prev)
	}
	e, ok := entryOf(t, in, "3.2.0")
	if !ok || !e.Current || e.Previous {
		t.Errorf("3.2.0 = %+v (present=%v), want current and not previous", e, ok)
	}
	if _, ok := entryOf(t, in, "3.3.0"); ok {
		t.Error("3.3.0 is still listed")
	}
	// The promoted version is the one a driver now resolves through Current.
	got, err := in.Current("gost")
	if err != nil || got.Version != "3.2.0" {
		t.Errorf("Current = %+v, %v; want 3.2.0", got, err)
	}
}

// TestRemoveCurrentAfterRollback covers a current version that is not the
// newest one (a rollback leaves exactly that shape): the version it rolled
// away from is previous, and removing the current one promotes it.
func TestRemoveCurrentAfterRollback(t *testing.T) {
	f := newFixture(t)
	fs := newFileServer(t)
	v1 := publish(t, f, fs, kern{Name: "gost", Version: "3.2.0"})
	v2 := publish(t, f, fs, kern{Name: "gost", Version: "3.3.0"})
	in := f.installer(t.TempDir())
	if err := in.LoadManifest(f.sign(v1, v2)); err != nil {
		t.Fatal(err)
	}
	mustEnsure(t, in, "gost", "3.2.0")
	mustEnsure(t, in, "gost", "3.3.0")
	if _, err := in.Rollback("gost"); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if cur := currentOf(t, in, "gost"); cur != "3.2.0" {
		t.Fatalf("current after rollback = %q, want 3.2.0", cur)
	}

	if err := in.RemoveCurrent("gost", "3.2.0"); err != nil {
		t.Fatalf("RemoveCurrent: %v", err)
	}
	if cur := currentOf(t, in, "gost"); cur != "3.3.0" {
		t.Errorf("current = %q, want the rolled-away 3.3.0 promoted", cur)
	}
	if e, ok := entryOf(t, in, "3.3.0"); !ok || !e.Current || e.Previous {
		t.Errorf("3.3.0 = %+v (present=%v), want current", e, ok)
	}
}

// TestRemoveCurrentNonCurrentKeepsRemoveSemantics covers the compatibility
// rule: a version that is not current is removed exactly like Remove does,
// including clearing the previous pointer when it names that version.
func TestRemoveCurrentNonCurrentKeepsRemoveSemantics(t *testing.T) {
	f := newFixture(t)
	fs := newFileServer(t)
	v1 := publish(t, f, fs, kern{Name: "gost", Version: "3.2.0"})
	v2 := publish(t, f, fs, kern{Name: "gost", Version: "3.3.0"})
	in := f.installer(t.TempDir())
	if err := in.LoadManifest(f.sign(v1, v2)); err != nil {
		t.Fatal(err)
	}
	mustEnsure(t, in, "gost", "3.2.0")
	mustEnsure(t, in, "gost", "3.3.0")

	// 3.2.0 is the previous version: removing it clears the pointer and
	// leaves the current version alone.
	if err := in.RemoveCurrent("gost", "3.2.0"); err != nil {
		t.Fatalf("RemoveCurrent(previous): %v", err)
	}
	if _, err := os.Stat(in.verDir("gost", "3.2.0")); !os.IsNotExist(err) {
		t.Errorf("the previous version survived: %v", err)
	}
	if prev, err := readPointer(in.prevPath("gost")); err == nil && prev != "" {
		t.Errorf("previous = %q, want the pointer cleared", prev)
	}
	if cur := currentOf(t, in, "gost"); cur != "3.3.0" {
		t.Errorf("current = %q, want 3.3.0 untouched", cur)
	}
	// An unknown version is still ErrNotInstalled, like Remove.
	if err := in.RemoveCurrent("gost", "9.9.9"); !errors.Is(err, kernel.ErrNotInstalled) {
		t.Errorf("RemoveCurrent(unknown) = %v, want ErrNotInstalled", err)
	}
	// A malformed name is still refused.
	if err := in.RemoveCurrent("../x", "1.0.0"); err == nil {
		t.Error("a path-like name must be refused")
	}
	// The "v" prefix the panel sends is normalised, like everywhere else.
	if err := in.RemoveCurrent("gost", "v3.3.0"); err != nil {
		t.Errorf("RemoveCurrent(v-prefixed): %v", err)
	}
	if l, _ := in.List(); len(l) != 0 {
		t.Errorf("List = %+v, want nothing installed", l)
	}
}

// TestRemoveCurrentLastVersionForgetsFailureRecords covers the cleanup the
// empty-version Remove already did: when the last version goes, the kernel
// directory and the persisted failure records go with it.
func TestRemoveCurrentLastVersionForgetsFailureRecords(t *testing.T) {
	f := newFixture(t)
	fs := newFileServer(t)
	v := publish(t, f, fs, kern{Name: "gost", Version: "3.3.0"})
	dir := t.TempDir()
	in := f.installer(dir)
	if err := in.LoadManifest(f.sign(v)); err != nil {
		t.Fatal(err)
	}
	mustEnsure(t, in, "gost", "3.3.0")
	in.recordFailure("gost", "3.3.0", errors.New("boom"))
	if in.st.Bad[badKey("gost", "3.3.0")] == nil {
		t.Fatal("the failure record was not recorded")
	}

	if err := in.RemoveCurrent("gost", "3.3.0"); err != nil {
		t.Fatalf("RemoveCurrent: %v", err)
	}
	// A fresh installer over the same directory proves what was persisted.
	in2, err := New(Config{
		Dir: dir, Keys: f.keys, Platform: &f.plat, AllowHTTP: true, Check: fakeCheck,
		FreeSpace: func(string) (uint64, bool) { return f.space, true },
		Now:       f.clk.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if in2.st.Bad[badKey("gost", "3.3.0")] != nil {
		t.Errorf("the failure record survived the removal of the last version: %+v", in2.st.Bad)
	}
}

// TestRemoveCurrentNeedsNoManifest covers the offline requirement: removal is
// a local operation and must not read the manifest.
func TestRemoveCurrentNeedsNoManifest(t *testing.T) {
	f := newFixture(t)
	fs := newFileServer(t)
	v := publish(t, f, fs, kern{Name: "gost", Version: "3.3.0"})
	dir := t.TempDir()
	in := f.installer(dir)
	if err := in.LoadManifest(f.sign(v)); err != nil {
		t.Fatal(err)
	}
	mustEnsure(t, in, "gost", "3.3.0")

	// A second installer over the same directory, with no LoadManifest call:
	// the stored manifest may even be unreadable for it and removal still works.
	off, err := New(Config{
		Dir: dir, Platform: &f.plat, Check: fakeCheck,
		FreeSpace: func(string) (uint64, bool) { return f.space, true },
		Now:       f.clk.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := off.RemoveCurrent("gost", "3.3.0"); err != nil {
		t.Fatalf("RemoveCurrent without a manifest: %v", err)
	}
	if _, err := os.Stat(off.verDir("gost", "3.3.0")); !os.IsNotExist(err) {
		t.Errorf("the version survived: %v", err)
	}
}

// entryOf finds one installed version in List.
func entryOf(t *testing.T, in *Installer, version string) (Entry, bool) {
	t.Helper()
	l, err := in.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, e := range l {
		if e.Version == version {
			return e, true
		}
	}
	return Entry{}, false
}
