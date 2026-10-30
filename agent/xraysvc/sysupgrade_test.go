package xraysvc

import (
	"os"
	"path/filepath"
	"testing"
)

// newSysupgradeConf returns a path inside a fresh directory, so writeIfChanged
// has somewhere to create the file.
func newSysupgradeConf(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "etc")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "sysupgrade.conf")
}

func readSysupgradeConf(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func writeSysupgradeConf(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A kernel base that moved (a changed StateDir or KernelsDir) must not stay
// listed: sysupgrade would back up both trees, and the bigger backup is what
// overflowed a small /boot (handoff 89).
func TestEnsureSysupgradeDropsAMovedKernelBase(t *testing.T) {
	conf := newSysupgradeConf(t)
	writeSysupgradeConf(t, conf, "/etc/keep-me\n")

	if err := EnsureSysupgrade(conf, "/etc/init.d/W1nCray-prism", "/old/state/kernels"); err != nil {
		t.Fatal(err)
	}
	// The old tree is gone from disk; only the record still knows about it.
	if err := EnsureSysupgrade(conf, "/etc/init.d/W1nCray-prism", "/new/state/kernels"); err != nil {
		t.Fatal(err)
	}

	got := readSysupgradeConf(t, conf)
	want := "/etc/keep-me\n/etc/init.d/W1nCray-prism\n/new/state/kernels\n"
	if got != want {
		t.Fatalf("sysupgrade.conf = %q, want %q", got, want)
	}
}

// sysupgrade.conf is the user's file: a line this program never wrote must
// survive every rewrite.
func TestEnsureSysupgradeNeverRemovesALineTheUserWrote(t *testing.T) {
	conf := newSysupgradeConf(t)
	writeSysupgradeConf(t, conf, "/user/own/path\n")

	if err := EnsureSysupgrade(conf, "/a"); err != nil {
		t.Fatal(err)
	}
	if err := EnsureSysupgrade(conf, "/b"); err != nil {
		t.Fatal(err)
	}

	got := readSysupgradeConf(t, conf)
	want := "/user/own/path\n/b\n"
	if got != want {
		t.Fatalf("sysupgrade.conf = %q, want %q", got, want)
	}
}

// A missing record (a firmware upgrade cleared it, say) degrades to the old
// add-only behaviour instead of guessing at what to delete.
func TestEnsureSysupgradeWithoutARecordOnlyAdds(t *testing.T) {
	conf := newSysupgradeConf(t)
	writeSysupgradeConf(t, conf, "/old/base\n")

	if err := EnsureSysupgrade(conf, "/new/base"); err != nil {
		t.Fatal(err)
	}

	got := readSysupgradeConf(t, conf)
	want := "/old/base\n/new/base\n"
	if got != want {
		t.Fatalf("sysupgrade.conf = %q, want %q", got, want)
	}
}

// Removing a service must forget its line, or a later Ensure would still count
// it as one of ours.
func TestDropSysupgradeForgetsTheLineInTheRecord(t *testing.T) {
	conf := newSysupgradeConf(t)
	if err := EnsureSysupgrade(conf, "/a", "/b"); err != nil {
		t.Fatal(err)
	}
	if err := DropSysupgrade(conf, "/a"); err != nil {
		t.Fatal(err)
	}
	if err := EnsureSysupgrade(conf, "/b"); err != nil {
		t.Fatal(err)
	}

	got := readSysupgradeConf(t, conf)
	want := "/b\n"
	if got != want {
		t.Fatalf("sysupgrade.conf = %q, want %q", got, want)
	}
}

func TestEnsureSysupgradeIsIdempotent(t *testing.T) {
	conf := newSysupgradeConf(t)
	for i := 0; i < 3; i++ {
		if err := EnsureSysupgrade(conf, "/a", "/b"); err != nil {
			t.Fatal(err)
		}
	}

	got := readSysupgradeConf(t, conf)
	want := "/a\n/b\n"
	if got != want {
		t.Fatalf("sysupgrade.conf = %q, want %q", got, want)
	}
}
