//go:build linux

package install

import (
	"os"
	"path/filepath"
	"testing"
)

// Linux-only behaviour that cannot be exercised on the Windows development
// machine: real statfs and symlink pointers.

func TestStatfsFree(t *testing.T) {
	free, ok := statfsFree(t.TempDir())
	if !ok || free == 0 {
		t.Fatalf("statfs: %d %v", free, ok)
	}
	if _, ok := statfsFree(filepath.Join(t.TempDir(), "does-not-exist")); ok {
		t.Fatal("statfs of a missing dir must report unknown")
	}
}

func TestPointerIsSymlinkOnLinux(t *testing.T) {
	p := filepath.Join(t.TempDir(), "current")
	if err := writePointer(p, "1.2.3"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("pointer is %v, want a symlink", fi.Mode())
	}
	if tgt, _ := os.Readlink(p); tgt != "1.2.3" {
		t.Fatalf("link target %q (must be relative)", tgt)
	}
}
