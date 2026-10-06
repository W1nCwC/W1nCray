//go:build unix

package fileops

import (
	"os"
	"syscall"
	"testing"
)

// makeSpecial creates a FIFO and, when the platform allows it without extra
// privileges, a device node. A device node normally needs root; the FIFO is
// the case that matters (a read of it would block forever without the
// O_NONBLOCK plus stat guard).
func makeSpecial(t *testing.T, fifo, dev string) {
	t.Helper()
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	// A device node needs CAP_MKNOD; when it is not available the FIFO still
	// covers the "not a regular file" rule. /dev/null is the fallback probe.
	if err := syscall.Mknod(dev, syscall.S_IFCHR|0o600, int(mkdev(1, 3))); err != nil {
		_ = os.Remove(dev)
	}
}

// mkdev renders a Linux device number (major, minor). It is the classic
// (major<<8)|minor for the small numbers used here.
func mkdev(major, minor uint32) uint64 {
	return uint64(major)<<8 | uint64(minor)
}
