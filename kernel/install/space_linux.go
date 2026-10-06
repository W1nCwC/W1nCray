//go:build linux

package install

import "syscall"

// statfsFree returns the bytes available to unprivileged users on the
// filesystem holding dir.
func statfsFree(dir string) (uint64, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, false
	}
	return uint64(st.Bavail) * uint64(st.Bsize), true //nolint:unconvert // field types differ per arch
}
