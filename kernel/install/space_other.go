//go:build !linux

package install

// statfsFree is only implemented on Linux (the only OS kernels are installed
// on in production). Elsewhere the free-space check degrades to "unknown"
// and is skipped.
func statfsFree(dir string) (uint64, bool) { return 0, false }
