//go:build !unix

package fileops

import "testing"

// makeSpecial cannot create a FIFO or a device node on this platform. The
// tests that call it skip the entries it would have created, and the Linux
// test machine exercises them (the design's "skip and say why" rule).
func makeSpecial(t *testing.T, fifo, dev string) {
	t.Helper()
	t.Log("no FIFO or device node can be created on this platform; the special-file rows are exercised on Linux")
}
