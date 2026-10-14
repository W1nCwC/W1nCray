//go:build !unix

package terminal

// processAlive cannot be answered without a Unix process table, and no test
// that needs it runs here (the real-PTY tests skip when Supported() is false).
func processAlive(pid int) bool { return false }
