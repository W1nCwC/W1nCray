//go:build !linux

package selfupdate

// processExecutable cannot be answered on this platform: there is no portable
// process table to read. The caller treats "unknown" as "not the agent", so a
// pid taken from a stale lock or ready marker is never signalled here.
func processExecutable(int) (string, bool) { return "", false }
