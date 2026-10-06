//go:build !(linux || darwin || freebsd || openbsd || netbsd)

package cmd

// setUmask is a no-op where umask(2) is unavailable (development builds).
func setUmask(int) int { return 0 }
