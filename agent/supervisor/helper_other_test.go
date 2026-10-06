//go:build !unix

package supervisor

// helperUnix has no extra modes on platforms without POSIX signals.
func helperUnix() {}
