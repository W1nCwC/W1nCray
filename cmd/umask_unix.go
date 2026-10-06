//go:build linux || darwin || freebsd || openbsd || netbsd

package cmd

import "syscall"

// setUmask sets the process umask and returns the previous one. It keeps the
// token file from ever being group/other readable, even if the explicit chmod
// that follows were to fail.
func setUmask(mask int) int { return syscall.Umask(mask) }
