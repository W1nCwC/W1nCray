//go:build windows

package xrayapi

import "path/filepath"

// SocketPath has no meaning on Windows: the kernel serves its status endpoint
// on a loopback TCP port and publishes the port in the address file. It is
// defined so the code both programs share compiles on every platform.
func SocketPath(configDir string) string {
	return filepath.Join(configDir, StatusAddrName)
}

// AddrPath is the file holding the kernel's loopback address.
func AddrPath(configDir string) string {
	return filepath.Join(configDir, StatusAddrName)
}
