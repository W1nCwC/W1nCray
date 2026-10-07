//go:build windows

package xraynode

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// listenStatus creates a loopback TCP listener and writes its address to
// <configDir>/xray.addr: Windows has no Unix sockets the standard library can
// serve.
func listenStatus(configDir string) (net.Listener, string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", fmt.Errorf("status listener: %w", err)
	}
	addr := ln.Addr().String()
	path := filepath.Join(configDir, StatusAddrName)
	if err := os.WriteFile(path, []byte(addr+"\n"), 0o600); err != nil {
		ln.Close()
		return nil, "", fmt.Errorf("status address file %s: %w", path, err)
	}
	return ln, addr, nil
}

// cleanupStatus removes the address file.
func cleanupStatus(configDir string) {
	_ = os.Remove(filepath.Join(configDir, StatusAddrName))
}
