//go:build windows

package xraynode

import (
	"fmt"
	"net"
	"os"

	"github.com/W1nCwC/W1nCray/agent/xrayapi"
)

// listenStatus creates a loopback TCP listener and writes its address to
// <configDir>/xray.addr: Windows has no Unix sockets the standard library can
// serve.
func listenStatus(configDir string) (net.Listener, string, string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", "", fmt.Errorf("status listener: %w", err)
	}
	addr := ln.Addr().String()
	path := xrayapi.AddrPath(configDir)
	if err := os.WriteFile(path, []byte(addr+"\n"), 0o600); err != nil {
		ln.Close()
		return nil, "", "", fmt.Errorf("status address file %s: %w", path, err)
	}
	return ln, addr, path, nil
}

// cleanupStatus removes the address file.
func cleanupStatus(path string) {
	if path != "" {
		_ = os.Remove(path)
	}
}
