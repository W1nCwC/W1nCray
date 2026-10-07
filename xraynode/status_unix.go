//go:build !windows

package xraynode

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// listenStatus creates the Unix socket of the status endpoint next to
// config.yml. The socket is 0600: only the agent (running as the same user)
// may read the status document.
func listenStatus(configDir string) (net.Listener, string, error) {
	path := filepath.Join(configDir, StatusSocketName)
	// A socket left behind by a crashed process would make Listen fail.
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, "", fmt.Errorf("status socket %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		_ = os.Remove(path)
		return nil, "", fmt.Errorf("status socket %s: %w", path, err)
	}
	return ln, path, nil
}

// cleanupStatus removes the socket file.
func cleanupStatus(configDir string) {
	_ = os.Remove(filepath.Join(configDir, StatusSocketName))
}
