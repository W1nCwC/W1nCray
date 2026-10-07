//go:build !windows

package xraynode

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/W1nCwC/W1nCray/agent/xrayapi"
)

// listenStatus creates the Unix socket of the status endpoint. It prefers the
// runtime directory (/run/W1nCray) and falls back to the configuration
// directory when that directory cannot be created — a development run as an
// unprivileged user, or a machine whose /run is not writable.
//
// A socket under /etc/W1nCray has type etc_t, and a service that runs in init_t
// is not allowed to create it; the runtime directory is what makes the endpoint
// work on an SELinux machine even before the kernel binary carries the bin_t
// label (see agent/selinux).
func listenStatus(configDir string) (net.Listener, string, string, error) {
	primary := xrayapi.SocketPath(configDir)
	if err := os.MkdirAll(filepath.Dir(primary), 0o755); err == nil {
		ln, lerr := listenUnix(primary)
		if lerr == nil {
			return ln, primary, primary, nil
		}
		log.Warnf("status endpoint: %v；改用 %s", lerr, xrayapi.LegacySocketPath(configDir))
	} else {
		log.Warnf("status endpoint: 无法创建运行时目录 %s: %v；改用配置目录", filepath.Dir(primary), err)
	}
	legacy := xrayapi.LegacySocketPath(configDir)
	ln, err := listenUnix(legacy)
	if err != nil {
		return nil, "", "", err
	}
	return ln, legacy, legacy, nil
}

// listenUnix binds a Unix socket at path, replacing a socket left behind by a
// crashed process. The socket is 0600: only the agent (running as the same
// user) may read the status document.
func listenUnix(path string) (net.Listener, error) {
	// A socket left behind by a crashed process would make Listen fail.
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("status socket %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("status socket %s: %w", path, err)
	}
	return ln, nil
}

// cleanupStatus removes the socket file.
func cleanupStatus(path string) {
	if path != "" {
		_ = os.Remove(path)
	}
}
