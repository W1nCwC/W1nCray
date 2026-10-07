//go:build !windows

package xrayapi

import (
	"os"
	"path/filepath"
)

const (
	// runtimeDirDefault is the runtime directory of a normal install.
	runtimeDirDefault = "/run/" + RuntimeDirName
)

// RuntimeDir returns the directory the kernel's status socket lives in.
func RuntimeDir() string {
	if d := os.Getenv(RuntimeDirEnv); d != "" {
		return d
	}
	return runtimeDirDefault
}

// SocketPath is where the kernel's status socket lives: the runtime directory,
// never the configuration directory.
//
// The socket used to sit next to config.yml, which put it under /etc/W1nCray
// (type etc_t). A service whose binary is labelled etc_t runs in init_t, and
// init_t may not create a sock_file there (see agent/selinux for the AVC), so
// the kernel died at start-up. /run/W1nCray is created by the service manager
// or by the kernel itself and is not part of the configuration tree.
func SocketPath(configDir string) string {
	return filepath.Join(RuntimeDir(), StatusSocketName)
}

// LegacySocketPath is where kernels up to v0.6.0 published the socket: next to
// config.yml. The agent still reads it, so an upgrade in place keeps working
// until the running kernel is restarted.
func LegacySocketPath(configDir string) string {
	return filepath.Join(configDir, StatusSocketName)
}

// AddrPath is the file holding the kernel's loopback address (Windows).
func AddrPath(configDir string) string {
	return filepath.Join(configDir, StatusAddrName)
}
