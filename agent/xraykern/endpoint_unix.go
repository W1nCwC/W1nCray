//go:build !windows

package xraykern

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/W1nCwC/W1nCray/agent/xrayapi"
)

// statusEndpoint builds the HTTP client and base URL of the kernel's local
// endpoint (the caller appends the route path). On Unix-like systems it is the
// Unix socket in the runtime directory (/run/W1nCray/xray.sock, mode 0600, so
// only the agent — running as the same user — can read it). A socket left by a
// kernel up to v0.6.0 next to config.yml is still accepted, so an in-place
// upgrade keeps reporting status until the running kernel is restarted.
func statusEndpoint(configPath string) (*http.Client, string, error) {
	dir := filepath.Dir(configPath)
	candidates := []string{xrayapi.SocketPath(dir), xrayapi.LegacySocketPath(dir)}
	sock := ""
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			sock = c
			break
		}
	}
	if sock == "" {
		return nil, "", fmt.Errorf("Xray 内核状态接口不可用（%s 不存在）", candidates[0])
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}
	return &http.Client{Transport: tr}, "http://unix", nil
}
