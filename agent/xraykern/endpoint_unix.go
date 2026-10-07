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

// statusEndpoint builds the HTTP client and URL of the kernel's status
// endpoint. On Unix-like systems it is the Unix socket next to config.yml
// (mode 0600, so only the agent, running as the same user, can read it).
func statusEndpoint(configPath string) (*http.Client, string, error) {
	sock := filepath.Join(filepath.Dir(configPath), xrayapi.StatusSocketName)
	if _, err := os.Stat(sock); err != nil {
		return nil, "", fmt.Errorf("Xray 内核状态接口不可用（%s 不存在）", sock)
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}
	return &http.Client{Transport: tr}, "http://unix" + xrayapi.StatusPath, nil
}
