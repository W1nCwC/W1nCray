//go:build windows

package xraykern

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/W1nCwC/W1nCray/agent/xrayapi"
)

// statusEndpoint builds the HTTP client and base URL of the kernel's local
// endpoint (the caller appends the route path). Windows has no Unix socket the
// standard library can serve, so the kernel writes its loopback address to
// <configDir>/xray.addr.
func statusEndpoint(configPath string) (*http.Client, string, error) {
	addrPath := xrayapi.AddrPath(filepath.Dir(configPath))
	b, err := os.ReadFile(addrPath)
	if err != nil {
		return nil, "", fmt.Errorf("Xray 内核状态接口不可用（读取 %s: %v）", addrPath, err)
	}
	addr := strings.TrimSpace(string(b))
	if addr == "" {
		return nil, "", fmt.Errorf("Xray 内核状态接口不可用（%s 是空的）", addrPath)
	}
	return &http.Client{}, "http://" + addr, nil
}
