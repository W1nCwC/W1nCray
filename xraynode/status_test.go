package xraynode

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/xrayapi"
)

// getStatus reads GET /status from a running status endpoint. It dials the
// endpoint itself (a Unix socket, or the loopback address file on Windows), so
// the test does not depend on the platform's transport.
func getStatus(t *testing.T, s *StatusServer) xrayapi.Status {
	t.Helper()
	network := "unix"
	if runtime.GOOS == "windows" {
		network = "tcp"
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, s.addr)
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := client.Get("http://xray" + StatusPath)
	if err != nil {
		t.Fatalf("GET %s: %v", StatusPath, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", StatusPath, resp.StatusCode)
	}
	var st xrayapi.Status
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	return st
}

// TestStatusEndpointReportsRunningAndFingerprint is acceptance C: the status
// endpoint answers GET /status with running=true and a non-empty config
// fingerprint, and the fingerprint changes after a configuration change was
// reloaded.
func TestStatusEndpointReportsRunningAndFingerprint(t *testing.T) {
	dir := t.TempDir()
	// The socket lives in the runtime directory; keep the test off the real
	// /run/W1nCray (and off a real kernel's socket).
	t.Setenv(xrayapi.RuntimeDirEnv, t.TempDir())
	configPath := filepath.Join(dir, "config.yml")
	body := "Log: {Level: warning}\nAgent:\n  Enabled: true\n"
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	svc := New(configPath, cfg)
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer svc.Close()
	srv, err := NewStatusServer(svc, dir)
	if err != nil {
		t.Fatalf("NewStatusServer: %v", err)
	}
	defer srv.Close()

	st := getStatus(t, srv)
	if !st.Running {
		t.Errorf("running = false, want true")
	}
	if st.ConfigFingerprint == "" {
		t.Errorf("config_fingerprint is empty")
	}
	if st.Version == "" || st.XrayCore == "" {
		t.Errorf("version=%q xray_core=%q, want both", st.Version, st.XrayCore)
	}
	if st.StartedAt == 0 {
		t.Errorf("started_at is 0")
	}
	if st.Nodes == nil {
		t.Errorf("nodes is null, want an array")
	}
	first := st.ConfigFingerprint

	// Change the configuration and reload; the fingerprint must follow.
	if err := os.WriteFile(configPath, []byte(strings.Replace(body, "warning", "info", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := svc.Reload(context.Background(), "test: status"); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		st = getStatus(t, srv)
		if st.ConfigFingerprint != first {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("config_fingerprint did not change after the reload (still %s)", first)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !st.Running {
		t.Errorf("running = false after the reload")
	}
	if st.LastReloadAt == 0 {
		t.Errorf("last_reload_at is 0 after a successful reload")
	}
}

// TestStatusSocketLivesInTheRuntimeDirectory is the SELinux layout requirement:
// the socket is not created next to config.yml any more, so a service domain
// that may not create files in the etc_t configuration directory can still
// publish its status (agent/selinux has the AVC this avoids).
func TestStatusSocketLivesInTheRuntimeDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows publishes a loopback address file instead of a socket")
	}
	dir := t.TempDir()
	rt := t.TempDir()
	t.Setenv(xrayapi.RuntimeDirEnv, rt)
	configPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(configPath, []byte("Log: {Level: warning}\nAgent:\n  Enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	svc := New(configPath, cfg)
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer svc.Close()
	srv, err := NewStatusServer(svc, dir)
	if err != nil {
		t.Fatalf("NewStatusServer: %v", err)
	}
	defer srv.Close()

	sock := filepath.Join(rt, xrayapi.StatusSocketName)
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("the socket is not in the runtime directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, xrayapi.StatusSocketName)); !os.IsNotExist(err) {
		t.Fatalf("a socket was left next to config.yml: %v", err)
	}
	if srv.addr != sock {
		t.Fatalf("addr = %q, want %q", srv.addr, sock)
	}
}

// TestStatusEndpointRejectsOtherMethods: the endpoint is read-only.
func TestStatusEndpointRejectsOtherMethods(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(xrayapi.RuntimeDirEnv, t.TempDir())
	configPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(configPath, []byte("Log: {Level: warning}\nAgent:\n  Enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	svc := New(configPath, cfg)
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer svc.Close()
	srv, err := NewStatusServer(svc, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	network := "unix"
	if runtime.GOOS == "windows" {
		network = "tcp"
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, srv.addr)
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := client.Post("http://xray"+StatusPath, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("POST %s: %v", StatusPath, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST %s: status %d, want %d", StatusPath, resp.StatusCode, http.StatusMethodNotAllowed)
	}
}
