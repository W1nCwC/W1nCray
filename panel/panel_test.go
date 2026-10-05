package panel

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/infra/conf"

	"github.com/W1nCwC/W1nCray/node"
)

func TestExampleConfigLoads(t *testing.T) {
	cfg, err := LoadConfig(filepath.Join("..", "release", "config", "config.yml.example"))
	if err != nil {
		t.Fatal(err)
	}
	n := cfg.NodesConfig[0]
	if n.ApiConfig.NodeID != 1 || n.ApiConfig.Timeout != 30 {
		t.Fatalf("api config %+v", n.ApiConfig)
	}
	cc := n.ControllerConfig
	if cc.ListenIP != "0.0.0.0" || cc.DNSType != "AsIs" || cc.BlockPrivateIP == nil || !*cc.BlockPrivateIP {
		t.Fatalf("controller config %+v", cc)
	}
	if cc.CertConfig == nil || cc.CertConfig.CertMode != "none" || cc.CertConfig.DNSEnv["cf_dns_api_token"] == "" && cc.CertConfig.DNSEnv["CF_DNS_API_TOKEN"] == "" {
		t.Fatalf("cert config %+v", cc.CertConfig)
	}
	if cfg.ConnectionConfig.ConnIdle != 30 || cfg.ConnectionConfig.BufferSize != 64 {
		t.Fatalf("connection config %+v", cfg.ConnectionConfig)
	}
}

func TestXrayRConfigCompat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	// Excerpt of a typical XrayR NewV2board config.
	os.WriteFile(path, []byte(`
Log:
  Level: warning
Nodes:
  - PanelType: "NewV2board"
    ApiConfig:
      ApiHost: "http://127.0.0.1:667"
      ApiKey: "123"
      NodeID: 41
      NodeType: V2ray
      EnableVless: true
      VlessFlow: "xtls-rprx-vision"
    ControllerConfig:
      UpdatePeriodic: 60
      DisableIVCheck: false
      GlobalDeviceLimitConfig:
        Enable: false
        RedisAddr: 127.0.0.1:6379
      CertConfig:
        CertMode: dns
        CertDomain: "node1.test.com"
        Provider: alidns
        DNSEnv:
          ALICLOUD_ACCESS_KEY: aaa
`), 0o600)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	n := cfg.NodesConfig[0]
	if n.ControllerConfig.ListenIP != "0.0.0.0" || n.ControllerConfig.UpdatePeriodic != 60 || n.ControllerConfig.CertConfig.Provider != "alidns" {
		t.Fatalf("%+v", n.ControllerConfig)
	}
	if !n.ApiConfig.EnableVless {
		t.Fatal("deprecated fields must still decode")
	}
}

func TestConfigRejects(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"sspanel":   "Nodes:\n  - PanelType: SSpanel\n    ApiConfig: {ApiHost: http://a, ApiKey: k, NodeID: 1}\n",
		"no-nodes":  "Log: {Level: info}\n",
		"no-nodeid": "Nodes:\n  - PanelType: Xboard\n    ApiConfig: {ApiHost: http://a, ApiKey: k}\n",
		"duplicate": "Nodes:\n  - ApiConfig: {ApiHost: http://a, ApiKey: k, NodeID: 1}\n  - ApiConfig: {ApiHost: http://a/, ApiKey: k, NodeID: 1}\n",
	} {
		p := filepath.Join(dir, name+".yml")
		os.WriteFile(p, []byte(body), 0o600)
		if _, err := LoadConfig(p); err == nil {
			t.Errorf("%s: expected error", name)
		} else {
			t.Logf("%s: %v", name, err)
		}
	}
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// Two nodes in one instance, one with a panel DNS route; then a config file
// edit triggers a full reload.
func TestPanelMultiNodeAndReload(t *testing.T) {
	ports := map[string]int{"1": freePort(t), "2": freePort(t)}
	var configHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("node_id")
		switch {
		case strings.HasSuffix(r.URL.Path, "/config"):
			configHits.Add(1)
			routes := `[]`
			if id == "2" {
				routes = `[{"id":9,"match":["example.org"],"action":"dns","action_value":"1.1.1.1"}]`
			}
			fmt.Fprintf(w, `{"protocol":"vmess","server_port":%d,"network":"tcp","tls":0,"routes":%s,"base_config":{"push_interval":60,"pull_interval":60}}`, ports[id], routes)
		case strings.HasSuffix(r.URL.Path, "/user"):
			io.WriteString(w, `{"users":[{"id":1,"uuid":"7f6fd2d2-9a3d-4a8e-9f5b-1c2d3e4f5a6b"}]}`)
		default:
			io.WriteString(w, `{"data":true}`)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	write := func(level string) {
		os.WriteFile(path, []byte(fmt.Sprintf(`
Log:
  Level: %s
Nodes:
  - PanelType: Xboard
    ApiConfig: {ApiHost: "%s", ApiKey: k, NodeID: 1}
    ControllerConfig: {ListenIP: 127.0.0.1}
  - PanelType: Xboard
    ApiConfig: {ApiHost: "%s", ApiKey: k, NodeID: 2}
    ControllerConfig: {ListenIP: 127.0.0.1}
`, level, srv.URL, srv.URL)), 0o600)
	}
	write("warning")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	p := New(path, cfg)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	listening := func() {
		t.Helper()
		for id, port := range ports {
			c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
			if err != nil {
				t.Fatalf("node %s not listening: %v", id, err)
			}
			c.Close()
		}
	}
	listening()
	p.mu.Lock()
	nodes := len(p.nodes)
	p.mu.Unlock()
	if nodes != 2 {
		t.Fatalf("%d nodes running", nodes)
	}

	before := configHits.Load()
	write("info")
	deadline := time.Now().Add(15 * time.Second)
	for configHits.Load() < before+2 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if configHits.Load() < before+2 {
		t.Fatal("config change did not trigger a reload")
	}
	time.Sleep(500 * time.Millisecond)
	p.mu.Lock()
	level := p.cfg.LogConfig.Level
	running := p.running
	p.mu.Unlock()
	if level != "info" || !running {
		t.Fatalf("after reload: level=%s running=%v", level, running)
	}
	listening()
	_ = node.DefaultConfig
}

// D-C: closing the instance (shutdown, and with it every reload) must abort
// the tracked connections; Xray itself leaves accepted connections running.
func TestPanelShutdownAbortsTrackedConns(t *testing.T) {
	nodePort := freePort(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/config"):
			fmt.Fprintf(w, `{"protocol":"vmess","server_port":%d,"network":"tcp","tls":0,"routes":[],"base_config":{"push_interval":60,"pull_interval":60}}`, nodePort)
		case strings.HasSuffix(r.URL.Path, "/user"):
			io.WriteString(w, `{"users":[{"id":1,"uuid":"7f6fd2d2-9a3d-4a8e-9f5b-1c2d3e4f5a6b"}]}`)
		default:
			io.WriteString(w, `{"data":true}`)
		}
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "config.yml")
	os.WriteFile(path, []byte(fmt.Sprintf(`
Nodes:
  - PanelType: Xboard
    ApiConfig: {ApiHost: "%s", ApiKey: k, NodeID: 1}
    ControllerConfig: {ListenIP: 127.0.0.1}
`, srv.URL)), 0o600)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	p := New(path, cfg)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()

	p.mu.Lock()
	cr := p.core
	p.mu.Unlock()
	cr.Conns().Watch("fwd-")
	fwd := freePort(t)
	var ic conf.InboundDetourConfig
	if err := json.Unmarshal([]byte(fmt.Sprintf(`{"tag":"fwd-1","listen":"127.0.0.1","port":%d,"protocol":"dokodemo-door",
		"settings":{"address":"127.0.0.1","port":%d,"network":"tcp"}}`, fwd, echo.Addr().(*net.TCPAddr).Port)), &ic); err != nil {
		t.Fatal(err)
	}
	hc, err := ic.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := cr.AddInbound(hc); err != nil {
		t.Fatal(err)
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", fwd), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write([]byte("ping"))
	if _, err := io.ReadFull(conn, make([]byte, 4)); err != nil {
		t.Fatalf("echo: %v", err)
	}
	if cr.Conns().Active("fwd-1") != 1 {
		t.Fatalf("Active = %d, want 1", cr.Conns().Active("fwd-1"))
	}

	p.shutdown()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("unexpected data after shutdown")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("tracked connection survived shutdown")
	}
}
