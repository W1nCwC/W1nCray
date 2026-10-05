package node

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	xcore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/W1nCwC/W1nCray/common/cert"
	"github.com/W1nCwC/W1nCray/core"
)

// ---- fake Xboard -------------------------------------------------------

type fakePanel struct {
	t       *testing.T
	srv     *httptest.Server
	mu      sync.Mutex
	node    string
	users   []map[string]any
	traffic []map[string][2]int64
	alive   []map[string][]string
	status  int
	// hook serves extra endpoints (WebSocket tests); true = handled.
	hook func(w http.ResponseWriter, r *http.Request) bool
}

func newFakePanel(t *testing.T, node string, users []map[string]any) *fakePanel {
	fp := &fakePanel{t: t, node: node, users: users}
	fp.srv = httptest.NewServer(http.HandlerFunc(fp.handle))
	t.Cleanup(fp.srv.Close)
	return fp
}

func etag(b []byte) string {
	h := sha1.Sum(b)
	return `"` + hex.EncodeToString(h[:]) + `"`
}

func (fp *fakePanel) handle(w http.ResponseWriter, r *http.Request) {
	if fp.hook != nil && fp.hook(w, r) {
		return
	}
	q := r.URL.Query()
	if q.Get("token") != "secret" || q.Get("node_id") != "1" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	fp.mu.Lock()
	defer fp.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/server/UniProxy/")
	switch name {
	case "config", "user":
		var b []byte
		if name == "config" {
			b = []byte(fp.node)
		} else {
			b, _ = json.Marshal(map[string]any{"users": fp.users})
		}
		tag := etag(b)
		if strings.Contains(r.Header.Get("If-None-Match"), tag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", tag)
		w.Write(b)
	case "push":
		var m map[string][2]int64
		if err := json.Unmarshal(body, &m); err != nil {
			fp.t.Errorf("push body %s: %v", body, err)
		}
		fp.traffic = append(fp.traffic, m)
		io.WriteString(w, `{"data":true}`)
	case "alive":
		var m map[string][]string
		if err := json.Unmarshal(body, &m); err != nil {
			fp.t.Errorf("alive body %s: %v", body, err)
		}
		fp.alive = append(fp.alive, m)
		io.WriteString(w, `{"data":true}`)
	case "alivelist":
		io.WriteString(w, `{"alive":{}}`)
	case "status":
		fp.status++
		io.WriteString(w, `{"data":true}`)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (fp *fakePanel) setUsers(users []map[string]any) {
	fp.mu.Lock()
	fp.users = users
	fp.mu.Unlock()
}

func (fp *fakePanel) totals(uid int) (up, down int64) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	for _, m := range fp.traffic {
		t := m[strconv.Itoa(uid)]
		up += t[0]
		down += t[1]
	}
	return
}

func (fp *fakePanel) aliveIPs(uid int) []string {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	var out []string
	for _, m := range fp.alive {
		out = append(out, m[strconv.Itoa(uid)]...)
	}
	return out
}

// ---- helpers -------------------------------------------------------------

const (
	uuid1 = "7f6fd2d2-9a3d-4a8e-9f5b-1c2d3e4f5a6b"
	uuid2 = "0e1d2c3b-4a59-6877-8695-a4b3c2d1e0f9"
)

func panelUsers(speed1, device1 int) []map[string]any {
	return []map[string]any{
		{"id": 1, "uuid": uuid1, "speed_limit": speed1, "device_limit": device1},
		{"id": 2, "uuid": uuid2, "speed_limit": nil, "device_limit": nil},
	}
}

func freePort(t *testing.T, network string) int {
	t.Helper()
	if network == "udp" {
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr).Port
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// target is the HTTP server reached through the proxy.
func target(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		chunk := make([]byte, 32*1024)
		if r.URL.Path == "/slow" {
			// 10 chunks over ~1 s, flushed one by one.
			for i := 0; i < 10; i++ {
				w.Write(chunk[:1024])
				w.(http.Flusher).Flush()
				time.Sleep(100 * time.Millisecond)
			}
			return
		}
		for n > 0 {
			k := min(n, len(chunk))
			if _, err := w.Write(chunk[:k]); err != nil {
				return
			}
			n -= k
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

type server struct {
	panel *fakePanel
	core  *core.Core
	ctl   *Controller
}

func startServer(t *testing.T, nodeJSON string, users []map[string]any, mutate func(*Config)) *server {
	t.Helper()
	return startServerOn(t, newFakePanel(t, nodeJSON, users), mutate)
}

func startServerOn(t *testing.T, fp *fakePanel, mutate func(*Config)) *server {
	t.Helper()
	return startServerWith(t, fp, mutate, nil)
}

// startServerWith also lets a test adjust the kernel options (route.json etc).
func startServerWith(t *testing.T, fp *fakePanel, mutate func(*Config), coreMut func(*core.Options)) *server {
	t.Helper()
	cfg := DefaultConfig()
	cfg.ListenIP = "127.0.0.1"
	off := false
	cfg.BlockPrivateIP = &off
	if mutate != nil {
		mutate(cfg)
	}
	ctl := New(Options{
		API:    &APIConfig{APIHost: fp.srv.URL, Key: "secret", NodeID: 1, Timeout: 10},
		Config: cfg,
		Certs:  cert.NewManager(t.TempDir()),
		Reload: func(reason string) { t.Errorf("unexpected reload: %s", reason) },
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := ctl.Prefetch(ctx); err != nil {
		t.Fatal(err)
	}
	copts := core.Options{
		LogLevel:    "warning",
		Connection:  core.ConnectionPolicy{Handshake: 4, ConnIdle: 30, UplinkOnly: 2, DownlinkOnly: 4, BufferSize: 64},
		NameServers: ctl.NameServers(),
	}
	if coreMut != nil {
		coreMut(&copts)
	}
	cr, err := core.New(copts)
	if err != nil {
		t.Fatal(err)
	}
	if err := cr.Start(); err != nil {
		t.Fatal(err)
	}
	if err := ctl.Start(cr); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctl.Close()
		cr.Close()
	})
	ctl.mu.Lock()
	up := ctl.inboundUp
	ctl.mu.Unlock()
	if !up {
		t.Fatal("inbound not started")
	}
	return &server{panel: fp, core: cr, ctl: ctl}
}

// certPin returns the SHA-256 of the node certificate, for clients that pin
// it (Xray v26 removed allowInsecure).
func (s *server) certPin(t *testing.T) string {
	t.Helper()
	s.ctl.mu.Lock()
	defer s.ctl.mu.Unlock()
	if s.ctl.spec == nil || s.ctl.spec.cert == nil {
		return ""
	}
	pair, err := tls.LoadX509KeyPair(s.ctl.spec.cert.CertFile, s.ctl.spec.cert.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(pair.Certificate[0])
	return hex.EncodeToString(sum[:])
}

// client is an official Xray instance with a local SOCKS inbound.
type client struct {
	inst  *xcore.Instance
	proxy *url.URL
}

func startClient(t *testing.T, outbound string) *client {
	t.Helper()
	port := freePort(t, "tcp")
	cfgJSON := fmt.Sprintf(`{
		"log": {"loglevel": "warning"},
		"inbounds": [{"listen": "127.0.0.1", "port": %d, "protocol": "socks", "settings": {"auth": "noauth", "udp": false}}],
		"outbounds": [%s]
	}`, port, outbound)
	var c conf.Config
	if err := json.Unmarshal([]byte(cfgJSON), &c); err != nil {
		t.Fatalf("client config: %v", err)
	}
	pb, err := c.Build()
	if err != nil {
		t.Fatalf("client build: %v", err)
	}
	inst, err := xcore.New(pb)
	if err != nil {
		t.Fatal(err)
	}
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { inst.Close() })
	u, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
	return &client{inst: inst, proxy: u}
}

func (c *client) get(rawURL string, timeout time.Duration) (int, error) {
	hc := &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{Proxy: http.ProxyURL(c.proxy), DisableKeepAlives: true},
	}
	resp, err := hc.Get(rawURL)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, resp.Body)
	return int(n), err
}

// ---- protocol matrix -----------------------------------------------------

type protoCase struct {
	name   string
	node   func(port int) string
	client func(port int, uuid string) string
	udp    bool
}

const ss2022ServerKey = "MTIzNDU2Nzg5MDEyMzQ1Ng=="

var protoCases = []protoCase{
	{
		name: "vmess-tcp",
		node: func(p int) string {
			return fmt.Sprintf(`{"protocol":"vmess","listen_ip":"0.0.0.0","server_port":%d,"network":"tcp","networkSettings":null,"tls":0,"tls_settings":null,"base_config":{"push_interval":60,"pull_interval":60},"routes":[]}`, p)
		},
		client: func(p int, id string) string {
			return fmt.Sprintf(`{"protocol":"vmess","settings":{"vnext":[{"address":"127.0.0.1","port":%d,"users":[{"id":"%s","security":"auto"}]}]}}`, p, id)
		},
	},
	{
		name: "vmess-ws",
		node: func(p int) string {
			return fmt.Sprintf(`{"protocol":"vmess","server_port":%d,"network":"ws","networkSettings":{"path":"/ws","headers":{"Host":"cdn.example.com"}},"tls":0}`, p)
		},
		client: func(p int, id string) string {
			return fmt.Sprintf(`{"protocol":"vmess","settings":{"vnext":[{"address":"127.0.0.1","port":%d,"users":[{"id":"%s"}]}]},"streamSettings":{"network":"ws","wsSettings":{"path":"/ws","host":"cdn.example.com"}}}`, p, id)
		},
	},
	{
		name: "vless-tcp",
		node: func(p int) string {
			return fmt.Sprintf(`{"protocol":"vless","server_port":%d,"network":"tcp","tls":0,"flow":null,"decryption":null}`, p)
		},
		client: func(p int, id string) string {
			return fmt.Sprintf(`{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":%d,"users":[{"id":"%s","encryption":"none"}]}]}}`, p, id)
		},
	},
	{
		name: "vless-xhttp",
		node: func(p int) string {
			return fmt.Sprintf(`{"protocol":"vless","server_port":%d,"network":"xhttp","networkSettings":{"path":"/xh","mode":"auto","extra":[]},"tls":0}`, p)
		},
		client: func(p int, id string) string {
			return fmt.Sprintf(`{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":%d,"users":[{"id":"%s","encryption":"none"}]}]},"streamSettings":{"network":"xhttp","xhttpSettings":{"path":"/xh","mode":"auto"}}}`, p, id)
		},
	},
	{
		name: "trojan-tls-selfcert",
		node: func(p int) string {
			return fmt.Sprintf(`{"protocol":"trojan","server_port":%d,"network":"tcp","host":"node.test","server_name":"node.test","tls":1,"tls_settings":{"server_name":"node.test","allow_insecure":true},"cert_config":{"cert_mode":"self","domain":"node.test"}}`, p)
		},
		client: func(p int, id string) string {
			return fmt.Sprintf(`{"protocol":"trojan","settings":{"servers":[{"address":"127.0.0.1","port":%d,"password":"%s"}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"node.test","pinnedPeerCertSha256":"%%PIN%%"}}}`, p, id)
		},
	},
	{
		name: "shadowsocks-aes-128-gcm",
		node: func(p int) string {
			return fmt.Sprintf(`{"protocol":"shadowsocks","server_port":%d,"network":null,"cipher":"aes-128-gcm","plugin":null,"plugin_opts":null,"server_key":null}`, p)
		},
		client: func(p int, id string) string {
			return fmt.Sprintf(`{"protocol":"shadowsocks","settings":{"servers":[{"address":"127.0.0.1","port":%d,"method":"aes-128-gcm","password":"%s"}]}}`, p, id)
		},
	},
	{
		name: "shadowsocks-2022",
		node: func(p int) string {
			return fmt.Sprintf(`{"protocol":"shadowsocks","server_port":%d,"cipher":"2022-blake3-aes-128-gcm","server_key":"%s"}`, p, ss2022ServerKey)
		},
		client: func(p int, id string) string {
			// Xboard subscription password: "<server_key>:<user_key>".
			return fmt.Sprintf(`{"protocol":"shadowsocks","settings":{"servers":[{"address":"127.0.0.1","port":%d,"method":"2022-blake3-aes-128-gcm","password":"%s:%s"}]}}`, p, ss2022ServerKey, ss2022UserKey(id, 16))
		},
	},
	{
		name: "hysteria2-salamander",
		udp:  true,
		node: func(p int) string {
			return fmt.Sprintf(`{"protocol":"hysteria","server_port":%d,"version":2,"host":"node.test","server_name":"node.test","tls_settings":{"server_name":"node.test","allow_insecure":true},"up_mbps":0,"down_mbps":0,"obfs":"salamander","obfs-password":"obfspass","cert_config":{"cert_mode":"self","domain":"node.test"}}`, p)
		},
		client: func(p int, id string) string {
			return fmt.Sprintf(`{"protocol":"hysteria","settings":{"version":2,"address":"127.0.0.1","port":%d},"streamSettings":{"network":"hysteria","hysteriaSettings":{"version":2,"auth":"%s"},"security":"tls","tlsSettings":{"serverName":"node.test","pinnedPeerCertSha256":"%%PIN%%","alpn":["h3"]},"finalmask":{"udp":[{"type":"salamander","settings":{"password":"obfspass"}}]}}}`, p, id)
		},
	},
	{
		name: "socks",
		node: func(p int) string {
			return fmt.Sprintf(`{"protocol":"socks","server_port":%d,"tls":0}`, p)
		},
		client: func(p int, id string) string {
			return fmt.Sprintf(`{"protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":%d,"users":[{"user":"%s","pass":"%s"}]}]}}`, p, id, id)
		},
	},
	{
		name: "http",
		node: func(p int) string {
			return fmt.Sprintf(`{"protocol":"http","server_port":%d,"tls":0}`, p)
		},
		client: func(p int, id string) string {
			return fmt.Sprintf(`{"protocol":"http","settings":{"servers":[{"address":"127.0.0.1","port":%d,"users":[{"user":"%s","pass":"%s"}]}]}}`, p, id, id)
		},
	},
}

func TestE2EProtocols(t *testing.T) {
	tgt := target(t)
	for _, pc := range protoCases {
		t.Run(pc.name, func(t *testing.T) {
			network := "tcp"
			if pc.udp {
				network = "udp"
			}
			port := freePort(t, network)
			s := startServer(t, pc.node(port), panelUsers(0, 0), nil)
			pin := s.certPin(t)
			c := startClient(t, strings.ReplaceAll(pc.client(port, uuid1), "%PIN%", pin))

			const size = 256 * 1024
			n, err := c.get(tgt.URL+"/bytes?n="+strconv.Itoa(size), 15*time.Second)
			if err != nil {
				t.Fatalf("request through %s: %v", pc.name, err)
			}
			if n != size {
				t.Fatalf("got %d bytes, want %d", n, size)
			}

			s.ctl.push()
			up, down := s.panel.totals(1)
			if up <= 0 || down < size {
				t.Fatalf("reported traffic up=%d down=%d, want up>0 down>=%d", up, down, size)
			}
			if u2, d2 := s.panel.totals(2); u2 != 0 || d2 != 0 {
				t.Fatalf("user 2 has traffic %d/%d", u2, d2)
			}
			// Online IPs are reported as they appear (devices.go).
			eventually(t, "online IP reported", 10*time.Second, func() bool {
				ips := s.panel.aliveIPs(1)
				return len(ips) > 0 && ips[0] == "127.0.0.1"
			})
			if s.panel.status == 0 {
				t.Fatal("status not reported")
			}

			// Counters were decreased by what was reported.
			s.ctl.push()
			if up2, down2 := s.panel.totals(1); up2 != up || down2 != down {
				t.Fatalf("traffic reported twice: %d/%d -> %d/%d", up, down, up2, down2)
			}

			// A wrong credential must be refused. It targets a fresh node:
			// Xray's hysteria client caches connections per destination
			// for the whole process, so a second client to the same
			// address would reuse the authenticated connection above.
			port2 := freePort(t, network)
			s2 := startServer(t, pc.node(port2), panelUsers(0, 0), nil)
			bad := startClient(t, strings.ReplaceAll(pc.client(port2, "00000000-0000-0000-0000-000000000000"), "%PIN%", s2.certPin(t)))
			if _, err := bad.get(tgt.URL+"/bytes?n=10", 5*time.Second); err == nil {
				t.Fatal("unknown user was accepted")
			}
		})
	}
}

// ---- users, limits, rules ------------------------------------------------

func vmessNode(port int, routes string) string {
	return fmt.Sprintf(`{"protocol":"vmess","server_port":%d,"network":"tcp","tls":0,"routes":%s}`, port, routes)
}

func vlessNode(port int) string {
	return fmt.Sprintf(`{"protocol":"vless","server_port":%d,"network":"tcp","tls":0}`, port)
}

func TestE2EUserHotUpdate(t *testing.T) {
	tgt := target(t)
	port := freePort(t, "tcp")
	s := startServer(t, vmessNode(port, "[]"), panelUsers(0, 0), nil)
	c1 := startClient(t, protoCases[0].client(port, uuid1))
	c2 := startClient(t, protoCases[0].client(port, uuid2))

	if _, err := c1.get(tgt.URL+"/bytes?n=1000", 10*time.Second); err != nil {
		t.Fatal(err)
	}

	// User 2 streams for ~1 s while user 1 is removed.
	done := make(chan error, 1)
	go func() {
		n, err := c2.get(tgt.URL+"/slow", 10*time.Second)
		if err == nil && n != 10*1024 {
			err = fmt.Errorf("got %d bytes", n)
		}
		done <- err
	}()
	time.Sleep(300 * time.Millisecond)
	s.panel.setUsers([]map[string]any{{"id": 2, "uuid": uuid2}})
	s.ctl.pull()
	if err := <-done; err != nil {
		t.Fatalf("other user's connection was disturbed: %v", err)
	}
	if _, err := c1.get(tgt.URL+"/bytes?n=1000", 5*time.Second); err == nil {
		t.Fatal("removed user still accepted")
	}

	// Traffic of the removed user is still reported once.
	s.ctl.push()
	if up, down := s.panel.totals(1); up <= 0 || down < 1000 {
		t.Fatalf("removed user's traffic lost: %d/%d", up, down)
	}

	// Re-adding works.
	s.panel.setUsers(panelUsers(0, 0))
	s.ctl.pull()
	if _, err := c1.get(tgt.URL+"/bytes?n=1000", 10*time.Second); err != nil {
		t.Fatalf("re-added user: %v", err)
	}
}

func timedGet(t *testing.T, c *client, u string) time.Duration {
	t.Helper()
	start := time.Now()
	n, err := c.get(u, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(u, "n=") {
		return time.Since(start)
	}
	want, _ := strconv.Atoi(u[strings.Index(u, "n=")+2:])
	if n != want {
		t.Fatalf("got %d bytes, want %d", n, want)
	}
	return time.Since(start)
}

func TestE2ESpeedLimit(t *testing.T) {
	tgt := target(t)
	// 8 Mbps = 1 MB/s; 3 MB with a 1 MB burst takes about 2 s.
	const size = 3 * 1000 * 1000
	for _, tc := range []struct {
		name string
		node func(int) string
		cli  func(int, string) string
	}{
		{"vmess-dispatch", func(p int) string { return vmessNode(p, "[]") }, protoCases[0].client},
		{"vless-dispatchlink", vlessNode, protoCases[2].client},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := freePort(t, "tcp")
			startServer(t, tc.node(port), panelUsers(8, 0), nil)
			limited := startClient(t, tc.cli(port, uuid1))
			free := startClient(t, tc.cli(port, uuid2))

			el := timedGet(t, limited, tgt.URL+"/bytes?n="+strconv.Itoa(size))
			if el < 1500*time.Millisecond {
				t.Fatalf("limited download took %v, want >= 1.5s", el)
			}
			if el > 6*time.Second {
				t.Fatalf("limited download took %v, far below the limit", el)
			}
			fast := timedGet(t, free, tgt.URL+"/bytes?n="+strconv.Itoa(size))
			if fast > el/2 {
				t.Fatalf("unlimited download took %v (limited %v)", fast, el)
			}
			t.Logf("limited %v, unlimited %v", el, fast)
		})
	}
}

func TestE2EDeviceLimit(t *testing.T) {
	tgt := target(t)
	port := freePort(t, "tcp")
	startServer(t, vmessNode(port, "[]"), panelUsers(0, 1), nil)
	out := func(src string) string {
		return fmt.Sprintf(`{"protocol":"vmess","sendThrough":"%s","settings":{"vnext":[{"address":"127.0.0.1","port":%d,"users":[{"id":"%s"}]}]}}`, src, port, uuid1)
	}
	a := startClient(t, out("127.0.0.1"))
	b := startClient(t, out("127.0.0.2"))

	if _, err := a.get(tgt.URL+"/bytes?n=1000", 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := b.get(tgt.URL+"/bytes?n=1000", 5*time.Second); err == nil {
		t.Fatal("second device was accepted with device_limit=1")
	}
	if _, err := a.get(tgt.URL+"/bytes?n=1000", 10*time.Second); err != nil {
		t.Fatalf("first device rejected: %v", err)
	}
}

func TestE2ERules(t *testing.T) {
	tgt := target(t)

	t.Run("block-private-ip", func(t *testing.T) {
		port := freePort(t, "tcp")
		startServer(t, vmessNode(port, "[]"), panelUsers(0, 0), func(c *Config) { c.BlockPrivateIP = nil })
		c := startClient(t, protoCases[0].client(port, uuid1))
		if _, err := c.get(tgt.URL+"/bytes?n=10", 5*time.Second); err == nil {
			t.Fatal("private address reachable with BlockPrivateIP")
		}
	})

	t.Run("panel-block-route", func(t *testing.T) {
		port := freePort(t, "tcp")
		routes := `[{"id":1,"match":["127.0.0.1/32"],"action":"block","action_value":null}]`
		startServer(t, vmessNode(port, routes), panelUsers(0, 0), nil)
		c := startClient(t, protoCases[0].client(port, uuid1))
		if _, err := c.get(tgt.URL+"/bytes?n=10", 5*time.Second); err == nil {
			t.Fatal("blocked destination reachable")
		}
	})

	t.Run("custom-outbound-proxy-route", func(t *testing.T) {
		port := freePort(t, "tcp")
		node := fmt.Sprintf(`{"protocol":"vmess","server_port":%d,"network":"tcp","tls":0,
			"routes":[{"id":2,"match":["127.0.0.1/32"],"action":"proxy","action_value":"sink"}],
			"custom_outbounds":[{"tag":"sink","protocol":"blackhole"}]}`, port)
		startServer(t, node, panelUsers(0, 0), nil)
		c := startClient(t, protoCases[0].client(port, uuid1))
		if _, err := c.get(tgt.URL+"/bytes?n=10", 5*time.Second); err == nil {
			t.Fatal("traffic not sent to the custom outbound")
		}
	})
}

// REALITY needs a TLS 1.3 target to borrow the handshake from; a local Go
// TLS server stands in for a real website.
func TestE2EREALITYVision(t *testing.T) {
	tgt := target(t)
	realityTarget := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	realityTarget.EnableHTTP2 = true
	realityTarget.StartTLS()
	t.Cleanup(realityTarget.Close)
	targetPort := realityTarget.Listener.Addr().(*net.TCPAddr).Port

	priv, pub := x25519Pair(t)
	port := freePort(t, "tcp")
	node := fmt.Sprintf(`{"protocol":"vless","server_port":%d,"network":"tcp","networkSettings":null,"tls":2,"flow":"xtls-rprx-vision","decryption":null,
		"tls_settings":{"server_name":"example.com","server_port":"%d","public_key":"%s","private_key":"%s","short_id":"0123abcd","allow_insecure":false}}`,
		port, targetPort, pub, priv)
	// Panel gives server_name:server_port as target; point it at the local
	// TLS server through a dest override in the same settings object.
	node = strings.Replace(node, `"short_id"`, fmt.Sprintf(`"dest":"127.0.0.1:%d","short_id"`, targetPort), 1)
	s := startServer(t, node, panelUsers(8, 0), nil)

	cli := func(id string) string {
		return fmt.Sprintf(`{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":%d,"users":[{"id":"%s","encryption":"none","flow":"xtls-rprx-vision"}]}]},
			"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"example.com","publicKey":"%s","shortId":"0123abcd","fingerprint":"chrome"}}}`, port, id, pub)
	}
	free := startClient(t, cli(uuid2))
	// The first handshake against a new target waits ~5 s while the REALITY
	// library probes the target's post-handshake records (upstream
	// behaviour, reality/tls.go), so warm up before timing.
	timedGet(t, free, tgt.URL+"/bytes?n=1000")
	const size = 3 * 1000 * 1000
	fast := timedGet(t, free, tgt.URL+"/bytes?n="+strconv.Itoa(size))

	limited := startClient(t, cli(uuid1))
	el := timedGet(t, limited, tgt.URL+"/bytes?n="+strconv.Itoa(size))
	if el < 1500*time.Millisecond {
		t.Fatalf("vision user with 8 Mbps limit took %v", el)
	}
	if fast > el/2 {
		t.Fatalf("unlimited vision user took %v (limited %v)", fast, el)
	}
	t.Logf("REALITY+Vision: limited %v, unlimited %v", el, fast)

	s.ctl.push()
	if _, down := s.panel.totals(1); down < size {
		t.Fatalf("reported download %d < %d", down, size)
	}
}

func x25519Pair(t *testing.T) (priv, pub string) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(k.Bytes()), base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes())
}
