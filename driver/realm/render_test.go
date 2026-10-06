package realm

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/spec"
)

var update = flag.Bool("update", false, "rewrite the golden files")

const testSecret = "test-secret-0123456789abcdef"

func fwd(id, listen, ports string, targets ...spec.Target) spec.Instance {
	return spec.Instance{
		ID: id, Enabled: true, Engine: spec.EngineRealm, Kind: spec.KindForward,
		Listen:  &spec.Listen{Addr: listen, Ports: ports},
		Targets: targets,
	}
}

func tg(host, ports string, weight int) spec.Target {
	return spec.Target{Host: host, Ports: ports, Weight: weight}
}

func entry(id string, t spec.Tunnel) spec.Instance {
	return spec.Instance{
		ID: id, Enabled: true, Engine: spec.EngineRealm, Kind: spec.KindTunnelEntry,
		Listen: &spec.Listen{Addr: "127.0.0.1", Ports: "8080"},
		Tunnel: &t,
	}
}

func exit(id string, t spec.Tunnel, targets ...spec.Target) spec.Instance {
	return spec.Instance{
		ID: id, Enabled: true, Engine: spec.EngineRealm, Kind: spec.KindTunnelExit,
		Tunnel: &t, Targets: targets,
	}
}

type goldenCase struct {
	name string
	opts Options
	in   spec.Instance
}

func goldenCases() []goldenCase {
	withProxyOut := func(i spec.Instance, v int) spec.Instance { i.ProxyProtocolOut = v; return i }
	withAccept := func(i spec.Instance) spec.Instance { i.AcceptProxyProtocol = true; return i }
	withNet := func(i spec.Instance, n ...string) spec.Instance { i.Network = n; return i }
	withBal := func(i spec.Instance, s string) spec.Instance { i.Balance = &spec.Balance{Strategy: s}; return i }
	withSecret := func(i spec.Instance) spec.Instance { i.Secret = testSecret; return i }

	rangeMap := fwd("rng", "0.0.0.0", "20000-20003", tg("backend.example.com", "30000-30003", 0))
	rangeMap.Listen.PortMap = map[string]string{"20001": "10.9.9.9:443", "20003": "[2001:db8::7]:8443"}

	udpLong := withNet(fwd("dns", "0.0.0.0", "5353", tg("1.1.1.1", "53", 0)), "udp")
	udpLong.IdleProfile = "udp_long"

	return []goldenCase{
		{"forward_tcp_single", Options{}, fwd("web", "127.0.0.1", "8080", tg("10.0.0.5", "80", 0))},
		{"forward_tcp_udp", Options{}, withNet(fwd("both", "0.0.0.0", "5000", tg("10.0.0.5", "5000", 0)), "tcp", "udp")},
		{"forward_udp_only_long_idle", Options{}, udpLong},
		{"forward_ipv6", Options{}, fwd("v6", "::1", "8443", tg("2001:db8::1", "443", 0))},
		{"forward_range_portmap", Options{}, rangeMap},
		{"forward_roundrobin_weights", Options{}, withBal(fwd("rr", "0.0.0.0", "9000",
			tg("10.0.0.1", "80", 1), tg("10.0.0.2", "80", 2), tg("lb3.example.com", "8080", 3)), "round_robin")},
		{"forward_iphash", Options{}, withBal(fwd("ih", "0.0.0.0", "9001",
			tg("10.0.0.1", "80", 0), tg("10.0.0.2", "80", 5)), "iphash")},
		{"forward_proxy_out_v2", Options{}, withProxyOut(fwd("po", "0.0.0.0", "9002", tg("10.0.0.1", "80", 0)), 2)},
		{"forward_proxy_out_v1_accept", Options{}, withAccept(withProxyOut(fwd("pa", "127.0.0.1", "9003", tg("10.0.0.1", "80", 0)), 1))},
		{"forward_accept_tcp_udp", Options{}, withAccept(withNet(fwd("au", "127.0.0.1", "9004", tg("10.0.0.1", "80", 0)), "tcp", "udp"))},
		{"entry_tcp", Options{}, entry("e-tcp", spec.Tunnel{Type: "tcp", Server: "198.51.100.7:7000"})},
		{"entry_ws", Options{}, entry("e-ws", spec.Tunnel{Type: "ws", Server: "198.51.100.7:7001", Host: "cdn.example.com", Path: "/ws/relay"})},
		{"entry_ws_secret", Options{}, withSecret(entry("e-wsk", spec.Tunnel{Type: "ws", Server: "exit.example.com:7001", Host: "cdn.example.com", Path: "/ws/relay"}))},
		{"entry_tls_alpn", Options{}, entry("e-tls", spec.Tunnel{Type: "tls", Server: "exit.example.com:443", SNI: "exit.example.com", ALPN: []string{"h2", "http/1.1"}})},
		{"entry_wss_secret_proxy", Options{}, withProxyOut(withSecret(entry("e-wss", spec.Tunnel{Type: "wss", Server: "exit.example.com:443", Host: "exit.example.com", Path: "/", SNI: "exit.example.com"})), 2)},
		{"entry_tls_insecure", Options{InsecureSkipTLSVerify: true}, entry("e-ins", spec.Tunnel{Type: "tls", Server: "127.0.0.1:7443", SNI: "localhost"})},
		{"exit_tcp", Options{}, exit("x-tcp", spec.Tunnel{Type: "tcp", Listen: "0.0.0.0:7000"}, tg("10.0.0.5", "22", 0))},
		{"exit_wss_file_cert", Options{}, withSecret(exit("x-wss", spec.Tunnel{
			Type: "wss", Listen: "0.0.0.0:443", Host: "exit.example.com", Path: "/ws/relay",
			Cert: &spec.Cert{Mode: "file", CertFile: "/etc/w1ncray/certs/exit.crt", KeyFile: "/etc/w1ncray/certs/exit.key"},
		}, tg("10.0.0.5", "22", 0)))},
		{"exit_ws_balance_accept_proxy", Options{}, withAccept(withProxyOut(withBal(exit("x-ws", spec.Tunnel{
			Type: "ws", Listen: "[::]:7001", Host: "cdn.example.com", Path: "/ws/relay",
		}, tg("10.0.0.1", "80", 1), tg("10.0.0.2", "80", 4)), "round_robin"), 2))},
		{"exit_tls_self_insecure", Options{InsecureSkipTLSVerify: true}, exit("x-self", spec.Tunnel{
			Type: "tls", Listen: "127.0.0.1:7443", SNI: "localhost", Cert: &spec.Cert{Mode: "self"},
		}, tg("127.0.0.1", "9", 0))},
	}
}

func TestRenderGolden(t *testing.T) {
	for _, tc := range goldenCases() {
		t.Run(tc.name, func(t *testing.T) {
			d := New(tc.opts)
			art, err := d.Render(tc.in)
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			got := art.Files[configName]
			path := filepath.Join("testdata", tc.name+".golden.json")
			if *update {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden (run with -update): %v", err)
			}
			want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
			if !bytes.Equal(got, want) {
				t.Errorf("rendered config differs from %s\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
			}
			// The output must be valid JSON and nothing else.
			var v any
			if err := json.Unmarshal(got, &v); err != nil {
				t.Errorf("not valid JSON: %v", err)
			}
			if bytes.Contains(got, []byte(testSecret)) {
				t.Errorf("the shared secret leaked into the configuration")
			}
		})
	}
}

func TestRenderDeterministic(t *testing.T) {
	in := fwd("rng", "0.0.0.0", "20000-20030", tg("backend.example.com", "30000-30030", 0))
	in.Listen.PortMap = map[string]string{}
	for p := 20001; p < 20030; p += 2 {
		in.Listen.PortMap[itoa(p)] = "10.0.0." + itoa(p%250+1) + ":" + itoa(p)
	}
	d := New(Options{})
	first, err := d.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		a, err := d.Render(in)
		if err != nil {
			t.Fatal(err)
		}
		if a.Hash != first.Hash || !bytes.Equal(a.Files[configName], first.Files[configName]) {
			t.Fatalf("render %d differs from the first one", i)
		}
	}
	// A different instance must hash differently.
	in.Listen.Ports = "20000-20029"
	in.Targets[0].Ports = "30000-30029"
	b, err := d.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if b.Hash == first.Hash {
		t.Fatal("different configuration, same hash")
	}
}

func TestRenderPortRangeExpansion(t *testing.T) {
	d := New(Options{})
	in := fwd("rng", "10.1.1.1", "20000-20002", tg("backend.example.com", "30000-30002", 0))
	in.Network = []string{"tcp", "udp"}
	art, err := d.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	var cfg fileConf
	if err := json.Unmarshal(art.Files[configName], &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Endpoints) != 3 {
		t.Fatalf("want 3 endpoints, got %d", len(cfg.Endpoints))
	}
	for i, ep := range cfg.Endpoints {
		if ep.Listen != "10.1.1.1:"+itoa(20000+i) || ep.Remote != "backend.example.com:"+itoa(30000+i) {
			t.Errorf("endpoint %d = %s -> %s", i, ep.Listen, ep.Remote)
		}
		if ep.Network == nil || !ep.Network.UseUDP || ep.Network.NoTCP {
			t.Errorf("endpoint %d network = %+v", i, ep.Network)
		}
	}
	if len(art.PortClaims) != 6 {
		t.Fatalf("want 6 port claims (3 ports x tcp+udp), got %d: %+v", len(art.PortClaims), art.PortClaims)
	}
	for _, c := range art.PortClaims {
		if c.Owner != "rng" || c.Addr != "10.1.1.1" || c.Port < 20000 || c.Port > 20002 {
			t.Errorf("bad claim %+v", c)
		}
	}
}

func TestRenderWeightedBalanceString(t *testing.T) {
	d := New(Options{})
	in := fwd("rr", "0.0.0.0", "9000", tg("10.0.0.1", "80", 0), tg("10.0.0.2", "80", 2), tg("10.0.0.3", "80", 7))
	in.Balance = &spec.Balance{Strategy: "round_robin"}
	art, err := d.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	var cfg fileConf
	_ = json.Unmarshal(art.Files[configName], &cfg)
	ep := cfg.Endpoints[0]
	if ep.Balance != "roundrobin: 1, 2, 7" {
		t.Errorf("balance = %q", ep.Balance)
	}
	if ep.Remote != "10.0.0.1:80" || strings.Join(ep.ExtraRemotes, ",") != "10.0.0.2:80,10.0.0.3:80" {
		t.Errorf("remotes = %q + %q (weights are positional: remote first, then extra_remotes in order)", ep.Remote, ep.ExtraRemotes)
	}
	in.Balance.Strategy = "iphash"
	art, _ = d.Render(in)
	_ = json.Unmarshal(art.Files[configName], &cfg)
	if cfg.Endpoints[0].Balance != "iphash: 1, 2, 7" {
		t.Errorf("iphash balance = %q", cfg.Endpoints[0].Balance)
	}
}

func TestRenderDisabledClaimsNothing(t *testing.T) {
	in := fwd("off", "0.0.0.0", "9000", tg("10.0.0.1", "80", 0))
	in.Enabled = false
	art, err := New(Options{}).Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(art.PortClaims) != 0 {
		t.Errorf("disabled instance claims %+v", art.PortClaims)
	}
}

// The ws path token is a pure function of Secret and Path, equal on entry and
// exit (otherwise the tunnel would not connect), and it differs per secret.
func TestWSPathTokenMatchesBothEnds(t *testing.T) {
	d := New(Options{})
	tun := spec.Tunnel{Type: "ws", Host: "cdn.example.com", Path: "/ws/relay"}
	en := tun
	en.Server = "198.51.100.7:7001"
	ex := tun
	ex.Listen = "0.0.0.0:7001"
	ein := entry("a", en)
	ein.Secret = testSecret
	xin := exit("b", ex, tg("10.0.0.5", "22", 0))
	xin.Secret = testSecret
	ea, err := d.Render(ein)
	if err != nil {
		t.Fatal(err)
	}
	xa, err := d.Render(xin)
	if err != nil {
		t.Fatal(err)
	}
	var ec, xc fileConf
	_ = json.Unmarshal(ea.Files[configName], &ec)
	_ = json.Unmarshal(xa.Files[configName], &xc)
	if ec.Endpoints[0].RemoteTransport != xc.Endpoints[0].ListenTransport {
		t.Fatalf("entry and exit disagree:\n entry %q\n exit  %q", ec.Endpoints[0].RemoteTransport, xc.Endpoints[0].ListenTransport)
	}
	if !strings.Contains(ec.Endpoints[0].RemoteTransport, "path=/ws/relay/") || strings.Contains(ec.Endpoints[0].RemoteTransport, testSecret) {
		t.Fatalf("unexpected transport %q", ec.Endpoints[0].RemoteTransport)
	}
	ein.Secret = testSecret + "x"
	eb, _ := d.Render(ein)
	if eb.Hash == ea.Hash {
		t.Fatal("a different secret must change the token")
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
