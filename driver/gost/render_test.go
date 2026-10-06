package gost

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/spec"
)

const testSecret = "s3cr3t-s3cr3t-s3cr3t-0123"

func fwd() spec.Instance {
	return spec.Instance{
		ID: "fw1", Enabled: true, Engine: spec.EngineGost, Kind: spec.KindForward,
		Listen:  &spec.Listen{Addr: "127.0.0.1", Ports: "20000-20002"},
		Network: []string{"tcp"},
		Targets: []spec.Target{{Host: "10.0.0.1", Ports: "30000-30002"}},
	}
}

func goldenInstances() map[string]spec.Instance {
	fwdRange := fwd()
	fwdRange.Network = []string{"udp", "tcp"}
	fwdRange.IdleProfile = "tcp_long"
	fwdRange.ProxyProtocolOut = 0
	fwdRange.Listen.PortMap = map[string]string{"20001": "192.0.2.9:4444"}

	lb := spec.Instance{
		ID: "lb", Enabled: true, Engine: spec.EngineGost, Kind: spec.KindForward,
		Listen: &spec.Listen{Addr: "0.0.0.0", Ports: "8443"},
		Targets: []spec.Target{
			{Host: "a.example.com", Ports: "443", Weight: 3},
			{Host: "10.0.0.2", Ports: "443", Weight: 1},
		},
		Balance:          &spec.Balance{Strategy: "random", Health: &spec.Health{Type: "tcp", MaxFails: 3, IntervalS: 30}},
		ProxyProtocolOut: 2,
		ACL:              &spec.ACL{Allow: []string{"10.0.0.0/8"}, Deny: []string{"10.1.2.3"}},
		Limits:           &spec.Limits{MaxConns: 50, RateUpBps: 8_000_000, RateDownBps: 16_000_000},
	}
	accept := spec.Instance{
		ID: "pp", Enabled: true, Engine: spec.EngineGost, Kind: spec.KindForward,
		Listen:              &spec.Listen{Addr: "127.0.0.1", Ports: "9000"},
		Targets:             []spec.Target{{Host: "10.0.0.5", Ports: "80"}},
		AcceptProxyProtocol: true, ProxyProtocolOut: 1,
	}
	entry := spec.Instance{
		ID: "en", Enabled: true, Engine: spec.EngineGost, Kind: spec.KindTunnelEntry,
		Listen:  &spec.Listen{Addr: "127.0.0.1", Ports: "7000"},
		Network: []string{"tcp", "udp"},
		Tunnel: &spec.Tunnel{Type: "wss", Server: "exit.example.com:443", Path: "/tun", Host: "cdn.example.com", SNI: "exit.example.com", Security: "tls",
			Cert: &spec.Cert{Mode: "file", CertFile: "/etc/w1ncray/exit-ca.pem"}},
		Secret: testSecret,
	}
	exit := spec.Instance{
		ID: "ex", Enabled: true, Engine: spec.EngineGost, Kind: spec.KindTunnelExit,
		Network: []string{"tcp", "udp"},
		Tunnel: &spec.Tunnel{Type: "wss", Listen: "0.0.0.0:443", Path: "/tun", Security: "tls",
			Cert: &spec.Cert{Mode: "file", CertFile: "/etc/w1ncray/c.pem", KeyFile: "/etc/w1ncray/k.pem"}},
		Targets: []spec.Target{{Host: "10.0.0.7", Ports: "5201"}},
		Secret:  testSecret,
	}
	portal := spec.Instance{
		ID: "po", Enabled: true, Engine: spec.EngineGost, Kind: spec.KindReversePortal,
		Listen: &spec.Listen{Addr: "0.0.0.0", Ports: "2222"},
		Tunnel: &spec.Tunnel{Type: "ws", Listen: "0.0.0.0:8443", Path: "/r"},
		Secret: testSecret,
	}
	bridge := spec.Instance{
		ID: "br", Enabled: true, Engine: spec.EngineGost, Kind: spec.KindReverseBridge,
		Listen:  &spec.Listen{Ports: "2222"},
		Network: []string{"tcp", "udp"},
		Tunnel:  &spec.Tunnel{Type: "ws", Server: "portal.example.com:8443", Path: "/r"},
		Targets: []spec.Target{{Host: "127.0.0.1", Ports: "22"}},
		Secret:  testSecret,
	}
	return map[string]spec.Instance{
		"forward_range": fwdRange, "forward_lb": lb, "forward_proxy": accept,
		"tunnel_entry": entry, "tunnel_exit": exit, "reverse_portal": portal, "reverse_bridge": bridge,
	}
}

func TestRenderGolden(t *testing.T) {
	d := New(Options{})
	for name, in := range goldenInstances() {
		t.Run(name, func(t *testing.T) {
			if err := d.Validate(in); err != nil {
				t.Fatalf("validate: %v", err)
			}
			a, err := d.Render(in)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("testdata", name+".golden.json")
			if os.Getenv("UPDATE_GOLDEN") != "" {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, a.Files[fragmentFile], 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("missing golden (run with UPDATE_GOLDEN=1): %v", err)
			}
			if !bytes.Equal(bytes.TrimSpace(want), bytes.TrimSpace(a.Files[fragmentFile])) {
				t.Fatalf("fragment differs from %s:\n%s", path, a.Files[fragmentFile])
			}
		})
	}
}

func TestRenderDeterministic(t *testing.T) {
	d := New(Options{})
	for name, in := range goldenInstances() {
		a1, _ := d.Render(in)
		a2, _ := d.Render(in)
		if a1.Hash != a2.Hash || !reflect.DeepEqual(a1.PortClaims, a2.PortClaims) {
			t.Errorf("%s: render is not deterministic", name)
		}
		if strings.Contains(a1.Hash, testSecret) {
			t.Errorf("%s: secret in hash", name)
		}
	}
	// A changed field changes the hash; network order does not.
	a := fwd()
	b := fwd()
	b.Targets[0].Host = "10.0.0.9"
	h1, _ := d.Render(a)
	h2, _ := d.Render(b)
	if h1.Hash == h2.Hash {
		t.Error("hash did not change with the target")
	}
	c, e := fwd(), fwd()
	c.Network = []string{"tcp", "udp"}
	e.Network = []string{"udp", "tcp"}
	hc, _ := d.Render(c)
	he, _ := d.Render(e)
	if hc.Hash != he.Hash {
		t.Error("network order changed the hash")
	}
}

// fragment decoded back from the artifact.
func frag(t *testing.T, in spec.Instance) fragment {
	t.Helper()
	a, err := New(Options{}).Render(in)
	if err != nil {
		t.Fatal(err)
	}
	var f fragment
	if err := json.Unmarshal(a.Files[fragmentFile], &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestPortRangeExpansionAndClaims(t *testing.T) {
	in := fwd()
	in.Network = []string{"tcp", "udp"}
	d := New(Options{})
	a, err := d.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	f := frag(t, in)
	if len(f.Services) != 6 {
		t.Fatalf("want 6 services (3 ports x 2 protocols), got %d", len(f.Services))
	}
	if len(a.PortClaims) != 6 {
		t.Fatalf("want 6 claims, got %d", len(a.PortClaims))
	}
	// One-to-one mapping: listen 20001 -> target port 30001.
	for _, s := range f.Services {
		if s.Name == "fw1.tcp.20001" {
			if got := s.Forwarder.Nodes[0].Addr; got != "10.0.0.1:30001" {
				t.Errorf("one-to-one mapping broken: %s", got)
			}
			if s.Addr != "127.0.0.1:20001" {
				t.Errorf("addr %s", s.Addr)
			}
		}
	}
	protos := map[string]int{}
	for _, c := range a.PortClaims {
		protos[c.Proto]++
		if c.Owner != "fw1" || c.Addr != "127.0.0.1" {
			t.Errorf("claim %+v", c)
		}
	}
	if protos["tcp"] != 3 || protos["udp"] != 3 {
		t.Errorf("claims by proto %v", protos)
	}
}

func TestPortMapOverridesTargets(t *testing.T) {
	in := fwd()
	in.Listen.PortMap = map[string]string{"20001": "192.0.2.9:4444"}
	f := frag(t, in)
	for _, s := range f.Services {
		if s.Name == "fw1.tcp.20001" && s.Forwarder.Nodes[0].Addr != "192.0.2.9:4444" {
			t.Errorf("port_map ignored: %v", s.Forwarder.Nodes)
		}
		if s.Name == "fw1.tcp.20002" && s.Forwarder.Nodes[0].Addr != "10.0.0.1:30002" {
			t.Errorf("other ports must keep the target range: %v", s.Forwarder.Nodes)
		}
	}
}

func TestSingleTargetPortFansIn(t *testing.T) {
	in := fwd()
	in.Targets = []spec.Target{{Host: "10.0.0.1", Ports: "9"}}
	f := frag(t, in)
	for _, s := range f.Services {
		if s.Forwarder.Nodes[0].Addr != "10.0.0.1:9" {
			t.Errorf("%s -> %s", s.Name, s.Forwarder.Nodes[0].Addr)
		}
	}
}

// The float64 trap: gost reads metadata with GetInt/GetBool/GetDuration which
// ignore JSON numbers. Every metadata value must be a string in the output.
func TestMetadataIsAlwaysStringTyped(t *testing.T) {
	d := New(Options{})
	for name, in := range goldenInstances() {
		a, err := d.Render(in)
		if err != nil {
			t.Fatal(err)
		}
		var raw map[string]any
		if err := json.Unmarshal(a.Files[fragmentFile], &raw); err != nil {
			t.Fatal(err)
		}
		var walk func(path string, v any)
		walk = func(path string, v any) {
			switch x := v.(type) {
			case map[string]any:
				for k, vv := range x {
					if k == "metadata" {
						m, ok := vv.(map[string]any)
						if !ok {
							t.Errorf("%s %s: metadata is not an object", name, path)
							continue
						}
						for mk, mv := range m {
							if _, ok := mv.(string); !ok {
								t.Errorf("%s %s.metadata.%s is %T, gost would ignore it", name, path, mk, mv)
							}
						}
						continue
					}
					walk(path+"."+k, vv)
				}
			case []any:
				for i, vv := range x {
					walk(path+"[]"+string(rune('0'+i%10)), vv)
				}
			}
		}
		walk("", raw)
	}
	// Concrete expectations.
	f := frag(t, goldenInstances()["forward_proxy"])
	s := f.Services[0]
	if s.Handler.Metadata["proxyProtocol"] != "1" {
		t.Errorf("send side must be the string \"1\": %v", s.Handler.Metadata)
	}
	if s.Metadata["proxyProtocol"] != "2" {
		t.Errorf("accept side must be the string \"2\": %v", s.Metadata)
	}
	raw := string(mustRender(t, goldenInstances()["forward_proxy"]))
	if strings.Contains(raw, `"proxyProtocol": 1`) || strings.Contains(raw, `"proxyProtocol": 2`) {
		t.Errorf("numeric proxyProtocol in output:\n%s", raw)
	}
}

func mustRender(t *testing.T, in spec.Instance) []byte {
	t.Helper()
	a, err := New(Options{}).Render(in)
	if err != nil {
		t.Fatal(err)
	}
	return a.Files[fragmentFile]
}

func TestUDPIdleTTLAndTCPIdle(t *testing.T) {
	in := fwd()
	in.Network = []string{"tcp", "udp"}
	in.IdleProfile = "tcp_long"
	f := frag(t, in)
	for _, s := range f.Services {
		switch s.Listener.Type {
		case "tcp":
			if s.Handler.Metadata["idleTimeout"] != "3600s" {
				t.Errorf("tcp idle: %v", s.Handler.Metadata)
			}
		case "udp":
			if s.Listener.Metadata["ttl"] != "60s" {
				t.Errorf("udp ttl must default to 60s (gost's 5s drops real flows): %v", s.Listener.Metadata)
			}
		}
	}
	in.IdleProfile = "udp_long"
	f = frag(t, in)
	for _, s := range f.Services {
		if s.Listener.Type == "udp" && s.Listener.Metadata["ttl"] != "120s" {
			t.Errorf("udp_long: %v", s.Listener.Metadata)
		}
	}
}

func TestBalanceMapping(t *testing.T) {
	in := goldenInstances()["forward_lb"]
	f := frag(t, in)
	sel := f.Services[0].Forwarder.Selector
	if sel == nil || sel.Strategy != "random" || sel.MaxFails != 3 || sel.FailTimeout != int64(30e9) {
		t.Errorf("selector %+v", sel)
	}
	if f.Services[0].Forwarder.Nodes[0].Metadata["weight"] != "3" {
		t.Errorf("weight not rendered: %+v", f.Services[0].Forwarder.Nodes)
	}
	for strat, want := range map[string]string{"round_robin": "round", "iphash": "hash", "failover": "fifo", "random": "random"} {
		x := fwd()
		x.Targets = []spec.Target{{Host: "10.0.0.1", Ports: "1"}, {Host: "10.0.0.2", Ports: "1"}}
		x.Balance = &spec.Balance{Strategy: strat}
		if got := frag(t, x).Services[0].Forwarder.Selector.Strategy; got != want {
			t.Errorf("%s -> %s, want %s", strat, got, want)
		}
	}
}

func TestTunnelRenderShapes(t *testing.T) {
	g := goldenInstances()
	// Entry: chain with relay connector and a verifying dialer.
	f := frag(t, g["tunnel_entry"])
	if len(f.Chains) != 1 {
		t.Fatalf("chains: %d", len(f.Chains))
	}
	n := f.Chains[0].Hops[0].Nodes[0]
	if n.Connector.Type != "relay" || n.Dialer.Type != "wss" || n.Addr != "exit.example.com:443" {
		t.Errorf("node %+v", n)
	}
	if n.Dialer.TLS == nil || n.Dialer.TLS.CAFile != "/etc/w1ncray/exit-ca.pem" || n.Dialer.TLS.ServerName != "exit.example.com" {
		t.Errorf("dialer tls %+v", n.Dialer.TLS)
	}
	if n.Dialer.Metadata["path"] != "/tun" || n.Dialer.Metadata["host"] != "cdn.example.com" {
		t.Errorf("dialer md %v", n.Dialer.Metadata)
	}
	for _, s := range f.Services {
		if s.Handler.Chain != "en.chain" {
			t.Errorf("service %s not using the chain", s.Name)
		}
		if s.Forwarder.Nodes[0].Addr != dummyTarget {
			t.Errorf("entry without targets must use the dummy target, got %s", s.Forwarder.Nodes[0].Addr)
		}
	}
	// Without a CA file the dialer verifies against system roots.
	e := g["tunnel_entry"]
	e.Tunnel = &spec.Tunnel{Type: "tls", Server: "x.example.com:443", Security: "tls"}
	if tc := frag(t, e).Chains[0].Hops[0].Nodes[0].Dialer.TLS; tc == nil || !tc.Secure || tc.CAFile != "" {
		t.Errorf("default must be full verification: %+v", tc)
	}
	// Exit: relay handler in forward mode, no bind.
	x := frag(t, g["tunnel_exit"])
	s := x.Services[0]
	if s.Handler.Type != "relay" || s.Handler.Auth == nil || s.Handler.Auth.Username != relayUser(testSecret) || s.Forwarder == nil || len(s.Forwarder.Nodes) != 1 {
		t.Errorf("exit %+v", s)
	}
	if s.Handler.Metadata["bind"] != "" {
		t.Error("an exit must not enable bind")
	}
	if s.Listener.TLS == nil || s.Listener.TLS.KeyFile != "/etc/w1ncray/k.pem" {
		t.Errorf("exit tls %+v", s.Listener.TLS)
	}
	// Portal: bind enabled, no forwarder.
	p := frag(t, g["reverse_portal"]).Services[0]
	if p.Handler.Metadata["bind"] != "true" || p.Forwarder != nil {
		t.Errorf("portal %+v", p)
	}
	// Bridge: rtcp/rudp listeners carrying the chain, bind address on the portal.
	b := frag(t, g["reverse_bridge"])
	if len(b.Services) != 2 {
		t.Fatalf("bridge services %d", len(b.Services))
	}
	for _, s := range b.Services {
		if (s.Listener.Type != "rtcp" && s.Listener.Type != "rudp") || s.Listener.Chain != "br.chain" || s.Addr != "0.0.0.0:2222" {
			t.Errorf("bridge service %+v", s)
		}
	}
}

func TestACLAndLimitsMapping(t *testing.T) {
	f := frag(t, goldenInstances()["forward_lb"])
	if len(f.Admissions) != 2 || !f.Admissions[0].Whitelist || f.Admissions[1].Whitelist {
		t.Fatalf("admissions %+v", f.Admissions)
	}
	if f.Admissions[0].Matchers[0] != "10.0.0.0/8" || f.Admissions[1].Matchers[0] != "10.1.2.3" {
		t.Errorf("matchers %+v", f.Admissions)
	}
	s := f.Services[0]
	if len(s.Admissions) != 2 || s.Limiter != "lb.limit" || s.CLimiter != "lb.climit" {
		t.Errorf("service refs %+v", s)
	}
	// rate_up 8 Mbit/s = 1,000,000 B/s, rate_down 16 Mbit/s = 2,000,000 B/s.
	if f.Limiters[0].Limits[0] != "$ 1000000B 2000000B" || f.CLimiters[0].Limits[0] != "$ 50" {
		t.Errorf("limits %+v %+v", f.Limiters, f.CLimiters)
	}
}

func TestPromParser(t *testing.T) {
	in := `# HELP x
# TYPE gost_service_transfer_input_bytes_total counter
gost_service_transfer_input_bytes_total{client="127.0.0.1",host="h\"x",service="fw.tcp.1"} 3.003e+04
gost_service_requests_total{client="10.0.0.1",host="h",service="fw.tcp.1"} 3 1700000000000
go_goroutines 7
`
	s, err := parseProm([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 3 || s[0].value != 30030 || s[0].labels["host"] != `h"x` || s[0].labels["service"] != "fw.tcp.1" || s[1].value != 3 || s[2].name != "go_goroutines" {
		t.Fatalf("%+v", s)
	}
	for _, bad := range []string{`x{a="b} 1`, `x{a=b} 1`, `x 1 2 3`, `x{a="b"} nope`, `{a="b"} 1`} {
		if _, err := parseProm([]byte(bad)); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}
