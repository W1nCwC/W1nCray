package frp

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"text/template"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/W1nCwC/W1nCray/agent/spec"
)

var update = flag.Bool("update", false, "rewrite golden files")

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
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
	if !bytes.Equal(bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n")), got) {
		t.Fatalf("%s differs from golden:\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func TestRenderGolden(t *testing.T) {
	cases := []struct {
		name string
		in   func() spec.Instance
		file string
	}{
		{"portal range tcp+udp tls cert", portalInst, "portal_range_tls.toml"},
		{"portal single kcp none", func() spec.Instance {
			in := portalInst()
			in.Network = []string{"tcp"}
			in.Listen.Ports = "8443"
			in.Tunnel = &spec.Tunnel{Type: "kcp", Listen: "[::]:7001", Security: "none"}
			return in
		}, "portal_single_kcp_none.toml"},
		{"portal quic self cert", func() spec.Instance {
			in := portalInst()
			in.Tunnel = &spec.Tunnel{Type: "quic", Listen: "10.0.0.1:7002", Security: "tls"}
			in.Network = []string{"udp"}
			in.Listen.Ports = "5353"
			return in
		}, "portal_quic_self.toml"},
		{"bridge range tcp+udp tls trust anchor", bridgeInst, "bridge_range_tls.toml"},
		{"bridge portmap proxy v2 http health", func() spec.Instance {
			in := bridgeInst()
			in.Network = []string{"tcp"}
			in.Listen = &spec.Listen{Ports: "20000-20002", PortMap: map[string]string{"20001": "192.168.1.9:3389"}}
			in.Targets = []spec.Target{{Host: "127.0.0.1", Ports: "9000-9002"}}
			in.ProxyProtocolOut = 2
			in.Balance = &spec.Balance{Strategy: "failover", Health: &spec.Health{Type: "http", IntervalS: 5, TimeoutS: 2, MaxFails: 3, ProbeURL: "/healthz"}}
			in.Tunnel = &spec.Tunnel{Type: "ws", Server: "203.0.113.5:7000", Security: "none"}
			return in
		}, "bridge_portmap_v2_health_ws.toml"},
		{"bridge single udp", func() spec.Instance {
			in := bridgeInst()
			in.Network = []string{"udp"}
			in.Listen = &spec.Listen{Ports: "5353"}
			in.Targets = []spec.Target{{Host: "dns.internal", Ports: "53"}}
			in.Tunnel = &spec.Tunnel{Type: "quic", Server: "[2001:db8::1]:7002"}
			return in
		}, "bridge_single_udp_quic.toml"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			art, err := New().Render(c.in())
			if err != nil {
				t.Fatal(err)
			}
			if len(art.Files) != 1 {
				t.Fatalf("want 1 file, got %d", len(art.Files))
			}
			for _, b := range art.Files {
				golden(t, c.file, b)
			}
		})
	}
}

func TestRenderDeterministic(t *testing.T) {
	for _, in := range []spec.Instance{portalInst(), bridgeInst()} {
		a, err := New().Render(in)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 20; i++ {
			b, _ := New().Render(in)
			if a.Hash != b.Hash || !reflect.DeepEqual(a.Files, b.Files) || !reflect.DeepEqual(a.PortClaims, b.PortClaims) {
				t.Fatal("Render is not deterministic")
			}
		}
	}
	// A different instance gives a different hash.
	a, _ := New().Render(portalInst())
	in := portalInst()
	in.Listen.Ports = "20000-20010"
	b, _ := New().Render(in)
	if a.Hash == b.Hash {
		t.Fatal("hash does not depend on the config")
	}
}

func TestPortalAllowPortsAndLimits(t *testing.T) {
	in := portalInst()
	u := mustCompile(t, in)
	var doc map[string]any
	if err := toml.Unmarshal(u.Files[fileFrps], &doc); err != nil {
		t.Fatal(err)
	}
	ap := doc["allowPorts"].([]any)
	if len(ap) != 1 {
		t.Fatalf("allowPorts: %v", ap)
	}
	r := ap[0].(map[string]any)
	if r["start"] != int64(20000) || r["end"] != int64(20009) || len(r) != 2 {
		t.Fatalf("allowPorts must cover exactly the public range, got %v", r)
	}
	if doc["maxPortsPerClient"] != int64(20) { // 10 ports x tcp+udp
		t.Fatalf("maxPortsPerClient = %v", doc["maxPortsPerClient"])
	}
	// Features that must stay off.
	for _, k := range []string{"vhostHTTPPort", "vhostHTTPSPort", "tcpmuxHTTPConnectPort", "webServer", "sshTunnelGateway", "httpPlugins", "enablePrometheus", "subDomainHost", "custom404Page"} {
		if _, ok := doc[k]; ok {
			t.Fatalf("frps config must not set %s", k)
		}
	}

	in.Listen.Ports = "8443"
	in.Network = []string{"tcp"}
	u = mustCompile(t, in)
	_ = toml.Unmarshal(u.Files[fileFrps], &doc)
	r = doc["allowPorts"].([]any)[0].(map[string]any)
	if r["single"] != int64(8443) || len(r) != 1 {
		t.Fatalf("single port allowPorts = %v", r)
	}
}

func TestPortClaims(t *testing.T) {
	u := mustCompile(t, portalInst())
	want := 1 + 10*2 // control + public tcp+udp
	if len(u.Claims) != want {
		t.Fatalf("claims = %d, want %d", len(u.Claims), want)
	}
	if u.Claims[0].Proto != "tcp" || u.Claims[0].Port != 7000 || u.Claims[0].Owner != "web" {
		t.Fatalf("control claim = %+v", u.Claims[0])
	}
	in := portalInst()
	in.Tunnel = &spec.Tunnel{Type: "kcp", Listen: "0.0.0.0:7000", Security: "none"}
	u = mustCompile(t, in)
	var kcp bool
	for _, c := range u.Claims {
		if c.Proto == "udp" && c.Port == 7000 {
			kcp = true
		}
	}
	if !kcp {
		t.Fatal("kcp portal must claim the control port over udp")
	}
	if len(mustCompile(t, bridgeInst()).Claims) != 0 {
		t.Fatal("a bridge binds no listening port")
	}
}

func TestBridgeProxyExpansion(t *testing.T) {
	in := bridgeInst()
	in.Listen = &spec.Listen{Ports: "20000-20002", PortMap: map[string]string{"20001": "10.1.1.1:3389"}}
	in.Targets = []spec.Target{{Host: "127.0.0.1", Ports: "8000-8002"}}
	in.ProxyProtocolOut = 0
	in.Network = []string{"tcp", "udp"}
	u := mustCompile(t, in)
	var doc struct {
		Proxies []map[string]any
	}
	if err := toml.Unmarshal(u.Files[fileFrpc], &doc); err != nil {
		t.Fatal(err)
	}
	type px struct {
		name, typ, ip string
		lp, rp        int64
	}
	var got []px
	for _, p := range doc.Proxies {
		got = append(got, px{p["name"].(string), p["type"].(string), p["localIP"].(string), p["localPort"].(int64), p["remotePort"].(int64)})
	}
	want := []px{
		{"web.t20000", "tcp", "127.0.0.1", 8000, 20000},
		{"web.t20001", "tcp", "10.1.1.1", 3389, 20001},
		{"web.t20002", "tcp", "127.0.0.1", 8002, 20002},
		{"web.u20000", "udp", "127.0.0.1", 8000, 20000},
		{"web.u20001", "udp", "10.1.1.1", 3389, 20001},
		{"web.u20002", "udp", "127.0.0.1", 8002, 20002},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("proxies:\n got %v\nwant %v", got, want)
	}
}

// TestNoTemplateEvaluation proves that frp's pre-parse text/template step
// leaves every rendered file untouched: with the same function set frp uses
// and an environment containing a canary, execution returns the input
// byte-for-byte. (The e2e suite additionally shows with the real binaries that
// frp does evaluate templates, i.e. that this guarantee is needed.)
func TestNoTemplateEvaluation(t *testing.T) {
	t.Setenv("W1NC_CANARY", "EVALUATED")
	files := [][]byte{}
	for _, in := range []spec.Instance{portalInst(), bridgeInst()} {
		u := mustCompile(t, in)
		for _, b := range u.Files {
			files = append(files, b)
			files = append(files, append(append([]byte(nil), b...), adminSection(adminInfo{Port: 1234, User: "w1nc-abcd", Pass: "00ff"})...))
		}
	}
	for _, b := range files {
		tmpl, err := template.New("frp").Funcs(template.FuncMap{
			"parseNumberRange":     func(string) ([]int64, error) { return nil, nil },
			"parseNumberRangePair": func(a, b string) ([]int64, error) { return nil, nil },
		}).Parse(string(b))
		if err != nil {
			t.Fatalf("template parse: %v", err)
		}
		var out bytes.Buffer
		if err := tmpl.Execute(&out, map[string]any{"Envs": map[string]string{"W1NC_CANARY": "EVALUATED"}}); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out.Bytes(), b) {
			t.Fatalf("template step changed the config:\n%s", out.String())
		}
		if bytes.Contains(b, []byte("{{")) || bytes.Contains(b, []byte("EVALUATED")) {
			t.Fatal("config contains template syntax")
		}
	}
	// Positive control: a value with template syntax WOULD be rewritten.
	tmpl, _ := template.New("x").Parse(`token = "{{ .Envs.W1NC_CANARY }}"`)
	var out bytes.Buffer
	_ = tmpl.Execute(&out, map[string]any{"Envs": map[string]string{"W1NC_CANARY": "EVALUATED"}})
	if !strings.Contains(out.String(), "EVALUATED") {
		t.Fatal("positive control failed")
	}
}

func TestSecretNeverInErrorsOrArgs(t *testing.T) {
	in := portalInst()
	in.Secret = "short"
	mustRejectWith(t, in, "secret must be")
	in = portalInst()
	in.Secret = "{{ .Envs.HOME }}-0123456789"
	mustRejectWith(t, in, "secret must be")
}

func TestCapsAreConsistent(t *testing.T) {
	c := New().Caps()
	if c.Name != "frp" || !c.Reverse || c.ProxyIn || !c.ProxyOut || c.ProxyOutUDP || c.DisruptsOnChange {
		t.Fatalf("unexpected caps %+v", c)
	}
	if len(c.Kinds) != 2 || c.Kinds[0] != spec.KindReversePortal || c.Kinds[1] != spec.KindReverseBridge {
		t.Fatalf("kinds %v", c.Kinds)
	}
	// Every declared tunnel type must be accepted by Validate for a portal,
	// every other spec type must be refused.
	for _, typ := range []string{"tcp", "tls", "ws", "wss", "grpc", "xhttp", "kcp", "quic"} {
		in := portalInst()
		in.Tunnel = &spec.Tunnel{Type: typ, Listen: "0.0.0.0:7000", Security: "tls"}
		err := New().Validate(in)
		declared := false
		for _, d := range c.TunnelTypes {
			declared = declared || d == typ
		}
		if declared && err != nil {
			t.Fatalf("declared type %s rejected: %v", typ, err)
		}
		if !declared && err == nil {
			t.Fatalf("undeclared type %s accepted", typ)
		}
	}
}

// TestCapsBalanceMatchesValidate keeps Caps.Balance/HealthCheck honest: the
// agent decides "greyed out" features from Caps alone, so a strategy is
// declared exactly when a bridge accepts it, and the declared active health
// check is the frpc healthCheck the e2e suite exercises.
func TestCapsBalanceMatchesValidate(t *testing.T) {
	c := New().Caps()
	if c.HealthCheck != "active" {
		t.Fatalf("HealthCheck = %q", c.HealthCheck)
	}
	for _, s := range []string{"round_robin", "random", "iphash", "failover", "least_ping"} {
		in := bridgeInst()
		in.Network = []string{"tcp"}
		in.Balance = &spec.Balance{Strategy: s}
		declared := false
		for _, d := range c.Balance {
			declared = declared || d == s
		}
		err := New().Validate(in)
		if declared && err != nil {
			t.Fatalf("declared strategy %s rejected: %v", s, err)
		}
		if !declared && err == nil {
			t.Fatalf("undeclared strategy %s accepted", s)
		}
	}
	if len(c.Balance) != 1 || c.Balance[0] != "failover" {
		t.Fatalf("Balance = %v, want [failover]", c.Balance)
	}
	// failover + active health check, the combination the e2e test runs.
	in := bridgeInst()
	in.Network = []string{"tcp"}
	in.Balance = &spec.Balance{Strategy: "failover", Health: &spec.Health{Type: "tcp", IntervalS: 1, TimeoutS: 1, MaxFails: 1}}
	if err := New().Validate(in); err != nil {
		t.Fatalf("failover + health rejected: %v", err)
	}
}

func TestBinaries(t *testing.T) {
	frps, frpc, err := Binaries(filepath.Join("opt", "frp", "0.71.0", "frps"))
	if err != nil || filepath.Base(frps) != "frps" || filepath.Base(frpc) != "frpc" || filepath.Dir(frps) != filepath.Dir(frpc) {
		t.Fatalf("%v %v %v", frps, frpc, err)
	}
	frps, frpc, err = Binaries(filepath.Join("opt", "frps.exe"))
	if err != nil || filepath.Base(frpc) != "frpc.exe" {
		t.Fatalf("%v %v %v", frps, frpc, err)
	}
	if _, _, err := Binaries(filepath.Join("opt", "frpc")); err == nil {
		t.Fatal("frpc must not be accepted as the kernel path")
	}
	if _, _, err := Binaries(""); err == nil {
		t.Fatal("empty path accepted")
	}
}
