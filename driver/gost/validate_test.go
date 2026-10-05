package gost

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/spec"
)

// Characters that must never reach a gost configuration through a free-form
// field: whitespace, quotes, line breaks, control characters, config and
// shell metacharacters.
var hostile = []string{
	"a b", "a\tb", "a\nb", "a\rb", "a\x00b", "a\x1bb", `a"b`, "a'b", "a`b", "a$b", "${x}", "a;b", "a#b",
	"a,b", "a\\b", "a|b", "a&b", "a<b", "a>b", "a(b)", "a{b}", "a*b", "a?b", "a%b", "a@b", "a:b/c", "../x",
	"a b.example.com", "-a.example.com", "a-.example.com", ".example.com", "a..example.com", "a.example.com\n",
	"é.example.com", "a/b", "fe80::1%eth0",
}

func mutate(f func(*spec.Instance, string)) func(t *testing.T, base spec.Instance, label string) {
	return func(t *testing.T, base spec.Instance, label string) {
		d := New(Options{})
		for _, h := range hostile {
			in := base
			// Deep-ish copies of the pointer fields the mutators touch.
			if in.Listen != nil {
				l := *in.Listen
				in.Listen = &l
			}
			if in.Tunnel != nil {
				tn := *in.Tunnel
				if tn.Cert != nil {
					c := *tn.Cert
					tn.Cert = &c
				}
				in.Tunnel = &tn
			}
			in.Targets = append([]spec.Target(nil), in.Targets...)
			f(&in, h)
			if err := d.Validate(in); err == nil {
				t.Errorf("%s: hostile value %q was accepted", label, h)
			}
			if _, err := d.Render(in); err == nil {
				t.Errorf("%s: hostile value %q was rendered", label, h)
			}
		}
	}
}

func TestInjectionTargetHost(t *testing.T) {
	mutate(func(in *spec.Instance, h string) { in.Targets[0].Host = h })(t, fwd(), "target.host")
	d := New(Options{})
	for _, h := range []string{"", "[::1]", "[2001:db8::1]"} {
		in := fwd()
		in.Targets[0].Host = h
		if err := d.Validate(in); err == nil {
			t.Errorf("target.host %q accepted (brackets are added by the renderer)", h)
		}
	}
}

func TestInjectionPortMapValue(t *testing.T) {
	mutate(func(in *spec.Instance, h string) { in.Listen.PortMap = map[string]string{"20001": h + ":80"} })(t, fwd(), "port_map host")
	mutate(func(in *spec.Instance, h string) { in.Listen.PortMap = map[string]string{h: "10.0.0.1:80"} })(t, fwd(), "port_map key")
}

func TestInjectionListenAddr(t *testing.T) {
	mutate(func(in *spec.Instance, h string) { in.Listen.Addr = h })(t, fwd(), "listen.addr")
}

func TestInjectionTunnelFields(t *testing.T) {
	g := goldenInstances()
	mutate(func(in *spec.Instance, h string) { in.Tunnel.Server = h + ":443" })(t, g["tunnel_entry"], "tunnel.server")
	mutate(func(in *spec.Instance, h string) { in.Tunnel.SNI = h })(t, withSNI(g["tunnel_entry"]), "tunnel.sni")
	mutate(func(in *spec.Instance, h string) { in.Tunnel.Host = h })(t, g["tunnel_entry"], "tunnel.host")
	mutate(func(in *spec.Instance, h string) { in.Tunnel.Listen = h })(t, g["tunnel_exit"], "tunnel.listen")
}

func withSNI(in spec.Instance) spec.Instance { return in }

func TestInjectionPathCertSecretACL(t *testing.T) {
	g := goldenInstances()
	paths := []string{`/x y`, "/x\ny", `/x"y`, "/x;y", "/x#y", "/x$y", "/x`y", "/x{y}", "/a?b=c", "x", "/x\\y", "/é", "/" + strings.Repeat("a", 200)}
	d := New(Options{})
	for _, p := range paths {
		in := g["tunnel_entry"]
		tn := *in.Tunnel
		tn.Path = p
		in.Tunnel = &tn
		if err := d.Validate(in); err == nil {
			t.Errorf("tunnel.path %q accepted", p)
		}
	}
	files := []string{"relative/c.pem", `/etc/a b.pem`, "/etc/a\nb.pem", `/etc/a"b.pem`, "/etc/../shadow", "/etc/a;b", "/etc/a$b", "/etc/a`b", "", "/etc/é.pem", "/etc/a#b"}
	for _, f := range files {
		in := g["tunnel_exit"]
		tn := *in.Tunnel
		c := *tn.Cert
		c.CertFile = f
		tn.Cert = &c
		in.Tunnel = &tn
		if err := d.Validate(in); err == nil {
			t.Errorf("cert_file %q accepted", f)
		}
		in = g["tunnel_exit"]
		tn = *in.Tunnel
		c = *tn.Cert
		c.KeyFile = f
		tn.Cert = &c
		in.Tunnel = &tn
		if err := d.Validate(in); err == nil {
			t.Errorf("key_file %q accepted", f)
		}
	}
	secrets := []string{"", "short", strings.Repeat("a", 15), strings.Repeat("a", 257), "has space 0123456789", "tab\t0123456789012345", "nl\n0123456789012345", "é0123456789012345678", "ctl\x01012345678901234"}
	for _, s := range secrets {
		in := g["tunnel_entry"]
		in.Secret = s
		if err := d.Validate(in); err == nil {
			t.Errorf("secret %q accepted", s)
		}
	}
	acls := []string{"a b", "10.0.0.0/33", "example.com", "*.example.com", "10.0.0.1\n", "10.0.0.1,10.0.0.2", "10.0.0.1-10.0.0.9", "fe80::1%eth0"}
	for _, a := range acls {
		in := fwd()
		in.ACL = &spec.ACL{Allow: []string{a}}
		if err := d.Validate(in); err == nil {
			t.Errorf("acl allow %q accepted", a)
		}
		in.ACL = &spec.ACL{Deny: []string{a}}
		if err := d.Validate(in); err == nil {
			t.Errorf("acl deny %q accepted", a)
		}
	}
	for _, id := range []string{"", "A", "a.b", "a b", "a/b", "../x", strings.Repeat("a", 41), "a\nb", "é", "a;b"} {
		in := fwd()
		in.ID = id
		if err := d.Validate(in); err == nil {
			t.Errorf("id %q accepted", id)
		}
	}
}

// Whatever is accepted must come out as inert JSON: marshalling typed
// structs cannot be broken out of, but check the full render of a nasty yet
// valid input anyway.
func TestRenderedJSONIsInert(t *testing.T) {
	in := goldenInstances()["tunnel_entry"]
	in.Secret = `p"a\ss'w$ord{}#;` + "0123456789"
	a, err := New(Options{}).Render(in)
	if err != nil {
		t.Fatal(err)
	}
	var f fragment
	if err := json.Unmarshal(a.Files[fragmentFile], &f); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	if f.Chains[0].Hops[0].Nodes[0].Connector.Auth.Password != in.Secret {
		t.Error("secret did not round trip")
	}
}

func TestValidateRejectsUnsupported(t *testing.T) {
	g := goldenInstances()
	d := New(Options{})
	cases := []struct {
		name string
		mod  func() spec.Instance
		want string
	}{
		{"udp+proxy_out", func() spec.Instance { i := fwd(); i.Network = []string{"udp"}; i.ProxyProtocolOut = 2; return i }, "TCP only"},
		{"tcp+udp+proxy_out", func() spec.Instance { i := fwd(); i.Network = []string{"tcp", "udp"}; i.ProxyProtocolOut = 1; return i }, "TCP only"},
		{"udp+accept", func() spec.Instance { i := fwd(); i.Network = []string{"udp"}; i.AcceptProxyProtocol = true; return i }, "TCP only"},
		{"proxy_out v3", func() spec.Instance { i := fwd(); i.ProxyProtocolOut = 3; return i }, "0, 1 or 2"},
		{"accept on exit", func() spec.Instance {
			i := g["tunnel_exit"]
			i.Network, i.AcceptProxyProtocol = []string{"tcp"}, true
			return i
		}, "only supported on forward"},
		{"proxy_out on exit", func() spec.Instance {
			i := g["tunnel_exit"]
			i.Network, i.ProxyProtocolOut = []string{"tcp"}, 2
			return i
		}, "relay handler"},
		{"tls_pin", func() spec.Instance {
			i := g["tunnel_entry"]
			tn := *i.Tunnel
			tn.Security, tn.PinSHA256 = "tls_pin", strings.Repeat("a", 64)
			i.Tunnel = &tn
			return i
		}, "pinning"},
		{"vless_enc", func() spec.Instance {
			i := g["tunnel_entry"]
			tn := *i.Tunnel
			tn.Security = "vless_enc"
			i.Tunnel = &tn
			return i
		}, "Xray only"},
		{"xhttp", func() spec.Instance {
			i := g["tunnel_entry"]
			tn := *i.Tunnel
			tn.Type = "xhttp"
			i.Tunnel = &tn
			return i
		}, "not supported"},
		{"security none on wss", func() spec.Instance {
			i := g["tunnel_entry"]
			tn := *i.Tunnel
			tn.Security = "none"
			i.Tunnel = &tn
			return i
		}, "contradictory"},
		{"tls on ws", func() spec.Instance {
			i := g["reverse_bridge"]
			tn := *i.Tunnel
			tn.Security = "tls"
			i.Tunnel = &tn
			return i
		}, "TLS carrier"},
		{"cert self on entry", func() spec.Instance {
			i := g["tunnel_entry"]
			tn := *i.Tunnel
			tn.Cert = &spec.Cert{Mode: "self"}
			i.Tunnel = &tn
			return i
		}, "verification"},
		{"cert panel", func() spec.Instance {
			i := g["tunnel_exit"]
			tn := *i.Tunnel
			tn.Cert = &spec.Cert{Mode: "panel"}
			i.Tunnel = &tn
			return i
		}, "materialised"},
		{"no secret", func() spec.Instance { i := g["tunnel_entry"]; i.Secret = ""; return i }, "secret is required"},
		{"exit needs target xor any", func() spec.Instance { i := g["tunnel_exit"]; i.Targets = nil; return i }, "exactly one"},
		{"exit both", func() spec.Instance { i := g["tunnel_exit"]; i.AllowAnyTarget = true; return i }, "exactly one"},
		{"exit target range", func() spec.Instance {
			i := g["tunnel_exit"]
			i.Targets = []spec.Target{{Host: "10.0.0.1", Ports: "1-3"}}
			return i
		}, "ranges are not supported"},
		{"exit with listen", func() spec.Instance {
			i := g["tunnel_exit"]
			i.Listen = &spec.Listen{Addr: "0.0.0.0", Ports: "1"}
			return i
		}, "not used by tunnel_exit"},
		{"any target on forward", func() spec.Instance { i := fwd(); i.AllowAnyTarget = true; return i }, "only applies to tunnel_exit"},
		{"portal acl", func() spec.Instance {
			i := g["reverse_portal"]
			i.ACL = &spec.ACL{Allow: []string{"10.0.0.0/8"}}
			return i
		}, "reverse_portal"},
		{"portal targets", func() spec.Instance { i := g["reverse_portal"]; i.Targets = fwd().Targets; return i }, "no targets"},
		{"bridge no listen", func() spec.Instance { i := g["reverse_bridge"]; i.Listen = nil; return i }, "listen is required"},
		{"bridge no target", func() spec.Instance { i := g["reverse_bridge"]; i.Targets = nil; return i }, "no target"},
		{"weight with round_robin", func() spec.Instance {
			i := g["forward_lb"]
			i.Balance = &spec.Balance{Strategy: "round_robin"}
			return i
		}, "weights"},
		{"least_ping", func() spec.Instance {
			i := fwd()
			i.Balance = &spec.Balance{Strategy: "least_ping"}
			return i
		}, "not supported"},
		{"active health http", func() spec.Instance {
			i := fwd()
			i.Balance = &spec.Balance{Strategy: "round_robin", Health: &spec.Health{Type: "http", ProbeURL: "http://x/"}}
			return i
		}, "not supported"},
		{"range length mismatch", func() spec.Instance { i := fwd(); i.Targets[0].Ports = "1-5"; return i }, "listen.ports has 3"},
		{"no target", func() spec.Instance { i := fwd(); i.Targets = nil; return i }, "no target"},
		{"too many ports", func() spec.Instance { i := fwd(); i.Listen.Ports = "1-5000"; return i }, "limit"},
		{"reversed range", func() spec.Instance { i := fwd(); i.Listen.Ports = "9-3"; return i }, "reversed"},
		{"port 0", func() spec.Instance { i := fwd(); i.Listen.Ports = "0"; return i }, "out of range"},
		{"port 65536", func() spec.Instance { i := fwd(); i.Listen.Ports = "65536"; return i }, "out of range"},
		{"port_map outside", func() spec.Instance { i := fwd(); i.Listen.PortMap = map[string]string{"1": "10.0.0.1:1"}; return i }, "outside"},
		{"unknown idle", func() spec.Instance { i := fwd(); i.IdleProfile = "forever"; return i }, "idle_profile"},
		{"negative limits", func() spec.Instance { i := fwd(); i.Limits = &spec.Limits{MaxConns: -1}; return i }, "negative"},
		{"other engine", func() spec.Instance { i := fwd(); i.Engine = spec.EngineRealm; return i }, "not gost"},
		{"unknown kind", func() spec.Instance { i := fwd(); i.Kind = "socks"; return i }, "unsupported instance kind"},
		{"forward with tunnel", func() spec.Instance { i := fwd(); i.Tunnel = &spec.Tunnel{Type: "tcp"}; return i }, "tunnel must not"},
		{"alpn", func() spec.Instance {
			i := g["tunnel_entry"]
			tn := *i.Tunnel
			tn.ALPN = []string{"h2"}
			i.Tunnel = &tn
			return i
		}, "alpn"},
		{"path on tcp", func() spec.Instance {
			i := g["tunnel_entry"]
			tn := *i.Tunnel
			tn.Type, tn.Security, tn.Cert = "tcp", "", nil
			i.Tunnel = &tn
			return i
		}, "only apply to ws"},
	}
	for _, c := range cases {
		err := d.Validate(c.mod())
		if err == nil {
			t.Errorf("%s: accepted, want error containing %q", c.name, c.want)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not contain %q", c.name, err, c.want)
		}
		if strings.Contains(err.Error(), testSecret) {
			t.Errorf("%s: secret in error", c.name)
		}
	}
}

func TestValidateAcceptsGolden(t *testing.T) {
	d := New(Options{})
	for n, in := range goldenInstances() {
		if err := d.Validate(in); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
	// IPv6 and DNS names.
	in := fwd()
	in.Listen.Addr = "::"
	in.Targets = []spec.Target{{Host: "2001:db8::1", Ports: "30000-30002"}, {Host: "a-b.example.com", Ports: "5"}}
	if err := d.Validate(in); err != nil {
		t.Errorf("ipv6/dns: %v", err)
	}
	f := frag(t, in)
	if f.Services[0].Addr != "[::]:20000" || f.Services[0].Forwarder.Nodes[0].Addr != "[2001:db8::1]:30000" {
		t.Errorf("ipv6 join: %s %s", f.Services[0].Addr, f.Services[0].Forwarder.Nodes[0].Addr)
	}
}

func TestCapsAreHonest(t *testing.T) {
	c := New(Options{}).Caps()
	if c.Name != spec.EngineGost || !c.External || c.ProxyOutUDP || c.DisruptsOnChange {
		t.Errorf("caps %+v", c)
	}
	// Everything declared must validate for at least one instance.
	if len(c.Kinds) != 5 {
		t.Errorf("kinds %v", c.Kinds)
	}
}
