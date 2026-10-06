package realm

import (
	"encoding/json"
	"math/rand"
	"strings"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/spec"
)

func mut(in spec.Instance, f func(*spec.Instance)) spec.Instance {
	// Deep enough copy for the fields the tests change.
	c := in
	if in.Listen != nil {
		l := *in.Listen
		c.Listen = &l
	}
	if in.Tunnel != nil {
		t := *in.Tunnel
		c.Tunnel = &t
	}
	c.Targets = append([]spec.Target(nil), in.Targets...)
	if in.Balance != nil {
		b := *in.Balance
		c.Balance = &b
	}
	f(&c)
	return c
}

func baseFwd() spec.Instance { return fwd("web", "127.0.0.1", "8080", tg("10.0.0.5", "80", 0)) }

func baseExit() spec.Instance {
	return exit("x", spec.Tunnel{Type: "wss", Listen: "0.0.0.0:443", Host: "e.example.com", Path: "/p",
		Cert: &spec.Cert{Mode: "file", CertFile: "/etc/c.crt", KeyFile: "/etc/c.key"}}, tg("10.0.0.5", "22", 0))
}

func baseEntry() spec.Instance {
	return entry("e", spec.Tunnel{Type: "wss", Server: "exit.example.com:443", Host: "e.example.com", Path: "/p", SNI: "exit.example.com"})
}

func TestValidateRejects(t *testing.T) {
	d := New(Options{})
	three := []spec.Target{tg("10.0.0.1", "80", 1), tg("10.0.0.2", "80", 1), tg("10.0.0.3", "80", 1)}
	rr := &spec.Balance{Strategy: "round_robin"}
	cases := []struct {
		name string
		in   spec.Instance
		want string // substring of the error
	}{
		// engine / kinds the realm driver does not have
		{"reverse portal", mut(baseFwd(), func(i *spec.Instance) { i.Kind = spec.KindReversePortal }), "reverse"},
		{"reverse bridge", mut(baseFwd(), func(i *spec.Instance) { i.Kind = spec.KindReverseBridge }), "reverse"},
		{"reverse block", mut(baseFwd(), func(i *spec.Instance) { i.Reverse = &spec.Reverse{Link: "x"} }), "reverse"},
		{"unknown kind", mut(baseFwd(), func(i *spec.Instance) { i.Kind = "mesh" }), "kind"},
		{"foreign engine", mut(baseFwd(), func(i *spec.Instance) { i.Engine = spec.EngineGost }), "engine"},
		// ids
		{"empty id", mut(baseFwd(), func(i *spec.Instance) { i.ID = "" }), "id"},
		{"upper id", mut(baseFwd(), func(i *spec.Instance) { i.ID = "Web" }), "id"},
		{"path id", mut(baseFwd(), func(i *spec.Instance) { i.ID = "../x" }), "id"},
		{"long id", mut(baseFwd(), func(i *spec.Instance) { i.ID = strings.Repeat("a", 41) }), "id"},
		// features realm lacks
		{"acl", mut(baseFwd(), func(i *spec.Instance) { i.ACL = &spec.ACL{Deny: []string{"1.2.3.4"}} }), "access control"},
		{"limits conns", mut(baseFwd(), func(i *spec.Instance) { i.Limits = &spec.Limits{MaxConns: 10} }), "limit"},
		{"limits rate", mut(baseFwd(), func(i *spec.Instance) { i.Limits = &spec.Limits{RateUpBps: 1} }), "limit"},
		{"allow any target", mut(baseExit(), func(i *spec.Instance) { i.AllowAnyTarget = true }), "allow_any_target"},
		{"health check", mut(baseFwd(), func(i *spec.Instance) {
			i.Targets = three
			i.Balance = &spec.Balance{Strategy: "round_robin", Health: &spec.Health{Type: "tcp"}}
		}), "health"},
		{"health check single target", mut(baseFwd(), func(i *spec.Instance) {
			i.Balance = &spec.Balance{Strategy: "round_robin", Health: &spec.Health{Type: "tcp"}}
		}), "health"},
		{"random strategy", mut(baseFwd(), func(i *spec.Instance) { i.Targets = three; i.Balance = &spec.Balance{Strategy: "random"} }), "round_robin and iphash"},
		{"failover strategy", mut(baseFwd(), func(i *spec.Instance) { i.Targets = three; i.Balance = &spec.Balance{Strategy: "failover"} }), "round_robin and iphash"},
		{"least_ping strategy", mut(baseFwd(), func(i *spec.Instance) { i.Targets = three; i.Balance = &spec.Balance{Strategy: "least_ping"} }), "round_robin and iphash"},
		{"unknown strategy", mut(baseFwd(), func(i *spec.Instance) { i.Targets = three; i.Balance = &spec.Balance{Strategy: "x"} }), "unknown strategy"},
		{"unsupported strategy even for one target", mut(baseFwd(), func(i *spec.Instance) { i.Balance = &spec.Balance{Strategy: "failover"} }), "round_robin and iphash"},
		{"multi targets need a balance", mut(baseFwd(), func(i *spec.Instance) { i.Targets = three }), "balance"},
		{"iphash with accept proxy", mut(baseFwd(), func(i *spec.Instance) {
			i.Targets = three
			i.Balance = &spec.Balance{Strategy: "iphash"}
			i.AcceptProxyProtocol = true
		}), "iphash"},
		// UDP
		{"udp multi target", mut(baseFwd(), func(i *spec.Instance) { i.Targets = three; i.Balance = rr; i.Network = []string{"udp"} }), "UDP"},
		{"tcp+udp multi target", mut(baseFwd(), func(i *spec.Instance) { i.Targets = three; i.Balance = rr; i.Network = []string{"tcp", "udp"} }), "UDP"},
		{"proxy out with udp", mut(baseFwd(), func(i *spec.Instance) { i.ProxyProtocolOut = 2; i.Network = []string{"tcp", "udp"} }), "TCP only"},
		{"proxy out v3", mut(baseFwd(), func(i *spec.Instance) { i.ProxyProtocolOut = 3 }), "0, 1 or 2"},
		{"proxy out negative", mut(baseFwd(), func(i *spec.Instance) { i.ProxyProtocolOut = -1 }), "0, 1 or 2"},
		{"accept proxy on udp only", mut(baseFwd(), func(i *spec.Instance) { i.AcceptProxyProtocol = true; i.Network = []string{"udp"} }), "TCP only"},
		{"unknown network", mut(baseFwd(), func(i *spec.Instance) { i.Network = []string{"sctp"} }), "network"},
		{"unknown idle profile", mut(baseFwd(), func(i *spec.Instance) { i.IdleProfile = "forever" }), "idle_profile"},
		// ports / targets
		{"no listen", mut(baseFwd(), func(i *spec.Instance) { i.Listen = nil }), "listen"},
		{"hostname listen", mut(baseFwd(), func(i *spec.Instance) { i.Listen.Addr = "localhost" }), "IP literal"},
		{"zone listen", mut(baseFwd(), func(i *spec.Instance) { i.Listen.Addr = "fe80::1%eth0" }), "IP literal"},
		{"port 0", mut(baseFwd(), func(i *spec.Instance) { i.Listen.Ports = "0" }), "port"},
		{"port 65536", mut(baseFwd(), func(i *spec.Instance) { i.Listen.Ports = "65536" }), "range"},
		{"descending range", mut(baseFwd(), func(i *spec.Instance) { i.Listen.Ports = "9-8" }), "descending"},
		{"huge range", mut(baseFwd(), func(i *spec.Instance) { i.Listen.Ports = "1000-3000"; i.Targets[0].Ports = "1000-3000" }), "per-instance limit"},
		{"range length mismatch", mut(baseFwd(), func(i *spec.Instance) { i.Listen.Ports = "9000-9003"; i.Targets[0].Ports = "80-82" }), "same length"},
		{"no targets", mut(baseFwd(), func(i *spec.Instance) { i.Targets = nil }), "targets"},
		{"target host injection", mut(baseFwd(), func(i *spec.Instance) { i.Targets[0].Host = "a.com:80;x" }), "host"},
		{"target host space", mut(baseFwd(), func(i *spec.Instance) { i.Targets[0].Host = "a.com " }), "host"},
		{"target host newline", mut(baseFwd(), func(i *spec.Instance) { i.Targets[0].Host = "a.com\nb" }), "host"},
		{"target host underscore", mut(baseFwd(), func(i *spec.Instance) { i.Targets[0].Host = "a_b.com" }), "host"},
		{"target host bad ipv4", mut(baseFwd(), func(i *spec.Instance) { i.Targets[0].Host = "999.1.1.1" }), "host"},
		{"target host zone", mut(baseFwd(), func(i *spec.Instance) { i.Targets[0].Host = "fe80::1%eth0" }), "zone"},
		{"target weight 256", mut(baseFwd(), func(i *spec.Instance) { i.Targets[0].Weight = 256 }), "weight"},
		{"target weight negative", mut(baseFwd(), func(i *spec.Instance) { i.Targets[0].Weight = -1 }), "weight"},
		{"weight sum overflow", mut(baseFwd(), func(i *spec.Instance) {
			i.Targets = []spec.Target{tg("10.0.0.1", "80", 255), tg("10.0.0.2", "80", 255), tg("10.0.0.3", "80", 255)}
			for len(i.Targets) < 70 {
				i.Targets = append(i.Targets, tg("10.0.0.4", "80", 255))
			}
			i.Balance = rr
		}), "weights"},
		{"too many targets", mut(baseFwd(), func(i *spec.Instance) {
			i.Targets = nil
			for n := 0; n < 256; n++ {
				i.Targets = append(i.Targets, tg("10.0.0.4", "80", 1))
			}
			i.Balance = &spec.Balance{Strategy: "iphash"}
		}), "at most 255"},
		{"portmap outside", mut(baseFwd(), func(i *spec.Instance) { i.Listen.PortMap = map[string]string{"9": "1.1.1.1:1"} }), "outside"},
		{"portmap bad value", mut(baseFwd(), func(i *spec.Instance) { i.Listen.PortMap = map[string]string{"8080": "1.1.1.1"} }), "host:port"},
		{"portmap injection", mut(baseFwd(), func(i *spec.Instance) { i.Listen.PortMap = map[string]string{"8080": "a.com;x:80"} }), "host"},
		{"portmap incomplete without targets", mut(baseFwd(), func(i *spec.Instance) {
			i.Targets = nil
			i.Listen.Ports = "8080-8081"
			i.Listen.PortMap = map[string]string{"8080": "1.1.1.1:1"}
		}), "port_map"},
		{"forward with tunnel", mut(baseFwd(), func(i *spec.Instance) { i.Tunnel = &spec.Tunnel{Type: "ws"} }), "tunnel"},

		// tunnels
		{"entry no tunnel", mut(baseEntry(), func(i *spec.Instance) { i.Tunnel = nil }), "tunnel"},
		{"entry with targets", mut(baseEntry(), func(i *spec.Instance) { i.Targets = []spec.Target{tg("10.0.0.1", "80", 0)} }), "exit instance"},
		{"entry with balance", mut(baseEntry(), func(i *spec.Instance) { i.Balance = rr }), "exactly one exit"},
		{"entry port range", mut(baseEntry(), func(i *spec.Instance) { i.Listen.Ports = "8080-8081" }), "exactly one port"},
		{"entry port_map", mut(baseEntry(), func(i *spec.Instance) { i.Listen.PortMap = map[string]string{"8080": "1.1.1.1:1"} }), "port_map"},
		{"entry udp", mut(baseEntry(), func(i *spec.Instance) { i.Network = []string{"tcp", "udp"} }), "TCP only"},
		{"entry udp only", mut(baseEntry(), func(i *spec.Instance) { i.Network = []string{"udp"} }), "TCP only"},
		{"entry listen field", mut(baseEntry(), func(i *spec.Instance) { i.Tunnel.Listen = "0.0.0.0:1" }), "tunnel.listen"},
		{"entry cert", mut(baseEntry(), func(i *spec.Instance) { i.Tunnel.Cert = &spec.Cert{Mode: "file"} }), "exit"},
		{"entry bad server", mut(baseEntry(), func(i *spec.Instance) { i.Tunnel.Server = "exit.example.com" }), "host:port"},
		{"exit server field", mut(baseExit(), func(i *spec.Instance) { i.Tunnel.Server = "1.1.1.1:1" }), "tunnel.server"},
		{"exit alpn", mut(baseExit(), func(i *spec.Instance) { i.Tunnel.ALPN = []string{"h2"} }), "ALPN"},
		{"exit no targets", mut(baseExit(), func(i *spec.Instance) { i.Targets = nil }), "targets"},
		{"exit listen hostname", mut(baseExit(), func(i *spec.Instance) { i.Tunnel.Listen = "localhost:443" }), "tunnel.listen"},
		{"exit listen no port", mut(baseExit(), func(i *spec.Instance) { i.Tunnel.Listen = "0.0.0.0" }), "tunnel.listen"},
		{"exit target range", mut(baseExit(), func(i *spec.Instance) { i.Targets[0].Ports = "22-23" }), "exactly one port"},
		{"exit listen block", mut(baseExit(), func(i *spec.Instance) { i.Listen = &spec.Listen{Addr: "0.0.0.0", Ports: "1"} }), "tunnel.listen only"},
		{"exit no cert", mut(baseExit(), func(i *spec.Instance) { i.Tunnel.Cert = nil }), "cert"},
		{"exit self cert needs the insecure option", mut(baseExit(), func(i *spec.Instance) { i.Tunnel.Cert = &spec.Cert{Mode: "self"} }), "self-signed"},
		{"exit panel cert", mut(baseExit(), func(i *spec.Instance) { i.Tunnel.Cert = &spec.Cert{Mode: "panel"} }), "materialised"},
		{"exit unknown cert mode", mut(baseExit(), func(i *spec.Instance) { i.Tunnel.Cert = &spec.Cert{Mode: "x"} }), "mode"},
		{"exit relative cert", mut(baseExit(), func(i *spec.Instance) { i.Tunnel.Cert.CertFile = "c.crt" }), "absolute"},
		{"tunnel grpc", mut(baseEntry(), func(i *spec.Instance) { i.Tunnel.Type = "grpc" }), "cannot carry"},
		{"tunnel xhttp", mut(baseEntry(), func(i *spec.Instance) { i.Tunnel.Type = "xhttp" }), "cannot carry"},
		{"tunnel kcp", mut(baseEntry(), func(i *spec.Instance) { i.Tunnel.Type = "kcp" }), "cannot carry"},
		{"tunnel quic", mut(baseEntry(), func(i *spec.Instance) { i.Tunnel.Type = "quic" }), "cannot carry"},
		{"tunnel unknown", mut(baseEntry(), func(i *spec.Instance) { i.Tunnel.Type = "x" }), "unknown type"},
		{"security tls_pin", mut(baseEntry(), func(i *spec.Instance) { i.Tunnel.Security = "tls_pin" }), "pin"},
		{"security vless_enc", mut(baseEntry(), func(i *spec.Instance) { i.Tunnel.Security = "vless_enc" }), "xray"},
		{"security unknown", mut(baseEntry(), func(i *spec.Instance) { i.Tunnel.Security = "x" }), "security"},
		{"pin sha256", mut(baseEntry(), func(i *spec.Instance) { i.Tunnel.PinSHA256 = strings.Repeat("a", 64) }), "pin"},
		{"security none on wss", mut(baseEntry(), func(i *spec.Instance) { i.Tunnel.Security = "none" }), "TLS"},
		{"security tls on ws", mut(baseEntry(), func(i *spec.Instance) { i.Tunnel.Type = "ws"; i.Tunnel.Security = "tls" }), "tls or wss"},
		{"ws without host", mut(baseEntry(), func(i *spec.Instance) { i.Tunnel.Type = "ws"; i.Tunnel.Host = "" }), "Host"},
		{"ws without path", mut(baseEntry(), func(i *spec.Instance) { i.Tunnel.Type = "ws"; i.Tunnel.Path = "" }), "path"},
		{"tls without sni", mut(baseEntry(), func(i *spec.Instance) {
			i.Tunnel.Type = "tls"
			i.Tunnel.Host, i.Tunnel.Path = "", ""
			i.Tunnel.SNI = ""
		}), "sni"},
		{"tls sni is an IP", mut(baseEntry(), func(i *spec.Instance) {
			i.Tunnel.Type = "tls"
			i.Tunnel.Host, i.Tunnel.Path = "", ""
			i.Tunnel.SNI = "1.2.3.4"
		}), "sni"},
		{"tcp with host", mut(baseEntry(), func(i *spec.Instance) { i.Tunnel = &spec.Tunnel{Type: "tcp", Server: "1.1.1.1:1", Host: "x"} }), "ws/wss only"},
		{"tcp with sni", mut(baseEntry(), func(i *spec.Instance) { i.Tunnel = &spec.Tunnel{Type: "tcp", Server: "1.1.1.1:1", SNI: "x.com"} }), "TLS tunnels only"},
		{"short secret", mut(baseEntry(), func(i *spec.Instance) { i.Secret = "short" }), "secret"},
		{"secret on a bare tls tunnel", mut(baseEntry(), func(i *spec.Instance) {
			i.Tunnel.Type = "tls"
			i.Tunnel.Host = ""
			i.Tunnel.Path = ""
			i.Secret = testSecret
		}), "authenticate"},
		{"secret on a tcp tunnel", mut(baseEntry(), func(i *spec.Instance) {
			i.Tunnel = &spec.Tunnel{Type: "tcp", Server: "1.1.1.1:1"}
			i.Secret = testSecret
		}), "authenticate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := d.Validate(tc.in)
			if err == nil {
				t.Fatalf("expected an error containing %q, got none", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
			if _, rerr := d.Render(tc.in); rerr == nil {
				t.Fatalf("Render accepted what Validate rejected")
			}
			if tc.in.Secret != "" && strings.Contains(err.Error(), tc.in.Secret) {
				t.Fatalf("error message leaks the secret: %v", err)
			}
		})
	}
}

func TestValidateAccepts(t *testing.T) {
	d := New(Options{})
	three := []spec.Target{tg("10.0.0.1", "80", 1), tg("10.0.0.2", "80", 2), tg("lb.example.com", "80", 3)}
	cases := map[string]spec.Instance{
		"forward":     baseFwd(),
		"disabled":    mut(baseFwd(), func(i *spec.Instance) { i.Enabled = false }),
		"auto engine": mut(baseFwd(), func(i *spec.Instance) { i.Engine = spec.EngineAuto }),
		"no engine":   mut(baseFwd(), func(i *spec.Instance) { i.Engine = "" }),
		"udp single":  mut(baseFwd(), func(i *spec.Instance) { i.Network = []string{"udp"} }),
		"tcp+udp":     mut(baseFwd(), func(i *spec.Instance) { i.Network = []string{"tcp", "udp"} }),
		"rr":          mut(baseFwd(), func(i *spec.Instance) { i.Targets = three; i.Balance = &spec.Balance{Strategy: "round_robin"} }),
		"iphash":      mut(baseFwd(), func(i *spec.Instance) { i.Targets = three; i.Balance = &spec.Balance{Strategy: "iphash"} }),
		"udp via portmap with balance": mut(baseFwd(), func(i *spec.Instance) {
			i.Targets = three
			i.Balance = &spec.Balance{Strategy: "round_robin"}
			i.Network = []string{"udp"}
			i.Listen.PortMap = map[string]string{"8080": "10.0.0.9:99"}
		}),
		"portmap only": mut(baseFwd(), func(i *spec.Instance) {
			i.Targets = nil
			i.Listen.PortMap = map[string]string{"8080": "10.0.0.9:99"}
		}),
		"tcp idle profiles": mut(baseFwd(), func(i *spec.Instance) { i.IdleProfile = "tcp_default" }),
		"empty limits":      mut(baseFwd(), func(i *spec.Instance) { i.Limits = &spec.Limits{}; i.ACL = &spec.ACL{} }),
		"proxy v1":          mut(baseFwd(), func(i *spec.Instance) { i.ProxyProtocolOut = 1 }),
		"entry wss":         baseEntry(),
		"entry ws":          mut(baseEntry(), func(i *spec.Instance) { i.Tunnel.Type = "ws"; i.Tunnel.SNI = "" }),
		"entry ws secret": mut(baseEntry(), func(i *spec.Instance) {
			i.Tunnel.Type = "ws"
			i.Tunnel.SNI = ""
			i.Secret = testSecret
		}),
		"entry tls": mut(baseEntry(), func(i *spec.Instance) { i.Tunnel.Type = "tls"; i.Tunnel.Host = ""; i.Tunnel.Path = "" }),
		"entry tcp": mut(baseEntry(), func(i *spec.Instance) { i.Tunnel = &spec.Tunnel{Type: "tcp", Server: "[2001:db8::1]:7000"} }),
		"entry explicit security": mut(baseEntry(), func(i *spec.Instance) {
			i.Tunnel.Security = "tls"
		}),
		"exit wss": baseExit(),
		"exit tcp": mut(baseExit(), func(i *spec.Instance) {
			i.Tunnel = &spec.Tunnel{Type: "tcp", Listen: "0.0.0.0:7000", Security: "none"}
		}),
		"exit balanced": mut(baseExit(), func(i *spec.Instance) { i.Targets = three; i.Balance = &spec.Balance{Strategy: "iphash"} }),
		"host with port header": mut(baseEntry(), func(i *spec.Instance) {
			i.Tunnel.Host = "e.example.com:8443"
		}),
		"host ipv6 header": mut(baseEntry(), func(i *spec.Instance) { i.Tunnel.Host = "[2001:db8::1]:8443" }),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if err := d.Validate(in); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if _, err := d.Render(in); err != nil {
				t.Fatalf("Render: %v", err)
			}
		})
	}
	// The explicitly insecure development mode.
	di := New(Options{InsecureSkipTLSVerify: true})
	self := mut(baseExit(), func(i *spec.Instance) {
		i.Tunnel.Cert = &spec.Cert{Mode: "self"}
		i.Tunnel.SNI = "localhost"
	})
	if err := di.Validate(self); err != nil {
		t.Fatalf("insecure mode must allow a self-signed exit: %v", err)
	}
	if err := d.Validate(self); err == nil {
		t.Fatal("a self-signed exit must be refused by default")
	}
}

// Caps must say exactly what Validate enforces.
func TestCapsMatchValidate(t *testing.T) {
	d := New(Options{})
	c := d.Caps()
	if c.Name != "realm" || c.Reverse || c.ProxyOutUDP || c.HealthCheck != "none" || c.Stats != "none" ||
		c.Reload != "none" || c.DisruptsOnChange || !c.External || c.InstalledSize <= 0 {
		t.Fatalf("unexpected caps %+v", c)
	}
	wantKinds := map[spec.Kind]bool{spec.KindForward: true, spec.KindTunnelEntry: true, spec.KindTunnelExit: true}
	if len(c.Kinds) != len(wantKinds) {
		t.Fatalf("kinds %v", c.Kinds)
	}
	for _, k := range c.Kinds {
		if !wantKinds[k] {
			t.Errorf("unexpected kind %s", k)
		}
	}
	if !c.ProxyIn || !c.ProxyOut {
		t.Error("PROXY in/out must be claimed")
	}

	// Every claimed balance strategy is accepted, every other one is refused.
	three := []spec.Target{tg("10.0.0.1", "80", 1), tg("10.0.0.2", "80", 2), tg("10.0.0.3", "80", 3)}
	claimed := map[string]bool{}
	for _, s := range c.Balance {
		claimed[s] = true
	}
	for _, s := range []string{"round_robin", "random", "iphash", "failover", "least_ping"} {
		err := d.Validate(mut(baseFwd(), func(i *spec.Instance) { i.Targets = three; i.Balance = &spec.Balance{Strategy: s} }))
		if claimed[s] != (err == nil) {
			t.Errorf("strategy %s: claimed=%v but Validate error=%v", s, claimed[s], err)
		}
	}
	// Every claimed tunnel type is accepted by an entry, every other one is refused.
	tt := map[string]bool{}
	for _, s := range c.TunnelTypes {
		tt[s] = true
	}
	for _, typ := range []string{"tcp", "tls", "ws", "wss", "grpc", "xhttp", "kcp", "quic"} {
		tun := spec.Tunnel{Type: typ, Server: "exit.example.com:443"}
		if typ == "ws" || typ == "wss" {
			tun.Host, tun.Path = "e.example.com", "/p"
		}
		if typ == "tls" || typ == "wss" {
			tun.SNI = "exit.example.com"
		}
		err := d.Validate(entry("e", tun))
		if tt[typ] != (err == nil) {
			t.Errorf("tunnel type %s: claimed=%v but Validate error=%v", typ, tt[typ], err)
		}
	}
	// Networks.
	for _, n := range []string{"tcp", "udp", "sctp"} {
		ok := false
		for _, x := range c.Network {
			ok = ok || x == n
		}
		err := d.Validate(mut(baseFwd(), func(i *spec.Instance) { i.Network = []string{n} }))
		if ok != (err == nil) {
			t.Errorf("network %s: claimed=%v err=%v", n, ok, err)
		}
	}
	// PROXY out/in are accepted for TCP.
	if err := d.Validate(mut(baseFwd(), func(i *spec.Instance) { i.ProxyProtocolOut = 2; i.AcceptProxyProtocol = true })); err != nil {
		t.Errorf("PROXY in+out must validate: %v", err)
	}
}

// ---------------------------------------------------------------------------
// transport DSL injection
// ---------------------------------------------------------------------------

// kaminariOpts replicates how kaminari/src/opt.rs reads a transport string:
// split on ';', trim, then look at the pieces ("ws"/"tls"/"insecure" must
// equal a piece; other options are found with starts_with(name) then
// split_once('=')). It returns the pieces.
func kaminariOpts(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ";") {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

var allowedOptKeys = map[string]bool{"ws": true, "host": true, "path": true, "tls": true, "sni": true, "alpn": true,
	"insecure": true, "cert": true, "key": true, "servername": true}

// checkTransport asserts the structural invariant that makes the DSL safe:
// every ';'-separated piece is a known bare flag or a known key=value with a
// non-empty value, and no key appears twice. A value that carried an extra
// option would show up here as an additional or duplicated piece.
func checkTransport(t *testing.T, s string, insecure bool) {
	t.Helper()
	seen := map[string]int{}
	for _, p := range kaminariOpts(s) {
		if p == "" {
			t.Fatalf("empty piece in %q", s)
		}
		k, v, hasEq := strings.Cut(p, "=")
		if !allowedOptKeys[k] {
			t.Fatalf("unexpected option %q in %q", k, s)
		}
		switch k {
		case "ws", "tls", "insecure":
			if hasEq {
				t.Fatalf("flag %q carries a value in %q", k, s)
			}
		default:
			if !hasEq || v == "" {
				t.Fatalf("option %q has no value in %q", k, s)
			}
			if strings.ContainsAny(v, "= \t\r\n\"'`") || strings.ContainsRune(v, 0) {
				t.Fatalf("option %q value %q is unsafe in %q", k, v, s)
			}
		}
		seen[k]++
		if seen[k] > 1 {
			t.Fatalf("option %q repeated in %q", k, s)
		}
	}
	if seen["insecure"] > 0 && !insecure {
		t.Fatalf("insecure option present without the driver option: %q", s)
	}
}

func transportsOf(t *testing.T, d *Driver, in spec.Instance) (listenT, remoteT string) {
	t.Helper()
	art, err := d.Render(in)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	var cfg fileConf
	if err := json.Unmarshal(art.Files[configName], &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Endpoints) != 1 {
		t.Fatalf("want 1 endpoint")
	}
	return cfg.Endpoints[0].ListenTransport, cfg.Endpoints[0].RemoteTransport
}

var injectionPayloads = []string{
	"x;insecure", "x;insecure;", ";insecure", "a;host=evil", "a;path=/evil", "a;tls", "a;ws", "a;sni=evil.com",
	"a;cert=/etc/passwd", "a;key=/etc/shadow", "a;servername=evil.com", "a;alpn=h2", "a=b", "=", "host=x",
	"a b", " a", "a ", "a\tb", "a\nb", "a\r\nb", "a\x00b", "a\x1bb", "a b", "a b", "a\"b", "a'b", "a`b",
	"a\\b", "a%3Bb", "a%3bb", "a&b", "a|b", "a$(id)", "a`id`", "a,b", "a;", ";", "", " ", "/a;b", "/a=b", "/a b",
	"/a?x=1", "/a#x", "/../x", "//x;y", "ünicode.example", "a;;b", "ws;host=a;path=/b", "tls;sni=a",
}

func TestTransportInjectionRejected(t *testing.T) {
	d := New(Options{})
	type field struct {
		name string
		set  func(*spec.Instance, string)
		base spec.Instance
	}
	wssEntry := baseEntry()
	tlsEntry := mut(baseEntry(), func(i *spec.Instance) { i.Tunnel.Type = "tls"; i.Tunnel.Host = ""; i.Tunnel.Path = "" })
	fields := []field{
		{"entry tunnel.host", func(i *spec.Instance, v string) { i.Tunnel.Host = v }, wssEntry},
		{"entry tunnel.path", func(i *spec.Instance, v string) { i.Tunnel.Path = v }, wssEntry},
		{"entry tunnel.sni", func(i *spec.Instance, v string) { i.Tunnel.SNI = v }, wssEntry},
		{"entry tunnel.alpn", func(i *spec.Instance, v string) { i.Tunnel.ALPN = []string{v} }, tlsEntry},
		{"exit tunnel.host", func(i *spec.Instance, v string) { i.Tunnel.Host = v }, baseExit()},
		{"exit tunnel.path", func(i *spec.Instance, v string) { i.Tunnel.Path = v }, baseExit()},
		{"exit cert_file", func(i *spec.Instance, v string) { i.Tunnel.Cert.CertFile = v }, baseExit()},
		{"exit key_file", func(i *spec.Instance, v string) { i.Tunnel.Cert.KeyFile = v }, baseExit()},
	}
	for _, f := range fields {
		for _, payload := range injectionPayloads {
			in := mut(f.base, func(i *spec.Instance) {
				if i.Tunnel.Cert != nil {
					c := *i.Tunnel.Cert
					i.Tunnel.Cert = &c
				}
				f.set(i, payload)
			})
			if err := d.Validate(in); err == nil {
				t.Errorf("%s accepted %q", f.name, payload)
			}
		}
	}
	// In self-signed (insecure) mode the SNI is rendered as servername= too.
	di := New(Options{InsecureSkipTLSVerify: true})
	for _, payload := range injectionPayloads {
		in := mut(baseExit(), func(i *spec.Instance) {
			i.Tunnel.Cert = &spec.Cert{Mode: "self"}
			i.Tunnel.SNI = payload
		})
		if err := di.Validate(in); err == nil {
			t.Errorf("exit sni (self-signed) accepted %q", payload)
		}
	}
}

// Whatever a field is set to, a rendered transport string has the same shape:
// either Validate refuses, or every piece is one of the known options. The
// inputs are random strings over an alphabet full of DSL metacharacters.
func TestTransportInjectionProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5eed))
	alphabet := []rune("ab.-_/;= \t\r\n\"'`\\%&|$,:[]\x00éwsthpkeyinscr") // includes keywords
	gen := func() string {
		n := rng.Intn(24)
		r := make([]rune, n)
		for i := range r {
			r[i] = alphabet[rng.Intn(len(alphabet))]
		}
		return string(r)
	}
	for _, insecure := range []bool{false, true} {
		d := New(Options{InsecureSkipTLSVerify: insecure})
		accepted := 0
		for n := 0; n < 30000; n++ {
			// Entry (client side: remote_transport).
			in := mut(baseEntry(), func(i *spec.Instance) {
				switch rng.Intn(5) {
				case 0:
					i.Tunnel.Host = gen()
				case 1:
					i.Tunnel.Path = "/" + gen()
				case 2:
					i.Tunnel.SNI = gen()
				case 3:
					i.Tunnel.ALPN = []string{gen(), gen()}
					i.Tunnel.Type = "tls"
					i.Tunnel.Host, i.Tunnel.Path = "", ""
				default:
					i.Secret = gen()
				}
			})
			if d.Validate(in) == nil {
				accepted++
				_, rt := transportsOf(t, d, in)
				checkTransport(t, rt, insecure)
			}
			// Exit (server side: listen_transport).
			ex := mut(baseExit(), func(i *spec.Instance) {
				c := *i.Tunnel.Cert
				i.Tunnel.Cert = &c
				switch rng.Intn(5) {
				case 0:
					i.Tunnel.Host = gen()
				case 1:
					i.Tunnel.Path = "/" + gen()
				case 2:
					i.Tunnel.Cert.CertFile = "/" + gen()
				case 3:
					i.Tunnel.Cert.KeyFile = "/" + gen()
				default:
					if insecure {
						i.Tunnel.Cert = &spec.Cert{Mode: "self"}
						i.Tunnel.SNI = gen()
					}
				}
			})
			if d.Validate(ex) == nil {
				accepted++
				lt, _ := transportsOf(t, d, ex)
				checkTransport(t, lt, insecure)
			}
		}
		if accepted == 0 {
			t.Fatal("the generator never produced a valid instance; the property test is vacuous")
		}
		t.Logf("insecure=%v: %d of 60000 generated instances were valid and structurally checked", insecure, accepted)
	}
}

func FuzzTransportInjection(f *testing.F) {
	for _, p := range injectionPayloads {
		f.Add(p, p, p)
	}
	f.Add("cdn.example.com", "/ws", "exit.example.com")
	d := New(Options{})
	f.Fuzz(func(t *testing.T, host, path, sni string) {
		in := mut(baseEntry(), func(i *spec.Instance) { i.Tunnel.Host, i.Tunnel.Path, i.Tunnel.SNI = host, path, sni })
		if d.Validate(in) != nil {
			return
		}
		_, rt := transportsOf(t, d, in)
		checkTransport(t, rt, false)
		ex := mut(baseExit(), func(i *spec.Instance) { i.Tunnel.Host, i.Tunnel.Path = host, path })
		if d.Validate(ex) != nil {
			return
		}
		lt, _ := transportsOf(t, d, ex)
		checkTransport(t, lt, false)
	})
}

// Unsafe characters in hosts reach neither the JSON nor realm's address
// parser: only whitelisted host names and IP literals get through.
func TestHostWhitelist(t *testing.T) {
	good := []string{"example.com", "a-b.example.com", "A.Example.COM", "10.0.0.1", "2001:db8::1", "xn--e1afmkfd.example", "localhost"}
	bad := []string{"", " ", "a.com ", "a_b.com", "a.com:80", "-a.com", "a-.com", "a..com", ".a.com", "a.com.", "1.2.3", "999.999.999.999",
		"a.com/x", "a.com\\x", "a.com#", "a@b.com", "[::1]", "fe80::1%lo", "a\x00.com", "é.com", strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 130) + "com"}
	for _, h := range good {
		if _, _, err := normHost("t", h); err != nil {
			t.Errorf("%q rejected: %v", h, err)
		}
	}
	for _, h := range bad {
		if _, _, err := normHost("t", h); err == nil {
			t.Errorf("%q accepted", h)
		}
	}
	// Hostnames are lower-cased, IPv6 compressed.
	if h, _, _ := normHost("t", "A.Example.COM"); h != "a.example.com" {
		t.Errorf("host = %q", h)
	}
	if h, _, _ := normHost("t", "2001:0db8:0::1"); h != "2001:db8::1" {
		t.Errorf("host = %q", h)
	}
}

func TestSecretNeverInArtifactsOrErrors(t *testing.T) {
	d := New(Options{})
	in := mut(baseEntry(), func(i *spec.Instance) { i.Tunnel.Type = "ws"; i.Tunnel.SNI = ""; i.Secret = testSecret })
	art, err := d.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range art.Files {
		if strings.Contains(string(b), testSecret) {
			t.Fatalf("secret in %s", name)
		}
	}
	if strings.Contains(art.Hash, testSecret) {
		t.Fatal("secret in hash")
	}
}
