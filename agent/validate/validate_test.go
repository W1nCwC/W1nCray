package validate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/spec"
)

const goodSecret = "0123456789abcdef-secret"
const goodDomain = "9f86d081884c7d659a2feaa0c55ad015" // 32 hex

func policy() spec.Policy {
	return spec.Policy{
		MaxInstances:        10,
		MaxPortsPerInstance: 20,
		AllowListen:         []string{"127.0.0.1", "10.1.0.0/16"},
		PortRange:           [2]int{1024, 60000},
		DenyPorts:           []int{9999},
	}
}

func fwd() spec.Instance {
	return spec.Instance{
		ID: "fwd", Enabled: true, Engine: "auto", Kind: spec.KindForward,
		Listen:  &spec.Listen{Addr: "127.0.0.1", Ports: "8443"},
		Targets: []spec.Target{{Host: "198.51.100.10", Ports: "443"}},
	}
}

func entry() spec.Instance {
	return spec.Instance{
		ID: "ent", Enabled: true, Engine: "auto", Kind: spec.KindTunnelEntry,
		Listen: &spec.Listen{Addr: "127.0.0.1", Ports: "9000"},
		Tunnel: &spec.Tunnel{Type: "ws", Server: "198.51.100.20:443", Host: "example.com", Path: "/ws", SNI: "example.com", Security: "tls"},
		Secret: goodSecret,
	}
}

func exit() spec.Instance {
	return spec.Instance{
		ID: "ext", Enabled: true, Engine: "auto", Kind: spec.KindTunnelExit,
		Tunnel:  &spec.Tunnel{Type: "ws", Listen: "127.0.0.1:9443", Security: "tls"},
		Targets: []spec.Target{{Host: "198.51.100.10", Ports: "443"}},
		Secret:  goodSecret,
	}
}

func portal() spec.Instance {
	return spec.Instance{
		ID: "por", Enabled: true, Engine: "xray", Kind: spec.KindReversePortal,
		Listen:  &spec.Listen{Addr: "127.0.0.1", Ports: "9100"},
		Tunnel:  &spec.Tunnel{Type: "tcp", Listen: "127.0.0.1:9101", Security: "vless_enc"},
		Reverse: &spec.Reverse{Domain: goodDomain, Link: "br"},
		Secret:  goodSecret,
	}
}

func bridge() spec.Instance {
	return spec.Instance{
		ID: "br", Enabled: true, Engine: "auto", Kind: spec.KindReverseBridge,
		Listen:  &spec.Listen{Ports: "9100"},
		Tunnel:  &spec.Tunnel{Type: "tcp", Server: "198.51.100.30:9101"},
		Targets: []spec.Target{{Host: "198.51.100.40", Ports: "22"}},
		Secret:  goodSecret,
	}
}

func desired(ins ...spec.Instance) spec.Desired {
	return spec.Desired{Version: spec.Version, Revision: 1, Instances: ins}
}

type fakeResolver struct {
	m     map[string][]string
	calls atomic.Int32
	delay time.Duration
}

func (f *fakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	f.calls.Add(1)
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	v, ok := f.m[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	var out []netip.Addr
	for _, s := range v {
		out = append(out, netip.MustParseAddr(s))
	}
	return out, nil
}

func opts() Options { return Options{Resolver: &fakeResolver{m: map[string][]string{}}} }

func find(errs []Error, field, substr string) bool {
	for _, e := range errs {
		if e.Field == field && strings.Contains(e.Message, substr) {
			return true
		}
	}
	return false
}

func dump(errs []Error) string {
	var sb strings.Builder
	for _, e := range errs {
		sb.WriteString("\n  " + e.Error())
	}
	return sb.String()
}

func TestValidBaselines(t *testing.T) {
	for _, in := range []spec.Instance{fwd(), entry(), exit(), portal(), bridge()} {
		if errs := Desired(desired(in), policy(), opts()); len(errs) != 0 {
			t.Errorf("%s should be valid:%s", in.Kind, dump(errs))
		}
	}
	all := desired(fwd(), entry(), exit(), portal(), bridge())
	// make listeners distinct
	all.Instances[2].Tunnel.Listen = "127.0.0.1:9444"
	all.Instances[3].Tunnel.Listen = "127.0.0.1:9102"
	all.Instances[3].Listen.Ports = "9101"
	all.Instances[3].Tunnel.Listen = "127.0.0.1:9103"
	if errs := Desired(all, policy(), opts()); len(errs) != 0 {
		t.Errorf("combined:%s", dump(errs))
	}
}

type mut struct {
	name   string
	base   func() spec.Instance
	edit   func(*spec.Instance)
	field  string
	substr string
}

func TestInstanceRules(t *testing.T) {
	cases := []mut{
		// id / engine / kind
		{"id empty", fwd, func(i *spec.Instance) { i.ID = "" }, "id", "invalid id"},
		{"id upper", fwd, func(i *spec.Instance) { i.ID = "Fwd" }, "id", "invalid id"},
		{"id slash", fwd, func(i *spec.Instance) { i.ID = "a/b" }, "id", "invalid id"},
		{"id newline", fwd, func(i *spec.Instance) { i.ID = "a\nb" }, "id", "invalid id"},
		{"id too long", fwd, func(i *spec.Instance) { i.ID = strings.Repeat("a", 41) }, "id", "invalid id"},
		{"engine unknown", fwd, func(i *spec.Instance) { i.Engine = "nginx" }, "engine", "unknown engine"},
		{"engine empty", fwd, func(i *spec.Instance) { i.Engine = "" }, "engine", "unknown engine"},
		{"kind unknown", fwd, func(i *spec.Instance) { i.Kind = "rm -rf" }, "kind", "unknown kind"},
		{"name injection", fwd, func(i *spec.Instance) { i.Name = "x\"; rm" }, "name", "forbidden character"},
		{"name newline", fwd, func(i *spec.Instance) { i.Name = "a\nb" }, "name", "forbidden character"},
		{"name too long", fwd, func(i *spec.Instance) { i.Name = strings.Repeat("a", 65) }, "name", "too long"},

		// kind / field matching
		{"forward no listen", fwd, func(i *spec.Instance) { i.Listen = nil }, "listen", "required"},
		{"forward no targets", fwd, func(i *spec.Instance) { i.Targets = nil }, "targets", "at least one target"},
		{"forward with tunnel", fwd, func(i *spec.Instance) { i.Tunnel = &spec.Tunnel{Type: "tcp"} }, "tunnel", "not allowed"},
		{"forward with secret", fwd, func(i *spec.Instance) { i.Secret = goodSecret }, "secret", "not allowed"},
		{"forward with reverse", fwd, func(i *spec.Instance) { i.Reverse = &spec.Reverse{} }, "reverse", "only allowed"},
		{"forward any target", fwd, func(i *spec.Instance) { i.AllowAnyTarget = true }, "allow_any_target", "only allowed for tunnel_exit"},
		{"entry no server", entry, func(i *spec.Instance) { i.Tunnel.Server = "" }, "tunnel.server", "required"},
		{"entry with tunnel listen", entry, func(i *spec.Instance) { i.Tunnel.Listen = "127.0.0.1:1" }, "tunnel.listen", "not used"},
		{"entry no tunnel", entry, func(i *spec.Instance) { i.Tunnel = nil }, "tunnel", "required"},
		{"entry cert", entry, func(i *spec.Instance) { i.Tunnel.Cert = &spec.Cert{Mode: "self"} }, "tunnel.cert.mode", "only supports mode"},
		{"exit no tunnel listen", exit, func(i *spec.Instance) { i.Tunnel.Listen = "" }, "tunnel.listen", "required"},
		{"exit server set", exit, func(i *spec.Instance) { i.Tunnel.Server = "198.51.100.1:1" }, "tunnel.server", "not used"},
		{"exit no targets", exit, func(i *spec.Instance) { i.Targets = nil }, "targets", "fixed targets or allow_any_target"},
		{"exit any target but policy denies", exit, func(i *spec.Instance) { i.Targets = nil; i.AllowAnyTarget = true }, "allow_any_target", "local policy"},
		{"exit targets and any", exit, func(i *spec.Instance) { i.AllowAnyTarget = true }, "allow_any_target", "mutually exclusive"},
		{"exit with listen", exit, func(i *spec.Instance) { i.Listen = &spec.Listen{Addr: "127.0.0.1", Ports: "9"} }, "listen", "not used by tunnel_exit"},
		{"portal no listen", portal, func(i *spec.Instance) { i.Listen = nil }, "listen", "required"},
		{"portal targets", portal, func(i *spec.Instance) { i.Targets = []spec.Target{{Host: "198.51.100.1", Ports: "1"}} }, "targets", "not used by reverse_portal"},
		{"portal portmap", portal, func(i *spec.Instance) { i.Listen.PortMap = map[string]string{"9100": "198.51.100.1:1"} }, "listen.port_map", "only allowed"},
		{"bridge no server", bridge, func(i *spec.Instance) { i.Tunnel.Server = "" }, "tunnel.server", "required"},
		{"bridge no targets", bridge, func(i *spec.Instance) { i.Targets = nil }, "targets", "at least one target"},
		{"bridge no listen", bridge, func(i *spec.Instance) { i.Listen = nil }, "listen", "required for reverse_bridge"},
		{"bridge bad ports", bridge, func(i *spec.Instance) { i.Listen.Ports = "abc" }, "listen.ports", "invalid port"},
		{"bridge addr garbage", bridge, func(i *spec.Instance) { i.Listen.Addr = "evil host" }, "listen.addr", "unused"},
		{"bridge port count", bridge, func(i *spec.Instance) {
			i.Listen.Ports = "100-199"
			i.Targets[0].Ports = "100-199"
		}, "listen.ports", "local policy allows 20"},
		{"bridge range mismatch", bridge, func(i *spec.Instance) { i.Listen.Ports = "9100-9102" }, "targets[0].ports", "same length"},

		// secrets
		{"secret missing", entry, func(i *spec.Instance) { i.Secret = "" }, "secret", "required"},
		{"secret short", entry, func(i *spec.Instance) { i.Secret = "short" }, "secret", "16-256"},
		{"secret quote", entry, func(i *spec.Instance) { i.Secret = goodSecret + "\"" }, "secret", "16-256"},
		{"secret space", entry, func(i *spec.Instance) { i.Secret = goodSecret + " x" }, "secret", "16-256"},
		{"secret missing exit", exit, func(i *spec.Instance) { i.Secret = "" }, "secret", "required"},
		{"secret missing portal", portal, func(i *spec.Instance) { i.Secret = "" }, "secret", "required"},
		{"secret missing bridge", bridge, func(i *spec.Instance) { i.Secret = "" }, "secret", "required"},

		// listen / ports / policy
		{"listen host name", fwd, func(i *spec.Instance) { i.Listen.Addr = "example.com" }, "listen.addr", "literal IP"},
		{"listen empty", fwd, func(i *spec.Instance) { i.Listen.Addr = "" }, "listen.addr", "literal IP"},
		{"listen brackets", fwd, func(i *spec.Instance) { i.Listen.Addr = "[::1]" }, "listen.addr", "literal IP"},
		{"listen zone", fwd, func(i *spec.Instance) { i.Listen.Addr = "fe80::1%eth0" }, "listen.addr", "literal IP"},
		{"listen not allowed", fwd, func(i *spec.Instance) { i.Listen.Addr = "0.0.0.0" }, "listen.addr", "not allowed by the local policy"},
		{"listen not allowed v6", fwd, func(i *spec.Instance) { i.Listen.Addr = "::" }, "listen.addr", "not allowed by the local policy"},
		{"listen port zero", fwd, func(i *spec.Instance) { i.Listen.Ports = "0" }, "listen.ports", "out of range"},
		{"listen port big", fwd, func(i *spec.Instance) { i.Listen.Ports = "65536" }, "listen.ports", "out of range"},
		{"listen range reversed", fwd, func(i *spec.Instance) { i.Listen.Ports = "9010-9000" }, "listen.ports", "start must be below end"},
		{"listen range junk", fwd, func(i *spec.Instance) { i.Listen.Ports = "9000;9001" }, "listen.ports", "invalid port"},
		{"listen range too wide", fwd, func(i *spec.Instance) {
			i.Listen.Ports = "20000-20020"
			i.Targets[0].Ports = "20000-20020"
		}, "listen.ports", "local policy allows 20"},
		{"listen privileged", fwd, func(i *spec.Instance) { i.Listen.Ports = "443" }, "listen.ports", "privileged"},
		{"listen outside port_range", fwd, func(i *spec.Instance) { i.Listen.Ports = "61000" }, "listen.ports", "outside the permitted range"},
		{"listen denied port", fwd, func(i *spec.Instance) { i.Listen.Ports = "9999" }, "listen.ports", "denied by the local policy"},
		{"listen denied port in range", fwd, func(i *spec.Instance) {
			i.Listen.Ports = "9990-9999"
			i.Targets[0].Ports = "1-10"
		}, "listen.ports", "port 9999 is denied"},
		{"tunnel listen not allowed", exit, func(i *spec.Instance) { i.Tunnel.Listen = "0.0.0.0:9443" }, "tunnel.listen", "not allowed by the local policy"},
		{"tunnel listen no port", exit, func(i *spec.Instance) { i.Tunnel.Listen = "127.0.0.1" }, "tunnel.listen", "<ip>:<port>"},
		{"tunnel listen host", exit, func(i *spec.Instance) { i.Tunnel.Listen = "localhost:9443" }, "tunnel.listen", "<ip>:<port>"},
		{"tunnel listen port zero", exit, func(i *spec.Instance) { i.Tunnel.Listen = "127.0.0.1:0" }, "tunnel.listen", "1-65535"},
		{"tunnel listen privileged", exit, func(i *spec.Instance) { i.Tunnel.Listen = "127.0.0.1:443" }, "tunnel.listen", "privileged"},
		{"tunnel listen denied", exit, func(i *spec.Instance) { i.Tunnel.Listen = "127.0.0.1:9999" }, "tunnel.listen", "denied"},

		// targets
		{"range length mismatch", fwd, func(i *spec.Instance) {
			i.Listen.Ports = "9000-9003"
			i.Targets[0].Ports = "443"
		}, "targets[0].ports", "same length"},
		{"range length mismatch 2", fwd, func(i *spec.Instance) {
			i.Listen.Ports = "9000-9003"
			i.Targets[0].Ports = "443-450"
		}, "targets[0].ports", "same length"},
		{"target port bad", fwd, func(i *spec.Instance) { i.Targets[0].Ports = "0" }, "targets[0].ports", "out of range"},
		{"target weight negative", fwd, func(i *spec.Instance) { i.Targets[0].Weight = -1 }, "targets[0].weight", "between"},
		{"too many targets", fwd, func(i *spec.Instance) {
			for n := 0; n < 70; n++ {
				i.Targets = append(i.Targets, spec.Target{Host: "198.51.100.10", Ports: "443"})
			}
		}, "targets", "too many targets"},

		// network / proxy
		{"network bad", fwd, func(i *spec.Instance) { i.Network = []string{"sctp"} }, "network[0]", "invalid network"},
		{"network dup", fwd, func(i *spec.Instance) { i.Network = []string{"tcp", "tcp"} }, "network[1]", "duplicate"},
		{"udp + proxy out", fwd, func(i *spec.Instance) { i.Network = []string{"tcp", "udp"}; i.ProxyProtocolOut = 2 }, "proxy_protocol_out", "TCP only"},
		{"udp only + proxy out", fwd, func(i *spec.Instance) { i.Network = []string{"udp"}; i.ProxyProtocolOut = 1 }, "proxy_protocol_out", "TCP only"},
		{"proxy out bad version", fwd, func(i *spec.Instance) { i.ProxyProtocolOut = 3 }, "proxy_protocol_out", "0, 1 or 2"},
		{"udp + accept proxy", fwd, func(i *spec.Instance) { i.Network = []string{"udp"}; i.AcceptProxyProtocol = true }, "accept_proxy_protocol", "TCP only"},
		{"accept proxy on exit", exit, func(i *spec.Instance) { i.AcceptProxyProtocol = true }, "accept_proxy_protocol", "no user-facing listener"},
		{"idle unknown", fwd, func(i *spec.Instance) { i.IdleProfile = "forever" }, "idle_profile", "unknown profile"},
		{"idle udp on tcp", fwd, func(i *spec.Instance) { i.IdleProfile = "udp_short" }, "idle_profile", "needs network udp"},
		{"idle tcp on udp", fwd, func(i *spec.Instance) { i.Network = []string{"udp"}; i.IdleProfile = "tcp_long" }, "idle_profile", "needs network tcp"},

		// tunnel type / security
		{"tunnel type unknown", entry, func(i *spec.Instance) { i.Tunnel.Type = "ssh" }, "tunnel.type", "unknown tunnel type"},
		{"security unknown", entry, func(i *spec.Instance) { i.Tunnel.Security = "magic" }, "tunnel.security", "unknown security"},
		{"vless_enc on gost", entry, func(i *spec.Instance) { i.Engine = "gost"; i.Tunnel.Security = "vless_enc" }, "tunnel.security", "only supported by the xray"},
		{"vless_enc on realm", entry, func(i *spec.Instance) { i.Engine = "realm"; i.Tunnel.Security = "vless_enc" }, "tunnel.security", "only supported by the xray"},
		{"wss with none", entry, func(i *spec.Instance) { i.Tunnel.Type = "wss"; i.Tunnel.Security = "none" }, "tunnel.security", "contradictory"},
		{"tls with vless_enc", entry, func(i *spec.Instance) { i.Engine = "xray"; i.Tunnel.Type = "tls"; i.Tunnel.Security = "vless_enc" }, "tunnel.security", "contradictory"},
		{"tls_pin no pin", entry, func(i *spec.Instance) { i.Tunnel.Security = "tls_pin" }, "tunnel.pin_sha256", "64 hex"},
		{"tls_pin short pin", entry, func(i *spec.Instance) { i.Tunnel.Security = "tls_pin"; i.Tunnel.PinSHA256 = "abcd" }, "tunnel.pin_sha256", "64 hex"},
		{"tls_pin non hex", entry, func(i *spec.Instance) {
			i.Tunnel.Security = "tls_pin"
			i.Tunnel.PinSHA256 = strings.Repeat("g", 64)
		}, "tunnel.pin_sha256", "64 hex"},
		{"pin without tls_pin", entry, func(i *spec.Instance) { i.Tunnel.PinSHA256 = strings.Repeat("a", 64) }, "tunnel.pin_sha256", "only meaningful"},

		// tunnel text fields (hostile)
		{"host space", entry, func(i *spec.Instance) { i.Tunnel.Host = "a b" }, "tunnel.host", "invalid host"},
		{"host newline", entry, func(i *spec.Instance) { i.Tunnel.Host = "a\nHost: evil" }, "tunnel.host", "invalid host"},
		{"host quote", entry, func(i *spec.Instance) { i.Tunnel.Host = `a"b` }, "tunnel.host", "invalid host"},
		{"host hash", entry, func(i *spec.Instance) { i.Tunnel.Host = "a#b" }, "tunnel.host", "invalid host"},
		{"host semicolon", entry, func(i *spec.Instance) { i.Tunnel.Host = "a;b" }, "tunnel.host", "invalid host"},
		{"host backtick", entry, func(i *spec.Instance) { i.Tunnel.Host = "a`id`" }, "tunnel.host", "invalid host"},
		{"path no slash", entry, func(i *spec.Instance) { i.Tunnel.Path = "ws" }, "tunnel.path", "invalid path"},
		{"path hash", entry, func(i *spec.Instance) { i.Tunnel.Path = "/a#b" }, "tunnel.path", "invalid path"},
		{"path quote", entry, func(i *spec.Instance) { i.Tunnel.Path = `/a"b` }, "tunnel.path", "invalid path"},
		{"path semicolon", entry, func(i *spec.Instance) { i.Tunnel.Path = "/a;b" }, "tunnel.path", "invalid path"},
		{"path backtick", entry, func(i *spec.Instance) { i.Tunnel.Path = "/a`b" }, "tunnel.path", "invalid path"},
		{"path newline", entry, func(i *spec.Instance) { i.Tunnel.Path = "/a\nb" }, "tunnel.path", "invalid path"},
		{"path space", entry, func(i *spec.Instance) { i.Tunnel.Path = "/a b" }, "tunnel.path", "invalid path"},
		{"path query", entry, func(i *spec.Instance) { i.Tunnel.Path = "/a?x=1" }, "tunnel.path", "invalid path"},
		{"sni space", entry, func(i *spec.Instance) { i.Tunnel.SNI = "a b" }, "tunnel.sni", ""},
		{"sni quote", entry, func(i *spec.Instance) { i.Tunnel.SNI = `a".com` }, "tunnel.sni", ""},
		{"sni ip", entry, func(i *spec.Instance) { i.Tunnel.SNI = "198.51.100.1" }, "tunnel.sni", "not an IP"},
		{"alpn bad", entry, func(i *spec.Instance) { i.Tunnel.ALPN = []string{"h2", "h2\";x"} }, "tunnel.alpn[1]", "invalid ALPN"},
		{"alpn many", entry, func(i *spec.Instance) { i.Tunnel.ALPN = make([]string, 9) }, "tunnel.alpn", "too many"},
		{"cert mode", exit, func(i *spec.Instance) { i.Tunnel.Cert = &spec.Cert{Mode: "magic"} }, "tunnel.cert.mode", "unknown mode"},
		{"cert file relative", exit, func(i *spec.Instance) {
			i.Tunnel.Cert = &spec.Cert{Mode: "file", CertFile: "a.pem", KeyFile: "/k.pem"}
		}, "tunnel.cert.cert_file", "absolute path"},
		{"cert file traversal", exit, func(i *spec.Instance) {
			i.Tunnel.Cert = &spec.Cert{Mode: "file", CertFile: "/etc/../shadow", KeyFile: "/k.pem"}
		}, "tunnel.cert.cert_file", "absolute path"},
		{"cert file injection", exit, func(i *spec.Instance) {
			i.Tunnel.Cert = &spec.Cert{Mode: "file", CertFile: "/a.pem\n", KeyFile: "/k.pem"}
		}, "tunnel.cert.cert_file", "absolute path"},
		{"cert files with self", exit, func(i *spec.Instance) { i.Tunnel.Cert = &spec.Cert{Mode: "self", CertFile: "/a"} }, "tunnel.cert", "only used with mode"},

		// balance
		{"balance strategy", fwd, func(i *spec.Instance) { i.Balance = &spec.Balance{Strategy: "chaos"} }, "balance.strategy", "unknown strategy"},
		{"balance no targets", fwd, func(i *spec.Instance) {
			i.Targets = nil
			i.Listen.PortMap = map[string]string{"8443": "198.51.100.1:1"}
			i.Balance = &spec.Balance{Strategy: "random"}
		}, "balance", "requires targets"},
		{"health type", fwd, func(i *spec.Instance) {
			i.Balance = &spec.Balance{Strategy: "random", Health: &spec.Health{Type: "icmp"}}
		}, "balance.health.type", "tcp or http"},
		{"health interval", fwd, func(i *spec.Instance) {
			i.Balance = &spec.Balance{Strategy: "random", Health: &spec.Health{Type: "tcp", IntervalS: 99999}}
		}, "balance.health.interval_s", "0-3600"},
		{"health probe url ssrf", fwd, func(i *spec.Instance) {
			i.Balance = &spec.Balance{Strategy: "random", Health: &spec.Health{Type: "http", ProbeURL: "http://169.254.169.254/latest/meta-data"}}
		}, "balance.health.probe_url", "full URLs are not accepted"},
		{"health probe url on tcp", fwd, func(i *spec.Instance) {
			i.Balance = &spec.Balance{Strategy: "random", Health: &spec.Health{Type: "tcp", ProbeURL: "/h"}}
		}, "balance.health.probe_url", "only used with type http"},

		// reverse
		{"domain short hex", portal, func(i *spec.Instance) { i.Reverse.Domain = "deadbeef" }, "reverse.domain", "at least 32"},
		{"domain 31 hex", portal, func(i *spec.Instance) { i.Reverse.Domain = goodDomain[:31] }, "reverse.domain", "at least 32"},
		{"domain short b64", portal, func(i *spec.Instance) { i.Reverse.Domain = "Zm9vYmFy_-Zm9vYmFyZ" }, "reverse.domain", "at least 22"},
		{"domain low entropy", portal, func(i *spec.Instance) { i.Reverse.Domain = strings.Repeat("a", 40) }, "reverse.domain", "not random enough"},
		{"domain dots", portal, func(i *spec.Instance) { i.Reverse.Domain = "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p" }, "reverse.domain", "hex or base64url"},
		{"domain injection", portal, func(i *spec.Instance) { i.Reverse.Domain = goodDomain + `"; x` }, "reverse.domain", "hex or base64url"},
		{"domain too long", portal, func(i *spec.Instance) { i.Reverse.Domain = strings.Repeat("0123456789abcdef", 9) }, "reverse.domain", "too long"},
		{"link bad", portal, func(i *spec.Instance) { i.Reverse.Link = "A B" }, "reverse.link", "invalid link"},
		{"bridge allow bad host", portal, func(i *spec.Instance) {
			i.Reverse.BridgeAllow = []spec.Allow{{Host: "127.0.0.1", Ports: "22"}}
		}, "reverse.bridge_allow[0].host", "loopback"},
		{"bridge allow bad port", portal, func(i *spec.Instance) {
			i.Reverse.BridgeAllow = []spec.Allow{{Host: "198.51.100.5", Ports: "x"}}
		}, "reverse.bridge_allow[0].ports", "invalid port"},

		// limits / acl
		{"limit conns", fwd, func(i *spec.Instance) { i.Limits = &spec.Limits{MaxConns: -1} }, "limits.max_conns", "must be"},
		{"limit up", fwd, func(i *spec.Instance) { i.Limits = &spec.Limits{RateUpBps: -5} }, "limits.rate_up_bps", "must be"},
		{"limit down", fwd, func(i *spec.Instance) { i.Limits = &spec.Limits{RateDownBps: 1 << 50} }, "limits.rate_down_bps", "must be"},
		{"acl cidr bad", fwd, func(i *spec.Instance) { i.ACL = &spec.ACL{Allow: []string{"10.0.0.0/33"}} }, "acl.allow[0]", "not an IP"},
		{"acl word", fwd, func(i *spec.Instance) { i.ACL = &spec.ACL{Deny: []string{"10.0.0.0/8", "evil"}} }, "acl.deny[1]", "not an IP"},
		{"acl zone", fwd, func(i *spec.Instance) { i.ACL = &spec.ACL{Deny: []string{"fe80::1%eth0"}} }, "acl.deny[0]", "not an IP"},

		// port map
		{"portmap key range", fwd, func(i *spec.Instance) { i.Listen.PortMap = map[string]string{"8000-8001": "198.51.100.1:1"} }, "listen.port_map[8000-8001]", "single listen port"},
		{"portmap key outside", fwd, func(i *spec.Instance) { i.Listen.PortMap = map[string]string{"8444": "198.51.100.1:1"} }, "listen.port_map[8444]", "outside listen.ports"},
		{"portmap key junk", fwd, func(i *spec.Instance) { i.Listen.PortMap = map[string]string{"x\ny": "198.51.100.1:1"} }, "listen.port_map[x?y]", "single listen port"},
		{"portmap value no port", fwd, func(i *spec.Instance) { i.Listen.PortMap = map[string]string{"8443": "198.51.100.1"} }, "listen.port_map[8443]", "host:port"},
		{"portmap value loopback", fwd, func(i *spec.Instance) { i.Listen.PortMap = map[string]string{"8443": "127.0.0.1:22"} }, "listen.port_map[8443]", "loopback"},
		{"portmap value bad port", fwd, func(i *spec.Instance) { i.Listen.PortMap = map[string]string{"8443": "198.51.100.1:99999"} }, "listen.port_map[8443]", "out of range"},
		{"portmap value metadata", fwd, func(i *spec.Instance) { i.Listen.PortMap = map[string]string{"8443": "169.254.169.254:80"} }, "listen.port_map[8443]", "link-local"},
	}
	for _, c := range cases {
		if c.field == "" {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			in := c.base()
			c.edit(&in)
			p := policy()
			if c.name == "exit any target but policy denies" {
				p.AllowAnyTarget = false
			}
			errs := Desired(desired(in), p, opts())
			if !find(errs, c.field, c.substr) {
				t.Fatalf("want error on %q containing %q, got:%s", c.field, c.substr, dump(errs))
			}
		})
	}
}

func TestPolicyOpensThings(t *testing.T) {
	// the same inputs pass once the local policy allows them
	in := exit()
	in.Targets = nil
	in.AllowAnyTarget = true
	p := policy()
	p.AllowAnyTarget = true
	if errs := Desired(desired(in), p, opts()); len(errs) != 0 {
		t.Fatalf("allow_any_target with policy:%s", dump(errs))
	}
	f := fwd()
	f.Listen.Ports = "443"
	p = policy()
	p.PrivilegedPorts = true
	p.PortRange = [2]int{}
	if errs := Desired(desired(f), p, opts()); len(errs) != 0 {
		t.Fatalf("privileged with policy:%s", dump(errs))
	}
	f = fwd()
	f.Listen.Addr = "10.1.2.3"
	if errs := Desired(desired(f), policy(), opts()); len(errs) != 0 {
		t.Fatalf("CIDR in allow_listen:%s", dump(errs))
	}
	f.Listen.Addr = "10.2.2.3"
	if errs := Desired(desired(f), policy(), opts()); !find(errs, "listen.addr", "not allowed") {
		t.Fatalf("outside CIDR must fail:%s", dump(errs))
	}
	// 0.0.0.0 in allow_listen permits any IPv4 address
	f = fwd()
	f.Listen.Addr = "192.168.5.5"
	p = policy()
	p.AllowListen = []string{"0.0.0.0"}
	if errs := Desired(desired(f), p, opts()); len(errs) != 0 {
		t.Fatalf("wildcard allow:%s", dump(errs))
	}
	f.Listen.Addr = "::1"
	if errs := Desired(desired(f), p, opts()); !find(errs, "listen.addr", "not allowed") {
		t.Fatalf("v6 under v4 wildcard allow must fail:%s", dump(errs))
	}
}

func TestAcceptProxyPublic(t *testing.T) {
	mk := func(addr string) spec.Instance {
		f := fwd()
		f.AcceptProxyProtocol = true
		f.Listen.Addr = addr
		return f
	}
	p := policy()
	p.AllowListen = []string{"127.0.0.1", "10.0.0.0/8", "192.168.0.0/16", "0.0.0.0", "::", "100.64.0.0/10", "203.0.113.0/24", "fd00::/8", "fe80::/10"}
	for _, a := range []string{"127.0.0.1", "10.2.3.4", "192.168.1.1", "fd00::1"} {
		if errs := Desired(desired(mk(a)), p, opts()); find(errs, "accept_proxy_protocol", "forgeable") {
			t.Errorf("%s should be acceptable for PROXY: %s", a, dump(errs))
		}
	}
	for _, a := range []string{"0.0.0.0", "::", "203.0.113.5", "100.64.1.1"} {
		if errs := Desired(desired(mk(a)), p, opts()); !find(errs, "accept_proxy_protocol", "forgeable") {
			t.Errorf("%s is public: want rejection, got %s", a, dump(errs))
		}
	}
	p.AllowAcceptProxyOnPublic = true
	if errs := Desired(desired(mk("0.0.0.0")), p, opts()); len(errs) != 0 {
		t.Errorf("policy opt-in ignored: %s", dump(errs))
	}
}

func TestGlobalRules(t *testing.T) {
	d := desired(fwd())
	d.Version = 2
	if errs := Desired(d, policy(), opts()); !find(errs, "version", "unsupported schema version") {
		t.Fatalf("%s", dump(errs))
	}
	d.Version = 0
	if errs := Desired(d, policy(), opts()); !find(errs, "version", "unsupported schema version") {
		t.Fatalf("%s", dump(errs))
	}

	// duplicate ids
	a, b := fwd(), fwd()
	b.Listen.Ports = "8444"
	errs := Desired(desired(a, b), policy(), opts())
	if !find(errs, "id", "duplicate id") || errs[0].Index != 1 {
		t.Fatalf("%s", dump(errs))
	}

	// instance count limit
	many := make([]spec.Instance, 0, 12)
	for i := 0; i < 12; i++ {
		in := fwd()
		in.ID = fmt.Sprintf("i%d", i)
		in.Listen.Ports = fmt.Sprint(8000 + i)
		many = append(many, in)
	}
	errs = Desired(desired(many...), policy(), opts())
	if !find(errs, "instances", "too many instances: 12") {
		t.Fatalf("%s", dump(errs))
	}
	if errs[0].Index != -1 || errs[0].Instance != "" {
		t.Fatalf("global error must sort first: %+v", errs[0])
	}

	// kernels
	d = desired(fwd())
	d.Kernels = []spec.KernelPin{{Name: "gost", Version: "3.3.0"}, {Name: "gost", Version: "3.3.1"}, {Name: "bash", Version: "1"}, {Name: "realm", Version: "../x"}}
	errs = Desired(d, policy(), opts())
	for _, w := range [][2]string{{"kernels[1].name", "pinned twice"}, {"kernels[2].name", "unknown kernel"}, {"kernels[3].version", "invalid version"}} {
		if !find(errs, w[0], w[1]) {
			t.Errorf("missing %v in:%s", w, dump(errs))
		}
	}
	d.Kernels = []spec.KernelPin{{Name: "gost"}, {Name: "xray", Version: "v26.3.27"}}
	if errs := Desired(d, policy(), opts()); len(errs) != 0 {
		t.Errorf("valid pins rejected:%s", dump(errs))
	}
}

func TestAllowEngines(t *testing.T) {
	p := policy()
	p.AllowEngines = []string{"xray"}
	g := fwd()
	g.Engine = "gost"
	if errs := Desired(desired(g), p, opts()); !find(errs, "engine", "not allowed by the local policy") {
		t.Fatalf("%s", dump(errs))
	}
	g.Engine = "xray"
	if errs := Desired(desired(g), p, opts()); len(errs) != 0 {
		t.Fatalf("%s", dump(errs))
	}
	g.Engine = "auto"
	if errs := Desired(desired(g), p, opts()); len(errs) != 0 {
		t.Fatalf("auto must pass validation (selection filters): %s", dump(errs))
	}
}

func TestListenOverlapAcrossInstances(t *testing.T) {
	a, b := fwd(), fwd()
	b.ID = "b"
	// same address & port
	errs := Desired(desired(a, b), policy(), opts())
	if !find(errs, "listen", "collide with instances[0]") {
		t.Fatalf("%s", dump(errs))
	}
	// overlapping ranges
	a.Listen.Ports, a.Targets[0].Ports = "8000-8009", "100-109"
	b.Listen.Ports, b.Targets[0].Ports = "8005-8012", "100-107"
	errs = Desired(desired(a, b), policy(), opts())
	if !find(errs, "listen", "8005-8009") {
		t.Fatalf("%s", dump(errs))
	}
	// disjoint ranges are fine
	b.Listen.Ports, b.Targets[0].Ports = "8010-8019", "100-109"
	if errs := Desired(desired(a, b), policy(), opts()); len(errs) != 0 {
		t.Fatalf("%s", dump(errs))
	}
	// tcp vs udp of the same port are fine
	a, b = fwd(), fwd()
	b.ID = "b"
	b.Network = []string{"udp"}
	if errs := Desired(desired(a, b), policy(), opts()); len(errs) != 0 {
		t.Fatalf("tcp/udp: %s", dump(errs))
	}
	// a disabled instance does not claim anything
	b.Network = nil
	b.Enabled = false
	if errs := Desired(desired(a, b), policy(), opts()); len(errs) != 0 {
		t.Fatalf("disabled: %s", dump(errs))
	}
	// tunnel listener vs forward listener
	x, e := fwd(), exit()
	x.Listen.Ports = "9443"
	if errs := Desired(desired(x, e), policy(), opts()); !find(errs, "tunnel.listen", "collide") {
		t.Fatalf("%s", dump(errs))
	}
	// kcp/quic carriers are udp: no clash with a tcp forward on the same port
	e.Tunnel.Type = "quic"
	if errs := Desired(desired(x, e), policy(), opts()); len(errs) != 0 {
		t.Fatalf("quic carrier is udp: %s", dump(errs))
	}
}

func TestDisabledInstanceStillChecked(t *testing.T) {
	f := fwd()
	f.Enabled = false
	f.Targets[0].Host = "127.0.0.1"
	if errs := Desired(desired(f), policy(), opts()); !find(errs, "targets[0].host", "loopback") {
		t.Fatalf("%s", dump(errs))
	}
}

func TestDeterministicAndJSON(t *testing.T) {
	bad1, bad2 := fwd(), entry()
	bad1.Targets[0].Host = "127.0.0.1"
	bad1.Listen.Ports = "80"
	bad2.Secret = ""
	bad2.Tunnel.Path = "x"
	d := desired(bad1, bad2)
	first := Desired(d, policy(), opts())
	if len(first) < 4 {
		t.Fatalf("expected several errors: %s", dump(first))
	}
	for i := 0; i < 20; i++ {
		if got := Desired(d, policy(), opts()); !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d differs:%s\nvs%s", i, dump(got), dump(first))
		}
	}
	for i := 1; i < len(first); i++ {
		a, b := first[i-1], first[i]
		if a.Index > b.Index || (a.Index == b.Index && a.Field > b.Field) {
			t.Fatalf("not sorted at %d: %v then %v", i, a, b)
		}
	}
	raw, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	var back []Error
	if err := json.Unmarshal(raw, &back); err != nil || !reflect.DeepEqual(back, first) {
		t.Fatalf("JSON round trip: %v\n%s", err, raw)
	}
	if !strings.Contains(string(raw), `"instance":"fwd"`) || !strings.Contains(string(raw), `"field":"targets[0].host"`) {
		t.Fatalf("unexpected JSON: %s", raw)
	}
	if first[0].Error() == "" {
		t.Fatal("Error() empty")
	}
}

func TestSecretNeverInMessages(t *testing.T) {
	in := entry()
	in.Secret = "bad secret with spaces \"quotes\" and more"
	in.Tunnel.Path = "bad"
	errs := Desired(desired(in), policy(), opts())
	raw, _ := json.Marshal(errs)
	if strings.Contains(string(raw), "bad secret") || strings.Contains(string(raw), "quotes") {
		t.Fatalf("secret leaked in errors: %s", raw)
	}
}

func TestPolicyMalformedFailsClosed(t *testing.T) {
	p := policy()
	p.AllowListen = []string{"127.0.0.1", "not-an-ip"}
	p.DenyCIDRs = []string{"10.0.0.0/99"}
	errs := Desired(desired(fwd()), p, opts())
	if !find(errs, "policy.allow_listen[1]", "invalid") || !find(errs, "policy.deny_cidrs[0]", "invalid CIDR") {
		t.Fatalf("%s", dump(errs))
	}
}

func TestNormalizePolicy(t *testing.T) {
	n := NormalizePolicy(spec.Policy{})
	if n.MaxInstances != DefaultMaxInstances || n.MaxPortsPerInstance != DefaultMaxPortsPerInstance || !reflect.DeepEqual(n.AllowListen, []string{"127.0.0.1"}) {
		t.Fatalf("%+v", n)
	}
	n = NormalizePolicy(spec.Policy{PortRange: [2]int{20000, 0}})
	if n.PortRange != [2]int{20000, 65535} {
		t.Fatalf("%+v", n.PortRange)
	}
	in := spec.Policy{AllowListen: []string{"1.2.3.4"}}
	n = NormalizePolicy(in)
	n.AllowListen[0] = "x"
	if in.AllowListen[0] != "1.2.3.4" {
		t.Fatal("NormalizePolicy aliases its input")
	}
}

func TestMaxPortsDefaultApplies(t *testing.T) {
	f := fwd()
	f.Listen.Ports, f.Targets[0].Ports = "10000-10300", "10000-10300" // 301 > 256 default
	p := spec.Policy{AllowListen: []string{"127.0.0.1"}}
	if errs := Desired(desired(f), p, opts()); !find(errs, "listen.ports", "local policy allows 256") {
		t.Fatalf("%s", dump(errs))
	}
}

func TestPortMapCoversTargets(t *testing.T) {
	f := fwd()
	f.Listen.Ports = "8000-8001"
	f.Targets = nil
	f.Listen.PortMap = map[string]string{"8000": "198.51.100.1:1", "8001": "198.51.100.2:2"}
	if errs := Desired(desired(f), policy(), opts()); len(errs) != 0 {
		t.Fatalf("full port_map should replace targets:%s", dump(errs))
	}
	delete(f.Listen.PortMap, "8001")
	if errs := Desired(desired(f), policy(), opts()); !find(errs, "targets", "at least one target") {
		t.Fatalf("partial port_map needs targets:%s", dump(errs))
	}
	// port_map with a hostile host
	f.Listen.PortMap = map[string]string{"8000": "a;b.com:1", "8001": "198.51.100.2:2"}
	if errs := Desired(desired(f), policy(), opts()); !find(errs, "listen.port_map[8000]", "invalid character") {
		t.Fatalf("%s", dump(errs))
	}
}

// ---- target address policy ---------------------------------------------

func TestTargetHostLiterals(t *testing.T) {
	deny := []struct{ host, substr string }{
		{"127.0.0.1", "loopback"},
		{"127.255.255.254", "loopback"},
		{"::1", "loopback"},
		{"0.0.0.0", "unspecified"},
		{"::", "unspecified"},
		{"169.254.169.254", "link-local"},
		{"169.254.1.1", "link-local"},
		{"fe80::1", "link-local"},
		{"224.0.0.1", "link-local"}, // 224.0.0.0/24 is link-local multicast
		{"239.1.1.1", "multicast"},
		{"ff02::1", "link-local"}, // link-local multicast
		{"ff0e::1", "multicast"},
		{"0.1.2.3", "this network"},
		{"255.255.255.255", "reserved"},
		{"240.0.0.1", "reserved"},
		{"10.0.0.1", "private"},
		{"172.16.5.5", "private"},
		{"172.31.255.255", "private"},
		{"192.168.0.1", "private"},
		{"fd12:3456::1", "private"},
		{"fec0::1", "private"},
		{"100.64.0.1", "carrier-grade"},
		{"100.127.255.254", "carrier-grade"},
		{"::ffff:127.0.0.1", "loopback"},
		{"::ffff:10.0.0.1", "private"},
		{"::ffff:169.254.169.254", "link-local"},
		{"64:ff9b::7f00:1", "embeds"},
		{"64:ff9b::a00:1", "embeds"},
		{"2002:7f00:1::1", "embeds"},
		{"2002:a9fe:a9fe::1", "embeds"},
		{"::7f00:1", "embeds"},
		{"100.100.100.200", "metadata"},
		{"fd00:ec2::254", "metadata"},
		{"168.63.129.16", "metadata"},
		{"192.0.0.192", "metadata"},
	}
	for _, c := range deny {
		f := fwd()
		f.Targets[0].Host = c.host
		errs := Desired(desired(f), policy(), opts())
		if !find(errs, "targets[0].host", c.substr) {
			t.Errorf("%s: want %q, got:%s", c.host, c.substr, dump(errs))
		}
	}
	allow := []string{"198.51.100.1", "8.8.8.8", "1.1.1.1", "2001:db8::1", "2606:4700::1111", "172.15.0.1", "172.32.0.1", "100.63.255.255", "100.128.0.1", "64:ff9b::808:808", "::8.8.8.8"}
	for _, h := range allow {
		f := fwd()
		f.Targets[0].Host = h
		if errs := Desired(desired(f), policy(), opts()); len(errs) != 0 {
			t.Errorf("%s should be allowed:%s", h, dump(errs))
		}
	}
}

func TestAllowPrivatePolicy(t *testing.T) {
	p := policy()
	p.AllowPrivate = true
	for _, h := range []string{"10.0.0.1", "192.168.1.1", "172.20.0.1", "fd12::1", "100.64.0.1"} {
		f := fwd()
		f.Targets[0].Host = h
		if errs := Desired(desired(f), p, opts()); len(errs) != 0 {
			t.Errorf("%s with allow_private:%s", h, dump(errs))
		}
	}
	// Never opened by allow_private:
	for _, h := range []string{"127.0.0.1", "::1", "169.254.169.254", "0.0.0.0", "224.0.0.1", "100.100.100.200", "fd00:ec2::254", "::ffff:127.0.0.1", "fe80::1"} {
		f := fwd()
		f.Targets[0].Host = h
		if errs := Desired(desired(f), p, opts()); !find(errs, "targets[0].host", "") {
			t.Errorf("%s must stay refused with allow_private", h)
		}
	}
}

func TestDenyCIDRsApplyEvenWithAllowPrivate(t *testing.T) {
	p := policy()
	p.AllowPrivate = true
	p.DenyCIDRs = []string{"10.9.0.0/16", "203.0.113.7"}
	for _, h := range []string{"10.9.1.1", "203.0.113.7"} {
		f := fwd()
		f.Targets[0].Host = h
		if errs := Desired(desired(f), p, opts()); !find(errs, "targets[0].host", "deny_cidrs") {
			t.Errorf("%s: %s", h, dump(errs))
		}
	}
	f := fwd()
	f.Targets[0].Host = "10.8.1.1"
	if errs := Desired(desired(f), p, opts()); len(errs) != 0 {
		t.Errorf("%s", dump(errs))
	}
}

func TestHostSyntaxHostile(t *testing.T) {
	bad := []string{
		"", " ", "a b", "a\tb", "a\nb", "a\x00b", `a"b`, "a'b", "a`b", "a#b", "a;b", "a$b", "a|b", "a&b", "a/b", "a\\b", "a?b", "a%b", "a@b",
		"-a.com", "a-.com", "a..com", ".a.com", "a.com.", "a_b.com", "é.com", "例え.jp",
		"localhost", "LOCALHOST", "foo.localhost", "[::1]", "[198.51.100.1]", "198.51.100.1:80", "::1%lo", "fe80::1%eth0",
		// numeric shorthands some resolvers expand to IPs
		"127.1", "2130706433", "0x7f000001", "0x7f.0.0.1", "0177.0.0.1", "1.2.3", "10.1", "4294967295", "1.2.3.4.5",
		strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 130) + "com",
	}
	for _, h := range bad {
		f := fwd()
		f.Targets[0].Host = h
		errs := Desired(desired(f), policy(), opts())
		if !find(errs, "targets[0].host", "") {
			t.Errorf("host %q accepted", h)
		}
	}
	// Syntax errors must not trigger DNS lookups.
	r := &fakeResolver{m: map[string][]string{}}
	f := fwd()
	f.Targets[0].Host = "a;b.com"
	Desired(desired(f), policy(), Options{Resolver: r})
	if r.calls.Load() != 0 {
		t.Error("resolver called for a syntactically invalid host")
	}
}

func TestDNSTargets(t *testing.T) {
	r := &fakeResolver{m: map[string][]string{
		"good.example.com":     {"198.51.100.5", "2001:db8::5"},
		"rebind.example.com":   {"198.51.100.5", "127.0.0.1"}, // any bad answer rejects
		"meta.example.com":     {"169.254.169.254"},
		"private.example.com":  {"192.168.1.10"},
		"mapped.example.com":   {"::ffff:10.0.0.9"},
		"empty.example.com":    {},
		"dualbad.example.com":  {"2001:db8::1", "fe80::1"},
		"nat64bad.example.com": {"64:ff9b::7f00:1"},
	}}
	o := Options{Resolver: r}
	check := func(host string, wantErr string) {
		t.Helper()
		f := fwd()
		f.Targets[0].Host = host
		errs := Desired(desired(f), policy(), o)
		if wantErr == "" {
			if len(errs) != 0 {
				t.Errorf("%s should pass:%s", host, dump(errs))
			}
			return
		}
		if !find(errs, "targets[0].host", wantErr) {
			t.Errorf("%s: want %q, got:%s", host, wantErr, dump(errs))
		}
	}
	check("good.example.com", "")
	check("rebind.example.com", "loopback")
	check("meta.example.com", "link-local")
	check("private.example.com", "private")
	check("mapped.example.com", "private")
	check("empty.example.com", "resolves to no address")
	check("dualbad.example.com", "link-local")
	check("nat64bad.example.com", "embeds")
	check("nxdomain.example.com", "cannot be resolved")

	p := policy()
	p.AllowPrivate = true
	f := fwd()
	f.Targets[0].Host = "private.example.com"
	if errs := Desired(desired(f), p, o); len(errs) != 0 {
		t.Errorf("allow_private should accept: %s", dump(errs))
	}
}

func TestDNSDedupAndAttribution(t *testing.T) {
	r := &fakeResolver{m: map[string][]string{"dup.example.com": {"127.0.0.1"}}}
	a, b := fwd(), bridge()
	a.Targets = []spec.Target{{Host: "dup.example.com", Ports: "1"}, {Host: "dup.example.com", Ports: "2"}}
	a.Listen.Ports = "8443"
	a.Targets[0].Ports, a.Targets[1].Ports = "1", "2"
	b.Targets[0].Host = "dup.example.com"
	errs := Desired(desired(a, b), policy(), Options{Resolver: r})
	if r.calls.Load() != 1 {
		t.Errorf("lookups = %d, want 1 (deduplicated)", r.calls.Load())
	}
	if !find(errs, "targets[0].host", "loopback") || !find(errs, "targets[1].host", "loopback") {
		t.Errorf("both fields must be attributed:%s", dump(errs))
	}
	var onBridge bool
	for _, e := range errs {
		if e.Instance == "br" && e.Field == "targets[0].host" {
			onBridge = true
		}
	}
	if !onBridge {
		t.Errorf("error missing for the second instance:%s", dump(errs))
	}
}

func TestDNSSkippedForDisabled(t *testing.T) {
	r := &fakeResolver{m: map[string][]string{}}
	f := fwd()
	f.Enabled = false
	f.Targets[0].Host = "stale.example.com"
	errs := Desired(desired(f), policy(), Options{Resolver: r})
	if len(errs) != 0 || r.calls.Load() != 0 {
		t.Fatalf("disabled instance must not be resolved: calls=%d errs=%s", r.calls.Load(), dump(errs))
	}
}

func TestDNSTimeout(t *testing.T) {
	r := &fakeResolver{m: map[string][]string{"slow.example.com": {"198.51.100.5"}}, delay: 5 * time.Second}
	f := fwd()
	f.Targets[0].Host = "slow.example.com"
	start := time.Now()
	errs := Desired(desired(f), policy(), Options{Resolver: r, ResolveTimeout: 50 * time.Millisecond})
	if time.Since(start) > 2*time.Second {
		t.Fatalf("timeout not honoured: %v", time.Since(start))
	}
	if !find(errs, "targets[0].host", "cannot be resolved") {
		t.Fatalf("%s", dump(errs))
	}
}

func TestDNSManyHostsConcurrent(t *testing.T) {
	m := map[string][]string{}
	var ins []spec.Instance
	for i := 0; i < 10; i++ {
		h := fmt.Sprintf("h%d.example.com", i)
		m[h] = []string{"198.51.100.5"}
		in := fwd()
		in.ID = fmt.Sprintf("i%d", i)
		in.Listen.Ports = fmt.Sprint(8000 + i)
		in.Targets[0].Host = h
		ins = append(ins, in)
	}
	r := &fakeResolver{m: m, delay: 100 * time.Millisecond}
	start := time.Now()
	errs := Desired(desired(ins...), policy(), Options{Resolver: r})
	if len(errs) != 0 {
		t.Fatalf("%s", dump(errs))
	}
	if el := time.Since(start); el > 700*time.Millisecond {
		t.Fatalf("lookups look sequential: %v", el)
	}
}

func TestTunnelServerPolicy(t *testing.T) {
	e := entry()
	e.Tunnel.Server = "127.0.0.1:443"
	if errs := Desired(desired(e), policy(), opts()); !find(errs, "tunnel.server", "loopback") {
		t.Fatalf("%s", dump(errs))
	}
	e.Tunnel.Server = "198.51.100.1"
	if errs := Desired(desired(e), policy(), opts()); !find(errs, "tunnel.server", "host:port") {
		t.Fatalf("%s", dump(errs))
	}
	e.Tunnel.Server = "198.51.100.1:99999"
	if errs := Desired(desired(e), policy(), opts()); !find(errs, "tunnel.server", "port") {
		t.Fatalf("%s", dump(errs))
	}
	e.Tunnel.Server = "[2001:db8::1]:443"
	if errs := Desired(desired(e), policy(), opts()); len(errs) != 0 {
		t.Fatalf("%s", dump(errs))
	}
	e.Tunnel.Server = "10.0.0.5:443"
	if errs := Desired(desired(e), policy(), opts()); !find(errs, "tunnel.server", "private") {
		t.Fatalf("%s", dump(errs))
	}
}

func TestDomainEntropy(t *testing.T) {
	good := []string{
		goodDomain,
		strings.Repeat("0123456789abcdef", 4),
		"Zm9vYmFyLWJhel9xdXV4MDEy",         // base64url, 24
		"q83Lx_9-aB2cD4eF6gH8iJ",           // 22
		"AbCdEfGhIjKlMnOpQrStUv",           // 22
		strings.Repeat("aBcD1234_-xYz", 9), // 117
	}
	for _, s := range good {
		if m := domainEntropy(s); m != "" {
			t.Errorf("%q rejected: %s", s, m)
		}
	}
	bad := []string{"", "abc", strings.Repeat("0", 32), strings.Repeat("ab", 16), "AAAAAAAAAAAAAAAAAAAAAAAA", "abcdefabcdefabcdefabcd", "has space xxxxxxxxxxxxxxxx", "dot.dot.dot.dot.dot.dot.dot"}
	for _, s := range bad {
		if m := domainEntropy(s); m == "" {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestIPv4MappedAndTargetsRanges(t *testing.T) {
	f := fwd()
	f.Listen.Ports = "9000-9002"
	f.Targets = []spec.Target{{Host: "198.51.100.10", Ports: "443-445", Weight: 3}, {Host: "198.51.100.11", Ports: "443-445"}}
	f.Balance = &spec.Balance{Strategy: "round_robin", Health: &spec.Health{Type: "http", ProbeURL: "/healthz", IntervalS: 5, TimeoutS: 2, MaxFails: 3}}
	if errs := Desired(desired(f), policy(), opts()); len(errs) != 0 {
		t.Fatalf("%s", dump(errs))
	}
}

func TestErrorCountBoundedByInstanceCap(t *testing.T) {
	// A hostile desired state with a huge instance list is cut at the policy
	// limit before per-instance work happens.
	var ins []spec.Instance
	for i := 0; i < 5000; i++ {
		in := fwd()
		in.ID = "!!"
		ins = append(ins, in)
	}
	errs := Desired(desired(ins...), policy(), opts())
	if len(errs) > 100 {
		t.Fatalf("errors not bounded: %d", len(errs))
	}
	if !find(errs, "instances", "too many instances: 5000") {
		t.Fatalf("%s", dump(errs))
	}
}
