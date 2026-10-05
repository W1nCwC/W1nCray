package frp

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/W1nCwC/W1nCray/agent/spec"
)

// supportedTunnelTypes are the spec Tunnel.Type values this driver accepts
// (spec name -> frp transport.protocol, see tunnelTypes). Each one is covered
// by an e2e test against the real frp binaries.
var supportedTunnelTypes = []string{"tcp", "tls", "ws", "kcp", "quic"}

// tunnelTypes maps a spec Tunnel.Type to frp's transport.protocol and tells
// whether TLS is mandatory for it.
var tunnelTypes = map[string]struct {
	frp         string
	tlsRequired bool
}{
	"tcp":  {"tcp", false},
	"tls":  {"tcp", true},
	"ws":   {"websocket", false},
	"kcp":  {"kcp", false},
	"quic": {"quic", true}, // frp always runs QUIC inside TLS
}

const (
	maxPortsPerInstance = 1024
	minSecretLen        = 16
	maxSecretLen        = 128
)

var (
	idRe     = regexp.MustCompile(`^[a-z0-9_-]{1,40}$`)
	secretRe = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]+$`)
	labelRe  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	pathRe   = regexp.MustCompile(`^/[A-Za-z0-9/_.~%?&=+-]{0,199}$`)
)

// role of a plan.
const (
	rolePortal = "portal"
	roleBridge = "bridge"
)

// proxyDef is one frpc proxy.
type proxyDef struct {
	Name      string
	Type      string // tcp | udp
	Remote    int
	LocalHost string
	LocalPort int
}

type healthPlan struct {
	Type     string // tcp | http
	Interval int
	Timeout  int
	MaxFails int
	Path     string
}

// plan is the validated, strongly typed form of an instance. Everything that
// reaches a config file is derived from it.
type plan struct {
	ID       string
	Role     string
	Networks []string // canonical order: tcp, udp
	Secret   string

	Transport string // frp transport.protocol
	TLS       bool

	// portal
	BindAddr      string
	BindPort      int
	ProxyBindAddr string
	CertFile      string
	KeyFile       string
	Public        []int // ascending

	// bridge
	ServerHost string
	ServerPort int
	ServerName string
	TrustedCA  string
	ProxyProto string // "" | v1 | v2
	Health     *healthPlan
	Proxies    []proxyDef
}

func errf(format string, args ...any) error {
	return fmt.Errorf("frp: "+format, args...)
}

// short limits attacker-controlled text echoed in errors.
func short(s string) string {
	const max = 40
	if len(s) > max {
		s = s[:max] + "..."
	}
	return strconv.QuoteToASCII(s)
}

// Validate implements driver.Driver. It does not touch the system.
func (d *Driver) Validate(in spec.Instance) error {
	_, err := buildPlan(in)
	return err
}

// validHost accepts an IP literal (no zone) or a DNS name.
func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Zone() == ""
	}
	for _, l := range strings.Split(h, ".") {
		if !labelRe.MatchString(l) {
			return false
		}
	}
	return true
}

func parsePort(s string) (int, error) {
	if s == "" || len(s) > 5 {
		return 0, fmt.Errorf("invalid port %s", short(s))
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid port %s", short(s))
		}
	}
	n, _ := strconv.Atoi(s)
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %d out of range", n)
	}
	return n, nil
}

// parsePorts parses "8443" or "20000-20009".
func parsePorts(s string) (lo, hi int, err error) {
	if i := strings.IndexByte(s, '-'); i >= 0 {
		if lo, err = parsePort(s[:i]); err != nil {
			return
		}
		if hi, err = parsePort(s[i+1:]); err != nil {
			return
		}
		if hi < lo {
			return 0, 0, fmt.Errorf("port range %s is reversed", short(s))
		}
		return
	}
	lo, err = parsePort(s)
	return lo, lo, err
}

func parseHostPort(s string) (string, int, error) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, fmt.Errorf("invalid host:port %s", short(s))
	}
	if !validHost(h) {
		return "", 0, fmt.Errorf("invalid host in %s", short(s))
	}
	n, err := parsePort(p)
	if err != nil {
		return "", 0, err
	}
	return h, n, nil
}

// validPath checks a file path that is written into a config file. Paths come
// from the agent's own cert handling; still, only a conservative character set
// is accepted ({ } " ' # $ ` and control characters are never allowed).
func validPath(p string) bool {
	if p == "" || len(p) > 512 {
		return false
	}
	abs := strings.HasPrefix(p, "/") ||
		(len(p) > 2 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') &&
			((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z')))
	if !abs {
		return false
	}
	for _, r := range p {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune(" _-./\\:+@~()", r):
		default:
			return false
		}
	}
	return !strings.Contains(p, "..")
}

func canonicalNetwork(n []string) ([]string, error) {
	if len(n) == 0 {
		return []string{"tcp"}, nil
	}
	var tcp, udp bool
	for _, v := range n {
		switch v {
		case "tcp":
			tcp = true
		case "udp":
			udp = true
		default:
			return nil, errf("unsupported network %s", short(v))
		}
	}
	var out []string
	if tcp {
		out = append(out, "tcp")
	}
	if udp {
		out = append(out, "udp")
	}
	return out, nil
}

func hasNet(n []string, want string) bool {
	for _, v := range n {
		if v == want {
			return true
		}
	}
	return false
}

// buildPlan validates in and converts it to a plan.
func buildPlan(in spec.Instance) (*plan, error) {
	if in.Engine != spec.EngineFrp && in.Engine != spec.EngineAuto {
		return nil, errf("instance engine is %s, not frp", short(in.Engine))
	}
	if !idRe.MatchString(in.ID) {
		return nil, errf("invalid instance id %s", short(in.ID))
	}
	p := &plan{ID: in.ID}
	switch in.Kind {
	case spec.KindReversePortal:
		p.Role = rolePortal
	case spec.KindReverseBridge:
		p.Role = roleBridge
	default:
		return nil, errf("kind %s is not supported (frp only does reverse_portal and reverse_bridge)", short(string(in.Kind)))
	}

	var err error
	if p.Networks, err = canonicalNetwork(in.Network); err != nil {
		return nil, err
	}

	// Features frp cannot express are rejected, never ignored.
	if in.AcceptProxyProtocol {
		return nil, errf("accept_proxy_protocol is not supported: frps cannot read a PROXY header on its public ports")
	}
	if in.AllowAnyTarget {
		return nil, errf("allow_any_target is not supported: the destinations of a frp bridge are fixed by its own config")
	}
	if in.IdleProfile != "" {
		return nil, errf("idle_profile is not supported: frp has no per-proxy idle timeout")
	}
	if l := in.Limits; l != nil && (l.MaxConns != 0 || l.RateUpBps != 0 || l.RateDownBps != 0) {
		return nil, errf("limits are not supported: frp has one shared bandwidthLimit and no connection cap per proxy")
	}
	if a := in.ACL; a != nil && (len(a.Allow) > 0 || len(a.Deny) > 0) {
		return nil, errf("acl is not supported: frp has no source address filter")
	}
	if in.ProxyProtocolOut != 0 {
		if in.Kind != spec.KindReverseBridge {
			return nil, errf("proxy_protocol_out is only meaningful on reverse_bridge (frpc writes the header)")
		}
		if in.ProxyProtocolOut != 1 && in.ProxyProtocolOut != 2 {
			return nil, errf("proxy_protocol_out must be 0, 1 or 2")
		}
		if hasNet(p.Networks, "udp") {
			return nil, errf("proxy_protocol_out is TCP only and cannot be combined with network udp")
		}
		p.ProxyProto = "v" + strconv.Itoa(in.ProxyProtocolOut)
	}

	// Secret.
	if l := len(in.Secret); l < minSecretLen || l > maxSecretLen || !secretRe.MatchString(in.Secret) {
		return nil, errf("secret must be %d-%d characters of [A-Za-z0-9._~+/=-]", minSecretLen, maxSecretLen)
	}
	p.Secret = in.Secret

	if err := p.tunnel(in); err != nil {
		return nil, err
	}
	if p.Role == rolePortal {
		err = p.portal(in)
	} else {
		err = p.bridge(in)
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

// tunnel validates the Tunnel section common to both roles.
func (p *plan) tunnel(in spec.Instance) error {
	t := in.Tunnel
	if t == nil {
		return errf("tunnel is required")
	}
	typ := t.Type
	if typ == "" {
		typ = "tcp"
	}
	if typ == "wss" {
		return errf("tunnel type wss is not supported: frps does not terminate wss itself (tested: frpc gets an EOF); it needs a TLS-terminating reverse proxy in front")
	}
	tt, ok := tunnelTypes[typ]
	if !ok {
		return errf("tunnel type %s is not supported (supported: %s)", short(typ), strings.Join(supportedTunnelTypes, ", "))
	}
	p.Transport = tt.frp

	if t.Host != "" || t.Path != "" || len(t.ALPN) > 0 {
		return errf("tunnel host, path and alpn are not supported: frp fixes the websocket path and ALPN")
	}
	if t.PinSHA256 != "" {
		return errf("pin_sha256 is not supported: frp cannot pin a certificate hash")
	}
	switch t.Security {
	case "":
		// frp's default is TLS on; keep it.
		p.TLS = true
	case "tls":
		p.TLS = true
	case "none":
		p.TLS = false
	case "tls_pin":
		return errf("security tls_pin is not supported: frp cannot pin a certificate hash")
	case "vless_enc":
		return errf("security vless_enc is only available with the xray engine")
	default:
		return errf("unknown tunnel security %s", short(t.Security))
	}
	if tt.tlsRequired && !p.TLS {
		return errf("tunnel type %s always runs over TLS; security none cannot be honoured", short(typ))
	}
	if tt.tlsRequired {
		p.TLS = true
	}
	return nil
}

func (p *plan) portal(in spec.Instance) error {
	if len(in.Targets) > 0 || (in.Listen != nil && len(in.Listen.PortMap) > 0) {
		return errf("a frp portal cannot choose targets: set targets/port_map on the reverse_bridge instance")
	}
	if in.Balance != nil {
		return errf("balance is not supported on a frp portal")
	}
	if in.Listen == nil {
		return errf("listen is required on a reverse_portal")
	}
	addr, err := netip.ParseAddr(in.Listen.Addr)
	if err != nil || addr.Zone() != "" {
		return errf("listen.addr must be an IP address, got %s", short(in.Listen.Addr))
	}
	p.ProxyBindAddr = addr.String()
	lo, hi, err := parsePorts(in.Listen.Ports)
	if err != nil {
		return errf("listen.ports: %v", err)
	}
	if hi-lo+1 > maxPortsPerInstance {
		return errf("listen.ports covers %d ports, limit is %d", hi-lo+1, maxPortsPerInstance)
	}
	for q := lo; q <= hi; q++ {
		p.Public = append(p.Public, q)
	}

	t := in.Tunnel
	if t.Server != "" {
		return errf("tunnel.server must be empty on a reverse_portal (use tunnel.listen)")
	}
	ap, err := netip.ParseAddrPort(t.Listen)
	if err != nil || ap.Addr().Zone() != "" || ap.Port() == 0 {
		return errf("tunnel.listen must be ip:port, got %s", short(t.Listen))
	}
	p.BindAddr = ap.Addr().String()
	p.BindPort = int(ap.Port())
	// The control port is bound as TCP always, as UDP for kcp/quic. A public
	// port with the same number could collide on the same address family.
	for _, q := range p.Public {
		if q == p.BindPort {
			return errf("public port %d collides with the control port", q)
		}
	}

	if t.SNI != "" {
		return errf("tunnel.sni is only used by a reverse_bridge")
	}
	if c := t.Cert; c != nil {
		switch c.Mode {
		case "", "self":
			if c.CertFile != "" || c.KeyFile != "" {
				return errf("cert files given but cert.mode is self")
			}
		case "file", "panel":
			if !validPath(c.CertFile) || !validPath(c.KeyFile) {
				return errf("cert.cert_file and cert.key_file must be absolute paths of plain characters")
			}
			p.CertFile, p.KeyFile = c.CertFile, c.KeyFile
		default:
			return errf("unknown cert mode %s", short(c.Mode))
		}
		if !p.TLS {
			return errf("a certificate was given but tunnel security is none")
		}
	}
	return nil
}

func (p *plan) bridge(in spec.Instance) error {
	t := in.Tunnel
	if t.Listen != "" {
		return errf("tunnel.listen must be empty on a reverse_bridge (use tunnel.server)")
	}
	h, port, err := parseHostPort(t.Server)
	if err != nil {
		return errf("tunnel.server: %v", err)
	}
	p.ServerHost, p.ServerPort = h, port
	if t.SNI != "" {
		if !validHost(t.SNI) {
			return errf("invalid tunnel.sni %s", short(t.SNI))
		}
		if !p.TLS {
			return errf("tunnel.sni given but tunnel security is none")
		}
		p.ServerName = t.SNI
	}
	// Convention: on a bridge Cert.CertFile is the trust anchor (CA or the
	// portal's own certificate) used to verify the portal. KeyFile (client
	// certificate / mTLS) is not supported.
	if c := t.Cert; c != nil {
		if c.KeyFile != "" {
			return errf("client certificates (cert.key_file) are not supported")
		}
		switch c.Mode {
		case "", "file":
		default:
			return errf("cert.mode %s is not usable on a bridge (use file with cert_file as trust anchor)", short(c.Mode))
		}
		if c.CertFile != "" {
			if !p.TLS {
				return errf("a trust anchor was given but tunnel security is none")
			}
			if !validPath(c.CertFile) {
				return errf("cert.cert_file must be an absolute path of plain characters")
			}
			p.TrustedCA = c.CertFile
		}
	}

	if in.Listen == nil || in.Listen.Ports == "" {
		return errf("listen.ports (the public ports registered on the portal) is required on a reverse_bridge")
	}
	lo, hi, err := parsePorts(in.Listen.Ports)
	if err != nil {
		return errf("listen.ports: %v", err)
	}
	n := hi - lo + 1
	if n > maxPortsPerInstance {
		return errf("listen.ports covers %d ports, limit is %d", n, maxPortsPerInstance)
	}

	// Per-port target resolution: PortMap beats Targets.
	portMap := map[int]struct {
		host string
		port int
	}{}
	for k, v := range in.Listen.PortMap {
		kp, err := parsePort(k)
		if err != nil || kp < lo || kp > hi {
			return errf("port_map key %s is not inside listen.ports", short(k))
		}
		h, tp, err := parseHostPort(v)
		if err != nil {
			return errf("port_map[%s]: %v", k, err)
		}
		portMap[kp] = struct {
			host string
			port int
		}{h, tp}
	}

	var tgtHost string
	var tgtLo, tgtN int
	switch len(in.Targets) {
	case 0:
		if len(portMap) != n {
			return errf("targets is empty and port_map does not cover every listen port")
		}
	case 1:
		tg := in.Targets[0]
		if tg.Weight > 1 {
			return errf("target weights are not supported")
		}
		if !validHost(tg.Host) {
			return errf("invalid target host %s", short(tg.Host))
		}
		tl, th, err := parsePorts(tg.Ports)
		if err != nil {
			return errf("target ports: %v", err)
		}
		tgtHost, tgtLo, tgtN = tg.Host, tl, th-tl+1
		if tgtN != n {
			return errf("target ports (%d) and listen.ports (%d) must have the same length", tgtN, n)
		}
	default:
		return errf("several targets would need load balancing, which this driver does not support")
	}

	if in.Balance != nil {
		if s := in.Balance.Strategy; s != "" && s != "failover" {
			return errf("balance strategy %s is not supported (a frp bridge has one target per port)", short(s))
		}
		if h := in.Balance.Health; h != nil {
			if hasNet(p.Networks, "udp") {
				return errf("health checks are TCP only and cannot be combined with network udp")
			}
			hp := &healthPlan{Type: h.Type, Interval: h.IntervalS, Timeout: h.TimeoutS, MaxFails: h.MaxFails}
			switch h.Type {
			case "tcp":
				if h.ProbeURL != "" {
					return errf("probe_url is only used by http health checks")
				}
			case "http":
				if !pathRe.MatchString(h.ProbeURL) {
					return errf("probe_url must be a request path like /healthz (frp probes the local target address)")
				}
				hp.Path = h.ProbeURL
			default:
				return errf("health type %s is not supported", short(h.Type))
			}
			if hp.Interval < 0 || hp.Interval > 3600 || hp.Timeout < 0 || hp.Timeout > 600 || hp.MaxFails < 0 || hp.MaxFails > 100 {
				return errf("health interval/timeout/max_fails out of range")
			}
			p.Health = hp
		}
	}

	// BridgeAllow: with frp the destinations are fixed here; the allow list is
	// a consistency check, the portal cannot ask for anything else anyway.
	idx := 0
	for q := lo; q <= hi; q, idx = q+1, idx+1 {
		var host string
		var port int
		if m, ok := portMap[q]; ok {
			host, port = m.host, m.port
		} else {
			host, port = tgtHost, tgtLo+idx
		}
		if r := in.Reverse; r != nil && len(r.BridgeAllow) > 0 && !allowed(r.BridgeAllow, host, port) {
			return errf("target %s:%d is not covered by reverse.bridge_allow", host, port)
		}
		for _, nw := range p.Networks {
			letter := "t"
			if nw == "udp" {
				letter = "u"
			}
			p.Proxies = append(p.Proxies, proxyDef{
				Name:      fmt.Sprintf("%s.%s%d", p.ID, letter, q),
				Type:      nw,
				Remote:    q,
				LocalHost: host,
				LocalPort: port,
			})
		}
	}
	sort.SliceStable(p.Proxies, func(i, j int) bool {
		if p.Proxies[i].Type != p.Proxies[j].Type {
			return p.Proxies[i].Type < p.Proxies[j].Type // tcp before udp
		}
		return p.Proxies[i].Remote < p.Proxies[j].Remote
	})
	return nil
}

func allowed(list []spec.Allow, host string, port int) bool {
	for _, a := range list {
		if a.Host != host {
			continue
		}
		lo, hi, err := parsePorts(a.Ports)
		if err == nil && port >= lo && port <= hi {
			return true
		}
	}
	return false
}
