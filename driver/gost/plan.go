package gost

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/W1nCwC/W1nCray/agent/spec"
)

// Limits on what a single instance may expand to. A listen range becomes one
// gost service per port and protocol, so this bounds memory and API traffic.
const defaultMaxListenPorts = 1024

// Idle presets (spec.Instance.IdleProfile). The tcp_* presets map to the
// handler's idleTimeout, the udp_* presets to the UDP listener's session ttl.
// Without a profile TCP has no idle timeout (gost default; keep-alives detect
// dead peers) and UDP sessions live 60 s instead of gost's 5 s default, which
// would drop typical UDP flows (WireGuard, QUIC, DNS over reused sockets).
const (
	idleTCPLong    = 3600 * time.Second
	idleTCPDefault = 300 * time.Second
	idleUDPShort   = 30 * time.Second
	idleUDPLong    = 120 * time.Second
	idleUDPDefault = 60 * time.Second
)

// Whitelists. Anything that reaches the gost configuration as a free-form
// string must match one of these (or be a netip/uint16 value re-formatted by
// us): whitespace, quotes, control characters, '#', ';', '$', '`', ',' and
// backslashes are rejected, and so is every other character not listed.
var (
	reID     = regexp.MustCompile(`^[a-z0-9_-]{1,40}$`)
	reLabel  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	rePath   = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{0,127}$`)
	reSecret = regexp.MustCompile(`^[\x21-\x7e]{16,256}$`)
	// Absolute file path, POSIX or Windows drive style; no whitespace, quotes,
	// shell or config metacharacters.
	reFile = regexp.MustCompile(`^(/|[A-Za-z]:[\\/])[A-Za-z0-9._/\\:@+~=-]{0,250}$`)
)

type hostPort struct {
	host string // validated DNS name or IP literal, no brackets
	port int
}

func (h hostPort) String() string { return net.JoinHostPort(h.host, strconv.Itoa(h.port)) }

type portRange struct {
	start, count int
}

func (r portRange) at(i int) int { return r.start + i }

type target struct {
	host   string
	ports  portRange
	weight int
}

type balancePlan struct {
	strategy    string // gost strategy name
	maxFails    int
	failTimeout time.Duration
}

type tunnelPlan struct {
	typ      string // tcp|tls|ws|wss|grpc
	tlsBased bool
	server   hostPort       // entry / bridge
	listen   netip.AddrPort // exit / portal
	path     string
	hostHdr  string
	sni      string
	certFile string // exit/portal: served cert; entry/bridge: CA file
	keyFile  string
	selfCert bool
}

// plan is the validated, normalised form of a spec.Instance. Validate and
// Render share it, so Render can never emit anything Validate did not accept.
type plan struct {
	id      string
	kind    spec.Kind
	nets    []string // "tcp", "udp"
	listen  netip.Addr
	lports  portRange
	hasLis  bool
	portMap map[int]hostPort
	targets []target
	balance *balancePlan

	proxyOut int
	proxyIn  bool

	idleTCP time.Duration // 0 = unset
	idleUDP time.Duration

	maxConns int
	rateUp   int64 // bytes/s
	rateDown int64

	allow []string
	deny  []string

	anyTarget bool
	secret    string
	tun       *tunnelPlan
}

func (p *plan) hasNet(n string) bool {
	for _, v := range p.nets {
		if v == n {
			return true
		}
	}
	return false
}

func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Zone() == ""
	}
	for _, l := range strings.Split(h, ".") {
		if !reLabel.MatchString(l) {
			return false
		}
	}
	return true
}

func parsePortNum(s string) (int, error) {
	if s == "" || len(s) > 5 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid port %q", s)
		}
	}
	n, _ := strconv.Atoi(s)
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %q out of range 1-65535", s)
	}
	return n, nil
}

// parsePorts parses "N" or "N-M".
func parsePorts(s string, max int) (portRange, error) {
	if i := strings.IndexByte(s, '-'); i >= 0 {
		a, err := parsePortNum(s[:i])
		if err != nil {
			return portRange{}, err
		}
		b, err := parsePortNum(s[i+1:])
		if err != nil {
			return portRange{}, err
		}
		if b < a {
			return portRange{}, fmt.Errorf("port range %q is reversed", s)
		}
		if b-a+1 > max {
			return portRange{}, fmt.Errorf("port range %q has %d ports, limit is %d", s, b-a+1, max)
		}
		return portRange{a, b - a + 1}, nil
	}
	n, err := parsePortNum(s)
	if err != nil {
		return portRange{}, err
	}
	return portRange{n, 1}, nil
}

// parseHostPort parses "host:port" with a whitelisted host.
func parseHostPort(s string) (hostPort, error) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return hostPort{}, fmt.Errorf("invalid host:port %q", s)
	}
	if !validHost(h) {
		return hostPort{}, fmt.Errorf("invalid host %q", h)
	}
	n, err := parsePortNum(p)
	if err != nil {
		return hostPort{}, err
	}
	return hostPort{h, n}, nil
}

func parseACLEntry(s string) (string, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked().String(), nil
	}
	if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
		return a.String(), nil
	}
	return "", fmt.Errorf("acl entry %q is not an IP address or CIDR", s)
}

func supportedKind(k spec.Kind) bool {
	switch k {
	case spec.KindForward, spec.KindTunnelEntry, spec.KindTunnelExit,
		spec.KindReversePortal, spec.KindReverseBridge:
		return true
	}
	return false
}

var tunnelTLSBased = map[string]bool{"tcp": false, "ws": false, "tls": true, "wss": true, "grpc": true}

// analyze validates in and returns its normalised plan.
func (d *Driver) analyze(in spec.Instance) (*plan, error) {
	if in.Engine != spec.EngineGost && in.Engine != spec.EngineAuto && in.Engine != "" {
		return nil, fmt.Errorf("instance engine %q is not gost", in.Engine)
	}
	if !reID.MatchString(in.ID) {
		return nil, fmt.Errorf("invalid instance id %q (want [a-z0-9_-]{1,40})", in.ID)
	}
	if !supportedKind(in.Kind) {
		return nil, fmt.Errorf("unsupported instance kind %q", in.Kind)
	}
	p := &plan{id: in.ID, kind: in.Kind, portMap: map[int]hostPort{}, secret: in.Secret}
	maxPorts := d.opts.MaxListenPorts

	// Networks.
	if len(in.Network) == 0 {
		p.nets = []string{"tcp"}
	} else {
		seen := map[string]bool{}
		for _, n := range in.Network {
			if n != "tcp" && n != "udp" {
				return nil, fmt.Errorf("unsupported network %q", n)
			}
			if !seen[n] {
				seen[n] = true
				p.nets = append(p.nets, n)
			}
		}
		// Deterministic order regardless of input order.
		if len(p.nets) == 2 && p.nets[0] == "udp" {
			p.nets[0], p.nets[1] = p.nets[1], p.nets[0]
		}
	}

	// PROXY protocol. gost sends it on the dialled stream; for UDP it would be
	// an independent first datagram, so it is refused (the spec layer refuses
	// it as well, this keeps the driver safe on its own).
	if in.ProxyProtocolOut < 0 || in.ProxyProtocolOut > 2 {
		return nil, fmt.Errorf("proxy_protocol_out must be 0, 1 or 2")
	}
	if in.ProxyProtocolOut > 0 && p.hasNet("udp") {
		return nil, fmt.Errorf("proxy_protocol_out is TCP only and cannot be combined with network udp")
	}
	p.proxyOut = in.ProxyProtocolOut
	if in.AcceptProxyProtocol {
		if p.hasNet("udp") {
			return nil, fmt.Errorf("accept_proxy_protocol is TCP only and cannot be combined with network udp")
		}
		p.proxyIn = true
	}

	// Idle profile.
	switch in.IdleProfile {
	case "":
	case "tcp_long":
		p.idleTCP = idleTCPLong
	case "tcp_default":
		p.idleTCP = idleTCPDefault
	case "udp_short":
		p.idleUDP = idleUDPShort
	case "udp_long":
		p.idleUDP = idleUDPLong
	default:
		return nil, fmt.Errorf("unknown idle_profile %q", in.IdleProfile)
	}
	if p.idleUDP == 0 {
		p.idleUDP = idleUDPDefault
	}

	// Limits.
	if l := in.Limits; l != nil {
		if l.MaxConns < 0 || l.RateUpBps < 0 || l.RateDownBps < 0 {
			return nil, fmt.Errorf("limits must not be negative")
		}
		p.maxConns = l.MaxConns
		p.rateUp = (l.RateUpBps + 7) / 8
		p.rateDown = (l.RateDownBps + 7) / 8
	}

	// ACL.
	if a := in.ACL; a != nil {
		for _, s := range a.Allow {
			v, err := parseACLEntry(s)
			if err != nil {
				return nil, err
			}
			p.allow = append(p.allow, v)
		}
		for _, s := range a.Deny {
			v, err := parseACLEntry(s)
			if err != nil {
				return nil, err
			}
			p.deny = append(p.deny, v)
		}
	}

	switch in.Kind {
	case spec.KindForward, spec.KindTunnelEntry, spec.KindReverseBridge:
		// Listener-per-port kinds.
	case spec.KindTunnelExit, spec.KindReversePortal:
		if in.ProxyProtocolOut > 0 {
			return nil, fmt.Errorf("proxy_protocol_out is not supported on %s (gost's relay handler cannot send PROXY headers; set it on the tunnel entry instead)", in.Kind)
		}
		if in.Limits != nil && (in.Limits.MaxConns > 0 || in.Limits.RateUpBps > 0 || in.Limits.RateDownBps > 0) {
			return nil, fmt.Errorf("limits are not supported on %s", in.Kind)
		}
	}
	if p.proxyIn && in.Kind != spec.KindForward && in.Kind != spec.KindTunnelEntry {
		return nil, fmt.Errorf("accept_proxy_protocol is only supported on forward and tunnel_entry instances")
	}
	if in.Kind == spec.KindReversePortal && (len(p.allow) > 0 || len(p.deny) > 0) {
		// The public port of a gost portal is bound by the relay handler
		// itself and has no admission hook; an ACL on the control listener
		// would filter bridges, not users, which is not what an ACL on a
		// portal is expected to mean.
		return nil, fmt.Errorf("acl is not supported on reverse_portal (the portal's public listener cannot be filtered in gost)")
	}

	// Listen.
	needListen := in.Kind == spec.KindForward || in.Kind == spec.KindTunnelEntry || in.Kind == spec.KindReverseBridge
	if in.Listen != nil && (in.Listen.Addr != "" || in.Listen.Ports != "" || len(in.Listen.PortMap) > 0) {
		if in.Listen.Ports == "" {
			return nil, fmt.Errorf("listen.ports is required")
		}
		r, err := parsePorts(in.Listen.Ports, maxPorts)
		if err != nil {
			return nil, fmt.Errorf("listen.ports: %w", err)
		}
		p.lports, p.hasLis = r, true
		switch {
		case in.Listen.Addr != "":
			a, err := netip.ParseAddr(in.Listen.Addr)
			if err != nil || a.Zone() != "" {
				return nil, fmt.Errorf("listen.addr %q is not an IP address", in.Listen.Addr)
			}
			p.listen = a
		case in.Kind == spec.KindReverseBridge:
			p.listen = netip.IPv4Unspecified()
		default:
			return nil, fmt.Errorf("listen.addr is required")
		}
		for k, v := range in.Listen.PortMap {
			kp, err := parsePortNum(k)
			if err != nil {
				return nil, fmt.Errorf("listen.port_map key: %w", err)
			}
			if kp < r.start || kp >= r.start+r.count {
				return nil, fmt.Errorf("listen.port_map key %d is outside listen.ports", kp)
			}
			hp, err := parseHostPort(v)
			if err != nil {
				return nil, fmt.Errorf("listen.port_map[%s]: %w", k, err)
			}
			p.portMap[kp] = hp
		}
		if in.Kind == spec.KindTunnelExit {
			return nil, fmt.Errorf("listen is not used by tunnel_exit (the exit accepts the tunnel on tunnel.listen)")
		}
	} else if needListen {
		return nil, fmt.Errorf("listen is required for %s", in.Kind)
	}

	// Targets.
	for i, t := range in.Targets {
		if !validHost(t.Host) {
			return nil, fmt.Errorf("targets[%d].host %q is invalid", i, t.Host)
		}
		r, err := parsePorts(t.Ports, maxPorts)
		if err != nil {
			return nil, fmt.Errorf("targets[%d].ports: %w", i, err)
		}
		if t.Weight < 0 || t.Weight > 1000 {
			return nil, fmt.Errorf("targets[%d].weight out of range 0-1000", i)
		}
		w := t.Weight
		if w == 0 {
			w = 1
		}
		p.targets = append(p.targets, target{t.Host, r, w})
	}
	p.anyTarget = in.AllowAnyTarget

	// Balance.
	if err := p.planBalance(in); err != nil {
		return nil, err
	}

	if in.AllowAnyTarget && in.Kind != spec.KindTunnelExit {
		return nil, fmt.Errorf("allow_any_target only applies to tunnel_exit")
	}

	// Kind specific rules.
	switch in.Kind {
	case spec.KindForward:
		if in.Tunnel != nil {
			return nil, fmt.Errorf("tunnel must not be set on a forward instance")
		}
		if err := p.checkTargets(); err != nil {
			return nil, err
		}
	case spec.KindTunnelEntry:
		if err := p.planTunnel(in); err != nil {
			return nil, err
		}
		if len(p.targets) > 0 || len(p.portMap) > 0 {
			if err := p.checkTargets(); err != nil {
				return nil, err
			}
		}
	case spec.KindTunnelExit:
		if err := p.planTunnel(in); err != nil {
			return nil, err
		}
		if (len(p.targets) > 0) == p.anyTarget {
			return nil, fmt.Errorf("tunnel_exit needs exactly one of targets or allow_any_target")
		}
		for i, t := range p.targets {
			if t.ports.count != 1 {
				return nil, fmt.Errorf("targets[%d].ports: port ranges are not supported on tunnel_exit (gost's exit picks a target per connection, there is no listen port to map)", i)
			}
		}
	case spec.KindReversePortal:
		if err := p.planTunnel(in); err != nil {
			return nil, err
		}
		if len(p.targets) > 0 || p.anyTarget {
			return nil, fmt.Errorf("a reverse_portal has no targets (the bridge decides what it serves)")
		}
		if in.Balance != nil {
			return nil, fmt.Errorf("balance is not supported on reverse_portal")
		}
	case spec.KindReverseBridge:
		if err := p.planTunnel(in); err != nil {
			return nil, err
		}
		if err := p.checkTargets(); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// checkTargets verifies that every listen port has at least one target and
// that target port ranges match the listen range.
func (p *plan) checkTargets() error {
	for _, t := range p.targets {
		if t.ports.count != 1 && t.ports.count != p.lports.count {
			return fmt.Errorf("target port range %d-%d has %d ports, listen.ports has %d", t.ports.start, t.ports.start+t.ports.count-1, t.ports.count, p.lports.count)
		}
	}
	for i := 0; i < p.lports.count; i++ {
		lp := p.lports.at(i)
		if _, ok := p.portMap[lp]; ok {
			continue
		}
		if len(p.targets) == 0 {
			return fmt.Errorf("listen port %d has no target (targets or port_map required)", lp)
		}
	}
	return nil
}

func (p *plan) planBalance(in spec.Instance) error {
	b := in.Balance
	strategy := "round_robin"
	maxFails, failTimeout := 1, 10*time.Second
	if b != nil {
		if b.Strategy != "" {
			strategy = b.Strategy
		}
		if h := b.Health; h != nil {
			if h.Type != "" && h.Type != "tcp" {
				return fmt.Errorf("balance.health.type %q is not supported (gost removes failing targets passively; active health checks are not implemented)", h.Type)
			}
			if h.ProbeURL != "" || h.TimeoutS != 0 {
				return fmt.Errorf("balance.health.probe_url/timeout_s are not supported (passive health only)")
			}
			if h.MaxFails < 0 || h.IntervalS < 0 || h.IntervalS > 86400 || h.MaxFails > 1000 {
				return fmt.Errorf("balance.health values out of range")
			}
			if h.MaxFails > 0 {
				maxFails = h.MaxFails
			}
			// interval_s is the time a failed target stays out of rotation
			// (gost's failTimeout).
			if h.IntervalS > 0 {
				failTimeout = time.Duration(h.IntervalS) * time.Second
			}
		}
	}
	var gs string
	switch strategy {
	case "round_robin":
		gs = "round"
	case "random":
		gs = "random"
	case "iphash":
		gs = "hash"
	case "failover":
		gs = "fifo"
	default:
		return fmt.Errorf("balance.strategy %q is not supported (round_robin, random, iphash, failover)", strategy)
	}
	if gs != "random" {
		for _, t := range p.targets {
			if t.weight != 1 {
				return fmt.Errorf("target weights are only honoured by the random strategy in gost; %q ignores them", strategy)
			}
		}
	}
	p.balance = &balancePlan{gs, maxFails, failTimeout}
	return nil
}

func (p *plan) planTunnel(in spec.Instance) error {
	t := in.Tunnel
	if t == nil {
		return fmt.Errorf("tunnel is required for %s", in.Kind)
	}
	tlsBased, ok := tunnelTLSBased[t.Type]
	if !ok {
		return fmt.Errorf("tunnel.type %q is not supported (tcp, tls, ws, wss, grpc)", t.Type)
	}
	if !reSecret.MatchString(in.Secret) {
		return fmt.Errorf("secret is required for %s (16-256 printable ASCII characters, no spaces)", in.Kind)
	}
	if len(t.ALPN) > 0 {
		return fmt.Errorf("tunnel.alpn is not supported")
	}
	switch t.Security {
	case "", "none":
		if tlsBased {
			if t.Security == "none" {
				return fmt.Errorf("tunnel.type %s always uses TLS; security \"none\" is contradictory", t.Type)
			}
		}
	case "tls":
		if !tlsBased {
			return fmt.Errorf("security \"tls\" needs a TLS carrier (tls, wss, grpc), not %s", t.Type)
		}
	case "tls_pin":
		return fmt.Errorf("security \"tls_pin\" is not supported by gost (no certificate pinning); use tunnel.cert with a certificate file as trust anchor instead")
	case "vless_enc":
		return fmt.Errorf("security \"vless_enc\" is Xray only")
	default:
		return fmt.Errorf("unknown tunnel.security %q", t.Security)
	}
	if t.PinSHA256 != "" {
		return fmt.Errorf("tunnel.pin_sha256 is not supported by gost")
	}
	tp := &tunnelPlan{typ: t.Type, tlsBased: tlsBased}
	if t.Type == "ws" || t.Type == "wss" {
		tp.path = "/ws"
		if t.Path != "" {
			if !rePath.MatchString(t.Path) {
				return fmt.Errorf("tunnel.path %q is invalid", t.Path)
			}
			tp.path = t.Path
		}
		if t.Host != "" {
			if !validHost(t.Host) {
				return fmt.Errorf("tunnel.host %q is invalid", t.Host)
			}
			tp.hostHdr = t.Host
		}
	} else if t.Path != "" || t.Host != "" {
		return fmt.Errorf("tunnel.path/host only apply to ws and wss")
	}
	if t.SNI != "" {
		if !tlsBased {
			return fmt.Errorf("tunnel.sni needs a TLS carrier")
		}
		if !validHost(t.SNI) {
			return fmt.Errorf("tunnel.sni %q is invalid", t.SNI)
		}
		tp.sni = t.SNI
	}

	// dialSide: entry and bridge dial the tunnel; exit and portal accept it.
	dialSide := in.Kind == spec.KindTunnelEntry || in.Kind == spec.KindReverseBridge
	if dialSide {
		if t.Listen != "" {
			return fmt.Errorf("tunnel.listen must be empty on %s", in.Kind)
		}
		hp, err := parseHostPort(t.Server)
		if err != nil {
			return fmt.Errorf("tunnel.server: %w", err)
		}
		tp.server = hp
	} else {
		if t.Server != "" {
			return fmt.Errorf("tunnel.server must be empty on %s", in.Kind)
		}
		ap, err := netip.ParseAddrPort(t.Listen)
		if err != nil || ap.Addr().Zone() != "" || ap.Port() == 0 {
			return fmt.Errorf("tunnel.listen %q is not addr:port", t.Listen)
		}
		tp.listen = ap
	}

	// Certificates.
	if c := t.Cert; c != nil {
		if !tlsBased {
			return fmt.Errorf("tunnel.cert needs a TLS carrier")
		}
		switch c.Mode {
		case "self":
			// Server side only: gost serves its own generated certificate.
			// A dialing side cannot "trust self"; that would disable
			// verification, so it is not offered.
			if dialSide {
				return fmt.Errorf("tunnel.cert.mode self is not supported on %s (it would disable verification; use mode file with the exit's certificate as CA)", in.Kind)
			}
			if c.CertFile != "" || c.KeyFile != "" {
				return fmt.Errorf("tunnel.cert.mode self takes no files")
			}
			tp.selfCert = true
		case "file":
			if !validFile(c.CertFile) {
				return fmt.Errorf("tunnel.cert.cert_file must be an absolute path without spaces or special characters")
			}
			tp.certFile = c.CertFile
			if dialSide {
				// Dialing side: cert_file is the trust anchor (CA) the exit's
				// certificate is verified against.
				if c.KeyFile != "" {
					return fmt.Errorf("tunnel.cert.key_file must be empty on %s (cert_file is the CA used to verify the exit)", in.Kind)
				}
			} else {
				if !validFile(c.KeyFile) {
					return fmt.Errorf("tunnel.cert.key_file must be an absolute path without spaces or special characters")
				}
				tp.keyFile = c.KeyFile
			}
		case "panel":
			return fmt.Errorf("tunnel.cert.mode panel must be materialised into files by the agent core before it reaches the driver")
		default:
			return fmt.Errorf("unknown tunnel.cert.mode %q", c.Mode)
		}
	}
	p.tun = tp
	return nil
}

func validFile(s string) bool {
	return s != "" && reFile.MatchString(s) && !strings.Contains(s, "..")
}
