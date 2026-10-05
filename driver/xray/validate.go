package xray

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/W1nCwC/W1nCray/agent/spec"
)

// Options configures compilation and validation. The zero value is valid.
type Options struct {
	// Policy is the local agent policy. When nil the driver does not enforce
	// listen-address, port and target policy (the agent core does), but it
	// still treats AllowAnyTarget and AllowAcceptProxyOnPublic as false.
	Policy *spec.Policy
	// Levels maps idle profiles to Xray policy levels (zero: DefaultLevels).
	Levels Levels
	// CertRoots lists the directories certificate/key files of Cert.Mode
	// "file" may live in. Empty: file mode is rejected.
	CertRoots []string
	// PanelCert supplies the certificate of Cert.Mode "panel". Nil: panel
	// mode is rejected.
	PanelCert func(instanceID string) (certPEM, keyPEM string, err error)
	// MaxPorts caps the number of listen ports of one instance (zero:
	// Policy.MaxPortsPerInstance, else 1024).
	MaxPorts int
}

func (o Options) levels() Levels {
	if o.Levels == (Levels{}) {
		return DefaultLevels()
	}
	return o.Levels
}

func (o Options) maxPorts() int {
	if o.MaxPorts > 0 {
		return o.MaxPorts
	}
	if o.Policy != nil && o.Policy.MaxPortsPerInstance > 0 {
		return o.Policy.MaxPortsPerInstance
	}
	return 1024
}

// ValidationError is returned for every rejected instance. Messages never
// contain secrets.
type ValidationError struct {
	Instance string
	Msg      string
}

func (e *ValidationError) Error() string {
	if e.Instance == "" {
		return "xray: " + e.Msg
	}
	return fmt.Sprintf("xray: instance %s: %s", e.Instance, e.Msg)
}

// ---------------------------------------------------------------- whitelists

var (
	idRe       = regexp.MustCompile(`^[a-z0-9_-]{1,40}$`)
	labelRe    = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	numericRe  = regexp.MustCompile(`^[0-9]+$`)
	pathRe     = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,199}$`)
	serviceRe  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	alpnRe     = regexp.MustCompile(`^[a-z0-9./-]{1,32}$`)
	pinRe      = regexp.MustCompile(`^[0-9A-Fa-f]{64}$`)
	secretRe   = regexp.MustCompile(`^[A-Za-z0-9+/=_.:@-]{16,256}$`)
	rdomainRe  = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{24,62}[a-z0-9])$`)
	fileRe     = regexp.MustCompile(`^[A-Za-z0-9._/@:~\\+-]{1,300}$`)
	validProto = map[spec.Kind]bool{
		spec.KindForward: true, spec.KindTunnelEntry: true, spec.KindTunnelExit: true,
		spec.KindReversePortal: true, spec.KindReverseBridge: true,
	}
)

func verr(id, format string, args ...any) error {
	return &ValidationError{Instance: id, Msg: fmt.Sprintf(format, args...)}
}

// hostKind classifies a validated host.
type hostRef struct {
	Host string // IP text or lower-case domain
	IP   netip.Addr
	IsIP bool
}

func parseHost(s string) (hostRef, error) {
	if s == "" {
		return hostRef{}, errors.New("empty host")
	}
	if len(s) > 253 {
		return hostRef{}, errors.New("host too long")
	}
	if a, err := netip.ParseAddr(s); err == nil {
		if a.Zone() != "" {
			return hostRef{}, errors.New("IPv6 zone is not allowed")
		}
		a = a.Unmap()
		return hostRef{Host: a.String(), IP: a, IsIP: true}, nil
	}
	labels := strings.Split(s, ".")
	for _, l := range labels {
		if !labelRe.MatchString(l) {
			return hostRef{}, errors.New("host is neither an IP address nor a valid domain name")
		}
	}
	if numericRe.MatchString(labels[len(labels)-1]) {
		return hostRef{}, errors.New("host is neither an IP address nor a valid domain name")
	}
	return hostRef{Host: strings.ToLower(s)}, nil
}

type portRange struct{ Lo, Hi int }

func (r portRange) Len() int { return r.Hi - r.Lo + 1 }

func (r portRange) String() string {
	if r.Lo == r.Hi {
		return strconv.Itoa(r.Lo)
	}
	return strconv.Itoa(r.Lo) + "-" + strconv.Itoa(r.Hi)
}

func parsePort(s string) (int, error) {
	if s == "" || len(s) > 5 || !numericRe.MatchString(s) {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	n, _ := strconv.Atoi(s)
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %d out of range", n)
	}
	return n, nil
}

func parsePorts(s string) (portRange, error) {
	if i := strings.IndexByte(s, '-'); i >= 0 {
		lo, err := parsePort(s[:i])
		if err != nil {
			return portRange{}, err
		}
		hi, err := parsePort(s[i+1:])
		if err != nil {
			return portRange{}, err
		}
		if lo > hi {
			return portRange{}, fmt.Errorf("invalid port range %q", s)
		}
		return portRange{lo, hi}, nil
	}
	p, err := parsePort(s)
	if err != nil {
		return portRange{}, err
	}
	return portRange{p, p}, nil
}

// parseHostPort parses "host:port" (IPv6 in brackets).
func parseHostPort(s string) (hostRef, int, error) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return hostRef{}, 0, errors.New("expected host:port")
	}
	hr, err := parseHost(h)
	if err != nil {
		return hostRef{}, 0, err
	}
	port, err := parsePort(p)
	if err != nil {
		return hostRef{}, 0, err
	}
	return hr, port, nil
}

func parseAddrPort(s string) (netip.Addr, int, error) {
	hr, port, err := parseHostPort(s)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	if !hr.IsIP {
		return netip.Addr{}, 0, errors.New("a listen address must be an IP address")
	}
	return hr.IP, port, nil
}

// ---------------------------------------------------------------- policy

var defaultDeny = mustPrefixes("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "::/128", "::1/128", "fe80::/10")
var privateDeny = mustPrefixes("10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")

func mustPrefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, v := range s {
		out[i] = netip.MustParsePrefix(v)
	}
	return out
}

// denyList returns the destination prefixes the policy forbids.
func denyList(p *spec.Policy) ([]netip.Prefix, error) {
	if len(p.DenyCIDRs) > 0 {
		out := make([]netip.Prefix, 0, len(p.DenyCIDRs))
		for _, c := range p.DenyCIDRs {
			pf, err := parsePrefixOrAddr(c)
			if err != nil {
				return nil, fmt.Errorf("policy deny_cidrs: %w", err)
			}
			out = append(out, pf)
		}
		if !p.AllowPrivate {
			out = append(out, privateDeny...)
		}
		return out, nil
	}
	out := append([]netip.Prefix(nil), defaultDeny...)
	if !p.AllowPrivate {
		out = append(out, privateDeny...)
	}
	return out, nil
}

func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR %q", s)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("invalid address %q", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func isLocalDomain(h string) bool {
	return h == "localhost" || strings.HasSuffix(h, ".localhost")
}

func (p *plan) checkTargetHost(h hostRef) error {
	if p.opts.Policy == nil {
		return nil
	}
	if h.IsIP {
		for _, pf := range p.deny {
			if pf.Contains(h.IP) {
				return fmt.Errorf("target %s is denied by the local policy", h.Host)
			}
		}
		return nil
	}
	if isLocalDomain(h.Host) {
		lo := netip.MustParseAddr("127.0.0.1")
		for _, pf := range p.deny {
			if pf.Contains(lo) {
				return fmt.Errorf("target %s is denied by the local policy", h.Host)
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------- plan

type target struct {
	Host   hostRef
	Ports  portRange
	Weight int
}

type hostPort struct {
	Host hostRef
	Port int
}

type tunnelPlan struct {
	Type     string // tcp | tls | ws | wss | grpc | xhttp
	Network  string // xray network name: raw | ws | grpc | xhttp
	TLS      bool
	Pin      string // lower hex
	VlessEnc bool
	Host     string
	SNI      string
	Path     string
	ALPN     []string
	Server   hostRef // client side
	ServerP  int
	ListenA  netip.Addr // server side
	ListenP  int
	Cert     *spec.Cert
}

// plan is the validated, normalised form of an instance.
type plan struct {
	in   spec.Instance
	opts Options
	deny []netip.Prefix

	hasTCP, hasUDP bool
	networks       []string

	listenAddr  netip.Addr
	listenPorts portRange
	portMap     map[int]hostPort
	targets     []target
	level       uint32

	allowAny bool
	tunnel   *tunnelPlan
	rdomain  string
	// slots is the number of destination slots of a reverse bridge: the
	// portal's n-th public port carries slot n, and slot n is redirected to
	// the n-th port of the bridge's single target range (1 when the target
	// has a single port).
	slots int

	balance string // "", round_robin, random, failover
	health  *spec.Health
}

func (p *plan) fail(format string, args ...any) error { return verr(p.in.ID, format, args...) }

func normalizeNetworks(in []string) (tcp, udp bool, list []string, err error) {
	if len(in) == 0 {
		return true, false, []string{"tcp"}, nil
	}
	for _, n := range in {
		switch n {
		case "tcp":
			tcp = true
		case "udp":
			udp = true
		default:
			return false, false, nil, fmt.Errorf("unsupported network %q", n)
		}
	}
	if tcp {
		list = append(list, "tcp")
	}
	if udp {
		list = append(list, "udp")
	}
	return tcp, udp, list, nil
}

// plan validates an instance against the driver's capabilities and the
// options and returns its normalised form.
func newPlan(in spec.Instance, opts Options) (*plan, error) {
	p := &plan{in: in, opts: opts}
	if !idRe.MatchString(in.ID) {
		return nil, verr("", "invalid instance id")
	}
	if !validProto[in.Kind] {
		return nil, p.fail("unsupported kind %q", in.Kind)
	}
	switch in.Engine {
	case "", spec.EngineAuto, spec.EngineXray:
	default:
		return nil, p.fail("engine %q is not handled by the xray driver", in.Engine)
	}
	if in.Limits != nil && (in.Limits.MaxConns != 0 || in.Limits.RateUpBps != 0 || in.Limits.RateDownBps != 0) {
		return nil, p.fail("limits (max_conns, rate_up_bps, rate_down_bps) are not supported by the xray driver")
	}
	var err error
	if p.hasTCP, p.hasUDP, p.networks, err = normalizeNetworks(in.Network); err != nil {
		return nil, p.fail("%v", err)
	}
	if opts.Policy != nil {
		if p.deny, err = denyList(opts.Policy); err != nil {
			return nil, p.fail("%v", err)
		}
	}

	// PROXY protocol.
	if in.ProxyProtocolOut < 0 || in.ProxyProtocolOut > 2 {
		return nil, p.fail("proxy_protocol_out must be 0, 1 or 2")
	}
	if in.ProxyProtocolOut > 0 && (p.hasUDP || !p.hasTCP) {
		return nil, p.fail("proxy_protocol_out is TCP only and cannot be combined with network udp")
	}
	if in.AcceptProxyProtocol && (p.hasUDP || !p.hasTCP) {
		return nil, p.fail("accept_proxy_protocol is TCP only and cannot be combined with network udp")
	}

	// Idle profile.
	switch in.IdleProfile {
	case "":
	case "tcp_long", "tcp_default":
		if !p.hasTCP {
			return nil, p.fail("idle_profile %s needs network tcp", in.IdleProfile)
		}
	case "udp_short", "udp_long":
		if !p.hasUDP {
			return nil, p.fail("idle_profile %s needs network udp", in.IdleProfile)
		}
	default:
		return nil, p.fail("unknown idle_profile %q", in.IdleProfile)
	}
	p.level = idleLevel(opts.levels(), in.IdleProfile, p.hasTCP)

	// ACL.
	if err := checkACL(in.ACL); err != nil {
		return nil, p.fail("%v", err)
	}

	// AllowAnyTarget is honoured only when the local policy allows it.
	if in.AllowAnyTarget {
		if opts.Policy == nil || !opts.Policy.AllowAnyTarget {
			return nil, p.fail("allow_any_target is not permitted by the local policy")
		}
		if in.Kind != spec.KindTunnelExit {
			return nil, p.fail("allow_any_target applies to tunnel_exit only (a reverse_bridge's targets fix its destinations)")
		}
		p.allowAny = true
	}

	switch in.Kind {
	case spec.KindForward:
		err = p.checkForward()
	case spec.KindTunnelEntry:
		err = p.checkEntry()
	case spec.KindTunnelExit:
		err = p.checkExit()
	case spec.KindReversePortal:
		err = p.checkPortal()
	case spec.KindReverseBridge:
		err = p.checkBridge()
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

// idleLevel maps an idle profile to its policy level. An explicit profile is
// honoured as written. With no profile an instance that carries TCP gets
// tcp_long and a UDP-only instance gets udp_short: the node ConnectionConfig
// (tcp_default, 30 s idle out of the box) would cut SSH-style long-lived
// connections that sit idle, which is the wrong default for a forwarder.
// tcp_default stays available as an explicit choice.
func idleLevel(l Levels, profile string, tcp bool) uint32 {
	switch profile {
	case "tcp_long":
		return l.TCPLong
	case "tcp_default":
		return l.TCPDefault
	case "udp_short":
		return l.UDPShort
	case "udp_long":
		return l.UDPLong
	}
	if tcp {
		return l.TCPLong
	}
	return l.UDPShort
}

func checkACL(a *spec.ACL) error {
	if a == nil {
		return nil
	}
	for name, list := range map[string][]string{"allow": a.Allow, "deny": a.Deny} {
		if len(list) > 64 {
			return fmt.Errorf("acl.%s has too many entries", name)
		}
		for _, e := range list {
			if _, err := parsePrefixOrAddr(e); err != nil {
				return fmt.Errorf("acl.%s: %v", name, err)
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------- listen

func (p *plan) checkListen(required bool) error {
	l := p.in.Listen
	if l == nil {
		if required {
			return p.fail("listen is required")
		}
		return nil
	}
	a, err := netip.ParseAddr(l.Addr)
	if err != nil || a.Zone() != "" {
		return p.fail("listen.addr must be an IP address")
	}
	p.listenAddr = a.Unmap()
	if p.listenPorts, err = parsePorts(l.Ports); err != nil {
		return p.fail("listen.ports: %v", err)
	}
	if p.listenPorts.Len() > p.opts.maxPorts() {
		return p.fail("listen.ports spans %d ports, the limit is %d", p.listenPorts.Len(), p.opts.maxPorts())
	}
	if pol := p.opts.Policy; pol != nil {
		if err := p.checkListenPolicy(pol); err != nil {
			return err
		}
	}
	if p.in.AcceptProxyProtocol {
		if !p.listenAddr.IsLoopback() && !p.listenAddr.IsPrivate() {
			if p.opts.Policy == nil || !p.opts.Policy.AllowAcceptProxyOnPublic {
				return p.fail("accept_proxy_protocol is only allowed on loopback or private listen addresses " +
					"(PROXY headers are forgeable); the local policy does not allow it on public listeners")
			}
		}
	}
	// Port map: keys are single listen ports inside Listen.Ports.
	if len(l.PortMap) > 0 {
		p.portMap = map[int]hostPort{}
		for k, v := range l.PortMap {
			kp, err := parsePort(k)
			if err != nil {
				return p.fail("listen.port_map key: %v", err)
			}
			if kp < p.listenPorts.Lo || kp > p.listenPorts.Hi {
				return p.fail("listen.port_map key %d is outside listen.ports", kp)
			}
			h, port, err := parseHostPort(v)
			if err != nil {
				return p.fail("listen.port_map[%d]: %v", kp, err)
			}
			if err := p.checkTargetHost(h); err != nil {
				return p.fail("%v", err)
			}
			p.portMap[kp] = hostPort{Host: h, Port: port}
		}
	}
	return nil
}

func (p *plan) checkListenPolicy(pol *spec.Policy) error {
	return p.checkBindPolicy(pol, p.listenAddr, p.listenPorts, "listen")
}

// checkBindPolicy applies the local listen policy to a bind address.
func (p *plan) checkBindPolicy(pol *spec.Policy, addr netip.Addr, r portRange, what string) error {
	allow := pol.AllowListen
	if len(allow) == 0 {
		allow = []string{"127.0.0.1"}
	}
	ok := false
	for _, e := range allow {
		pf, err := parsePrefixOrAddr(e)
		if err != nil {
			return p.fail("policy allow_listen: %v", err)
		}
		if pf.Contains(addr) {
			ok = true
			break
		}
	}
	if !ok {
		return p.fail("%s address %s is not permitted by the local policy", what, addr)
	}
	if r.Lo < 1024 && !pol.PrivilegedPorts {
		return p.fail("%s: privileged ports are not permitted by the local policy", what)
	}
	if pol.PortRange[0] != 0 || pol.PortRange[1] != 0 {
		if r.Lo < pol.PortRange[0] || r.Hi > pol.PortRange[1] {
			return p.fail("%s: outside the port range %d-%d permitted by the local policy", what, pol.PortRange[0], pol.PortRange[1])
		}
	}
	for _, d := range pol.DenyPorts {
		if d >= r.Lo && d <= r.Hi {
			return p.fail("%s: port %d is denied by the local policy", what, d)
		}
	}
	return nil
}

// ---------------------------------------------------------------- targets

func (p *plan) checkTargets(minOne bool) error {
	var weightSum int
	for i, t := range p.in.Targets {
		h, err := parseHost(t.Host)
		if err != nil {
			return p.fail("targets[%d].host: %v", i, err)
		}
		if err := p.checkTargetHost(h); err != nil {
			return p.fail("%v", err)
		}
		pr, err := parsePorts(t.Ports)
		if err != nil {
			return p.fail("targets[%d].ports: %v", i, err)
		}
		w := t.Weight
		if w == 0 {
			w = 1
		}
		if w < 0 || w > 64 {
			return p.fail("targets[%d].weight must be between 1 and 64", i)
		}
		weightSum += w
		p.targets = append(p.targets, target{Host: h, Ports: pr, Weight: w})
	}
	if weightSum > 64 {
		return p.fail("the sum of target weights must not exceed 64")
	}
	if minOne && len(p.targets) == 0 {
		return p.fail("at least one target is required")
	}
	return nil
}

// checkMapping verifies that every listen port has a destination, either
// from a port_map entry or from the (single) target, and that range lengths
// match.
func (p *plan) checkMapping() error {
	if len(p.targets) > 1 {
		if len(p.portMap) > 0 {
			return p.fail("listen.port_map cannot be combined with several targets")
		}
		if p.listenPorts.Len() != 1 {
			return p.fail("several targets are only supported with a single listen port")
		}
		for i, t := range p.targets {
			if t.Ports.Len() != 1 {
				return p.fail("targets[%d]: several targets must use single ports", i)
			}
		}
		return nil
	}
	if len(p.targets) == 1 {
		t := p.targets[0]
		if t.Ports.Len() != p.listenPorts.Len() && !(t.Ports.Len() == 1 && p.listenPorts.Len() == 1) {
			// A single target port with a listen range maps every listen
			// port to the same target port only when it is a single port.
			if t.Ports.Len() != 1 {
				return p.fail("target ports (%d) and listen ports (%d) must have the same length", t.Ports.Len(), p.listenPorts.Len())
			}
		}
		return nil
	}
	// No target: the port map must cover every listen port.
	for port := p.listenPorts.Lo; port <= p.listenPorts.Hi; port++ {
		if _, ok := p.portMap[port]; !ok {
			return p.fail("listen port %d has no target (add targets or a port_map entry)", port)
		}
	}
	return nil
}

func (p *plan) checkBalance() error {
	b := p.in.Balance
	if b == nil {
		if len(p.targets) > 1 {
			p.balance = "round_robin"
		}
		return nil
	}
	switch b.Strategy {
	case "", "round_robin":
		p.balance = "round_robin"
	case "random":
		p.balance = "random"
	case "failover":
		p.balance = "failover"
	default:
		return p.fail("balance strategy %q is not supported by the xray driver (round_robin, random, failover)", b.Strategy)
	}
	if h := b.Health; h != nil {
		if h.Type != "tcp" {
			return p.fail("balance.health.type %q is not supported (tcp)", h.Type)
		}
		if h.ProbeURL != "" {
			return p.fail("balance.health.probe_url is not supported for tcp checks")
		}
		if h.IntervalS < 0 || h.IntervalS > 3600 || h.TimeoutS < 0 || h.TimeoutS > 60 || h.MaxFails < 0 || h.MaxFails > 100 {
			return p.fail("balance.health values out of range")
		}
		p.health = h
	}
	if p.balance == "failover" && p.health == nil {
		return p.fail("balance strategy failover needs balance.health")
	}
	if len(p.targets) < 2 && p.health != nil {
		return p.fail("balance.health needs at least two targets")
	}
	return nil
}

// ---------------------------------------------------------------- kinds

func (p *plan) noReverse() error {
	if p.in.Reverse != nil {
		return p.fail("reverse settings are only valid for reverse_portal and reverse_bridge")
	}
	return nil
}

func (p *plan) checkForward() error {
	in := p.in
	if in.Tunnel != nil {
		return p.fail("tunnel settings are not valid for forward")
	}
	if err := p.noReverse(); err != nil {
		return err
	}
	if in.Secret != "" {
		return p.fail("secret is not valid for forward")
	}
	if err := p.checkListen(true); err != nil {
		return err
	}
	if err := p.checkTargets(false); err != nil {
		return err
	}
	if err := p.checkMapping(); err != nil {
		return err
	}
	return p.checkBalance()
}

func (p *plan) checkEntry() error {
	in := p.in
	if err := p.noReverse(); err != nil {
		return err
	}
	if err := p.checkListen(true); err != nil {
		return err
	}
	if err := p.checkTargets(false); err != nil {
		return err
	}
	if err := p.checkMapping(); err != nil {
		return err
	}
	if err := p.checkBalance(); err != nil {
		return err
	}
	if p.health != nil {
		return p.fail("balance.health is not supported for tunnel_entry (targets are reached through the exit side)")
	}
	if in.Tunnel == nil || in.Tunnel.Server == "" {
		return p.fail("tunnel.server is required for tunnel_entry")
	}
	if in.Tunnel.Listen != "" {
		return p.fail("tunnel.listen is not valid for tunnel_entry")
	}
	if len(p.targets) > 1 || in.ProxyProtocolOut > 0 {
		if p.hasUDP {
			return p.fail("several targets and PROXY header carrying are TCP only")
		}
	}
	return p.checkTunnel(false, p.hasUDP)
}

func (p *plan) checkExit() error {
	in := p.in
	if err := p.noReverse(); err != nil {
		return err
	}
	if in.Listen != nil {
		return p.fail("listen is not valid for tunnel_exit (use tunnel.listen)")
	}
	if in.AcceptProxyProtocol {
		return p.fail("accept_proxy_protocol is not valid for tunnel_exit")
	}
	if in.Balance != nil {
		return p.fail("balance is not valid for tunnel_exit (the entry side chooses)")
	}
	if err := p.checkTargets(false); err != nil {
		return err
	}
	if !p.allowAny && len(p.targets) == 0 {
		return p.fail("tunnel_exit needs fixed targets (or allow_any_target permitted by the local policy)")
	}
	if in.Tunnel == nil || in.Tunnel.Listen == "" {
		return p.fail("tunnel.listen is required for tunnel_exit")
	}
	if in.Tunnel.Server != "" {
		return p.fail("tunnel.server is not valid for tunnel_exit")
	}
	return p.checkTunnel(true, p.hasUDP)
}

// Reverse proxy semantics (shared with the gost and frp drivers): the bridge
// side decides the destinations. A reverse_portal only accepts users and has
// no targets; a reverse_bridge rewrites every connection the portal relays to
// one of its own targets, so a portal (or its users) can never choose where
// the bridge connects.

func (p *plan) checkPortal() error {
	in := p.in
	if in.Tunnel == nil || in.Tunnel.Listen == "" {
		return p.fail("tunnel.listen is required for reverse_portal")
	}
	if in.Tunnel.Server != "" {
		return p.fail("tunnel.server is not valid for reverse_portal")
	}
	if in.ProxyProtocolOut != 0 {
		return p.fail("proxy_protocol_out is not valid for reverse_portal (set it on the bridge)")
	}
	if in.Balance != nil {
		return p.fail("balance is not valid for reverse_portal (set it on the bridge)")
	}
	if len(in.Targets) > 0 {
		return p.fail("targets are not used by reverse_portal (the bridge's targets decide the destinations)")
	}
	if in.Listen != nil && len(in.Listen.PortMap) > 0 {
		return p.fail("listen.port_map is not valid for reverse_portal (the bridge's targets decide the destinations)")
	}
	if err := p.checkListen(true); err != nil {
		return err
	}
	if err := p.checkReverseDomain(); err != nil {
		return err
	}
	return p.checkTunnel(true, p.hasUDP)
}

func (p *plan) checkBridge() error {
	in := p.in
	if in.Tunnel == nil || in.Tunnel.Server == "" {
		return p.fail("tunnel.server is required for reverse_bridge")
	}
	if in.Tunnel.Listen != "" {
		return p.fail("tunnel.listen is not valid for reverse_bridge")
	}
	if in.AcceptProxyProtocol {
		return p.fail("accept_proxy_protocol is not valid for reverse_bridge")
	}
	// Listen.Ports names the portal side public ports; nothing is bound here,
	// only the number of ports matters (see slots).
	listenLen := 0
	if in.Listen != nil {
		if len(in.Listen.PortMap) > 0 {
			return p.fail("listen.port_map is not valid for reverse_bridge")
		}
		pr, err := parsePorts(in.Listen.Ports)
		if err != nil {
			return p.fail("listen.ports: %v", err)
		}
		listenLen = pr.Len()
	}
	if err := p.checkTargets(true); err != nil {
		return err
	}
	if err := p.checkReverseDomain(); err != nil {
		return err
	}
	p.slots = 1
	switch {
	case len(p.targets) > 1:
		for i, t := range p.targets {
			if t.Ports.Len() != 1 {
				return p.fail("targets[%d]: several targets must use single ports", i)
			}
		}
		if listenLen > 1 {
			return p.fail("several targets are only supported with a single listen port")
		}
	default:
		if n := p.targets[0].Ports.Len(); n > 1 {
			if listenLen != n {
				return p.fail("target ports (%d) and listen.ports (%d, the portal's public ports) must have the same length", n, listenLen)
			}
			p.slots = n
		}
	}
	if err := p.checkBalance(); err != nil {
		return err
	}
	return p.checkTunnel(false, p.hasUDP)
}

func (p *plan) checkReverseDomain() error {
	r := p.in.Reverse
	if r == nil || r.Domain == "" {
		return p.fail("reverse.domain is required")
	}
	if !rdomainRe.MatchString(r.Domain) || r.Domain == "reverse" {
		return p.fail("reverse.domain must be 26-64 characters of [a-z0-9.-] (>=128 bit of randomness)")
	}
	distinct := map[rune]bool{}
	for _, c := range r.Domain {
		distinct[c] = true
	}
	if len(distinct) < 10 {
		return p.fail("reverse.domain does not look random")
	}
	p.rdomain = r.Domain
	if len(r.BridgeAllow) > 0 {
		return p.fail("reverse.bridge_allow is not supported by the xray driver: the bridge rewrites every relayed connection " +
			"to its targets, so list the permitted destinations in targets instead")
	}
	return nil
}

// ---------------------------------------------------------------- tunnel

func (p *plan) checkTunnel(server, udp bool) error {
	in := p.in
	t := in.Tunnel
	if !secretRe.MatchString(in.Secret) {
		return p.fail("secret is missing or malformed (16-256 characters of [A-Za-z0-9+/=_.:@-])")
	}
	tp := &tunnelPlan{Type: t.Type, Host: t.Host, SNI: t.SNI, Path: t.Path}
	switch t.Type {
	case "tcp":
		tp.Network = "raw"
	case "tls":
		tp.Network, tp.TLS = "raw", true
	case "ws":
		tp.Network = "ws"
	case "wss":
		tp.Network, tp.TLS = "ws", true
	case "grpc":
		tp.Network = "grpc"
	case "xhttp":
		tp.Network = "xhttp"
	case "kcp", "quic":
		return p.fail("tunnel type %q is not supported by the xray driver (tcp, tls, ws, wss, grpc, xhttp)", t.Type)
	default:
		return p.fail("unknown tunnel type %q", t.Type)
	}

	// Security. Empty means: tls for tls/wss, VLESS encryption otherwise.
	sec := t.Security
	tlsType := t.Type == "tls" || t.Type == "wss"
	if sec == "" {
		if tlsType {
			sec = "tls"
		} else {
			sec = "vless_enc"
		}
	}
	switch sec {
	case "none":
		if tlsType {
			return p.fail("tunnel type %s requires TLS", t.Type)
		}
		if t.Type == "tcp" {
			return p.fail("an unencrypted raw tunnel is not allowed (use vless_enc, tls or tls_pin)")
		}
	case "tls":
		tp.TLS = true
	case "tls_pin":
		tp.TLS = true
		if !pinRe.MatchString(t.PinSHA256) {
			return p.fail("tunnel.pin_sha256 must be 64 hex characters")
		}
		tp.Pin = strings.ToLower(t.PinSHA256)
	case "vless_enc":
		if tlsType {
			return p.fail("vless_enc cannot be combined with tunnel type %s (use security tls or tls_pin)", t.Type)
		}
		tp.VlessEnc = true
	default:
		return p.fail("unknown tunnel security %q", sec)
	}
	if tp.TLS && sec == "none" {
		return p.fail("inconsistent tunnel security")
	}
	if sec != "tls_pin" && t.PinSHA256 != "" {
		return p.fail("tunnel.pin_sha256 needs security tls_pin")
	}

	// Free text fields.
	if t.Host != "" {
		if _, err := parseHost(t.Host); err != nil {
			return p.fail("tunnel.host: %v", err)
		}
	}
	if t.SNI != "" {
		h, err := parseHost(t.SNI)
		if err != nil || h.IsIP {
			return p.fail("tunnel.sni must be a domain name")
		}
	}
	switch tp.Network {
	case "ws", "xhttp":
		if tp.Path == "" {
			tp.Path = "/"
		}
		if !pathRe.MatchString(tp.Path) {
			return p.fail("tunnel.path is not a valid URL path")
		}
	case "grpc":
		sn := strings.Trim(tp.Path, "/")
		if sn == "" {
			sn = "w1n"
		}
		if !serviceRe.MatchString(sn) {
			return p.fail("tunnel.path is not a valid gRPC service name")
		}
		tp.Path = sn
	default:
		if t.Path != "" {
			return p.fail("tunnel.path is not valid for a raw tunnel")
		}
	}
	for _, a := range t.ALPN {
		if !alpnRe.MatchString(a) {
			return p.fail("invalid tunnel.alpn entry")
		}
	}
	if len(t.ALPN) > 4 {
		return p.fail("too many tunnel.alpn entries")
	}
	tp.ALPN = append([]string(nil), t.ALPN...)
	if !tp.TLS && (len(t.ALPN) > 0 || t.SNI != "") {
		return p.fail("tunnel.sni and tunnel.alpn need TLS")
	}

	if server {
		a, port, err := parseAddrPort(t.Listen)
		if err != nil {
			return p.fail("tunnel.listen: %v", err)
		}
		tp.ListenA, tp.ListenP = a.Unmap(), port
		if pol := p.opts.Policy; pol != nil {
			if err := p.checkBindPolicy(pol, tp.ListenA, portRange{port, port}, "tunnel.listen"); err != nil {
				return err
			}
		}
		if tp.TLS {
			if err := p.checkCert(t.Cert, sec == "tls_pin"); err != nil {
				return err
			}
			tp.Cert = t.Cert
		} else if t.Cert != nil {
			return p.fail("tunnel.cert needs TLS")
		}
	} else {
		h, port, err := parseHostPort(t.Server)
		if err != nil {
			return p.fail("tunnel.server: %v", err)
		}
		tp.Server, tp.ServerP = h, port
		if t.Cert != nil {
			return p.fail("tunnel.cert is only valid on the accepting side")
		}
		if t.Listen != "" {
			return p.fail("tunnel.listen is not valid on the dialing side")
		}
	}
	_ = udp
	p.tunnel = tp
	return nil
}

func (p *plan) checkCert(c *spec.Cert, pinned bool) error {
	if c == nil {
		return p.fail("tunnel.cert is required on the accepting side of a TLS tunnel")
	}
	switch c.Mode {
	case "self":
		if !pinned {
			return p.fail("a self-signed certificate needs security tls_pin (clients can only verify it by pin)")
		}
	case "file":
		if len(p.opts.CertRoots) == 0 {
			return p.fail("certificate files are not allowed (no certificate root configured)")
		}
		for _, f := range []string{c.CertFile, c.KeyFile} {
			if !p.certPathAllowed(f) {
				return p.fail("certificate file path is invalid or outside the permitted directories")
			}
		}
	case "panel":
		if p.opts.PanelCert == nil {
			return p.fail("panel certificates are not available")
		}
	default:
		return p.fail("unknown tunnel.cert.mode %q", c.Mode)
	}
	return nil
}

func (p *plan) certPathAllowed(f string) bool {
	if f == "" || !fileRe.MatchString(f) || strings.Contains(f, "..") {
		return false
	}
	slash := strings.ReplaceAll(f, `\`, "/")
	clean := path.Clean(slash)
	if clean != slash {
		return false
	}
	for _, root := range p.opts.CertRoots {
		r := strings.TrimRight(strings.ReplaceAll(root, `\`, "/"), "/")
		if r != "" && strings.HasPrefix(clean, r+"/") {
			return true
		}
	}
	return false
}

// sortedKeys returns the keys of a port map in ascending order.
func sortedKeys(m map[int]hostPort) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}
