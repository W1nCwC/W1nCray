package realm

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/spec"
)

// ---------------------------------------------------------------------------
// realm configuration model. Field names are realm's (src/conf/*.rs). The file
// is produced by encoding/json from these typed structs, never by text
// concatenation; the only free-form strings that realm itself parses are
// balance and the two transport DSL strings, which are built by the helpers
// below from whitelisted components.
// ---------------------------------------------------------------------------

type fileConf struct {
	Log       logConf        `json:"log"`
	Endpoints []endpointConf `json:"endpoints"`
}

type logConf struct {
	Level string `json:"level"`
}

type endpointConf struct {
	Listen          string   `json:"listen"`
	Remote          string   `json:"remote"`
	ExtraRemotes    []string `json:"extra_remotes,omitempty"`
	Balance         string   `json:"balance,omitempty"`
	ListenTransport string   `json:"listen_transport,omitempty"`
	RemoteTransport string   `json:"remote_transport,omitempty"`
	Network         *netConf `json:"network,omitempty"`
}

type netConf struct {
	NoTCP              bool `json:"no_tcp,omitempty"`
	UseUDP             bool `json:"use_udp,omitempty"`
	SendProxy          bool `json:"send_proxy,omitempty"`
	SendProxyVersion   int  `json:"send_proxy_version,omitempty"`
	AcceptProxy        bool `json:"accept_proxy,omitempty"`
	AcceptProxyTimeout int  `json:"accept_proxy_timeout,omitempty"`
	UDPTimeout         int  `json:"udp_timeout,omitempty"`
}

// plan is the validated, normalised form of one instance.
type plan struct {
	id        string
	enabled   bool
	endpoints []endpointConf
	claims    []driver.PortClaim
}

// ---------------------------------------------------------------------------
// whitelists
// ---------------------------------------------------------------------------

var idRe = regexp.MustCompile(`^[a-z0-9_-]{1,40}$`)

// show renders an untrusted value for an error message (quoted, bounded).
func show(s string) string {
	if len(s) > 48 {
		s = s[:48] + "..."
	}
	return strconv.Quote(s)
}

func fieldErr(field, format string, a ...any) error {
	return fmt.Errorf("realm: %s: %s", field, fmt.Sprintf(format, a...))
}

// validHostname accepts an RFC 1123 host name (no trailing dot, no IDN, no
// underscore) of at most 253 bytes. Purely numeric dotted names are refused
// so that a malformed IPv4 literal is not silently treated as a name.
func validHostname(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	allNumeric := true
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= '0' && c <= '9':
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
				allNumeric = false
			case c == '-':
				allNumeric = false
				if i == 0 || i == len(label)-1 {
					return false
				}
			default:
				return false
			}
		}
	}
	return !allNumeric
}

// normHost validates a target/server host: an IP literal (no zone) or a host
// name. It returns the canonical text (IPv6 compressed, names lower-cased) and
// whether it is an IP.
func normHost(field, h string) (string, bool, error) {
	if h == "" {
		return "", false, fieldErr(field, "empty host")
	}
	if a, err := netip.ParseAddr(h); err == nil {
		if a.Zone() != "" {
			return "", false, fieldErr(field, "IPv6 zones are not supported (%s)", show(h))
		}
		return a.String(), true, nil
	}
	if !validHostname(h) {
		return "", false, fieldErr(field, "invalid host %s (IP literal or RFC 1123 name expected)", show(h))
	}
	return strings.ToLower(h), false, nil
}

// joinHostPort renders host:port, bracketing IPv6 literals.
func joinHostPort(host string, isIP bool, port int) string {
	if isIP {
		a, _ := netip.ParseAddr(host)
		return netip.AddrPortFrom(a, uint16(port)).String()
	}
	return host + ":" + strconv.Itoa(port)
}

func parsePort(field, s string) (int, error) {
	if s == "" || len(s) > 5 {
		return 0, fieldErr(field, "invalid port %s", show(s))
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fieldErr(field, "invalid port %s", show(s))
		}
		n = n*10 + int(s[i]-'0')
	}
	if n < 1 || n > 65535 {
		return 0, fieldErr(field, "port %d out of range 1-65535", n)
	}
	return n, nil
}

type portRange struct{ lo, hi int }

func (r portRange) n() int { return r.hi - r.lo + 1 }

// parsePorts parses "8443" or "20000-20009".
func parsePorts(field, s string) (portRange, error) {
	if s == "" {
		return portRange{}, fieldErr(field, "empty")
	}
	lo, hi, isRange := strings.Cut(s, "-")
	a, err := parsePort(field, lo)
	if err != nil {
		return portRange{}, err
	}
	if !isRange {
		return portRange{a, a}, nil
	}
	b, err := parsePort(field, hi)
	if err != nil {
		return portRange{}, err
	}
	if b < a {
		return portRange{}, fieldErr(field, "range %s is descending", show(s))
	}
	return portRange{a, b}, nil
}

// parseHostPort parses "host:port" ("[v6]:port" for IPv6 literals).
func parseHostPort(field, s string) (host string, isIP bool, port int, err error) {
	h, p, e := net.SplitHostPort(s)
	if e != nil {
		return "", false, 0, fieldErr(field, "invalid host:port %s", show(s))
	}
	host, isIP, err = normHost(field, h)
	if err != nil {
		return "", false, 0, err
	}
	port, err = parsePort(field, p)
	return host, isIP, port, err
}

// parseListenAddr requires an IP literal.
func parseListenAddr(field, s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, fieldErr(field, "an IP literal without zone is required, got %s", show(s))
	}
	return a, nil
}

// validPath is the ws request path: absolute, no query/fragment, a small
// unreserved alphabet.
func validPath(p string) bool {
	if len(p) < 1 || len(p) > 256 || p[0] != '/' {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case c == '/', c == '-', c == '.', c == '_', c == '~':
		default:
			return false
		}
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == ".." || seg == "." {
			return false
		}
	}
	return true
}

// validHostHeader: host name or IPv4 or [IPv6], optional ":port".
func validHostHeader(h string) bool {
	if h == "" || len(h) > 260 {
		return false
	}
	host, port := h, ""
	if strings.HasPrefix(h, "[") {
		end := strings.IndexByte(h, ']')
		if end < 0 {
			return false
		}
		a, err := netip.ParseAddr(h[1:end])
		if err != nil || !a.Is6() || a.Zone() != "" {
			return false
		}
		rest := h[end+1:]
		if rest != "" {
			if rest[0] != ':' {
				return false
			}
			port = rest[1:]
		}
		host = ""
	} else if i := strings.LastIndexByte(h, ':'); i >= 0 {
		host, port = h[:i], h[i+1:]
	}
	if port != "" {
		if _, err := parsePort("host", port); err != nil {
			return false
		}
	}
	if host == "" {
		return port != "" || strings.HasPrefix(h, "[")
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Is4()
	}
	return validHostname(host)
}

var alpnRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9./+-]{0,31}$`)

// validFilePath is the cert/key path: absolute POSIX or Windows drive path,
// conservative alphabet (no whitespace, no quotes, no ';' '=' ','), no ".."
// components.
func validFilePath(p string) bool {
	if len(p) < 2 || len(p) > 512 {
		return false
	}
	rest := p
	switch {
	case p[0] == '/':
	case len(p) > 3 && ((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) && p[1] == ':' && (p[2] == '\\' || p[2] == '/'):
		rest = p[2:]
	default:
		return false
	}
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case c == '/', c == '\\', c == '.', c == '_', c == '-', c == '@', c == '+', c == '~':
		default:
			return false
		}
	}
	for _, part := range strings.FieldsFunc(rest, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." {
			return false
		}
	}
	return true
}

// dslValue is the last line of defence for the transport option strings that
// realm splits on ';' and '=' (kaminari opt.rs): whatever the field
// whitelists let through, a value that could add or split an option, or that
// contains whitespace, quotes or control bytes is refused here.
func dslValue(name, v string) (string, error) {
	if v == "" {
		return "", fieldErr("tunnel."+name, "empty")
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c <= 0x20 || c >= 0x7f || c == ';' || c == '=' || c == '"' || c == '\'' || c == '`' {
			return "", fieldErr("tunnel."+name, "value %s contains a character that is not allowed in a transport option", show(v))
		}
	}
	return v, nil
}

// ---------------------------------------------------------------------------
// planning
// ---------------------------------------------------------------------------

type target struct {
	host   string
	isIP   bool
	ports  portRange
	weight int
}

// Validate checks everything this driver can or cannot express. It is pure.
func (d *Driver) Validate(in spec.Instance) error {
	_, err := d.buildPlan(in)
	return err
}

func (d *Driver) buildPlan(in spec.Instance) (*plan, error) {
	if !idRe.MatchString(in.ID) {
		return nil, fieldErr("id", "must match [a-z0-9_-]{1,40}, got %s", show(in.ID))
	}
	switch in.Engine {
	case "", spec.EngineAuto, spec.EngineRealm:
	default:
		return nil, fieldErr("engine", "instance is for engine %s, not realm", show(in.Engine))
	}
	if in.Reverse != nil {
		return nil, fieldErr("reverse", "realm has no reverse proxy")
	}
	if in.ACL != nil && (len(in.ACL.Allow) > 0 || len(in.ACL.Deny) > 0) {
		return nil, fieldErr("acl", "realm has no access control; use the local policy or another engine")
	}
	if in.Limits != nil && (in.Limits.MaxConns != 0 || in.Limits.RateUpBps != 0 || in.Limits.RateDownBps != 0) {
		return nil, fieldErr("limits", "realm cannot limit connections or bandwidth")
	}
	if in.AllowAnyTarget {
		return nil, fieldErr("allow_any_target", "a realm exit relays to a fixed target list only")
	}

	tcp, udp, err := parseNetwork(in.Network)
	if err != nil {
		return nil, err
	}
	if in.ProxyProtocolOut < 0 || in.ProxyProtocolOut > 2 {
		return nil, fieldErr("proxy_protocol_out", "must be 0, 1 or 2")
	}
	if in.ProxyProtocolOut > 0 && udp {
		return nil, fieldErr("proxy_protocol_out", "PROXY protocol is TCP only; incompatible with network udp")
	}
	if in.AcceptProxyProtocol && !tcp {
		return nil, fieldErr("accept_proxy_protocol", "PROXY protocol is TCP only")
	}
	udpTimeout, err := idleProfile(in.IdleProfile)
	if err != nil {
		return nil, err
	}

	nc := &netConf{}
	if !tcp {
		nc.NoTCP = true
	}
	if udp {
		nc.UseUDP = true
		nc.UDPTimeout = udpTimeout
	}
	if in.ProxyProtocolOut > 0 {
		nc.SendProxy = true
		nc.SendProxyVersion = in.ProxyProtocolOut
	}
	if in.AcceptProxyProtocol {
		nc.AcceptProxy = true
		nc.AcceptProxyTimeout = acceptProxyTimeoutS
	}

	if *nc == (netConf{}) {
		nc = nil // realm's defaults: tcp only, no PROXY protocol
	}

	p := &plan{id: in.ID, enabled: in.Enabled}
	switch in.Kind {
	case spec.KindForward:
		err = d.planForward(p, in, nc, tcp, udp)
	case spec.KindTunnelEntry:
		err = d.planEntry(p, in, nc, tcp, udp)
	case spec.KindTunnelExit:
		err = d.planExit(p, in, nc, tcp, udp)
	case spec.KindReversePortal, spec.KindReverseBridge:
		err = fieldErr("kind", "realm has no reverse proxy (%s)", show(string(in.Kind)))
	default:
		err = fieldErr("kind", "unknown kind %s", show(string(in.Kind)))
	}
	if err != nil {
		return nil, err
	}
	if !in.Enabled {
		// A disabled instance claims nothing.
		p.claims = nil
	}
	return p, nil
}

func parseNetwork(n []string) (tcp, udp bool, err error) {
	if len(n) == 0 {
		return true, false, nil
	}
	for _, s := range n {
		switch s {
		case "tcp":
			tcp = true
		case "udp":
			udp = true
		default:
			return false, false, fieldErr("network", "unsupported network %s (tcp, udp)", show(s))
		}
	}
	return tcp, udp, nil
}

// idleProfile maps spec.IdleProfile. realm has no TCP idle timeout at all
// (its tcp_timeout is the connect timeout), so the tcp_* presets are accepted
// as no-ops: realm never times out an idle TCP connection and detects dead
// peers through TCP keepalive (15 s x 3). udp_* set realm's udp_timeout,
// the idle time of a UDP association.
func idleProfile(s string) (udpTimeoutS int, err error) {
	switch s {
	case "", "tcp_long", "tcp_default":
		return 0, nil
	case "udp_short":
		return udpShortTimeoutS, nil
	case "udp_long":
		return udpLongTimeoutS, nil
	}
	return 0, fieldErr("idle_profile", "unknown profile %s", show(s))
}

func parseTargets(in spec.Instance) ([]target, error) {
	if len(in.Targets) > maxTargets {
		return nil, fieldErr("targets", "at most %d targets (realm peer list limit)", maxTargets)
	}
	out := make([]target, 0, len(in.Targets))
	for i, t := range in.Targets {
		f := fmt.Sprintf("targets[%d]", i)
		host, isIP, err := normHost(f+".host", t.Host)
		if err != nil {
			return nil, err
		}
		pr, err := parsePorts(f+".ports", t.Ports)
		if err != nil {
			return nil, err
		}
		w := t.Weight
		if w == 0 {
			w = 1
		}
		if w < 1 || w > 255 {
			return nil, fieldErr(f+".weight", "must be 1-255 (realm weights are a u8), got %d", t.Weight)
		}
		out = append(out, target{host: host, isIP: isIP, ports: pr, weight: w})
	}
	return out, nil
}

// balanceString builds realm's "strategy: w1, w2, ..." text. Returns "" when
// there is only one remote (realm needs no balancer then).
func balanceString(b *spec.Balance, ts []target) (string, error) {
	if b != nil && b.Health != nil {
		return "", fieldErr("balance.health", "realm has no health checks; a dead target keeps receiving traffic")
	}
	name := ""
	if b != nil {
		switch b.Strategy {
		case "round_robin":
			name = "roundrobin"
		case "iphash":
			name = "iphash"
		case "random", "failover", "least_ping":
			return "", fieldErr("balance.strategy", "realm supports round_robin and iphash only, not %s", show(b.Strategy))
		default:
			return "", fieldErr("balance.strategy", "unknown strategy %s", show(b.Strategy))
		}
	}
	if len(ts) <= 1 {
		return "", nil
	}
	if name == "" {
		return "", fieldErr("balance", "required with more than one target (realm would silently use only the first)")
	}
	sum := 0
	ws := make([]string, len(ts))
	for i, t := range ts {
		sum += t.weight
		ws[i] = strconv.Itoa(t.weight)
	}
	if name == "roundrobin" && sum > maxWeightSum {
		return "", fieldErr("targets", "sum of weights %d exceeds %d (realm round robin uses 16-bit accumulators)", sum, maxWeightSum)
	}
	return name + ": " + strings.Join(ws, ", "), nil
}

func (d *Driver) planForward(p *plan, in spec.Instance, nc *netConf, tcp, udp bool) error {
	if in.Tunnel != nil {
		return fieldErr("tunnel", "not allowed for kind forward")
	}
	if in.Listen == nil {
		return fieldErr("listen", "required")
	}
	addr, err := parseListenAddr("listen.addr", in.Listen.Addr)
	if err != nil {
		return err
	}
	lr, err := parsePorts("listen.ports", in.Listen.Ports)
	if err != nil {
		return err
	}
	if lr.n() > MaxEndpointsPerInstance {
		return fieldErr("listen.ports", "%d ports exceed the per-instance limit %d", lr.n(), MaxEndpointsPerInstance)
	}
	ts, err := parseTargets(in)
	if err != nil {
		return err
	}
	for i, t := range ts {
		if t.ports.n() != 1 && t.ports.n() != lr.n() {
			return fieldErr(fmt.Sprintf("targets[%d].ports", i), "must be one port or a range of the same length as listen.ports (%d)", lr.n())
		}
	}

	// PortMap: listen port -> "host:port", overrides targets for that port.
	type mapped struct {
		host string
		isIP bool
		port int
	}
	pm := map[int]mapped{}
	for k, v := range in.Listen.PortMap {
		kp, err := parsePort("listen.port_map key", k)
		if err != nil {
			return err
		}
		if kp < lr.lo || kp > lr.hi {
			return fieldErr("listen.port_map", "port %d is outside listen.ports", kp)
		}
		h, isIP, port, err := parseHostPort("listen.port_map["+k+"]", v)
		if err != nil {
			return err
		}
		pm[kp] = mapped{h, isIP, port}
	}
	if len(ts) == 0 && len(pm) != lr.n() {
		return fieldErr("targets", "required unless port_map covers every listen port")
	}
	bal := ""
	if len(ts) > 0 {
		if bal, err = balanceString(in.Balance, ts); err != nil {
			return err
		}
		if len(ts) > 1 {
			if udp && len(pm) != lr.n() {
				return fieldErr("targets", "realm does no load balancing for UDP (single remote only); use one target, or network tcp")
			}
			if in.Balance != nil && in.Balance.Strategy == "iphash" && in.AcceptProxyProtocol {
				return fieldErr("balance.strategy", "iphash hashes the TCP peer, not the PROXY header source; incompatible with accept_proxy_protocol")
			}
		}
	} else if in.Balance != nil && in.Balance.Health != nil {
		return fieldErr("balance.health", "realm has no health checks")
	}

	for i := 0; i < lr.n(); i++ {
		lp := lr.lo + i
		ep := endpointConf{Listen: netip.AddrPortFrom(addr, uint16(lp)).String(), Network: nc}
		if m, ok := pm[lp]; ok {
			ep.Remote = joinHostPort(m.host, m.isIP, m.port)
		} else {
			for j, t := range ts {
				port := t.ports.lo
				if t.ports.n() > 1 {
					port += i
				}
				r := joinHostPort(t.host, t.isIP, port)
				if j == 0 {
					ep.Remote = r
				} else {
					ep.ExtraRemotes = append(ep.ExtraRemotes, r)
				}
			}
			ep.Balance = bal
		}
		p.endpoints = append(p.endpoints, ep)
		if tcp {
			p.claims = append(p.claims, driver.PortClaim{Proto: "tcp", Addr: addr.String(), Port: lp, Owner: in.ID})
		}
		if udp {
			p.claims = append(p.claims, driver.PortClaim{Proto: "udp", Addr: addr.String(), Port: lp, Owner: in.ID})
		}
	}
	return nil
}

func sortedClaims(c []driver.PortClaim) {
	sort.SliceStable(c, func(i, j int) bool {
		if c[i].Port != c[j].Port {
			return c[i].Port < c[j].Port
		}
		return c[i].Proto < c[j].Proto
	})
}
