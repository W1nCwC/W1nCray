// Package validate checks a desired state against the agent's schema and the
// local policy before anything is rendered. It is the first line of defence:
// every string that may later reach a kernel configuration is restricted to a
// conservative character set here (renderers still escape independently), and
// every destination is judged against the target address policy.
//
// All checks are deterministic: the returned errors are sorted.
package validate

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/W1nCwC/W1nCray/agent/portledger"
	"github.com/W1nCwC/W1nCray/agent/spec"
)

// Defaults applied by NormalizePolicy when the local policy leaves a limit at
// zero. A zero limit never means "unlimited".
const (
	DefaultMaxInstances        = 64
	DefaultMaxPortsPerInstance = 256
)

// Error is one validation failure, serialisable for the panel.
type Error struct {
	// Instance is the instance id ("" for errors not tied to an instance).
	Instance string `json:"instance,omitempty"`
	// Index is the position in Desired.Instances, -1 for global errors.
	Index int `json:"index"`
	// Field is the path inside the instance (or inside Desired for global
	// errors), for example "targets[0].host".
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e Error) Error() string {
	var sb strings.Builder
	if e.Instance != "" {
		sb.WriteString(e.Instance)
		sb.WriteString(": ")
	}
	if e.Field != "" {
		sb.WriteString(e.Field)
		sb.WriteString(": ")
	}
	sb.WriteString(e.Message)
	return sb.String()
}

// Options tunes validation.
type Options struct {
	// Resolver resolves target host names; nil means net.DefaultResolver.
	Resolver Resolver
	// ResolveTimeout bounds each lookup; zero means 3 seconds.
	ResolveTimeout time.Duration
}

var (
	reID      = regexp.MustCompile(`^[a-z0-9_-]{1,40}$`)
	reVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	// reSecret is the intersection of what every engine accepts: xray
	// refuses '~', frp refuses ':' and '@', gost needs printable ASCII and
	// realm only checks the length.
	reSecret  = regexp.MustCompile(`^[A-Za-z0-9_.+/=-]{16,256}$`)
	rePin     = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	reHostHdr = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$`)
	rePath    = regexp.MustCompile(`^/[A-Za-z0-9._~%+=:@/-]{0,254}$`)
	reALPN    = regexp.MustCompile(`^[a-z0-9][a-z0-9./-]{0,31}$`)
	reB64URL  = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	reHex     = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	reCertCh  = regexp.MustCompile(`^/[A-Za-z0-9._/-]{1,254}$`)
)

var (
	engines       = []string{spec.EngineAuto, spec.EngineXray, spec.EngineGost, spec.EngineFrp, spec.EngineRealm}
	kernelNames   = []string{spec.EngineXray, spec.EngineGost, spec.EngineFrp, spec.EngineRealm}
	tunnelTypes   = []string{"tcp", "tls", "ws", "wss", "grpc", "xhttp", "kcp", "quic"}
	securities    = []string{"", "none", "tls", "tls_pin", "vless_enc"}
	strategies    = []string{"round_robin", "random", "iphash", "failover", "least_ping"}
	idleProfiles  = []string{"", "tcp_long", "tcp_default", "udp_short", "udp_long"}
	certModes     = []string{"self", "file", "panel"}
	udpTunnelType = map[string]bool{"kcp": true, "quic": true}
)

// Per-collection caps keep a hostile desired state from costing much to check.
const (
	maxTargets     = 64
	maxBridgeAllow = 64
	maxACL         = 256
	maxALPN        = 8
	maxNameLen     = 64
)

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// NormalizePolicy returns a copy of p with defaults filled in: non-positive
// limits become the Default* constants, an empty AllowListen becomes
// ["127.0.0.1"], and a PortRange with only a lower bound extends to 65535.
func NormalizePolicy(p spec.Policy) spec.Policy {
	if p.MaxInstances <= 0 {
		p.MaxInstances = DefaultMaxInstances
	}
	if p.MaxPortsPerInstance <= 0 {
		p.MaxPortsPerInstance = DefaultMaxPortsPerInstance
	}
	if len(p.AllowListen) == 0 {
		p.AllowListen = []string{"127.0.0.1"}
	} else {
		p.AllowListen = append([]string(nil), p.AllowListen...)
	}
	if p.PortRange[1] == 0 && p.PortRange[0] != 0 {
		p.PortRange[1] = portledger.MaxPort
	}
	p.DenyPorts = append([]int(nil), p.DenyPorts...)
	p.DenyCIDRs = append([]string(nil), p.DenyCIDRs...)
	p.AllowEngines = append([]string(nil), p.AllowEngines...)
	return p
}

// ParsePorts parses "8443" or "20000-20009" (see portledger.ParsePorts).
func ParsePorts(s string) (lo, hi int, err error) { return portledger.ParsePorts(s) }

type listenAllow struct {
	addr   netip.Addr
	prefix netip.Prefix
	isPfx  bool
}

type validator struct {
	p     spec.Policy
	opts  Options
	tp    targetPolicy
	allow []listenAllow
	errs  []Error
	dns   map[string][]dnsRef

	// claims of enabled instances, for cross-instance overlap detection
	claims []claimRef
}

type claimRef struct {
	index    int
	instance string
	field    string
	proto    string
	addr     string
	lo, hi   int
}

func (v *validator) addErr(index int, inst, field, format string, args ...any) {
	v.errs = append(v.errs, Error{Instance: inst, Index: index, Field: field, Message: fmt.Sprintf(format, args...)})
}

// Desired validates d against policy p and returns every problem found
// (nil if none), sorted by instance, index, field and message. The policy is
// normalised first (see NormalizePolicy).
func Desired(d spec.Desired, p spec.Policy, opts Options) []Error {
	p = NormalizePolicy(p)
	v := &validator{p: p, opts: opts, dns: map[string][]dnsRef{}}
	v.tp.allowPrivate = p.AllowPrivate
	v.policy()

	if d.Version != spec.Version {
		v.addErr(-1, "", "version", "unsupported schema version %d (this agent speaks %d)", d.Version, spec.Version)
	}
	v.kernels(d.Kernels)

	n := len(d.Instances)
	if n > p.MaxInstances {
		v.addErr(-1, "", "instances", "too many instances: %d (local policy allows %d)", n, p.MaxInstances)
		n = p.MaxInstances // do not spend work on the excess
	}
	seen := map[string]int{}
	for i := 0; i < n; i++ {
		in := d.Instances[i]
		if first, dup := seen[in.ID]; dup && reID.MatchString(in.ID) {
			v.addErr(i, in.ID, "id", "duplicate id (also used by instances[%d])", first)
		} else if !dup {
			seen[in.ID] = i
		}
		v.instance(i, in)
	}
	v.overlaps()
	v.resolveAll()
	return v.finish()
}

func (v *validator) finish() []Error {
	if len(v.errs) == 0 {
		return nil
	}
	sort.SliceStable(v.errs, func(i, j int) bool {
		a, b := v.errs[i], v.errs[j]
		if a.Index != b.Index {
			return a.Index < b.Index
		}
		if a.Instance != b.Instance {
			return a.Instance < b.Instance
		}
		if a.Field != b.Field {
			return a.Field < b.Field
		}
		return a.Message < b.Message
	})
	// drop exact duplicates (the same host used twice in one field, etc.)
	out := v.errs[:0]
	for i, e := range v.errs {
		if i > 0 && e == v.errs[i-1] {
			continue
		}
		out = append(out, e)
	}
	return out
}

// policy parses the local policy; a malformed policy is reported as an error
// and fails everything (fail closed).
func (v *validator) policy() {
	for i, s := range v.p.AllowListen {
		if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
			v.allow = append(v.allow, listenAllow{addr: a.Unmap()})
		} else if pf, err := netip.ParsePrefix(s); err == nil {
			v.allow = append(v.allow, listenAllow{prefix: pf.Masked(), isPfx: true})
		} else {
			v.addErr(-1, "", fmt.Sprintf("policy.allow_listen[%d]", i), "invalid listen address or CIDR %q", s)
		}
	}
	for i, s := range v.p.DenyCIDRs {
		pf, err := netip.ParsePrefix(s)
		if err != nil {
			if a, err2 := netip.ParseAddr(s); err2 == nil {
				pf = netip.PrefixFrom(a, a.BitLen())
				err = nil
			}
		}
		if err != nil {
			v.addErr(-1, "", fmt.Sprintf("policy.deny_cidrs[%d]", i), "invalid CIDR %q", s)
			continue
		}
		v.tp.deny = append(v.tp.deny, pf.Masked())
	}
}

func (v *validator) kernels(pins []spec.KernelPin) {
	seen := map[string]bool{}
	for i, k := range pins {
		f := fmt.Sprintf("kernels[%d]", i)
		if !contains(kernelNames, k.Name) {
			v.addErr(-1, "", f+".name", "unknown kernel %q", k.Name)
		} else if seen[k.Name] {
			v.addErr(-1, "", f+".name", "kernel %q pinned twice", k.Name)
		}
		seen[k.Name] = true
		if k.Version != "" && !reVersion.MatchString(k.Version) {
			v.addErr(-1, "", f+".version", "invalid version string")
		}
	}
}

// ---- per-instance -------------------------------------------------------

type inst struct {
	v     *validator
	i     int
	id    string
	in    spec.Instance
	udp   bool
	tcp   bool
	nPort int // ports in Listen.Ports (0 if not parsed)
}

func (x *inst) err(field, format string, args ...any) {
	x.v.addErr(x.i, x.id, field, format, args...)
}

func (v *validator) instance(i int, in spec.Instance) {
	x := &inst{v: v, i: i, id: in.ID, in: in}
	if !reID.MatchString(in.ID) {
		x.id = "" // never echo an unvetted id
		x.err("id", "invalid id: must match [a-z0-9_-]{1,40}")
	}
	if in.Name != "" {
		x.checkText("name", in.Name, maxNameLen)
	}
	x.engine()
	x.network()
	if !validKind(in.Kind) {
		x.err("kind", "unknown kind %q", string(in.Kind))
		return
	}
	x.kindFields()
	x.proxy()
	x.idle()
	x.limitsACL()
}

func validKind(k spec.Kind) bool {
	switch k {
	case spec.KindForward, spec.KindTunnelEntry, spec.KindTunnelExit, spec.KindReversePortal, spec.KindReverseBridge:
		return true
	}
	return false
}

// checkText restricts free text (names) so it cannot break config text.
func (x *inst) checkText(field, s string, max int) {
	if len([]rune(s)) > max {
		x.err(field, "too long (max %d characters)", max)
	}
	for _, r := range s {
		if unicode.IsControl(r) || strings.ContainsRune("\"'`\\#;$<>{}|&", r) || r == ' ' || r == ' ' {
			x.err(field, "contains a forbidden character %q", r)
			return
		}
	}
}

func (x *inst) engine() {
	e := x.in.Engine
	if !contains(engines, e) {
		x.err("engine", "unknown engine %q (want auto, xray, gost, frp or realm)", e)
		return
	}
	if e != spec.EngineAuto && len(x.v.p.AllowEngines) > 0 && !contains(x.v.p.AllowEngines, e) {
		x.err("engine", "engine %q is not allowed by the local policy", e)
	}
	if t := x.in.Tunnel; t != nil && t.Security == "vless_enc" && e != spec.EngineXray && e != spec.EngineAuto {
		x.err("tunnel.security", "vless_enc is only supported by the xray engine")
	}
}

func (x *inst) network() {
	nw := x.in.Network
	if len(nw) == 0 {
		x.tcp = true
		return
	}
	seen := map[string]bool{}
	for i, n := range nw {
		if n != "tcp" && n != "udp" {
			x.err(fmt.Sprintf("network[%d]", i), "invalid network %q (want tcp or udp)", n)
			continue
		}
		if seen[n] {
			x.err(fmt.Sprintf("network[%d]", i), "duplicate network %q", n)
		}
		seen[n] = true
	}
	x.tcp, x.udp = seen["tcp"], seen["udp"]
}

func (x *inst) protos() []string {
	var p []string
	if x.tcp {
		p = append(p, "tcp")
	}
	if x.udp {
		p = append(p, "udp")
	}
	return p
}

func (x *inst) kindFields() {
	in := x.in
	k := in.Kind
	hasListen := k == spec.KindForward || k == spec.KindTunnelEntry || k == spec.KindReversePortal
	needsTunnel := k != spec.KindForward
	reverse := k == spec.KindReversePortal || k == spec.KindReverseBridge

	// Sections that do not apply to the kind are refused instead of silently
	// ignored, so the panel never shows an option that has no effect.
	if !needsTunnel {
		if in.Tunnel != nil {
			x.err("tunnel", "not allowed for kind %q", k)
		}
		if in.Secret != "" {
			x.err("secret", "not allowed for kind %q", k)
		}
	}
	if !reverse && in.Reverse != nil {
		x.err("reverse", "only allowed for reverse_portal and reverse_bridge")
	}
	if k != spec.KindTunnelExit && in.AllowAnyTarget {
		x.err("allow_any_target", "only allowed for tunnel_exit")
	}
	if k == spec.KindTunnelExit && in.Listen != nil {
		x.err("listen", "not used by tunnel_exit (it listens on tunnel.listen)")
	}

	// Listen
	switch {
	case hasListen:
		if in.Listen == nil {
			x.err("listen", "required for kind %q", k)
		} else {
			x.listen(in.Listen)
		}
	case k == spec.KindReverseBridge:
		x.bridgeListen()
	}

	// Tunnel
	if needsTunnel {
		if in.Tunnel == nil {
			x.err("tunnel", "required for kind %q", k)
		} else {
			x.tunnel()
		}
		x.secret()
	}

	// Targets
	x.targets()
	if in.Listen != nil && len(in.Listen.PortMap) > 0 {
		if k != spec.KindForward && k != spec.KindTunnelEntry {
			x.err("listen.port_map", "only allowed for forward and tunnel_entry")
		} else {
			x.portMap()
		}
	}
	x.balance()
	if reverse {
		x.reverse()
	}
}

// ---- listen -------------------------------------------------------------

func (v *validator) allowedListen(a netip.Addr) bool {
	a = a.Unmap()
	for _, e := range v.allow {
		switch {
		case e.isPfx:
			if e.prefix.Contains(a) {
				return true
			}
		case e.addr == a:
			return true
		case e.addr.IsUnspecified() && e.addr.Is4() == a.Is4():
			// "0.0.0.0" / "::" in allow_listen permit any address of that family
			return true
		}
	}
	return false
}

func (x *inst) listenAddr(field, s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		x.err(field, "must be a literal IP address (no host names, brackets or zones)")
		return netip.Addr{}, false
	}
	a = a.Unmap()
	if !x.v.allowedListen(a) {
		x.err(field, "listen address %s is not allowed by the local policy", a)
		return a, false
	}
	return a, true
}

// listenPorts parses ports and applies the port policy.
func (x *inst) listenPorts(field, s string) (lo, hi int, ok bool) {
	lo, hi, err := portledger.ParsePorts(s)
	if err != nil {
		x.err(field, "%v", err)
		return 0, 0, false
	}
	x.portPolicy(field, lo, hi)
	return lo, hi, true
}

func (x *inst) portPolicy(field string, lo, hi int) {
	p := x.v.p
	if n := hi - lo + 1; n > p.MaxPortsPerInstance {
		x.err(field, "%d ports requested, local policy allows %d per instance", n, p.MaxPortsPerInstance)
	}
	min, max := p.PortRange[0], p.PortRange[1]
	if min == 0 {
		min = 1
	}
	if max == 0 {
		max = portledger.MaxPort
	}
	if lo < min || hi > max {
		x.err(field, "ports %d-%d are outside the permitted range %d-%d", lo, hi, min, max)
	}
	if !p.PrivilegedPorts && lo < 1024 {
		x.err(field, "privileged ports (below 1024) are not allowed by the local policy")
	}
	for _, d := range p.DenyPorts {
		if d >= lo && d <= hi {
			x.err(field, "port %d is denied by the local policy", d)
		}
	}
}

func (x *inst) listen(l *spec.Listen) {
	addr, aok := x.listenAddr("listen.addr", l.Addr)
	lo, hi, pok := x.listenPorts("listen.ports", l.Ports)
	if pok {
		x.nPort = hi - lo + 1
	}
	if aok && pok && x.in.Enabled {
		for _, pr := range x.protos() {
			x.v.claims = append(x.v.claims, claimRef{x.i, x.id, "listen", pr, addr.String(), lo, hi})
		}
	}
	if x.in.AcceptProxyProtocol && aok && !isPrivateOrLocal(addr) && !x.v.p.AllowAcceptProxyOnPublic {
		x.err("accept_proxy_protocol", "listen address %s is not loopback/private; PROXY headers are forgeable there and the local policy does not allow it", addr)
	}
}

// bridgeListen validates the reverse_bridge convention: Listen.Ports names the
// portal-side public port(s); nothing is bound locally, so only the syntax
// and the per-instance port count are checked.
func (x *inst) bridgeListen() {
	l := x.in.Listen
	if l == nil {
		x.err("listen", "required for reverse_bridge (listen.ports names the portal-side public ports)")
		return
	}
	if l.Addr != "" {
		if a, err := netip.ParseAddr(l.Addr); err != nil || a.Zone() != "" {
			x.err("listen.addr", "unused by reverse_bridge; leave empty or give an IP literal")
		}
	}
	lo, hi, err := portledger.ParsePorts(l.Ports)
	if err != nil {
		x.err("listen.ports", "%v", err)
		return
	}
	x.nPort = hi - lo + 1
	if n := hi - lo + 1; n > x.v.p.MaxPortsPerInstance {
		x.err("listen.ports", "%d ports requested, local policy allows %d per instance", n, x.v.p.MaxPortsPerInstance)
	}
}

func (x *inst) portMap() {
	l := x.in.Listen
	if len(l.PortMap) > x.v.p.MaxPortsPerInstance {
		x.err("listen.port_map", "too many entries (%d, max %d)", len(l.PortMap), x.v.p.MaxPortsPerInstance)
		return
	}
	lo, hi, err := portledger.ParsePorts(l.Ports)
	keys := make([]string, 0, len(l.PortMap))
	for k := range l.PortMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		field := "listen.port_map[" + safeKey(k) + "]"
		kp, kerr := strconv.Atoi(k)
		if _, _, e := portledger.ParsePorts(k); e != nil || kerr != nil || strings.Contains(k, "-") {
			x.err(field, "key must be a single listen port")
			continue
		}
		if err == nil && (kp < lo || kp > hi) {
			x.err(field, "key %d is outside listen.ports %s", kp, l.Ports)
		}
		host, port, serr := net.SplitHostPort(l.PortMap[k])
		if serr != nil {
			x.err(field, "value must be host:port")
			continue
		}
		if _, _, e := portledger.ParsePorts(port); e != nil {
			x.err(field, "value port: %v", e)
		} else if strings.Contains(port, "-") {
			x.err(field, "value port must be a single port")
		}
		x.host(field, host)
	}
}

// safeKey renders a map key for use in a field path without trusting it.
func safeKey(k string) string {
	if len(k) > 16 {
		k = k[:16]
	}
	var sb strings.Builder
	for _, r := range k {
		if r >= 0x21 && r <= 0x7e && r != '[' && r != ']' {
			sb.WriteRune(r)
		} else {
			sb.WriteByte('?')
		}
	}
	return sb.String()
}

// ---- tunnel -------------------------------------------------------------

func (x *inst) tunnel() {
	t := x.in.Tunnel
	k := x.in.Kind
	client := k == spec.KindTunnelEntry || k == spec.KindReverseBridge
	server := !client

	if !contains(tunnelTypes, t.Type) {
		x.err("tunnel.type", "unknown tunnel type %q", t.Type)
	}
	if client {
		if t.Server == "" {
			x.err("tunnel.server", "required for kind %q", k)
		} else {
			x.tunnelServer(t.Server)
		}
		if t.Listen != "" {
			x.err("tunnel.listen", "not used by kind %q", k)
		}
	}
	if server {
		if t.Listen == "" {
			x.err("tunnel.listen", "required for kind %q", k)
		} else {
			x.tunnelListen(t.Listen)
		}
		if t.Server != "" {
			x.err("tunnel.server", "not used by kind %q", k)
		}
	}

	if t.Host != "" && !reHostHdr.MatchString(t.Host) {
		x.err("tunnel.host", "invalid host (allowed: letters, digits, '.', '-', '_', ':')")
	}
	if t.SNI != "" {
		if _, isName, msg := checkHostSyntax(t.SNI); msg != "" {
			x.err("tunnel.sni", "%s", msg)
		} else if !isName {
			x.err("tunnel.sni", "must be a host name, not an IP address")
		}
	}
	if t.Path != "" && !rePath.MatchString(t.Path) {
		x.err("tunnel.path", "invalid path (must start with '/', allowed: letters, digits and . _ ~ %% + = : @ / -)")
	}
	if len(t.ALPN) > maxALPN {
		x.err("tunnel.alpn", "too many entries (max %d)", maxALPN)
	}
	for i, a := range t.ALPN {
		if i >= maxALPN {
			break
		}
		if !reALPN.MatchString(a) {
			x.err(fmt.Sprintf("tunnel.alpn[%d]", i), "invalid ALPN token")
		}
	}

	if !contains(securities, t.Security) {
		x.err("tunnel.security", "unknown security %q (want none, tls, tls_pin or vless_enc)", t.Security)
	}
	switch t.Type {
	case "tls", "wss":
		if t.Security == "none" || t.Security == "vless_enc" {
			x.err("tunnel.security", "tunnel type %q is TLS by definition; security %q is contradictory", t.Type, t.Security)
		}
	}
	if t.Security == "tls_pin" {
		if !rePin.MatchString(t.PinSHA256) {
			x.err("tunnel.pin_sha256", "tls_pin requires pin_sha256: 64 hex characters (SHA-256 of the leaf certificate)")
		}
	} else if t.PinSHA256 != "" {
		x.err("tunnel.pin_sha256", "only meaningful with security tls_pin")
	}
	if t.Cert != nil {
		x.cert(t.Cert, client)
	}
}

func validCertPath(p string) bool {
	return reCertCh.MatchString(p) && !strings.Contains(p, "..")
}

// cert checks tunnel.cert. On the server side (exit, portal) it is the
// certificate to present. On the client side (entry, bridge) it can only be a
// trust anchor: mode "file" with cert_file naming the CA (or the server's own
// certificate) and no key_file. An engine that cannot honour it refuses it in
// its own Validate.
func (x *inst) cert(c *spec.Cert, client bool) {
	if !contains(certModes, c.Mode) {
		x.err("tunnel.cert.mode", "unknown mode %q (want self, file or panel)", c.Mode)
		return
	}
	if client {
		if c.Mode != "file" {
			x.err("tunnel.cert.mode", "kind %q only supports mode \"file\" (cert_file is the trust anchor used to verify the server)", x.in.Kind)
			return
		}
		if !validCertPath(c.CertFile) {
			x.err("tunnel.cert.cert_file", "must be an absolute path (letters, digits and . _ / - only, no '..')")
		}
		if c.KeyFile != "" {
			x.err("tunnel.cert.key_file", "not used by kind %q (client certificates are not supported; cert_file is only the trust anchor)", x.in.Kind)
		}
		return
	}
	if c.Mode == "file" {
		for _, f := range []struct{ name, val string }{{"tunnel.cert.cert_file", c.CertFile}, {"tunnel.cert.key_file", c.KeyFile}} {
			if !validCertPath(f.val) {
				x.err(f.name, "must be an absolute path (letters, digits and . _ / - only, no '..')")
			}
		}
	} else if c.CertFile != "" || c.KeyFile != "" {
		x.err("tunnel.cert", "cert_file/key_file are only used with mode \"file\"")
	}
}

func (x *inst) tunnelListen(s string) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil || ap.Addr().Zone() != "" {
		x.err("tunnel.listen", "must be <ip>:<port> with a literal IP")
		return
	}
	if ap.Port() == 0 {
		x.err("tunnel.listen", "port must be 1-65535")
		return
	}
	a, ok := x.listenAddr("tunnel.listen", ap.Addr().String())
	port := int(ap.Port())
	x.portPolicy("tunnel.listen", port, port)
	if ok && x.in.Enabled {
		proto := "tcp"
		if udpTunnelType[x.in.Tunnel.Type] {
			proto = "udp"
		}
		x.v.claims = append(x.v.claims, claimRef{x.i, x.id, "tunnel.listen", proto, a.String(), port, port})
	}
}

func (x *inst) tunnelServer(s string) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		x.err("tunnel.server", "must be host:port")
		return
	}
	if _, _, e := portledger.ParsePorts(port); e != nil || strings.Contains(port, "-") {
		x.err("tunnel.server", "port must be a single port 1-65535")
	}
	x.host("tunnel.server", host)
}

func (x *inst) secret() {
	s := x.in.Secret
	if s == "" {
		x.err("secret", "required for kind %q (at least 16 characters)", x.in.Kind)
		return
	}
	if !reSecret.MatchString(s) {
		// Never echo the secret itself.
		x.err("secret", "must be 16-256 characters of [A-Za-z0-9_.+/=-] (the set every engine accepts)")
	}
}

// ---- targets ------------------------------------------------------------

func (x *inst) targets() {
	in := x.in
	k := in.Kind
	ts := in.Targets
	if len(ts) > maxTargets {
		x.err("targets", "too many targets (max %d)", maxTargets)
		ts = ts[:maxTargets]
	}
	switch k {
	case spec.KindReversePortal:
		if len(in.Targets) > 0 {
			x.err("targets", "not used by reverse_portal (the bridge decides the destinations)")
		}
		return
	case spec.KindForward:
		covered := in.Listen != nil && x.nPort > 0 && len(in.Listen.PortMap) >= x.nPort
		if len(in.Targets) == 0 && !covered {
			x.err("targets", "at least one target is required (or a port_map covering every listen port)")
		}
	case spec.KindReverseBridge:
		if len(in.Targets) == 0 {
			x.err("targets", "at least one target is required for reverse_bridge")
		}
	case spec.KindTunnelExit:
		switch {
		case len(in.Targets) == 0 && !in.AllowAnyTarget:
			x.err("targets", "tunnel_exit needs fixed targets or allow_any_target")
		case len(in.Targets) > 0 && in.AllowAnyTarget:
			x.err("allow_any_target", "mutually exclusive with targets")
		case in.AllowAnyTarget && !x.v.p.AllowAnyTarget:
			x.err("allow_any_target", "not allowed by the local policy")
		}
	}
	for i, t := range ts {
		f := fmt.Sprintf("targets[%d]", i)
		x.host(f+".host", t.Host)
		lo, hi, err := portledger.ParsePorts(t.Ports)
		if err != nil {
			x.err(f+".ports", "%v", err)
		} else if n := hi - lo + 1; n > x.v.p.MaxPortsPerInstance {
			x.err(f+".ports", "%d ports requested, local policy allows %d per instance", n, x.v.p.MaxPortsPerInstance)
		} else if x.nPort > 0 && k != spec.KindTunnelExit && n != x.nPort {
			x.err(f+".ports", "has %d port(s) but listen.ports has %d; ranges must be the same length", n, x.nPort)
		}
		if t.Weight < 0 || t.Weight > 65535 {
			x.err(f+".weight", "must be between 0 and 65535")
		}
	}
}

// host validates a destination host: syntax, literal-IP policy, or queues a
// DNS check for names.
func (x *inst) host(field, h string) {
	addr, isName, msg := checkHostSyntax(h)
	if msg != "" {
		x.err(field, "%s", msg)
		return
	}
	if isName {
		if x.in.Enabled {
			x.v.dns[h] = append(x.v.dns[h], dnsRef{x.i, x.id, field})
		}
		return
	}
	if why := x.v.tp.denyReason(addr); why != "" {
		x.err(field, "destination %s refused: %s", addr, why)
	}
}

func (x *inst) balance() {
	b := x.in.Balance
	if b == nil {
		return
	}
	if !contains(strategies, b.Strategy) {
		x.err("balance.strategy", "unknown strategy %q", b.Strategy)
	}
	if len(x.in.Targets) == 0 {
		x.err("balance", "requires targets")
	}
	h := b.Health
	if h == nil {
		return
	}
	if h.Type != "tcp" && h.Type != "http" {
		x.err("balance.health.type", "must be tcp or http")
	}
	if h.IntervalS < 0 || h.IntervalS > 3600 {
		x.err("balance.health.interval_s", "must be 0-3600")
	}
	if h.TimeoutS < 0 || h.TimeoutS > 300 {
		x.err("balance.health.timeout_s", "must be 0-300")
	}
	if h.MaxFails < 0 || h.MaxFails > 100 {
		x.err("balance.health.max_fails", "must be 0-100")
	}
	if h.ProbeURL != "" {
		// A full URL would let the panel make the agent fetch arbitrary
		// addresses (SSRF); only a path probed on the targets is accepted.
		if h.Type != "http" {
			x.err("balance.health.probe_url", "only used with type http")
		} else if !rePath.MatchString(h.ProbeURL) {
			x.err("balance.health.probe_url", "must be a path starting with '/', probed on the targets (full URLs are not accepted)")
		}
	}
}

// ---- reverse ------------------------------------------------------------

func (x *inst) reverse() {
	r := x.in.Reverse
	if r == nil {
		return
	}
	if r.Link != "" && !reID.MatchString(r.Link) {
		x.err("reverse.link", "invalid link id")
	}
	if r.Domain != "" {
		if msg := domainEntropy(r.Domain); msg != "" {
			x.err("reverse.domain", "%s", msg)
		}
	}
	if len(r.BridgeAllow) > maxBridgeAllow {
		x.err("reverse.bridge_allow", "too many entries (max %d)", maxBridgeAllow)
	}
	for i, a := range r.BridgeAllow {
		if i >= maxBridgeAllow {
			break
		}
		f := fmt.Sprintf("reverse.bridge_allow[%d]", i)
		x.host(f+".host", a.Host)
		if _, _, err := portledger.ParsePorts(a.Ports); err != nil {
			x.err(f+".ports", "%v", err)
		}
	}
}

// domainEntropy requires a random rendezvous name: hex with at least 32
// characters (128 bit) or base64url with at least 22 characters (~131 bit),
// and some variety so that "aaaa...a" is refused. It is a format check; it
// cannot prove the value was generated randomly.
func domainEntropy(s string) string {
	if len(s) > 128 {
		return "too long (max 128 characters)"
	}
	switch {
	case reHex.MatchString(s):
		if len(s) < 32 {
			return "too short: hex domains need at least 32 characters (128 bit)"
		}
	case reB64URL.MatchString(s):
		if len(s) < 22 {
			return "too short: base64url domains need at least 22 characters (128 bit)"
		}
	default:
		return "must be hex or base64url ([A-Za-z0-9_-])"
	}
	distinct := map[rune]bool{}
	for _, r := range s {
		distinct[r] = true
	}
	if len(distinct) < 8 {
		return "not random enough (fewer than 8 distinct characters)"
	}
	return ""
}

// ---- proxy / idle / limits / acl -----------------------------------------

func (x *inst) proxy() {
	in := x.in
	if in.ProxyProtocolOut < 0 || in.ProxyProtocolOut > 2 {
		x.err("proxy_protocol_out", "must be 0, 1 or 2")
	}
	if in.ProxyProtocolOut > 0 && x.udp {
		x.err("proxy_protocol_out", "PROXY protocol is TCP only and cannot be combined with network udp")
	}
	if in.AcceptProxyProtocol {
		if x.udp {
			x.err("accept_proxy_protocol", "PROXY protocol is TCP only and cannot be combined with network udp")
		}
		switch in.Kind {
		case spec.KindForward, spec.KindTunnelEntry, spec.KindReversePortal:
		default:
			x.err("accept_proxy_protocol", "kind %q has no user-facing listener to accept PROXY headers on", in.Kind)
		}
	}
}

func (x *inst) idle() {
	p := x.in.IdleProfile
	if !contains(idleProfiles, p) {
		x.err("idle_profile", "unknown profile %q", p)
		return
	}
	if strings.HasPrefix(p, "tcp_") && !x.tcp {
		x.err("idle_profile", "profile %q needs network tcp", p)
	}
	if strings.HasPrefix(p, "udp_") && !x.udp {
		x.err("idle_profile", "profile %q needs network udp", p)
	}
}

func (x *inst) limitsACL() {
	if l := x.in.Limits; l != nil {
		if l.MaxConns < 0 || l.MaxConns > 10_000_000 {
			x.err("limits.max_conns", "must be 0-10000000")
		}
		if l.RateUpBps < 0 || l.RateUpBps > 1_000_000_000_000 {
			x.err("limits.rate_up_bps", "must be 0-1e12")
		}
		if l.RateDownBps < 0 || l.RateDownBps > 1_000_000_000_000 {
			x.err("limits.rate_down_bps", "must be 0-1e12")
		}
	}
	if a := x.in.ACL; a != nil {
		x.aclList("acl.allow", a.Allow)
		x.aclList("acl.deny", a.Deny)
	}
}

func (x *inst) aclList(field string, list []string) {
	if len(list) > maxACL {
		x.err(field, "too many entries (max %d)", maxACL)
		list = list[:maxACL]
	}
	for i, s := range list {
		if _, err := netip.ParsePrefix(s); err == nil {
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
			continue
		}
		x.err(fmt.Sprintf("%s[%d]", field, i), "not an IP address or CIDR")
	}
}

// ---- cross-instance listener overlap ------------------------------------

func (v *validator) overlaps() {
	for a := 0; a < len(v.claims); a++ {
		for b := a + 1; b < len(v.claims); b++ {
			x, y := v.claims[a], v.claims[b]
			if x.proto != y.proto || x.hi < y.lo || y.hi < x.lo || !portledger.AddrOverlap(x.addr, y.addr) {
				continue
			}
			lo, hi := x.lo, x.hi
			if y.lo > lo {
				lo = y.lo
			}
			if y.hi < hi {
				hi = y.hi
			}
			span := strconv.Itoa(lo)
			if hi != lo {
				span += "-" + strconv.Itoa(hi)
			}
			v.addErr(y.index, y.instance, y.field, "%s port(s) %s on %s collide with instances[%d] (%s)", y.proto, span, y.addr, x.index, x.field)
		}
	}
}
