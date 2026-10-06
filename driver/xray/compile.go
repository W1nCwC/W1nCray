package xray

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/spec"
)

// CompileVersion is part of every artifact hash; bump it whenever the
// compiler output for the same input changes. Version 2: reverse proxies use
// the bridge-decides semantics (placeholder destination on the portal,
// redirect outbounds on the bridge) and the default idle level is tcp_long.
const CompileVersion = 2

// Part is one inbound or outbound object (Xray JSON) with its tag.
type Part struct {
	Tag    string          `json:"tag"`
	Config json.RawMessage `json:"config"`
}

// ReverseSpec describes the self-managed reverse proxy half of an instance.
type ReverseSpec struct {
	Role   string `json:"role"` // portal | bridge
	Tag    string `json:"tag"`  // outbound tag (portal) / inbound tag of relayed requests (bridge)
	Domain string `json:"domain"`
}

// HealthTarget is one balanced target and the outbounds that serve it.
type HealthTarget struct {
	Addr string   `json:"addr"` // host:port, as dialled
	Tags []string `json:"tags"`
}

// HealthSpec asks the driver to probe targets and keep only live ones in the
// balancer's candidate set (by removing and re-adding outbound handlers).
type HealthSpec struct {
	Strategy  string         `json:"strategy"` // round_robin | random | failover
	IntervalS int            `json:"interval_s"`
	TimeoutS  int            `json:"timeout_s"`
	MaxFails  int            `json:"max_fails"`
	Targets   []HealthTarget `json:"targets"`
}

// StatsRef names where the counters of an instance live.
type StatsRef struct {
	InboundTag   string   `json:"inbound_tag,omitempty"`
	OutboundTags []string `json:"outbound_tags,omitempty"`
}

// Claim is a listener the instance binds.
type Claim struct {
	Proto string `json:"proto"`
	Addr  string `json:"addr"`
	Port  int    `json:"port"`
}

// Compiled is the complete Xray-level realisation of one instance. It is the
// content of the artifact file "compiled.json".
type Compiled struct {
	V         int               `json:"v"`
	ID        string            `json:"id"`
	Kind      spec.Kind         `json:"kind"`
	Disabled  bool              `json:"disabled,omitempty"`
	Inbounds  []Part            `json:"inbounds,omitempty"`
	Outbounds []Part            `json:"outbounds,omitempty"`
	Rules     []json.RawMessage `json:"rules,omitempty"`
	Balancers []json.RawMessage `json:"balancers,omitempty"`
	Reverse   *ReverseSpec      `json:"reverse,omitempty"`
	Health    *HealthSpec       `json:"health,omitempty"`
	CertFiles []string          `json:"cert_files,omitempty"`
	Stats     StatsRef          `json:"stats"`
	Claims    []Claim           `json:"claims,omitempty"`
}

// CompiledFile is the artifact file name carrying a Compiled.
const CompiledFile = "compiled.json"

// PortClaims returns the listeners of the instance for the port ledger.
func (c *Compiled) PortClaims() []driver.PortClaim {
	out := make([]driver.PortClaim, 0, len(c.Claims))
	for _, cl := range c.Claims {
		out = append(out, driver.PortClaim{Proto: cl.Proto, Addr: cl.Addr, Port: cl.Port, Owner: c.ID})
	}
	return out
}

// Validate checks an instance without compiling it.
func Validate(in spec.Instance, opts Options) error {
	_, err := newPlan(in, opts)
	return err
}

// Compile validates an instance and renders it. It is a pure function of its
// arguments: the same input gives byte-identical output.
func Compile(in spec.Instance, opts Options) (Compiled, error) {
	p, err := newPlan(in, opts)
	if err != nil {
		return Compiled{}, err
	}
	c := Compiled{V: CompileVersion, ID: in.ID, Kind: in.Kind}
	if !in.Enabled {
		c.Disabled = true
		return c, nil
	}
	b := &builder{p: p, c: &c}
	switch in.Kind {
	case spec.KindForward:
		err = b.forward()
	case spec.KindTunnelEntry:
		err = b.entry()
	case spec.KindTunnelExit:
		err = b.exit()
	case spec.KindReversePortal:
		err = b.portal()
	case spec.KindReverseBridge:
		err = b.bridge()
	}
	if err != nil {
		return Compiled{}, err
	}
	return c, nil
}

// MarshalCompiled serialises a Compiled deterministically.
func MarshalCompiled(c Compiled) ([]byte, error) { return json.Marshal(c) }

// ArtifactHash is the content hash of a compiled artifact file.
func ArtifactHash(files map[string][]byte) string {
	h := sha256.New()
	fmt.Fprintf(h, "w1ncray-xray-driver/%d\n", CompileVersion)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(h, "%s\x00%d\x00", n, len(files[n]))
		h.Write(files[n])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ---------------------------------------------------------------- builder

type builder struct {
	p *plan
	c *Compiled
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		// Only typed structures are marshalled here; failure is a bug.
		panic("xray driver: marshal: " + err.Error())
	}
	return b
}

func (b *builder) addIn(tag, protocol, listen, port string, settings any, st *jStream) {
	b.c.Inbounds = append(b.c.Inbounds, Part{Tag: tag, Config: mustJSON(jInbound{
		Tag: tag, Protocol: protocol, Listen: listen, Port: port, Settings: settings, Stream: st,
	})})
}

func (b *builder) addOut(tag, protocol string, settings any, st *jStream) {
	b.c.Outbounds = append(b.c.Outbounds, Part{Tag: tag, Config: mustJSON(jOutbound{
		Tag: tag, Protocol: protocol, Settings: settings, Stream: st,
	})})
}

func (b *builder) addRule(r jRule) {
	r.Type = "field"
	b.c.Rules = append(b.c.Rules, mustJSON(r))
}

func (b *builder) addBlock() string {
	t := tagBlock(b.p.in.ID)
	b.addOut(t, "blackhole", jBlackhole{}, nil)
	return t
}

func (b *builder) claim(proto, addr string, lo, hi int) {
	for port := lo; port <= hi; port++ {
		b.c.Claims = append(b.c.Claims, Claim{Proto: proto, Addr: addr, Port: port})
	}
}

// claimListen registers the user facing listeners.
func (b *builder) claimListen() {
	for _, n := range b.p.networks {
		b.claim(n, b.p.listenAddr.String(), b.p.listenPorts.Lo, b.p.listenPorts.Hi)
	}
}

func hostPortStr(h hostRef, port int) string {
	return net.JoinHostPort(h.Host, strconv.Itoa(port))
}

// ---------------------------------------------------------------- user inbound

// placeholderHost is the destination a reverse_portal's dokodemo inbound
// stamps on user connections. It is a TEST-NET-1 address (RFC 5737): never
// routable, so even a bug that let it escape would not reach a local service.
// It is never dialled: the bridge rewrites the destination of every relayed
// connection to one of its own targets (see bridge). The port carries the
// destination slot (index of the public port + 1) so that a bridge with a
// target port range can map public port n to target port n.
const placeholderHost = "192.0.2.1"

// userInbound adds the dokodemo inbound that receives user traffic.
func (b *builder) userInbound() string {
	p := b.p
	tag := tagIn(p.in.ID)
	d := jDokodemo{Network: strings.Join(p.networks, ","), UserLevel: p.level}
	pm := map[string]string{}
	if p.in.Kind == spec.KindReversePortal {
		// A portal has no targets: the destination is a placeholder that the
		// bridge overwrites, so the users cannot choose it.
		d.Address, d.Port = placeholderHost, 1
		if n := p.listenPorts.Len(); n > 1 {
			for i := 0; i < n; i++ {
				pm[strconv.Itoa(p.listenPorts.Lo+i)] = net.JoinHostPort(placeholderHost, strconv.Itoa(i+1))
			}
		}
	} else {
		b.userDestination(&d, pm)
	}
	if len(pm) > 0 {
		d.PortMap = pm
	}
	var st *jStream
	if p.in.AcceptProxyProtocol {
		st = &jStream{Sockopt: &jSockopt{AcceptProxyProtocol: true}}
	}
	listen := ""
	if p.listenAddr.IsValid() {
		listen = p.listenAddr.String()
	}
	b.addIn(tag, "dokodemo-door", listen, p.listenPorts.String(), d, st)
	b.claimListen()
	b.c.Stats.InboundTag = tag
	return tag
}

// userDestination fills in the destination of a forward or tunnel_entry user
// inbound from its targets and port map.
func (b *builder) userDestination(d *jDokodemo, pm map[string]string) {
	p := b.p
	switch {
	case len(p.targets) == 1:
		t := p.targets[0]
		d.Address = t.Host.Host
		if t.Ports.Len() == 1 {
			d.Port = uint16(t.Ports.Lo)
		} else {
			for i := 0; i < t.Ports.Len(); i++ {
				pm[strconv.Itoa(p.listenPorts.Lo+i)] = hostPortStr(t.Host, t.Ports.Lo+i)
			}
		}
	case len(p.targets) > 1:
		// The destination is replaced by the per-target freedom redirect;
		// the first target only makes sure the default is never localhost.
		t := p.targets[0]
		d.Address = t.Host.Host
		d.Port = uint16(t.Ports.Lo)
	}
	keys := sortedKeys(p.portMap)
	for _, k := range keys {
		v := p.portMap[k]
		pm[strconv.Itoa(k)] = hostPortStr(v.Host, v.Port)
	}
	if d.Address == "" && len(keys) > 0 {
		d.Address = p.portMap[keys[0]].Host.Host
	}
}

// accessRules emits the ACL rules of an inbound followed by pass (the rule
// that routes allowed traffic) and a final block rule for the inbound.
func (b *builder) accessRules(inTag, block string, pass jRule) {
	acl := b.p.in.ACL
	if acl != nil && len(acl.Deny) > 0 {
		b.addRule(jRule{InboundTag: []string{inTag}, Source: normalizeACL(acl.Deny), OutboundTag: block})
	}
	if acl != nil && len(acl.Allow) > 0 {
		pass.Source = normalizeACL(acl.Allow)
	}
	pass.InboundTag = []string{inTag}
	b.addRule(pass)
	b.addRule(jRule{InboundTag: []string{inTag}, OutboundTag: block})
}

func normalizeACL(in []string) []string {
	out := make([]string, 0, len(in))
	for _, e := range in {
		pf, _ := parsePrefixOrAddr(e) // validated
		if pf.IsSingleIP() {
			out = append(out, pf.Addr().String())
		} else {
			out = append(out, pf.String())
		}
	}
	return out
}

// ---------------------------------------------------------------- forward / entry

func (b *builder) forward() error {
	inTag := b.userInbound()
	block := b.addBlock()
	pass, err := b.targetOutbounds(inTag, "")
	if err != nil {
		return err
	}
	b.accessRules(inTag, block, pass)
	return nil
}

// targetOutbounds creates the freedom outbound(s) of the targets and returns
// the pass rule that routes into them. dialer is the tag of the tunnel
// outbound used as dialerProxy ("" for direct dialling).
func (b *builder) targetOutbounds(inTag, dialer string) (jRule, error) {
	p := b.p
	id := p.in.ID
	var st *jStream
	if dialer != "" {
		st = &jStream{Sockopt: &jSockopt{DialerProxy: dialer}}
	}
	freedom := func(redirect string) jFreedom {
		return jFreedom{Redirect: redirect, UserLevel: p.level, ProxyProtocol: uint32(p.in.ProxyProtocolOut)}
	}
	if len(p.targets) <= 1 {
		tag := tagOut(id)
		b.addOut(tag, "freedom", freedom(""), st)
		b.c.Stats.OutboundTags = append(b.c.Stats.OutboundTags, tag)
		return jRule{OutboundTag: tag}, nil
	}

	// Several targets: one freedom{redirect} per target (repeated by weight
	// for weighted round robin / random) behind a balancer. The selector is
	// a prefix, so outbounds added or removed later are picked up
	// dynamically (used by the health checks).
	n := 0
	var hs *HealthSpec
	if p.health != nil {
		hs = &HealthSpec{
			Strategy:  p.balance,
			IntervalS: orDefault(p.health.IntervalS, 5),
			TimeoutS:  orDefault(p.health.TimeoutS, 2),
			MaxFails:  orDefault(p.health.MaxFails, 3),
		}
	}
	for _, t := range p.targets {
		addr := hostPortStr(t.Host, t.Ports.Lo)
		ht := HealthTarget{Addr: addr}
		copies := t.Weight
		if p.balance == "failover" {
			copies = 1
		}
		for k := 0; k < copies; k++ {
			tag := tagOutN(id, n)
			n++
			b.addOut(tag, "freedom", freedom(addr), st)
			b.c.Stats.OutboundTags = append(b.c.Stats.OutboundTags, tag)
			ht.Tags = append(ht.Tags, tag)
		}
		if hs != nil {
			hs.Targets = append(hs.Targets, ht)
		}
	}
	b.c.Health = hs
	strategy := "roundRobin"
	if p.balance == "random" {
		strategy = "random"
	}
	bal := tagBalancer(id)
	b.c.Balancers = append(b.c.Balancers, mustJSON(jBalancer{
		Tag: bal, Selector: []string{outSelector(id)}, Strategy: jStrategy{Type: strategy},
	}))
	return jRule{BalancerTag: bal}, nil
}

func orDefault(v, d int) int {
	if v == 0 {
		return d
	}
	return v
}

func (b *builder) entry() error {
	p := b.p
	inTag := b.userInbound()
	block := b.addBlock()
	if err := b.tunnelClient(); err != nil {
		return err
	}
	tun := tagTunnelOut(p.in.ID)
	if len(p.targets) > 1 || p.in.ProxyProtocolOut > 0 {
		// The PROXY header is written by freedom on the stream it dials
		// through the tunnel (dialerProxy), so the client address reaches
		// the final target intact. Several targets are balanced the same way.
		pass, err := b.targetOutbounds(inTag, tun)
		if err != nil {
			return err
		}
		b.accessRules(inTag, block, pass)
		return nil
	}
	// Plain tunnel: route straight into the VLESS client; the destination is
	// the one the user inbound sets (target, port map).
	b.c.Stats.OutboundTags = append(b.c.Stats.OutboundTags, tun)
	b.accessRules(inTag, block, jRule{OutboundTag: tun})
	return nil
}

// ---------------------------------------------------------------- tunnel

func (b *builder) tunnelClient() error {
	p := b.p
	t := p.tunnel
	cr, err := deriveCreds(p.in.Secret)
	if err != nil {
		return p.fail("credential derivation failed")
	}
	enc := "none"
	if t.VlessEnc {
		enc = cr.Encryption
	}
	out := jVlessOut{
		Address: t.Server.Host, Port: t.ServerP, ID: cr.UUID, Level: p.level,
		Email: clientEmail(p.in.ID), Encryption: enc,
	}
	b.addOut(tagTunnelOut(p.in.ID), "vless", out, b.tunnelStream(false, nil))
	return nil
}

func (b *builder) tunnelServer(users bool) (*credentials, error) {
	p := b.p
	t := p.tunnel
	cr, err := deriveCreds(p.in.Secret)
	if err != nil {
		return nil, p.fail("credential derivation failed")
	}
	dec := "none"
	if t.VlessEnc {
		dec = cr.Decryption
	}
	var cert *jCert
	if t.TLS {
		cert, err = b.serverCert()
		if err != nil {
			return nil, err
		}
	}
	tag := tagTunnelIn(p.in.ID)
	b.addIn(tag, "vless", t.ListenA.String(), strconv.Itoa(t.ListenP),
		jVlessIn{Clients: []jVlessClient{{ID: cr.UUID, Email: clientEmail(p.in.ID), Level: p.level}}, Decryption: dec},
		b.tunnelStream(true, cert))
	b.c.Claims = append(b.c.Claims, Claim{Proto: "tcp", Addr: t.ListenA.String(), Port: t.ListenP})
	return cr, nil
}

// serverCert resolves the certificate of the accepting side.
func (b *builder) serverCert() (*jCert, error) {
	p := b.p
	c := p.tunnel.Cert
	switch c.Mode {
	case "self":
		certPEM, keyPEM, _, err := SelfCert(p.in.Secret, p.tunnel.SNI)
		if err != nil {
			return nil, p.fail("self-signed certificate generation failed")
		}
		return &jCert{Cert: splitLines(certPEM), Key: splitLines(keyPEM), OneTimeLoading: true}, nil
	case "panel":
		certPEM, keyPEM, err := p.opts.PanelCert(p.in.ID)
		if err != nil || certPEM == "" || keyPEM == "" {
			return nil, p.fail("panel certificate is not available")
		}
		return &jCert{Cert: splitLines(certPEM), Key: splitLines(keyPEM), OneTimeLoading: true}, nil
	default: // file
		// OneTimeLoading avoids the never-ending reload goroutine Xray
		// starts for file certificates; Apply folds the file contents into
		// the instance hash so a renewed certificate restarts the inbound.
		b.c.CertFiles = append(b.c.CertFiles, c.CertFile, c.KeyFile)
		return &jCert{CertFile: c.CertFile, KeyFile: c.KeyFile, OneTimeLoading: true}, nil
	}
}

func splitLines(s string) []string {
	return strings.Split(strings.TrimRight(s, "\n"), "\n")
}

// tunnelStream builds the stream settings of the tunnel carrier.
func (b *builder) tunnelStream(server bool, cert *jCert) *jStream {
	p := b.p
	t := p.tunnel
	st := &jStream{Network: t.Network}
	if t.TLS {
		st.Security = "tls"
		tls := &jTLS{ALPN: t.alpn(), MinVersion: "1.2"}
		if server {
			tls.Certs = []jCert{*cert}
		} else {
			tls.ServerName = t.clientServerName()
			if t.Pin != "" {
				tls.Pin = t.Pin
				// Pinned tunnels connect directly to a peer that may use an
				// Ed25519 certificate (self mode); Go's TLS stack offers
				// it, the default Chrome fingerprint does not.
				tls.Fingerprint = "unsafe"
			}
		}
		st.TLS = tls
	}
	switch t.Network {
	case "ws":
		st.WS = &jWS{Path: t.Path, Host: t.Host}
	case "grpc":
		st.GRPC = &jGRPC{ServiceName: t.Path, Authority: t.Host}
	case "xhttp":
		st.XHTTP = &jXHTTP{Path: t.Path, Host: t.Host, Mode: "auto"}
	}
	// Detect dead tunnel connections (half-open reverse links) in time.
	st.Sockopt = &jSockopt{TCPKeepAliveIdle: 30, TCPKeepAliveInterval: 10}
	return st
}

func (t *tunnelPlan) alpn() []string {
	if len(t.ALPN) > 0 {
		return t.ALPN
	}
	switch t.Network {
	case "ws":
		return []string{"http/1.1"}
	case "grpc", "xhttp":
		return []string{"h2"}
	}
	return nil
}

func (t *tunnelPlan) clientServerName() string {
	switch {
	case t.SNI != "":
		return t.SNI
	case t.Host != "":
		return t.Host
	case !t.Server.IsIP:
		return t.Server.Host
	}
	return ""
}

// allowRules emits the destination whitelist of a relaying inbound: one rule
// per allowed destination, then (unless everything is allowed) nothing else;
// the caller appends the final block rule.
func (b *builder) allowRules(inTag string, users []string, dests []target, out string, networks string) {
	for _, d := range dests {
		r := jRule{InboundTag: []string{inTag}, User: users, Port: d.Ports.String(), OutboundTag: out}
		if d.Host.IsIP {
			r.IP = []string{d.Host.Host}
		} else {
			r.Domain = []string{"full:" + d.Host.Host}
		}
		if networks != "tcp,udp" {
			r.Network = networks
		}
		b.addRule(r)
	}
}

func (b *builder) exit() error {
	p := b.p
	id := p.in.ID
	if _, err := b.tunnelServer(true); err != nil {
		return err
	}
	inTag := tagTunnelIn(id)
	block := b.addBlock()
	out := tagOut(id)
	b.addOut(out, "freedom", jFreedom{UserLevel: p.level, ProxyProtocol: uint32(p.in.ProxyProtocolOut)}, nil)
	b.c.Stats.InboundTag = inTag
	b.c.Stats.OutboundTags = []string{out}
	users := []string{clientEmail(id)}
	// ACL on the tunnel source (the entry machines).
	if acl := p.in.ACL; acl != nil && len(acl.Deny) > 0 {
		b.addRule(jRule{InboundTag: []string{inTag}, Source: normalizeACL(acl.Deny), OutboundTag: block})
	}
	var src []string
	if acl := p.in.ACL; acl != nil && len(acl.Allow) > 0 {
		src = normalizeACL(acl.Allow)
	}
	if p.allowAny {
		b.addRule(jRule{InboundTag: []string{inTag}, User: users, Source: src, OutboundTag: out})
	} else {
		start := len(b.c.Rules)
		b.allowRules(inTag, users, p.targets, out, strings.Join(p.networks, ","))
		if len(src) > 0 {
			for i := start; i < len(b.c.Rules); i++ {
				var r jRule
				_ = json.Unmarshal(b.c.Rules[i], &r)
				r.Source = src
				b.c.Rules[i] = mustJSON(r)
			}
		}
	}
	b.addRule(jRule{InboundTag: []string{inTag}, OutboundTag: block})
	return nil
}

// ---------------------------------------------------------------- reverse

func (b *builder) portal() error {
	p := b.p
	id := p.in.ID
	if _, err := b.tunnelServer(true); err != nil {
		return err
	}
	tunIn := tagTunnelIn(id)
	userIn := b.userInbound()
	block := b.addBlock()
	rev := tagReverse(id)
	b.c.Reverse = &ReverseSpec{Role: "portal", Tag: rev, Domain: p.rdomain}
	// The rendezvous request of the bridge goes to the portal; everything
	// else arriving on the tunnel inbound is refused, so a holder of the
	// secret cannot use the tunnel inbound as a proxy.
	b.addRule(jRule{InboundTag: []string{tunIn}, User: []string{clientEmail(id)}, Domain: []string{"full:" + p.rdomain}, OutboundTag: rev})
	b.addRule(jRule{InboundTag: []string{tunIn}, OutboundTag: block})
	b.accessRules(userIn, block, jRule{OutboundTag: rev})
	b.c.Stats.InboundTag = userIn
	return nil
}

// bridge compiles the dialling side of a reverse proxy. Every connection the
// portal relays enters under the inbound tag rev and is rewritten to one of
// the bridge's own targets: each destination outbound is a freedom with a
// redirect, and there is no rule that routes rev traffic to a freedom without
// one, so neither the portal nor its users can pick the destination. The only
// other routes are the rendezvous request (to the tunnel, to reach the portal
// itself) and the final block.
func (b *builder) bridge() error {
	p := b.p
	id := p.in.ID
	if err := b.tunnelClient(); err != nil {
		return err
	}
	block := b.addBlock()
	rev := tagReverse(id)
	b.c.Reverse = &ReverseSpec{Role: "bridge", Tag: rev, Domain: p.rdomain}
	b.c.Stats.InboundTag = rev
	// The bridge worker dials the rendezvous domain with inbound tag rev.
	b.addRule(jRule{InboundTag: []string{rev}, Domain: []string{"full:" + p.rdomain}, OutboundTag: tagTunnelOut(id)})
	// A relay restricted to the instance's networks; both networks need no
	// condition.
	network := ""
	if n := strings.Join(p.networks, ","); n != "tcp,udp" {
		network = n
	}
	redirect := func(tag string, t target, port int) {
		b.addOut(tag, "freedom", jFreedom{
			Redirect: hostPortStr(t.Host, port), UserLevel: p.level, ProxyProtocol: uint32(p.in.ProxyProtocolOut),
		}, nil)
		b.c.Stats.OutboundTags = append(b.c.Stats.OutboundTags, tag)
	}
	switch {
	case len(p.targets) > 1:
		pass, err := b.targetOutbounds(rev, "")
		if err != nil {
			return err
		}
		pass.InboundTag, pass.Network = []string{rev}, network
		b.addRule(pass)
	case p.slots > 1:
		// Target port range: public port n (slot n) goes to target port n.
		t := p.targets[0]
		for k := 0; k < p.slots; k++ {
			tag := tagOutN(id, k)
			redirect(tag, t, t.Ports.Lo+k)
			b.addRule(jRule{InboundTag: []string{rev}, Port: strconv.Itoa(k + 1), Network: network, OutboundTag: tag})
		}
	default:
		tag := tagOut(id)
		redirect(tag, p.targets[0], p.targets[0].Ports.Lo)
		b.addRule(jRule{InboundTag: []string{rev}, Network: network, OutboundTag: tag})
	}
	b.addRule(jRule{InboundTag: []string{rev}, OutboundTag: block})
	return nil
}
