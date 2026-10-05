package gost

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/spec"
)

const (
	// fragmentFile is the only file of an Artifact: the instance's share of
	// the gost configuration (services plus the objects they reference).
	fragmentFile = "fragment.json"
	// driverTag is mixed into every artifact hash; bump it whenever the
	// rendering of an unchanged instance changes.
	driverTag = "w1ncray/driver/gost/1"
	// dummyTarget is the address a tunnel entry asks the exit for when it has
	// no targets of its own (the exit then picks the target itself). Port 0
	// can never be connected to, so an exit that wrongly honours the request
	// fails closed.
	dummyTarget = "127.0.0.1:0"
)

// relayUser derives the gost relay username shared by the two ends of a
// tunnel or reverse link. gost matches the connector's auth against the
// handler's auth, so both sides must render the same username; deriving it
// from the shared secret (instead of the instance id) makes the two ends
// agree and does not leak ids or secrets into configs or logs.
func relayUser(secret string) string {
	sum := sha256.Sum256([]byte("w1ncray relay " + secret))
	return hex.EncodeToString(sum[:6])
}

// gostBytes formats bytes/s for a gost traffic-limiter limits string.
// gost parses limits with units.ParseBase2Bytes, which rejects bare
// integers (they parse to 0 and the limiter is silently not created);
// an explicit B suffix is always accepted.
func gostBytes(n int64) string { return strconv.FormatInt(n, 10) + "B" }

// Render implements driver.Driver. It is a pure function of in.
func (d *Driver) Render(in spec.Instance) (driver.Artifact, error) {
	p, err := d.analyze(in)
	if err != nil {
		return driver.Artifact{}, err
	}
	frag, claims := p.build()
	b, err := json.MarshalIndent(frag, "", " ")
	if err != nil {
		return driver.Artifact{}, fmt.Errorf("gost: marshal fragment: %w", err)
	}
	files := map[string][]byte{fragmentFile: b}
	return driver.Artifact{Files: files, Hash: hashFiles(files), PortClaims: claims}, nil
}

// hashFiles is sha256 over the driver tag and the files in name order. The
// fragment contains the tunnel secret, so only the digest ever leaves the
// driver in logs or status.
func hashFiles(files map[string][]byte) string {
	h := sha256.New()
	h.Write([]byte(driverTag))
	h.Write([]byte{0})
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		h.Write([]byte(n))
		h.Write([]byte{0})
		h.Write(files[n])
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func svcName(id, network string, port int) string {
	return id + "." + network + "." + strconv.Itoa(port)
}

func (p *plan) chainName() string { return p.id + ".chain" }

// build turns the plan into the instance's gost objects and its port claims.
func (p *plan) build() (fragment, []driver.PortClaim) {
	var f fragment
	var claims []driver.PortClaim

	// ACL and limits are shared by every service of the instance.
	var admRefs []string
	if len(p.allow) > 0 {
		f.Admissions = append(f.Admissions, admission{Name: p.id + ".allow", Whitelist: true, Matchers: p.allow})
		admRefs = append(admRefs, p.id+".allow")
	}
	if len(p.deny) > 0 {
		f.Admissions = append(f.Admissions, admission{Name: p.id + ".deny", Matchers: p.deny})
		admRefs = append(admRefs, p.id+".deny")
	}
	var limRef, climRef string
	if p.rateUp > 0 || p.rateDown > 0 {
		limRef = p.id + ".limit"
		f.Limiters = append(f.Limiters, limiter{Name: limRef, Limits: []string{fmt.Sprintf("$ %s %s", gostBytes(p.rateUp), gostBytes(p.rateDown))}})
	}
	if p.maxConns > 0 {
		climRef = p.id + ".climit"
		f.CLimiters = append(f.CLimiters, limiter{Name: climRef, Limits: []string{fmt.Sprintf("$ %d", p.maxConns)}})
	}

	switch p.kind {
	case spec.KindForward, spec.KindTunnelEntry, spec.KindReverseBridge:
		if p.kind != spec.KindForward {
			f.Chains = append(f.Chains, p.buildChain())
		}
		for _, n := range p.nets {
			for i := 0; i < p.lports.count; i++ {
				lp := p.lports.at(i)
				s := service{
					Name:       svcName(p.id, n, lp),
					Addr:       net.JoinHostPort(p.listen.String(), strconv.Itoa(lp)),
					Admissions: admRefs,
					Limiter:    limRef,
					CLimiter:   climRef,
					Metadata:   map[string]string{"enableStats": "true"},
					Handler:    handler{Type: n},
					Listener:   listener{Type: n},
				}
				if p.kind == spec.KindReverseBridge {
					rt := "r" + n // rtcp | rudp
					s.Handler.Type, s.Listener.Type, s.Listener.Chain = rt, rt, p.chainName()
				} else if p.kind == spec.KindTunnelEntry {
					s.Handler.Chain = p.chainName()
				}
				hmd := map[string]string{}
				if n == "tcp" {
					if p.idleTCP > 0 {
						hmd["idleTimeout"] = durStr(p.idleTCP)
					}
					if p.proxyOut > 0 {
						hmd["proxyProtocol"] = strconv.Itoa(p.proxyOut)
					}
					if p.proxyIn {
						s.Metadata["proxyProtocol"] = "2"
					}
				} else {
					s.Listener.Metadata = map[string]string{"ttl": durStr(p.idleUDP)}
				}
				if len(hmd) > 0 {
					s.Handler.Metadata = hmd
				}
				s.Forwarder = p.forwarderFor(i, lp)
				f.Services = append(f.Services, s)
				if p.kind != spec.KindReverseBridge {
					claims = append(claims, driver.PortClaim{Proto: n, Addr: p.listen.String(), Port: lp, Owner: p.id})
				}
			}
		}

	case spec.KindTunnelExit:
		s := service{
			Name:       p.id + ".tunnel",
			Addr:       p.tun.listen.String(),
			Admissions: admRefs,
			Metadata:   map[string]string{"enableStats": "true"},
			Handler:    handler{Type: "relay", Auth: &auth{Username: relayUser(p.secret), Password: p.secret}},
			Listener:   p.tunnelListener(),
		}
		if len(p.targets) > 0 {
			s.Forwarder = p.exitForwarder()
		}
		f.Services = append(f.Services, s)
		claims = append(claims, driver.PortClaim{Proto: "tcp", Addr: p.tun.listen.Addr().String(), Port: int(p.tun.listen.Port()), Owner: p.id})

	case spec.KindReversePortal:
		s := service{
			Name:       p.id + ".portal",
			Addr:       p.tun.listen.String(),
			Admissions: admRefs,
			Metadata:   map[string]string{"enableStats": "true"},
			Handler: handler{Type: "relay", Auth: &auth{Username: relayUser(p.secret), Password: p.secret},
				Metadata: map[string]string{"bind": "true"}},
			Listener: p.tunnelListener(),
		}
		f.Services = append(f.Services, s)
		claims = append(claims, driver.PortClaim{Proto: "tcp", Addr: p.tun.listen.Addr().String(), Port: int(p.tun.listen.Port()), Owner: p.id})
		// The public ports are bound by the relay handler when the bridge
		// asks for them; claim them so the port ledger reserves them.
		if p.hasLis {
			for _, n := range p.nets {
				for i := 0; i < p.lports.count; i++ {
					claims = append(claims, driver.PortClaim{Proto: n, Addr: p.listen.String(), Port: p.lports.at(i), Owner: p.id})
				}
			}
		}
	}
	return f, claims
}

func durStr(d time.Duration) string {
	if d%time.Second == 0 {
		return strconv.Itoa(int(d/time.Second)) + "s"
	}
	return d.String()
}

// tunnelListener is the carrier listener of an exit or portal.
func (p *plan) tunnelListener() listener {
	l := listener{Type: p.tun.typ}
	if p.tun.path != "" {
		l.Metadata = map[string]string{"path": p.tun.path}
	}
	if p.tun.tlsBased && p.tun.certFile != "" {
		l.TLS = &tlsConf{CertFile: p.tun.certFile, KeyFile: p.tun.keyFile}
	}
	return l
}

// buildChain is the entry/bridge side of the tunnel: one relay hop.
func (p *plan) buildChain() chain {
	t := p.tun
	dl := dialer{Type: t.typ}
	md := map[string]string{}
	if t.path != "" {
		md["path"] = t.path
	}
	if t.hostHdr != "" {
		md["host"] = t.hostHdr
	}
	if len(md) > 0 {
		dl.Metadata = md
	}
	if t.tlsBased {
		tc := &tlsConf{ServerName: t.sni}
		if t.certFile != "" {
			// Verify the exit's chain against the given certificate/CA; gost
			// skips the host name check in this mode, which suits a
			// self-issued exit certificate.
			tc.CAFile = t.certFile
		} else {
			// No anchor given: full verification against the system roots,
			// including the host name (SNI, or the server host).
			tc.Secure = true
		}
		dl.TLS = tc
	}
	return chain{
		Name: p.chainName(),
		Hops: []hop{{
			Name: p.id + ".hop",
			Nodes: []chainNode{{
				Name:      p.id + ".node",
				Addr:      t.server.String(),
				Connector: connector{Type: "relay", Auth: &auth{Username: relayUser(p.secret), Password: p.secret}},
				Dialer:    dl,
			}},
		}},
	}
}

func (p *plan) selectorFor(n int) *selector {
	if n < 2 {
		return nil
	}
	return &selector{Strategy: p.balance.strategy, MaxFails: p.balance.maxFails, FailTimeout: int64(p.balance.failTimeout)}
}

// forwarderFor builds the target set of listen port index i (port lp).
func (p *plan) forwarderFor(i, lp int) *forwarder {
	var nodes []node
	if hp, ok := p.portMap[lp]; ok {
		nodes = []node{{Name: "t0", Addr: hp.String()}}
	} else if len(p.targets) == 0 {
		// Tunnel entry without targets: the exit decides.
		nodes = []node{{Name: "t0", Addr: dummyTarget}}
	} else {
		for ti, t := range p.targets {
			port := t.ports.start
			if t.ports.count > 1 {
				port = t.ports.at(i)
			}
			nd := node{Name: "t" + strconv.Itoa(ti), Addr: net.JoinHostPort(t.host, strconv.Itoa(port))}
			if p.balance.strategy == "random" && t.weight > 1 {
				nd.Metadata = map[string]string{"weight": strconv.Itoa(t.weight)}
			}
			nodes = append(nodes, nd)
		}
	}
	return &forwarder{Selector: p.selectorFor(len(nodes)), Nodes: nodes}
}

// exitForwarder is the fixed target group of a tunnel exit (gost's relay
// handler "forward mode": the address requested by the entry is ignored).
func (p *plan) exitForwarder() *forwarder {
	var nodes []node
	for ti, t := range p.targets {
		nd := node{Name: "t" + strconv.Itoa(ti), Addr: net.JoinHostPort(t.host, strconv.Itoa(t.ports.start))}
		if p.balance.strategy == "random" && t.weight > 1 {
			nd.Metadata = map[string]string{"weight": strconv.Itoa(t.weight)}
		}
		nodes = append(nodes, nd)
	}
	return &forwarder{Selector: p.selectorFor(len(nodes)), Nodes: nodes}
}

// serviceNames lists the gost services of a fragment.
func (f fragment) serviceNames() []string {
	names := make([]string, 0, len(f.Services))
	for _, s := range f.Services {
		names = append(names, s.Name)
	}
	return names
}

// instanceOfService maps a gost service name back to the instance id: names
// are "<id>.<proto>.<port>", "<id>.tunnel" or "<id>.portal" and ids never
// contain a dot.
func instanceOfService(name string) string {
	if i := strings.IndexByte(name, '.'); i > 0 {
		return name[:i]
	}
	return name
}
