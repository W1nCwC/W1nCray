package realm

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strconv"
	"strings"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/spec"
)

// tunnelInfo is the validated, normalised tunnel description shared by entry
// and exit.
type tunnelInfo struct {
	t     spec.Tunnel
	path  string // effective ws path, secret token included
	tlsOn bool
	wsOn  bool
}

// tunnelCommon validates what tunnel entry and exit share.
func (d *Driver) tunnelCommon(in spec.Instance, tcp, udp bool) (tunnelInfo, error) {
	var ti tunnelInfo
	if in.Tunnel == nil {
		return ti, fieldErr("tunnel", "required for kind %s", in.Kind)
	}
	if in.Listen != nil && len(in.Listen.PortMap) > 0 {
		return ti, fieldErr("listen.port_map", "a realm tunnel carries no destination; port_map is not possible")
	}
	if udp || !tcp {
		return ti, fieldErr("network", "realm tunnels carry TCP only (the transport is never applied to UDP); network must be [tcp]")
	}
	t := *in.Tunnel
	ti.t = t
	switch t.Type {
	case "tcp":
	case "tls":
		ti.tlsOn = true
	case "ws":
		ti.wsOn = true
	case "wss":
		ti.wsOn, ti.tlsOn = true, true
	case "grpc", "xhttp", "kcp", "quic":
		return ti, fieldErr("tunnel.type", "realm cannot carry %s (tcp, tls, ws, wss)", show(t.Type))
	default:
		return ti, fieldErr("tunnel.type", "unknown type %s", show(t.Type))
	}
	switch t.Security {
	case "":
	case "none":
		if ti.tlsOn {
			return ti, fieldErr("tunnel.security", "type %s is TLS; security none contradicts it", t.Type)
		}
	case "tls":
		if !ti.tlsOn {
			return ti, fieldErr("tunnel.security", "security tls needs tunnel type tls or wss")
		}
	case "tls_pin":
		return ti, fieldErr("tunnel.security", "realm cannot pin certificates (it verifies against the built-in Mozilla roots only)")
	case "tls_self":
		return ti, fieldErr("tunnel.security", "realm cannot verify a self-signed certificate (it trusts the built-in public CA roots only); use the gost or xray engine for security tls_self")
	case "vless_enc":
		return ti, fieldErr("tunnel.security", "VLESS encryption exists in the xray engine only")
	default:
		return ti, fieldErr("tunnel.security", "unknown security %s", show(t.Security))
	}
	if t.PinSHA256 != "" {
		return ti, fieldErr("tunnel.pin_sha256", "realm cannot pin certificates")
	}

	if ti.wsOn {
		if !validHostHeader(t.Host) {
			return ti, fieldErr("tunnel.host", "a valid Host header value is required for ws (realm checks it), got %s", show(t.Host))
		}
		if !validPath(t.Path) {
			return ti, fieldErr("tunnel.path", "a path of [A-Za-z0-9/._~-] starting with / is required for ws, got %s", show(t.Path))
		}
		ti.path = t.Path
		if in.Secret != "" {
			if len(in.Secret) < minSecretLen || len(in.Secret) > 256 {
				return ti, fieldErr("secret", "length must be %d-256 when used for the ws path token", minSecretLen)
			}
			ti.path = deriveTokenPath(t.Path, in.Secret)
		}
	} else {
		if t.Host != "" || t.Path != "" {
			return ti, fieldErr("tunnel.host", "host and path apply to ws/wss only")
		}
		if in.Secret != "" {
			return ti, fieldErr("secret", "realm cannot authenticate a %s tunnel with a shared secret (only a ws path token is possible); use ws/wss or leave the secret empty", t.Type)
		}
	}
	return ti, nil
}

// deriveTokenPath appends a 128-bit token derived from the secret to the
// configured path. Entry and exit compute it from the same Secret and Path;
// the secret itself never reaches the configuration file.
func deriveTokenPath(base, secret string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte("w1ncray/realm/ws-path/v1\x00" + base))
	tok := hex.EncodeToString(m.Sum(nil))[:32]
	return strings.TrimRight(base, "/") + "/" + tok
}

func (d *Driver) planEntry(p *plan, in spec.Instance, nc *netConf, tcp, udp bool) error {
	if len(in.Targets) > 0 {
		return fieldErr("targets", "a realm tunnel entry has no targets; the destination is configured on the exit instance")
	}
	if in.Balance != nil {
		return fieldErr("balance", "a realm tunnel entry dials exactly one exit")
	}
	if in.Listen == nil {
		return fieldErr("listen", "required")
	}
	ti, err := d.tunnelCommon(in, tcp, udp)
	if err != nil {
		return err
	}
	t := ti.t
	if t.Listen != "" {
		return fieldErr("tunnel.listen", "not allowed on a tunnel entry")
	}
	if t.Cert != nil {
		return fieldErr("tunnel.cert", "a certificate belongs to the tunnel exit")
	}
	addr, err := parseListenAddr("listen.addr", in.Listen.Addr)
	if err != nil {
		return err
	}
	lr, err := parsePorts("listen.ports", in.Listen.Ports)
	if err != nil {
		return err
	}
	if lr.n() != 1 {
		return fieldErr("listen.ports", "a realm tunnel entry takes exactly one port (the tunnel carries no destination, so ranges cannot map one to one)")
	}
	host, isIP, port, err := parseHostPort("tunnel.server", t.Server)
	if err != nil {
		return err
	}

	// remote_transport: the client side towards the exit.
	var parts []string
	if ti.wsOn {
		h, err := dslValue("host", t.Host)
		if err != nil {
			return err
		}
		pth, err := dslValue("path", ti.path)
		if err != nil {
			return err
		}
		parts = append(parts, "ws", "host="+h, "path="+pth)
	}
	if ti.tlsOn {
		if !validHostname(t.SNI) {
			return fieldErr("tunnel.sni", "a DNS name is required for TLS (realm verifies the certificate against it), got %s", show(t.SNI))
		}
		sni, err := dslValue("sni", t.SNI)
		if err != nil {
			return err
		}
		parts = append(parts, "tls", "sni="+strings.ToLower(sni))
		if len(t.ALPN) > 0 {
			if len(t.ALPN) > 8 {
				return fieldErr("tunnel.alpn", "at most 8 protocols")
			}
			for _, a := range t.ALPN {
				if !alpnRe.MatchString(a) {
					return fieldErr("tunnel.alpn", "invalid protocol %s", show(a))
				}
				if _, err := dslValue("alpn", a); err != nil {
					return err
				}
			}
			parts = append(parts, "alpn="+strings.Join(t.ALPN, ","))
		}
		if d.opts.InsecureSkipTLSVerify {
			parts = append(parts, "insecure")
		}
	} else if t.SNI != "" || len(t.ALPN) > 0 {
		return fieldErr("tunnel.sni", "sni and alpn apply to TLS tunnels only")
	}

	ep := endpointConf{
		Listen:          netip.AddrPortFrom(addr, uint16(lr.lo)).String(),
		Remote:          joinHostPort(host, isIP, port),
		RemoteTransport: strings.Join(parts, ";"),
		Network:         nc,
	}
	p.endpoints = append(p.endpoints, ep)
	p.claims = append(p.claims, driver.PortClaim{Proto: "tcp", Addr: addr.String(), Port: lr.lo, Owner: in.ID})
	return nil
}

func (d *Driver) planExit(p *plan, in spec.Instance, nc *netConf, tcp, udp bool) error {
	if in.Listen != nil && (in.Listen.Addr != "" || in.Listen.Ports != "" || len(in.Listen.PortMap) > 0) {
		return fieldErr("listen", "a tunnel exit listens on tunnel.listen only")
	}
	ti, err := d.tunnelCommon(in, tcp, udp)
	if err != nil {
		return err
	}
	t := ti.t
	if t.Server != "" {
		return fieldErr("tunnel.server", "not allowed on a tunnel exit")
	}
	if len(t.ALPN) > 0 {
		return fieldErr("tunnel.alpn", "realm's TLS server cannot set ALPN")
	}
	if len(in.Targets) == 0 {
		return fieldErr("targets", "a realm exit needs a fixed target list (allow_any_target is not supported)")
	}
	la, err := netip.ParseAddrPort(t.Listen)
	if err != nil || la.Addr().Zone() != "" || la.Port() == 0 {
		return fieldErr("tunnel.listen", "an IP literal and port are required, got %s", show(t.Listen))
	}
	ts, err := parseTargets(in)
	if err != nil {
		return err
	}
	for i, tg := range ts {
		if tg.ports.n() != 1 {
			return fieldErr("targets["+strconv.Itoa(i)+"].ports", "a tunnel exit target takes exactly one port")
		}
	}
	bal, err := balanceString(in.Balance, ts)
	if err != nil {
		return err
	}
	if len(ts) > 1 && in.Balance != nil && in.Balance.Strategy == "iphash" && in.AcceptProxyProtocol {
		return fieldErr("balance.strategy", "iphash hashes the TCP peer, not the PROXY header source; incompatible with accept_proxy_protocol")
	}

	// listen_transport: the server side towards the entry.
	var parts []string
	if ti.wsOn {
		h, err := dslValue("host", t.Host)
		if err != nil {
			return err
		}
		pth, err := dslValue("path", ti.path)
		if err != nil {
			return err
		}
		parts = append(parts, "ws", "host="+h, "path="+pth)
	}
	if ti.tlsOn {
		parts = append(parts, "tls")
		switch {
		case t.Cert == nil:
			return fieldErr("tunnel.cert", "required for a TLS exit")
		case t.Cert.Mode == "file":
			if !validFilePath(t.Cert.CertFile) || !validFilePath(t.Cert.KeyFile) {
				return fieldErr("tunnel.cert", "cert_file and key_file must be absolute paths of [A-Za-z0-9/\\._@+~-]")
			}
			c, err := dslValue("cert_file", t.Cert.CertFile)
			if err != nil {
				return err
			}
			k, err := dslValue("key_file", t.Cert.KeyFile)
			if err != nil {
				return err
			}
			parts = append(parts, "cert="+c, "key="+k)
		case t.Cert.Mode == "self":
			if !d.opts.InsecureSkipTLSVerify {
				return fieldErr("tunnel.cert", "a self-signed certificate cannot be verified by a realm entry (it trusts public CAs only); use cert mode file with a CA-signed certificate")
			}
			if !validHostname(t.SNI) {
				return fieldErr("tunnel.sni", "a DNS name is required as the self-signed certificate name, got %s", show(t.SNI))
			}
			sni, err := dslValue("sni", t.SNI)
			if err != nil {
				return err
			}
			parts = append(parts, "servername="+strings.ToLower(sni))
		case t.Cert.Mode == "panel":
			return fieldErr("tunnel.cert", "mode panel must be materialised by the agent as mode file before it reaches the driver")
		default:
			return fieldErr("tunnel.cert", "unknown mode %s", show(t.Cert.Mode))
		}
	} else if t.Cert != nil || t.SNI != "" {
		return fieldErr("tunnel.cert", "certificate and sni apply to TLS tunnels only")
	}

	for i, tg := range ts {
		r := joinHostPort(tg.host, tg.isIP, tg.ports.lo)
		if i == 0 {
			p.endpoints = append(p.endpoints, endpointConf{})
			p.endpoints[0].Remote = r
		} else {
			p.endpoints[0].ExtraRemotes = append(p.endpoints[0].ExtraRemotes, r)
		}
	}
	ep := &p.endpoints[0]
	ep.Listen = la.String()
	ep.Balance = bal
	ep.ListenTransport = strings.Join(parts, ";")
	ep.Network = nc
	p.claims = append(p.claims, driver.PortClaim{Proto: "tcp", Addr: la.Addr().String(), Port: int(la.Port()), Owner: in.ID})
	return nil
}
