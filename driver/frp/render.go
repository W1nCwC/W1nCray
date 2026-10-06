package frp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/spec"
)

const (
	fileFrps = "frps.toml"
	fileFrpc = "frpc.toml"

	proxiesMarker = "\n[[proxies]]\n"
)

// tomlW writes TOML with every string checked: the character set accepted
// here is the last line of defence against config/template injection, on top
// of the per-field validation in buildPlan.
type tomlW struct {
	b   bytes.Buffer
	err error
}

// safeString reports whether s may be written inside a basic TOML string.
// Backslash is allowed (and escaped) only for Windows paths.
func safeString(s string) bool {
	for _, r := range s {
		switch {
		case r < 0x20 || r == 0x7f:
			return false
		case r == '"' || r == '{' || r == '}' || r == '#' || r == '$' || r == '`' || r == '\'':
			return false
		case r > 0x7e:
			return false
		}
	}
	return true
}

func (w *tomlW) fail(format string, args ...any) {
	if w.err == nil {
		w.err = errf(format, args...)
	}
}

func (w *tomlW) line(s string) { w.b.WriteString(s); w.b.WriteByte('\n') }

func quote(s string) string {
	return `"` + strings.ReplaceAll(s, `\`, `\\`) + `"`
}

func (w *tomlW) str(key, val string) {
	if !safeString(val) {
		w.fail("refusing to write unsafe value for %s", key)
		return
	}
	w.line(key + " = " + quote(val))
}

func (w *tomlW) num(key string, v int) { w.line(key + " = " + strconv.Itoa(v)) }

func (w *tomlW) boolean(key string, v bool) { w.line(key + " = " + strconv.FormatBool(v)) }

func (w *tomlW) raw(s string) { w.line(s) }

func (w *tomlW) blank() { w.b.WriteByte('\n') }

// Render implements driver.Driver: a pure function of the instance and the
// driver version.
func (d *Driver) Render(in spec.Instance) (driver.Artifact, error) {
	u, err := compile(in)
	if err != nil {
		return driver.Artifact{}, err
	}
	return u.artifact(), nil
}

// compile validates in and renders it to a unit (rendered text + metadata).
func compile(in spec.Instance) (*unit, error) {
	p, err := buildPlan(in)
	if err != nil {
		return nil, err
	}
	var name string
	var body []byte
	var common string
	switch p.Role {
	case rolePortal:
		name = fileFrps
		body, err = renderFrps(p)
		common = string(body)
	default:
		name = fileFrpc
		body, err = renderFrpc(p)
		if err == nil {
			common = string(body)
			if i := strings.Index(common, proxiesMarker); i >= 0 {
				common = common[:i]
			}
		}
	}
	if err != nil {
		return nil, err
	}
	if err := checkRendered(body); err != nil {
		return nil, err
	}
	u := &unit{
		ID:         p.ID,
		Role:       p.Role,
		Files:      map[string][]byte{name: body},
		Networks:   p.Networks,
		Claims:     claims(p),
		CommonHash: sum([]byte(common)),
		Transport:  p.Transport,
	}
	u.Hash = hashFiles(u.Files)
	if p.Role == rolePortal {
		u.ControlAddr = p.BindAddr
		u.ControlPort = p.BindPort
	} else {
		for _, px := range p.Proxies {
			u.Proxies = append(u.Proxies, proxyMeta{
				Name: px.Name, Type: px.Type, Remote: px.Remote,
				Local: fmt.Sprintf("%s:%d", px.LocalHost, px.LocalPort),
				Hash:  sum([]byte(proxyBlock(p, px))),
			})
		}
	}
	return u, nil
}

// checkRendered is the final guard over the bytes that will be handed to frp.
// frp runs the file through text/template, so "{{" must never occur.
func checkRendered(b []byte) error {
	for _, bad := range []string{"{{", "}}", "${", "`", "\r", "\x00"} {
		if bytes.Contains(b, []byte(bad)) {
			return errors.New("frp: rendered configuration contains a forbidden sequence")
		}
	}
	for _, c := range b {
		if c >= 0x80 || (c < 0x20 && c != '\n') {
			return errors.New("frp: rendered configuration contains a non-ASCII or control byte")
		}
	}
	return nil
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// hashFiles is the artifact hash: sha256 over the driver version and every
// file (sorted by name).
func hashFiles(files map[string][]byte) string {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	h := sha256.New()
	h.Write([]byte(driverVersion))
	h.Write([]byte{0})
	for _, n := range names {
		h.Write([]byte(n))
		h.Write([]byte{0})
		h.Write(files[n])
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (u *unit) artifact() driver.Artifact {
	files := make(map[string][]byte, len(u.Files))
	for k, v := range u.Files {
		files[k] = append([]byte(nil), v...)
	}
	return driver.Artifact{Files: files, Hash: u.Hash, PortClaims: append([]driver.PortClaim(nil), u.Claims...)}
}

func claims(p *plan) []driver.PortClaim {
	if p.Role != rolePortal {
		return nil
	}
	var out []driver.PortClaim
	out = append(out, driver.PortClaim{Proto: "tcp", Addr: p.BindAddr, Port: p.BindPort, Owner: p.ID})
	if p.Transport == "kcp" || p.Transport == "quic" {
		out = append(out, driver.PortClaim{Proto: "udp", Addr: p.BindAddr, Port: p.BindPort, Owner: p.ID})
	}
	for _, nw := range p.Networks {
		for _, q := range p.Public {
			out = append(out, driver.PortClaim{Proto: nw, Addr: p.ProxyBindAddr, Port: q, Owner: p.ID})
		}
	}
	return out
}

func writeLog(w *tomlW) {
	w.blank()
	w.raw("[log]")
	w.str("to", "console")
	w.str("level", "info")
	w.boolean("disablePrintColor", true)
}

func writeAuth(w *tomlW, secret string) {
	w.blank()
	w.raw("[auth]")
	w.str("method", "token")
	w.str("token", secret)
	// Authenticate heartbeats and work connections too, not only the login.
	w.raw(`additionalScopes = ["HeartBeats", "NewWorkConns"]`)
}

// allowPorts renders the frps allowPorts list: exactly the public ports.
func allowPorts(public []int) string {
	if len(public) == 1 {
		return fmt.Sprintf("[{ single = %d }]", public[0])
	}
	return fmt.Sprintf("[{ start = %d, end = %d }]", public[0], public[len(public)-1])
}

func renderFrps(p *plan) ([]byte, error) {
	w := &tomlW{}
	w.line("# generated by the W1nCray frp driver; do not edit")
	w.str("bindAddr", p.BindAddr)
	w.num("bindPort", p.BindPort)
	if p.Transport == "kcp" {
		w.num("kcpBindPort", p.BindPort)
	}
	if p.Transport == "quic" {
		w.num("quicBindPort", p.BindPort)
	}
	w.str("proxyBindAddr", p.ProxyBindAddr)
	// No vhost, tcpmux, ssh gateway, plugins or dashboard ports: only plain
	// tcp/udp proxies on the allowed public ports.
	w.num("maxPortsPerClient", len(p.Public)*len(p.Networks))
	w.raw("allowPorts = " + allowPorts(p.Public))
	writeAuth(w, p.Secret)
	if p.TLS {
		w.blank()
		w.raw("[transport.tls]")
		w.boolean("force", true)
		if p.CertFile != "" {
			w.str("certFile", p.CertFile)
			w.str("keyFile", p.KeyFile)
		}
	}
	writeLog(w)
	return w.b.Bytes(), w.err
}

func proxyBlock(p *plan, px proxyDef) string {
	w := &tomlW{}
	w.raw("[[proxies]]")
	w.str("name", px.Name)
	w.str("type", px.Type)
	w.str("localIP", px.LocalHost)
	w.num("localPort", px.LocalPort)
	w.num("remotePort", px.Remote)
	if px.Type == "tcp" && p.ProxyProto != "" {
		w.blank()
		w.raw("[proxies.transport]")
		w.str("proxyProtocolVersion", p.ProxyProto)
	}
	if h := p.Health; h != nil && px.Type == "tcp" {
		w.blank()
		w.raw("[proxies.healthCheck]")
		w.str("type", h.Type)
		if h.Timeout > 0 {
			w.num("timeoutSeconds", h.Timeout)
		}
		if h.MaxFails > 0 {
			w.num("maxFailed", h.MaxFails)
		}
		if h.Interval > 0 {
			w.num("intervalSeconds", h.Interval)
		}
		if h.Type == "http" {
			w.str("path", h.Path)
		}
	}
	if w.err != nil {
		return "\x00" + w.err.Error()
	}
	return w.b.String()
}

func renderFrpc(p *plan) ([]byte, error) {
	w := &tomlW{}
	w.line("# generated by the W1nCray frp driver; do not edit")
	w.str("serverAddr", p.ServerHost)
	w.num("serverPort", p.ServerPort)
	w.str("clientID", p.ID)
	// Keep retrying when the portal is down or the first login is refused;
	// the supervisor must not crash-loop on a remote condition.
	w.boolean("loginFailExit", false)
	writeAuth(w, p.Secret)
	w.blank()
	w.raw("[transport]")
	w.str("protocol", p.Transport)
	w.blank()
	w.raw("[transport.tls]")
	w.boolean("enable", p.TLS)
	if p.TLS {
		if p.ServerName != "" {
			w.str("serverName", p.ServerName)
		}
		if p.TrustedCA != "" {
			w.str("trustedCaFile", p.TrustedCA)
		}
	}
	writeLog(w)
	for _, px := range p.Proxies {
		blk := proxyBlock(p, px)
		if strings.HasPrefix(blk, "\x00") {
			return nil, errors.New("frp: " + blk[1:])
		}
		w.blank()
		w.b.WriteString(blk)
	}
	return w.b.Bytes(), w.err
}
