package node

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/protocol"
	xcore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	"google.golang.org/protobuf/proto"

	"w1ncray/api/xboard"
)

// Xboard node types handled by the official Xray kernel.
const (
	protoVMess       = "vmess"
	protoVLESS       = "vless"
	protoTrojan      = "trojan"
	protoShadowsocks = "shadowsocks"
	protoHysteria    = "hysteria"
	protoSocks       = "socks"
	protoHTTP        = "http"
)

// normalizeProtocol maps Xboard type aliases (Server::TYPE_ALIASES).
func normalizeProtocol(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	switch p {
	case "v2ray":
		return protoVMess
	case "hysteria2":
		return protoHysteria
	}
	return p
}

func checkProtocol(nc *xboard.NodeConfig) (string, error) {
	p := normalizeProtocol(string(nc.Protocol))
	switch p {
	case protoVMess, protoVLESS, protoTrojan, protoShadowsocks, protoSocks, protoHTTP:
		return p, nil
	case protoHysteria:
		if nc.Version != 0 && nc.Version != 2 {
			return "", fmt.Errorf("hysteria v%d is not supported by Xray (only hysteria2)", nc.Version)
		}
		return p, nil
	case "tuic", "anytls", "naive", "mieru":
		return "", fmt.Errorf("protocol %s is not supported by the official Xray kernel", p)
	}
	return "", fmt.Errorf("unknown protocol %q", p)
}

// hotUsers reports whether the protocol supports adding/removing users on a
// running inbound (proxy.UserManager).
func hotUsers(p string) bool {
	return p != protoSocks && p != protoHTTP
}

// nodeUser is a panel user with its effective limits.
type nodeUser struct {
	UID         int
	UUID        string
	Email       string
	SpeedLimit  uint64 // bytes/s
	DeviceLimit int
}

// userEmail is the Xray user identifier. Socks and HTTP use the username as
// the user's email, so for them the UUID (their username) is the identifier.
func userEmail(p, tag string, uid int, uuid string) string {
	if p == protoSocks || p == protoHTTP {
		return uuid
	}
	return tag + "|" + strconv.Itoa(uid)
}

// ss2022KeySize returns the user key size of a Shadowsocks 2022 cipher, or 0.
func ss2022KeySize(cipher string) int {
	switch cipher {
	case "2022-blake3-aes-128-gcm":
		return 16
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		return 32
	}
	return 0
}

// ss2022UserKey reproduces Xboard Helper::uuidToBase64:
// base64_encode(substr($uuid, 0, $length)).
func ss2022UserKey(uuid string, size int) string {
	b := []byte(uuid)
	if len(b) > size {
		b = b[:size]
	}
	return base64.StdEncoding.EncodeToString(b)
}

// certPaths are the files of the inbound certificate.
type certPaths struct {
	CertFile string
	KeyFile  string
	// RejectUnknownSNI rejects TLS handshakes for other server names.
	RejectUnknownSNI bool
}

// inboundSpec builds the Xray inbound of a node.
type inboundSpec struct {
	tag      string
	protocol string
	node     *xboard.NodeConfig
	cfg      *Config
	cert     *certPaths
}

// needsTLS reports whether the inbound uses a TLS certificate.
func (s *inboundSpec) needsTLS() bool {
	switch s.protocol {
	case protoHysteria:
		return true
	case protoTrojan:
		return !s.useREALITY()
	case protoVMess, protoVLESS, protoSocks, protoHTTP:
		return s.node.TLS == 1 && !s.useREALITY()
	}
	return false
}

func (s *inboundSpec) useREALITY() bool {
	if s.protocol != protoVLESS && s.protocol != protoTrojan {
		return false
	}
	return s.node.TLS == 2 || (s.cfg.EnableREALITY && s.cfg.REALITYConfigs != nil)
}

func (s *inboundSpec) build(users []nodeUser) (*xcore.InboundHandlerConfig, error) {
	settings, err := s.settings(users)
	if err != nil {
		return nil, err
	}
	stream, err := s.stream()
	if err != nil {
		return nil, err
	}
	listen := s.cfg.ListenIP
	if listen == "" {
		listen = string(s.node.ListenIP)
	}
	if listen == "" {
		listen = "0.0.0.0"
	}
	if s.node.ServerPort <= 0 || s.node.ServerPort > 65535 {
		return nil, fmt.Errorf("invalid server port %d", s.node.ServerPort)
	}
	ib := map[string]any{
		"tag":            s.tag,
		"protocol":       s.protocol,
		"listen":         listen,
		"port":           int(s.node.ServerPort),
		"settings":       settings,
		"streamSettings": stream,
	}
	if !s.cfg.DisableSniffing {
		ib["sniffing"] = map[string]any{
			"enabled":      true,
			"destOverride": []string{"http", "tls", "quic"},
		}
	}
	raw, err := json.Marshal(ib)
	if err != nil {
		return nil, err
	}
	var dc conf.InboundDetourConfig
	if err := json.Unmarshal(raw, &dc); err != nil {
		return nil, fmt.Errorf("parse inbound: %w", err)
	}
	ic, err := dc.Build()
	if err != nil {
		return nil, fmt.Errorf("build inbound: %w", err)
	}
	return ic, nil
}

// settings returns the protocol "settings" object.
func (s *inboundSpec) settings(users []nodeUser) (map[string]any, error) {
	clients := make([]map[string]any, 0, len(users))
	switch s.protocol {
	case protoVMess:
		for _, u := range users {
			clients = append(clients, map[string]any{"id": u.UUID, "email": u.Email, "level": 0})
		}
		return map[string]any{"clients": clients}, nil

	case protoVLESS:
		flow := string(s.node.Flow)
		for _, u := range users {
			c := map[string]any{"id": u.UUID, "email": u.Email, "level": 0}
			if flow != "" {
				c["flow"] = flow
			}
			clients = append(clients, c)
		}
		decryption := string(s.node.Decryption)
		if decryption == "" {
			decryption = "none"
		}
		m := map[string]any{"clients": clients, "decryption": decryption}
		if fb := s.fallbacks(); fb != nil {
			m["fallbacks"] = fb
		}
		return m, nil

	case protoTrojan:
		for _, u := range users {
			clients = append(clients, map[string]any{"password": u.UUID, "email": u.Email, "level": 0})
		}
		m := map[string]any{"clients": clients}
		if fb := s.fallbacks(); fb != nil {
			m["fallbacks"] = fb
		}
		return m, nil

	case protoShadowsocks:
		cipher := strings.ToLower(string(s.node.Cipher))
		if s.node.Plugin != "" {
			return nil, fmt.Errorf("shadowsocks plugin %q is not supported by Xray", s.node.Plugin)
		}
		if size := ss2022KeySize(cipher); size > 0 {
			if !strings.Contains(cipher, "aes") {
				return nil, fmt.Errorf("%s does not support multiple users in Xray; use 2022-blake3-aes-128-gcm or 2022-blake3-aes-256-gcm", cipher)
			}
			if s.node.ServerKey == "" {
				return nil, fmt.Errorf("%s requires server_key from the panel", cipher)
			}
			for _, u := range users {
				clients = append(clients, map[string]any{"password": ss2022UserKey(u.UUID, size), "email": u.Email, "level": 0})
			}
			return map[string]any{"method": cipher, "password": string(s.node.ServerKey), "clients": clients, "network": "tcp,udp"}, nil
		}
		for _, u := range users {
			clients = append(clients, map[string]any{"method": cipher, "password": u.UUID, "email": u.Email, "level": 0})
		}
		return map[string]any{"method": cipher, "clients": clients, "network": "tcp,udp"}, nil

	case protoHysteria:
		for _, u := range users {
			clients = append(clients, map[string]any{"auth": u.UUID, "email": u.Email, "level": 0})
		}
		return map[string]any{"version": 2, "clients": clients}, nil

	case protoSocks:
		accounts := make([]map[string]any, 0, len(users))
		for _, u := range users {
			accounts = append(accounts, map[string]any{"user": u.UUID, "pass": u.UUID})
		}
		return map[string]any{"auth": "password", "accounts": accounts, "udp": true}, nil

	case protoHTTP:
		accounts := make([]map[string]any, 0, len(users))
		for _, u := range users {
			accounts = append(accounts, map[string]any{"user": u.UUID, "pass": u.UUID})
		}
		return map[string]any{"accounts": accounts}, nil
	}
	return nil, fmt.Errorf("unsupported protocol %s", s.protocol)
}

// fallbacks returns the local fallbacks for VLESS/Trojan over TCP + TLS.
func (s *inboundSpec) fallbacks() []map[string]any {
	if !s.cfg.EnableFallback || len(s.cfg.FallBackConfigs) == 0 || s.network() != "tcp" {
		return nil
	}
	var out []map[string]any
	for _, f := range s.cfg.FallBackConfigs {
		if f == nil || f.Dest == "" {
			continue
		}
		fb := map[string]any{"xver": f.ProxyProtocolVer}
		if f.SNI != "" {
			fb["name"] = f.SNI
		}
		if f.Alpn != "" {
			fb["alpn"] = f.Alpn
		}
		if f.Path != "" {
			fb["path"] = f.Path
		}
		if port, err := strconv.Atoi(f.Dest); err == nil {
			fb["dest"] = port
		} else {
			fb["dest"] = f.Dest
		}
		out = append(out, fb)
	}
	return out
}

// protocolUsers builds Xray users exactly as the JSON config would, by
// running the protocol's own config builder on a settings object.
func (s *inboundSpec) protocolUsers(users []nodeUser) ([]*protocol.User, error) {
	if len(users) == 0 {
		return nil, nil
	}
	settings, err := s.settings(users)
	if err != nil {
		return nil, err
	}
	delete(settings, "fallbacks")
	raw, err := json.Marshal(settings)
	if err != nil {
		return nil, err
	}
	var builder conf.Buildable
	switch s.protocol {
	case protoVMess:
		builder = new(conf.VMessInboundConfig)
	case protoVLESS:
		builder = new(conf.VLessInboundConfig)
	case protoTrojan:
		builder = new(conf.TrojanServerConfig)
	case protoShadowsocks:
		builder = new(conf.ShadowsocksServerConfig)
	case protoHysteria:
		builder = new(conf.HysteriaServerConfig)
	default:
		return nil, fmt.Errorf("protocol %s does not support hot user updates", s.protocol)
	}
	if err := json.Unmarshal(raw, builder); err != nil {
		return nil, err
	}
	msg, err := builder.Build()
	if err != nil {
		return nil, err
	}
	return extractUsers(msg)
}

type usersGetter interface{ GetUsers() []*protocol.User }
type userGetter interface{ GetUser() []*protocol.User }
type clientsGetter interface{ GetClients() []*protocol.User }

func extractUsers(msg proto.Message) ([]*protocol.User, error) {
	switch m := msg.(type) {
	case usersGetter:
		return m.GetUsers(), nil
	case userGetter:
		return m.GetUser(), nil
	case clientsGetter:
		return m.GetClients(), nil
	}
	return nil, fmt.Errorf("cannot extract users from %T", msg)
}

// network returns the Xray transport name of the node.
func (s *inboundSpec) network() string {
	switch s.protocol {
	case protoShadowsocks, protoSocks, protoHTTP:
		return "tcp"
	case protoHysteria:
		return "hysteria"
	}
	switch n := strings.ToLower(string(s.node.Network)); n {
	case "", "tcp", "raw":
		return "tcp"
	case "splithttp":
		return "xhttp"
	case "mkcp":
		return "kcp"
	default:
		return n
	}
}

// stream returns the "streamSettings" object.
func (s *inboundSpec) stream() (map[string]any, error) {
	st := map[string]any{}
	network := s.network()
	ns := sanitizePHP(s.node.NetworkSettingsObject().Map())
	if ns == nil {
		ns = map[string]any{}
	}

	switch network {
	case "tcp":
		st["network"] = "raw"
		if s.protocol != protoShadowsocks && s.protocol != protoSocks && s.protocol != protoHTTP && len(ns) > 0 {
			st["rawSettings"] = ns
		}
	case "ws":
		st["network"] = "ws"
		normalizeHostHeader(ns)
		st["wsSettings"] = ns
	case "httpupgrade":
		st["network"] = "httpupgrade"
		normalizeHostHeader(ns)
		st["httpupgradeSettings"] = ns
	case "grpc":
		st["network"] = "grpc"
		if v, ok := ns["service_name"]; ok {
			if _, has := ns["serviceName"]; !has {
				ns["serviceName"] = v
			}
			delete(ns, "service_name")
		}
		st["grpcSettings"] = ns
	case "xhttp":
		st["network"] = "xhttp"
		st["xhttpSettings"] = ns
	case "kcp":
		st["network"] = "kcp"
		masks := kcpMasks(ns)
		delete(ns, "header")
		delete(ns, "seed")
		st["kcpSettings"] = ns
		if len(masks) > 0 {
			st["finalmask"] = map[string]any{"udp": masks}
		}
	case "hysteria":
		st["network"] = "hysteria"
		st["hysteriaSettings"] = map[string]any{"version": 2, "udpIdleTimeout": 60}
		fm := map[string]any{}
		// Server sends at min(brutalUp, client download): Xboard's
		// bandwidth is client oriented, so the client's download
		// (down_mbps) caps the server's upload and vice versa.
		qp := map[string]any{}
		if s.node.DownMbps > 0 {
			qp["brutalUp"] = fmt.Sprintf("%d mbps", s.node.DownMbps)
		}
		if s.node.UpMbps > 0 {
			qp["brutalDown"] = fmt.Sprintf("%d mbps", s.node.UpMbps)
		}
		if len(qp) > 0 {
			fm["quicParams"] = qp
		}
		if strings.EqualFold(string(s.node.Obfs), "salamander") && s.node.ObfsPassword != "" {
			fm["udp"] = []map[string]any{{"type": "salamander", "settings": map[string]any{"password": string(s.node.ObfsPassword)}}}
		}
		if len(fm) > 0 {
			st["finalmask"] = fm
		}
	case "h2", "http", "quic":
		return nil, fmt.Errorf("transport %s was removed from Xray; switch the node to xhttp", network)
	default:
		return nil, fmt.Errorf("unsupported transport %q", network)
	}

	switch {
	case s.useREALITY():
		rs, err := s.reality(network)
		if err != nil {
			return nil, err
		}
		st["security"] = "reality"
		st["realitySettings"] = rs
	case s.needsTLS():
		ts, err := s.tls()
		if err != nil {
			return nil, err
		}
		st["security"] = "tls"
		st["tlsSettings"] = ts
	}

	if s.cfg.EnableProxyProtocol && network != "hysteria" && network != "kcp" {
		st["sockopt"] = map[string]any{"acceptProxyProtocol": true}
	}
	return st, nil
}

func (s *inboundSpec) tls() (map[string]any, error) {
	if s.cert == nil {
		return nil, fmt.Errorf("TLS is enabled but no certificate is configured (set cert_config in the panel or CertConfig locally)")
	}
	ts := map[string]any{
		"certificates": []map[string]any{{
			"certificateFile": s.cert.CertFile,
			"keyFile":         s.cert.KeyFile,
			// Xray reloads the files at this interval (seconds), which
			// picks up renewed certificates.
			"ocspStapling": 3600,
		}},
		"rejectUnknownSni": s.cert.RejectUnknownSNI,
	}
	t := s.node.TLSConfig()
	if sn := s.serverName(t); sn != "" {
		ts["serverName"] = sn
	}
	if s.protocol == protoHysteria {
		ts["alpn"] = []string{"h3"}
	}
	if keys, err := echServerKeys(t.ECH); err != nil {
		return nil, err
	} else if keys != "" {
		ts["echServerKeys"] = keys
	}
	return ts, nil
}

func (s *inboundSpec) serverName(t *xboard.TLSSettings) string {
	if t.ServerName != "" {
		return string(t.ServerName)
	}
	if s.node.ServerName != "" {
		return string(s.node.ServerName)
	}
	return ""
}

func (s *inboundSpec) reality(network string) (map[string]any, error) {
	if network != "tcp" && network != "xhttp" && network != "grpc" {
		return nil, fmt.Errorf("REALITY only supports RAW (tcp), XHTTP and gRPC, not %s", network)
	}
	if s.cfg.EnableREALITY && s.cfg.REALITYConfigs != nil {
		r := s.cfg.REALITYConfigs
		if r.PrivateKey == "" || r.Dest == "" || len(r.ServerNames) == 0 {
			return nil, fmt.Errorf("local REALITYConfigs requires Dest, ServerNames and PrivateKey")
		}
		shortIDs := r.ShortIds
		if len(shortIDs) == 0 {
			shortIDs = []string{""}
		}
		return map[string]any{
			"show":         r.Show,
			"target":       r.Dest,
			"xver":         r.ProxyProtocolVer,
			"serverNames":  r.ServerNames,
			"privateKey":   r.PrivateKey,
			"minClientVer": r.MinClientVer,
			"maxClientVer": r.MaxClientVer,
			"maxTimeDiff":  r.MaxTimeDiff,
			"shortIds":     shortIDs,
		}, nil
	}

	t := s.node.TLSConfig()
	if t.ServerName == "" || t.PrivateKey == "" {
		return nil, fmt.Errorf("REALITY requires server_name and private_key in the panel reality settings")
	}
	target := string(t.Dest)
	if target == "" {
		port := string(t.ServerPort)
		if port == "" || port == "0" {
			port = "443"
		}
		target = string(t.ServerName) + ":" + port
	}
	shortIDs := []string(t.ShortIDs)
	if len(shortIDs) == 0 {
		shortIDs = []string{string(t.ShortID)}
	}
	return map[string]any{
		"show":        false,
		"target":      target,
		"xver":        int64(t.Xver),
		"serverNames": []string{string(t.ServerName)},
		"privateKey":  string(t.PrivateKey),
		"shortIds":    shortIDs,
	}, nil
}

// echServerKeys returns the base64 ECH server keys from the panel ECH config
// (inline PEM or a key file).
func echServerKeys(ech *xboard.ECH) (string, error) {
	if ech == nil || !ech.Enabled {
		return "", nil
	}
	data := []byte(ech.Key)
	if len(data) == 0 && ech.KeyPath != "" {
		b, err := os.ReadFile(string(ech.KeyPath))
		if err != nil {
			return "", fmt.Errorf("read ECH key: %w", err)
		}
		data = b
	}
	if len(data) == 0 {
		return "", nil
	}
	trimmed := strings.TrimSpace(string(data))
	if !strings.Contains(trimmed, "-----") {
		return trimmed, nil
	}
	block, _ := pem.Decode([]byte(trimmed))
	if block == nil || block.Type != "ECH KEYS" {
		return "", fmt.Errorf("invalid ECH key: expected an \"ECH KEYS\" PEM block")
	}
	return base64.StdEncoding.EncodeToString(block.Bytes), nil
}

// kcpMasks converts the legacy mKCP header/seed into finalmask UDP masks.
func kcpMasks(ns map[string]any) []map[string]any {
	var masks []map[string]any
	if seed, _ := ns["seed"].(string); seed != "" {
		masks = append(masks, map[string]any{"type": "mkcp-aes128gcm", "settings": map[string]any{"password": seed}})
	} else {
		masks = append(masks, map[string]any{"type": "mkcp-original"})
	}
	if h, ok := ns["header"].(map[string]any); ok {
		switch t, _ := h["type"].(string); t {
		case "", "none":
		case "wechat-video":
			masks = append(masks, map[string]any{"type": "header-wechat"})
		default:
			masks = append(masks, map[string]any{"type": "header-" + t})
		}
	}
	return masks
}

// normalizeHostHeader moves headers.Host into the dedicated host field and
// makes sure header values are strings (Xray expects map[string]string).
func normalizeHostHeader(ns map[string]any) {
	h, ok := ns["headers"].(map[string]any)
	if !ok {
		delete(ns, "headers")
		return
	}
	for k, v := range h {
		if strings.EqualFold(k, "host") {
			if _, has := ns["host"]; !has {
				ns["host"] = fmt.Sprint(v)
			}
			delete(h, k)
			continue
		}
		if _, isStr := v.(string); !isStr {
			h[k] = fmt.Sprint(v)
		}
	}
	if len(h) == 0 {
		delete(ns, "headers")
	}
}

// sanitizePHP removes empty arrays, which PHP emits for empty objects and
// which Xray rejects where an object is expected.
func sanitizePHP(m map[string]any) map[string]any {
	for k, v := range m {
		switch t := v.(type) {
		case []any:
			if len(t) == 0 {
				delete(m, k)
			}
		case map[string]any:
			sanitizePHP(t)
		case nil:
			delete(m, k)
		}
	}
	return m
}
