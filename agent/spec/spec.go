// Package spec defines the declarative desired state the W1nCray agent
// accepts from the panel (or from a local file). It contains data only: the
// agent renders it into kernel configuration itself and never executes
// anything the panel sends. Field names are snake_case on the wire.
//
// Contract owner: the agent core. Packages that consume these types (drivers,
// reconciler, kernel manager) must not change this file; request additions
// from the owner instead.
package spec

// Version is the schema version of Desired.
const Version = 1

// Engine names. EngineAuto lets the agent choose by driver capabilities,
// platform and free space; it never silently degrades.
//
// EngineXray is kept only as a name: PLAN v11 §2.5 removed the embedded xray
// forwarding engine, so the validator refuses it with a clear message instead
// of treating it as a typo. The Xray instance itself is the separate
// W1nCray-xray program (KernelPin.Name still accepts "xray" for it).
const (
	EngineAuto  = "auto"
	EngineXray  = "xray"
	EngineGost  = "gost"
	EngineFrp   = "frp"
	EngineRealm = "realm"
)

// Kind is what an instance does.
type Kind string

const (
	// KindForward listens locally and forwards to Targets directly.
	KindForward Kind = "forward"
	// KindTunnelEntry listens locally and forwards through a tunnel to the
	// exit endpoint described by Tunnel.Server.
	KindTunnelEntry Kind = "tunnel_entry"
	// KindTunnelExit accepts the tunnel on Tunnel.Listen and forwards to
	// Targets (or to anything, when AllowAnyTarget is set and policy allows).
	KindTunnelExit Kind = "tunnel_exit"
	// KindReversePortal is the public side of a reverse proxy: the control
	// link is accepted on Tunnel.Listen, user traffic on Listen.
	KindReversePortal Kind = "reverse_portal"
	// KindReverseBridge is the NAT side: it dials Tunnel.Server and serves
	// the requests relayed by the portal to Targets. By convention
	// Listen.Ports of a bridge names the portal-side public port(s) it
	// serves (required by frp, which registers them; informational for the
	// other engines) and Listen.Addr is unused.
	KindReverseBridge Kind = "reverse_bridge"
)

// Desired is the complete desired state of one machine. It is always applied
// as a whole: instances missing from it are removed.
type Desired struct {
	Version   int         `json:"version"`
	Revision  int64       `json:"revision"`
	Kernels   []KernelPin `json:"kernels,omitempty"`
	Instances []Instance  `json:"instances"`
	// Files are the managed xray files the panel wants on this machine
	// (docs/WS-PROTOCOL.md section 7 ruling 1). The content never travels in
	// the desired state: only the name, the size and the sha256, which the
	// agent resolves through the blob endpoint over HTTPS. The key is only
	// sent to an agent that declared the "files" capability, because the
	// desired state is decoded strictly.
	Files []FileRef `json:"files,omitempty"`
}

// FileRef is one managed file the panel wants: a fixed whitelisted name plus
// the sha256 and size of its content. Kernel names the kernel version the file
// belongs to when the panel knows one (informational for the agent; the file's
// own whitelist decides where it is written).
type FileRef struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Kernel string `json:"kernel,omitempty"`
}

// KernelPin selects a kernel version from the signed manifest. The panel can
// only name a version; URLs and hashes always come from the manifest.
type KernelPin struct {
	Name    string `json:"name"` // xray | gost | frp | realm
	Version string `json:"version"`
}

// Instance is one forwarding unit.
type Instance struct {
	ID      string `json:"id"` // stable, [a-z0-9_-]{1,40}
	Name    string `json:"name,omitempty"`
	Enabled bool   `json:"enabled"`
	Engine  string `json:"engine"` // Engine* constant
	Kind    Kind   `json:"kind"`

	Listen  *Listen  `json:"listen,omitempty"`  // user-facing listener
	Network []string `json:"network,omitempty"` // "tcp", "udp"; default ["tcp"]
	Targets []Target `json:"targets,omitempty"`
	Balance *Balance `json:"balance,omitempty"`

	// ProxyProtocolOut is the PROXY protocol version (0, 1, 2) written to
	// the target connection. TCP only; incompatible with network "udp".
	ProxyProtocolOut int `json:"proxy_protocol_out,omitempty"`
	// AcceptProxyProtocol requires a PROXY header on Listen (TCP only).
	AcceptProxyProtocol bool `json:"accept_proxy_protocol,omitempty"`

	Tunnel  *Tunnel  `json:"tunnel,omitempty"`
	Reverse *Reverse `json:"reverse,omitempty"`

	// IdleProfile selects preset idle timeouts: tcp_long, tcp_default,
	// udp_short, udp_long.
	IdleProfile string  `json:"idle_profile,omitempty"`
	Limits      *Limits `json:"limits,omitempty"`
	ACL         *ACL    `json:"acl,omitempty"`

	// AllowAnyTarget lets a tunnel exit relay to arbitrary destinations
	// chosen by the entry side. Honoured only if the local policy allows it.
	AllowAnyTarget bool `json:"allow_any_target,omitempty"`

	// Secret is the shared secret of a tunnel/reverse link. The panel stores
	// it encrypted and delivers it only over HTTPS; it must never be logged
	// or written outside the 0600 state files.
	Secret string `json:"secret,omitempty"`
}

// Listen is a local listener. Ports is one port ("8443") or a range
// ("20000-20009"). PortMap maps listen ports to "host:port" targets
// (range one-to-one forwarding) and overrides Targets for those ports.
type Listen struct {
	Addr    string            `json:"addr"`
	Ports   string            `json:"ports"`
	PortMap map[string]string `json:"port_map,omitempty"`
}

// Target is a forward destination. Ports is a single port or a range of the
// same length as Listen.Ports.
type Target struct {
	Host   string `json:"host"`
	Ports  string `json:"ports"`
	Weight int    `json:"weight,omitempty"` // 0 means 1
}

// Balance selects among several targets.
type Balance struct {
	Strategy string  `json:"strategy"` // round_robin | random | iphash | failover | least_ping
	Health   *Health `json:"health,omitempty"`
}

// Health configures active health checks.
type Health struct {
	Type      string `json:"type"` // tcp | http
	IntervalS int    `json:"interval_s,omitempty"`
	TimeoutS  int    `json:"timeout_s,omitempty"`
	MaxFails  int    `json:"max_fails,omitempty"`
	ProbeURL  string `json:"probe_url,omitempty"`
}

// Tunnel describes the carrier between two W1nCray agents (entry↔exit or
// bridge↔portal).
type Tunnel struct {
	// Type is the tunnel carrier. xhttp was the removed xray engine's
	// transport: no current engine supports it (see the driver Caps()).
	Type   string   `json:"type"`             // tcp | tls | ws | wss | grpc | xhttp | kcp | quic
	Server string   `json:"server,omitempty"` // host:port to dial (entry, bridge)
	Listen string   `json:"listen,omitempty"` // addr:port to accept on (exit, portal)
	Host   string   `json:"host,omitempty"`   // Host header / authority
	Path   string   `json:"path,omitempty"`   // ws/xhttp/grpc path
	SNI    string   `json:"sni,omitempty"`
	ALPN   []string `json:"alpn,omitempty"`
	// Security is "none", "tls", "tls_pin" (certificate pinned by
	// PinSHA256; no current engine implements it, gost and realm cannot pin,
	// so it is refused with a clear message), "tls_self" (both ends derive
	// the same self-signed certificate from Instance.Secret, so the panel
	// never has to generate x509; gost only) or "vless_enc" (the removed
	// xray engine's tunnel security; refused by validation).
	Security  string `json:"security,omitempty"`
	PinSHA256 string `json:"pin_sha256,omitempty"` // hex SHA-256 of the leaf certificate DER
	Cert      *Cert  `json:"cert,omitempty"`       // server side certificate source (unused by tls_self)
}

// Cert is the certificate used by a tunnel server side.
type Cert struct {
	Mode     string `json:"mode"` // self | file | panel
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`
}

// Reverse carries reverse-proxy specific settings.
type Reverse struct {
	// Link pairs a portal and a bridge instance (informational for the panel).
	Link string `json:"link,omitempty"`
	// Domain is the random rendezvous name of the classic Xray reverse
	// proxy. It belonged to the removed xray forwarding engine (PLAN v11
	// §2.5); no current engine reads it. The field is kept for schema
	// compatibility and is still validated (entropy, charset) so an old
	// panel payload cannot smuggle arbitrary text into the state.
	Domain string `json:"domain,omitempty"`
	// BridgeAllow restricts which destinations a portal may request from
	// the bridge; everything else is blocked.
	BridgeAllow []Allow `json:"bridge_allow,omitempty"`
}

// Allow is one permitted destination.
type Allow struct {
	Host  string `json:"host"`
	Ports string `json:"ports"`
}

// Limits are per-instance resource limits (0 = unlimited).
type Limits struct {
	MaxConns    int   `json:"max_conns,omitempty"`
	RateUpBps   int64 `json:"rate_up_bps,omitempty"`
	RateDownBps int64 `json:"rate_down_bps,omitempty"`
}

// ACL filters client source addresses (CIDR or IP).
type ACL struct {
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}

// Policy is the local, root-of-trust policy from the agent's own config
// file. Remote desired state can never relax it.
type Policy struct {
	MaxInstances        int      `json:"max_instances"`
	MaxPortsPerInstance int      `json:"max_ports_per_instance"`
	AllowListen         []string `json:"allow_listen"` // permitted listen addresses, default ["127.0.0.1"]
	PrivilegedPorts     bool     `json:"privileged_ports"`
	PortRange           [2]int   `json:"port_range"` // permitted listen ports, 0 = any
	DenyPorts           []int    `json:"deny_ports"`
	DenyCIDRs           []string `json:"deny_cidrs"` // extra target CIDRs; loopback/link-local/metadata are always denied anyway
	AllowPrivate        bool     `json:"allow_private"`
	AllowAnyTarget      bool     `json:"allow_any_target"`
	// AllowAcceptProxyOnPublic permits accept_proxy_protocol on a
	// non-loopback, non-private listener (PROXY headers are forgeable).
	AllowAcceptProxyOnPublic bool     `json:"allow_accept_proxy_on_public"`
	AllowEngines             []string `json:"allow_engines"` // empty = all installed
}
