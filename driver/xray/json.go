package xray

// Typed mirrors of the Xray JSON configuration objects the compiler emits.
// Everything is produced with encoding/json over these structures (maps are
// marshalled with sorted keys), so the output is deterministic and no
// configuration text is ever assembled by string concatenation.

type jInbound struct {
	Tag      string   `json:"tag"`
	Protocol string   `json:"protocol"`
	Listen   string   `json:"listen,omitempty"`
	Port     string   `json:"port"`
	Settings any      `json:"settings"`
	Stream   *jStream `json:"streamSettings,omitempty"`
}

type jOutbound struct {
	Tag      string   `json:"tag"`
	Protocol string   `json:"protocol"`
	Settings any      `json:"settings,omitempty"`
	Stream   *jStream `json:"streamSettings,omitempty"`
}

type jDokodemo struct {
	Address   string            `json:"address,omitempty"`
	Port      uint16            `json:"port,omitempty"`
	PortMap   map[string]string `json:"portMap,omitempty"`
	Network   string            `json:"network"`
	UserLevel uint32            `json:"userLevel"`
}

type jVlessClient struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Level uint32 `json:"level"`
}

type jVlessIn struct {
	Clients    []jVlessClient `json:"clients"`
	Decryption string         `json:"decryption"`
}

type jVlessOut struct {
	Address    string `json:"address"`
	Port       int    `json:"port"`
	ID         string `json:"id"`
	Level      uint32 `json:"level"`
	Email      string `json:"email"`
	Encryption string `json:"encryption"`
}

type jFreedom struct {
	Redirect      string `json:"redirect,omitempty"`
	UserLevel     uint32 `json:"userLevel"`
	ProxyProtocol uint32 `json:"proxyProtocol,omitempty"`
}

type jBlackhole struct{}

type jStream struct {
	Network  string    `json:"network,omitempty"`
	Security string    `json:"security,omitempty"`
	TLS      *jTLS     `json:"tlsSettings,omitempty"`
	WS       *jWS      `json:"wsSettings,omitempty"`
	GRPC     *jGRPC    `json:"grpcSettings,omitempty"`
	XHTTP    *jXHTTP   `json:"xhttpSettings,omitempty"`
	Sockopt  *jSockopt `json:"sockopt,omitempty"`
}

type jSockopt struct {
	AcceptProxyProtocol  bool   `json:"acceptProxyProtocol,omitempty"`
	DialerProxy          string `json:"dialerProxy,omitempty"`
	TCPKeepAliveIdle     int32  `json:"tcpKeepAliveIdle,omitempty"`
	TCPKeepAliveInterval int32  `json:"tcpKeepAliveInterval,omitempty"`
}

type jTLS struct {
	ServerName  string   `json:"serverName,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
	Certs       []jCert  `json:"certificates,omitempty"`
	Pin         string   `json:"pinnedPeerCertSha256,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	MinVersion  string   `json:"minVersion,omitempty"`
}

type jCert struct {
	CertFile       string   `json:"certificateFile,omitempty"`
	KeyFile        string   `json:"keyFile,omitempty"`
	Cert           []string `json:"certificate,omitempty"`
	Key            []string `json:"key,omitempty"`
	OneTimeLoading bool     `json:"oneTimeLoading"`
}

type jWS struct {
	Path string `json:"path"`
	Host string `json:"host,omitempty"`
}

type jGRPC struct {
	ServiceName string `json:"serviceName"`
	Authority   string `json:"authority,omitempty"`
}

type jXHTTP struct {
	Path string `json:"path"`
	Host string `json:"host,omitempty"`
	Mode string `json:"mode,omitempty"`
}

// jRule is a routing rule. All set conditions must match (AND); list
// entries are alternatives (OR).
type jRule struct {
	Type        string   `json:"type"`
	InboundTag  []string `json:"inboundTag,omitempty"`
	User        []string `json:"user,omitempty"`
	Source      []string `json:"source,omitempty"`
	IP          []string `json:"ip,omitempty"`
	Domain      []string `json:"domain,omitempty"`
	Port        string   `json:"port,omitempty"`
	Network     string   `json:"network,omitempty"`
	OutboundTag string   `json:"outboundTag,omitempty"`
	BalancerTag string   `json:"balancerTag,omitempty"`
}

type jBalancer struct {
	Tag      string    `json:"tag"`
	Selector []string  `json:"selector"`
	Strategy jStrategy `json:"strategy"`
}

type jStrategy struct {
	Type string `json:"type"`
}
