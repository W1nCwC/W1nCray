package gost

// This file holds the strongly typed subset of the gost (go-gost/x v0.16.0,
// gost v3.3.0) configuration that the driver emits. Every value that ends up
// in a gost metadata map is a string: gost reads metadata through
// mdutil.GetInt/GetBool/GetDuration, which accept int/bool/string but NOT the
// float64 that encoding/json produces for numbers, so a JSON number such as
// "proxyProtocol":2 is silently ignored by gost. Typing metadata as
// map[string]string makes that trap unrepresentable.

// fragment is what one instance contributes to the gost configuration. It is
// the content of Artifact.Files[fragmentFile].
type fragment struct {
	Services   []service   `json:"services,omitempty"`
	Chains     []chain     `json:"chains,omitempty"`
	Admissions []admission `json:"admissions,omitempty"`
	Limiters   []limiter   `json:"limiters,omitempty"`
	CLimiters  []limiter   `json:"climiters,omitempty"`
}

type service struct {
	Name       string            `json:"name"`
	Addr       string            `json:"addr"`
	Admissions []string          `json:"admissions,omitempty"`
	Limiter    string            `json:"limiter,omitempty"`
	CLimiter   string            `json:"climiter,omitempty"`
	Handler    handler           `json:"handler"`
	Listener   listener          `json:"listener"`
	Forwarder  *forwarder        `json:"forwarder,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type handler struct {
	Type     string            `json:"type"`
	Chain    string            `json:"chain,omitempty"`
	Auth     *auth             `json:"auth,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

type listener struct {
	Type     string            `json:"type"`
	Chain    string            `json:"chain,omitempty"`
	TLS      *tlsConf          `json:"tls,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

type auth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// tlsConf is gost's TLSConfig. On a listener CertFile/KeyFile select the
// served certificate. On a dialer CAFile is the trust anchor and Secure turns
// on full verification including the host name.
type tlsConf struct {
	CertFile   string `json:"certFile,omitempty"`
	KeyFile    string `json:"keyFile,omitempty"`
	CAFile     string `json:"caFile,omitempty"`
	Secure     bool   `json:"secure,omitempty"`
	ServerName string `json:"serverName,omitempty"`
}

type forwarder struct {
	Selector *selector `json:"selector,omitempty"`
	Nodes    []node    `json:"nodes"`
}

// selector selects among forwarder nodes. FailTimeout is a number of
// nanoseconds: gost's API decodes it with encoding/json into a time.Duration
// (a string would be rejected there), and the file loader accepts numbers as
// well as strings.
type selector struct {
	Strategy    string `json:"strategy"`
	MaxFails    int    `json:"maxFails"`
	FailTimeout int64  `json:"failTimeout"`
}

type node struct {
	Name     string            `json:"name"`
	Addr     string            `json:"addr"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

type chain struct {
	Name string `json:"name"`
	Hops []hop  `json:"hops"`
}

type hop struct {
	Name  string      `json:"name"`
	Nodes []chainNode `json:"nodes"`
}

type chainNode struct {
	Name      string    `json:"name"`
	Addr      string    `json:"addr"`
	Connector connector `json:"connector"`
	Dialer    dialer    `json:"dialer"`
}

type connector struct {
	Type string `json:"type"`
	Auth *auth  `json:"auth,omitempty"`
}

type dialer struct {
	Type     string            `json:"type"`
	TLS      *tlsConf          `json:"tls,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// admission is a gost admission list: Whitelist=true admits only the listed
// addresses, false admits everything except them. A service referencing both
// kinds admits a client only if every list admits it (admissionGroup is a
// logical AND).
type admission struct {
	Name      string   `json:"name"`
	Whitelist bool     `json:"whitelist,omitempty"`
	Matchers  []string `json:"matchers"`
}

// limiter is a gost traffic/connection limiter. Limits entries look like
// "$ <in bytes/s> <out bytes/s>" (traffic) or "$ <n>" (connections).
type limiter struct {
	Name   string   `json:"name"`
	Limits []string `json:"limits"`
}

// baseConfig is the static part of the gost configuration (API, optional
// metrics, logging). It never contains services.
type baseConfig struct {
	API      apiConf     `json:"api"`
	Metrics  *metricConf `json:"metrics,omitempty"`
	Log      logConf     `json:"log"`
	Services []service   `json:"services"`
}

type apiConf struct {
	Addr string `json:"addr"`
	Auth auth   `json:"auth"`
}

type metricConf struct {
	Addr string `json:"addr"`
	Path string `json:"path"`
	Auth auth   `json:"auth"`
}

type logConf struct {
	Level  string `json:"level"`
	Format string `json:"format"`
}

// currentConfig is the file passed as the second -C argument: the union of the
// fragments of every applied instance. gost merges it with the base file.
type currentConfig struct {
	Services   []service   `json:"services"`
	Chains     []chain     `json:"chains,omitempty"`
	Admissions []admission `json:"admissions,omitempty"`
	Limiters   []limiter   `json:"limiters,omitempty"`
	CLimiters  []limiter   `json:"climiters,omitempty"`
}
