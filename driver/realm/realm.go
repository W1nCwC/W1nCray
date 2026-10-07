// Package realm is the W1nCray driver for the realm relay
// (https://github.com/zhboner/realm, verified against v2.9.6).
//
// # What it does
//
// Every enabled spec.Instance becomes ONE supervised realm process
// ("realm/<instance-id>") with its own 0600 JSON configuration. All port
// listeners of one instance (a port range is expanded to one realm endpoint
// per port) live in that process. Changing, removing or crashing one instance
// therefore never touches the established connections of another one, which
// is why Caps.DisruptsOnChange is false even though realm itself cannot reload.
//
// # Limitations (all verified in the realm/kaminari sources or against the
// real v2.9.6 binary; see the tests)
//
//   - No statistics: Stats returns nothing, Caps.Stats is "none". The panel
//     must grey out metering for this engine.
//   - No hot reload: any configuration change restarts the instance's process
//     and cuts its established connections (ApplyResult.Restarted/Disrupted).
//   - No health checks and no failover: the balancer only does weighted
//     round robin or IP hash over a fixed list. A dead target keeps receiving
//     its share. Balance.Health is rejected.
//   - UDP is a plain single-target relay: no balancing (extra_remotes are
//     ignored by realm's UDP path), no PROXY protocol, no tunnel transport.
//   - Tunnels are realm to realm only, TCP only. The tunnel does not carry a
//     destination: entry port N maps to the exit's one fixed target list, so
//     port ranges and PortMap are rejected on tunnel kinds.
//   - There is NO tunnel authentication. ws only checks that the HTTP Host and
//     request path equal the configured values (verified: any other path or
//     host is closed without a response) and the client's frame mask key is
//     always zero. The path is therefore a bearer token: when Instance.Secret
//     is set, the driver appends a token derived from it by HMAC-SHA256 to the
//     configured path (the secret itself is never written anywhere). Over
//     plain ws the token is visible to anyone on the wire; only wss protects
//     it. A bare tls tunnel has no application level authentication at all and
//     is refused if a Secret is supplied.
//   - realm verifies server certificates only against the built-in Mozilla
//     root set. It cannot pin a certificate and cannot trust a private CA.
//     Security "tls_pin", "tls_self" and "vless_enc" are rejected (tls_self
//     derives a self-signed certificate, which realm has no way to verify; the
//     gost and xray engines serve it). Self-signed exits
//     only work when the driver is explicitly created with
//     Options.InsecureSkipTLSVerify (development/local policy only; never
//     derive it from remote desired state).
//   - realm dials the target BEFORE it reads anything from the client
//     (src/tcp/middle.rs). On a tunnel exit this means that any host that can
//     reach the exit port makes it open a connection to the target, and, with
//     accept+send PROXY, the (client chosen) header is forwarded to the target
//     before the ws/tls handshake is validated (verified: only payload is
//     withheld). The exit is not a gatekeeper; bind it to the entry's address
//     or firewall it.
//   - Accepting PROXY protocol: realm parses the header with a single peek of
//     at most 256 bytes; a missing or malformed header closes the connection
//     (5 s timeout), and so does a header that arrives split over two
//     segments (verified). Headers are forgeable; the core's policy must
//     restrict the listener.
//   - IPHash hashes the TCP peer address, not the address announced in a
//     PROXY header, so it is rejected together with accept_proxy_protocol.
//   - ACL, rate/connection limits and the "any target" exit are not
//     supported and are rejected.
//   - realm has no "check configuration" mode: an invalid file makes it panic
//     at start, and a listener that cannot bind only kills that endpoint's
//     task while the process keeps running. Apply therefore (1) refuses to
//     claim a port that is already bound by another process, and (2) only
//     calls an instance ready when its process runs and every claimed port is
//     bound. Ports are probed by trying to bind them, never by connecting:
//     a connect would make realm dial the target (see above) on every probe.
//     "Bound" cannot tell realm from a foreign owner, hence (1).
//   - A failed (re)start restores the instance's last verified configuration
//     (state.json "good"); a new instance that fails is stopped. Apply then
//     returns an error and a valid ApplyResult (Failed/Running).
//   - The binary must be the full build. The slim build lacks PROXY, balance
//     and transport; Apply refuses a binary whose "-v" output does not list
//     [proxy][balance][transport]. musl versus glibc cannot be detected from
//     the binary and is guaranteed by the signed kernel manifest.
package realm

import (
	"context"
	"sync"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/spec"
)

// Name is the engine name of this driver.
const Name = spec.EngineRealm

const (
	// procPrefix prefixes the supervised process id of every instance.
	procPrefix = "realm/"
	// configName is the single file of an Artifact.
	configName = "realm.json"
	// artifactVersion is mixed into Artifact.Hash so a change of the
	// rendering rules restarts instances even when the input is identical.
	artifactVersion = "w1ncray/driver/realm/artifact/v1"

	// MaxEndpointsPerInstance bounds the port expansion of one instance
	// (one realm endpoint, i.e. one task and one fd, per port). The agent
	// core's Policy.MaxPortsPerInstance is the real limit; this is a guard
	// against configuration explosion inside the driver.
	MaxEndpointsPerInstance = 1024
	// maxTargets is realm's limit of peers per endpoint (weights are a u8
	// list and the balancer asserts len <= 255).
	maxTargets = 255
	// maxWeightSum keeps realm's round robin inside its i16 accumulators
	// (realm_lb/src/round_robin.rs: `tw: i16`, `cw: i16`). This is a
	// deliberately conservative bound, half of i16::MAX.
	maxWeightSum = 16383

	// acceptProxyTimeoutS is realm's own default (consts.rs) written out so
	// that the rendered file does not depend on the binary's default.
	acceptProxyTimeoutS = 5
	// udp idle presets, in seconds (realm option udp_timeout; its default
	// is 30). The numbers are this driver's reading of spec.IdleProfile.
	udpShortTimeoutS = 30
	udpLongTimeoutS  = 120

	// minSecretLen is the minimum accepted Instance.Secret length when it is
	// used to derive the ws path token.
	minSecretLen = 16

	// startGrace is how long waitReady lets a (re)started process claim its
	// ports before the first probe (see bindProbe).
	startGrace = 300 * time.Millisecond
)

// Options configure a Driver. The zero value is the safe production setting.
type Options struct {
	// InsecureSkipTLSVerify makes tunnel entries render the "insecure" TLS
	// option (certificate verification off) and allows exits to use a
	// generated self-signed certificate. realm cannot verify anything but
	// public-CA certificates, so without this switch self-signed tunnels are
	// refused. The tunnel is then encrypted but unauthenticated (man in the
	// middle possible). Development and explicit local policy only: it must
	// never be driven by remote desired state.
	InsecureSkipTLSVerify bool

	// ReadyTimeout bounds how long Apply waits for a (re)started instance to
	// accept connections on every claimed port. Default 10 s.
	ReadyTimeout time.Duration

	// Test hooks (same-package tests only).
	probeBinary  func(ctx context.Context, path string) (BinaryInfo, error)
	portInUse    func(c driver.PortClaim) bool
	noStartGrace bool
}

// Driver is the realm driver. Create it with New; it is safe for concurrent
// use (Apply, Rollback and Stop are serialised).
type Driver struct {
	opts Options
	mu   sync.Mutex
}

// New creates a realm driver.
func New(opts Options) *Driver {
	if opts.ReadyTimeout <= 0 {
		opts.ReadyTimeout = 10 * time.Second
	}
	return &Driver{opts: opts}
}

var _ driver.Driver = (*Driver)(nil)

// Caps reports what this driver can really do. Every entry is backed by the
// realm sources and the tests of this package.
func (d *Driver) Caps() driver.Caps {
	return driver.Caps{
		Name:        Name,
		Kinds:       []spec.Kind{spec.KindForward, spec.KindTunnelEntry, spec.KindTunnelExit},
		Network:     []string{"tcp", "udp"},
		TunnelTypes: []string{"tcp", "tls", "ws", "wss"},
		Reverse:     false,

		ProxyIn:     true,
		ProxyOut:    true,
		ProxyOutUDP: false,

		// Weighted round robin and IP hash. No random, no failover.
		Balance:     []string{"round_robin", "iphash"},
		HealthCheck: "none",

		Stats:            "none",
		Reload:           "none",
		DisruptsOnChange: false, // one process per instance

		External: true,
		// Upper bound of the unpacked full (non-slim) binary over the
		// supported targets (x86_64-musl measured: 6 864 392 bytes).
		InstalledSize: 6_900_000,
	}
}
