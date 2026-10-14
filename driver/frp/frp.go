// Package frp is the frp driver of the W1nCray agent. It implements
// driver.Driver on top of the official frps/frpc binaries and only covers
// reverse tunnels: reverse_portal (frps side, public ports) and
// reverse_bridge (frpc side, dials the portal from behind NAT).
//
// # Kernel layout
//
// rt.Kernel.Path is the absolute path of one of the two binaries of an
// installed frp version directory. The other binary is its sibling in the same
// directory (see Binaries): the kernel manifest declares run.binary = frpc, so
// kernel/install hands that path over, while a reverse_portal needs the frps
// next to it. Both binaries must be the same release.
//
// # Process model (verified against frp v0.71.0)
//
//   - Every reverse_portal instance runs its own frps; every reverse_bridge
//     instance runs its own frpc. One process per instance means a change of
//     instance A can never touch the connections of instance B
//     (Caps.DisruptsOnChange == false). The price is one extra process per
//     instance. Grouping bridges per portal was rejected: it couples
//     unrelated instances (shared fate on a common-config change) for a
//     memory saving that has not been measured on a target device.
//   - frps has no hot reload: any change of a portal restarts that frps and
//     cuts the connections of that portal only (reported in
//     ApplyResult.Disrupted). The bridge reconnects by itself.
//   - frpc re-reads proxies on GET /api/reload and only rebuilds the proxies
//     whose configuration changed, but it does NOT re-apply the common
//     section (server address, token, transport, TLS). Proxy-only changes
//     therefore go through the reload API, anything else restarts frpc.
//
// # Configuration safety
//
// Both binaries pass the whole config file through Go text/template before
// parsing it ({{ .Envs.NAME }} reads the process environment). Every string
// that reaches a config file is therefore validated against a strict
// whitelist, and the renderer refuses to emit "{{" or "}}" at all. Config
// files (which hold the token) are written 0600; the token never appears in
// argv, log lines or error messages. The admin web server of both programs is
// bound to 127.0.0.1 with random credentials generated at every process
// start (stored only in a 0600 file under rt.StateDir).
//
// # Semantics worth knowing
//
//   - reverse_bridge: Listen.Ports are the public ports registered on the
//     portal (spec convention); Listen.Addr is ignored. Targets map to those
//     ports one-to-one; Listen.PortMap overrides single ports.
//   - TLS: Tunnel.Security "tls" enables frp transport TLS (forced on the
//     portal). frp cannot pin a certificate hash, so "tls_pin" and
//     "vless_enc" are rejected. frpc only verifies the server certificate if
//     a trust anchor is given; by convention (see SPEC-REQUEST in the work
//     package report) a bridge's Tunnel.Cert.CertFile is used as that trust
//     anchor. Without it the server certificate is not verified (frp
//     default).
//   - Statistics come from the frps admin API. frps adds the bytes of a TCP
//     connection only when that connection closes; UDP is counted per
//     packet. frp does not expose a total connection count (ConnsTotal is
//     always 0). Only portals report counters.
package frp

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/spec"
)

// Name is the engine name of this driver.
const Name = spec.EngineFrp

// driverVersion is mixed into every artifact hash; bump it whenever the
// rendering changes so that running processes pick the new output up.
const driverVersion = "w1ncray-frp-driver/1"

// Binaries returns the paths of frps and frpc for the kernel path handed over
// in driver.Runtime. kernelPath may name either binary of an installed frp
// version directory; the other one is derived from the same directory, which is
// where the installer always puts the pair (both manifest extract entries use
// plain file names, see kernel/install and the frp manifest). Accepting both
// names is what makes the real chain work: the manifest's run.binary is frpc,
// so driver.Installed.Path is .../frpc, but a reverse_portal must run frps.
// Only those two file names are accepted; any other path is still refused.
func Binaries(kernelPath string) (frps, frpc string, err error) {
	if kernelPath == "" {
		return "", "", errors.New("frp: kernel path is empty")
	}
	base := filepath.Base(kernelPath)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	if stem != "frps" && stem != "frpc" {
		return "", "", errors.New("frp: kernel path must point at the frps or frpc binary")
	}
	dir := filepath.Dir(kernelPath)
	return filepath.Join(dir, "frps"+ext), filepath.Join(dir, "frpc"+ext), nil
}

// Driver implements driver.Driver for frp. The zero value is not usable; call
// New.
type Driver struct {
	// mu serializes Apply, Rollback and Stop.
	mu sync.Mutex

	// rmu guards the runtime maps below (read by Stats and Health).
	rmu     sync.RWMutex
	admins  map[string]adminInfo // by instance id, only for running processes
	stats   map[string]*instStats
	current map[string]*unit // mirror of current.json

	// Test hooks.
	verifyFn func(ctx context.Context, bin, cfg string) error
	now      func() time.Time
	timing   timing
}

// timing holds the waits used by Apply; tests shrink them.
type timing struct {
	ready       time.Duration // wait for a started process to answer
	reloadSettl time.Duration // wait for proxies after a reload
	verify      time.Duration
}

// Options configures a Driver. The zero value is usable.
type Options struct {
	// ReadyTimeout bounds how long Apply waits for a started frps/frpc to
	// answer before it reports that instance as failed. 0 means
	// driver.DefaultReadyTimeout(runtime.GOARCH, OpenWrt). It is what
	// agent.yml's Drivers.Frp.ReadyTimeoutSec overrides (D4).
	ReadyTimeout time.Duration
	// OpenWrt is the platform fact of the machine the agent runs on
	// (platform.Info.OpenWrt). It only selects the default readiness limit:
	// every architecture on OpenWrt is a router CPU and takes the 60s slow
	// path (F6), never the 15s one. It is ignored when ReadyTimeout is set.
	OpenWrt bool
}

// New returns a ready driver.
func New(opts Options) *Driver {
	ready := opts.ReadyTimeout
	if ready <= 0 {
		ready = driver.DefaultReadyTimeout(runtime.GOARCH, opts.OpenWrt)
	}
	return &Driver{
		admins:  map[string]adminInfo{},
		stats:   map[string]*instStats{},
		current: map[string]*unit{},
		now:     time.Now,
		timing:  timing{ready: ready, reloadSettl: 3 * time.Second, verify: 15 * time.Second},
	}
}

// ReadyTimeout reports the readiness limit in force: the shared architecture
// default unless Options.ReadyTimeout (agent.yml Drivers.Frp.ReadyTimeoutSec)
// overrode it. It is what Apply waits for a started instance to answer (D4).
func (d *Driver) ReadyTimeout() time.Duration { return d.timing.ready }

var _ driver.Driver = (*Driver)(nil)

// Caps implements driver.Driver. Every claim below is backed by a test in
// this package (unit tests or the e2e suite against real frp binaries).
func (d *Driver) Caps() driver.Caps {
	return driver.Caps{
		Name:        Name,
		Kinds:       []spec.Kind{spec.KindReversePortal, spec.KindReverseBridge},
		Network:     []string{"tcp", "udp"},
		TunnelTypes: append([]string(nil), supportedTunnelTypes...),
		Reverse:     true,
		// frps cannot read a PROXY header from the public side.
		ProxyIn: false,
		// frpc writes PROXY v1/v2 towards the local target (TCP only).
		ProxyOut:    true,
		ProxyOutUDP: false,
		// A bridge has one target per port, so the only strategy it can
		// express is failover (with an active health check the proxy is
		// withdrawn while the target is down: TestE2EActiveHealthCheck).
		// Portals accept no balance section; their Validate refuses it.
		Balance:          []string{"failover"},
		HealthCheck:      "active", // frpc healthCheck, TCP targets only
		Stats:            "api",
		Reload:           "api", // frpc only; frps restarts (see package doc)
		DisruptsOnChange: false, // one process per instance
		External:         true,
		InstalledSize:    installedSizeApprox,
	}
}

// installedSizeApprox is the unpacked size of frps+frpc 0.71.0 on linux/amd64
// (measured when the driver was written); other targets differ by a few MB.
const installedSizeApprox = 36 << 20
