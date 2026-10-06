// Package gost is the W1nCray driver for the gost v3 kernel (go-gost/gost,
// tested with v3.3.0 / go-gost/x v0.16.0). It renders declarative instances
// into gost configuration, runs one supervised gost process for all of them
// and changes single instances through gost's REST API without restarting
// the process.
//
// Design (all points were verified against the real v3.3.0 binary, see the
// e2e tests):
//
//   - One gost process hosts every instance. A listen range or a tcp+udp
//     instance becomes one gost service per port and protocol.
//   - Adding, replacing and removing a service through the API
//     (POST/PUT/DELETE /config/services/...) leaves the established
//     connections of every other service untouched. A full reload
//     (POST /config/reload, SIGHUP) unregisters all services first and leaves
//     a half updated registry when one of the new services cannot bind
//     (go-gost issue #754), so the driver never uses it.
//   - gost cannot cut established connections by deleting or replacing a
//     service: connections that were accepted before the change keep running
//     until they end. Stop and Apply therefore only stop new traffic; this is
//     reported through Caps.DisruptsOnChange=false and documented here
//     because the core has no field for it.
//   - The API and (optionally) the metrics endpoint listen on 127.0.0.1 with
//     random basic-auth credentials stored in a 0600 file.
//
// Security: nothing the panel sends reaches an argv or a shell. The only
// external command is the gost binary itself, started through the core's
// Supervisor with a fixed argv. Every field that is written into the gost
// configuration is either a typed value or matches a strict whitelist (see
// plan.go), and the configuration is built with encoding/json from typed
// structs, so no value can break out of its field. Secrets live only in
// 0600 files and are redacted from every error returned to the core.
package gost

import (
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/spec"
)

// Options tunes the driver. The zero value is usable.
type Options struct {
	// LogLevel of the gost process (trace|debug|info|warn|error). Default
	// "warn": at "info" gost logs two lines per connection.
	LogLevel string
	// MaxListenPorts bounds the number of ports one instance may listen on
	// (each becomes a gost service). Default 1024.
	MaxListenPorts int
	// EnableMetrics also starts gost's Prometheus endpoint (127.0.0.1, basic
	// auth) and makes Stats read it. Off by default: gost labels its transfer
	// counters with the client IP, so every distinct source address creates
	// time series that are never freed. Stats then come from the API's
	// per-service statistics, which have no such label.
	EnableMetrics bool
	// ProbeConnect makes Health additionally open and close a TCP connection
	// to every claimed TCP port. This is a real end-to-end check but gost
	// counts the connection and dials the target for it, so it is off by
	// default; without it a port counts as listening when the API reports the
	// service as ready.
	ProbeConnect bool
	// APITimeout bounds every API request. Default 5 s.
	APITimeout time.Duration
	// ReadyTimeout bounds waits for the process or a service to become
	// ready. Default 10 s.
	ReadyTimeout time.Duration
}

func (o *Options) setDefaults() {
	if o.LogLevel == "" {
		o.LogLevel = "warn"
	}
	if o.MaxListenPorts <= 0 {
		o.MaxListenPorts = defaultMaxListenPorts
	}
	if o.APITimeout <= 0 {
		o.APITimeout = 5 * time.Second
	}
	if o.ReadyTimeout <= 0 {
		o.ReadyTimeout = 10 * time.Second
	}
}

// Driver implements driver.Driver for gost. Methods that touch the running
// process are serialised.
type Driver struct {
	opts Options
	rt   *runtimeState
}

// New creates a gost driver.
func New(opts Options) *Driver {
	opts.setDefaults()
	return &Driver{opts: opts, rt: newRuntimeState()}
}

var _ driver.Driver = (*Driver)(nil)

// Caps reports what the driver implements and the e2e suite verified.
func (d *Driver) Caps() driver.Caps {
	return driver.Caps{
		Name: spec.EngineGost,
		Kinds: []spec.Kind{
			spec.KindForward, spec.KindTunnelEntry, spec.KindTunnelExit,
			spec.KindReversePortal, spec.KindReverseBridge,
		},
		Network: []string{"tcp", "udp"},

		// Verified end to end for TCP and UDP: tcp, tls, ws, wss, grpc.
		TunnelTypes: []string{"tcp", "tls", "ws", "wss", "grpc"},
		// rtcp/rudp over a relay link with bind enabled on the portal.
		Reverse: true,

		ProxyIn:     true, // optional header: gost accepts connections without one
		ProxyOut:    true,
		ProxyOutUDP: false,

		Balance:     []string{"round_robin", "random", "iphash", "failover"},
		HealthCheck: "passive",

		Stats:            "api",
		Reload:           "api",
		DisruptsOnChange: false,

		External:      true,
		InstalledSize: 50_000_000,
	}
}

// Validate implements driver.Driver. It does not touch the system.
func (d *Driver) Validate(in spec.Instance) error {
	_, err := d.analyze(in)
	return err
}
