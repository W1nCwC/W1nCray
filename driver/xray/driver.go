package xray

import (
	"context"
	"fmt"
	"sync"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/spec"
)

// Driver implements driver.Driver on top of the embedded Xray instance.
type Driver struct {
	host Host
	opts Options

	mu    sync.Mutex
	state *state            // what is currently applied
	base  map[string]uint64 // counters carried over from removed handlers
}

var _ driver.Driver = (*Driver)(nil)

// New creates the driver. host is the running Xray instance (see Host).
func New(host Host, opts Options) *Driver {
	return &Driver{host: host, opts: opts, state: newState(), base: map[string]uint64{}}
}

// Caps declares what the driver implements and has been tested for.
func (d *Driver) Caps() driver.Caps {
	return driver.Caps{
		Name: spec.EngineXray,
		Kinds: []spec.Kind{
			spec.KindForward, spec.KindTunnelEntry, spec.KindTunnelExit,
			spec.KindReversePortal, spec.KindReverseBridge,
		},
		Network:     []string{"tcp", "udp"},
		TunnelTypes: []string{"tcp", "tls", "ws", "wss", "grpc", "xhttp"},
		Reverse:     true,
		ProxyIn:     true,
		ProxyOut:    true,
		ProxyOutUDP: false,
		Balance:     []string{"round_robin", "random", "failover"},
		HealthCheck: "active",
		Stats:       "counters",
		Reload:      "hot",
		// Adding and removing inbounds does not touch other instances; the
		// rule table is replaced as a whole but atomically (WP0 D-B).
		DisruptsOnChange: false,
		External:         false,
		InstalledSize:    0,
	}
}

// Validate checks engine specific constraints without touching the system.
func (d *Driver) Validate(in spec.Instance) error { return Validate(in, d.opts) }

// Render compiles an instance. The artifact has one file, compiled.json.
func (d *Driver) Render(in spec.Instance) (driver.Artifact, error) {
	c, err := Compile(in, d.opts)
	if err != nil {
		return driver.Artifact{}, err
	}
	raw, err := MarshalCompiled(c)
	if err != nil {
		return driver.Artifact{}, fmt.Errorf("xray: %w", err)
	}
	files := map[string][]byte{CompiledFile: raw}
	return driver.Artifact{Files: files, Hash: ArtifactHash(files), PortClaims: c.PortClaims()}, nil
}

// ctxErr returns the context error, if any.
func ctxErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}
