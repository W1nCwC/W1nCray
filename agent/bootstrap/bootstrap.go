// Package bootstrap wires the agent's parts into one runnable unit: the process
// supervisor, the kernel manager (kernelx), the engine drivers, and the
// reconciler that turns a desired state into running kernels. It is the only
// place that knows how the pieces fit together; every part stays independently
// testable.
//
// The package deliberately does not import panel: panel imports bootstrap, so
// the panel translates its Agent config into Options here. This keeps the
// dependency direction one-way.
package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/kernelx"
	"github.com/W1nCwC/W1nCray/agent/reconcile"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/agent/state"
	"github.com/W1nCwC/W1nCray/agent/supervisor"
	"github.com/W1nCwC/W1nCray/core"
	"github.com/W1nCwC/W1nCray/corehost"
	"github.com/W1nCwC/W1nCray/driver/frp"
	"github.com/W1nCwC/W1nCray/driver/gost"
	"github.com/W1nCwC/W1nCray/driver/realm"
	"github.com/W1nCwC/W1nCray/driver/xray"
)

// Options carries the config-derived settings Boot needs. All paths must be
// resolved by the caller (see panel.Config.resolvePaths).
type Options struct {
	// StateDir holds the state store and the supervisor's PID directory.
	// Required.
	StateDir string
	// KernelsDir is the kernel install base directory. Required.
	KernelsDir string
	// ManifestPath is the signed kernel manifest; empty leaves only the builtin
	// xray engine available.
	ManifestPath string
	// ManifestKeysPath is an optional extra-keys file (see kernelx.Options).
	ManifestKeysPath string
	// Policy is the local root-of-trust policy.
	Policy spec.Policy
	// AgentVersion is compared with a kernel's min_agent ("" skips).
	AgentVersion string
	// AllowHTTP permits http:// kernel sources (development only).
	AllowHTTP bool
	// Log receives driver, supervisor, kernel and reconciler events.
	Log driver.Logger
}

// Runtime is a booted agent. It owns the supervisor and the reconciler.
type Runtime struct {
	Reconciler *reconcile.Reconciler
	Sup        *supervisor.Supervisor
	Kernels    *kernelx.Ensurer
	State      *state.Store

	log     driver.Logger
	applied atomic.Bool
}

type nopLog struct{}

func (nopLog) Debugf(string, ...any) {}
func (nopLog) Infof(string, ...any)  {}
func (nopLog) Warnf(string, ...any)  {}
func (nopLog) Errorf(string, ...any) {}

// driverBuilder builds the engine registry. It is a package variable so tests
// can substitute fakes without a running core.Core; production code never
// changes it.
var driverBuilder = buildDrivers

// Boot builds and starts the agent. c is the running Xray instance; when it is
// nil the xray engine is not registered (the other engines still work), which
// is what the offline "agent-apply" command uses.
func Boot(opts Options, c *core.Core) (*Runtime, error) {
	log := opts.Log
	if log == nil {
		log = nopLog{}
	}
	if opts.StateDir == "" || opts.KernelsDir == "" {
		return nil, fmt.Errorf("bootstrap: StateDir and KernelsDir are required")
	}
	st, err := state.Open(opts.StateDir)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	kern, err := kernelx.New(kernelx.Options{
		Dir:          opts.KernelsDir,
		ManifestPath: opts.ManifestPath,
		KeysPath:     opts.ManifestKeysPath,
		AgentVersion: opts.AgentVersion,
		AllowHTTP:    opts.AllowHTTP,
		Log:          log,
	})
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	sup := supervisor.New(supervisor.Options{Log: log, PIDDir: filepath.Join(opts.StateDir, "pid")})
	drivers, err := driverBuilder(c, opts.Policy, log)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	rec := &reconcile.Reconciler{
		Drivers: drivers,
		Kernels: kern,
		Sup:     sup,
		Policy:  opts.Policy,
		State:   st,
		Log:     log,
	}
	return &Runtime{Reconciler: rec, Sup: sup, Kernels: kern, State: st, log: log}, nil
}

// buildDrivers is the production driver registry.
func buildDrivers(c *core.Core, pol spec.Policy, log driver.Logger) (map[string]driver.Driver, error) {
	m := map[string]driver.Driver{}
	if c != nil {
		h, err := corehost.New(c)
		if err != nil {
			return nil, err
		}
		m[spec.EngineXray] = xray.New(h, xray.Options{Policy: &pol})
	}
	m[spec.EngineGost] = gost.New(gost.Options{})
	m[spec.EngineFrp] = frp.New()
	m[spec.EngineRealm] = realm.New(realm.Options{})
	return m, nil
}

// Apply makes d the running state and returns the report.
func (r *Runtime) Apply(ctx context.Context, d spec.Desired) (reconcile.Report, error) {
	rep, err := r.Reconciler.Apply(ctx, d)
	if err == nil {
		r.applied.Store(true)
	}
	return rep, err
}

// ApplyFile reads a spec.Desired JSON file (strict: unknown fields are
// rejected) and applies it.
func (r *Runtime) ApplyFile(path string) (reconcile.Report, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return reconcile.Report{}, fmt.Errorf("bootstrap: read desired state %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var d spec.Desired
	if err := dec.Decode(&d); err != nil {
		return reconcile.Report{}, fmt.Errorf("bootstrap: parse desired state %s: %w", path, err)
	}
	if dec.More() {
		return reconcile.Report{}, fmt.Errorf("bootstrap: desired state %s has trailing data", path)
	}
	return r.Apply(context.Background(), d)
}

// Shutdown stops every kernel and the supervised processes. An empty desired
// state is applied first so in-process kernels (the builtin xray and any
// driver holding listeners) are torn down through the normal apply path; the
// apply error, if any, is logged and does not prevent the supervisor from
// stopping.
func (r *Runtime) Shutdown(ctx context.Context) error {
	if r.applied.Load() {
		stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		if _, err := r.Reconciler.Apply(stopCtx, spec.Desired{Version: spec.Version}); err != nil {
			r.log.Warnf("bootstrap: stopping instances during shutdown: %v", err)
		}
		cancel()
	}
	return r.Sup.Shutdown(ctx)
}
