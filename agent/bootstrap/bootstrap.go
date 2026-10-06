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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
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

// ManifestFileName is the file the agent keeps its last verified kernel
// manifest in, directly under the state directory. The panel sync loop writes
// it and Boot reads it back when no explicit Agent.ManifestPath is configured.
const ManifestFileName = "manifest.json"

// PersistedManifestPath returns where the agent persists the last accepted
// kernel manifest for the given state directory. The empty state directory
// yields "" (nothing to persist).
func PersistedManifestPath(stateDir string) string {
	if stateDir == "" {
		return ""
	}
	return filepath.Join(stateDir, ManifestFileName)
}

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
	// Resume makes Boot re-apply the persisted last good state before it
	// returns, so forwarding comes back after a restart without waiting for the
	// panel. A failed resume never fails Boot: it is logged and kept for
	// ResumeReport. Default false (the caller applies a state itself).
	Resume bool
}

// Runtime is a booted agent. It owns the supervisor and the reconciler.
type Runtime struct {
	Reconciler *reconcile.Reconciler
	Sup        *supervisor.Supervisor
	Kernels    *kernelx.Ensurer
	State      *state.Store

	log driver.Logger

	resumeMu  sync.Mutex
	resumeRep reconcile.Report
	resumeOK  bool
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
	loadPersistedManifest(kern, opts.StateDir, opts.ManifestPath, log)
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
	rt := &Runtime{Reconciler: rec, Sup: sup, Kernels: kern, State: st, log: log}
	if opts.Resume {
		rt.resume()
	}
	return rt, nil
}

// loadPersistedManifest restores the manifest the panel sync loop persisted in
// a previous run, so external kernels stay available across a restart without
// waiting for the panel. It only applies when no explicit ManifestPath is
// configured: that file is loaded, and must be valid, by kernelx.New.
//
// The persisted copy goes through exactly the same verification as a manifest
// fetched from the panel. A tampered, expired or rolled-back file is logged and
// ignored, and Boot continues: the panel link, if any, provides a fresh one.
func loadPersistedManifest(kern *kernelx.Ensurer, stateDir, manifestPath string, log driver.Logger) {
	if manifestPath != "" {
		return
	}
	path := PersistedManifestPath(stateDir)
	if path == "" {
		return
	}
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return
	case err != nil:
		log.Warnf("bootstrap: reading the persisted kernel manifest %s: %v", path, err)
		return
	}
	if err := kern.LoadManifest(raw); err != nil {
		log.Warnf("bootstrap: persisted kernel manifest %s was rejected: %v (continuing without it)", path, err)
		return
	}
	if seq, ok := kern.ManifestSequence(); ok {
		log.Infof("bootstrap: restored the persisted kernel manifest %s (sequence %d)", path, seq)
	}
}

// resume re-applies the persisted last good state and records the outcome. It
// never fails the caller: a state that cannot be restored must not keep the
// agent (and the panel link) from starting.
func (r *Runtime) resume() {
	rep, err := r.Reconciler.Resume(context.Background())
	if err != nil {
		r.log.Warnf("bootstrap: resuming the last good state: %v", err)
		if rep.Hash == "" {
			// Failed before an apply started (for example an unreadable
			// state file): give the report something to say.
			rep = reconcile.Report{Status: reconcile.StatusFailed, Message: err.Error(), At: time.Now()}
		}
	} else if rep.Hash != "" {
		r.log.Infof("bootstrap: resumed the last good state (revision %d): %s, %d instance(s)", rep.Revision, rep.Status, len(rep.Instances))
	}
	r.resumeMu.Lock()
	// ok is false only when there was nothing to resume.
	r.resumeRep, r.resumeOK = rep, err != nil || rep.Hash != ""
	r.resumeMu.Unlock()
}

// ResumeReport returns the outcome of the resume Boot ran (Options.Resume). ok
// is false if Boot did not resume or there was no persisted state to resume.
func (r *Runtime) ResumeReport() (rep reconcile.Report, ok bool) {
	r.resumeMu.Lock()
	defer r.resumeMu.Unlock()
	return r.resumeRep, r.resumeOK
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
	return r.Reconciler.Apply(ctx, d)
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

// Shutdown stops every kernel and the supervised processes. The reconciler
// stops its instances without touching the persisted desired and last good
// state (applying an empty desired state would erase them), so the next start
// can resume where this one stopped. A stop error is logged and does not
// prevent the supervisor from stopping.
func (r *Runtime) Shutdown(ctx context.Context) error {
	stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	if err := r.Reconciler.Stop(stopCtx); err != nil {
		r.log.Warnf("bootstrap: stopping instances during shutdown: %v", err)
	}
	cancel()
	return r.Sup.Shutdown(ctx)
}
