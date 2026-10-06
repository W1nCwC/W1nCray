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

	"github.com/W1nCwC/W1nCray/agent/agentcfg"
	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/fileops"
	"github.com/W1nCwC/W1nCray/agent/kernelx"
	"github.com/W1nCwC/W1nCray/agent/opscmd"
	"github.com/W1nCwC/W1nCray/agent/reconcile"
	"github.com/W1nCwC/W1nCray/agent/selfupdate"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/agent/state"
	"github.com/W1nCwC/W1nCray/agent/supervisor"
	"github.com/W1nCwC/W1nCray/agent/terminal"
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
	// AgentConfig is the local agent configuration the capability list and the
	// local gates are read from (agent.yml). Nil means the defaults of a zero
	// Config.
	AgentConfig *agentcfg.Config
	// Files is the local managed-file policy (D4/D5). Nil (or an empty
	// ConfigDir) turns the managed-file commands off on this machine.
	Files *FilesOptions
	// AgentVersion is compared with a kernel's min_agent ("" skips).
	AgentVersion string
	// SelfVersion is the build version of this process. It names the
	// known-good copy of the previous binary that the self-update watchdog
	// runs (update/watchdog/W1nCray-<version>).
	SelfVersion string
	// LockPath is the single-instance lock file of the running config
	// (<config>.lock). The self-update watchdog reads the agent pid from it to
	// tell "the new version is up" from "a broken binary is restart-looping".
	LockPath string
	// AllowHTTP permits http:// kernel sources (development only).
	AllowHTTP bool
	// Terminal is the local terminal policy (D8). Enabled is the resolved
	// agentcfg value: on unless the machine opted out. A machine without a PTY
	// gets no manager, so it never declares the capability.
	Terminal terminal.Options
	// FileOps is the local confined file-operation policy (D9/WP-G6). No roots
	// means no file_* commands and no "files" capability. It is distinct from
	// Files, the managed xray files the panel replaces (D4/D5).
	FileOps fileops.Options
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
	// Ops is the operations command registry (kernel_* and, later, the other
	// operation commands). It is nil only for a Runtime built by hand.
	Ops *opscmd.Registry
	// Terminal is the interactive terminal manager (D8/WP-G6). It is nil when
	// the local switch is off or the platform has no PTY, and the "terminal"
	// capability is then not declared.
	Terminal *terminal.Manager
	// Updater replaces the agent's own binary with a version from the signed
	// manifest (self_update). It is nil when the executable path cannot be
	// resolved; upgradeReady is the one-time verdict of its Ready check.
	Updater      *selfupdate.Updater
	upgradeReady bool
	// Files is the managed-file layer (D4/D5); nil when the local policy or the
	// configuration has no xray directory to manage.
	Files *FilesRuntime
	// FileOps is the confined file manager (D9/WP-G6): the file_* commands. It
	// is nil when no root is configured, and the "files" capability is then not
	// declared.
	FileOps *fileops.Ops
	// cfg is the local agent configuration the capability list and the policy
	// gates are read from (nil means the defaults).
	cfg *agentcfg.Config

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
		// The pid directory is how the kernel commands tell "installed" from
		// "actually running" (kernelx.RunningVersion).
		PIDDir: filepath.Join(opts.StateDir, "pid"),
		Log:    log,
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
	rt := &Runtime{Reconciler: rec, Sup: sup, Kernels: kern, State: st, log: log, cfg: opts.AgentConfig}
	// The interactive terminal (D8) exists only when the local switch is on and
	// this machine can really create a PTY. A nil manager is what makes the
	// dispatcher answer term.error{terminal_disabled} and keeps the capability
	// out of hello.capabilities.
	rt.Terminal = newTerminalManager(opts.Terminal, log)
	// The file operations (D9) exist only when at least one root is configured;
	// a machine without roots must not advertise the commands. They are the
	// file_* commands, not the managed xray files (D4/D5, rt.Files below).
	// A refused root disables the file_* commands; it must never stop the agent
	// (a v0.5.0 install under /etc/W1nCray failed to boot exactly this way).
	fileOps, err := newFileOps(opts.FileOps, log)
	if err != nil {
		log.Errorf("bootstrap: file operations disabled: %v", err)
		fileOps = nil
	}
	rt.FileOps = fileOps
	// The managed-file layer (D4/D5). It is built here because the xray
	// configuration directory and the state directory are known now; the blob
	// fetcher and the validator are installed by the panel link (StartRemote)
	// and by the panel itself.
	rt.Files = newFilesRuntime(opts)
	// The operations registry is built here, where the kernel manager, the
	// supervisor and the state store are all in scope. The channels (the HTTP
	// link and the WebSocket) install their result and event sinks in
	// StartRemote, once they exist.
	ops, err := opscmd.New(opscmd.Deps{
		Kernels: kern,
		Comp:    componentRestarter{rt: rt},
		Log:     log,
	})
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	// The file_* commands are additive: RegisterFileCmds refuses a manager
	// without roots, so a machine with no file policy simply does not have
	// them.
	if fileOps != nil {
		if err := opscmd.RegisterFileCmds(ops, fileOps); err != nil {
			return nil, fmt.Errorf("bootstrap: %w", err)
		}
	}
	rt.Ops = ops
	// The self-update updater: it stages the agent's own manifest entry (the
	// reserved kernel name "agent") through the same installer the kernel
	// commands use, and swaps the running executable. A machine that cannot
	// replace its executable (Windows) or is not run by a service manager
	// never declares the upgrade capability.
	if up, uerr := newUpdater(kern, opts, log); uerr != nil {
		log.Warnf("bootstrap: self-update is not available: %v", uerr)
	} else {
		rt.Updater = up
		if rerr := up.Ready(); rerr != nil {
			log.Infof("bootstrap: self-update capability withheld: %v", rerr)
		} else {
			rt.upgradeReady = true
		}
	}
	if opts.Resume {
		rt.resume()
	}
	return rt, nil
}

// newUpdater builds the self-update updater around the running executable and
// the kernel installer. The executable is resolved (EvalSymlinks) so the swap
// replaces the real file a service manager runs, not a symlink to it.
func newUpdater(kern *kernelx.Ensurer, opts Options, log driver.Logger) (*selfupdate.Updater, error) {
	if kern == nil {
		return nil, errors.New("no kernel installer")
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolving the running executable: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return selfupdate.New(selfupdate.Options{
		ExePath:      exe,
		StateDir:     opts.StateDir,
		LockPath:     opts.LockPath,
		AgentVersion: opts.SelfVersion,
		Installer:    kern,
		Log:          log,
	})
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
//
// The interactive terminal is closed first: CloseAll kills every session's
// process group, so the agent never leaves an orphaned shell behind (WP-G6
// acceptance 4).
func (r *Runtime) Shutdown(ctx context.Context) error {
	if r.Terminal != nil {
		r.Terminal.CloseAll(terminal.ReasonAgentShutdown)
	}
	stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	if r.Reconciler != nil {
		if err := r.Reconciler.Stop(stopCtx); err != nil {
			r.log.Warnf("bootstrap: stopping instances during shutdown: %v", err)
		}
	}
	cancel()
	if r.Sup == nil {
		return nil
	}
	return r.Sup.Shutdown(ctx)
}
