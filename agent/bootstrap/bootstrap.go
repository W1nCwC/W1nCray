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
	"github.com/W1nCwC/W1nCray/agent/fwopen"
	"github.com/W1nCwC/W1nCray/agent/kernelx"
	"github.com/W1nCwC/W1nCray/agent/opscmd"
	"github.com/W1nCwC/W1nCray/agent/reconcile"
	"github.com/W1nCwC/W1nCray/agent/selfupdate"
	"github.com/W1nCwC/W1nCray/agent/selinux"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/agent/state"
	"github.com/W1nCwC/W1nCray/agent/supervisor"
	"github.com/W1nCwC/W1nCray/agent/terminal"
	"github.com/W1nCwC/W1nCray/agent/xrayapi"
	"github.com/W1nCwC/W1nCray/agent/xraykern"
	"github.com/W1nCwC/W1nCray/agent/xraysvc"
	"github.com/W1nCwC/W1nCray/driver/frp"
	"github.com/W1nCwC/W1nCray/driver/gost"
	"github.com/W1nCwC/W1nCray/driver/realm"
	"github.com/W1nCwC/W1nCray/kernel/platform"
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
	// SelfUpdateAliveWindow and SelfUpdateDeadline are the local watchdog
	// timing overrides (Agent.SelfUpdate, D-M7). Zero means the architecture
	// default (selfupdate.DefaultWatchdogWindows). They are local-only: the
	// panel never pushes agent configuration.
	SelfUpdateAliveWindow time.Duration
	SelfUpdateDeadline    time.Duration
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
	// Labeler applies the SELinux bin_t label to the kernel tree and to every
	// kernel binary before it is started. Nil makes Boot build the production
	// one (agent/selinux); a machine with SELinux off is a no-op.
	Labeler *selinux.Labeler
	// Resume makes Boot re-apply the persisted last good state before it
	// returns, so forwarding comes back after a restart without waiting for the
	// panel. A failed resume never fails Boot: it is logged and kept for
	// ResumeReport. Default false (the caller applies a state itself).
	Resume bool
	// Xray is the agent's view of the locally installed Xray kernel. It is nil
	// on a machine where the kernel is not installed; the managed-file layer
	// then refuses every apply with "Xray 内核未安装" instead of writing files
	// no running instance would pick up. The agent itself never links
	// Xray-core. When XrayConfigPath is set and this is nil, Boot builds the
	// real client (xraykern).
	Xray xrayapi.Service
	// XrayConfigPath is the absolute path of config.yml. It is what the Xray
	// status client and the service manager are built around; empty disables
	// both (a machine with no Xray configuration).
	XrayConfigPath string
	// XrayNeeded reports whether this machine's configuration needs the Xray
	// kernel (config.yml has Nodes, or machine mode is on). It gates the
	// start-up migration.
	XrayNeeded bool
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
	// Xray is the status client of the local Xray kernel (nil when the kernel
	// is not installed or this machine has no Xray configuration).
	Xray xrayapi.Service
	// XrayManager manages the Xray kernel service (nil when it is unavailable
	// on this machine).
	XrayManager *xraysvc.Manager
	// xrayNeeded is Options.XrayNeeded: whether the start-up migration should
	// bring the Xray kernel service up.
	xrayNeeded bool
	// xrayOnce makes the start-up migration run once per process.
	xrayOnce sync.Once
	// cfg is the local agent configuration the capability list and the policy
	// gates are read from (nil means the defaults).
	cfg *agentcfg.Config
	// openWrt is the detected platform fact (PLAN v11 §4.3). It gates the
	// OpenWrt firewall automation and is reported in hello.policy.firewall.
	openWrt bool

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
// can substitute fakes without a running xray core; production code never
// changes it. cfg carries the local driver overrides (agent.yml Drivers, D4)
// and openWrt the platform fact the readiness defaults follow (F6).
var driverBuilder = buildDrivers

// Boot builds and starts the agent. The Xray forwarding engine is gone
// (PLAN v11 §2.5): only the external engines (gost, frp, realm) are
// registered, and the Xray instance lives in the separate W1nCray-xray
// program.
func Boot(opts Options) (*Runtime, error) {
	log := opts.Log
	if log == nil {
		log = nopLog{}
	}
	if opts.StateDir == "" || opts.KernelsDir == "" {
		return nil, fmt.Errorf("bootstrap: StateDir and KernelsDir are required")
	}
	// One labeler for the whole runtime: the kernel installer, the Xray service
	// manager and the supervisor all share its per-path cache, so a kernel is
	// labelled once per process and not on every driver apply.
	if opts.Labeler == nil {
		opts.Labeler = selinux.New(selinux.Options{Log: log})
	}
	st, err := state.Open(opts.StateDir)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	kern, err := KernelInstaller(opts)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	sup := supervisor.New(supervisor.Options{Log: log, PIDDir: filepath.Join(opts.StateDir, "pid"), Labeler: opts.Labeler})
	// The Xray kernel service (PLAN v11 §2.2): its status client, its service
	// manager and the managed-file validator/reloader are built here, where the
	// kernel installer, the supervisor and the configuration path are all in
	// scope. A failure only disables the service management; the agent keeps
	// running.
	var xrayMgr *xraysvc.Manager
	if opts.XrayConfigPath != "" {
		mgr, client, xerr := XrayManager(opts, kern, sup)
		if xerr != nil {
			log.Warnf("bootstrap: Xray service management unavailable: %v", xerr)
		} else {
			xrayMgr = mgr
			if opts.Xray == nil {
				opts.Xray = client
			}
		}
	}
	// The platform facts are read once: the driver readiness defaults (F6), the
	// OpenWrt firewall automation and the hello.policy report all need them
	// (PLAN v11 §4.3).
	plat := platform.Detect()
	drivers, err := driverBuilder(opts.Policy, opts.AgentConfig, plat.OpenWrt, log)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	rec := &reconcile.Reconciler{
		Drivers:  drivers,
		Kernels:  kern,
		Sup:      sup,
		Policy:   opts.Policy,
		State:    st,
		Log:      log,
		Firewall: newFirewall(opts, plat.OpenWrt, log),
	}
	rt := &Runtime{
		Reconciler:  rec,
		Sup:         sup,
		Kernels:     kern,
		State:       st,
		log:         log,
		cfg:         opts.AgentConfig,
		openWrt:     plat.OpenWrt,
		Xray:        opts.Xray,
		XrayManager: xrayMgr,
		xrayNeeded:  opts.XrayNeeded,
	}
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
		Xray:    xrayMgr,
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
		// The authoritative "the new version is really running" signal for the
		// watchdog (D-M7): a marker carrying this process's pid and version.
		// It is written before Ready is judged, so a watchdog still deciding
		// sees the version-correct process even if the install path was
		// already swapped under us.
		if _, pending := up.Pending(); pending {
			if merr := up.MarkReady(); merr != nil {
				log.Warnf("bootstrap: writing the self-update ready marker: %v", merr)
			}
		}
		if rerr := up.Ready(); rerr != nil {
			log.Infof("bootstrap: self-update capability withheld: %v", rerr)
		} else {
			rt.upgradeReady = true
		}
	}
	if opts.Resume {
		rt.resume()
		// The start-up firewall reconcile (PLAN v11 §4.3). A successful resume
		// already synced the rules inside its apply; this second pass is a
		// no-op then, and on a machine with no state to resume it removes the
		// w1ncray_* rules a previous run left behind. agent-apply (Resume
		// false) skips it and syncs when it applies its desired state.
		if err := rt.Reconciler.ReconcileFirewall(context.Background()); err != nil {
			log.Warnf("bootstrap: firewall reconcile: %v", err)
		}
	}
	// The start-up migration (PLAN v11 §2.6): when the configuration needs the
	// Xray kernel, its service is brought up. It must wait for a pending
	// self-update to be confirmed — a rollback to a 0.5.x agent (in-process
	// Xray) must not find the service already holding the ports — so Boot only
	// starts it when nothing is pending; the confirmed hook in StartRemote (and
	// the local command after Confirm) covers the other case.
	if !rt.xrayStartupDeferred() {
		bootXrayStart(rt)
	}
	return rt, nil
}

// bootXrayStart is the start-up migration trigger. It is a variable so tests
// can observe the decision without racing a goroutine; production code never
// changes it.
var bootXrayStart = func(rt *Runtime) { go rt.EnsureXray(context.Background()) }

// xrayStartupDeferred reports whether the start-up migration has to wait: a
// committed self_update that has not reached the panel yet could still be
// rolled back to the in-process 0.5.x agent, which must not find the Xray
// service already running.
func (r *Runtime) xrayStartupDeferred() bool {
	if r == nil || r.Updater == nil {
		return false
	}
	_, pending := r.Updater.Pending()
	return pending
}

// EnsureXray brings the Xray kernel service up when the configuration needs
// it. It is idempotent and runs at most once per process; the caller decides
// when it is allowed to run (never before a pending self-update is confirmed).
func (r *Runtime) EnsureXray(ctx context.Context) error {
	if r == nil || r.XrayManager == nil || !r.xrayNeeded {
		return nil
	}
	var err error
	r.xrayOnce.Do(func() {
		err = r.XrayManager.EnsureRunning(ctx)
		if err != nil {
			r.warnf("bootstrap: 启动 Xray 内核服务: %v", err)
		}
	})
	return err
}

// selfUpdateStalledReporter is the callback WatchStalled runs when a committed
// self-update was not confirmed within ConfirmWindow. It reports the stall and
// then stops deferring the Xray start-up migration (R1-7).
func (r *Runtime) selfUpdateStalledReporter(version string) func(kind, level, message string) {
	return func(kind, level, message string) {
		r.warnf("bootstrap: %s: %s", kind, message)
		if r.Ops != nil {
			r.Ops.EmitEvent(kind, level, message)
		}
		r.StartXrayAfterUnconfirmedUpdate(version)
	}
}

// StartXrayAfterUnconfirmedUpdate runs the Xray start-up migration for a
// process whose self-update the panel never confirmed (R1-7).
//
// The migration is deferred while an update is pending so that a rollback to
// the in-process-Xray 0.5.x agent never finds the 0.6 service holding the node
// ports. Once ConfirmWindow has passed, the watchdog has already exited: it
// either rolled the update back (this process is gone) or gave up and kept it
// (protocol ruling 11). Keeping Xray down for as long as the panel is
// unreachable is a regression against 0.5.x, which served Xray without the
// panel, so the migration runs now and the decision is reported. The
// rollbackAndRestart path also stops the Xray service first (R1-16), so a
// rollback racing this start still cannot leave two Xray instances on the
// ports.
func (r *Runtime) StartXrayAfterUnconfirmedUpdate(version string) {
	if r == nil || !r.xrayNeeded || r.XrayManager == nil {
		return
	}
	if err := r.EnsureXray(context.Background()); err != nil {
		r.warnf("bootstrap: 未确认的自升级 %s 之后启动 Xray 内核服务: %v", version, err)
		return
	}
	msg := fmt.Sprintf("version %s was not confirmed within %s; the Xray kernel service was started without the panel confirmation",
		version, r.ConfirmWindow())
	r.warnf("bootstrap: %s", msg)
	if r.Ops != nil {
		r.Ops.EmitEvent("self_update.xray_started", "warn", msg)
	}
}

// ConfirmWindow is how long a process from a committed self-update waits for
// the panel before it reports self_update.stalled (and, R1-7, starts Xray
// anyway). A runtime without an updater reports the default.
func (r *Runtime) ConfirmWindow() time.Duration {
	if r == nil || r.Updater == nil {
		return selfupdate.DefaultConfirmWindow
	}
	return r.Updater.ConfirmWindow()
}

// KernelInstaller builds the kernel installer (kernelx) and loads the
// persisted manifest. Boot uses it; the local `W1nCray xray` command uses it
// too, so both go through exactly the same trust root.
func KernelInstaller(o Options) (*kernelx.Ensurer, error) {
	if o.KernelsDir == "" {
		return nil, errors.New("bootstrap: KernelsDir is required")
	}
	log := o.Log
	if log == nil {
		log = nopLog{}
	}
	kern, err := kernelx.New(kernelx.Options{
		Dir:          o.KernelsDir,
		ManifestPath: o.ManifestPath,
		KeysPath:     o.ManifestKeysPath,
		AgentVersion: o.AgentVersion,
		AllowHTTP:    o.AllowHTTP,
		Labeler:      o.Labeler,
		// The pid directory is how the kernel commands tell "installed" from
		// "actually running" (kernelx.RunningVersion).
		PIDDir: filepath.Join(o.StateDir, "pid"),
		Log:    log,
	})
	if err != nil {
		return nil, err
	}
	loadPersistedManifest(kern, o.StateDir, o.ManifestPath, log)
	return kern, nil
}

// XrayManager builds the Xray kernel service manager and its status client
// from the same settings Boot uses. sup is the supervisor of the fallback
// backend (Boot passes its own; the local command creates one).
func XrayManager(o Options, kern *kernelx.Ensurer, sup *supervisor.Supervisor) (*xraysvc.Manager, xrayapi.Service, error) {
	if o.XrayConfigPath == "" {
		return nil, nil, errors.New("bootstrap: XrayConfigPath is required")
	}
	client, err := xraykern.New(xraykern.Options{ConfigPath: o.XrayConfigPath, Kernels: kern})
	if err != nil {
		return nil, nil, err
	}
	mgr, err := xraysvc.New(xraysvc.Options{
		Kernels:    kern,
		ConfigPath: o.XrayConfigPath,
		KernelsDir: o.KernelsDir,
		StateDir:   o.StateDir,
		Status:     client,
		Sup:        sup,
		Labeler:    kern,
		Log:        o.Log,
	})
	if err != nil {
		return nil, nil, err
	}
	return mgr, client, nil
}

// newUpdater builds the self-update updater around the running executable and
// the kernel installer. The executable is resolved (EvalSymlinks) so the swap
// replaces the real file a service manager runs, not a symlink to it.
//
// When the running image no longer resolves, the installed path from the
// service unit is used instead. That is the D-M7 self-heal: a rollback that
// raced this process's start unlinks the running image, and /proc/self/exe then
// reports "<path> (deleted)"; without the fallback, Ready would fail and the
// upgrade capability would be gone for the life of the process, with no way for
// the panel to put the machine back into a consistent state.
func newUpdater(kern *kernelx.Ensurer, opts Options, log driver.Logger) (*selfupdate.Updater, error) {
	if kern == nil {
		return nil, errors.New("no kernel installer")
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolving the running executable: %w", err)
	}
	target, healed := resolveUpdaterExe(exe, filepath.EvalSymlinks, selfupdate.ServiceExecutable)
	if healed {
		log.Warnf("bootstrap: the running executable %s no longer resolves; self-update targets the installed path %s", exe, target)
	}
	return selfupdate.New(selfupdate.Options{
		ExePath:      target,
		StateDir:     opts.StateDir,
		LockPath:     opts.LockPath,
		AgentVersion: opts.SelfVersion,
		Installer:    kern,
		Log:          log,
		AliveWindow:  opts.SelfUpdateAliveWindow,
		Deadline:     opts.SelfUpdateDeadline,
	})
}

// resolveUpdaterExe picks the file a self-update replaces: the running
// executable when it still resolves, else the installed path a service manager
// runs. The second result reports whether the fallback was used.
//
// The fallback is the D-M7 self-heal: a rollback that raced this process's
// start unlinks the running image, so os.Executable() returns
// "<path> (deleted)" and EvalSymlinks fails. The install path is still the file
// that has to be swapped, so targeting it keeps Ready() (and therefore the
// "upgrade" capability) working instead of losing it for the life of the
// process. It is pure so both branches are testable.
func resolveUpdaterExe(running string, resolve func(string) (string, error), installed func() string) (string, bool) {
	if resolved, err := resolve(running); err == nil {
		return resolved, false
	}
	if p := installed(); p != "" {
		return p, true
	}
	return running, false
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

// newFirewall builds the OpenWrt firewall manager the reconciler drives, or
// nil when this machine does not manage its firewall: everywhere but OpenWrt,
// and on OpenWrt with Firewall.AutoOpen turned off locally. A nil Firewall is
// what makes every instance report firewall_open false.
func newFirewall(opts Options, openWrt bool, log driver.Logger) reconcile.Firewall {
	if !openWrt || !opts.AgentConfig.FirewallAutoOpen(openWrt) {
		return nil
	}
	return fwopen.New(fwopen.Options{OpenWrt: true, AutoOpen: true, Log: log})
}

// buildDrivers is the production driver registry. The Xray forwarding engine
// is gone (PLAN v11 §2.5): the Xray instance is the separate W1nCray-xray
// program, so no engine here links Xray-core. openWrt is the platform fact of
// this machine: both readiness limits follow it (F6).
func buildDrivers(pol spec.Policy, cfg *agentcfg.Config, openWrt bool, log driver.Logger) (map[string]driver.Driver, error) {
	// The readiness limits are per architecture and per OpenWrt unless
	// agent.yml overrides them (Drivers.Frp.ReadyTimeoutSec, D4;
	// Drivers.Gost.ReadyTimeoutSec, F6). The drivers resolve their own default
	// from the platform fact, so only a real override is passed on.
	frpOpts := frp.Options{OpenWrt: openWrt}
	if d, ok := cfg.FrpReadyTimeout(); ok {
		frpOpts.ReadyTimeout = d
	}
	gostOpts := gost.Options{OpenWrt: openWrt}
	if d, ok := cfg.GostReadyTimeout(); ok {
		gostOpts.ReadyTimeout = d
	}
	m := map[string]driver.Driver{}
	m[spec.EngineGost] = gost.New(gostOpts)
	m[spec.EngineFrp] = frp.New(frpOpts)
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
