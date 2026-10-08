package agentd

import (
	"context"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"

	"github.com/W1nCwC/W1nCray/agent/agentcfg"
	"github.com/W1nCwC/W1nCray/agent/bootstrap"
	"github.com/W1nCwC/W1nCray/agent/xrayapi"
)

// AgentVersion is the version the agent reports to the panel. The command
// package sets it from the build version; "dev" otherwise.
var AgentVersion = "dev"

// RequestRestart asks the process owner to shut down cleanly so the binary a
// committed self_update put in place takes over. The command package sets it
// (like AgentVersion); a nil hook means self_update is not served and the
// upgrade capability is not declared.
var RequestRestart func()

// Options configures a Daemon.
type Options struct {
	// Xray is the agent's view of the locally installed Xray kernel. Nil means
	// the kernel is not installed on this machine: managed Xray files are then
	// refused with "Xray 内核未安装" instead of being half-applied. The agent
	// never links Xray-core itself; X2 provides the implementation.
	Xray xrayapi.Service
}

// Daemon owns the agent runtime and its panel link.
type Daemon struct {
	path string

	mu     sync.Mutex
	cfg    *Config
	agent  *bootstrap.Runtime
	remote func()
	wsStop func()
	// running reports whether the daemon was started (not whether the agent is
	// enabled: a machine may run with no Agent section at all).
	running bool

	// xray is the Xray kernel service this daemon was started with.
	xray xrayapi.Service

	reloadCh chan struct{}
	stop     chan struct{}
	done     chan struct{}
}

// New creates a daemon for the config file at path.
func New(path string, cfg *Config, opts Options) *Daemon {
	return &Daemon{
		path:     path,
		cfg:      cfg,
		xray:     opts.Xray,
		reloadCh: make(chan struct{}, 1),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// Start boots the agent and watches agent.yml and the desired-state file.
func (d *Daemon) Start() error {
	if err := d.start(); err != nil {
		return err
	}
	ready := make(chan struct{})
	go d.watch(ready)
	// Returning before the directory watches exist would lose a config change
	// made right after Start (the watcher registers asynchronously).
	<-ready
	return nil
}

func (d *Daemon) start() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.startLocked()
}

// startLocked boots the agent when it is enabled. The caller must hold d.mu.
func (d *Daemon) startLocked() error {
	d.running = true
	d.startAgentLocked(d.cfg)
	if d.agent != nil {
		log.Infof("W1nCray agent started")
	} else {
		log.Infof("W1nCray agent started (no Agent section is enabled)")
	}
	return nil
}

// startAgentLocked boots the agent when it is enabled and not running yet. A
// boot failure is logged, not fatal. The caller must hold d.mu.
func (d *Daemon) startAgentLocked(cfg *Config) {
	if d.agent != nil || cfg.Agent == nil || !cfg.Agent.Enabled {
		return
	}
	// Say which file the agent's configuration came from: with two files in
	// play, silence is exactly what makes a stale edit hard to find.
	if src := cfg.AgentSourcePath(); src != "" {
		log.Infof("agent: configuration from %s", src)
	}
	// The self-update watchdog timing is a local override (agent.yml, D-M7):
	// the panel never pushes agent configuration. Zero keeps the architecture
	// default.
	selfAlive, selfDeadline := cfg.Agent.SelfUpdateWindows(runtime.GOARCH)
	rt, err := bootstrap.Boot(bootstrap.Options{
		StateDir:         cfg.Agent.StateDir,
		KernelsDir:       cfg.Agent.KernelsDir,
		ManifestPath:     cfg.Agent.ManifestPath,
		ManifestKeysPath: cfg.Agent.ManifestKeysPath,
		Policy:           cfg.Agent.PolicySpec(),
		AgentConfig:      cfg.Agent,
		// The local kernel-source switch (Kernels.AllowHTTP, D-M1): off unless
		// this machine's own configuration turned it on.
		AllowHTTP: KernelAllowHTTP(cfg),
		// The build version names the watchdog copy of the previous binary
		// a committed self_update leaves behind, and the single-instance
		// lock is how that watchdog tells a restarted broken binary from a
		// running agent.
		SelfVersion: AgentVersion,
		LockPath:    d.path + ".lock",
		// The local self-update watchdog timing (D-M7): a slow device widens
		// the "no agent alive" window instead of being rolled back mid-start.
		SelfUpdateAliveWindow: selfAlive,
		SelfUpdateDeadline:    selfDeadline,
		Files:                 FilesOptionsFor(cfg, d.path),
		Log:                   log.StandardLogger(),
		// The local terminal policy (D8, WP-G6). Enabled is the resolved
		// agentcfg value: on unless the machine opted out with
		// Terminal.Enabled: false or --noterminal.
		Terminal: terminalOptions(cfg.Agent),
		// The confined file operations (D9, WP-G6). No roots means no
		// file_* commands and no "files" capability.
		FileOps: fileOptions(d.path, cfg.Agent),
		// The Xray kernel service (nil when it is not installed): the managed
		// xray files are validated by the kernel itself.
		Xray: d.xray,
		// The Xray kernel service manager (PLAN v11 §2.2) is built inside Boot,
		// around the supervisor it creates. Boot needs the config path to reach
		// the kernel's status endpoint and to start it, and NeedsXray to know
		// whether the start-up migration applies.
		XrayConfigPath: d.path,
		XrayNeeded:     NeedsXray(d.path, cfg),
		// After a restart the persisted last good state comes back before
		// (and without) the panel, so a panel that is down never costs
		// forwarding.
		Resume: true,
	})
	if err != nil {
		log.Errorf("agent: boot: %v", err)
		return
	}
	d.agent = rt
	if cfg.Agent.DesiredPath != "" {
		d.applyAgentDesiredLocked(cfg.Agent.DesiredPath, rt)
	}
	d.startRemoteLocked(cfg.Agent, rt)
}

// stopAgentLocked ends the agent and its panel link. The caller must hold
// d.mu.
func (d *Daemon) stopAgentLocked() {
	// Stop the WebSocket channel before the HTTP link: WS commands and hints
	// run through the same Runner the HTTP link stops below.
	if d.wsStop != nil {
		d.wsStop()
		d.wsStop = nil
	}
	// Stop the panel link first: no apply may race the teardown below.
	if d.remote != nil {
		d.remote()
		d.remote = nil
	}
	if d.agent == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	if err := d.agent.Shutdown(ctx); err != nil {
		log.Errorf("agent: shutdown: %v", err)
	}
	cancel()
	d.agent = nil
}

// EnsureXray runs the start-up migration (PLAN v11 §2.6) on the running
// runtime: when the configuration needs the Xray kernel, its service is
// installed or started. It is a no-op when the runtime is not up or the machine
// does not need Xray, and idempotent within one process.
//
// The caller must only call it after a pending self-update is confirmed: a
// rollback to the in-process 0.5.x agent must not find the Xray service already
// holding the ports.
func (d *Daemon) EnsureXray(ctx context.Context) {
	d.mu.Lock()
	rt := d.agent
	d.mu.Unlock()
	if rt == nil {
		return
	}
	if err := rt.EnsureXray(ctx); err != nil {
		log.Warnf("agent: Xray 内核服务: %v", err)
	}
}

// applyAgentDesiredLocked applies a desired-state file and logs the outcome.
// The caller must hold d.mu.
func (d *Daemon) applyAgentDesiredLocked(path string, rt *bootstrap.Runtime) {
	rep, err := rt.ApplyFile(path)
	if err != nil {
		log.Errorf("agent: apply %s: %v", path, err)
		return
	}
	log.Infof("agent: %s: %s (%d instance(s))", path, rep.Status, len(rep.Instances))
}

// shutdown stops everything.
func (d *Daemon) shutdown() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.running {
		return
	}
	d.stopAgentLocked()
	d.running = false
}

// Close stops everything.
func (d *Daemon) Close() {
	close(d.stop)
	<-d.done
	d.shutdown()
}

// reload re-reads the agent configuration and restarts the agent when it
// changed. The Xray core is not touched: it is a separate process now.
func (d *Daemon) reload() {
	cfg, err := LoadConfig(d.path)
	if err != nil {
		log.Errorf("reload aborted, keeping the running agent configuration: %v", err)
		return
	}
	d.mu.Lock()
	old := d.cfg
	d.mu.Unlock()
	if sameAgentConfig(old, cfg) {
		log.Infof("reload: the agent configuration is unchanged; nothing to do")
		return
	}
	log.Infof("reloading: agent configuration changed")
	d.restartAgent(cfg)
}

// restartAgent restarts the agent with cfg. The old Runtime owns the terminals,
// the supervisor, the external kernels and the panel link, so they all end here
// and the new Runtime resumes the persisted state.
func (d *Daemon) restartAgent(cfg *Config) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stopAgentLocked()
	d.cfg = cfg
	if d.running {
		d.startAgentLocked(cfg)
	}
}

// sameAgentConfig reports whether two loaded configs describe the same agent
// configuration. It is what tells a touch (or an edit that resolved to the same
// values) from a real change: the agent half is compared as a whole, with its
// paths already resolved by the loader.
func sameAgentConfig(a, b *Config) bool {
	return reflect.DeepEqual(agentOf(a), agentOf(b))
}

func agentOf(c *Config) *agentcfg.Config {
	if c == nil {
		return nil
	}
	return c.Agent
}

// watch handles changes of the agent configuration and of the desired-state
// file. The Xray configuration files are watched by the kernel program.
func (d *Daemon) watch(ready chan<- struct{}) {
	defer close(d.done)
	var readyOnce sync.Once
	signalReady := func() { readyOnce.Do(func() { close(ready) }) }
	defer signalReady()
	w, err := fsnotify.NewWatcher()
	if err != nil {
		log.Warnf("agent config watcher unavailable: %v", err)
	}
	watched := map[string]bool{}
	if w != nil {
		defer w.Close()
		// Watch directories: editors replace files, which drops file watches.
		for _, f := range d.watchedFiles() {
			abs, err := filepath.Abs(f)
			if err != nil {
				continue
			}
			watched[abs] = true
			_ = w.Add(filepath.Dir(abs))
		}
	}
	signalReady()
	var events chan fsnotify.Event
	var errs chan error
	if w != nil {
		events, errs = w.Events, w.Errors
	}
	// The desired-state file is watched too, but a change applies the agent
	// state instead of restarting the agent. Debounce both.
	desiredAbs := ""
	if dp := d.agentDesiredPath(); dp != "" {
		desiredAbs, _ = filepath.Abs(dp)
	}

	var debounce <-chan time.Time
	var desiredDebounce <-chan time.Time
	for {
		select {
		case <-d.stop:
			return
		case <-d.reloadCh:
			d.reload()
		case ev := <-events:
			abs, _ := filepath.Abs(ev.Name)
			if desiredAbs != "" && abs == desiredAbs {
				if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
					desiredDebounce = time.After(500 * time.Millisecond)
				}
			} else if watched[abs] && ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
				if debounce == nil {
					debounce = time.After(2 * time.Second)
				}
			}
		case err := <-errs:
			log.Warnf("agent config watcher: %v", err)
		case <-desiredDebounce:
			desiredDebounce = nil
			d.applyAgentDesired()
		case <-debounce:
			debounce = nil
			// Through the reload channel, not straight into reload: a restart
			// may be running and two concurrent restarts would race.
			select {
			case d.reloadCh <- struct{}{}:
			default:
			}
		}
	}
}

// applyAgentDesired applies the current desired-state file, if the agent is
// running. It is called from the watcher goroutine.
func (d *Daemon) applyAgentDesired() {
	d.mu.Lock()
	rt := d.agent
	var path string
	if d.cfg.Agent != nil {
		path = d.cfg.Agent.DesiredPath
	}
	d.mu.Unlock()
	if rt == nil || path == "" {
		return
	}
	rep, err := rt.ApplyFile(path)
	if err != nil {
		log.Errorf("agent: apply %s: %v", path, err)
		return
	}
	log.Infof("agent: %s: %s", path, rep.Status)
}

// watchedFiles returns the files whose changes the daemon reacts to: config.yml
// and agent.yml (the agent's own configuration, whichever layout is in use) and
// the desired-state file.
func (d *Daemon) watchedFiles() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	files := []string{d.path, filepath.Join(filepath.Dir(d.path), agentcfg.FileName)}
	if d.cfg.Agent != nil && d.cfg.Agent.DesiredPath != "" {
		files = append(files, d.cfg.Agent.DesiredPath)
	}
	return files
}

// agentDesiredPath returns the configured desired-state file ("" if none).
func (d *Daemon) agentDesiredPath() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cfg.Agent == nil {
		return ""
	}
	return d.cfg.Agent.DesiredPath
}
