package panel

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"

	"github.com/W1nCwC/W1nCray/agent/agentcfg"
	"github.com/W1nCwC/W1nCray/agent/bootstrap"
	"github.com/W1nCwC/W1nCray/agent/filesync"
	"github.com/W1nCwC/W1nCray/api/xboard"
	"github.com/W1nCwC/W1nCray/common/cert"
	"github.com/W1nCwC/W1nCray/core"
	"github.com/W1nCwC/W1nCray/corehost"
	"github.com/W1nCwC/W1nCray/node"
)

// Machine mode timing. The intervals are variables so tests can shorten them.
var (
	// machinePollInterval is how often the machine's node list is polled.
	machinePollInterval = 60 * time.Second
	// machineRetryDelay is how long a failed discovery waits before it is
	// retried through the reload mechanism; the delay keeps a panel outage from
	// turning into a tight restart loop.
	machineRetryDelay = 30 * time.Second
)

// machineRequestTimeout bounds one machine-node request.
const machineRequestTimeout = 60 * time.Second

// reloadRequest is one queued rebuild. files names the watched files whose
// change triggered it; an empty list means the request did not come from the
// config watcher (a node controller, the machine watch or the managed-file
// reload), which always rebuilds xray.
type reloadRequest struct {
	reason string
	files  []string
}

// Panel owns the Xray instance and the node controllers.
type Panel struct {
	path string

	mu      sync.Mutex
	cfg     *Config
	core    *core.Core
	nodes   []*node.Controller
	agent   *bootstrap.Runtime
	running bool

	// host is the replaceable xray host the agent's xray engine is built on.
	// It is created with the first agent boot and survives every xray rebuild:
	// ReattachXray swaps in the new core and recreates the engine=xray
	// instances on it, so an xray change never restarts the agent.
	host *corehost.Swappable

	// coreOpts is the core options of the running xray instance, published by
	// startXrayLocked for the files validator (read without p.mu).
	coreOpts atomic.Pointer[core.Options]

	// remoteStop ends the agent's panel link (nil when it is not running).
	remoteStop func()

	// wsStop ends the agent's persistent WebSocket channel. The channel's
	// lifecycle belongs to bootstrap.StartRemote's stop (it owns both links and
	// ends the socket before the HTTP runner), so this field stays nil and is
	// kept only for a future split.
	wsStop func()

	// machineCancel ends the machine-node tasks of the running instance (nil
	// when machine mode is off or nothing runs); machineWG joins them so
	// shutdown never returns before they stopped.
	machineCancel context.CancelFunc
	machineWG     *sync.WaitGroup

	reloadCh chan struct{}
	stop     chan struct{}
	done     chan struct{}

	// reloadMu guards the rebuild queue. reloadPending is the request to serve
	// next (a request that arrives while one is pending is merged into it) and
	// reloadRunning is true while reload is executing one, so a request that
	// arrives during a long rebuild is remembered instead of being lost.
	reloadMu      sync.Mutex
	reloadPending *reloadRequest
	reloadRunning bool
}

// New creates a panel for the config file at path.
func New(path string, cfg *Config) *Panel {
	return &Panel{
		path:     path,
		cfg:      cfg,
		reloadCh: make(chan struct{}, 1),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// requestReload schedules a rebuild without blocking the caller. It is the node
// controller callback (node.Options.Reload) and is used for every event that is
// not a watched-file change; such a request always rebuilds xray.
func (p *Panel) requestReload(reason string) {
	p.enqueueReload(reloadRequest{reason: reason})
}

// requestReloadFiles schedules a rebuild triggered by a change of the named
// watched files. The file list is what lets reload tell an agent.yml-only edit
// (agent restart) from an xray edit (core rebuild).
func (p *Panel) requestReloadFiles(reason string, files []string) {
	p.enqueueReload(reloadRequest{reason: reason, files: files})
}

// enqueueReload queues a rebuild. A request that arrives while one is pending
// is merged into it (the first reason wins, but a non-file request keeps the
// rebuild an xray change); a request that arrives while a rebuild is running is
// remembered and served by the running reload's loop. The channel is only a
// wake-up signal.
func (p *Panel) enqueueReload(req reloadRequest) {
	p.reloadMu.Lock()
	if p.reloadPending == nil {
		r := req
		p.reloadPending = &r
	} else if p.reloadPending.files != nil && req.files != nil {
		p.reloadPending.files = mergeFiles(p.reloadPending.files, req.files)
	} else {
		// A request without a file list (a node, the machine watch, a managed
		// file reload) is always an xray change.
		p.reloadPending.files = nil
	}
	wake := !p.reloadRunning
	p.reloadMu.Unlock()
	if wake {
		select {
		case p.reloadCh <- struct{}{}:
		default:
		}
	}
}

// takeReload returns the next pending request and marks a rebuild as running.
// ok is false for a spurious wake-up (nothing pending).
func (p *Panel) takeReload() (reloadRequest, bool) {
	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()
	if p.reloadPending == nil {
		return reloadRequest{}, false
	}
	req := *p.reloadPending
	p.reloadPending = nil
	p.reloadRunning = true
	return req, true
}

// finishReload releases the "running" mark.
func (p *Panel) finishReload() {
	p.reloadMu.Lock()
	p.reloadRunning = false
	p.reloadMu.Unlock()
}

// mergeFiles returns the union of two watched-file lists, keeping the order and
// dropping duplicates.
func mergeFiles(a, b []string) []string {
	out := append([]string(nil), a...)
	seen := make(map[string]bool, len(out)+len(b))
	for _, f := range out {
		seen[f] = true
	}
	for _, f := range b {
		if !seen[f] {
			out = append(out, f)
			seen[f] = true
		}
	}
	return out
}

// ReloadForAgent rebuilds the xray instance after the managed files were
// replaced (agent/filesync). It is serialised with every other reload and it
// validates the config *before* it shuts anything down: a config.yml that does
// not load returns an error and leaves the running instance untouched (ruling 2,
// design section 6.2).
//
// Only xray is rebuilt: the agent (its terminals, its supervisor, its external
// kernels and its panel link) keeps running, so the applied-pending answer can
// be reported on the same link (WP-A).
//
// The rebuild itself is asynchronous: rebuildXray retries a failed start
// forever, so waiting for it here would either destroy the caller or never
// return. The panel judges health from the hello/telemetry that follow
// (protocol ruling 9).
func (p *Panel) ReloadForAgent(ctx context.Context, reason string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := LoadConfig(p.path); err != nil {
		return fmt.Errorf("reload refused, the running config is kept: %w", err)
	}
	p.requestReload("agent: " + reason)
	return nil
}

// Start builds and starts everything, then watches for reload requests.
func (p *Panel) Start() error {
	if err := p.start(); err != nil {
		return err
	}
	ready := make(chan struct{})
	go p.watch(ready)
	// Returning before the directory watches exist would lose a config change
	// made right after Start (the watcher registers asynchronously).
	<-ready
	return nil
}

func (p *Panel) start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.startLocked()
}

// startLocked starts the xray core with its node controllers and, on the first
// start, boots the agent. The caller must hold p.mu.
func (p *Panel) startLocked() error {
	if err := p.startXrayLocked(p.cfg); err != nil {
		return err
	}
	p.running = true
	p.startAgentLocked(p.cfg)
	log.Infof("W1nCray started with %d node(s)", len(p.nodes))
	return nil
}

// startXrayLocked builds and starts an xray core with its node controllers and
// machine-node tasks from cfg. On success the panel's core, nodes and machine
// task fields are replaced; the agent is not touched. The caller must hold
// p.mu.
func (p *Panel) startXrayLocked(cfg *Config) (err error) {
	setLogLevel(cfg.LogConfig.Level)

	certs := cert.NewManager(certDir(p.path, cfg))

	nodes := make([]*node.Controller, 0, len(cfg.NodesConfig))
	for _, nc := range cfg.NodesConfig {
		nodes = append(nodes, node.New(node.Options{
			API:    nc.ApiConfig,
			Config: nc.ControllerConfig,
			Certs:  certs,
			Reload: p.requestReload,
		}))
	}

	// Machine mode: the panel owns the node list. A discovery failure (panel
	// down, bad token) never keeps the static nodes from starting: it logs a
	// warning and is retried in the background through the reload mechanism.
	var machine *xboard.Client
	var machineVersion string
	var machineCtx context.Context
	var machineCancel context.CancelFunc
	var machineWG sync.WaitGroup
	if pc := machinePanel(cfg); pc != nil {
		ctx, cancel := context.WithCancel(context.Background())
		machineCtx, machineCancel = ctx, cancel
		c, version, derr := p.discoverMachineNodes(pc, certs, &nodes)
		if derr != nil {
			log.Warnf("machine nodes: %v (static nodes keep running; retrying)", derr)
			p.scheduleMachineRetry(ctx, &machineWG, "machine node discovery failed")
		} else {
			machine, machineVersion = c, version
		}
	}
	// A start that fails after this point must not leave the machine tasks
	// behind: the next start would otherwise start a second set.
	defer func() {
		if err != nil && machineCancel != nil {
			machineCancel()
			machineWG.Wait()
		}
	}()

	// Fetch node configs first: panel DNS routes are part of the DNS app,
	// which cannot change without rebuilding the instance.
	var wg sync.WaitGroup
	for _, n := range nodes {
		wg.Add(1)
		go func(n *node.Controller) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			if err := n.Prefetch(ctx); err != nil {
				log.WithField("node", n.Tag()).Errorf("%v (will retry)", err)
			}
		}(n)
	}
	wg.Wait()

	var ns []core.NameServer
	for _, n := range nodes {
		ns = append(ns, n.NameServers()...)
	}

	cr, cerr := core.New(coreOptions(cfg, ns))
	if cerr != nil {
		return cerr
	}
	if serr := cr.Start(); serr != nil {
		cr.Close()
		return fmt.Errorf("start xray: %w", serr)
	}
	for _, n := range nodes {
		if err := n.Start(cr); err != nil {
			log.WithField("node", n.Tag()).Errorf("start: %v", err)
		}
	}
	// Watch the machine's node list so a node added or removed on the panel is
	// picked up without a config change.
	if machine != nil {
		p.startMachineWatch(machineCtx, &machineWG, machine, machineVersion)
	}
	p.core, p.nodes = cr, nodes
	p.publishCoreOptionsLocked()
	p.machineCancel, p.machineWG = machineCancel, &machineWG
	return nil
}

// startAgentLocked boots the agent when it is enabled and not running yet, on
// the panel's current core. A boot failure is logged, not fatal: the panel
// nodes keep serving. The caller must hold p.mu.
func (p *Panel) startAgentLocked(cfg *Config) {
	if p.agent != nil || cfg.Agent == nil || !cfg.Agent.Enabled || p.core == nil {
		return
	}
	if p.host == nil {
		p.host = corehost.NewSwappable()
	}
	// The agent's xray engine runs on the current core. No Runtime exists yet
	// (or the old one was stopped), so the swap cannot race an Apply.
	p.host.Swap(p.core)
	// Say which file the agent's configuration came from: with two files in
	// play, silence is exactly what makes a stale edit hard to find.
	if src := cfg.AgentSourcePath(); src != "" {
		log.Infof("agent: configuration from %s", src)
	}
	rt, err := bootstrap.Boot(bootstrap.Options{
		StateDir:         cfg.Agent.StateDir,
		KernelsDir:       cfg.Agent.KernelsDir,
		ManifestPath:     cfg.Agent.ManifestPath,
		ManifestKeysPath: cfg.Agent.ManifestKeysPath,
		Policy:           cfg.Agent.PolicySpec(),
		AgentConfig:      cfg.Agent,
		// The build version names the watchdog copy of the previous binary
		// a committed self_update leaves behind, and the single-instance
		// lock is how that watchdog tells a restarted broken binary from a
		// running agent.
		SelfVersion: AgentVersion,
		LockPath:    p.path + ".lock",
		Files:       FilesOptionsFor(cfg, p.path),
		Log:         log.StandardLogger(),
		// The local terminal policy (D8, WP-G6). Enabled is the resolved
		// agentcfg value: on unless the machine opted out with
		// Terminal.Enabled: false or --noterminal.
		Terminal: terminalOptions(cfg.Agent),
		// The confined file operations (D9, WP-G6). No roots means no
		// file_* commands and no "files" capability.
		FileOps: fileOptions(p.path, cfg.Agent),
		// After a restart the persisted last good state comes back before
		// (and without) the panel, so a panel that is down never costs
		// forwarding.
		Resume: true,
	}, p.host)
	if err != nil {
		log.Errorf("agent: boot: %v", err)
		return
	}
	p.agent = rt
	if cfg.Agent.DesiredPath != "" {
		p.applyAgentDesiredLocked(cfg.Agent.DesiredPath, rt)
	}
	p.startRemoteLocked(cfg.Agent, rt)
}

// stopAgentLocked ends the agent and its panel link. It is what an agent.yml
// change and a process exit use; an xray rebuild never calls it. The caller
// must hold p.mu.
func (p *Panel) stopAgentLocked() {
	// Stop the WebSocket channel before the HTTP link: WS commands and hints
	// run through the same Runner the HTTP link stops below (design §3.6).
	if p.wsStop != nil {
		p.wsStop()
		p.wsStop = nil
	}
	// Stop the panel link first: no apply may race the teardown below.
	if p.remoteStop != nil {
		p.remoteStop()
		p.remoteStop = nil
	}
	if p.agent == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	if err := p.agent.Shutdown(ctx); err != nil {
		log.Errorf("agent: shutdown: %v", err)
	}
	cancel()
	p.agent = nil
}

// stopXrayLocked stops the machine tasks, the node controllers and the xray
// core. The caller must hold p.mu.
func (p *Panel) stopXrayLocked() {
	// Stop the machine-node tasks first: no discovery or watch may race the
	// teardown below. They never take p.mu, so waiting here cannot deadlock.
	p.stopMachineLocked()
	var wg sync.WaitGroup
	for _, n := range p.nodes {
		wg.Add(1)
		go func(n *node.Controller) {
			defer wg.Done()
			n.Close()
		}(n)
	}
	wg.Wait()
	// Closing the instance does not end accepted connections; abort the
	// tracked ones (none unless a tag prefix is watched) so that a rebuild does
	// not leave sessions of the old instance behind.
	if p.core != nil {
		if n := p.core.Conns().KillAll(); n > 0 {
			log.Infof("aborted %d tracked connection(s)", n)
		}
		if err := p.core.Close(); err != nil {
			log.Errorf("close xray: %v", err)
		}
	}
	p.nodes, p.core, p.running = nil, nil, false
}

// reattachXrayLocked recreates the agent's engine=xray instances on the core
// that is now running, leaving every other engine alone. The caller must hold
// p.mu.
func (p *Panel) reattachXrayLocked() {
	if p.agent == nil || p.core == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rep, err := p.agent.ReattachXray(ctx, p.core)
	if err != nil {
		log.Errorf("agent: reattach xray: %v", err)
		return
	}
	log.Infof("agent: xray reattached: %s (%d instance(s))", rep.Status, len(rep.Instances))
}

// discoverMachineNodes asks the panel which nodes this machine runs and appends
// a controller for each of them to nodes. It returns the machine client (for
// the version watch) and the version of the assignment. The token is passed to
// the client only; it never reaches a log or an error message.
func (p *Panel) discoverMachineNodes(pc *AgentPanelConfig, certs *cert.Manager, nodes *[]*node.Controller) (*xboard.Client, string, error) {
	token, err := pc.ResolveToken()
	if err != nil {
		return nil, "", err
	}
	c := xboard.New(xboard.Config{
		APIHost:      pc.URL,
		MachineID:    pc.MachineID,
		MachineToken: token,
	})
	ctx, cancel := context.WithTimeout(context.Background(), machineRequestTimeout)
	defer cancel()
	list, version, err := c.ListMachineNodes(ctx)
	if err != nil {
		return nil, "", err
	}
	for _, mn := range list {
		*nodes = append(*nodes, node.New(node.Options{
			API: &node.APIConfig{
				APIHost:      pc.URL,
				NodeID:       mn.ID,
				NodeType:     mn.Type,
				MachineID:    pc.MachineID,
				MachineToken: token,
			},
			Config: machineNodeConfig(pc, mn.ID),
			Certs:  certs,
			Reload: p.requestReload,
		}))
	}
	logUnassignedNodeControllers(pc, list)
	log.Infof("machine %d: %d node(s) assigned by the panel", pc.MachineID, len(list))
	return c, version, nil
}

// machineNodeConfig returns the ControllerConfig of one machine node: a
// NodeControllers[id] override wins as a whole, then the shared NodeController
// template, then the node defaults. Both paths copy, so no two controllers
// share mutable state.
func machineNodeConfig(pc *AgentPanelConfig, id int) *node.Config {
	if cc := pc.NodeControllers[id]; cc != nil {
		return machineControllerConfig(cc)
	}
	return machineControllerConfig(pc.NodeController)
}

// logUnassignedNodeControllers logs one info line per NodeControllers entry the
// panel did not assign to this machine. A stale override is not an error: the
// panel owns the assignment and the node may come back later.
func logUnassignedNodeControllers(pc *AgentPanelConfig, list []xboard.MachineNode) {
	if len(pc.NodeControllers) == 0 {
		return
	}
	assigned := make(map[int]bool, len(list))
	for _, mn := range list {
		assigned[mn.ID] = true
	}
	for _, id := range pc.NodeControllerIDs() {
		if !assigned[id] {
			log.Infof("NodeControllers[%d] is configured but the panel did not assign that node", id)
		}
	}
}

// machineControllerConfig returns a fresh ControllerConfig (the shared
// template or a per-node override) completed with the node defaults, so no two
// controllers share the top-level struct. validate() already completed the
// configured ones; applying the defaults again is idempotent and also covers a
// directly built config. The copy is shallow: the controller treats the nested
// config (CertConfig, REALITYConfigs, ...) as read-only, so sharing it cannot
// move a change from one node to another.
func machineControllerConfig(t *node.Config) *node.Config {
	return controllerConfigWithDefaults(t)
}

// startMachineWatch starts the node-list watcher of a new instance. wg is the
// wait group of the instance the watcher belongs to.
func (p *Panel) startMachineWatch(ctx context.Context, wg *sync.WaitGroup, c *xboard.Client, version string) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.machineWatch(ctx, c, version)
	}()
}

// machineWatch polls the machine's node list and asks for a reload when it
// changes. It returns when the instance is shut down (ctx) or after it
// requested a reload, which starts a fresh watcher.
func (p *Panel) machineWatch(ctx context.Context, c *xboard.Client, version string) {
	t := time.NewTicker(machinePollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		reqCtx, cancel := context.WithTimeout(ctx, machineRequestTimeout)
		_, next, err := c.ListMachineNodes(reqCtx)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Warnf("machine nodes: %v", err)
			continue
		}
		if next != version {
			log.Infof("machine node list changed (version %s)", next)
			p.requestReload("machine nodes changed")
			return
		}
	}
}

// scheduleMachineRetry asks for a reload after machineRetryDelay, so a failed
// discovery is retried without blocking the running nodes. The goroutine ends
// with the instance context or after it fired. wg is the wait group of the
// instance the retry belongs to.
func (p *Panel) scheduleMachineRetry(ctx context.Context, wg *sync.WaitGroup, reason string) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTimer(machineRetryDelay)
		defer t.Stop()
		select {
		case <-ctx.Done():
		case <-t.C:
			p.requestReload(reason)
		}
	}()
}

// stopMachineLocked cancels and joins the machine-node tasks. The caller must
// hold p.mu.
func (p *Panel) stopMachineLocked() {
	if p.machineCancel == nil {
		return
	}
	p.machineCancel()
	if p.machineWG != nil {
		p.machineWG.Wait()
	}
	p.machineCancel, p.machineWG = nil, nil
}

// applyAgentDesiredLocked applies a desired-state file and logs the outcome.
// The caller must hold p.mu.
func (p *Panel) applyAgentDesiredLocked(path string, rt *bootstrap.Runtime) {
	rep, err := rt.ApplyFile(path)
	if err != nil {
		log.Errorf("agent: apply %s: %v", path, err)
		return
	}
	log.Infof("agent: %s: %s (%d instance(s))", path, rep.Status, len(rep.Instances))
}

// AgentVersion is the version the agent reports to the panel. The command
// package sets it from the build version; "dev" otherwise.
var AgentVersion = "dev"

// RequestRestart asks the process owner to shut down cleanly so the binary a
// committed self_update put in place takes over. The command package sets it
// (like AgentVersion); a nil hook means self_update is not served and the
// upgrade capability is not declared.
var RequestRestart func()

// startRemoteLocked links the agent to the panel when it is configured. A
// problem with the link (unreadable token file, bad options) is logged and
// leaves the agent running on its local state. The caller must hold p.mu.
func (p *Panel) startRemoteLocked(a *AgentConfig, rt *bootstrap.Runtime) {
	if a == nil || a.Panel == nil || !a.Panel.Enabled {
		return
	}
	pc := a.Panel
	token, err := pc.ResolveToken()
	if err != nil {
		log.Errorf("agent: panel link not started: %v", err)
		return
	}
	pull, report := pc.Intervals()
	o := bootstrap.RemoteOptions{
		URL:               pc.URL,
		MachineID:         pc.MachineID,
		Token:             token,
		AllowInsecureHTTP: pc.AllowInsecureHTTP,
		PullInterval:      pull,
		ReportInterval:    report,
		AgentVersion:      AgentVersion,
		Log:               log.StandardLogger(),
		// The persistent WebSocket channel rides on the same validated link:
		// it only exists once a token and a machine id did (design section
		// 3.1). Without them startRemoteLocked returned above, so an agent in
		// the legacy node mode never opens a socket.
		WS:          true,
		AgentConfig: a,
		// A committed self_update swaps the executable and asks this process to
		// exit; the self-update watchdog (or the service manager) then brings
		// the new binary back up. Without the hook the command is not
		// registered.
		OnRestart: RequestRestart,
		// The managed-file layer needs the panel side of the two operations
		// bootstrap cannot own: the offline pre-check (the panel has the live
		// core options) and the rebuild (ReloadForAgent).
		FilesValidator: p.NewCoreValidator(),
		Reloader:       filesync.ReloaderFunc(p.ReloadForAgent),
	}
	// The panel may also serve the signed kernel manifest; the agent verifies
	// it locally before it is used, so a compromised panel cannot push a
	// malicious kernel.
	if pc.ManifestSyncEnabled() {
		o.ManifestSync = true
		o.ManifestPersistPath = bootstrap.PersistedManifestPath(a.StateDir)
		o.ManifestInterval = pc.ManifestInterval()
	}
	stop, err := rt.StartRemote(context.Background(), o)
	if err != nil {
		log.Errorf("agent: panel link not started: %v", err)
		return
	}
	p.remoteStop = stop
	log.Infof("agent: linked to the panel %s as machine %d", pc.URL, pc.MachineID)
	if o.ManifestSync {
		log.Infof("agent: kernel manifest sync enabled (every %s, persisted to %s)", o.ManifestInterval, o.ManifestPersistPath)
	}
}

// shutdown stops everything, agent included. It is the process-exit path
// (Close): an xray rebuild no longer goes through it, so a config change never
// ends the agent's terminals, its supervisor or its external kernels.
func (p *Panel) shutdown() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.running && p.agent == nil {
		return
	}
	// The agent's kernels may live in the Xray instance, so stop it before
	// closing the core.
	p.stopAgentLocked()
	p.stopXrayLocked()
}

// Close stops everything.
func (p *Panel) Close() {
	close(p.stop)
	<-p.done
	p.shutdown()
}

// reload serves queued rebuild requests. It keeps taking requests until none is
// pending, so a request that arrived during a long rebuild is served next
// instead of being lost.
func (p *Panel) reload() {
	for {
		req, ok := p.takeReload()
		if !ok {
			return
		}
		p.applyReload(req)
		p.finishReload()
	}
}

// applyReload carries out one rebuild. An agent.yml-only change restarts the
// agent and leaves xray running; every other watched file (and every request
// that did not come from the watcher) rebuilds the xray core and its node
// controllers, keeping the agent alive and reattaching only its xray engine.
func (p *Panel) applyReload(req reloadRequest) {
	reason := req.reason
	if reason == "" {
		reason = "config file changed"
	}
	log.Infof("reloading: %s", reason)
	cfg, err := LoadConfig(p.path)
	if err != nil {
		log.Errorf("reload aborted, keeping the running config: %v", err)
		return
	}

	p.mu.Lock()
	old := p.cfg
	p.mu.Unlock()

	if isAgentYMLOnly(req.files, p.path) {
		if sameAgentConfig(old, cfg) {
			// The agent.yml change did not change the effective agent
			// configuration (a touch, or an edit that resolved to the same
			// values): nothing to restart.
			p.mu.Lock()
			p.cfg = cfg
			p.mu.Unlock()
			log.Infof("reload: agent.yml changed but the agent configuration is unchanged")
			return
		}
		p.restartAgent(cfg)
		return
	}
	p.rebuildXray(cfg, !sameAgentConfig(old, cfg))
}

// restartAgent restarts the agent with cfg and leaves xray untouched. It is the
// agent.yml-only path: the old Runtime owns the terminals, the supervisor, the
// external kernels and the panel link, so they all end here, while the xray
// core keeps running and is handed to the new Runtime.
func (p *Panel) restartAgent(cfg *Config) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopAgentLocked()
	p.cfg = cfg
	if p.running {
		p.startAgentLocked(cfg)
	}
}

// rebuildXray replaces the xray core and its node controllers with ones built
// from cfg. The agent is not shut down: its xray engine is detached from the
// old core before it is closed and reattached to the new one afterwards, while
// its terminals, its supervisor, its panel link and the instances of the other
// engines keep running. restartAgent restarts the agent too when the change
// touched the agent configuration; the new Runtime resumes the persisted state
// on the new core.
func (p *Panel) rebuildXray(cfg *Config, restartAgent bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	select {
	case <-p.stop:
		return
	default:
	}

	if !p.running {
		// Nothing is running (a previous start failed, or Close raced the
		// reload): start from scratch with the new configuration.
		p.stopAgentLocked()
		p.cfg = cfg
		if err := p.startLocked(); err != nil {
			log.Errorf("restart failed: %v", err)
		}
		return
	}

	// Take the xray engine off the core that is about to be closed: from here
	// on its calls fail cleanly instead of reaching a closed instance, and no
	// Apply can be in flight while the core is replaced.
	if p.agent != nil {
		p.agent.DetachXray()
	}
	p.stopXrayLocked()
	p.cfg = cfg
	for {
		if err := p.startXrayLocked(cfg); err == nil {
			break
		} else {
			log.Errorf("xray restart failed: %v; retrying in 10s", err)
		}
		// Do not hold p.mu while waiting: the previous implementation
		// released it between attempts too, and Close (and everything else
		// that takes p.mu) must not stall for as long as xray keeps failing.
		p.mu.Unlock()
		var stopped bool
		select {
		case <-p.stop:
			stopped = true
		case <-time.After(10 * time.Second):
		}
		p.mu.Lock()
		if stopped {
			return
		}
	}
	p.running = true
	if restartAgent {
		p.stopAgentLocked()
	}
	if p.agent == nil {
		p.startAgentLocked(cfg)
	} else {
		p.reattachXrayLocked()
	}
}

// isAgentYMLOnly reports whether every changed watched file is agent.yml. Such
// a change restarts the agent and leaves the xray core alone; any other watched
// file (config.yml, route/dns/custom_*, a rule list) rebuilds xray. The file
// names are absolute, as the watcher produces them.
func isAgentYMLOnly(files []string, configPath string) bool {
	if len(files) == 0 {
		return false
	}
	agentYML, err := filepath.Abs(filepath.Join(filepath.Dir(configPath), agentcfg.FileName))
	if err != nil {
		return false
	}
	for _, f := range files {
		if f != agentYML {
			return false
		}
	}
	return true
}

// sameAgentConfig reports whether two loaded configs describe the same agent
// configuration. It is what tells an agent-only edit from a change that also
// affects xray: the agent half is compared as a whole, with its paths already
// resolved by LoadConfig.
func sameAgentConfig(a, b *Config) bool {
	return reflect.DeepEqual(agentOf(a), agentOf(b))
}

func agentOf(c *Config) *AgentConfig {
	if c == nil {
		return nil
	}
	return c.Agent
}

// watch handles reload requests from nodes and changes of the config files.
func (p *Panel) watch(ready chan<- struct{}) {
	defer close(p.done)
	var readyOnce sync.Once
	signalReady := func() { readyOnce.Do(func() { close(ready) }) }
	defer signalReady()
	w, err := fsnotify.NewWatcher()
	if err != nil {
		log.Warnf("config watcher unavailable: %v", err)
	}
	watched := map[string]bool{}
	if w != nil {
		defer w.Close()
		// Watch directories: editors replace files, which drops file watches.
		for _, f := range p.watchedFiles() {
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
	// state instead of reloading the panel. Debounce both.
	desiredAbs := ""
	if dp := p.agentDesiredPath(); dp != "" {
		desiredAbs, _ = filepath.Abs(dp)
	}

	var debounce <-chan time.Time
	var debounceFiles []string
	var desiredDebounce <-chan time.Time
	for {
		select {
		case <-p.stop:
			return
		case <-p.reloadCh:
			// requestReload already queued the request; reload serves it and
			// any request that arrived meanwhile.
			p.reload()
		case ev := <-events:
			abs, _ := filepath.Abs(ev.Name)
			if desiredAbs != "" && abs == desiredAbs {
				if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
					desiredDebounce = time.After(500 * time.Millisecond)
				}
			} else if watched[abs] && ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
				// Remember which file changed: an agent.yml-only edit restarts
				// the agent, everything else rebuilds xray.
				debounceFiles = mergeFiles(debounceFiles, []string{abs})
				if debounce == nil {
					debounce = time.After(2 * time.Second)
				}
			}
		case err := <-errs:
			log.Warnf("config watcher: %v", err)
		case <-desiredDebounce:
			desiredDebounce = nil
			p.applyAgentDesired()
		case <-debounce:
			debounce = nil
			files := debounceFiles
			debounceFiles = nil
			// Through requestReload, not straight into reload: a rebuild may be
			// running (a long reload, or ReloadForAgent), and two concurrent
			// rebuilds would race over p.core and p.nodes.
			p.requestReloadFiles("config file changed", files)
		}
	}
}

// applyAgentDesired applies the current desired-state file, if the agent is
// running. It is called from the watcher goroutine.
func (p *Panel) applyAgentDesired() {
	p.mu.Lock()
	rt := p.agent
	var path string
	if p.cfg.Agent != nil {
		path = p.cfg.Agent.DesiredPath
	}
	p.mu.Unlock()
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

func (p *Panel) watchedFiles() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	files := []string{p.path}
	for _, f := range []string{p.cfg.DnsConfigPath, p.cfg.RouteConfigPath, p.cfg.InboundConfigPath, p.cfg.OutboundConfigPath} {
		if f != "" {
			files = append(files, f)
		}
	}
	for _, n := range p.cfg.NodesConfig {
		if n.ApiConfig.RuleListPath != "" {
			files = append(files, n.ApiConfig.RuleListPath)
		}
	}
	if p.cfg.Agent != nil && p.cfg.Agent.DesiredPath != "" {
		files = append(files, p.cfg.Agent.DesiredPath)
	}
	// agent.yml is watched even before it exists: creating it switches the
	// agent to the separated layout and must take effect without a restart
	// (D1). The watcher registers the directory, so the create event arrives.
	files = append(files, filepath.Join(filepath.Dir(p.path), agentcfg.FileName))
	return files
}

// agentDesiredPath returns the configured desired-state file ("" if none).
func (p *Panel) agentDesiredPath() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cfg.Agent == nil {
		return ""
	}
	return p.cfg.Agent.DesiredPath
}

func certDir(path string, cfg *Config) string {
	if cfg.CertDir != "" {
		return cfg.CertDir
	}
	return filepath.Join(filepath.Dir(path), "cert")
}

// FilesOptionsFor translates the local Files policy into the managed-file
// layer's options (D4/D5). configPath is the live config.yml: the xray
// configuration directory is where the four JSON files and the two geo
// databases live, so that is the only place a managed file is written.
// config.yml is only manageable when the machine uses the agent.yml layout
// (ruling 2): otherwise that file is the agent's own configuration and a remote
// write would overwrite it.
//
// The command package (agent-apply) uses it too, so the offline run reports the
// same local policy as the running service.
func FilesOptionsFor(cfg *Config, configPath string) *bootstrap.FilesOptions {
	if cfg == nil || cfg.Agent == nil {
		return nil
	}
	a := cfg.Agent
	var maxBytes, maxGeo int64
	if a.Files != nil {
		maxBytes, maxGeo = a.Files.MaxBytes, a.Files.MaxGeoBytes
	}
	return &bootstrap.FilesOptions{
		ConfigDir:       filepath.Dir(configPath),
		ConfigPath:      configPath,
		StateDir:        filepath.Join(a.StateDir, "filesync"),
		MaxBytes:        maxBytes,
		MaxGeoBytes:     maxGeo,
		LayoutSeparated: a.SeparatedLayout(),
	}
}

func coreOptions(cfg *Config, ns []core.NameServer) core.Options {
	cc := cfg.ConnectionConfig
	return core.Options{
		LogLevel:           xrayLogLevel(cfg.LogConfig.Level),
		AccessPath:         cfg.LogConfig.AccessPath,
		ErrorPath:          cfg.LogConfig.ErrorPath,
		DNSConfigPath:      cfg.DnsConfigPath,
		RouteConfigPath:    cfg.RouteConfigPath,
		InboundConfigPath:  cfg.InboundConfigPath,
		OutboundConfigPath: cfg.OutboundConfigPath,
		Connection: core.ConnectionPolicy{
			Handshake:    cc.Handshake,
			ConnIdle:     cc.ConnIdle,
			UplinkOnly:   cc.UplinkOnly,
			DownlinkOnly: cc.DownlinkOnly,
			BufferSize:   cc.BufferSize,
		},
		NameServers: ns,
	}
}

func xrayLogLevel(l string) string {
	switch strings.ToLower(l) {
	case "debug", "info", "warning", "error", "none":
		return strings.ToLower(l)
	case "warn":
		return "warning"
	}
	return "warning"
}

func setLogLevel(l string) {
	switch strings.ToLower(l) {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "error", "none":
		log.SetLevel(log.ErrorLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}
}
