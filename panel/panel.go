package panel

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"

	"github.com/W1nCwC/W1nCray/agent/bootstrap"
	"github.com/W1nCwC/W1nCray/api/xboard"
	"github.com/W1nCwC/W1nCray/common/cert"
	"github.com/W1nCwC/W1nCray/core"
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

// Panel owns the Xray instance and the node controllers.
type Panel struct {
	path string

	mu      sync.Mutex
	cfg     *Config
	core    *core.Core
	nodes   []*node.Controller
	agent   *bootstrap.Runtime
	running bool

	// remoteStop ends the agent's panel link (nil when it is not running).
	remoteStop func()

	// machineCancel ends the machine-node tasks of the running instance (nil
	// when machine mode is off or nothing runs); machineWG joins them so
	// shutdown never returns before they stopped.
	machineCancel context.CancelFunc
	machineWG     sync.WaitGroup

	reloadCh chan string
	stop     chan struct{}
	done     chan struct{}
}

// New creates a panel for the config file at path.
func New(path string, cfg *Config) *Panel {
	return &Panel{
		path:     path,
		cfg:      cfg,
		reloadCh: make(chan string, 1),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// requestReload schedules a rebuild without blocking the caller.
func (p *Panel) requestReload(reason string) {
	select {
	case p.reloadCh <- reason:
	default:
	}
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

func (p *Panel) start() (err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	cfg := p.cfg
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
	if pc := machinePanel(cfg); pc != nil {
		ctx, cancel := context.WithCancel(context.Background())
		p.machineCancel = cancel
		machineCtx = ctx
		c, version, derr := p.discoverMachineNodes(pc, certs, &nodes)
		if derr != nil {
			log.Warnf("machine nodes: %v (static nodes keep running; retrying)", derr)
			p.scheduleMachineRetry(ctx, "machine node discovery failed")
		} else {
			machine, machineVersion = c, version
		}
	}
	// A start that fails after this point must not leave the machine tasks
	// behind: the next start would otherwise start a second set.
	defer func() {
		if err != nil {
			p.stopMachineLocked()
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

	cr, err := core.New(coreOptions(cfg, ns))
	if err != nil {
		return err
	}
	if err := cr.Start(); err != nil {
		cr.Close()
		return fmt.Errorf("start xray: %w", err)
	}
	for _, n := range nodes {
		if err := n.Start(cr); err != nil {
			log.WithField("node", n.Tag()).Errorf("start: %v", err)
		}
	}
	// The agent runs on top of the same Xray instance. A boot failure is
	// logged, not fatal: the panel nodes keep serving.
	if cfg.Agent != nil && cfg.Agent.Enabled {
		rt, err := bootstrap.Boot(bootstrap.Options{
			StateDir:         cfg.Agent.StateDir,
			KernelsDir:       cfg.Agent.KernelsDir,
			ManifestPath:     cfg.Agent.ManifestPath,
			ManifestKeysPath: cfg.Agent.ManifestKeysPath,
			Policy:           cfg.Agent.PolicySpec(),
			Log:              log.StandardLogger(),
			// After a restart the persisted last good state comes back before
			// (and without) the panel, so a panel that is down never costs
			// forwarding.
			Resume: true,
		}, cr)
		if err != nil {
			log.Errorf("agent: boot: %v", err)
		} else {
			p.agent = rt
			if cfg.Agent.DesiredPath != "" {
				p.applyAgentDesiredLocked(cfg.Agent.DesiredPath, rt)
			}
			p.startRemoteLocked(cfg.Agent, rt)
		}
	}
	// Watch the machine's node list so a node added or removed on the panel is
	// picked up without a config change.
	if machine != nil {
		p.startMachineWatchLocked(machineCtx, machine, machineVersion)
	}
	p.core, p.nodes, p.running = cr, nodes, true
	log.Infof("W1nCray started with %d node(s)", len(nodes))
	return nil
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
	for _, id := range pc.nodeControllerIDs() {
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

// startMachineWatchLocked starts the node-list watcher of the running instance.
// The caller must hold p.mu.
func (p *Panel) startMachineWatchLocked(ctx context.Context, c *xboard.Client, version string) {
	p.machineWG.Add(1)
	go func() {
		defer p.machineWG.Done()
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
// with the instance context or after it fired. The caller must hold p.mu.
func (p *Panel) scheduleMachineRetry(ctx context.Context, reason string) {
	p.machineWG.Add(1)
	go func() {
		defer p.machineWG.Done()
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
	p.machineWG.Wait()
	p.machineCancel = nil
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

func (p *Panel) shutdown() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.running {
		return
	}
	// Stop the machine-node tasks first: no discovery or watch may race the
	// teardown below. They never take p.mu, so waiting here cannot deadlock.
	p.stopMachineLocked()
	// Stop the panel link first: no apply may race the teardown below.
	if p.remoteStop != nil {
		p.remoteStop()
		p.remoteStop = nil
	}
	var wg sync.WaitGroup
	for _, n := range p.nodes {
		wg.Add(1)
		go func(n *node.Controller) {
			defer wg.Done()
			n.Close()
		}(n)
	}
	wg.Wait()
	// The agent's kernels may live in the Xray instance, so stop them before
	// closing it.
	if p.agent != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := p.agent.Shutdown(ctx); err != nil {
			log.Errorf("agent: shutdown: %v", err)
		}
		cancel()
		p.agent = nil
	}
	// Closing the instance does not end accepted connections; abort the
	// tracked ones (none unless a tag prefix is watched) so that a reload does
	// not leave sessions of the old instance behind.
	if n := p.core.Conns().KillAll(); n > 0 {
		log.Infof("aborted %d tracked connection(s)", n)
	}
	if err := p.core.Close(); err != nil {
		log.Errorf("close xray: %v", err)
	}
	p.nodes, p.core, p.running = nil, nil, false
}

// Close stops everything.
func (p *Panel) Close() {
	close(p.stop)
	<-p.done
	p.shutdown()
}

// reload rebuilds everything, re-reading the config file. On a config error
// the previous config keeps being used.
func (p *Panel) reload(reason string) {
	log.Infof("reloading: %s", reason)
	cfg, err := LoadConfig(p.path)
	if err != nil {
		log.Errorf("reload aborted, keeping the running config: %v", err)
		return
	}
	p.shutdown()
	p.mu.Lock()
	p.cfg = cfg
	p.mu.Unlock()
	for {
		err := p.start()
		if err == nil {
			return
		}
		log.Errorf("restart failed: %v; retrying in 10s", err)
		select {
		case <-p.stop:
			return
		case <-time.After(10 * time.Second):
		}
	}
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
	var desiredDebounce <-chan time.Time
	for {
		select {
		case <-p.stop:
			return
		case reason := <-p.reloadCh:
			p.reload(reason)
		case ev := <-events:
			abs, _ := filepath.Abs(ev.Name)
			if desiredAbs != "" && abs == desiredAbs {
				if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
					desiredDebounce = time.After(500 * time.Millisecond)
				}
			} else if watched[abs] && ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
				debounce = time.After(2 * time.Second)
			}
		case err := <-errs:
			log.Warnf("config watcher: %v", err)
		case <-desiredDebounce:
			desiredDebounce = nil
			p.applyAgentDesired()
		case <-debounce:
			debounce = nil
			p.reload("config file changed")
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
