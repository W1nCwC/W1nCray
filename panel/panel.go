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
	"github.com/W1nCwC/W1nCray/common/cert"
	"github.com/W1nCwC/W1nCray/core"
	"github.com/W1nCwC/W1nCray/node"
)

// Panel owns the Xray instance and the node controllers.
type Panel struct {
	path string

	mu      sync.Mutex
	cfg     *Config
	core    *core.Core
	nodes   []*node.Controller
	agent   *bootstrap.Runtime
	running bool

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
	go p.watch()
	return nil
}

func (p *Panel) start() error {
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
		}, cr)
		if err != nil {
			log.Errorf("agent: boot: %v", err)
		} else {
			p.agent = rt
			if cfg.Agent.DesiredPath != "" {
				p.applyAgentDesiredLocked(cfg.Agent.DesiredPath, rt)
			}
		}
	}
	p.core, p.nodes, p.running = cr, nodes, true
	log.Infof("W1nCray started with %d node(s)", len(nodes))
	return nil
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

func (p *Panel) shutdown() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.running {
		return
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
func (p *Panel) watch() {
	defer close(p.done)
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
