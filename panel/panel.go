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

	"w1ncray/common/cert"
	"w1ncray/core"
	"w1ncray/node"
)

// Panel owns the Xray instance and the node controllers.
type Panel struct {
	path string

	mu      sync.Mutex
	cfg     *Config
	core    *core.Core
	nodes   []*node.Controller
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

	certDir := cfg.CertDir
	if certDir == "" {
		certDir = filepath.Join(filepath.Dir(p.path), "cert")
	}
	certs := cert.NewManager(certDir)

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

	cc := cfg.ConnectionConfig
	cr, err := core.New(core.Options{
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
	})
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
	p.core, p.nodes, p.running = cr, nodes, true
	log.Infof("W1nCray started with %d node(s)", len(nodes))
	return nil
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

	var debounce <-chan time.Time
	for {
		select {
		case <-p.stop:
			return
		case reason := <-p.reloadCh:
			p.reload(reason)
		case ev := <-events:
			abs, _ := filepath.Abs(ev.Name)
			if watched[abs] && ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
				debounce = time.After(2 * time.Second)
			}
		case err := <-errs:
			log.Warnf("config watcher: %v", err)
		case <-debounce:
			debounce = nil
			p.reload("config file changed")
		}
	}
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
	return files
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
