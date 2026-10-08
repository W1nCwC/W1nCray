package xraynode

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
	xcore "github.com/xtls/xray-core/core"

	"github.com/W1nCwC/W1nCray/agent/xrayapi"
	"github.com/W1nCwC/W1nCray/api/xboard"
	"github.com/W1nCwC/W1nCray/common/cert"
	"github.com/W1nCwC/W1nCray/config"
	"github.com/W1nCwC/W1nCray/core"
	"github.com/W1nCwC/W1nCray/node"
)

// Version is the version of the W1nCray-xray program. The release build sets it
// with -ldflags "-X github.com/W1nCwC/W1nCray/xraynode.Version=..."; it is also
// what the status interface and the version_cmd of the signed kernel manifest
// report.
var Version = "0.6.0"

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

// reloadRequest is one queued rebuild.
type reloadRequest struct {
	reason string
	files  []string
}

// Service owns the Xray instance and the node controllers.
type Service struct {
	path string

	mu      sync.Mutex
	cfg     *Config
	core    *core.Core
	nodes   []*node.Controller
	running bool

	// fingerprint is the content hash of the watched files at the last
	// (re)build. A watcher event whose files hash the same is skipped: a
	// managed-file write may be followed by its own explicit reload, and the
	// watcher would otherwise rebuild a second time two seconds later.
	fingerprint string

	// coreOpts is the core options of the running xray instance, published by
	// startXrayLocked for the staged-file validator (read without s.mu).
	coreOpts atomic.Pointer[core.Options]

	// machineCancel ends the machine-node tasks of the running instance (nil
	// when machine mode is off or nothing runs); machineWG joins them so
	// shutdown never returns before they stopped.
	machineCancel context.CancelFunc
	machineWG     *sync.WaitGroup
	// machineClient and machineVersion are the machine-node watcher state of
	// the running instance: the client the agent's nodes hint reuses, and the
	// node-list version the instance was built from. They are guarded by s.mu
	// and nil/"" when machine mode is off or nothing runs.
	machineClient  *xboard.Client
	machineVersion string
	// machineSyncMu serialises the hint-driven node fetches, so two hints
	// arriving together cannot both report the same change as theirs.
	machineSyncMu sync.Mutex

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

	startedAt    time.Time
	lastReloadAt atomic.Int64
	lastError    atomic.Pointer[string]

	// statusListener is the local status endpoint (Unix socket, or a loopback
	// TCP listener on Windows); statusAddr is what it is reachable at.
	statusListener interface{ Close() error }
	statusAddr     string
}

// New creates a service for the config file at path.
func New(path string, cfg *Config) *Service {
	return &Service{
		path:     path,
		cfg:      cfg,
		reloadCh: make(chan struct{}, 1),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// requestReload schedules a rebuild without blocking the caller. It is the node
// controller callback (node.Options.Reload).
func (s *Service) requestReload(reason string) {
	s.enqueueReload(reloadRequest{reason: reason})
}

// requestReloadFiles schedules a rebuild triggered by a change of the named
// watched files.
func (s *Service) requestReloadFiles(reason string, files []string) {
	s.enqueueReload(reloadRequest{reason: reason, files: files})
}

// enqueueReload queues a rebuild. A request that arrives while one is pending
// is merged into it; a request that arrives while a rebuild is running is
// remembered and served by the running reload's loop. The channel is only a
// wake-up signal.
func (s *Service) enqueueReload(req reloadRequest) {
	s.reloadMu.Lock()
	if s.reloadPending == nil {
		r := req
		s.reloadPending = &r
	} else if s.reloadPending.files != nil && req.files != nil {
		s.reloadPending.files = mergeFiles(s.reloadPending.files, req.files)
	} else {
		s.reloadPending.files = nil
	}
	wake := !s.reloadRunning
	s.reloadMu.Unlock()
	if wake {
		select {
		case s.reloadCh <- struct{}{}:
		default:
		}
	}
}

// takeReload returns the next pending request and marks a rebuild as running.
// ok is false for a spurious wake-up (nothing pending).
func (s *Service) takeReload() (reloadRequest, bool) {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	if s.reloadPending == nil {
		return reloadRequest{}, false
	}
	req := *s.reloadPending
	s.reloadPending = nil
	s.reloadRunning = true
	return req, true
}

// finishReload releases the "running" mark.
func (s *Service) finishReload() {
	s.reloadMu.Lock()
	s.reloadRunning = false
	s.reloadMu.Unlock()
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

// Reload rebuilds the Xray instance after the managed files were replaced. It
// is serialised with every other reload and it validates the config *before* it
// shuts anything down: a config.yml that does not load returns an error and
// leaves the running instance untouched.
//
// The rebuild itself is asynchronous: rebuildXray retries a failed start
// forever, so waiting for it here would either destroy the caller or never
// return. Callers that need the result poll Status (the fingerprint and
// running flag) instead.
func (s *Service) Reload(ctx context.Context, reason string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := LoadConfig(s.path); err != nil {
		return fmt.Errorf("reload refused, the running config is kept: %w", err)
	}
	s.requestReload("agent: " + reason)
	return nil
}

// Start builds and starts everything, then watches for reload requests.
func (s *Service) Start() error {
	s.startedAt = time.Now()
	if err := s.start(); err != nil {
		return err
	}
	fp := filesFingerprint(s.watchedFiles())
	s.mu.Lock()
	s.fingerprint = fp
	s.mu.Unlock()
	ready := make(chan struct{})
	go s.watch(ready)
	// Returning before the directory watches exist would lose a config change
	// made right after Start (the watcher registers asynchronously).
	<-ready
	return nil
}

func (s *Service) start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.startLocked()
}

// startLocked starts the xray core with its node controllers. The caller must
// hold s.mu.
func (s *Service) startLocked() error {
	if err := s.startXrayLocked(s.cfg); err != nil {
		return err
	}
	s.running = true
	log.Infof("W1nCray-xray started with %d node(s)", len(s.nodes))
	return nil
}

// startXrayLocked builds and starts an xray core with its node controllers and
// machine-node tasks from cfg. On success the service's core, nodes and machine
// task fields are replaced. The caller must hold s.mu.
func (s *Service) startXrayLocked(cfg *Config) (err error) {
	setLogLevel(cfg.LogConfig.Level)

	certs := cert.NewManager(certDir(s.path, cfg))

	nodes := make([]*node.Controller, 0, len(cfg.NodesConfig))
	for _, nc := range cfg.NodesConfig {
		nodes = append(nodes, node.New(node.Options{
			API:    nc.ApiConfig,
			Config: nc.ControllerConfig,
			Certs:  certs,
			Reload: s.requestReload,
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
		c, version, derr := s.discoverMachineNodes(pc, certs, &nodes)
		if derr != nil {
			log.Warnf("machine nodes: %v (static nodes keep running; retrying)", derr)
			s.scheduleMachineRetry(ctx, &machineWG, "machine node discovery failed")
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
		s.startMachineWatch(machineCtx, &machineWG, machine, machineVersion)
	}
	s.machineClient, s.machineVersion = machine, machineVersion
	s.core, s.nodes = cr, nodes
	s.publishCoreOptionsLocked()
	s.machineCancel, s.machineWG = machineCancel, &machineWG
	return nil
}

// stopXrayLocked stops the machine tasks, the node controllers and the xray
// core. The caller must hold s.mu.
func (s *Service) stopXrayLocked() {
	// Stop the machine-node tasks first: no discovery or watch may race the
	// teardown below. They never take s.mu, so waiting here cannot deadlock.
	s.stopMachineLocked()
	var wg sync.WaitGroup
	for _, n := range s.nodes {
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
	if s.core != nil {
		if n := s.core.Conns().KillAll(); n > 0 {
			log.Infof("aborted %d tracked connection(s)", n)
		}
		if err := s.core.Close(); err != nil {
			log.Errorf("close xray: %v", err)
		}
	}
	s.nodes, s.core, s.running = nil, nil, false
}

// discoverMachineNodes asks the panel which nodes this machine runs and appends
// a controller for each of them to nodes. It returns the machine client (for
// the version watch) and the version of the assignment. The token is passed to
// the client only; it never reaches a log or an error message.
func (s *Service) discoverMachineNodes(pc *AgentPanelConfig, certs *cert.Manager, nodes *[]*node.Controller) (*xboard.Client, string, error) {
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
			Reload: s.requestReload,
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
// controllers share the top-level struct.
func machineControllerConfig(t *node.Config) *node.Config {
	return controllerConfigWithDefaults(t)
}

// startMachineWatch starts the node-list watcher of a new instance. wg is the
// wait group of the instance the watcher belongs to.
func (s *Service) startMachineWatch(ctx context.Context, wg *sync.WaitGroup, c *xboard.Client, version string) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.machineWatch(ctx, c, version)
	}()
}

// machineWatch polls the machine's node list and asks for a reload when it
// changes. It returns when the instance is shut down (ctx) or after it
// requested a reload, which starts a fresh watcher.
func (s *Service) machineWatch(ctx context.Context, c *xboard.Client, version string) {
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
			s.requestReload("machine nodes changed")
			return
		}
	}
}

// SyncMachineNodes asks the panel for this machine's node list right now and
// requests a reload when the list changed since the running instance was built.
// It is the kernel side of the agent's hint{what:"nodes"}: the same "fetch the
// version, reload only when it differs" rule machineWatch applies every 60 s,
// just on demand. An idle hint (same version) returns changed=false and does
// not reload; a configuration without machine mode has no list to refresh and
// also returns changed=false.
//
// version is the version the panel reported, for the caller's log. It is empty
// when there is nothing to refresh.
//
// The version is recorded before the (asynchronous) reload so that a second
// hint arriving while the rebuild runs is idle instead of queueing another one;
// startXrayLocked republishes the authoritative version when it discovers the
// list again. Calls are serialised, so concurrent hints never both report the
// same change.
func (s *Service) SyncMachineNodes(ctx context.Context) (changed bool, version string, err error) {
	s.machineSyncMu.Lock()
	defer s.machineSyncMu.Unlock()

	s.mu.Lock()
	c, current := s.machineClient, s.machineVersion
	s.mu.Unlock()
	if c == nil {
		// Machine mode is off, or the instance is being rebuilt and has no
		// client right now: there is nothing to refresh.
		return false, "", nil
	}
	reqCtx, cancel := context.WithTimeout(ctx, machineRequestTimeout)
	defer cancel()
	_, next, err := c.ListMachineNodes(reqCtx)
	if err != nil {
		return false, "", err
	}
	if next == current {
		return false, next, nil
	}
	s.mu.Lock()
	s.machineVersion = next
	s.mu.Unlock()
	log.Infof("machine node list changed (version %s)", next)
	s.requestReload("machine nodes changed")
	return true, next, nil
}

// scheduleMachineRetry asks for a reload after machineRetryDelay, so a failed
// discovery is retried without blocking the running nodes. The goroutine ends
// with the instance context or after it fired. wg is the wait group of the
// instance the retry belongs to.
func (s *Service) scheduleMachineRetry(ctx context.Context, wg *sync.WaitGroup, reason string) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTimer(machineRetryDelay)
		defer t.Stop()
		select {
		case <-ctx.Done():
		case <-t.C:
			s.requestReload(reason)
		}
	}()
}

// stopMachineLocked cancels and joins the machine-node tasks. The caller must
// hold s.mu.
func (s *Service) stopMachineLocked() {
	// The hint route must not keep the client of an instance that is being torn
	// down: drop it before the tasks are joined, so a hint that arrives during
	// a rebuild reports "nothing to refresh" instead of fetching through a
	// client of the previous instance.
	s.machineClient, s.machineVersion = nil, ""
	if s.machineCancel == nil {
		return
	}
	s.machineCancel()
	if s.machineWG != nil {
		s.machineWG.Wait()
	}
	s.machineCancel, s.machineWG = nil, nil
}

// shutdown stops everything. It is the process-exit path (Close).
func (s *Service) shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return
	}
	s.stopXrayLocked()
}

// Close stops everything.
func (s *Service) Close() {
	close(s.stop)
	<-s.done
	s.shutdown()
}

// reload serves queued rebuild requests. It keeps taking requests until none is
// pending, so a request that arrived during a long rebuild is served next
// instead of being lost.
func (s *Service) reload() {
	for {
		req, ok := s.takeReload()
		if !ok {
			return
		}
		s.applyReload(req)
		s.finishReload()
	}
}

// applyReload carries out one rebuild. Every watched file (and every request
// that did not come from the watcher) rebuilds the xray core and its node
// controllers.
func (s *Service) applyReload(req reloadRequest) {
	reason := req.reason
	if reason == "" {
		reason = "config file changed"
	}
	log.Infof("reloading: %s", reason)
	cfg, err := LoadConfig(s.path)
	if err != nil {
		log.Errorf("reload aborted, keeping the running config: %v", err)
		s.setLastError(fmt.Errorf("reload aborted: %w", err))
		return
	}

	fp := filesFingerprint(s.watchedFiles())
	s.mu.Lock()
	unchanged := len(req.files) > 0 && fp == s.fingerprint
	s.mu.Unlock()
	if unchanged {
		// A watcher event for content the running instance was already built
		// from (a touch, or a managed-file write that asked for its own
		// reload).
		log.Infof("reload: the watched files are unchanged since the last rebuild; nothing to do")
		return
	}
	defer func() {
		s.mu.Lock()
		s.fingerprint = fp
		s.mu.Unlock()
	}()

	s.rebuildXray(cfg)
}

// rebuildXray replaces the xray core and its node controllers with ones built
// from cfg.
func (s *Service) rebuildXray(cfg *Config) {
	s.mu.Lock()
	defer s.mu.Unlock()

	select {
	case <-s.stop:
		return
	default:
	}

	if !s.running {
		// Nothing is running (a previous start failed, or Close raced the
		// reload): start from scratch with the new configuration.
		s.cfg = cfg
		if err := s.startLocked(); err != nil {
			log.Errorf("restart failed: %v", err)
			s.setLastError(err)
		} else {
			s.clearLastError()
			s.lastReloadAt.Store(time.Now().Unix())
		}
		return
	}

	s.stopXrayLocked()
	s.cfg = cfg
	for {
		if err := s.startXrayLocked(cfg); err == nil {
			break
		} else {
			log.Errorf("xray restart failed: %v; retrying in 10s", err)
			s.setLastError(err)
		}
		// Do not hold s.mu while waiting: the previous implementation
		// released it between attempts too, and Close (and everything else
		// that takes s.mu) must not stall for as long as xray keeps failing.
		s.mu.Unlock()
		var stopped bool
		select {
		case <-s.stop:
			stopped = true
		case <-time.After(10 * time.Second):
		}
		s.mu.Lock()
		if stopped {
			return
		}
	}
	s.running = true
	s.clearLastError()
	s.lastReloadAt.Store(time.Now().Unix())
}

// watch handles reload requests from nodes and changes of the config files.
func (s *Service) watch(ready chan<- struct{}) {
	defer close(s.done)
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
		for _, f := range s.watchedFiles() {
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

	var debounce <-chan time.Time
	var debounceFiles []string
	for {
		select {
		case <-s.stop:
			return
		case <-s.reloadCh:
			// requestReload already queued the request; reload serves it and
			// any request that arrived meanwhile.
			s.reload()
		case ev := <-events:
			abs, _ := filepath.Abs(ev.Name)
			if watched[abs] && ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
				// Remember which file changed for the dedup check.
				debounceFiles = mergeFiles(debounceFiles, []string{abs})
				if debounce == nil {
					debounce = time.After(2 * time.Second)
				}
			}
		case err := <-errs:
			log.Warnf("config watcher: %v", err)
		case <-debounce:
			debounce = nil
			files := debounceFiles
			debounceFiles = nil
			// Through requestReloadFiles, not straight into reload: a rebuild
			// may be running (a long reload, or Reload), and two concurrent
			// rebuilds would race over s.core and s.nodes.
			s.requestReloadFiles("config file changed", files)
		}
	}
}

// WatchedFiles returns the files whose changes trigger a rebuild: config.yml,
// the four JSON configuration files and every node rule list.
func (s *Service) WatchedFiles() []string { return s.watchedFiles() }

func (s *Service) watchedFiles() []string {
	s.mu.Lock()
	cfg, path := s.cfg, s.path
	s.mu.Unlock()
	return cfg.WatchedFiles(path)
}

// Fingerprint returns the content fingerprint of the watched files at the last
// successful build.
func (s *Service) Fingerprint() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fingerprint
}

// Status returns the status document served on the local endpoint.
func (s *Service) Status() xrayapi.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := xrayapi.Status{
		Version:           Version,
		XrayCore:          xcore.Version(),
		StartedAt:         s.startedAt.Unix(),
		Running:           s.running,
		Nodes:             make([]xrayapi.NodeStatus, 0, len(s.nodes)),
		ConfigFingerprint: s.fingerprint,
		LastReloadAt:      s.lastReloadAt.Load(),
	}
	if p := s.lastError.Load(); p != nil {
		st.LastError = *p
	}
	for _, n := range s.nodes {
		st.Nodes = append(st.Nodes, xrayapi.NodeStatus{
			Tag:    n.Tag(),
			ID:     n.ID(),
			Type:   n.Type(),
			Users:  n.Users(),
			Online: n.OnlineIPs(),
			Error:  n.LastError(),
		})
	}
	return st
}

// setLastError records the last reload/start error for the status document.
func (s *Service) setLastError(err error) {
	if err == nil {
		return
	}
	msg := err.Error()
	s.lastError.Store(&msg)
}

// clearLastError drops the recorded error after a successful rebuild.
func (s *Service) clearLastError() { s.lastError.Store(nil) }

// filesFingerprint hashes the names and contents of files (a missing or
// unreadable file counts as its own state). It is config.Fingerprint, which the
// agent also computes after a managed-file apply.
func filesFingerprint(files []string) string { return config.Fingerprint(files) }

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
