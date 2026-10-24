// Package prismnode drives the machine's Prism kernel (handoff 69): it fetches
// the kernel document from the panel, hands it to the kernel over its local
// control API, and keeps the users and the traffic of every node in step with
// the panel.
//
// The agent translates nothing. The panel builds the document; the kernel
// builds it with its own builder before it replaces the running one, and keeps
// the previous config when it cannot. Users travel over the control API only,
// so a user change never restarts a listener.
package prismnode

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/prismapi"
	"github.com/W1nCwC/W1nCray/api/xboard"
)

// Panel is what the controller needs of the panel.
type Panel interface {
	// Prism returns the kernel document; etag is the version already held.
	// ErrNotModified and ErrNoPrismNodes are the expected answers.
	Prism(ctx context.Context, etag string) (*xboard.Prism, error)
	// Node returns the API of one node of the machine.
	Node(id int, nodeType string) NodeAPI
}

// NodeAPI is the node API of the panel (machine token + node_id).
type NodeAPI interface {
	GetNodeConfig(ctx context.Context) (*xboard.NodeConfig, error)
	GetUsers(ctx context.Context) ([]xboard.User, error)
	PushTraffic(ctx context.Context, traffic map[int][2]int64) error
	PushAlive(ctx context.Context, alive map[int][]string) error
	GetAliveList(ctx context.Context) (map[int]int, error)
	PushStatus(ctx context.Context, s *xboard.Status) error
}

// Kernel is the control API of the kernel (*prismapi.Client).
type Kernel interface {
	Status(ctx context.Context) (prismapi.Status, error)
	Apply(ctx context.Context, hash string, config json.RawMessage) (prismapi.ApplyResult, error)
	SetUsers(ctx context.Context, tag string, seq int64, users []prismapi.User) (prismapi.UsersResult, error)
	SetDevices(ctx context.Context, tag string, alive map[int]int) error
	Stats(ctx context.Context, tag string) (prismapi.Stats, error)
	Commit(ctx context.Context, tag string, snapshot uint64, bootID string) error
}

// Service makes the kernel process exist and run.
type Service interface {
	// Ensure installs the service definition and starts the kernel when it
	// does not run yet. It returns an error when the kernel is not installed.
	Ensure(ctx context.Context) error
	// Stop stops the kernel service (the installation stays).
	Stop(ctx context.Context) error
}

// Options configures a Controller. Panel, Kernel and Service are required.
type Options struct {
	Panel   Panel
	Kernel  Kernel
	Service Service
	Log     driver.Logger

	// PollEvery is how often the document is re-fetched (default 60 s).
	PollEvery time.Duration
	// WatchEvery is how often the kernel is health-checked (default 15 s).
	WatchEvery time.Duration
	// IdleStopAfter is how long the machine may have no Prism node before the
	// kernel service is stopped (default 10 min).
	IdleStopAfter time.Duration
	// DefaultInterval is the pull/push interval of a node whose config does
	// not name one (default 60 s); MinInterval is the lower bound (default 5 s).
	DefaultInterval time.Duration
	MinInterval     time.Duration
	// Sample reads the machine load for the status report (nil: no report).
	Sample func() (*xboard.Status, error)
	// Now is the clock (tests).
	Now func() time.Time
}

// Status is what the telemetry shows about the Prism kernel.
type Status struct {
	// Nodes is the number of nodes the kernel serves.
	Nodes int
	// Version is the document version the kernel runs ("" when none).
	Version string
	// Rejected is the document version the kernel refused.
	Rejected string
	// Error is why the document is not in use ("" when it is).
	Error string
	// Kernel is the kernel's own view; zero when it cannot be reached.
	Kernel prismapi.Status
	// Reachable says whether the kernel answered the last health check.
	Reachable bool
}

// Controller is safe for concurrent use.
type Controller struct {
	o   Options
	log driver.Logger

	mu          sync.Mutex
	version     string // the panel document version held (for If-None-Match)
	applied     string // the version the kernel runs
	rejected    string // the version the kernel refused
	lastErr     string
	noNodesAt   time.Time // since when the panel reports no Prism node
	workers     map[int]*worker
	boot        string // boot id of the kernel the last time it was seen
	generation  uint64 // bumped when the users of every node must be re-sent
	lastStatus  prismapi.Status
	reachable   bool
	seq         int64
	stopped     bool
	parent      context.Context
	wg          sync.WaitGroup
	syncRunning bool

	hint chan struct{}
}

// New builds a Controller.
func New(o Options) (*Controller, error) {
	if o.Panel == nil || o.Kernel == nil || o.Service == nil {
		return nil, errors.New("prismnode: a panel, a kernel and a service are required")
	}
	if o.PollEvery <= 0 {
		o.PollEvery = 60 * time.Second
	}
	if o.WatchEvery <= 0 {
		o.WatchEvery = 15 * time.Second
	}
	if o.IdleStopAfter <= 0 {
		o.IdleStopAfter = 10 * time.Minute
	}
	if o.DefaultInterval <= 0 {
		o.DefaultInterval = 60 * time.Second
	}
	if o.MinInterval <= 0 {
		o.MinInterval = 5 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	log := o.Log
	if log == nil {
		log = nopLog{}
	}
	return &Controller{o: o, log: log, workers: map[int]*worker{}, hint: make(chan struct{}, 1)}, nil
}

// Hint asks for an immediate re-fetch of the document (the panel pushed a
// nodes hint). It never blocks.
func (c *Controller) Hint() {
	select {
	case c.hint <- struct{}{}:
	default:
	}
}

// Run blocks until ctx ends. It fetches the document at once, then on every
// poll, hint and kernel restart.
func (c *Controller) Run(ctx context.Context) {
	c.mu.Lock()
	c.parent = ctx
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.stopped = true
		for _, w := range c.workers {
			w.cancel()
		}
		c.mu.Unlock()
		c.wg.Wait()
	}()

	c.Sync(ctx)
	poll := time.NewTicker(c.o.PollEvery)
	defer poll.Stop()
	watch := time.NewTicker(c.o.WatchEvery)
	defer watch.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-poll.C:
			c.Sync(ctx)
		case <-c.hint:
			c.Sync(ctx)
		case <-watch.C:
			c.watch(ctx)
		}
	}
}

// Status reports the controller's view for the telemetry.
func (c *Controller) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Status{
		Nodes:     len(c.workers),
		Version:   c.applied,
		Rejected:  c.rejected,
		Error:     c.lastErr,
		Kernel:    c.lastStatus,
		Reachable: c.reachable,
	}
}

// Sync fetches the document and brings the kernel and the node workers in step
// with it.
func (c *Controller) Sync(ctx context.Context) {
	c.mu.Lock()
	if c.syncRunning {
		c.mu.Unlock()
		return
	}
	c.syncRunning = true
	etag := c.version
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.syncRunning = false
		c.mu.Unlock()
	}()

	doc, err := c.o.Panel.Prism(ctx, etag)
	switch {
	case errors.Is(err, xboard.ErrNotModified):
		// The document did not change; a restarted kernel is handled by watch.
		c.mu.Lock()
		c.noNodesAt = time.Time{}
		c.mu.Unlock()
		return
	case errors.Is(err, xboard.ErrNoPrismNodes):
		c.noNodes(ctx)
		return
	case err != nil:
		var se *xboard.StatusError
		if errors.As(err, &se) && se.Code == 422 {
			// The panel could not translate the nodes and the runtime profile:
			// the kernel keeps what it runs, the reason is shown.
			c.fail(fmt.Sprintf("panel refused to build the document: %s", se.Body), "")
			return
		}
		c.log.Warnf("prismnode: 获取内核文档失败: %v", err)
		return
	}
	c.mu.Lock()
	c.noNodesAt = time.Time{}
	c.version = doc.Version
	c.mu.Unlock()
	c.apply(ctx, doc)
}

func (c *Controller) apply(ctx context.Context, doc *xboard.Prism) {
	c.mu.Lock()
	rejected := c.rejected == doc.Version
	c.mu.Unlock()
	if rejected {
		return // the kernel already refused this exact document
	}
	if err := c.o.Service.Ensure(ctx); err != nil {
		c.fail("prism kernel is not running: "+err.Error(), "")
		c.mu.Lock()
		c.version = "" // fetch again next time, the kernel was the problem
		c.mu.Unlock()
		return
	}
	st, err := c.o.Kernel.Status(ctx)
	if err != nil {
		c.fail("prism kernel is not reachable: "+err.Error(), "")
		c.mu.Lock()
		c.version = ""
		c.mu.Unlock()
		return
	}
	c.observe(st)
	if st.ConfigHash == nil || *st.ConfigHash != doc.Version {
		if _, err := c.o.Kernel.Apply(ctx, doc.Version, doc.Config); err != nil {
			var pe *prismapi.Error
			if errors.As(err, &pe) && pe.IsInvalid() {
				c.log.Errorf("prismnode: 内核拒绝了文档 %s: %s", short(doc.Version), pe.Message)
				c.fail(pe.Message, doc.Version)
				return
			}
			c.fail("prism kernel could not start the document: "+err.Error(), "")
			c.mu.Lock()
			c.version = "" // retry on the next poll
			c.mu.Unlock()
			return
		}
		c.log.Infof("prismnode: 内核已应用文档 %s（%d 个节点）", short(doc.Version), len(doc.Nodes))
	}
	c.mu.Lock()
	c.applied, c.rejected, c.lastErr = doc.Version, "", ""
	c.generation++
	c.mu.Unlock()
	c.reconcile(ctx, doc.Nodes)
}

// noNodes handles a machine without Prism nodes: the kernel gets an empty
// config at once and the service is stopped after IdleStopAfter.
func (c *Controller) noNodes(ctx context.Context) {
	c.mu.Lock()
	if c.noNodesAt.IsZero() {
		c.noNodesAt = c.o.Now()
	}
	since := c.noNodesAt
	hadWorkers := len(c.workers) > 0
	c.mu.Unlock()
	if hadWorkers {
		c.reconcile(ctx, nil)
	}
	c.mu.Lock()
	c.version, c.applied, c.rejected, c.lastErr = "", "", "", ""
	c.mu.Unlock()
	if c.o.Now().Sub(since) >= c.o.IdleStopAfter {
		if st, err := c.o.Kernel.Status(ctx); err == nil {
			c.observe(st)
			if st.State != "" {
				_ = c.o.Service.Stop(ctx)
			}
		}
	}
}

func (c *Controller) fail(msg, rejected string) {
	c.mu.Lock()
	c.lastErr = msg
	if rejected != "" {
		c.rejected = rejected
	}
	c.mu.Unlock()
	c.log.Warnf("prismnode: %s", msg)
}

// observe records the kernel's status and notices a restart: a new boot id
// means every user table is gone from memory and must be sent again.
func (c *Controller) observe(st prismapi.Status) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastStatus, c.reachable = st, true
	if c.boot != "" && c.boot != st.BootID {
		c.generation++
	}
	c.boot = st.BootID
}

// watch health-checks the kernel; a restarted kernel (new boot id, or one that
// lost the config) is brought back to the applied document.
func (c *Controller) watch(ctx context.Context) {
	c.mu.Lock()
	want := c.applied
	idle := len(c.workers) == 0 && want == ""
	c.mu.Unlock()
	if idle {
		return
	}
	// Ensure is idempotent: it restarts the kernel when a new version was
	// installed since, and starts it when it died.
	if serr := c.o.Service.Ensure(ctx); serr != nil {
		c.log.Warnf("prismnode: 确保内核运行失败: %v", serr)
	}
	st, err := c.o.Kernel.Status(ctx)
	if err != nil {
		c.mu.Lock()
		c.reachable = false
		c.version = "" // fetch again: the kernel may have restarted empty
		c.mu.Unlock()
		return
	}
	c.observe(st)
	if want != "" && (st.ConfigHash == nil || *st.ConfigHash != want) {
		c.mu.Lock()
		c.version = "" // the next Sync applies the document again
		c.mu.Unlock()
		c.Sync(ctx)
	}
}

func short(v string) string {
	if len(v) > 12 {
		return v[:12]
	}
	return v
}

type nopLog struct{}

func (nopLog) Debugf(string, ...any) {}
func (nopLog) Infof(string, ...any)  {}
func (nopLog) Warnf(string, ...any)  {}
func (nopLog) Errorf(string, ...any) {}

// nodeIDs returns the sorted node ids of the running workers (tests).
func (c *Controller) nodeIDs() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	ids := make([]int, 0, len(c.workers))
	for id := range c.workers {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
}
