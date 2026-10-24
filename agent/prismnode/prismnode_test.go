package prismnode

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/prismapi"
	"github.com/W1nCwC/W1nCray/api/xboard"
)

// ---- fakes ----------------------------------------------------------------

type fakePanel struct {
	mu    sync.Mutex
	doc   *xboard.Prism
	err   error
	gets  int
	etags []string
	nodes map[int]*fakeNode
}

func (p *fakePanel) Prism(_ context.Context, etag string) (*xboard.Prism, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gets++
	p.etags = append(p.etags, etag)
	if p.err != nil {
		return nil, p.err
	}
	if p.doc == nil {
		return nil, xboard.ErrNoPrismNodes
	}
	if etag == p.doc.Version {
		return nil, xboard.ErrNotModified
	}
	d := *p.doc
	return &d, nil
}

func (p *fakePanel) Node(id int, _ string) NodeAPI {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.nodes == nil {
		p.nodes = map[int]*fakeNode{}
	}
	n := p.nodes[id]
	if n == nil {
		n = &fakeNode{}
		p.nodes[id] = n
	}
	return n
}

func (p *fakePanel) node(id int) *fakeNode {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.nodes[id]
}

type fakeNode struct {
	mu        sync.Mutex
	users     []xboard.User
	usersErr  error
	pushed    []map[int][2]int64
	pushErr   error
	alive     []map[int][]string
	aliveList map[int]int
	statuses  int
	served    int
}

func (n *fakeNode) GetNodeConfig(context.Context) (*xboard.NodeConfig, error) {
	return &xboard.NodeConfig{BaseConfig: &xboard.BaseConfig{PushInterval: 1, PullInterval: 1}}, nil
}

func (n *fakeNode) GetUsers(context.Context) ([]xboard.User, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.served++
	if n.usersErr != nil {
		return nil, n.usersErr
	}
	if n.served > 1 {
		return nil, xboard.ErrNotModified
	}
	return n.users, nil
}

func (n *fakeNode) PushTraffic(_ context.Context, t map[int][2]int64) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.pushErr != nil {
		return n.pushErr
	}
	n.pushed = append(n.pushed, t)
	return nil
}

func (n *fakeNode) PushAlive(_ context.Context, a map[int][]string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.alive = append(n.alive, a)
	return nil
}

func (n *fakeNode) GetAliveList(context.Context) (map[int]int, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.aliveList, nil
}

func (n *fakeNode) PushStatus(context.Context, *xboard.Status) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.statuses++
	return nil
}

type fakeKernel struct {
	mu        sync.Mutex
	boot      string
	hash      *string
	state     string
	down      bool
	applyErr  error
	applied   []string
	users     map[string][]prismapi.User
	setErrs   map[string]error
	traffic   map[string][]prismapi.Traffic
	snapshot  uint64
	committed []uint64
	commitErr error
	devices   map[string]map[int]int
}

func newKernel() *fakeKernel {
	return &fakeKernel{boot: "boot-1", state: "idle", users: map[string][]prismapi.User{}, traffic: map[string][]prismapi.Traffic{}, devices: map[string]map[int]int{}}
}

func (k *fakeKernel) Status(context.Context) (prismapi.Status, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.down {
		return prismapi.Status{}, errors.New("connection refused")
	}
	return prismapi.Status{API: 1, BootID: k.boot, State: k.state, ConfigHash: k.hash}, nil
}

func (k *fakeKernel) Apply(_ context.Context, hash string, _ json.RawMessage) (prismapi.ApplyResult, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.applyErr != nil {
		return prismapi.ApplyResult{}, k.applyErr
	}
	h := hash
	k.hash, k.state = &h, "running"
	k.applied = append(k.applied, hash)
	return prismapi.ApplyResult{Applied: hash}, nil
}

func (k *fakeKernel) SetUsers(_ context.Context, tag string, _ int64, users []prismapi.User) (prismapi.UsersResult, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.setErrs[tag]; err != nil {
		return prismapi.UsersResult{}, err
	}
	k.users[tag] = users
	return prismapi.UsersResult{Applied: true, Users: len(users), Added: len(users)}, nil
}

func (k *fakeKernel) SetDevices(_ context.Context, tag string, alive map[int]int) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.devices[tag] = alive
	return nil
}

func (k *fakeKernel) Stats(_ context.Context, tag string) (prismapi.Stats, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.snapshot++
	return prismapi.Stats{BootID: k.boot, Snapshot: k.snapshot, Traffic: k.traffic[tag]}, nil
}

func (k *fakeKernel) Commit(_ context.Context, _ string, snapshot uint64, _ string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.commitErr != nil {
		return k.commitErr
	}
	k.committed = append(k.committed, snapshot)
	return nil
}

type fakeService struct {
	mu      sync.Mutex
	ensured int
	stopped int
	err     error
}

func (s *fakeService) Ensure(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensured++
	return s.err
}

func (s *fakeService) Stop(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopped++
	return nil
}

func newController(t *testing.T, p *fakePanel, k *fakeKernel, s *fakeService) *Controller {
	t.Helper()
	c, err := New(Options{Panel: p, Kernel: k, Service: s, PollEvery: time.Hour, WatchEvery: time.Hour, DefaultInterval: 50 * time.Millisecond, MinInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func doc(version string, ids ...int) *xboard.Prism {
	d := &xboard.Prism{Version: version, Config: json.RawMessage(`{"inbounds":[]}`)}
	for _, id := range ids {
		d.Nodes = append(d.Nodes, xboard.PrismNode{ID: id, Type: "tuic", Tag: "node" + itoa(id) + "@machine1"})
	}
	return d
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

func start(t *testing.T, c *Controller) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return cancel
}

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

// ---- tests ------------------------------------------------------------------

func TestADocumentIsAppliedAndUsersAreSent(t *testing.T) {
	p := &fakePanel{doc: doc("v1", 7)}
	p.Node(7, "tuic").(*fakeNode).users = []xboard.User{{ID: 1, UUID: "u-1", SpeedLimit: 8, DeviceLimit: 2}, {ID: 0, UUID: "bad"}, {ID: 2}}
	k, s := newKernel(), &fakeService{}
	c := newController(t, p, k, s)
	start(t, c)

	eventually(t, "document applied", func() bool { k.mu.Lock(); defer k.mu.Unlock(); return len(k.applied) == 1 })
	eventually(t, "users sent", func() bool { k.mu.Lock(); defer k.mu.Unlock(); return len(k.users["node7@machine1"]) == 1 })

	k.mu.Lock()
	u := k.users["node7@machine1"][0]
	k.mu.Unlock()
	if u.ID != 1 || u.UUID != "u-1" || u.SpeedBps != 1_000_000 || u.DeviceLimit != 2 {
		t.Fatalf("user = %+v (8 Mbps must become 1,000,000 B/s; ids <= 0 and users without a uuid are dropped)", u)
	}
	if s.ensured < 1 {
		t.Fatal("the service was never ensured")
	}
	st := c.Status()
	if st.Version != "v1" || st.Nodes != 1 || st.Error != "" {
		t.Fatalf("status = %+v", st)
	}
}

func TestAnUnchangedDocumentIsNotAppliedAgain(t *testing.T) {
	p := &fakePanel{doc: doc("v1", 7)}
	k := newKernel()
	c := newController(t, p, k, &fakeService{})
	start(t, c)
	eventually(t, "applied", func() bool { k.mu.Lock(); defer k.mu.Unlock(); return len(k.applied) == 1 })

	c.Sync(context.Background())
	c.Sync(context.Background())

	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.applied) != 1 {
		t.Fatalf("applied %d times", len(k.applied))
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.etags[len(p.etags)-1] != "v1" {
		t.Fatalf("the held version must travel as the etag, got %v", p.etags)
	}
}

func TestARefusedDocumentIsReportedAndNotRetried(t *testing.T) {
	p := &fakePanel{doc: doc("bad", 7)}
	k := newKernel()
	k.applyErr = &prismapi.Error{Code: 422, Kind: "invalid", Message: "tls: missing certificate"}
	c := newController(t, p, k, &fakeService{})
	c.parent = context.Background()

	c.Sync(context.Background())
	c.Sync(context.Background())

	st := c.Status()
	if st.Rejected != "bad" || st.Error != "tls: missing certificate" {
		t.Fatalf("status = %+v", st)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.applied) != 0 {
		t.Fatalf("a refused document was applied")
	}
	if c.nodeIDs() != nil && len(c.nodeIDs()) != 0 {
		t.Fatal("workers started for a refused document")
	}
}

func TestAKernelStartFailureIsRetriedOnTheNextPoll(t *testing.T) {
	p := &fakePanel{doc: doc("v1", 7)}
	k := newKernel()
	k.applyErr = &prismapi.Error{Code: 500, Kind: "start_failed", Message: "port in use"}
	c := newController(t, p, k, &fakeService{})
	c.parent = context.Background()

	c.Sync(context.Background())
	if st := c.Status(); st.Rejected != "" || st.Error == "" {
		t.Fatalf("a start failure is not a refusal: %+v", st)
	}
	k.mu.Lock()
	k.applyErr = nil
	k.mu.Unlock()
	c.Sync(context.Background())

	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.applied) != 1 {
		t.Fatalf("applied = %v, want a retry to succeed", k.applied)
	}
}

func TestTheServiceNotRunningFailsWithoutTouchingTheKernel(t *testing.T) {
	p := &fakePanel{doc: doc("v1", 7)}
	k := newKernel()
	s := &fakeService{err: errors.New("prism is not installed")}
	c := newController(t, p, k, s)
	c.parent = context.Background()

	c.Sync(context.Background())

	if st := c.Status(); st.Error == "" || st.Version != "" {
		t.Fatalf("status = %+v", st)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.applied) != 0 {
		t.Fatal("the kernel was configured although it does not run")
	}
}

func TestTrafficIsCommittedOnlyAfterThePanelAcceptsIt(t *testing.T) {
	p := &fakePanel{doc: doc("v1", 7)}
	n := p.Node(7, "tuic").(*fakeNode)
	n.users = []xboard.User{{ID: 1, UUID: "u"}}
	n.aliveList = map[int]int{1: 2}
	k := newKernel()
	k.traffic["node7@machine1"] = []prismapi.Traffic{{ID: 1, Up: 10, Down: 20}, {ID: 1, Up: 1, Down: 2}}
	n.pushErr = errors.New("panel down")
	c := newController(t, p, k, &fakeService{})
	c.o.Sample = func() (*xboard.Status, error) { return &xboard.Status{}, nil }
	start(t, c)

	eventually(t, "stats read", func() bool { k.mu.Lock(); defer k.mu.Unlock(); return k.snapshot >= 2 })
	k.mu.Lock()
	if len(k.committed) != 0 {
		k.mu.Unlock()
		t.Fatal("traffic was committed although the panel refused it")
	}
	k.mu.Unlock()

	n.mu.Lock()
	n.pushErr = nil
	n.mu.Unlock()
	eventually(t, "traffic pushed and committed", func() bool {
		n.mu.Lock()
		defer n.mu.Unlock()
		k.mu.Lock()
		defer k.mu.Unlock()
		return len(n.pushed) > 0 && len(k.committed) > 0
	})
	n.mu.Lock()
	got := n.pushed[0][1]
	n.mu.Unlock()
	if got != [2]int64{11, 22} {
		t.Fatalf("pushed %v, want the two rows of one user summed to [11 22]", got)
	}
	eventually(t, "devices set", func() bool { k.mu.Lock(); defer k.mu.Unlock(); return k.devices["node7@machine1"][1] == 2 })
	eventually(t, "status reported", func() bool { n.mu.Lock(); defer n.mu.Unlock(); return n.statuses > 0 })
}

func TestARestartedKernelGetsTheConfigAndEveryUserTableAgain(t *testing.T) {
	p := &fakePanel{doc: doc("v1", 7)}
	n := p.Node(7, "tuic").(*fakeNode)
	n.users = []xboard.User{{ID: 1, UUID: "u"}}
	k := newKernel()
	c := newController(t, p, k, &fakeService{})
	start(t, c)
	eventually(t, "first users", func() bool { k.mu.Lock(); defer k.mu.Unlock(); return len(k.users["node7@machine1"]) == 1 })

	// The kernel restarts: a new boot id, no config, no users.
	k.mu.Lock()
	k.boot, k.hash, k.state = "boot-2", nil, "idle"
	delete(k.users, "node7@machine1")
	k.mu.Unlock()
	c.watch(context.Background())

	eventually(t, "config applied again", func() bool { k.mu.Lock(); defer k.mu.Unlock(); return len(k.applied) == 2 })
	eventually(t, "users sent again", func() bool { k.mu.Lock(); defer k.mu.Unlock(); return len(k.users["node7@machine1"]) == 1 })
}

func TestAnUnreachableKernelIsRestartedThroughTheService(t *testing.T) {
	p := &fakePanel{doc: doc("v1", 7)}
	k := newKernel()
	s := &fakeService{}
	c := newController(t, p, k, s)
	start(t, c)
	eventually(t, "applied", func() bool { k.mu.Lock(); defer k.mu.Unlock(); return len(k.applied) == 1 })

	s.mu.Lock()
	before := s.ensured
	s.mu.Unlock()
	k.mu.Lock()
	k.down = true
	k.mu.Unlock()
	c.watch(context.Background())

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ensured <= before {
		t.Fatal("the service was not asked to bring the kernel back")
	}
	if c.Status().Reachable {
		t.Fatal("status still says reachable")
	}
}

func TestNodesThatLeaveTheDocumentLoseTheirWorker(t *testing.T) {
	p := &fakePanel{doc: doc("v1", 7, 8)}
	k := newKernel()
	c := newController(t, p, k, &fakeService{})
	start(t, c)
	eventually(t, "two workers", func() bool { return len(c.nodeIDs()) == 2 })

	p.mu.Lock()
	p.doc = doc("v2", 8)
	p.mu.Unlock()
	c.Sync(context.Background())

	eventually(t, "one worker", func() bool { ids := c.nodeIDs(); return len(ids) == 1 && ids[0] == 8 })
}

func TestNoPrismNodesStopsTheServiceAfterTheIdleTime(t *testing.T) {
	p := &fakePanel{doc: nil}
	k := newKernel()
	k.state = "idle"
	s := &fakeService{}
	now := time.Unix(1_700_000_000, 0)
	c, err := New(Options{Panel: p, Kernel: k, Service: s, IdleStopAfter: 10 * time.Minute, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	c.parent = context.Background()

	c.Sync(context.Background())
	if s.stopped != 0 {
		t.Fatal("stopped at once")
	}
	now = now.Add(11 * time.Minute)
	c.Sync(context.Background())
	if s.stopped != 1 {
		t.Fatalf("stopped = %d, want 1 after the idle time", s.stopped)
	}
}

func TestAPanelTranslationFailureIsShownAndTheKernelKeepsRunning(t *testing.T) {
	p := &fakePanel{err: &xboard.StatusError{Path: "prism", Code: 422, Body: `{"error":"prism_translate"}`}}
	k := newKernel()
	c := newController(t, p, k, &fakeService{})
	c.parent = context.Background()

	c.Sync(context.Background())

	st := c.Status()
	if st.Error == "" {
		t.Fatalf("status = %+v", st)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.applied) != 0 {
		t.Fatal("the kernel was touched")
	}
}

func TestNewNeedsAllThreeParts(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("expected an error")
	}
}
