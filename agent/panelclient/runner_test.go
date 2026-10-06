package panelclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/reconcile"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/agent/validate"
)

const (
	leakySecret = "S3cr3t-Shared-Value-0042"
	runnerID    = "abcd1234"
)

// ---- fake clock --------------------------------------------------------------

type waiter struct {
	d  time.Duration // the duration it was registered with
	at time.Time     // the fake instant it fires
	ch chan time.Time
}

// fakeClock never sleeps: After registers a waiter at now+d, and the test
// advances the clock, releasing whatever has come due.
type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	pending []*waiter
	waits   []time.Duration // every duration ever requested, in order
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Unix(1790000000, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) set(t time.Time) {
	c.mu.Lock()
	c.now = t
	c.mu.Unlock()
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	w := &waiter{d: d, at: c.now.Add(d), ch: make(chan time.Time, 1)}
	c.waits = append(c.waits, d)
	c.pending = append(c.pending, w)
	c.releaseReadyLocked()
	return w.ch
}

func (c *fakeClock) waitsCopy() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.waits...)
}

// fire advances the fake clock by d and releases every waiter whose deadline
// has arrived. It first waits for the runner to (re)arm a wait that this fire
// will release: the runner acts, then rearms its timer, so firing before the
// rearm would advance the clock past a timer that is registered too late (the
// lost wakeup this harness once had). If the runner never arms one, the wait
// below fails the test with the clock's state and every goroutine's stack.
func (c *fakeClock) fire(t *testing.T, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(waitBudget(t, pollWait))
	for !c.waitArmed(d) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for a wait of %s to be armed; pending waits: %v; all waits: %v\n%s",
				d, c.pendingDurations(), c.waitsCopy(), goroutineDump())
		}
		time.Sleep(time.Millisecond)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	c.releaseReadyLocked()
}

// waitArmed reports whether an unreleased wait of exactly d is registered. A
// released waiter is removed from pending, so a match is one the runner armed
// after the previous fire. Matching "any waiter due by now+d" is wrong: the
// report loop's longer wait would satisfy it while the pull loop has not
// rearmed yet.
func (c *fakeClock) waitArmed(d time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, w := range c.pending {
		if w.d == d {
			return true
		}
	}
	return false
}

// pendingDurations lists the waits that have not been released yet, for the
// failure message of fire.
func (c *fakeClock) pendingDurations() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]time.Duration, 0, len(c.pending))
	for _, w := range c.pending {
		out = append(out, w.d)
	}
	return out
}

func (c *fakeClock) releaseReadyLocked() {
	rest := c.pending[:0]
	for _, w := range c.pending {
		if w.at.After(c.now) {
			rest = append(rest, w)
		} else {
			w.ch <- c.now
		}
	}
	c.pending = rest
}

// How long the harness is willing to wait for a condition to hold.
const (
	// pollWait bounds every condition wait. The tests drive time through the
	// fake clock, so a condition holds within microseconds of real time; the
	// generous bound only covers a machine loaded by the race detector.
	pollWait = 30 * time.Second

	// deadlineMargin is left to the test binary's own -timeout, so a stuck test
	// is still reported by the runtime, which dumps every goroutine itself.
	deadlineMargin = 5 * time.Second

	// runExitWait bounds how long Run may take to return after its context was
	// cancelled.
	runExitWait = 30 * time.Second

	// leakSettleWait bounds how long a goroutine that already finished its loop
	// may stay on the stack dump while it unwinds.
	leakSettleWait = 10 * time.Second
)

// waitBudget returns how long a condition may take to hold: maxWait, shortened
// so the test binary's -timeout keeps a margin to report the stuck test itself.
// A non-positive result means there is no time left. It must never be computed
// as t.Deadline() minus a fixed margin alone: with a custom -timeout shorter
// than that margin every wait would fail before the condition was ever given a
// chance.
func waitBudget(t *testing.T, maxWait time.Duration) time.Duration {
	t.Helper()
	dl, ok := t.Deadline()
	if !ok {
		return maxWait
	}
	if remain := time.Until(dl) - deadlineMargin; remain < maxWait {
		return remain
	}
	return maxWait
}

// eventually polls cond; the polling only synchronises with goroutines, no
// logic depends on real time.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitBudget(t, pollWait))
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// runnerFrame marks a goroutine that is executing Runner code. It cannot tell a
// survivor from a loop goroutine that has already returned: such a goroutine
// stays on the stack for a few instructions while its deferred wg.Done runs,
// and its frame is named "(*Runner).Run.funcN". waitRunnerGoroutines samples
// until the dump is clean instead of trusting a single reading.
var runnerFrame = []byte("panelclient.(*Runner)")

// goroutineDump returns the stacks of every goroutine, growing the buffer until
// the runtime reports that they all fitted.
func goroutineDump() []byte {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) || len(buf) >= 1<<26 {
			return buf[:n]
		}
		buf = make([]byte, 2*len(buf))
	}
}

// waitRunnerGoroutines waits until no goroutine is executing Runner code and
// reports whether that happened within budget. A goroutine that really survived
// Run is blocked and never leaves, so the wait only lets a goroutine that has
// already finished its loop disappear from the dump: the assertion keeps its
// meaning. On failure the last dump is returned for the report.
func waitRunnerGoroutines(budget time.Duration) ([]byte, bool) {
	deadline := time.Now().Add(budget)
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			if !bytes.Contains(buf[:n], runnerFrame) {
				return nil, true
			}
		} else if len(buf) < 1<<26 {
			// Truncated: a survivor could have been cut off, so retry bigger.
			buf = make([]byte, 2*len(buf))
			continue
		}
		if time.Now().After(deadline) {
			return goroutineDump(), false
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// ---- recording logger ----------------------------------------------------------

type recLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *recLog) add(level, f string, a ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, level+" "+fmt.Sprintf(f, a...))
	l.mu.Unlock()
}
func (l *recLog) Debugf(f string, a ...any) { l.add("DEBUG", f, a...) }
func (l *recLog) Infof(f string, a ...any)  { l.add("INFO", f, a...) }
func (l *recLog) Warnf(f string, a ...any)  { l.add("WARN", f, a...) }
func (l *recLog) Errorf(f string, a ...any) { l.add("ERROR", f, a...) }
func (l *recLog) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}
func (l *recLog) count(sub string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, s := range l.lines {
		if strings.Contains(s, sub) {
			n++
		}
	}
	return n
}

// ---- fake applier --------------------------------------------------------------

type fakeApp struct {
	mu       sync.Mutex
	applies  []spec.Desired
	applyFn  func(d spec.Desired) (reconcile.Report, error)
	last     reconcile.Report
	hasLast  bool
	health   reconcile.HealthReport
	counters []driver.Counter
	panicIn  string // "apply" | "health"
}

func okReport(d spec.Desired) reconcile.Report {
	r := reconcile.Report{Revision: d.Revision, Hash: fmt.Sprintf("local-%d", d.Revision), Status: reconcile.StatusApplied, At: time.Unix(1790000001, 0), Instances: []reconcile.InstanceReport{}}
	for _, in := range d.Instances {
		r.Instances = append(r.Instances, reconcile.InstanceReport{ID: in.ID, State: reconcile.StateRunning, Engine: in.Engine})
	}
	return r
}

func (a *fakeApp) Apply(ctx context.Context, d spec.Desired) (reconcile.Report, error) {
	a.mu.Lock()
	if a.panicIn == "apply" {
		a.mu.Unlock()
		panic("boom in apply")
	}
	a.applies = append(a.applies, d)
	fn := a.applyFn
	a.mu.Unlock()
	rep, err := okReport(d), error(nil)
	if fn != nil {
		rep, err = fn(d)
	}
	a.mu.Lock()
	a.last, a.hasLast = rep, true
	a.mu.Unlock()
	return rep, err
}

func (a *fakeApp) Last() (reconcile.Report, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.last, a.hasLast
}

func (a *fakeApp) Health(ctx context.Context) reconcile.HealthReport {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.panicIn == "health" {
		panic("boom in health")
	}
	return a.health
}

func (a *fakeApp) Stats(ctx context.Context) []driver.Counter {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]driver.Counter(nil), a.counters...)
}

func (a *fakeApp) applyCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.applies)
}

// ---- contract server -----------------------------------------------------------

type call struct {
	endpoint string
	raw      []byte
}

// panelSrv is a TLS server that speaks the contract with programmable answers.
type panelSrv struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	calls    []call
	config   func(n int, req ConfigRequest) (int, string)
	ack      func(n int, req AckRequest) int
	report   func(n int, req ReportRequest) (int, string)
	cmdRes   func(req CommandResultRequest) int
	manifest func(n int, req *http.Request) (status int, body, etag string)
	counts   map[string]int
	hanging  chan struct{} // when non-nil, every request blocks until it is closed
}

func newPanel(t *testing.T) *panelSrv {
	p := &panelSrv{t: t, counts: map[string]int{}}
	p.srv = httptest.NewTLSServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *panelSrv) serve(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	ep := strings.TrimPrefix(r.URL.Path, testPrefix)
	p.mu.Lock()
	p.counts[ep]++
	n := p.counts[ep]
	p.calls = append(p.calls, call{ep, raw})
	hang := p.hanging
	p.mu.Unlock()
	if hang != nil {
		select {
		case <-hang:
		case <-r.Context().Done():
			return
		}
	}

	status, body := 200, `{"ok":true}`
	switch ep {
	case "config":
		p.mu.Lock()
		f := p.config
		p.mu.Unlock()
		var req ConfigRequest
		json.Unmarshal(raw, &req)
		status, body = 200, `{"schema":1,"unchanged":true,"revision":0}`
		if f != nil {
			status, body = f(n, req)
		}
	case "ack":
		p.mu.Lock()
		f := p.ack
		p.mu.Unlock()
		var req AckRequest
		json.Unmarshal(raw, &req)
		if f != nil {
			status = f(n, req)
		}
	case "report":
		p.mu.Lock()
		f := p.report
		p.mu.Unlock()
		var req ReportRequest
		json.Unmarshal(raw, &req)
		if f != nil {
			status, body = f(n, req)
		}
	case "command-result":
		p.mu.Lock()
		f := p.cmdRes
		p.mu.Unlock()
		var req CommandResultRequest
		json.Unmarshal(raw, &req)
		if f != nil {
			status = f(req)
		}
	case "manifest":
		p.mu.Lock()
		f := p.manifest
		p.mu.Unlock()
		if f == nil {
			// No manifest published: the contract's 404 answer.
			status, body = 404, `{"error":"no_manifest"}`
			break
		}
		var etag string
		status, body, etag = f(n, r)
		if etag != "" {
			w.Header().Set("ETag", etag)
		}
	}
	if status >= 300 && ep != "config" && ep != "report" && body == `{"ok":true}` {
		body = `{"error":"nope","message":"refused"}`
	}
	writeJSON(w, status, body)
}

func (p *panelSrv) setConfig(f func(n int, req ConfigRequest) (int, string)) {
	p.mu.Lock()
	p.config = f
	p.mu.Unlock()
}
func (p *panelSrv) setAck(f func(n int, req AckRequest) int) {
	p.mu.Lock()
	p.ack = f
	p.mu.Unlock()
}
func (p *panelSrv) setReport(f func(n int, req ReportRequest) (int, string)) {
	p.mu.Lock()
	p.report = f
	p.mu.Unlock()
}
func (p *panelSrv) setCmdResult(f func(req CommandResultRequest) int) {
	p.mu.Lock()
	p.cmdRes = f
	p.mu.Unlock()
}

// setManifest programs the GET /manifest answer. A nil handler answers the
// contract's 404 no_manifest.
func (p *panelSrv) setManifest(f func(n int, req *http.Request) (status int, body, etag string)) {
	p.mu.Lock()
	p.manifest = f
	p.mu.Unlock()
}

func (p *panelSrv) count(ep string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.counts[ep]
}

func (p *panelSrv) waitCount(ep string, n int) {
	p.t.Helper()
	eventually(p.t, fmt.Sprintf("%d request(s) to /%s", n, ep), func() bool { return p.count(ep) >= n })
}

func (p *panelSrv) bodies(ep string) [][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out [][]byte
	for _, c := range p.calls {
		if c.endpoint == ep {
			out = append(out, c.raw)
		}
	}
	return out
}

func (p *panelSrv) allBodies() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var sb strings.Builder
	for _, c := range p.calls {
		sb.Write(c.raw)
		sb.WriteByte('\n')
	}
	return sb.String()
}

func (p *panelSrv) order() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for _, c := range p.calls {
		out = append(out, c.endpoint)
	}
	return out
}

func (p *panelSrv) configReq(i int) ConfigRequest {
	p.t.Helper()
	var r ConfigRequest
	b := p.bodies("config")
	if i >= len(b) {
		p.t.Fatalf("only %d config requests, want index %d", len(b), i)
	}
	if err := json.Unmarshal(b[i], &r); err != nil {
		p.t.Fatal(err)
	}
	return r
}

func (p *panelSrv) ackReq(i int) AckRequest {
	p.t.Helper()
	var r AckRequest
	b := p.bodies("ack")
	if i >= len(b) {
		p.t.Fatalf("only %d acks, want index %d", len(b), i)
	}
	if err := json.Unmarshal(b[i], &r); err != nil {
		p.t.Fatal(err)
	}
	return r
}

func (p *panelSrv) resultReq(i int) CommandResultRequest {
	p.t.Helper()
	var r CommandResultRequest
	b := p.bodies("command-result")
	if i >= len(b) {
		p.t.Fatalf("only %d command results, want index %d", len(b), i)
	}
	if err := json.Unmarshal(b[i], &r); err != nil {
		p.t.Fatal(err)
	}
	return r
}

// desiredBody builds a changed /config answer.
func desiredBody(rev int64, hash string, instances string, commands string) string {
	if commands == "" {
		commands = "[]"
	}
	return fmt.Sprintf(`{"schema":1,"revision":%d,"hash":%q,"issued_at":1790000000,"desired":{"version":1,"revision":%d,"instances":[%s]},"commands":%s}`,
		rev, hash, rev, instances, commands)
}

func instJSON(id, engine, extra string) string {
	return fmt.Sprintf(`{"id":%q,"enabled":true,"engine":%q,"kind":"forward"%s}`, id, engine, extra)
}

func unchangedBody(rev int64, commands string) string {
	if commands == "" {
		return fmt.Sprintf(`{"schema":1,"unchanged":true,"revision":%d}`, rev)
	}
	return fmt.Sprintf(`{"schema":1,"unchanged":true,"revision":%d,"commands":%s}`, rev, commands)
}

// ---- harness -------------------------------------------------------------------

type harness struct {
	t      *testing.T
	panel  *panelSrv
	app    *fakeApp
	clock  *fakeClock
	log    *recLog
	runner *Runner
	cancel context.CancelFunc
	done   chan error
}

type hopts struct {
	pull, report time.Duration
	rand         func() float64
	instanceID   string
	host         func() *HostStat
	noStart      bool

	// manifest sync (disabled when manifest is nil).
	manifest         ManifestSink
	manifestPath     string
	manifestInterval time.Duration
	manifestAnswer   func(n int, req *http.Request) (status int, body, etag string)
}

// newHarness builds a Runner against a fresh contract server. By default the
// pull interval is the 10s minimum and the report interval the 300s maximum,
// so a test releases a loop by firing exactly its wait.
func newHarness(t *testing.T, o hopts) *harness {
	t.Helper()
	h := &harness{t: t, panel: newPanel(t), app: &fakeApp{}, clock: newFakeClock(), log: &recLog{}}
	if o.pull == 0 {
		o.pull = 10 * time.Second
	}
	if o.report == 0 {
		o.report = 300 * time.Second
	}
	if o.rand == nil {
		o.rand = func() float64 { return 0.5 }
	}
	if o.host == nil {
		o.host = func() *HostStat { return nil }
	}
	if o.instanceID == "" {
		o.instanceID = runnerID
	}
	client := newClient(t, h.panel.srv)
	if o.manifestAnswer != nil {
		h.panel.setManifest(o.manifestAnswer)
	}
	r, err := NewRunner(client, h.app, RunnerOptions{
		AgentVersion:        "1.2.3",
		Engines:             []string{"gost", "realm", "xray"},
		Kernels:             func() map[string]string { return map[string]string{"gost": "3.3.0"} },
		PullInterval:        o.pull,
		ReportInterval:      o.report,
		Log:                 h.log,
		Clock:               h.clock,
		Rand:                o.rand,
		InstanceID:          o.instanceID,
		Host:                o.host,
		Manifest:            o.manifest,
		ManifestPersistPath: o.manifestPath,
		ManifestInterval:    o.manifestInterval,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.runner = r
	if !o.noStart {
		h.start()
	}
	return h
}

func (h *harness) start() {
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	h.done = make(chan error, 1)
	go func() { h.done <- h.runner.Run(ctx) }()
	h.t.Cleanup(func() { h.stop() })
}

// stop cancels Run and checks that it exits and leaves no goroutine behind.
func (h *harness) stop() {
	h.t.Helper()
	if h.cancel == nil {
		return
	}
	// Clear the handle first: a second call (a test that stops explicitly and
	// then runs the cleanup) must not wait for Run twice.
	cancel := h.cancel
	h.cancel = nil
	cancel()
	select {
	case err := <-h.done:
		if !errors.Is(err, context.Canceled) {
			h.t.Errorf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(waitBudget(h.t, runExitWait)):
		h.t.Fatalf("Run did not return after the context was cancelled:\n%s", goroutineDump())
	}
	// A loop goroutine that has just returned is still on the stack for a few
	// instructions while its deferred wg.Done runs, so a single sample can see
	// "(*Runner).Run.funcN" and call a finished goroutine a survivor. Wait for
	// the dump to drain: a goroutine that really survived Run never does.
	if dump, ok := waitRunnerGoroutines(waitBudget(h.t, leakSettleWait)); !ok {
		h.t.Errorf("a Runner goroutine survived Run:\n%s", dump)
	}
}

// ---- tests ---------------------------------------------------------------------

func TestChangedDesiredIsAppliedAndAcknowledged(t *testing.T) {
	h := newHarness(t, hopts{})
	h.panel.setConfig(func(n int, req ConfigRequest) (int, string) {
		if n == 1 {
			return 200, desiredBody(42, "sha256:cd34", instJSON("hk-ssh", "gost", ""), "")
		}
		return 200, unchangedBody(42, "")
	})
	h.panel.waitCount("ack", 1)

	// First request: nothing applied yet.
	req := h.panel.configReq(0)
	if req.Schema != 1 || req.InstanceID != runnerID || req.AgentVersion != "1.2.3" {
		t.Errorf("config request identity = %+v", req)
	}
	if req.HaveRevision != 0 || req.HaveHash != "" {
		t.Errorf("first request must say have 0/\"\", got %d/%q", req.HaveRevision, req.HaveHash)
	}
	if req.Platform.OS != runtime.GOOS || req.Platform.Arch != runtime.GOARCH {
		t.Errorf("platform = %+v", req.Platform)
	}
	if strings.Join(req.Engines, ",") != "gost,realm,xray" || req.Kernels["gost"] != "3.3.0" {
		t.Errorf("engines/kernels = %v %v", req.Engines, req.Kernels)
	}

	// Apply received the strictly decoded desired state.
	if h.app.applyCount() != 1 {
		t.Fatalf("Apply called %d times", h.app.applyCount())
	}
	if d := h.app.applies[0]; d.Revision != 42 || len(d.Instances) != 1 || d.Instances[0].ID != "hk-ssh" {
		t.Errorf("applied desired = %+v", d)
	}

	// The ack carries the panel's revision/hash and the report.
	ack := h.panel.ackReq(0)
	if ack.Schema != 1 || ack.InstanceID != runnerID || ack.Revision != 42 || ack.Hash != "sha256:cd34" {
		t.Errorf("ack envelope = %+v", ack)
	}
	if ack.Report.Status != reconcile.StatusApplied || len(ack.Report.Instances) != 1 || ack.Report.Instances[0].ID != "hk-ssh" {
		t.Errorf("ack report = %+v", ack.Report)
	}

	// The next pull echoes what was applied, and "unchanged" applies nothing.
	h.clock.fire(t, 10*time.Second)
	h.panel.waitCount("config", 2)
	next := h.panel.configReq(1)
	if next.HaveRevision != 42 || next.HaveHash != "sha256:cd34" {
		t.Errorf("second request have = %d/%q, want 42/sha256:cd34", next.HaveRevision, next.HaveHash)
	}
	h.clock.fire(t, 10*time.Second)
	h.panel.waitCount("config", 3)
	if h.app.applyCount() != 1 || h.panel.count("ack") != 1 {
		t.Errorf("unchanged must not apply or ack: applies=%d acks=%d", h.app.applyCount(), h.panel.count("ack"))
	}
}

func TestFailedOutcomesAreStillAcknowledgedAndDoNotAdvanceHave(t *testing.T) {
	cases := []struct {
		name string
		rep  reconcile.Report
		err  error
		want reconcile.Status
	}{
		{"rejected", reconcile.Report{Revision: 7, Hash: "x", Status: reconcile.StatusRejected, Message: "policy says no", At: time.Unix(1, 0),
			ValidationErrors: []validate.Error{{Instance: "a", Field: "listen.addr", Message: "not allowed"}}}, reconcile.ErrRejected, reconcile.StatusRejected},
		{"failed", reconcile.Report{Revision: 7, Hash: "x", Status: reconcile.StatusFailed, Message: "kernel missing", At: time.Unix(1, 0)}, reconcile.ErrFailed, reconcile.StatusFailed},
		{"rolled_back", reconcile.Report{Revision: 7, Hash: "x", Status: reconcile.StatusRolledBack, Message: "restored", At: time.Unix(1, 0)}, reconcile.ErrRolledBack, reconcile.StatusRolledBack},
		{"partial", reconcile.Report{Revision: 7, Hash: "x", Status: reconcile.StatusPartial, Message: "mixed", At: time.Unix(1, 0)}, reconcile.ErrPartial, reconcile.StatusPartial},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, hopts{})
			h.app.applyFn = func(d spec.Desired) (reconcile.Report, error) { return tc.rep, tc.err }
			h.panel.setConfig(func(n int, req ConfigRequest) (int, string) {
				return 200, desiredBody(7, "sha256:bad", instJSON("a", "gost", ""), "")
			})
			h.panel.waitCount("ack", 1)
			ack := h.panel.ackReq(0)
			if ack.Report.Status != tc.want || ack.Revision != 7 || ack.Hash != "sha256:bad" {
				t.Fatalf("ack = %+v", ack)
			}
			if tc.name == "rejected" && (len(ack.Report.ValidationErrors) != 1 || ack.Report.ValidationErrors[0].Field != "listen.addr") {
				t.Errorf("validation errors lost: %+v", ack.Report.ValidationErrors)
			}
			h.clock.fire(t, 10*time.Second)
			h.panel.waitCount("config", 2)
			if next := h.panel.configReq(1); next.HaveRevision != 0 || next.HaveHash != "" {
				t.Errorf("a non-applied outcome must not advance have, got %d/%q", next.HaveRevision, next.HaveHash)
			}
		})
	}
}

func TestApplyErrorWithoutReportStillAcks(t *testing.T) {
	h := newHarness(t, hopts{})
	h.app.applyFn = func(d spec.Desired) (reconcile.Report, error) {
		return reconcile.Report{}, errors.New("state dir unusable for " + leakySecret)
	}
	h.panel.setConfig(func(n int, req ConfigRequest) (int, string) {
		return 200, desiredBody(8, "sha256:h8", instJSON("a", "gost", `,"secret":"`+leakySecret+`"`), "")
	})
	h.panel.waitCount("ack", 1)
	ack := h.panel.ackReq(0)
	if ack.Report.Status != reconcile.StatusFailed || ack.Report.Revision != 8 || ack.Report.Hash != "sha256:h8" {
		t.Fatalf("synthesised report = %+v", ack.Report)
	}
	if !strings.Contains(ack.Report.Message, "state dir unusable") || strings.Contains(ack.Report.Message, leakySecret) {
		t.Errorf("message = %q (must say why, without the secret)", ack.Report.Message)
	}
	if ack.Report.At.IsZero() {
		t.Error("synthesised report has no time")
	}
	if strings.Contains(h.panel.allBodies(), leakySecret) || strings.Contains(h.log.text(), leakySecret) {
		t.Error("the secret leaked")
	}
}

func TestBadDesiredIsRejectedWithoutApplying(t *testing.T) {
	bad := map[string]string{
		"unknown field": `{"schema":1,"revision":9,"hash":"sha256:u","desired":{"version":1,"revision":9,"instances":[],"surprise":true}}`,
		"revision":      `{"schema":1,"revision":9,"hash":"sha256:u","desired":{"version":1,"revision":10,"instances":[]}}`,
		"missing":       `{"schema":1,"revision":9,"hash":"sha256:u"}`,
	}
	for name, body := range bad {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, hopts{})
			h.panel.setConfig(func(n int, req ConfigRequest) (int, string) { return 200, body })
			h.panel.waitCount("ack", 1)
			if h.app.applyCount() != 0 {
				t.Fatalf("Apply was called %d times for an invalid desired state", h.app.applyCount())
			}
			ack := h.panel.ackReq(0)
			rep := ack.Report
			if rep.Status != reconcile.StatusRejected || ack.Revision != 9 || ack.Hash != "sha256:u" || rep.Revision != 9 {
				t.Fatalf("ack = %+v", ack)
			}
			if !strings.Contains(rep.Message, "invalid desired state") {
				t.Errorf("message = %q", rep.Message)
			}
			if !rep.At.Equal(time.Unix(1790000000, 0)) {
				t.Errorf("At = %v, want the clock's now", rep.At)
			}
			if strings.Contains(string(h.panel.bodies("ack")[0]), `"instances":null`) {
				t.Error("instances must be an empty list, not null")
			}
		})
	}
}

func TestAckIsRetriedUntilDelivered(t *testing.T) {
	h := newHarness(t, hopts{})
	h.panel.setConfig(func(n int, req ConfigRequest) (int, string) {
		if n == 1 {
			return 200, desiredBody(42, "sha256:cd", instJSON("a", "gost", ""), "")
		}
		return 200, unchangedBody(42, "")
	})
	h.panel.setAck(func(n int, req AckRequest) int {
		if n <= 2 {
			return 503
		}
		return 200
	})
	h.panel.waitCount("ack", 1)
	// Delivery failed, so the loop backs off (30s) and the retry comes before
	// any new /config request.
	h.clock.fire(t, 30*time.Second)
	h.panel.waitCount("ack", 2)
	h.clock.fire(t, 60*time.Second)
	// The third attempt succeeds and the same round then pulls again.
	h.panel.waitCount("config", 2)
	if got, want := strings.Join(h.panel.order(), ","), "config,ack,ack,ack,config"; got != want {
		t.Errorf("request order = %s, want %s", got, want)
	}

	a0, a2 := h.panel.ackReq(0), h.panel.ackReq(2)
	if a0.Revision != 42 || a2.Revision != 42 || !a0.Report.At.Equal(a2.Report.At) || a0.Hash != a2.Hash {
		t.Errorf("the retried ack differs from the original: %+v vs %+v", a0, a2)
	}
	// Back on the normal cadence, with the applied revision echoed.
	h.clock.fire(t, 10*time.Second)
	h.panel.waitCount("config", 3)
	if req := h.panel.configReq(2); req.HaveRevision != 42 {
		t.Errorf("have_revision = %d", req.HaveRevision)
	}
	if h.panel.count("ack") != 3 || h.app.applyCount() != 1 {
		t.Errorf("acks=%d applies=%d, want 3 and 1", h.panel.count("ack"), h.app.applyCount())
	}
}

func countOf(s []string, v string) int {
	n := 0
	for _, x := range s {
		if x == v {
			n++
		}
	}
	return n
}

func TestAckTheOnlyPanelWillNeverAcceptIsDropped(t *testing.T) {
	h := newHarness(t, hopts{})
	h.panel.setConfig(func(n int, req ConfigRequest) (int, string) {
		if n == 1 {
			return 200, desiredBody(42, "sha256:cd", instJSON("a", "gost", ""), "")
		}
		return 200, unchangedBody(42, "")
	})
	h.panel.setAck(func(n int, req AckRequest) int { return 422 })
	h.panel.waitCount("ack", 1)
	h.clock.fire(t, 10*time.Second) // normal cadence: the ack was dropped, no backoff
	h.panel.waitCount("config", 2)
	if h.panel.count("ack") != 1 {
		t.Errorf("a 422 ack was retried %d times", h.panel.count("ack")-1)
	}
	if h.log.count("dropping the ack") != 1 {
		t.Errorf("drop not logged: %s", h.log.text())
	}
}

func TestReportMergesStatsAndOmitsMissingCounters(t *testing.T) {
	host := &HostStat{}
	cpu, mem := 12.5, uint64(1<<30)
	host.CPU, host.MemTotal = &cpu, &mem
	h := newHarness(t, hopts{report: 40 * time.Second, host: func() *HostStat { return host }, noStart: true})
	h.app.applyFn = func(d spec.Desired) (reconcile.Report, error) {
		return reconcile.Report{
			Revision: d.Revision, Hash: "local", Status: reconcile.StatusApplied,
			Kernels: map[string]string{"gost": "3.3.0", "xray": "builtin"},
			Instances: []reconcile.InstanceReport{
				{ID: "hk-ssh", State: reconcile.StateRunning, Engine: "gost"},
				{ID: "relay", State: reconcile.StateRunning, Engine: "realm"},
				{ID: "off", State: reconcile.StateDisabled},
			},
		}, nil
	}
	h.app.health = reconcile.HealthReport{Revision: 42, OK: true}
	h.app.counters = []driver.Counter{
		{InstanceID: "hk-ssh", BytesUp: 123456, BytesDown: 654321, ConnsActive: 3, ConnsTotal: 120},
		{InstanceID: "orphan", BytesUp: 1, BytesDown: 2, ConnsActive: 0, ConnsTotal: 3},
	}
	h.panel.setConfig(func(n int, req ConfigRequest) (int, string) {
		if n == 1 {
			return 200, desiredBody(42, "sha256:cd", instJSON("hk-ssh", "gost", ""), "")
		}
		return 200, unchangedBody(42, "")
	})
	h.start()
	h.panel.waitCount("ack", 1)

	h.clock.fire(t, 40*time.Second)
	h.panel.waitCount("report", 1)
	h.clock.fire(t, 40*time.Second)
	h.panel.waitCount("report", 2)
	h.clock.fire(t, 40*time.Second)
	h.panel.waitCount("report", 3)

	var reps []ReportRequest
	for _, b := range h.panel.bodies("report") {
		var r ReportRequest
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		reps = append(reps, r)
	}
	for i, r := range reps {
		if r.Seq != uint64(i+1) {
			t.Errorf("report %d has seq %d, want %d", i, r.Seq, i+1)
		}
		if r.InstanceID != runnerID || r.Schema != 1 {
			t.Errorf("report envelope = %+v", r)
		}
	}
	r := reps[0]
	if r.AppliedRevision != 42 || r.AppliedHash != "sha256:cd" {
		t.Errorf("applied = %d/%q", r.AppliedRevision, r.AppliedHash)
	}
	if r.TS < 1790000000 {
		t.Errorf("ts = %d", r.TS)
	}
	if !r.Health.OK || r.Health.Revision != 42 {
		t.Errorf("health = %+v", r.Health)
	}
	if r.Kernels["gost"] != "3.3.0" || r.Kernels["xray"] != "builtin" {
		t.Errorf("kernels = %v", r.Kernels)
	}
	if r.Host == nil || r.Host.CPU == nil || *r.Host.CPU != 12.5 || r.Host.MemTotal == nil || *r.Host.MemTotal != 1<<30 || r.Host.DiskTotal != nil {
		t.Errorf("host = %+v", r.Host)
	}

	byID := map[string]InstanceStat{}
	for _, in := range r.Instances {
		byID[in.ID] = in
	}
	if len(r.Instances) != 4 {
		t.Fatalf("instances = %+v", r.Instances)
	}
	hk := byID["hk-ssh"]
	if hk.State != "running" || hk.Engine != "gost" || hk.BytesUp == nil || *hk.BytesUp != 123456 || *hk.BytesDown != 654321 || *hk.ConnsActive != 3 || *hk.ConnsTotal != 120 {
		t.Errorf("hk-ssh = %+v", hk)
	}
	if orphan := byID["orphan"]; orphan.State != "running" || orphan.BytesUp == nil || *orphan.ConnsTotal != 3 {
		t.Errorf("orphan counter = %+v", orphan)
	}

	// An engine without statistics (realm) and a disabled instance carry none
	// of the four counter fields, so the panel shows "not metered".
	var raw struct {
		Instances []map[string]any `json:"instances"`
	}
	if err := json.Unmarshal(h.panel.bodies("report")[0], &raw); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, in := range raw.Instances {
		if in["id"] == "relay" || in["id"] == "off" {
			checked++
			for _, f := range []string{"bytes_up", "bytes_down", "conns_active", "conns_total"} {
				if _, present := in[f]; present {
					t.Errorf("instance %v must omit %s", in["id"], f)
				}
			}
		}
	}
	if checked != 2 {
		t.Errorf("checked %d uncounted instances, want 2", checked)
	}
}

func TestReportWithNothingAppliedIsWellFormed(t *testing.T) {
	h := newHarness(t, hopts{report: 40 * time.Second})
	h.clock.fire(t, 40*time.Second)
	h.panel.waitCount("report", 1)
	body := string(h.panel.bodies("report")[0])
	if !strings.Contains(body, `"instances":[]`) {
		t.Errorf("instances must be [], body: %s", body)
	}
	if strings.Contains(body, `"host"`) {
		t.Errorf("host must be omitted when unavailable: %s", body)
	}
	var r ReportRequest
	if err := json.Unmarshal([]byte(body), &r); err != nil || r.AppliedRevision != 0 || r.AppliedHash != "" {
		t.Errorf("report = %+v err=%v", r, err)
	}
}

func TestCommandWhitelist(t *testing.T) {
	h := newHarness(t, hopts{})
	now := h.clock.Now().Unix()
	cmds := fmt.Sprintf(`[
		{"id":"c-bad","type":"restart_instance","args":{"id":"a"}},
		{"id":"c-shell","type":"exec","args":{"cmd":"rm -rf /"}},
		{"id":"c-old","type":"refresh","expires_at":%d},
		{"id":"c-oldDump","type":"dump_state","expires_at":%d},
		{"id":"c-nosuch","type":""}
	]`, now-1, now-1)
	h.panel.setConfig(func(n int, req ConfigRequest) (int, string) {
		return 200, unchangedBody(0, cmds)
	})
	h.panel.waitCount("command-result", 5)

	res := map[string]CommandResultRequest{}
	for i := 0; i < 5; i++ {
		r := h.panel.resultReq(i)
		res[r.ID] = r
		if r.InstanceID != runnerID || r.Schema != 1 {
			t.Errorf("result envelope = %+v", r)
		}
	}
	for _, id := range []string{"c-bad", "c-shell", "c-nosuch"} {
		r := res[id]
		var body map[string]string
		json.Unmarshal(r.Result, &body)
		if r.Status != ResultFailed || body["error"] != "unsupported command" {
			t.Errorf("%s: %+v / %s", id, r, r.Result)
		}
	}
	for _, id := range []string{"c-old", "c-oldDump"} {
		if res[id].Status != ResultExpired {
			t.Errorf("%s: status %q, want expired", id, res[id].Status)
		}
		if len(res[id].Result) != 0 {
			t.Errorf("%s: an expired command must not carry a result: %s", id, res[id].Result)
		}
	}
	if h.app.applyCount() != 0 {
		t.Errorf("a command must never apply anything (%d applies)", h.app.applyCount())
	}
	// None of them is an executed refresh: no pull beyond the first happens
	// without the clock firing.
	h.stop()
	if n := h.panel.count("config"); n != 1 {
		t.Errorf("expired/unsupported commands triggered %d extra pull(s)", n-1)
	}
}

func TestCommandDeduplicationAcrossConfigAndReport(t *testing.T) {
	h := newHarness(t, hopts{report: 40 * time.Second})
	cmd := `[{"id":"dup-1","type":"dump_state"}]`
	h.panel.setConfig(func(n int, req ConfigRequest) (int, string) { return 200, unchangedBody(0, cmd) })
	h.panel.setReport(func(n int, req ReportRequest) (int, string) {
		return 200, `{"ok":true,"ack_seq":1,"commands":` + cmd + `}`
	})
	h.panel.waitCount("command-result", 1)
	h.clock.fire(t, 10*time.Second) // same command again through /config
	h.panel.waitCount("config", 2)
	h.clock.fire(t, 40*time.Second) // and again through /report
	h.panel.waitCount("report", 1)
	h.clock.fire(t, 10*time.Second)
	h.panel.waitCount("config", 3)
	h.stop()
	if n := h.panel.count("command-result"); n != 1 {
		t.Fatalf("command executed %d times, want exactly once", n)
	}
	if r := h.panel.resultReq(0); r.ID != "dup-1" || r.Status != ResultDone {
		t.Errorf("result = %+v", r)
	}
}

func TestCommandsFromReportResponseRun(t *testing.T) {
	h := newHarness(t, hopts{report: 40 * time.Second})
	h.panel.setReport(func(n int, req ReportRequest) (int, string) {
		return 200, `{"ok":true,"commands":[{"id":"r-1","type":"nope"}]}`
	})
	h.clock.fire(t, 40*time.Second)
	h.panel.waitCount("command-result", 1)
	if r := h.panel.resultReq(0); r.ID != "r-1" || r.Status != ResultFailed {
		t.Errorf("result = %+v", r)
	}
}

func TestUndeliveredCommandResultIsAnsweredAgainOnRedelivery(t *testing.T) {
	h := newHarness(t, hopts{})
	h.panel.setConfig(func(n int, req ConfigRequest) (int, string) {
		return 200, unchangedBody(0, `[{"id":"again","type":"nope"}]`)
	})
	h.panel.setCmdResult(func(req CommandResultRequest) int {
		if h.panel.count("command-result") == 1 {
			return 500
		}
		return 200
	})
	h.panel.waitCount("command-result", 1)
	h.clock.fire(t, 10*time.Second)
	h.panel.waitCount("command-result", 2)
	h.clock.fire(t, 10*time.Second)
	h.panel.waitCount("config", 3)
	h.stop()
	if n := h.panel.count("command-result"); n != 2 {
		t.Errorf("results = %d, want 2 (one failed delivery, one retry)", n)
	}
}

func TestSeenCommandsKeepTheMostRecent256(t *testing.T) {
	r, err := NewRunner(&Client{}, &fakeApp{}, RunnerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 300; i++ {
		r.remember(fmt.Sprintf("id-%d", i))
	}
	if len(r.seen) != seenCommands || len(r.seenOrder) != seenCommands {
		t.Fatalf("remembers %d/%d ids, want %d", len(r.seen), len(r.seenOrder), seenCommands)
	}
	if _, ok := r.seen["id-43"]; ok {
		t.Error("the oldest ids should have been evicted")
	}
	if _, ok := r.seen["id-44"]; !ok {
		t.Error("id-44 is among the newest 256 and must be remembered")
	}
	if _, ok := r.seen["id-299"]; !ok {
		t.Error("the newest id must be remembered")
	}
	r.remember("id-299") // no double bookkeeping
	if len(r.seenOrder) != seenCommands {
		t.Errorf("remembering a known id changed the bookkeeping: %d", len(r.seenOrder))
	}
}

func TestDumpStateIsRedacted(t *testing.T) {
	h := newHarness(t, hopts{})
	// A reconciler that leaked the secret into its report, as a regression
	// would: the runner must still not forward it.
	leak := reconcile.Report{
		Revision: 3, Hash: "local", Status: reconcile.StatusFailed,
		Message:          "link " + leakySecret + " refused",
		ValidationErrors: []validate.Error{{Field: "secret", Message: "bad " + leakySecret}},
		Instances: []reconcile.InstanceReport{
			{ID: "t1", State: reconcile.StateFailed, Error: "dial with " + leakySecret,
				Considered: map[string]string{"gost": "needs " + leakySecret}},
		},
	}
	h.app.applyFn = func(d spec.Desired) (reconcile.Report, error) { return leak, reconcile.ErrFailed }
	h.app.health = reconcile.HealthReport{Revision: 3, Diffs: []reconcile.Diff{{Instance: "t1", Kind: "not_running"}}}
	desired := desiredBody(3, "sha256:s", instJSON("t1", "gost", `,"secret":"`+leakySecret+`"`),
		`[{"id":"dump","type":"dump_state"}]`)
	h.panel.setConfig(func(n int, req ConfigRequest) (int, string) { return 200, desired })
	h.panel.waitCount("command-result", 1)

	r := h.panel.resultReq(0)
	if r.Status != ResultDone {
		t.Fatalf("status = %q", r.Status)
	}
	var out struct {
		Report *reconcile.Report      `json:"report"`
		Health reconcile.HealthReport `json:"health"`
	}
	if err := json.Unmarshal(r.Result, &out); err != nil {
		t.Fatalf("result is not {report, health}: %v: %s", err, r.Result)
	}
	if out.Report == nil || out.Report.Revision != 3 || out.Report.Status != reconcile.StatusFailed {
		t.Errorf("report = %+v", out.Report)
	}
	if len(out.Health.Diffs) != 1 || out.Health.Diffs[0].Kind != "not_running" {
		t.Errorf("health = %+v", out.Health)
	}
	if !strings.Contains(out.Report.Message, "***") {
		t.Errorf("the secret should be replaced by ***: %q", out.Report.Message)
	}

	// Nothing the agent sent, and nothing it logged, contains the secret.
	h.stop()
	if all := h.panel.allBodies(); strings.Contains(all, leakySecret) {
		t.Errorf("a request body contains the secret:\n%s", all)
	}
	if strings.Contains(h.log.text(), leakySecret) || strings.Contains(h.log.text(), testToken) {
		t.Errorf("the log contains a secret or the token:\n%s", h.log.text())
	}
	// The ack's report is scrubbed too.
	if ack := h.panel.ackReq(0); strings.Contains(ack.Report.Message, leakySecret) || ack.Report.Instances[0].Error == "dial with "+leakySecret {
		t.Errorf("ack report leaks: %+v", ack.Report)
	}
}

func TestDumpStateWithNothingAppliedYet(t *testing.T) {
	h := newHarness(t, hopts{})
	h.panel.setConfig(func(n int, req ConfigRequest) (int, string) {
		return 200, unchangedBody(0, `[{"id":"d0","type":"dump_state"}]`)
	})
	h.panel.waitCount("command-result", 1)
	r := h.panel.resultReq(0)
	var out map[string]json.RawMessage
	if err := json.Unmarshal(r.Result, &out); err != nil {
		t.Fatal(err)
	}
	if string(out["report"]) != "null" {
		t.Errorf("report = %s, want null", out["report"])
	}
	if _, ok := out["health"]; !ok {
		t.Error("health missing")
	}
}

func TestRefreshCommandPullsImmediately(t *testing.T) {
	h := newHarness(t, hopts{})
	h.panel.setConfig(func(n int, req ConfigRequest) (int, string) {
		if n == 1 {
			return 200, unchangedBody(0, `[{"id":"rf","type":"refresh","args":{}}]`)
		}
		return 200, unchangedBody(0, "")
	})
	// No clock is fired: the second pull can only come from the command.
	h.panel.waitCount("config", 2)
	h.panel.waitCount("command-result", 1)
	if r := h.panel.resultReq(0); r.ID != "rf" || r.Status != ResultDone {
		t.Errorf("result = %+v", r)
	}
	var res map[string]int64
	json.Unmarshal(h.panel.resultReq(0).Result, &res)
	if _, ok := res["revision"]; !ok {
		t.Errorf("refresh result = %s", h.panel.resultReq(0).Result)
	}
	// The normal cadence continues. The wait that the refresh cut short is
	// still registered with the fake clock, so wait for the next one too before
	// firing (firing releases every wait of that length).
	eventually(t, "the pull loop to wait again", func() bool { return len(h.clock.waitsCopy()) >= 3 })
	h.clock.fire(t, 10*time.Second)
	h.panel.waitCount("config", 3)
	h.stop()
	if n := h.panel.count("config"); n != 3 {
		t.Errorf("config pulled %d times, want 3", n)
	}
}

func TestRefreshFromReportWakesAPullLoopThatIsWaiting(t *testing.T) {
	h := newHarness(t, hopts{report: 40 * time.Second})
	h.panel.setReport(func(n int, req ReportRequest) (int, string) {
		return 200, `{"ok":true,"commands":[{"id":"rf2","type":"refresh"}]}`
	})
	h.panel.waitCount("config", 1)
	h.clock.fire(t, 40*time.Second)
	h.panel.waitCount("config", 2) // woken by the command, not by a 10s timer
}

func TestBackoffSequenceAndReset(t *testing.T) {
	h := newHarness(t, hopts{report: 200 * time.Second})
	want := []time.Duration{30 * time.Second, 60 * time.Second, 120 * time.Second, 240 * time.Second, 300 * time.Second, 300 * time.Second}
	// The panel answers by request ordinal: the initial pull and the six that
	// the back-off fires release fail, the next two pulls (the panel has
	// recovered) succeed, and everything after that (it broke again) fails.
	// Deciding from n, which the server assigns before the handler runs, fixes
	// the answer of a request before the test can observe it. A flag flipped
	// after waitCount("config", n) is racy instead: the server counts a request
	// before the handler reads the flag, so the flip can land between the two
	// and change the answer of the very request whose arrival the test just saw
	// (the "wait of 10s/5m0s to be armed" hang).
	firstOK, lastOK := len(want)+2, len(want)+3
	h.panel.setConfig(func(n int, req ConfigRequest) (int, string) {
		if n < firstOK || n > lastOK {
			return 503, `{"error":"unavailable","message":"try later"}`
		}
		return 200, unchangedBody(0, "")
	})
	for i, d := range want {
		h.panel.waitCount("config", i+1)
		h.clock.fire(t, d)
	}
	h.panel.waitCount("config", len(want)+1)
	h.clock.fire(t, 300*time.Second)
	h.panel.waitCount("config", len(want)+2)
	// A success resets the backoff: the next wait is the normal interval.
	h.clock.fire(t, 10*time.Second)
	h.panel.waitCount("config", len(want)+3)
	// ... and the next failure starts again at 30s instead of continuing the
	// old sequence.
	h.clock.fire(t, 10*time.Second)
	h.panel.waitCount("config", len(want)+4)
	h.clock.fire(t, 30*time.Second)
	h.panel.waitCount("config", len(want)+5)
	if h.app.applyCount() != 0 {
		t.Errorf("Apply called %d times against a failing panel", h.app.applyCount())
	}
	if h.log.count("pull failed") < len(want)+1 {
		t.Errorf("failures logged %d times: %s", h.log.count("pull failed"), h.log.text())
	}
}

func TestJitterStaysWithinTwentyPercent(t *testing.T) {
	const base = 100 * time.Second
	for _, tc := range []struct {
		rand float64
		want time.Duration
	}{{0, 80 * time.Second}, {0.5, 100 * time.Second}, {0.999999, 120 * time.Second}} {
		r, _ := NewRunner(&Client{}, &fakeApp{}, RunnerOptions{Rand: func() float64 { return tc.rand }})
		got := r.jitter(base)
		if diff := got - tc.want; diff < -time.Millisecond || diff > time.Millisecond {
			t.Errorf("jitter(rand=%v) = %v, want about %v", tc.rand, got, tc.want)
		}
	}
	// A misbehaving random source cannot push it outside the band.
	for _, bad := range []float64{-1, 1, 2} {
		r, _ := NewRunner(&Client{}, &fakeApp{}, RunnerOptions{Rand: func() float64 { return bad }})
		if got := r.jitter(base); got < 80*time.Second || got > 120*time.Second {
			t.Errorf("jitter(rand=%v) = %v out of band", bad, got)
		}
	}
	// The default source is spread over the whole band.
	r, _ := NewRunner(&Client{}, &fakeApp{}, RunnerOptions{})
	lo, hi := base*2, time.Duration(0)
	for i := 0; i < 2000; i++ {
		j := r.jitter(base)
		if j < 80*time.Second || j > 120*time.Second {
			t.Fatalf("jitter = %v", j)
		}
		lo, hi = min(lo, j), max(hi, j)
	}
	if lo > 84*time.Second || hi < 116*time.Second {
		t.Errorf("jitter spread %v..%v looks too narrow", lo, hi)
	}
}

func TestBackoffDoublesAndCaps(t *testing.T) {
	var b backoff
	var got []time.Duration
	for i := 0; i < 8; i++ {
		got = append(got, b.fail())
	}
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 5 * time.Minute, 5 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("backoff = %v, want %v", got, want)
		}
	}
	b.reset()
	if d := b.fail(); d != 30*time.Second {
		t.Errorf("after reset: %v", d)
	}
}

func TestClampInterval(t *testing.T) {
	for in, want := range map[time.Duration]time.Duration{
		0: 30 * time.Second, -5: 30 * time.Second, time.Second: 10 * time.Second, 10 * time.Second: 10 * time.Second,
		45 * time.Second: 45 * time.Second, 300 * time.Second: 300 * time.Second, time.Hour: 300 * time.Second,
	} {
		if got := ClampInterval(in); got != want {
			t.Errorf("ClampInterval(%v) = %v, want %v", in, got, want)
		}
	}
}

func TestIntervalsAreJittered(t *testing.T) {
	// rand=0 -> 0.8x: the first scheduled waits are 0.8 * interval.
	h := newHarness(t, hopts{pull: 50 * time.Second, report: 100 * time.Second, rand: func() float64 { return 0 }})
	h.panel.waitCount("config", 1)
	eventually(t, "both loops to wait", func() bool { return len(h.clock.waitsCopy()) >= 2 })
	got := map[time.Duration]bool{}
	for _, d := range h.clock.waitsCopy() {
		got[d] = true
	}
	if !got[40*time.Second] || !got[80*time.Second] {
		t.Errorf("waits = %v, want 40s (pull) and 80s (report)", h.clock.waitsCopy())
	}
}

func TestUnreachableOrFailingPanelNeverTouchesTheRunningState(t *testing.T) {
	cases := []struct {
		name   string
		config func(n int, req ConfigRequest) (int, string)
		close  bool
	}{
		{"429", func(int, ConfigRequest) (int, string) { return 429, `{"error":"rate_limited","message":"slow down"}` }, false},
		{"500", func(int, ConfigRequest) (int, string) { return 500, `{"error":"boom","message":"oops"}` }, false},
		{"503", func(int, ConfigRequest) (int, string) { return 503, `` }, false},
		{"401", func(int, ConfigRequest) (int, string) { return 401, `{"error":"bad_token","message":"no"}` }, false},
		{"garbage 200", func(int, ConfigRequest) (int, string) { return 200, `<html>captive portal</html>` }, false},
		{"truncated 200", func(int, ConfigRequest) (int, string) { return 200, `{"schema":1,"revi` }, false},
		{"closed server", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, hopts{})
			if tc.close {
				h.panel.srv.Close()
			} else {
				h.panel.setConfig(tc.config)
				h.panel.setReport(func(int, ReportRequest) (int, string) { return 500, `{"error":"x","message":"y"}` })
			}
			// Several failed rounds on both loops; the loops keep going.
			for _, d := range []time.Duration{30 * time.Second, 60 * time.Second, 120 * time.Second} {
				eventually(t, "a failure to be logged", func() bool { return h.log.count("pull failed") >= 1 })
				h.clock.fire(t, d)
			}
			eventually(t, "more failures", func() bool { return h.log.count("pull failed") >= 3 })
			if h.app.applyCount() != 0 {
				t.Fatalf("Apply was called %d times against a failing panel", h.app.applyCount())
			}
			if strings.Contains(h.log.text(), testToken) {
				t.Errorf("token in the log: %s", h.log.text())
			}
			h.stop()
		})
	}
}

func TestPanicsInTheApplierDoNotKillTheLoops(t *testing.T) {
	t.Run("apply", func(t *testing.T) {
		h := newHarness(t, hopts{})
		h.app.panicIn = "apply"
		h.panel.setConfig(func(n int, req ConfigRequest) (int, string) {
			return 200, desiredBody(1, "h", instJSON("a", "gost", ""), "")
		})
		eventually(t, "the panic to be logged", func() bool { return h.log.count("panicked") >= 1 })
		h.clock.fire(t, 30*time.Second) // the loop is alive and backing off
		h.panel.waitCount("config", 2)
	})
	t.Run("health", func(t *testing.T) {
		h := newHarness(t, hopts{report: 20 * time.Second})
		h.app.panicIn = "health"
		eventually(t, "both loops to wait", func() bool { return len(h.clock.waitsCopy()) >= 2 })
		h.clock.fire(t, 20*time.Second)
		eventually(t, "the panic to be logged", func() bool { return h.log.count("report failed") >= 1 })
		h.clock.fire(t, 30*time.Second)
		eventually(t, "the loop to retry", func() bool { return h.log.count("report failed") >= 2 })
	})
}

func TestRevisionGoingBackwardsIsAppliedWithAWarning(t *testing.T) {
	h := newHarness(t, hopts{})
	h.panel.setConfig(func(n int, req ConfigRequest) (int, string) {
		switch n {
		case 1:
			return 200, desiredBody(50, "sha256:aaa", instJSON("a", "gost", ""), "")
		case 2:
			return 200, desiredBody(40, "sha256:bbb", instJSON("b", "gost", ""), "") // restored database
		default:
			return 200, unchangedBody(40, "")
		}
	})
	h.panel.waitCount("ack", 1)
	if h.log.count("went backwards") != 0 {
		t.Error("no warning expected for the first apply")
	}
	h.clock.fire(t, 10*time.Second)
	h.panel.waitCount("ack", 2)
	if h.app.applyCount() != 2 {
		t.Fatalf("the older revision must still be applied (applies=%d)", h.app.applyCount())
	}
	if h.app.applies[1].Revision != 40 {
		t.Errorf("applied revision = %d", h.app.applies[1].Revision)
	}
	if h.log.count("WARN panel: revision went backwards (50 -> 40)") != 1 {
		t.Errorf("missing WARN: %s", h.log.text())
	}
	if ack := h.panel.ackReq(1); ack.Revision != 40 || ack.Report.Status != reconcile.StatusApplied {
		t.Errorf("ack = %+v", ack)
	}
	// have now follows the restored state.
	h.clock.fire(t, 10*time.Second)
	h.panel.waitCount("config", 3)
	if req := h.panel.configReq(2); req.HaveRevision != 40 || req.HaveHash != "sha256:bbb" {
		t.Errorf("have = %d/%q", req.HaveRevision, req.HaveHash)
	}
}

func TestLowerRevisionWithTheSameHashIsNotWarned(t *testing.T) {
	h := newHarness(t, hopts{})
	h.panel.setConfig(func(n int, req ConfigRequest) (int, string) {
		if n == 1 {
			return 200, desiredBody(50, "sha256:aaa", instJSON("a", "gost", ""), "")
		}
		return 200, desiredBody(49, "sha256:aaa", instJSON("a", "gost", ""), "")
	})
	h.panel.waitCount("ack", 1)
	h.clock.fire(t, 10*time.Second)
	h.panel.waitCount("ack", 2)
	if h.log.count("went backwards") != 0 {
		t.Errorf("unexpected warning: %s", h.log.text())
	}
}

func TestRunStopsPromptlyWhileARequestHangs(t *testing.T) {
	h := newHarness(t, hopts{noStart: true})
	h.panel.mu.Lock()
	h.panel.hanging = make(chan struct{})
	h.panel.mu.Unlock()
	h.start()
	h.panel.waitCount("config", 1) // the request is stuck inside the server
	h.stop()                       // must return anyway, and without goroutines left
	close(h.panel.hanging)
}

func TestRunStopsWhileWaiting(t *testing.T) {
	h := newHarness(t, hopts{})
	h.panel.waitCount("config", 1)
	eventually(t, "both loops to wait", func() bool { return len(h.clock.waitsCopy()) >= 2 })
	h.stop()
}

func TestInstanceIDIsRandomPerRun(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{8}$`)
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		p := newPanel(t)
		app := &fakeApp{}
		r, err := NewRunner(newClient(t, p.srv), app, RunnerOptions{Clock: newFakeClock()})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- r.Run(ctx) }()
		p.waitCount("config", 1)
		id := p.configReq(0).InstanceID
		cancel()
		<-done
		if !re.MatchString(id) {
			t.Errorf("instance id %q is not 8 hex characters", id)
		}
		seen[id] = true
	}
	if len(seen) < 2 {
		t.Errorf("instance ids repeat across runs: %v", seen)
	}
}

func TestNewRunnerRequiresItsDependencies(t *testing.T) {
	if _, err := NewRunner(nil, &fakeApp{}, RunnerOptions{}); err == nil {
		t.Error("nil API accepted")
	}
	if _, err := NewRunner(&Client{}, nil, RunnerOptions{}); err == nil {
		t.Error("nil Applier accepted")
	}
}

func TestPermanentClassification(t *testing.T) {
	for status, want := range map[int]bool{400: true, 404: true, 409: true, 422: true, 401: false, 403: false, 408: false, 429: false, 500: false, 503: false} {
		if got := permanent(&APIError{Status: status}); got != want {
			t.Errorf("permanent(%d) = %v, want %v", status, got, want)
		}
	}
	if permanent(errors.New("network down")) {
		t.Error("a network error is never permanent")
	}
	if permanent(fmt.Errorf("wrapped: %w", &APIError{Status: 429})) {
		t.Error("429 must be retried")
	}
}
