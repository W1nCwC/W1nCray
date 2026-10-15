package ws

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/wsproto"
	"github.com/W1nCwC/W1nCray/agent/xrayapi"
)

// fakeAuditSource is the kernel side of the audit stream: the test controls
// what the kernel reports, which pages it serves and what the agent wrote to
// its switch.
type fakeAuditSource struct {
	mu sync.Mutex
	// supported is the kernel's status bit.
	supported bool
	// supportErr makes Supported fail (a kernel that is not up yet).
	supportErr error
	// pages are handed out in order; a request past the end gets an empty page
	// at the last epoch.
	pages []xrayapi.AuditBatch
	// calls counts every Batch attempt (including a failing one) and served
	// counts the answers handed out, so a test can tell "asked" from "served".
	calls  int
	served int
	// after/max are the parameters of the last pull.
	after uint64
	max   int
	// enabled is the kernel's switch as the agent set it.
	enabled bool
	// setCalls counts SetEnabled calls, and setErr fails them.
	setCalls int
	setErr   error
	// batchErr fails Batch.
	batchErr error
}

func (f *fakeAuditSource) Supported(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.supportErr != nil {
		return false, f.supportErr
	}
	return f.supported, nil
}

func (f *fakeAuditSource) Batch(_ context.Context, after uint64, max int) (AuditPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// The attempt is counted before the failure, so a test can prove how often
	// the agent asked.
	f.calls++
	f.after, f.max = after, max
	if f.batchErr != nil {
		return AuditPage{}, f.batchErr
	}
	if !f.supported {
		return AuditPage{}, nil
	}
	i := f.served
	f.served++
	var batch xrayapi.AuditBatch
	switch {
	case i < len(f.pages):
		batch = f.pages[i]
	case len(f.pages) > 0:
		batch = xrayapi.AuditBatch{Epoch: f.pages[len(f.pages)-1].Epoch, Items: []xrayapi.AuditItem{}}
	default:
		batch = xrayapi.AuditBatch{Items: []xrayapi.AuditItem{}}
	}
	return AuditPage{Batch: batch, Supported: true}, nil
}

func (f *fakeAuditSource) SetEnabled(_ context.Context, enabled bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setCalls++
	if f.setErr != nil {
		return f.setErr
	}
	f.enabled = enabled
	return nil
}

func (f *fakeAuditSource) setSupported(v bool) {
	f.mu.Lock()
	f.supported = v
	f.mu.Unlock()
}

func (f *fakeAuditSource) state() (supported, enabled bool, setCalls, calls int, after uint64, max int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.supported, f.enabled, f.setCalls, f.calls, f.after, f.max
}

func (f *fakeAuditSource) page(i int) xrayapi.AuditBatch {
	f.mu.Lock()
	defer f.mu.Unlock()
	if i >= len(f.pages) {
		return xrayapi.AuditBatch{}
	}
	return f.pages[i]
}

// setPages replaces the pages the kernel serves (used to model a restart).
func (f *fakeAuditSource) setPages(pages ...xrayapi.AuditBatch) {
	f.mu.Lock()
	f.pages = pages
	f.served = 0
	f.mu.Unlock()
}

// auditStreams is a Streams that publishes the audit capability the way
// bootstrap's runtimeStreams does: the audit loop reports the kernel's support
// bit, and Capabilities reads it. Without that sink the agent would have no way
// to declare the capability at all.
type auditStreams struct {
	capStreams
	mu        sync.Mutex
	supported bool
}

func newAuditStreams() *auditStreams {
	return &auditStreams{capStreams: capStreams{caps: []string{wsproto.CapTelemetry}}}
}

func (s *auditStreams) SetAuditSupported(supported bool) {
	s.mu.Lock()
	s.supported = supported
	s.mu.Unlock()
}

func (s *auditStreams) Capabilities() []string {
	s.mu.Lock()
	supported := s.supported
	s.mu.Unlock()
	caps := []string{wsproto.CapTelemetry}
	if supported {
		caps = append(caps, wsproto.CapAudit)
	}
	return caps
}

// auditPage builds one kernel page of n lines.
func auditPage(epoch int64, from uint64, n int) xrayapi.AuditBatch {
	items := make([]xrayapi.AuditItem, 0, n)
	for i := 0; i < n; i++ {
		items = append(items, xrayapi.AuditItem{
			T: 1700000000000 + int64(i),
			L: fmt.Sprintf("accepted tcp:10.0.0.1:%d [inbound >>> node-1] email=user%d", 10000+i, i),
		})
	}
	return xrayapi.AuditBatch{
		Epoch:   epoch,
		FromSeq: from,
		ToSeq:   from + uint64(n) - 1,
		Items:   items,
	}
}

// auditInterval is the pull cadence the audit tests use. It is far below the
// production 3 s so a case does not sleep for real; the loop's own rules (one
// page per tick, five frames per second) are unchanged.
const auditInterval = 20 * time.Millisecond

// newAuditAgent wires an Agent with the audit source against the test server.
func newAuditAgent(t *testing.T, ts *testServer, src AuditSource) *Agent {
	t.Helper()
	return newAgentUnderTest(t, ts, AgentOptions{
		Streams:           newAuditStreams(),
		Audit:             src,
		AuditPullInterval: auditInterval,
		Log:               &recordLogger{},
	}, Options{})
}

// helloOKAudit builds the panel's hello.ok with an explicit audit switch.
func helloOKAudit(t *testing.T, session string, enabled bool) wsproto.Envelope {
	t.Helper()
	env, err := Encode(wsproto.TypeHelloOK, "", wsproto.HelloOK{
		ServerTime: time.Now().Unix(),
		Intervals:  wsproto.Intervals{TelemetryS: 1, ComponentsS: 1},
		Session:    session,
		Audit:      &wsproto.AuditCtl{Enabled: enabled},
	})
	if err != nil {
		t.Fatalf("encode hello.ok: %v", err)
	}
	return env
}

// waitNoAudit fails when an audit.log frame arrives within d. It is how the
// tests assert "nothing is sent" without racing a fixed sleep.
func waitNoAudit(t *testing.T, tc *testConn, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		tc.mu.Lock()
		raw := tc.raw
		tc.raw = nil
		tc.mu.Unlock()
		for _, r := range raw {
			env := decodeFrame(t, r)
			if env.T == wsproto.TypeAuditLog {
				t.Fatalf("an audit.log frame was sent when it should not be: %s", env.D)
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestAuditOffByDefaultPullsNothingAndSendsNothing is the default state: a
// panel that never mentions audit gets no frame, and the kernel is never
// touched.
func TestAuditOffByDefaultPullsNothingAndSendsNothing(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	src := &fakeAuditSource{supported: true, pages: []xrayapi.AuditBatch{auditPage(1000, 1, 3)}}
	ag := newAuditAgent(t, ts, src)
	runAgent(t, ag)

	tc, _ := handshake(t, ts, "session-1", 1, 1)
	waitNoAudit(t, tc, 200*time.Millisecond)

	if _, enabled, setCalls, calls, _, _ := src.state(); enabled || setCalls != 0 || calls != 0 {
		t.Errorf("audit was touched while off: enabled=%v setCalls=%d pulls=%d", enabled, setCalls, calls)
	}
}

// TestAuditEnabledByHelloOKSendsMappedFrames covers the happy path: the panel's
// hello.ok turns the kernel's collection on and every page reaches it as an
// audit.log frame with the kernel's sequence numbers and lines.
func TestAuditEnabledByHelloOKSendsMappedFrames(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	page := auditPage(1000, 41, 2)
	page.Dropped = 3
	src := &fakeAuditSource{supported: true, pages: []xrayapi.AuditBatch{page}}
	ag := newAuditAgent(t, ts, src)
	runAgent(t, ag)

	tc := ts.waitConn(t)
	helloEnv := tc.recvType(t, wsproto.TypeHello)
	var hello wsproto.Hello
	decodeInto(t, helloEnv, &hello)
	if !capSet(hello.Capabilities, wsproto.CapAudit) {
		t.Fatalf("hello.capabilities = %v, want the audit capability", hello.Capabilities)
	}
	tc.send(t, helloOKAudit(t, "session-1", true))

	env := tc.recvType(t, wsproto.TypeAuditLog)
	var got wsproto.AuditLog
	decodeInto(t, env, &got)
	if got.Epoch != 1000 || got.FromSeq != 41 || got.ToSeq != 42 || got.Dropped != 3 {
		t.Errorf("audit.log = %+v, want epoch 1000, 41..42, dropped 3", got)
	}
	if len(got.Items) != 2 || got.Items[0].T != 1700000000000 || !strings.Contains(got.Items[0].L, "accepted tcp:") {
		t.Errorf("audit.log items = %+v", got.Items)
	}

	// The kernel's switch was written exactly once, and the cursor is the
	// page's ToSeq on the next pull.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, enabled, setCalls, _, _, _ := src.state(); enabled && setCalls >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	_, enabled, setCalls, _, after, _ := src.state()
	if !enabled || setCalls < 1 {
		t.Errorf("kernel switch: enabled=%v setCalls=%d, want true/at least 1", enabled, setCalls)
	}
	if after != 42 {
		t.Errorf("next pull after=%d, want the page's ToSeq 42", after)
	}
}

// TestAuditPullCadenceIsOnePagePerTick pins the pull tick: with more=false the
// loop asks once per tick, not in a spin.
func TestAuditPullCadenceIsOnePagePerTick(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	src := &fakeAuditSource{supported: true}
	src.setPages(auditPage(1000, 1, 1), auditPage(1000, 2, 1), auditPage(1000, 3, 1))
	ag := newAuditAgent(t, ts, src)
	runAgent(t, ag)

	tc, _ := handshake(t, ts, "session-1", 1, 1)
	tc.send(t, helloOKAudit(t, "session-1", true))
	tc.recvType(t, wsproto.TypeAuditLog)

	// Within a fraction of the tick only the first page can have been pulled;
	// after a few ticks all three are out.
	time.Sleep(auditInterval / 4)
	if _, _, _, calls, _, _ := src.state(); calls > 2 {
		t.Errorf("pulls = %d within a quarter tick, want at most 2", calls)
	}
	tc.recvType(t, wsproto.TypeAuditLog)
	tc.recvType(t, wsproto.TypeAuditLog)
}

// TestAuditMorePullsAgainImmediately covers the kernel's more=true hint: the
// agent does not wait for the next tick to drain a backlog.
func TestAuditMorePullsAgainImmediately(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	first := auditPage(1000, 1, 1)
	first.More = true
	src := &fakeAuditSource{supported: true}
	src.setPages(first, auditPage(1000, 2, 1))
	ag := newAuditAgent(t, ts, src)
	runAgent(t, ag)

	tc, _ := handshake(t, ts, "session-1", 1, 1)
	tc.send(t, helloOKAudit(t, "session-1", true))

	// Both pages come out without waiting for a second pull tick: more=true is
	// what makes the loop pull the second page in the same iteration, and the
	// contract's frame rate cap is the only thing between the two frames.
	env := tc.recvType(t, wsproto.TypeAuditLog)
	var firstFrame wsproto.AuditLog
	decodeInto(t, env, &firstFrame)
	env = tc.recvType(t, wsproto.TypeAuditLog)
	var second wsproto.AuditLog
	decodeInto(t, env, &second)
	if firstFrame.FromSeq != 1 || second.FromSeq != 2 {
		t.Errorf("frames = %+v / %+v, want from_seq 1 then 2", firstFrame, second)
	}
	if _, _, _, calls, _, _ := src.state(); calls < 2 {
		t.Errorf("pulls = %d, want the second page to have been pulled without waiting for a tick", calls)
	}
}

// TestAuditFrameRateIsCappedAtFivePerSecond pins the contract's send cap: a
// kernel with an endless backlog is drained at five frames per second, not as
// fast as the queue accepts them.
func TestAuditFrameRateIsCappedAtFivePerSecond(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	src := &fakeAuditSource{supported: true}
	pages := make([]xrayapi.AuditBatch, 0, 8)
	for i := 0; i < 8; i++ {
		p := auditPage(1000, uint64(i*10+1), 1)
		p.More = true
		pages = append(pages, p)
	}
	src.setPages(pages...)
	ag := newAuditAgent(t, ts, src)
	runAgent(t, ag)

	tc, _ := handshake(t, ts, "session-1", 1, 1)
	start := time.Now()
	tc.send(t, helloOKAudit(t, "session-1", true))
	for i := 0; i < 6; i++ {
		tc.recvType(t, wsproto.TypeAuditLog)
	}
	if elapsed := time.Since(start); elapsed < 900*time.Millisecond {
		t.Errorf("six frames took %s, want at least ~1 s (five per second)", elapsed)
	}
}

// TestAuditStopsWhileTheSocketIsDown covers the offline rule: no pull and no
// frame while there is no session, so nothing accumulates in the agent (the
// kernel's own buffer and its dropped counter are the loss).
func TestAuditStopsWhileTheSocketIsDown(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	src := &fakeAuditSource{supported: true}
	src.setPages(auditPage(1000, 1, 1), auditPage(1000, 2, 1), auditPage(1000, 3, 1))
	ag := newAuditAgent(t, ts, src)
	runAgent(t, ag)

	tc, _ := handshake(t, ts, "session-1", 1, 1)
	tc.send(t, helloOKAudit(t, "session-1", true))
	tc.recvType(t, wsproto.TypeAuditLog)

	// The panel goes away: the agent must stop pulling and stop sending. The
	// reconnected session says nothing about audit, so the stream stays off:
	// the panel is the authority.
	tc.closeNow()
	tc2 := ts.waitConn(t)
	env := tc2.recvType(t, wsproto.TypeHello)
	var hello wsproto.Hello
	decodeInto(t, env, &hello)
	pulled := func() int {
		_, _, _, calls, _, _ := src.state()
		return calls
	}
	before := pulled()
	waitNoAudit(t, tc2, 200*time.Millisecond)
	if after := pulled(); after != before {
		t.Errorf("pulls after the reconnect = %d, want %d (nothing is pulled while the panel is silent)", after, before)
	}
}

// TestAuditStopsAfterThePanelRejectsTheFrame covers the protocol answer: a
// panel that does not know audit.log answers unknown_type, and the agent stops
// for the rest of the session instead of repeating the error.
func TestAuditStopsAfterThePanelRejectsTheFrame(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	src := &fakeAuditSource{supported: true}
	pages := make([]xrayapi.AuditBatch, 0, 20)
	for i := 0; i < 20; i++ {
		pages = append(pages, auditPage(1000, uint64(i+1), 1))
	}
	src.setPages(pages...)
	ag := newAuditAgent(t, ts, src)
	runAgent(t, ag)

	tc, _ := handshake(t, ts, "session-1", 1, 1)
	tc.send(t, helloOKAudit(t, "session-1", true))
	tc.recvType(t, wsproto.TypeAuditLog)

	tc.sendType(t, wsproto.TypeError, "", wsproto.ErrorBody{
		Code:    wsproto.ErrCodeUnknownType,
		Message: "unknown message type audit.log",
	})
	// The frame is already in flight; once the agent has seen the error it
	// must stop sending.
	time.Sleep(2 * auditInterval)
	waitNoAudit(t, tc, 200*time.Millisecond)
}

// TestAuditCapabilityAppearsWhenTheKernelSaysItSupportsIt covers the
// declaration rule: no capability for a kernel that predates the collector, and
// a reconnect carrying it once the audit loop reports the kernel's support bit.
// The reconnect is the protocol's only way to publish a capability that became
// true after the handshake, and the loop is what reports it (the same call
// bootstrap's Streams reads).
func TestAuditCapabilityAppearsWhenTheKernelSaysItSupportsIt(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	src := &fakeAuditSource{supported: false}
	ag := newAuditAgent(t, ts, src)
	runAgent(t, ag)

	tc, hello := handshake(t, ts, "session-1", 1, 1)
	if capSet(hello.Capabilities, wsproto.CapAudit) {
		t.Fatalf("hello.capabilities = %v, want no audit capability", hello.Capabilities)
	}
	if ag.AuditSupported() {
		t.Fatal("AuditSupported() = true for a kernel that reports no collector")
	}
	_ = tc

	// The kernel now reports the collector (an upgrade, or a kernel that was
	// installed while the agent ran). The audit loop publishes it, which is
	// what makes the capability watchdog reconnect with a fresh hello.
	src.setSupported(true)
	ag.setAuditSupport(true)
	tc2 := ts.waitConn(t)
	env := tc2.recvType(t, wsproto.TypeHello)
	var hello2 wsproto.Hello
	decodeInto(t, env, &hello2)
	if !capSet(hello2.Capabilities, wsproto.CapAudit) {
		t.Fatalf("reconnected hello.capabilities = %v, want the audit capability", hello2.Capabilities)
	}
	if !ag.AuditSupported() {
		t.Error("AuditSupported() = false after the kernel reported the collector")
	}
}

// TestAuditEpochChangeReEnablesTheKernel covers the restart rule: a new kernel
// epoch means the switch is off again and the cursor belongs to a dead process,
// so the agent enables it once more and starts from the kernel's position.
func TestAuditEpochChangeReEnablesTheKernel(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	src := &fakeAuditSource{supported: true}
	src.setPages(auditPage(1000, 1, 1))
	ag := newAuditAgent(t, ts, src)
	runAgent(t, ag)

	tc, _ := handshake(t, ts, "session-1", 1, 1)
	tc.send(t, helloOKAudit(t, "session-1", true))
	tc.recvType(t, wsproto.TypeAuditLog)

	// The kernel restarted: a new epoch and a fresh sequence space.
	src.setPages(auditPage(2000, 1, 1))
	deadline := time.Now().Add(2 * time.Second)
	var second wsproto.AuditLog
	for time.Now().Before(deadline) {
		env := tc.recvType(t, wsproto.TypeAuditLog)
		decodeInto(t, env, &second)
		if second.Epoch == 2000 {
			break
		}
	}
	if second.Epoch != 2000 || second.FromSeq != 1 {
		t.Fatalf("frame after the restart = %+v, want epoch 2000 from_seq 1", second)
	}
	_, _, setCalls, _, _, _ := src.state()
	if setCalls < 2 {
		t.Errorf("SetEnabled calls = %d, want the enable to be re-sent after the epoch change", setCalls)
	}
}

// TestAuditCommandTurnsTheStreamOnAndOff covers the command path (audit_ctl):
// it enables without a hello.ok field, and disabling stops the frames.
func TestAuditCommandTurnsTheStreamOnAndOff(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	src := &fakeAuditSource{supported: true}
	pages := make([]xrayapi.AuditBatch, 0, 20)
	for i := 0; i < 20; i++ {
		pages = append(pages, auditPage(1000, uint64(i+1), 1))
	}
	src.setPages(pages...)
	ag := newAuditAgent(t, ts, src)
	runAgent(t, ag)

	tc, _ := handshake(t, ts, "session-1", 1, 1)
	// The panel says nothing about audit; the command turns it on.
	if !ag.SetAuditEnabled(true) {
		t.Fatal("SetAuditEnabled(true) reported off")
	}
	tc.recvType(t, wsproto.TypeAuditLog)
	if !ag.AuditEnabled() {
		t.Error("AuditEnabled() = false after the command")
	}

	if ag.SetAuditEnabled(false) {
		t.Error("SetAuditEnabled(false) reported on")
	}
	// Drain what was already in flight, then assert silence.
	time.Sleep(2 * auditInterval)
	waitNoAudit(t, tc, 200*time.Millisecond)
	_, enabled, _, _, _, _ := src.state()
	if enabled {
		t.Error("the kernel's switch is still on after audit_ctl{enabled:false}")
	}
}

// TestAuditPullFailureBacksOffAndKeepsTelemetry covers the failure rule: a
// kernel that cannot be read is retried with a growing delay instead of every
// tick, and the failure never touches the telemetry cadence.
func TestAuditPullFailureBacksOffAndKeepsTelemetry(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	src := &fakeAuditSource{supported: true, batchErr: errors.New("kernel is restarting")}
	ag := newAuditAgent(t, ts, src)
	runAgent(t, ag)

	tc, _ := handshake(t, ts, "session-1", 1, 1)
	tc.send(t, helloOKAudit(t, "session-1", true))

	// The first failure arms a one-second back-off, so only one request may
	// reach the kernel even after several ticks.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, _, calls, _, _ := src.state(); calls >= 1 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	time.Sleep(4 * auditInterval)
	if _, _, _, calls, _, _ := src.state(); calls != 1 {
		t.Errorf("pull attempts = %d during the back-off, want exactly 1", calls)
	}

	// Telemetry still flows: a failing audit stream must not disturb it.
	tc.recvType(t, wsproto.TypeTelemetry)
}

// TestAuditCursorDoesNotMoveWhenTheSendFails covers the cursor rule: the cursor
// only moves when the frame really entered the transport. The outbound queue is
// filled directly, which is the deterministic way to reach ErrQueueFull, and
// the assertion is written as the invariant (cursor moved if and only if the
// frame was queued) so it holds whether or not the writer drained a slot in
// between.
func TestAuditCursorDoesNotMoveWhenTheSendFails(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	src := &fakeAuditSource{supported: true}
	src.setPages(auditPage(1000, 41, 1), auditPage(1000, 42, 1))
	ag := newAuditAgent(t, ts, src)
	runAgent(t, ag)

	tc, _ := handshake(t, ts, "session-1", 1, 1)
	// The server stops reading, so the writer stalls and the outbound queue
	// can be filled; the audit loop is not told about audit at all, so it is
	// the test that drives the pull and the send.
	tc.pauseReading()
	env, err := Encode(wsproto.TypeTelemetry, "", wsproto.Telemetry{TS: time.Now().Unix()})
	if err != nil {
		t.Fatalf("encode telemetry: %v", err)
	}
	full := false
	for i := 0; i < 4*DefaultQueueSize; i++ {
		if ag.Client().Send(env) == ErrQueueFull {
			full = true
			break
		}
	}
	if !full {
		t.Fatal("the outbound queue never reported being full")
	}

	// Pull one page and try to send it. pullAudit reports "pull again" (the
	// kernel's more flag), so the queued page is what says the pull happened.
	ag.pullAudit(context.Background())
	ag.auditMu.Lock()
	pending := ag.audit.pending
	ag.auditMu.Unlock()
	if pending == nil {
		t.Fatal("pullAudit queued nothing")
	}
	queued := ag.sendPendingAudit()

	ag.auditMu.Lock()
	cursor := ag.audit.cursor
	still := ag.audit.pending
	ag.auditMu.Unlock()
	if queued {
		// The writer had drained a slot: the frame was accepted, and only then
		// may the cursor have moved.
		if cursor != pending.ToSeq {
			t.Errorf("cursor = %d after the frame was queued, want %d", cursor, pending.ToSeq)
		}
		if still != nil {
			t.Errorf("a page is still pending after a successful send: %+v", still)
		}
		return
	}
	// The queue refused the frame: the cursor must not move and the page must
	// be kept for the retry.
	if cursor != 0 {
		t.Errorf("cursor = %d after a refused send, want 0", cursor)
	}
	if still == nil {
		t.Fatal("the refused page was dropped instead of kept")
	}
	if still.FromSeq != 41 {
		t.Errorf("pending page from_seq = %d, want 41", still.FromSeq)
	}

	// The queue accepts it again once it has room: the very page that was
	// refused is what leaves, and only then does the cursor move.
	tc.paused.Store(false)
	for {
		ag.auditMu.Lock()
		done := ag.audit.pending == nil
		ag.auditMu.Unlock()
		if done {
			break
		}
		ag.sendPendingAudit()
		time.Sleep(2 * time.Millisecond)
	}
	ag.auditMu.Lock()
	cursor = ag.audit.cursor
	ag.auditMu.Unlock()
	if cursor != 41 {
		t.Errorf("cursor = %d after the page was accepted, want 41", cursor)
	}
}
