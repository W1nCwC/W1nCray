package ws

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// capStreams is a Streams whose capability set and terminal session count the
// test controls. It is the reference the capability watchdog compares.
type capStreams struct {
	mu       sync.Mutex
	caps     []string
	sessions int
}

func (s *capStreams) HostInfo(context.Context) wsproto.HostInfo {
	return wsproto.HostInfo{Hostname: "cap-host", OS: "linux", Arch: "amd64"}
}

func (s *capStreams) Telemetry(context.Context) wsproto.Telemetry {
	return wsproto.Telemetry{TS: time.Now().Unix()}
}

func (s *capStreams) Components(context.Context) wsproto.Components {
	return wsproto.Components{TS: time.Now().Unix()}
}

func (s *capStreams) Kernels() []wsproto.KernelEntry { return nil }

func (s *capStreams) Policy() wsproto.Policy { return wsproto.Policy{} }

func (s *capStreams) Capabilities() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.caps...)
}

func (s *capStreams) TerminalSupported() bool { return true }

// TerminalSessions is the optional ws.SessionCounter extension the watchdog
// uses to avoid interrupting a live terminal.
func (s *capStreams) TerminalSessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions
}

func (s *capStreams) setCaps(caps ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.caps = append([]string(nil), caps...)
}

func (s *capStreams) setSessions(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = n
}

// fakeClock is the injectable clock of the capability throttle.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Now()} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// capSet reports whether caps contains want.
func capSet(caps []string, want string) bool {
	for _, c := range caps {
		if c == want {
			return true
		}
	}
	return false
}

// TestCanonicalCapsIsASet pins the comparison rule: hello.capabilities is a
// set, so order and repetition must not look like a change.
func TestCanonicalCapsIsASet(t *testing.T) {
	got := canonicalCaps([]string{"kernel", "telemetry", "kernel"})
	if len(got) != 2 || got[0] != "kernel" || got[1] != "telemetry" {
		t.Errorf("canonicalCaps = %v, want [kernel telemetry]", got)
	}
	if canonicalCaps(nil) != nil {
		t.Error("canonicalCaps(nil) is not nil")
	}
	if !equalCapabilities(canonicalCaps([]string{"a", "b"}), canonicalCaps([]string{"b", "a", "b"})) {
		t.Error("two spellings of the same set compare unequal")
	}
	if equalCapabilities(canonicalCaps([]string{"a"}), canonicalCaps([]string{"a", "b"})) {
		t.Error("different sets compare equal")
	}
}

// TestTerminalBusyWithoutTheOptionalInterface covers the "nil is none" rule: a
// Streams that does not implement SessionCounter, or a nil one, never defers.
func TestTerminalBusyWithoutTheOptionalInterface(t *testing.T) {
	if (&Agent{streams: &stubStreams{}}).terminalBusy() {
		t.Error("a Streams without SessionCounter reports a live terminal")
	}
	if (&Agent{}).terminalBusy() {
		t.Error("a nil Streams reports a live terminal")
	}
	if !(&Agent{streams: &capStreams{sessions: 1}}).terminalBusy() {
		t.Error("a live session was not seen")
	}
}

// TestCapabilityChangeReconnectsOnceWithTheNewHello covers the whole point of
// CAP-RESEND: a capability that becomes servable after the handshake (the
// signed kernel manifest arriving) must reach the panel. The hello is the only
// place capabilities live and the protocol allows one hello per connection, so
// the agent reconnects exactly once and the new hello carries the new set.
func TestCapabilityChangeReconnectsOnceWithTheNewHello(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	streams := &capStreams{caps: []string{wsproto.CapTelemetry}}
	log := &recordLogger{}
	ag := newAgentUnderTest(t, ts, AgentOptions{Streams: streams, Log: log}, Options{})
	runAgent(t, ag)

	_, hello1 := handshake(t, ts, "session-1", 1, 1)
	if !capSet(hello1.Capabilities, wsproto.CapTelemetry) || capSet(hello1.Capabilities, wsproto.CapKernel) {
		t.Fatalf("first hello.capabilities = %v", hello1.Capabilities)
	}
	waitConnected(t, ag.Client(), "session-1")

	// The kernel installer gets a signed manifest after the hello was sent.
	streams.setCaps(wsproto.CapTelemetry, wsproto.CapKernel)
	ag.SendEvent("test", "info", "poke the watchdog")

	_, hello2 := handshake(t, ts, "session-2", 1, 1)
	if !capSet(hello2.Capabilities, wsproto.CapKernel) {
		t.Fatalf("hello after the change = %v, want kernel", hello2.Capabilities)
	}
	if hello2.Seq <= hello1.Seq {
		t.Errorf("hello seq did not advance: %d then %d", hello1.Seq, hello2.Seq)
	}
	// The change triggers one reconnect, not a loop.
	if extra := ts.maybeConn(); extra != nil {
		t.Error("a capability change caused more than one reconnect")
	}
	if got := ts.attempts(); got != 2 {
		t.Errorf("upgrade attempts = %d, want 2", got)
	}
	// The reason is logged once, with both sets.
	line := log.all()
	if !strings.Contains(line, "capability set changed") {
		t.Errorf("no capability change line in the log:\n%s", line)
	}
	if !strings.Contains(line, "telemetry") || !strings.Contains(line, "kernel") {
		t.Errorf("the log line does not name the old and new sets:\n%s", line)
	}
}

// TestUnchangedCapabilitiesDoNotReconnect is the anti-flap half of the
// contract: the set is compared against what the last hello carried, so an
// unchanged set never closes a healthy connection.
func TestUnchangedCapabilitiesDoNotReconnect(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	streams := &capStreams{caps: []string{wsproto.CapTelemetry, wsproto.CapKernel}}
	ag := newAgentUnderTest(t, ts, AgentOptions{Streams: streams, Log: &recordLogger{}}, Options{})
	runAgent(t, ag)

	handshake(t, ts, "session-1", 1, 1)
	waitConnected(t, ag.Client(), "session-1")

	// Several cadence cycles, in a different order: the set is what matters.
	for i := 0; i < 3; i++ {
		streams.setCaps(wsproto.CapKernel, wsproto.CapTelemetry)
		ag.SendEvent("test", "info", "poke the watchdog")
	}
	time.Sleep(250 * time.Millisecond)
	if got := ts.attempts(); got != 1 {
		t.Errorf("upgrade attempts = %d, want 1 (no reconnect for an unchanged set)", got)
	}
	if !ag.Client().Connected() {
		t.Error("the client lost a healthy connection")
	}
}

// TestCapabilityChangeWaitsForTheTerminalSession covers the user-facing
// promise: a reconnect would kill the shell, so the change is published only
// once the terminal session ends.
func TestCapabilityChangeWaitsForTheTerminalSession(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	streams := &capStreams{caps: []string{wsproto.CapTelemetry}}
	streams.setSessions(1)
	ag := newAgentUnderTest(t, ts, AgentOptions{Streams: streams, Log: &recordLogger{}}, Options{})
	runAgent(t, ag)

	handshake(t, ts, "session-1", 1, 1)
	waitConnected(t, ag.Client(), "session-1")

	streams.setCaps(wsproto.CapTelemetry, wsproto.CapKernel)
	ag.SendEvent("test", "info", "poke the watchdog")
	time.Sleep(250 * time.Millisecond)
	if got := ts.attempts(); got != 1 {
		t.Errorf("upgrade attempts = %d, want 1 while a terminal session is live", got)
	}
	if !ag.Client().Connected() {
		t.Error("a live terminal session did not keep the connection")
	}

	// The shell exits: the next cycle publishes the change.
	streams.setSessions(0)
	ag.SendEvent("test", "info", "poke the watchdog")
	_, hello2 := handshake(t, ts, "session-2", 1, 1)
	if !capSet(hello2.Capabilities, wsproto.CapKernel) {
		t.Errorf("hello after the session ended = %v, want kernel", hello2.Capabilities)
	}
}

// TestCapabilityReconnectIsThrottled covers the anti-flap rate limit: a set
// that keeps changing cannot drive more than one reconnect per 30 s. The clock
// is injected so the test does not wait for real.
func TestCapabilityReconnectIsThrottled(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	streams := &capStreams{caps: []string{wsproto.CapTelemetry}}
	clk := newFakeClock()
	ag := newAgentUnderTest(t, ts, AgentOptions{Streams: streams, Log: &recordLogger{}, Now: clk.Now}, Options{})
	runAgent(t, ag)

	handshake(t, ts, "session-1", 1, 1)
	waitConnected(t, ag.Client(), "session-1")

	// First change: it reconnects.
	streams.setCaps(wsproto.CapTelemetry, wsproto.CapKernel)
	ag.SendEvent("test", "info", "poke the watchdog")
	_, hello2 := handshake(t, ts, "session-2", 1, 1)
	if !capSet(hello2.Capabilities, wsproto.CapKernel) {
		t.Fatalf("hello after the first change = %v, want kernel", hello2.Capabilities)
	}

	// Second change inside the window: it is throttled.
	streams.setCaps(wsproto.CapTelemetry, wsproto.CapKernel, wsproto.CapFiles)
	ag.SendEvent("test", "info", "poke the watchdog")
	time.Sleep(250 * time.Millisecond)
	if got := ts.attempts(); got != 2 {
		t.Fatalf("upgrade attempts = %d, want 2 (a second change must be throttled)", got)
	}
	if !ag.Client().Connected() {
		t.Error("the throttle did not keep the connection")
	}

	// Past the window the change is published.
	clk.Advance(capabilityReconnectThrottle + time.Second)
	ag.SendEvent("test", "info", "poke the watchdog")
	_, hello3 := handshake(t, ts, "session-3", 1, 1)
	if !capSet(hello3.Capabilities, wsproto.CapFiles) {
		t.Errorf("hello after the throttle window = %v, want files", hello3.Capabilities)
	}
}

// TestRequestReconnectUsesMinimumBackoff covers the transport half: a
// deliberate reconnect must not inherit a backoff that had grown over previous
// failures. The first retry is the minimum interval (1 s by default).
func TestRequestReconnectUsesMinimumBackoff(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	h := newTestHandler()
	const min = 80 * time.Millisecond
	c := newTestClient(t, ts, h, Options{
		BackoffMin: min,
		BackoffMax: 10 * time.Second,
		Rand:       func() float64 { return 0.5 }, // no jitter
	})
	runClient(t, c)

	// Three server-side drops grow the backoff to 8*min (640 ms).
	for i := 0; i < 3; i++ {
		tc, _ := handshake(t, ts, "s", 5, 15)
		waitConnected(t, c, "s")
		tc.closeNow()
		waitDisconnected(t, h)
	}

	_, _ = handshake(t, ts, "s", 5, 15)
	waitConnected(t, c, "s")
	start := time.Now()
	c.RequestReconnect("test")
	waitDisconnected(t, h)

	// The forced reconnect waits ~min, not the grown ~8*min.
	_, _ = handshake(t, ts, "s", 5, 15)
	waitConnected(t, c, "s")
	if gap := time.Since(start); gap > 4*min {
		t.Errorf("forced reconnect took %v, want about %v (the grown backoff must be discarded)", gap, min)
	}
}
