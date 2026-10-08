package ws

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// mustEvent encodes an event frame for the backlog unit tests.
func mustEvent(t *testing.T, kind string) wsproto.Envelope {
	t.Helper()
	env, err := Encode(wsproto.TypeEvent, "", map[string]any{
		"kind": kind, "level": "info", "message": kind,
	})
	if err != nil {
		t.Fatalf("encode event: %v", err)
	}
	return env
}

// eventPayload decodes an "event" frame the way the panel does.
func eventPayload(t *testing.T, env wsproto.Envelope) (kind, level, message string) {
	t.Helper()
	var body struct {
		Kind    string `json:"kind"`
		Level   string `json:"level"`
		Message string `json:"message"`
	}
	decodeInto(t, env, &body)
	return body.Kind, body.Level, body.Message
}

// TestEventQueuedBeforeHandshakeIsReplayedAfterConnect is the REG3-2
// regression: the self-update watchdog's self_update.rolled_back is produced by
// a fresh process before the WebSocket is even dialed (bootstrap/remote.go
// emits it right after the ws agent is built). The sender used to consume the
// frame during the pre-hello.ok window and silently drop it, so the panel never
// saw the rollback. The event must survive that window and be replayed, in
// order, once the session is up.
func TestEventQueuedBeforeHandshakeIsReplayedAfterConnect(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	log := &recordLogger{}
	ag := newAgentUnderTest(t, ts, AgentOptions{Streams: &stubStreams{}, Log: log}, Options{})

	// Produced before Run: exactly what the rolled-back agent does at boot.
	ag.SendEvent("self_update.rolled_back", "warn",
		"version 0.6.96 was rolled back: no agent was alive for 1m0s after the update")

	runAgent(t, ag)
	tc := ts.waitConn(t)
	tc.recvType(t, wsproto.TypeHello)

	// The sender has drained the local queue while the handshake is still
	// pending. This is precisely the window in which REG3-2 lost the frame.
	waitFor(t, func() bool { return len(ag.events) == 0 }, "sender did not consume the queued event")
	if ag.Client().Connected() {
		t.Fatal("client reports a session before hello.ok")
	}

	tc.send(t, helloOKEnv(t, "session-1", 60, 60))
	waitConnected(t, ag.Client(), "session-1")

	kind, level, message := eventPayload(t, tc.recvType(t, wsproto.TypeEvent))
	if kind != "self_update.rolled_back" || level != "warn" || !strings.Contains(message, "0.6.96") {
		t.Fatalf("replayed event = %q/%q/%q, want the pre-connect self_update.rolled_back", kind, level, message)
	}
}

// TestEventQueuedWhileDisconnectedIsReplayedAfterReconnect covers the other
// half of the pre-connect window: a connection that ends while an event is
// still queued. The frame must be buffered and sent on the next session, in
// order, instead of being dropped with the dead connection's queue.
func TestEventQueuedWhileDisconnectedIsReplayedAfterReconnect(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	ag := newAgentUnderTest(t, ts, AgentOptions{Streams: &stubStreams{}}, Options{})
	runAgent(t, ag)

	tc, _ := handshake(t, ts, "session-1", 60, 60)
	waitConnected(t, ag.Client(), "session-1")

	// The panel goes away with an event still to be delivered.
	tc.closeNow()
	waitFor(t, func() bool { return !ag.Client().Connected() }, "client still reports the dropped connection as online")
	ag.SendEvent("files.applied", "info", "queued while the panel was unreachable")
	waitFor(t, func() bool { return len(ag.events) == 0 }, "sender did not consume the offline event")

	tc2, _ := handshake(t, ts, "session-2", 60, 60)
	waitConnected(t, ag.Client(), "session-2")

	kind, _, message := eventPayload(t, tc2.recvType(t, wsproto.TypeEvent))
	if kind != "files.applied" || !strings.Contains(message, "unreachable") {
		t.Fatalf("replayed event = %q/%q, want the offline files.applied", kind, message)
	}
}

// TestConnectedEventIsSentWithoutDelay pins the unchanged half of the
// behaviour: while a session is up, an event goes out immediately instead of
// waiting for a cadence tick or for a replay pass.
func TestConnectedEventIsSentWithoutDelay(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	ag := newAgentUnderTest(t, ts, AgentOptions{Streams: &stubStreams{}}, Options{})
	runAgent(t, ag)

	tc, _ := handshake(t, ts, "session-1", 60, 60)
	waitConnected(t, ag.Client(), "session-1")

	start := time.Now()
	ag.SendEvent("kernel.installed", "info", "live")
	kind, _, _ := eventPayload(t, tc.recvType(t, wsproto.TypeEvent))
	if kind != "kernel.installed" {
		t.Fatalf("event kind = %q, want kernel.installed", kind)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("a connected event took %s to reach the panel: no extra delay is allowed", elapsed)
	}
}

// TestEventBacklogDropsOldestAndCounts pins the overflow rule: the backlog is
// bounded, the oldest frame goes first, and every eviction is counted.
func TestEventBacklogDropsOldestAndCounts(t *testing.T) {
	b := &eventBacklog{limit: 4, maxTry: 2}
	var evicted []string
	for i := 0; i < 6; i++ {
		kind := fmt.Sprintf("event-%d", i)
		if old := b.push(mustEvent(t, kind)); old != nil {
			oldKind, _, _ := eventPayload(t, *old)
			evicted = append(evicted, oldKind)
		}
	}
	if got := b.length(); got != 4 {
		t.Fatalf("backlog length = %d, want 4", got)
	}
	if strings.Join(evicted, ",") != "event-0,event-1" {
		t.Fatalf("evicted %v, want the two oldest (event-0,event-1)", evicted)
	}
	if got := b.dropped.Load(); got != 2 {
		t.Fatalf("dropped counter = %d, want 2", got)
	}
}

// TestEventBacklogFlushKeepsOrderAndRetriesFailedSends covers the delivery
// rule: frames leave in order, a failed send keeps its frame at the head, and
// the retry succeeds on the next flush.
func TestEventBacklogFlushKeepsOrderAndRetriesFailedSends(t *testing.T) {
	b := &eventBacklog{limit: 8, maxTry: 3}
	for _, kind := range []string{"a", "b", "c"} {
		b.push(mustEvent(t, kind))
	}
	var sent []string
	online := false
	send := func(env wsproto.Envelope) bool {
		if !online {
			return false
		}
		kind, _, _ := eventPayload(t, env)
		sent = append(sent, kind)
		return true
	}
	if dropped := b.flush(send); len(dropped) != 0 {
		t.Fatalf("an offline flush dropped %d frames", len(dropped))
	}
	if got := b.length(); got != 3 {
		t.Fatalf("an offline flush removed frames: length = %d, want 3", got)
	}
	online = true
	if dropped := b.flush(send); len(dropped) != 0 {
		t.Fatalf("the online flush dropped %d frames", len(dropped))
	}
	if got := b.length(); got != 0 {
		t.Fatalf("backlog not drained: %d frames left", got)
	}
	if strings.Join(sent, ",") != "a,b,c" {
		t.Fatalf("delivered order = %v, want a,b,c", sent)
	}
}

// TestEventBacklogBoundsRetriesOfOneFrame pins the "no infinite retry" rule: a
// frame whose send always fails is dropped after maxTry attempts, and the
// frames queued behind it are then delivered.
func TestEventBacklogBoundsRetriesOfOneFrame(t *testing.T) {
	b := &eventBacklog{limit: 8, maxTry: 3}
	b.push(mustEvent(t, "stuck"))
	b.push(mustEvent(t, "later"))
	var sent, dropped []string
	send := func(env wsproto.Envelope) bool {
		kind, _, _ := eventPayload(t, env)
		if kind == "stuck" {
			return false
		}
		sent = append(sent, kind)
		return true
	}
	for i := 0; i < 3; i++ {
		for _, env := range b.flush(send) {
			kind, _, _ := eventPayload(t, env)
			dropped = append(dropped, kind)
		}
	}
	if strings.Join(dropped, ",") != "stuck" {
		t.Fatalf("dropped %v, want exactly the stuck frame", dropped)
	}
	if got := b.dropped.Load(); got != 1 {
		t.Fatalf("dropped counter = %d, want 1", got)
	}
	if strings.Join(sent, ",") != "later" {
		t.Fatalf("delivered %v, want the frame behind the stuck one", sent)
	}
	if got := b.length(); got != 0 {
		t.Fatalf("backlog not drained: %d frames left", got)
	}
}

// TestDroppedEventsReadsTheBacklog wires the diagnostic counter to the queue.
func TestDroppedEventsReadsTheBacklog(t *testing.T) {
	ag := &Agent{backlog: &eventBacklog{limit: 1, maxTry: 2}}
	ag.enqueueEvent(mustEvent(t, "a"))
	ag.enqueueEvent(mustEvent(t, "b"))
	if got := ag.DroppedEvents(); got != 1 {
		t.Fatalf("DroppedEvents = %d, want 1", got)
	}
}
