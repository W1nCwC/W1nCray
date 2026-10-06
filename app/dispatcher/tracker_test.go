package dispatcher

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/session"
)

func inboundCtx(tag string, conn net.Conn) context.Context {
	return session.ContextWithInbound(context.Background(), &session.Inbound{Tag: tag, Conn: conn})
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timeout waiting for %s", what)
}

func TestTrackerOffByDefault(t *testing.T) {
	var tr ConnTracker
	ctx := inboundCtx("fwd-1", nil)
	got, untrack := tr.track(ctx)
	if got != ctx || untrack != nil {
		t.Fatal("an unwatched tracker must hand the context back untouched")
	}
	if tr.Active("fwd-1") != 0 || tr.Total("fwd-1") != 0 || tr.Kill("fwd-1") != 0 || tr.KillAll() != 0 {
		t.Fatal("empty tracker reports sessions")
	}
	tr.Watch("") // ignored: would track everything
	if _, untrack := tr.track(ctx); untrack != nil {
		t.Fatal("empty prefix enabled tracking")
	}
}

func TestTrackerWatchPrefix(t *testing.T) {
	var tr ConnTracker
	tr.Watch("fwd-")
	if _, untrack := tr.track(inboundCtx("node-1", nil)); untrack != nil {
		t.Fatal("tag outside the watched prefix was tracked")
	}
	if _, untrack := tr.track(context.Background()); untrack != nil {
		t.Fatal("context without inbound was tracked")
	}
	ctx, untrack := tr.track(inboundCtx("fwd-1", nil))
	if untrack == nil || ctx.Err() != nil {
		t.Fatal("watched tag was not tracked")
	}
	if tr.Active("fwd-1") != 1 || tr.Total("fwd-1") != 1 || tr.Active("node-1") != 0 {
		t.Fatalf("counters: active=%d total=%d", tr.Active("fwd-1"), tr.Total("fwd-1"))
	}
	// Deregistering early (a failed Dispatch) frees the slot but keeps Total.
	untrack()
	eventually(t, "deregistration", func() bool { return tr.Active("fwd-1") == 0 })
	if tr.Total("fwd-1") != 1 {
		t.Fatalf("total = %d, want 1", tr.Total("fwd-1"))
	}
}

func TestTrackerDeregistersWhenContextEnds(t *testing.T) {
	var tr ConnTracker
	tr.Watch("fwd-")
	parent, end := context.WithCancel(inboundCtx("fwd-1", nil))
	tr.track(parent)
	tr.track(parent)
	if tr.Active("fwd-1") != 2 {
		t.Fatalf("active = %d, want 2", tr.Active("fwd-1"))
	}
	end() // the inbound finished the connection
	eventually(t, "sessions to deregister", func() bool { return tr.Active("fwd-1") == 0 })
	if tr.Total("fwd-1") != 2 {
		t.Fatalf("total = %d, want 2", tr.Total("fwd-1"))
	}
}

func TestTrackerKill(t *testing.T) {
	var tr ConnTracker
	tr.Watch("fwd-")
	a1, a2 := net.Pipe()
	defer a2.Close()
	b1, b2 := net.Pipe()
	defer b2.Close()
	ctxA, _ := tr.track(inboundCtx("fwd-a", a1))
	ctxB, _ := tr.track(inboundCtx("fwd-b", b1))

	if n := tr.Kill("fwd-a"); n != 1 {
		t.Fatalf("Kill = %d, want 1", n)
	}
	if ctxA.Err() == nil {
		t.Fatal("killed session context not cancelled")
	}
	// The peer of the killed connection sees EOF/closed pipe.
	a2.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := a2.Read(make([]byte, 1)); err == nil {
		t.Fatal("killed connection still open")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("killed connection was not closed: %v", err)
	}
	if ctxB.Err() != nil {
		t.Fatal("Kill touched another tag")
	}
	eventually(t, "deregistration", func() bool { return tr.Active("fwd-a") == 0 })
	if tr.Active("fwd-b") != 1 || tr.Total("fwd-a") != 1 {
		t.Fatalf("counters after Kill: b=%d totalA=%d", tr.Active("fwd-b"), tr.Total("fwd-a"))
	}
	if n := tr.Kill("fwd-a"); n != 0 {
		t.Fatalf("second Kill = %d, want 0", n)
	}

	if n := tr.KillAll(); n != 1 {
		t.Fatalf("KillAll = %d, want 1", n)
	}
	if ctxB.Err() == nil {
		t.Fatal("KillAll did not cancel the session")
	}
	eventually(t, "deregistration", func() bool { return tr.Active("fwd-b") == 0 })
}

func TestTrackerUnwatchForgetsIdleTags(t *testing.T) {
	var tr ConnTracker
	tr.Watch("fwd-")
	ctx, _ := tr.track(inboundCtx("fwd-1", nil))
	tr.Unwatch("fwd-")
	if _, untrack := tr.track(inboundCtx("fwd-2", nil)); untrack != nil {
		t.Fatal("tracking continued after Unwatch")
	}
	if tr.Active("fwd-1") != 1 {
		t.Fatal("Unwatch dropped a live session")
	}
	tr.Kill("fwd-1")
	<-ctx.Done()
	eventually(t, "state of the idle tag to disappear", func() bool {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		return len(tr.tags) == 0
	})
}

// The hot path with nothing watched: one atomic load.
func BenchmarkTrackOff(b *testing.B) {
	var tr ConnTracker
	ctx := inboundCtx("node-1", nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tr.track(ctx)
	}
}

// A watched tag: context + AfterFunc + map insert/delete per session.
func BenchmarkTrackOn(b *testing.B) {
	var tr ConnTracker
	tr.Watch("fwd-")
	parent := inboundCtx("fwd-1", nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, untrack := tr.track(parent)
		untrack()
	}
}

// Inbound that is not watched while another prefix is: prefix scan only.
func BenchmarkTrackUnmatched(b *testing.B) {
	var tr ConnTracker
	tr.Watch("fwd-")
	ctx := inboundCtx("node-1", nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tr.track(ctx)
	}
}
