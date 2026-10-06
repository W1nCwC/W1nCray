package dispatcher

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

// ConnTracker registers the live sessions of selected inbounds so that they
// can be counted and aborted. Xray never closes accepted connections by
// itself: removing an inbound, a rule or an outbound only affects new
// connections, so established ones keep flowing until a peer or an idle timer
// ends them.
//
// Tracking is opt-in. A session is registered only when the tag of its inbound
// starts with a prefix given to Watch; with no prefix watched (the default,
// and the case for all node inbounds) the cost per Dispatch is one atomic
// load. A tracked session costs one context.WithCancel, one AfterFunc and a
// map insert/delete under a mutex.
//
// A "session" is one Dispatch/DispatchLink call: one per proxied TCP
// connection, one per UDP flow, one per mux sub-connection. Kill cancels the
// context of every session of the tag and closes the inbound connection, which
// ends TCP connections and UDP flows alike. A session whose context is never
// cancelled (internally created contexts such as reverse bridge workers)
// stays registered until it is killed.
//
// The zero value is ready to use.
type ConnTracker struct {
	prefixes atomic.Pointer[[]string] // copy-on-write; nil or empty = off

	mu   sync.Mutex
	tags map[string]*tagSessions
}

type tagSessions struct {
	total  uint64
	active map[*tracked]struct{}
}

type tracked struct {
	conn   net.Conn // inbound connection, nil for UDP flows
	cancel context.CancelFunc
}

// Watch starts tracking sessions of inbounds whose tag starts with prefix.
// It does not affect sessions that are already running. An empty prefix is
// ignored (it would track every inbound).
func (t *ConnTracker) Watch(prefix string) {
	if prefix == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	cur := t.loadPrefixes()
	for _, p := range cur {
		if p == prefix {
			return
		}
	}
	next := append(append([]string(nil), cur...), prefix)
	t.prefixes.Store(&next)
}

// Unwatch stops tracking new sessions for prefix. Sessions already tracked
// stay registered until they end or are killed; their counters of a tag
// disappear once the tag has no live session and no watched prefix.
func (t *ConnTracker) Unwatch(prefix string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	cur := t.loadPrefixes()
	next := make([]string, 0, len(cur))
	for _, p := range cur {
		if p != prefix {
			next = append(next, p)
		}
	}
	t.prefixes.Store(&next)
	for tag, ts := range t.tags {
		if len(ts.active) == 0 && !matches(next, tag) {
			delete(t.tags, tag)
		}
	}
}

func (t *ConnTracker) loadPrefixes() []string {
	if p := t.prefixes.Load(); p != nil {
		return *p
	}
	return nil
}

func matches(prefixes []string, tag string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(tag, p) {
			return true
		}
	}
	return false
}

// Active returns the number of live tracked sessions of the inbound tag.
func (t *ConnTracker) Active(tag string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if ts := t.tags[tag]; ts != nil {
		return len(ts.active)
	}
	return 0
}

// Total returns the number of sessions tracked for the inbound tag since it
// was first seen (they are not reset when sessions end).
func (t *ConnTracker) Total(tag string) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	if ts := t.tags[tag]; ts != nil {
		return ts.total
	}
	return 0
}

// Kill aborts the live tracked sessions of the inbound tag and returns how
// many there were.
func (t *ConnTracker) Kill(tag string) int {
	t.mu.Lock()
	var victims []*tracked
	if ts := t.tags[tag]; ts != nil {
		victims = collect(victims, ts)
	}
	t.mu.Unlock()
	return abort(victims)
}

// KillAll aborts every live tracked session and returns how many there were.
func (t *ConnTracker) KillAll() int {
	t.mu.Lock()
	var victims []*tracked
	for _, ts := range t.tags {
		victims = collect(victims, ts)
	}
	t.mu.Unlock()
	return abort(victims)
}

func collect(dst []*tracked, ts *tagSessions) []*tracked {
	for s := range ts.active {
		dst = append(dst, s)
	}
	return dst
}

// abort runs outside the lock: cancelling a context runs the AfterFunc that
// deregisters the session, which takes the lock again.
func abort(victims []*tracked) int {
	for _, s := range victims {
		s.cancel()
		if s.conn != nil {
			_ = s.conn.Close()
		}
	}
	return len(victims)
}

// track registers the session of ctx when its inbound is watched. It returns
// the context to pass on and a function that deregisters the session early
// (for a Dispatch that fails). Unwatched sessions get ctx and a nil function.
func (t *ConnTracker) track(ctx context.Context) (context.Context, func()) {
	prefixes := t.prefixes.Load()
	if prefixes == nil || len(*prefixes) == 0 {
		return ctx, nil
	}
	in := session.InboundFromContext(ctx)
	if in == nil || in.Tag == "" || !matches(*prefixes, in.Tag) {
		return ctx, nil
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &tracked{conn: in.Conn, cancel: cancel}
	tag := in.Tag

	t.mu.Lock()
	if t.tags == nil {
		t.tags = make(map[string]*tagSessions)
	}
	ts := t.tags[tag]
	if ts == nil {
		ts = &tagSessions{active: make(map[*tracked]struct{})}
		t.tags[tag] = ts
	}
	ts.total++
	ts.active[s] = struct{}{}
	t.mu.Unlock()

	context.AfterFunc(ctx, func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		delete(ts.active, s)
		// Drop the state of a tag that is no longer watched once idle.
		if len(ts.active) == 0 && !matches(t.loadPrefixes(), tag) && t.tags[tag] == ts {
			delete(t.tags, tag)
		}
	})
	return ctx, cancel
}
