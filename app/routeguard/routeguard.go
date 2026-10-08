// Package routeguard makes run-time changes of the routing table and of the
// outbound handler set safe against route selection that is in flight.
//
// Upstream Xray assumes both are static. Router.ReloadRules empties the rule
// table and rebuilds it rule by rule while Router.PickRoute walks the same
// slice without any lock, and the outbound manager swaps its tag cache while
// balancers read it without a lock. W1nCray changes both at run time (rules
// whenever a node is added, changed or removed; outbounds whenever a
// forwarding instance comes or goes), so a connection can see a half-built
// table (for example without the rule that blocks private ranges, and fall
// through to the default outbound) or a torn slice header.
//
// The fix is one reader/writer guard:
//
//   - route selection (PickRoute) holds it for reading, so selections run
//     concurrently with each other;
//   - every change (router AddRule/RemoveRule, outbound AddHandler/
//     RemoveHandler) holds it for writing, so a selection sees the table
//     either entirely before or entirely after a change, never in between.
//
// The guard is package level on purpose: a process has exactly one Core, and
// all writers (core.RuleManager, core.Core and the wrappers built on them) must
// share the lock the dispatcher's readers use without any wiring between them.
// Two instances in one process (tests) merely serialize against each other.
//
// # Lock order and re-entrancy
//
// The guard is not re-entrant for writers. Code that runs under the write lock
// (the function passed to Mutate, and the AddRule/RemoveRule/AddHandler/
// RemoveHandler of the wrappers) must not call PickRoute, must not call
// Mutate or a wrapper mutator again, and must not block on anything that
// does. The only locks taken inside the guard are the router's and the
// outbound manager's own, always in the order guard, then upstream lock; no
// upstream code calls back into the guard while holding its own lock.
//
// A reader may nest inside a reader: when the router resolves a domain for a
// rule (domainStrategy IPOnDemand / IPIfNonMatch), a DNS-over-HTTPS/TCP/QUIC
// server is reached through the dispatcher, which selects a route again. Go's
// sync.RWMutex would deadlock there when a writer queues between the two
// reads, so the guard lets such a nested read (a context with
// GetSkipDNSResolve, which only the DNS module sets) pass a waiting writer.
// A writer never waits for a reader that waits for a writer, so this cannot
// deadlock; ordinary reads still queue behind a waiting writer, so writers do
// not starve.
//
// # Trade-off
//
// The read lock is held for the whole of PickRoute, DNS lookups included, so
// one slow lookup delays a rule change (bounded by the DNS timeout) and, while
// the change waits, new ordinary selections queue behind it. That is accepted:
// changes are rare and short, and the alternative is a half-built table.
package routeguard

import (
	"context"
	"sync"

	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
)

// guard is a reader/writer lock with writer preference whose "nested" readers
// ignore waiting writers (see the package comment).
type guard struct {
	mu             sync.Mutex
	cond           *sync.Cond
	readers        int
	writing        bool
	writersWaiting int
}

func newGuard() *guard {
	g := &guard{}
	g.cond = sync.NewCond(&g.mu)
	return g
}

// rlock takes the read lock. A nested reader waits only for an active writer.
func (g *guard) rlock(nested bool) {
	g.mu.Lock()
	for g.writing || (!nested && g.writersWaiting > 0) {
		g.cond.Wait()
	}
	g.readers++
	g.mu.Unlock()
}

func (g *guard) runlock() {
	g.mu.Lock()
	g.readers--
	if g.readers == 0 && g.writersWaiting > 0 {
		g.cond.Broadcast()
	}
	g.mu.Unlock()
}

func (g *guard) lock() {
	g.mu.Lock()
	g.writersWaiting++
	for g.writing || g.readers > 0 {
		g.cond.Wait()
	}
	g.writersWaiting--
	g.writing = true
	g.mu.Unlock()
}

func (g *guard) unlock() {
	g.mu.Lock()
	g.writing = false
	g.cond.Broadcast()
	g.mu.Unlock()
}

// shared is the process-wide guard.
var shared = newGuard()

// Mutate runs f under the write lock. f must not block for long and must obey
// the re-entrancy rules of the package comment. Use it to group several
// router/outbound-manager changes into one step that route selection cannot
// observe half-done, for example a failed rule reload followed by its restore.
func Mutate(f func() error) error {
	shared.lock()
	defer shared.unlock()
	return f()
}

// Router returns r with route selection under the read lock and rule changes
// under the write lock. Hand the result to every consumer that selects routes
// (the dispatcher). The raw router stays valid for code that already holds the
// write lock through Mutate.
func Router(r routing.Router) routing.Router {
	if r == nil {
		return nil
	}
	if g, ok := r.(*guardedRouter); ok {
		return g
	}
	return &guardedRouter{inner: r}
}

type guardedRouter struct {
	inner routing.Router
}

var _ routing.Router = (*guardedRouter)(nil)

// Type implements common.HasType.
func (r *guardedRouter) Type() interface{} { return r.inner.Type() }

// Start implements common.Runnable.
func (r *guardedRouter) Start() error { return r.inner.Start() }

// Close implements common.Closable.
func (r *guardedRouter) Close() error { return r.inner.Close() }

// PickRoute implements routing.Router under the read lock.
func (r *guardedRouter) PickRoute(ctx routing.Context) (routing.Route, error) {
	shared.rlock(ctx != nil && ctx.GetSkipDNSResolve())
	defer shared.runlock()
	return r.inner.PickRoute(ctx)
}

// ListRule implements routing.Router under the read lock.
func (r *guardedRouter) ListRule() []routing.Route {
	shared.rlock(false)
	defer shared.runlock()
	return r.inner.ListRule()
}

// AddRule implements routing.Router under the write lock.
func (r *guardedRouter) AddRule(config *serial.TypedMessage, shouldAppend bool) error {
	shared.lock()
	defer shared.unlock()
	return r.inner.AddRule(config, shouldAppend)
}

// RemoveRule implements routing.Router under the write lock.
func (r *guardedRouter) RemoveRule(tag string) error {
	shared.lock()
	defer shared.unlock()
	return r.inner.RemoveRule(tag)
}

// OutboundManager returns m with AddHandler and RemoveHandler under the write
// lock; every other method passes through. Balancers read the manager's tag
// cache inside PickRoute, which is why adding or removing a handler must
// exclude route selection.
func OutboundManager(m outbound.Manager) outbound.Manager {
	if m == nil {
		return nil
	}
	if g, ok := m.(*guardedManager); ok {
		return g
	}
	return &guardedManager{Manager: m}
}

type guardedManager struct {
	outbound.Manager
}

var (
	_ outbound.Manager         = (*guardedManager)(nil)
	_ outbound.HandlerSelector = (*guardedManager)(nil)
)

// AddHandler implements outbound.Manager under the write lock. The handler's
// Start runs inside the lock (the manager starts it there), so a handler must
// not dispatch from Start.
func (m *guardedManager) AddHandler(ctx context.Context, h outbound.Handler) error {
	shared.lock()
	defer shared.unlock()
	return m.Manager.AddHandler(ctx, h)
}

// RemoveHandler implements outbound.Manager under the write lock. It only
// forgets the handler; closing it is the caller's job and belongs outside the
// lock.
func (m *guardedManager) RemoveHandler(ctx context.Context, tag string) error {
	shared.lock()
	defer shared.unlock()
	return m.Manager.RemoveHandler(ctx, tag)
}

// Select implements outbound.HandlerSelector. It is the call balancers make
// inside PickRoute, so it reads as a nested reader.
func (m *guardedManager) Select(selectors []string) []string {
	s, ok := m.Manager.(outbound.HandlerSelector)
	if !ok {
		return nil
	}
	shared.rlock(true)
	defer shared.runlock()
	return s.Select(selectors)
}
