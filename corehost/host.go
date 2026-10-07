// Package corehost adapts a running core.Core to the driver/xray Host
// interface. It is the production Host of the embedded Xray kernel: unlike the
// driver's test host, Kill and Conns work through the W1nCray connection
// tracker, so tearing an instance down also aborts its established sessions.
//
// New registers the tag prefix of the driver's instances ("w1n-fwd/") with the
// tracker. The tracker tracks nothing until a prefix is watched, so the node
// inbounds (which never use that prefix) keep costing nothing.
package corehost

import (
	"encoding/json"
	"errors"
	"sync"

	xcore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"

	"github.com/W1nCwC/W1nCray/app/routeguard"
	"github.com/W1nCwC/W1nCray/core"
	"github.com/W1nCwC/W1nCray/driver/xray"
)

// fwdPrefix is the tag prefix of every inbound and outbound the xray driver
// creates (driver/xray names.go tagRoot). Watching it enables Kill and Conns
// for forwarding instances only.
const fwdPrefix = "w1n-fwd/"

// Host implements xray.Host on top of a core.Core.
type Host struct {
	c *core.Core
}

var _ xray.Host = (*Host)(nil)

// New returns a Host backed by c, the in-process Xray instance built by
// core.New. It watches the driver's tag prefix on the connection tracker,
// which turns Kill and Conns on for the driver's instances; the instance may
// be started before or after New (Watch only affects sessions created later).
func New(c *core.Core) (xray.Host, error) {
	if c == nil {
		return nil, errors.New("corehost: nil core")
	}
	c.Conns().Watch(fwdPrefix)
	return &Host{c: c}, nil
}

// AddInbound adds an inbound handler to the instance.
func (h *Host) AddInbound(cfg *xcore.InboundHandlerConfig) error {
	return h.c.AddInbound(cfg)
}

// RemoveInbound removes an inbound handler; a missing tag is not an error.
func (h *Host) RemoveInbound(tag string) error {
	return h.c.RemoveInbound(tag)
}

// AddOutbound adds an outbound handler to the instance.
func (h *Host) AddOutbound(cfg *xcore.OutboundHandlerConfig) error {
	return h.c.AddOutbound(cfg)
}

// RemoveOutbound closes and removes an outbound handler; a missing tag is not
// an error.
func (h *Host) RemoveOutbound(tag string) error {
	return h.c.RemoveOutbound(tag)
}

// SetRules installs the head rules and balancers of the driver under tag. The
// rule manager keeps them ordered between the per-node security rules and the
// per-node fallbacks and replaces the table atomically.
func (h *Host) SetRules(tag string, head []json.RawMessage, balancers json.RawMessage) error {
	return h.c.Rules.SetNode(tag, &core.NodeRules{Head: head, Balancers: balancers})
}

// Kill aborts the live tracked sessions of an inbound tag and returns how many
// there were.
func (h *Host) Kill(inboundTag string) int {
	return h.c.Conns().Kill(inboundTag)
}

// Conns reports the active and cumulative tracked sessions of an inbound tag.
func (h *Host) Conns(inboundTag string) (active, total uint64) {
	return uint64(h.c.Conns().Active(inboundTag)), h.c.Conns().Total(inboundTag)
}

// Counter reads a named stats counter; ok is false when it does not exist.
func (h *Host) Counter(name string) (value uint64, ok bool) {
	c := h.c.Stats().GetCounter(name)
	if c == nil {
		return 0, false
	}
	return uint64(c.Value()), true
}

// DropCounter unregisters a counter.
func (h *Host) DropCounter(name string) {
	_ = h.c.Stats().UnregisterCounter(name)
}

// Dispatcher returns the dispatcher feature, used by the reverse bridge.
func (h *Host) Dispatcher() routing.Dispatcher {
	return h.c.Instance.GetFeature(routing.DispatcherType()).(routing.Dispatcher)
}

// OutboundManager returns the outbound manager feature, used by the reverse
// portal. AddHandler and RemoveHandler of the returned manager run under the
// routeguard write lock, so route selection never overlaps them; the caller
// must not call them from code that already holds that lock.
func (h *Host) OutboundManager() outbound.Manager {
	return routeguard.OutboundManager(h.c.Instance.GetFeature(outbound.ManagerType()).(outbound.Manager))
}

// ErrNoCore is returned by the Swappable methods that can report an error while
// no core is installed.
var ErrNoCore = errors.New("corehost: no xray core is attached")

// Swappable is a Host whose core can be replaced while the xray driver keeps
// running. The panel builds one, hands it to the agent once, and installs a new
// core with Swap on every xray rebuild; the driver's AddInbound/AddOutbound
// calls always reach the core that is current at the moment of the call.
//
// While no core is installed every method either returns ErrNoCore or, for the
// two methods that cannot report one, a nil feature / zero counters. A rebuild
// that detaches the core (Swap(nil)) therefore makes the driver fail cleanly
// instead of touching a closed instance.
type Swappable struct {
	mu sync.RWMutex
	c  *core.Core
}

var _ xray.Host = (*Swappable)(nil)

// NewSwappable returns an empty Swappable. It has no core until Swap installs
// one.
func NewSwappable() *Swappable { return &Swappable{} }

// Swap installs c as the current core (nil detaches it) and registers the
// driver's tag prefix on c's connection tracker. A Swap waits for every call
// that is in flight on the previous core, so once it returns the previous core
// can be closed safely.
func (h *Swappable) Swap(c *core.Core) {
	h.mu.Lock()
	h.c = c
	h.mu.Unlock()
	if c != nil {
		c.Conns().Watch(fwdPrefix)
	}
}

// Core returns the current core, or nil when none is installed.
func (h *Swappable) Core() *core.Core {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.c
}

// current returns the current core or ErrNoCore.
func (h *Swappable) current() (*core.Core, error) {
	if c := h.Core(); c != nil {
		return c, nil
	}
	return nil, ErrNoCore
}

// AddInbound adds an inbound handler to the current core.
func (h *Swappable) AddInbound(cfg *xcore.InboundHandlerConfig) error {
	c, err := h.current()
	if err != nil {
		return err
	}
	return c.AddInbound(cfg)
}

// RemoveInbound removes an inbound handler from the current core; a missing tag
// is not an error.
func (h *Swappable) RemoveInbound(tag string) error {
	c, err := h.current()
	if err != nil {
		return err
	}
	return c.RemoveInbound(tag)
}

// AddOutbound adds an outbound handler to the current core.
func (h *Swappable) AddOutbound(cfg *xcore.OutboundHandlerConfig) error {
	c, err := h.current()
	if err != nil {
		return err
	}
	return c.AddOutbound(cfg)
}

// RemoveOutbound closes and removes an outbound handler from the current core.
func (h *Swappable) RemoveOutbound(tag string) error {
	c, err := h.current()
	if err != nil {
		return err
	}
	return c.RemoveOutbound(tag)
}

// SetRules installs the head rules and balancers under tag on the current core.
func (h *Swappable) SetRules(tag string, head []json.RawMessage, balancers json.RawMessage) error {
	c, err := h.current()
	if err != nil {
		return err
	}
	return c.Rules.SetNode(tag, &core.NodeRules{Head: head, Balancers: balancers})
}

// Kill aborts the tracked sessions of an inbound tag on the current core. With
// no core there is nothing to abort.
func (h *Swappable) Kill(inboundTag string) int {
	c, err := h.current()
	if err != nil {
		return 0
	}
	return c.Conns().Kill(inboundTag)
}

// Conns reports the tracked sessions of an inbound tag on the current core.
func (h *Swappable) Conns(inboundTag string) (active, total uint64) {
	c, err := h.current()
	if err != nil {
		return 0, 0
	}
	return uint64(c.Conns().Active(inboundTag)), c.Conns().Total(inboundTag)
}

// Counter reads a named stats counter of the current core.
func (h *Swappable) Counter(name string) (value uint64, ok bool) {
	c, err := h.current()
	if err != nil {
		return 0, false
	}
	cnt := c.Stats().GetCounter(name)
	if cnt == nil {
		return 0, false
	}
	return uint64(cnt.Value()), true
}

// DropCounter unregisters a counter on the current core.
func (h *Swappable) DropCounter(name string) {
	c, err := h.current()
	if err != nil {
		return
	}
	_ = c.Stats().UnregisterCounter(name)
}

// Dispatcher returns the dispatcher feature of the current core, or nil when no
// core is installed.
func (h *Swappable) Dispatcher() routing.Dispatcher {
	c, err := h.current()
	if err != nil {
		return nil
	}
	return c.Instance.GetFeature(routing.DispatcherType()).(routing.Dispatcher)
}

// OutboundManager returns the outbound manager feature of the current core, or
// nil when no core is installed.
func (h *Swappable) OutboundManager() outbound.Manager {
	c, err := h.current()
	if err != nil {
		return nil
	}
	return routeguard.OutboundManager(c.Instance.GetFeature(outbound.ManagerType()).(outbound.Manager))
}
