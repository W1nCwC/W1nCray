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
