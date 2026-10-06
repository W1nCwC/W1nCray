package xray

import (
	"encoding/json"

	xcore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
)

// Host is what the driver needs from the running Xray instance. It mirrors
// the methods of core.Core (AddInbound, RemoveInbound, AddOutbound,
// RemoveOutbound), core.RuleManager (SetRules is SetNode with the driver's
// rules and balancers) and the dispatcher's ConnTracker (Kill, Conns), so the
// main program adapts core.Core with a few one-line methods.
//
// Contract the driver relies on:
//   - RemoveOutbound closes the handler (stops a freedom/vless handler's
//     background work) and a missing tag is not an error; likewise for
//     RemoveInbound.
//   - SetRules replaces the rules and balancers registered under tag
//     atomically; on failure the previous table is still in force.
//   - Kill closes every established connection that entered through the
//     inbound tag and returns how many it closed.
type Host interface {
	AddInbound(cfg *xcore.InboundHandlerConfig) error
	RemoveInbound(tag string) error
	AddOutbound(cfg *xcore.OutboundHandlerConfig) error
	RemoveOutbound(tag string) error

	// SetRules installs head rules (evaluated before the global rules) and
	// the balancers (a JSON array as in the "balancers" key of Xray's
	// routing object) under the node tag.
	SetRules(tag string, head []json.RawMessage, balancers json.RawMessage) error

	// Kill closes the established connections of an inbound tag.
	Kill(inboundTag string) int
	// Conns reports active and cumulative connections of an inbound tag.
	Conns(inboundTag string) (active, total uint64)

	// Counter reads a named stats counter such as
	// "inbound>>>w1n-fwd/i/a>>>traffic>>>uplink"; ok is false when it does
	// not exist (yet).
	Counter(name string) (value uint64, ok bool)
	// DropCounter unregisters a counter.
	DropCounter(name string)

	// Dispatcher and OutboundManager are used by the self-managed reverse
	// proxy.
	Dispatcher() routing.Dispatcher
	OutboundManager() outbound.Manager
}
