package core

import (
	"context"
	"errors"
	"fmt"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol"
	xcore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"

	"github.com/W1nCwC/W1nCray/app/routeguard"
)

// AddInbound adds an inbound handler.
func (c *Core) AddInbound(cfg *xcore.InboundHandlerConfig) error {
	return xcore.AddInboundHandler(c.Instance, cfg)
}

// RemoveInbound removes an inbound handler; a missing tag is not an error.
func (c *Core) RemoveInbound(tag string) error {
	if _, err := c.ibm.GetHandler(context.Background(), tag); err != nil {
		return nil
	}
	return c.ibm.RemoveHandler(context.Background(), tag)
}

// RemoveInboundAndKill removes an inbound and aborts its tracked sessions
// (see Conns), returning how many were aborted. Plain RemoveInbound leaves
// established connections running: Xray only stops the listener.
func (c *Core) RemoveInboundAndKill(tag string) (int, error) {
	err := c.RemoveInbound(tag)
	return c.conns.Kill(tag), err
}

// AddOutbound adds an outbound handler. It is xcore.AddOutboundHandler split
// in two: the handler is built outside the routeguard lock (construction may
// be slow) and only its registration, which route selection must not overlap,
// runs under the write lock.
func (c *Core) AddOutbound(cfg *xcore.OutboundHandlerConfig) error {
	raw, err := xcore.CreateObject(c.Instance, cfg)
	if err != nil {
		return err
	}
	h, ok := raw.(outbound.Handler)
	if !ok {
		return errors.New("not an OutboundHandler")
	}
	return routeguard.Mutate(func() error {
		return c.obm.AddHandler(context.Background(), h)
	})
}

// RemoveOutbound closes and removes an outbound handler; a missing tag is not
// an error. Xray's outbound manager only forgets a removed handler, so without
// the Close a handler that owns background work (the mux client of a reverse
// bridge, which redials by itself) would keep running as a zombie.
func (c *Core) RemoveOutbound(tag string) error {
	h := c.obm.GetHandler(tag)
	if h == nil {
		return nil
	}
	// Close may block, so it stays outside the routeguard write lock; only the
	// removal from the manager is a change that route selection must not
	// overlap.
	closeErr := common.Close(h)
	if err := routeguard.Mutate(func() error {
		return c.obm.RemoveHandler(context.Background(), tag)
	}); err != nil {
		return err
	}
	return closeErr
}

// HasOutbound reports whether an outbound with the tag exists.
func (c *Core) HasOutbound(tag string) bool {
	return c.obm.GetHandler(tag) != nil
}

// UserManager returns the user manager of an inbound, if the protocol has one.
func (c *Core) UserManager(tag string) (proxy.UserManager, error) {
	h, err := c.ibm.GetHandler(context.Background(), tag)
	if err != nil {
		return nil, fmt.Errorf("inbound %s: %w", tag, err)
	}
	gi, ok := h.(proxy.GetInbound)
	if !ok {
		return nil, fmt.Errorf("inbound %s: handler does not expose its proxy", tag)
	}
	um, ok := gi.GetInbound().(proxy.UserManager)
	if !ok {
		return nil, fmt.Errorf("inbound %s: protocol does not support user management", tag)
	}
	return um, nil
}

// AddUsers adds users to an inbound.
func (c *Core) AddUsers(tag string, users []*protocol.User) error {
	um, err := c.UserManager(tag)
	if err != nil {
		return err
	}
	for _, u := range users {
		mu, err := u.ToMemoryUser()
		if err != nil {
			return fmt.Errorf("user %s: %w", u.Email, err)
		}
		if err := um.AddUser(context.Background(), mu); err != nil {
			return fmt.Errorf("add user %s: %w", u.Email, err)
		}
	}
	return nil
}

// RemoveUsers removes users from an inbound by email and drops their counters.
func (c *Core) RemoveUsers(tag string, emails []string) error {
	um, err := c.UserManager(tag)
	if err != nil {
		return err
	}
	for _, e := range emails {
		if err := um.RemoveUser(context.Background(), e); err != nil {
			return fmt.Errorf("remove user %s: %w", e, err)
		}
	}
	return nil
}

// TrafficCounters returns the uplink/downlink counters of a user (nil when the
// user has not transferred anything yet).
func (c *Core) TrafficCounters(email string) (up, down stats.Counter) {
	up = c.stats.GetCounter("user>>>" + email + ">>>traffic>>>uplink")
	down = c.stats.GetCounter("user>>>" + email + ">>>traffic>>>downlink")
	return up, down
}

// InboundTraffic returns the byte counters of an inbound: bytes received from
// (up) and sent to (down) its clients. Both are nil unless Options.Forward is
// set, or while the inbound does not exist.
func (c *Core) InboundTraffic(tag string) (up, down stats.Counter) {
	up = c.stats.GetCounter("inbound>>>" + tag + ">>>traffic>>>uplink")
	down = c.stats.GetCounter("inbound>>>" + tag + ">>>traffic>>>downlink")
	return up, down
}

// OutboundTraffic returns the byte counters of an outbound: bytes sent to
// (up) and received from (down) its peer. Both are nil unless Options.Forward
// is set, or while the outbound does not exist.
func (c *Core) OutboundTraffic(tag string) (up, down stats.Counter) {
	up = c.stats.GetCounter("outbound>>>" + tag + ">>>traffic>>>uplink")
	down = c.stats.GetCounter("outbound>>>" + tag + ">>>traffic>>>downlink")
	return up, down
}

// DropCounters unregisters the traffic counters of a user.
func (c *Core) DropCounters(email string) {
	_ = c.stats.UnregisterCounter("user>>>" + email + ">>>traffic>>>uplink")
	_ = c.stats.UnregisterCounter("user>>>" + email + ">>>traffic>>>downlink")
}
