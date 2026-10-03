package core

import (
	"context"
	"fmt"

	"github.com/xtls/xray-core/common/protocol"
	xcore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
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

// AddOutbound adds an outbound handler.
func (c *Core) AddOutbound(cfg *xcore.OutboundHandlerConfig) error {
	return xcore.AddOutboundHandler(c.Instance, cfg)
}

// RemoveOutbound removes an outbound handler; a missing tag is not an error.
func (c *Core) RemoveOutbound(tag string) error {
	if c.obm.GetHandler(tag) == nil {
		return nil
	}
	return c.obm.RemoveHandler(context.Background(), tag)
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

// DropCounters unregisters the traffic counters of a user.
func (c *Core) DropCounters(email string) {
	_ = c.stats.UnregisterCounter("user>>>" + email + ">>>traffic>>>uplink")
	_ = c.stats.UnregisterCounter("user>>>" + email + ">>>traffic>>>downlink")
}
