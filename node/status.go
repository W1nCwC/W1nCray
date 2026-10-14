package node

import "time"

// StatusWindow is the window in which an IP counts as online in the kernel
// status report. It matches the device grace period the panel sees.
const StatusWindow = 5 * time.Minute

// ID returns the panel node id.
func (c *Controller) ID() int {
	if c == nil || c.apiCfg == nil {
		return 0
	}
	return c.apiCfg.NodeID
}

// Type returns the configured panel node type ("" when the panel decides).
func (c *Controller) Type() string {
	if c == nil || c.apiCfg == nil {
		return ""
	}
	return c.apiCfg.NodeType
}

// Users returns the number of users currently synced to this node.
func (c *Controller) Users() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.users)
}

// OnlineIPs returns the number of online IPs across all users of this node.
func (c *Controller) OnlineIPs() int {
	if c == nil || c.limiterIn == nil {
		return 0
	}
	n := 0
	for _, ips := range c.limiterIn.AliveIPs(StatusWindow) {
		n += len(ips)
	}
	return n
}

// LastError returns the most recent pull/apply error ("" when none was seen).
func (c *Controller) LastError() string {
	if c == nil {
		return ""
	}
	if p := c.lastErr.Load(); p != nil {
		return *p
	}
	return ""
}

// setLastError records an error for the status report.
func (c *Controller) setLastError(err error) {
	if c == nil || err == nil {
		return
	}
	msg := err.Error()
	c.lastErr.Store(&msg)
}

// clearLastError drops the recorded error after a successful apply.
func (c *Controller) clearLastError() {
	if c == nil {
		return
	}
	c.lastErr.Store(nil)
}
