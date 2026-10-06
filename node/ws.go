package node

import (
	"context"
	"encoding/json"
	"runtime"
	"time"

	"github.com/W1nCwC/W1nCray/api/xboard"
)

// wsReportInterval is how often node.status goes over the WebSocket.
var wsReportInterval = 60 * time.Second

// startWS starts the WebSocket loop unless the config disables it or the
// controller runs in machine mode. Machine mode authenticates with request
// headers, but the panel's WebSocket handshake takes the token as a URL
// parameter, which must never happen, so machine nodes keep polling over HTTP.
func (c *Controller) startWS() {
	if c.cfg.DisableWebSocket {
		return
	}
	if c.api.MachineMode() {
		c.log.Debug("machine mode: websocket disabled, using HTTP polling")
		return
	}
	c.wg.Add(1)
	go c.wsLoop()
}

// wsLoop discovers the panel WebSocket through the handshake and keeps it
// connected. HTTP polling continues meanwhile as a safety net.
func (c *Controller) wsLoop() {
	defer c.wg.Done()
	for c.ctx.Err() == nil {
		ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
		hs, err := c.api.Handshake(ctx)
		cancel()
		switch {
		case err != nil:
			c.log.Debugf("websocket handshake: %v", err)
		case !hs.WebSocket.Enabled || hs.WebSocket.URL == "":
			c.log.Debug("panel websocket disabled, using HTTP polling")
		default:
			wc, err := c.api.NewWSClient(hs.WebSocket.URL, &wsHandler{c: c})
			if err != nil {
				c.log.Warnf("websocket: %v", err)
				break
			}
			c.log.Infof("panel websocket enabled: %s", hs.WebSocket.URL)
			c.ws.Store(wc)
			go c.wsReporter(wc)
			wc.Run(c.ctx) // reconnects until the controller stops
			c.ws.Store(nil)
			return
		}
		select {
		case <-c.ctx.Done():
			return
		case <-time.After(c.interval(true)):
		}
	}
}

// wsConnected reports whether pushes currently arrive over the WebSocket.
func (c *Controller) wsConnected() bool {
	wc := c.ws.Load()
	return wc != nil && wc.Connected()
}

func (c *Controller) wsReporter(wc *xboard.WSClient) {
	t := time.NewTicker(wsReportInterval)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			if wc.Connected() {
				c.wsSendStatus(wc)
			}
		}
	}
}

func (c *Controller) wsSendStatus(wc *xboard.WSClient) {
	c.mu.Lock()
	total := len(c.users)
	c.mu.Unlock()
	wc.Send(xboard.EventNodeStatus, map[string]any{
		"uptime":        int64(time.Since(c.started).Seconds()),
		"goroutines":    runtime.NumGoroutine(),
		"total_users":   total,
		"kernel_status": true,
	})
}

// wsHandler applies panel pushes through the same paths as HTTP polling.
type wsHandler struct{ c *Controller }

func (h *wsHandler) OnConnected() {
	c := h.c
	c.log.Info("panel websocket connected")
	// The panel cleared this node's devices on connect: report them now.
	c.devices.notify(true)
	if wc := c.ws.Load(); wc != nil {
		c.wsSendStatus(wc)
	}
}

func (h *wsHandler) OnDisconnected(err error) {
	c := h.c
	if c.ctx.Err() != nil {
		return
	}
	if err != nil {
		c.log.Warnf("panel websocket disconnected: %v (HTTP polling continues)", err)
	}
	c.limiterIn.ClearGlobalDevices()
	// The panel dropped this node's devices on disconnect; restore them
	// over HTTP right away.
	c.devices.notify(true)
}

func (h *wsHandler) OnConfig(nc *xboard.NodeConfig) {
	c := h.c
	// sync.config carries no base_config (NodeSyncService::notifyConfigUpdated);
	// keep the intervals from the last HTTP config.
	c.mu.Lock()
	if nc.BaseConfig == nil && c.node != nil {
		nc.BaseConfig = c.node.BaseConfig
	}
	c.mu.Unlock()
	if err := c.applyNode(nc, nil); err != nil {
		c.log.Errorf("apply pushed node config: %v", err)
		c.api.ResetETags()
	}
}

func (h *wsHandler) OnUsers(users []xboard.User) {
	if err := h.c.applyUsers(users); err != nil {
		h.c.log.Errorf("apply pushed users: %v", err)
		h.c.api.ResetETags()
	}
}

func (h *wsHandler) OnUserDelta(d *xboard.UserDelta) {
	if err := h.c.applyUserDelta(string(d.Action), d.Users); err != nil {
		h.c.log.Errorf("apply pushed user change: %v", err)
		h.c.api.ResetETags()
	}
}

func (h *wsHandler) OnDevices(devices map[int][]string) {
	h.c.limiterIn.SetGlobalDevices(devices)
}

// applyUserDelta adds/updates or removes users from the current panel list.
func (c *Controller) applyUserDelta(action string, delta []xboard.User) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	byID := make(map[xboard.Int]int, len(c.panelUsers))
	next := make([]xboard.User, 0, len(c.panelUsers)+len(delta))
	for _, u := range c.panelUsers {
		byID[u.ID] = len(next)
		next = append(next, u)
	}
	switch action {
	case "add":
		for _, u := range delta {
			if i, ok := byID[u.ID]; ok {
				next[i] = u
			} else {
				byID[u.ID] = len(next)
				next = append(next, u)
			}
		}
	case "remove":
		drop := make(map[xboard.Int]bool, len(delta))
		for _, u := range delta {
			drop[u.ID] = true
		}
		kept := next[:0]
		for _, u := range next {
			if !drop[u.ID] {
				kept = append(kept, u)
			}
		}
		next = kept
	default:
		c.log.Warnf("unknown user delta action %q", action)
		return nil
	}
	return c.applyUsersLocked(next)
}

// configKey identifies a node config for change detection. base_config is
// left out: HTTP configs carry it and WebSocket pushes do not, and only the
// intervals depend on it.
func configKey(nc *xboard.NodeConfig) string {
	var m map[string]json.RawMessage
	if json.Unmarshal(nc.Raw, &m) != nil {
		return string(nc.Raw)
	}
	delete(m, "base_config")
	b, _ := json.Marshal(m) // map keys are sorted
	return string(b)
}
