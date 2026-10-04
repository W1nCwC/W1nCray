package node

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"time"

	"github.com/W1nCwC/W1nCray/api/xboard"
)

// Online IP reporting (docs/PLAN-v4-websocket.md §6): changes are reported
// as they happen, over the WebSocket when it is up, otherwise over HTTP.
var (
	// devicesGrace keeps an IP online after its last connection closed, so
	// clients that reconnect often do not flap the panel's device count.
	devicesGrace = 30 * time.Second
	// devicesTick is how often expired IPs are looked for.
	devicesTick = 5 * time.Second
	// devicesDebounce merges changes arriving close together.
	devicesDebounce = time.Second
	// devicesRefresh re-sends an unchanged snapshot before the panel's
	// 300 s device TTL (DeviceStateService::TTL) drops it.
	devicesRefresh = 60 * time.Second
	// devicesHTTPGap limits HTTP reports: each one writes to the panel DB.
	devicesHTTPGap = 5 * time.Second
)

type deviceSignal struct {
	wake  chan struct{}
	force atomic.Bool
}

func newDeviceSignal() *deviceSignal {
	return &deviceSignal{wake: make(chan struct{}, 1)}
}

// notify asks for a report; force sends even an unchanged snapshot (the panel
// cleared this node's devices on WebSocket connect/disconnect).
func (s *deviceSignal) notify(force bool) {
	if force {
		s.force.Store(true)
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// deviceReporter sends this node's online IPs whenever they change.
func (c *Controller) deviceReporter() {
	defer c.wg.Done()
	t := time.NewTicker(devicesTick)
	defer t.Stop()
	var last string
	var lastSent time.Time
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
		case <-c.devices.wake:
			select {
			case <-c.ctx.Done():
				return
			case <-time.After(devicesDebounce):
			}
		}
		force := c.devices.force.Swap(false)

		snapshot := c.limiterIn.AliveIPs(devicesGrace)
		b, _ := json.Marshal(snapshot) // map keys are sorted
		key := string(b)
		if !force && key == last && time.Since(lastSent) < devicesRefresh {
			continue
		}

		if wc := c.ws.Load(); wc != nil && wc.Connected() {
			if !wc.Send(xboard.EventReportDevices, xboard.DevicesPayload(snapshot)) {
				if force {
					c.devices.force.Store(true) // retry on the next tick
				}
				continue
			}
		} else {
			if !force && time.Since(lastSent) < devicesHTTPGap {
				continue // picked up by a later tick
			}
			// HTTP alive only updates the users it lists, so an empty
			// snapshot changes nothing there: users who went offline
			// expire on the panel after its TTL. Only the WebSocket
			// report can remove them immediately.
			if len(snapshot) > 0 {
				ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
				err := c.api.PushAlive(ctx, snapshot)
				cancel()
				if err != nil {
					c.log.Errorf("report online IPs: %v", err)
					continue
				}
			}
		}
		last, lastSent = key, time.Now()
	}
}
