package node

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/xtls/xray-core/features/stats"

	"github.com/W1nCwC/W1nCray/api/xboard"
	"github.com/W1nCwC/W1nCray/common/serverstatus"
)

func (c *Controller) push() {
	ctx, cancel := context.WithTimeout(c.ctx, 2*time.Minute)
	defer cancel()

	traffic := c.reportTraffic(ctx)
	if c.auto != nil {
		c.mu.Lock()
		if c.auto.check(traffic, c.pushEvery, c.log) {
			c.syncLimiter()
		}
		c.mu.Unlock()
	}
	c.reportAlive(ctx)
	c.reportStatus(ctx)
}

type trafficItem struct {
	uid      int
	email    string
	up, down stats.Counter
	u, d     int64
}

// reportTraffic pushes the traffic counted since the last successful report
// and returns it per uid. Counters are decreased by the reported amount only
// after the panel accepted the report, so nothing is lost on failure and
// nothing counted meanwhile is dropped.
func (c *Controller) reportTraffic(ctx context.Context) map[int][2]int64 {
	if c.core == nil {
		return nil
	}
	c.mu.Lock()
	var items []trafficItem
	collect := func(uid int, email string) {
		up, down := c.core.TrafficCounters(email)
		it := trafficItem{uid: uid, email: email, up: up, down: down}
		if up != nil {
			it.u = up.Value()
		}
		if down != nil {
			it.d = down.Value()
		}
		items = append(items, it)
	}
	for _, u := range c.users {
		collect(u.UID, u.Email)
	}
	dropped := make(map[string]int, len(c.dropped))
	for email, uid := range c.dropped {
		dropped[email] = uid
		collect(uid, email)
	}
	c.mu.Unlock()

	traffic := make(map[int][2]int64)
	for _, it := range items {
		if it.u == 0 && it.d == 0 {
			continue
		}
		t := traffic[it.uid]
		traffic[it.uid] = [2]int64{t[0] + it.u, t[1] + it.d}
	}

	if len(traffic) > 0 && !c.cfg.DisableUploadTraffic {
		if err := c.api.PushTraffic(ctx, traffic); err != nil {
			c.log.Errorf("report traffic: %v", err)
			return nil
		}
		c.log.Debugf("reported traffic of %d users", len(traffic))
	}
	for _, it := range items {
		if it.up != nil && it.u != 0 {
			it.up.Add(-it.u)
		}
		if it.down != nil && it.d != 0 {
			it.down.Add(-it.d)
		}
	}

	c.mu.Lock()
	inUse := make(map[string]bool, len(c.users))
	for _, u := range c.users {
		inUse[u.Email] = true
	}
	for email := range dropped {
		delete(c.dropped, email)
		if !inUse[email] {
			c.core.DropCounters(email)
		}
	}
	c.mu.Unlock()
	return traffic
}

func (c *Controller) reportAlive(ctx context.Context) {
	if c.limiterIn == nil {
		return
	}
	alive := c.limiterIn.AliveIPs(c.interval(false))
	if len(alive) == 0 {
		return
	}
	if err := c.api.PushAlive(ctx, alive); err != nil {
		c.log.Errorf("report online IPs: %v", err)
		return
	}
	c.log.Debugf("reported online IPs of %d users", len(alive))
}

func (c *Controller) reportStatus(ctx context.Context) {
	c.mu.Lock()
	off := c.statusOff
	c.mu.Unlock()
	if off {
		return
	}
	s, err := serverstatus.Get()
	if err != nil {
		c.log.Debugf("sample status: %v", err)
		return
	}
	err = c.api.PushStatus(ctx, &xboard.Status{
		CPU:  s.CPU,
		Mem:  xboard.Resource{Total: s.MemTotal, Used: s.MemUsed},
		Swap: xboard.Resource{Total: s.SwapTotal, Used: s.SwapUsed},
		Disk: xboard.Resource{Total: s.DiskTotal, Used: s.DiskUsed},
	})
	var se *xboard.StatusError
	if errors.As(err, &se) && (se.Code == http.StatusNotFound || se.Code == http.StatusMethodNotAllowed) {
		c.mu.Lock()
		c.statusOff = true
		c.mu.Unlock()
		c.log.Info("panel has no status endpoint, status reporting disabled")
		return
	}
	if err != nil {
		c.log.Errorf("report status: %v", err)
	}
}

// autoLimit implements XrayR's AutoSpeedLimit: users above Limit for more
// than WarnTimes consecutive reports are limited to LimitSpeed for
// LimitDuration minutes.
type autoLimit struct {
	cfg     *AutoSpeedLimitConfig
	warned  map[int]int
	limited map[int]time.Time
}

func newAutoLimit(cfg *AutoSpeedLimitConfig) *autoLimit {
	return &autoLimit{cfg: cfg, warned: make(map[int]int), limited: make(map[int]time.Time)}
}

func (a *autoLimit) override(uid int) (uint64, bool) {
	if _, ok := a.limited[uid]; ok {
		return mbpsToBytes(float64(a.cfg.LimitSpeed)), true
	}
	return 0, false
}

// check updates the state from one report interval and reports whether any
// user's limit changed.
func (a *autoLimit) check(traffic map[int][2]int64, interval time.Duration, logger interface {
	Infof(string, ...any)
}) bool {
	changed := false
	now := time.Now()
	for uid, until := range a.limited {
		if now.After(until) {
			delete(a.limited, uid)
			changed = true
			logger.Infof("auto speed limit lifted for user %d", uid)
		}
	}
	threshold := int64(float64(a.cfg.Limit) * 1000000 / 8 * interval.Seconds())
	for uid := range a.warned {
		if t, ok := traffic[uid]; !ok || (t[0] <= threshold && t[1] <= threshold) {
			delete(a.warned, uid)
		}
	}
	for uid, t := range traffic {
		if t[0] <= threshold && t[1] <= threshold {
			continue
		}
		if _, ok := a.limited[uid]; ok {
			continue
		}
		a.warned[uid]++
		if a.cfg.WarnTimes == 0 || a.warned[uid] > a.cfg.WarnTimes {
			delete(a.warned, uid)
			a.limited[uid] = now.Add(time.Duration(a.cfg.LimitDuration) * time.Minute)
			changed = true
			logger.Infof("auto speed limit: user %d limited to %d Mbps for %d min", uid, a.cfg.LimitSpeed, a.cfg.LimitDuration)
		}
	}
	return changed
}
