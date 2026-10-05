package frp

import (
	"context"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// instStats accumulates the counters of one portal instance.
//
// frps reports "today" counters (they reset at local midnight and when frps
// restarts), so the driver turns them into counters that never decrease while
// the driver lives:
//   - same day, value grew: add the difference;
//   - day rolled over or value shrank (midnight, or a restarted frps): the
//     missing tail of the previous day is taken from /api/traffic (yesterday)
//     and today's value is added.
type instStats struct {
	date    string
	proxies map[string]*proxyAcc
}

type proxyAcc struct {
	lastIn, lastOut int64
	totIn, totOut   uint64
	cur             uint64
}

func (d *Driver) instStatsLocked(id string) *instStats {
	st := d.stats[id]
	if st == nil {
		st = &instStats{proxies: map[string]*proxyAcc{}}
		d.stats[id] = st
	}
	return st
}

// rebaseStats must be called when the frps of an instance starts: its
// counters start from zero again.
func (d *Driver) rebaseStats(id string) {
	d.rmu.Lock()
	defer d.rmu.Unlock()
	if st := d.stats[id]; st != nil {
		for _, a := range st.proxies {
			a.lastIn, a.lastOut, a.cur = 0, 0, 0
		}
	}
}

func delta(cur, last, yesterday int64, rolled bool) uint64 {
	if rolled || cur < last {
		tail := yesterday - last
		if tail < 0 {
			tail = 0
		}
		return uint64(tail + cur)
	}
	return uint64(cur - last)
}

// Stats implements driver.Driver. Only portals report counters: frps counts
// the traffic of a TCP connection when it closes, UDP per packet. ConnsTotal
// is not available from frp and stays 0.
func (d *Driver) Stats(ctx context.Context, rt driver.Runtime) ([]driver.Counter, error) {
	cur := d.snapshotCurrent()
	today := d.now().Format("2006-01-02")
	var out []driver.Counter
	var firstErr error
	for _, id := range sortedKeys(cur) {
		u := cur[id]
		if u.Role != rolePortal {
			continue
		}
		d.rmu.Lock()
		st := d.instStatsLocked(id)
		d.rmu.Unlock()

		if rt.Sup != nil && rt.Sup.Status(procID(u)).Running {
			if a, ok := d.adminFor(rt, id); ok {
				if err := d.pollPortal(ctx, a, st, today); err != nil && firstErr == nil {
					firstErr = err
				}
			}
		}

		d.rmu.RLock()
		c := driver.Counter{InstanceID: id}
		for _, p := range st.proxies {
			c.BytesUp += p.totIn
			c.BytesDown += p.totOut
			c.ConnsActive += p.cur
		}
		d.rmu.RUnlock()
		out = append(out, c)
	}
	return out, firstErr
}

func (d *Driver) pollPortal(ctx context.Context, a adminInfo, st *instStats, today string) error {
	var seen []frpsProxy
	for _, typ := range []string{"tcp", "udp"} {
		ps, err := a.proxies(ctx, typ)
		if err != nil {
			return err
		}
		seen = append(seen, ps...)
	}
	d.rmu.Lock()
	rolled := st.date != "" && st.date != today
	for _, acc := range st.proxies {
		acc.cur = 0 // proxies that vanished have no live connections
	}
	d.rmu.Unlock()

	for _, p := range seen {
		// Every proxy of this frps belongs to this portal instance (one frps
		// per portal): the bridge names its proxies after its own instance
		// id, which the portal does not know.
		d.rmu.Lock()
		acc := st.proxies[p.Name]
		if acc == nil {
			acc = &proxyAcc{}
			st.proxies[p.Name] = acc
		}
		needY := rolled || p.TodayTrafficIn < acc.lastIn || p.TodayTrafficOut < acc.lastOut
		d.rmu.Unlock()

		var yIn, yOut int64
		if needY {
			in, outb, err := a.traffic(ctx, p.Name)
			if err == nil {
				if len(in) > 1 {
					yIn = in[1]
				}
				if len(outb) > 1 {
					yOut = outb[1]
				}
			}
		}
		d.rmu.Lock()
		acc.totIn += delta(p.TodayTrafficIn, acc.lastIn, yIn, rolled)
		acc.totOut += delta(p.TodayTrafficOut, acc.lastOut, yOut, rolled)
		acc.lastIn, acc.lastOut = p.TodayTrafficIn, p.TodayTrafficOut
		acc.cur = uint64(max(p.CurConns, 0))
		d.rmu.Unlock()
	}
	d.rmu.Lock()
	st.date = today
	d.rmu.Unlock()
	return nil
}
