package telemetry

import (
	"context"
	"math"
	"sort"
	"time"

	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// sampleTelemetry samples every dynamic field independently, so one failing
// probe cannot blank the others.
func (c *Collector) sampleTelemetry(ctx context.Context, now time.Time) wsproto.Telemetry {
	t := wsproto.Telemetry{TS: now.Unix()}

	c.field("cpu_pct", func() {
		// interval 0 measures against the previous call; the first call has no
		// previous sample and gopsutil reports an error, leaving cpu_pct 0.
		if p, err := cpuPercent(ctx); err == nil && len(p) > 0 {
			t.CPUPct = clampPct(p[0])
		}
	})

	c.field("load", func() {
		if l1, l5, l15, ok := loadAverage(); ok {
			t.Load = wsproto.Load{L1: l1, L5: l5, L15: l15}
		}
	})

	c.field("memory", func() { t.Mem, t.Swap = memoryUsage(ctx) })

	c.field("disks", func() { t.Disks = diskUsage(ctx) })

	c.field("net", func() { t.Net, c.prev = netSample(c.prev, now) })

	c.field("conns", func() {
		// Unreadable stays nil, i.e. JSON null: the panel must be able to tell
		// "not readable here" from "zero connections" (design R8,
		// wsproto.Telemetry.Conns is a pointer for exactly this).
		if tcp, udp, ok := socketCounts(); ok {
			t.Conns = &wsproto.Conns{TCP: tcp, UDP: udp}
		}
	})

	c.field("procs", func() { t.Procs = processCount(ctx) })

	c.field("uptime", func() { t.UptimeS = uptimeSeconds(ctx) })

	return t
}

// clampPct mirrors common/serverstatus: a value outside [0,100] is a sampling
// artifact (counter reset, first sample), not a real reading.
func clampPct(v float64) float64 {
	if math.IsNaN(v) || v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// memoryUsage returns RAM and swap usage. A platform that cannot read one of
// them leaves that usage at zero.
func memoryUsage(ctx context.Context) (memUse, swapUse wsproto.Usage) {
	if vm, err := virtualMemory(ctx); err == nil && vm != nil {
		memUse = wsproto.Usage{Total: vm.Total, Used: vm.Used}
	}
	if sw, err := swapMemory(ctx); err == nil && sw != nil {
		swapUse = wsproto.Usage{Total: sw.Total, Used: sw.Used}
	}
	return memUse, swapUse
}

// diskUsage reports used bytes per mount point, using the same filter and the
// same mount points as diskInfos so the two lists line up.
func diskUsage(ctx context.Context) []wsproto.DiskUse {
	parts, err := partitions(ctx, false)
	if err != nil {
		return nil
	}
	seen := make(map[string]bool, len(parts))
	var out []wsproto.DiskUse
	for _, p := range parts {
		if p.Mountpoint == "" || seen[p.Mountpoint] || !realFS(p.Fstype) {
			continue
		}
		seen[p.Mountpoint] = true
		u, err := usageOf(ctx, p.Mountpoint)
		if err != nil || u == nil {
			continue
		}
		out = append(out, wsproto.DiskUse{Mount: p.Mountpoint, Total: u.Total, Used: u.Used})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Mount < out[j].Mount })
	return out
}

func processCount(ctx context.Context) int {
	pids, err := processPids(ctx)
	if err != nil {
		return 0
	}
	return len(pids)
}

func uptimeSeconds(ctx context.Context) int64 {
	up, err := hostUptime(ctx)
	if err != nil {
		return 0
	}
	return int64(up)
}
