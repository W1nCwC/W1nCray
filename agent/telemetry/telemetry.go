// Package telemetry samples one machine for the panel: the static-ish HostInfo,
// the dynamic Telemetry and the Components list of docs/WS-PROTOCOL.md §3.
//
// Every collection item is independent. A probe that fails or panics leaves
// that one field at its zero value — which the contract reads as "unknown,
// never invent a value" — and is logged as a warning, so a broken gopsutil call
// on an unusual platform (design R12) can never lose the whole sample.
//
// Nothing here starts an external process and nothing probes the network: the
// public IP list is deliberately left empty (design §6-R4).
package telemetry

import (
	"context"
	"net"
	"os"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// DefaultHostInfoTTL is how long one HostInfo sample is reused. Sampling it is
// expensive on Linux (cpu.Info parses /proc/cpuinfo, the disk list walks every
// mount) while the values change only on reboot or hardware change.
const DefaultHostInfoTTL = 10 * time.Minute

// Options configures a Collector. The zero value is usable.
type Options struct {
	// Log receives one warning per panicking collection item (a probe that
	// merely fails is expected and stays silent). nil is silent.
	Log driver.Logger
	// Now overrides the clock (tests).
	Now func() time.Time
	// Components supplies the process/kernel side of the "components" message.
	// nil reports only the agent component.
	Components ComponentProbe
	// AgentVersion is reported as the version of the "agent" component.
	AgentVersion string
	// HostInfoTTL overrides DefaultHostInfoTTL (tests).
	HostInfoTTL time.Duration
}

// Collector samples one machine. It is safe for concurrent use: the sampling
// state (previous network counters, cached HostInfo) is mutex-protected so the
// HTTP report loop and the WebSocket telemetry loop can share one Collector —
// two Collectors would each diff the counters from their own first sample and
// disagree about the bandwidth (design §3.3, R2).
type Collector struct {
	log          driver.Logger
	now          func() time.Time
	ttl          time.Duration
	probe        ComponentProbe
	agentVersion string

	mu      sync.Mutex // guards prev, host, hostAt, hostSet
	prev    netSnapshot
	host    wsproto.HostInfo
	hostAt  time.Time
	hostSet bool
}

// New returns a Collector; the zero Options is valid.
func New(o Options) *Collector {
	c := &Collector{
		log:          o.Log,
		now:          o.Now,
		ttl:          o.HostInfoTTL,
		probe:        o.Components,
		agentVersion: o.AgentVersion,
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.ttl <= 0 {
		c.ttl = DefaultHostInfoTTL
	}
	return c
}

// Probes are package-level variables so tests can replace them. The bandwidth
// diff is tested with synthetic counters, and the soft-failure and panic paths
// are tested by making one probe fail or panic while the others keep working.
var (
	hostInfo       = host.InfoWithContext
	cpuInfo        = cpu.InfoWithContext
	cpuCounts      = cpu.CountsWithContext
	cpuPercent     = func(ctx context.Context) ([]float64, error) { return cpu.PercentWithContext(ctx, 0, false) }
	virtualMemory  = mem.VirtualMemoryWithContext
	swapMemory     = mem.SwapMemoryWithContext
	partitions     = disk.PartitionsWithContext
	usageOf        = disk.UsageWithContext
	netCounters    = netCountersOS
	interfaceAddrs = net.InterfaceAddrs
	processPids    = process.PidsWithContext
	hostUptime     = host.UptimeWithContext
	loadAverage    = loadAverageOS
	socketCounts   = socketCountsOS
	selfRSSBytes   = selfRSSBytesOS
	readlink       = os.Readlink
	localZoneName  = func() string { return time.Now().Location().String() }
)

// HostInfo returns the device description, sampled at most once per
// HostInfoTTL. Fields that cannot be read stay empty.
func (c *Collector) HostInfo(ctx context.Context) wsproto.HostInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.hostSet && now.Sub(c.hostAt) < c.ttl {
		return cloneHostInfo(c.host)
	}
	c.host, c.hostAt, c.hostSet = c.sampleHostInfo(ctx), now, true
	return cloneHostInfo(c.host)
}

// Telemetry returns one dynamic sample. Bandwidth is a difference against the
// previous call, so the first call (and the first call after the counters
// became readable again) reports zero rates but real totals.
func (c *Collector) Telemetry(ctx context.Context) wsproto.Telemetry {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sampleTelemetry(ctx, c.now())
}

// Components returns the component list. Items is never nil, so the frame
// always carries an array.
func (c *Collector) Components(ctx context.Context) wsproto.Components {
	now := c.now()
	items := make([]wsproto.Component, 0, 1)
	c.field("components", func() { items = c.componentsFrom(now) })
	return wsproto.Components{TS: now.Unix(), Items: items}
}

// field runs one collection item under guard.
func (c *Collector) field(what string, f func()) {
	guard(c.log, what, f)
}

// guard runs f and turns a panic into a warning. The caller's variable keeps
// its zero value, so one broken probe cannot take the rest of the sample (or
// the agent process) down with it.
func guard(log driver.Logger, what string, f func()) {
	defer func() {
		if p := recover(); p != nil && log != nil {
			log.Warnf("telemetry: %s panicked, field left empty: %v", what, p)
		}
	}()
	f()
}

// cloneHostInfo hands out a copy: the cached value is shared by every caller
// and one of them must not be able to mutate it.
func cloneHostInfo(hi wsproto.HostInfo) wsproto.HostInfo {
	hi.Disks = append([]wsproto.DiskInfo(nil), hi.Disks...)
	hi.IPs.Private = append([]string(nil), hi.IPs.Private...)
	hi.IPs.Public = append([]string(nil), hi.IPs.Public...)
	return hi
}
