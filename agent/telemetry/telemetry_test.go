package telemetry

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"

	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// fakeLogger records the warnings of a sample.
type fakeLogger struct {
	mu    sync.Mutex
	warns []string
}

func (l *fakeLogger) Debugf(string, ...any) {}
func (l *fakeLogger) Infof(string, ...any)  {}
func (l *fakeLogger) Errorf(string, ...any) {}

func (l *fakeLogger) Warnf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warns = append(l.warns, fmt.Sprintf(format, args...))
}

func (l *fakeLogger) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.warns)
}

func (l *fakeLogger) contains(sub string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, w := range l.warns {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}

func TestNewDefaults(t *testing.T) {
	c := New(Options{})
	if c.now == nil {
		t.Fatal("Now not defaulted")
	}
	if c.ttl != DefaultHostInfoTTL {
		t.Fatalf("ttl = %s, want %s", c.ttl, DefaultHostInfoTTL)
	}
}

func TestHostInfoCachedForTTL(t *testing.T) {
	calls := 0
	swap(t, &hostInfo, func(context.Context) (*host.InfoStat, error) {
		calls++
		return &host.InfoStat{PlatformVersion: "1.0"}, nil
	})
	clock := time.Unix(1000, 0)
	c := New(Options{Now: func() time.Time { return clock }, HostInfoTTL: time.Minute})

	if got := c.HostInfo(context.Background()); got.OSVersion != "1.0" {
		t.Fatalf("OSVersion = %q, want 1.0", got.OSVersion)
	}
	c.HostInfo(context.Background())
	if calls != 1 {
		t.Fatalf("probe called %d times inside the TTL, want 1", calls)
	}
	clock = clock.Add(time.Minute + time.Second)
	c.HostInfo(context.Background())
	if calls != 2 {
		t.Fatalf("probe called %d times after the TTL, want 2", calls)
	}
}

func TestHostInfoReturnsACopy(t *testing.T) {
	swap(t, &partitions, func(context.Context, bool) ([]disk.PartitionStat, error) {
		return []disk.PartitionStat{{Mountpoint: "/", Fstype: "ext4"}}, nil
	})
	swap(t, &usageOf, func(context.Context, string) (*disk.UsageStat, error) {
		return &disk.UsageStat{Total: 100, Used: 40}, nil
	})
	c := New(Options{})

	first := c.HostInfo(context.Background())
	if len(first.Disks) != 1 {
		t.Fatalf("disks = %+v, want one entry", first.Disks)
	}
	first.Disks[0].Mount = "tampered"
	first.IPs.Private = append(first.IPs.Private, "tampered")

	second := c.HostInfo(context.Background())
	if second.Disks[0].Mount != "/" {
		t.Fatalf("cached HostInfo was mutated: %+v", second.Disks)
	}
	for _, ip := range second.IPs.Private {
		if ip == "tampered" {
			t.Fatal("cached IP list was mutated")
		}
	}
}

func TestHostInfoArchAndOS(t *testing.T) {
	hi := New(Options{}).HostInfo(context.Background())
	if hi.OS != runtime.GOOS || hi.Arch != runtime.GOARCH {
		t.Fatalf("os/arch = %q/%q, want %q/%q", hi.OS, hi.Arch, runtime.GOOS, runtime.GOARCH)
	}
}

// A panic in one collection item must leave that field empty, warn, and keep
// every other item of the same sample.
func TestPanicInOneHostItemLeavesOnlyThatFieldEmpty(t *testing.T) {
	log := &fakeLogger{}
	swap(t, &hostInfo, func(context.Context) (*host.InfoStat, error) {
		return &host.InfoStat{
			PlatformVersion:      "22.04",
			KernelVersion:        "6.1.0",
			VirtualizationSystem: "kvm",
			BootTime:             1700000000,
		}, nil
	})
	swap(t, &cpuInfo, func(context.Context) ([]cpu.InfoStat, error) { panic("cpu probe exploded") })
	swap(t, &partitions, func(context.Context, bool) ([]disk.PartitionStat, error) {
		return []disk.PartitionStat{{Mountpoint: "/", Fstype: "ext4"}}, nil
	})
	swap(t, &usageOf, func(context.Context, string) (*disk.UsageStat, error) {
		return &disk.UsageStat{Total: 100, Used: 40}, nil
	})

	hi := New(Options{Log: log}).HostInfo(context.Background())
	if hi.CPUModel != "" || hi.CPUCores != 0 || hi.CPUThreads != 0 {
		t.Fatalf("panicking cpu item leaked values: %+v", hi)
	}
	if hi.OSVersion != "22.04" || hi.KernelVersion != "6.1.0" || hi.Virtualization != "kvm" || hi.BootTime != 1700000000 {
		t.Fatalf("os item lost its values: %+v", hi)
	}
	if len(hi.Disks) != 1 || hi.Disks[0].Total != 100 {
		t.Fatalf("disks item lost its values: %+v", hi.Disks)
	}
	if !log.contains("cpu") {
		t.Fatalf("no warning for the panicking item: %v", log.warns)
	}
}

func TestPanicInOneTelemetryItemLeavesOnlyThatFieldEmpty(t *testing.T) {
	log := &fakeLogger{}
	swap(t, &cpuPercent, func(context.Context) ([]float64, error) { panic("cpu percent exploded") })
	swap(t, &loadAverage, func() (float64, float64, float64, bool) { return 1, 2, 3, true })
	swap(t, &virtualMemory, func(context.Context) (*mem.VirtualMemoryStat, error) {
		return &mem.VirtualMemoryStat{Total: 1000, Used: 400}, nil
	})
	swap(t, &swapMemory, func(context.Context) (*mem.SwapMemoryStat, error) {
		return &mem.SwapMemoryStat{Total: 2000, Used: 100}, nil
	})
	swap(t, &netCounters, func() (uint64, uint64, bool) { return 10, 20, true })
	swap(t, &socketCounts, func() (int, int, bool) { return 7, 8, true })
	swap(t, &processPids, func(context.Context) ([]int32, error) { return []int32{1, 2, 3}, nil })
	swap(t, &hostUptime, func(context.Context) (uint64, error) { return 42, nil })
	swap(t, &partitions, func(context.Context, bool) ([]disk.PartitionStat, error) { return nil, nil })

	c := New(Options{Log: log, Now: func() time.Time { return time.Unix(500, 0) }})
	te := c.Telemetry(context.Background())

	if te.CPUPct != 0 {
		t.Fatalf("cpu_pct = %v, want 0 after the panic", te.CPUPct)
	}
	if te.TS != 500 {
		t.Fatalf("ts = %d, want 500", te.TS)
	}
	if te.Load.L1 != 1 || te.Load.L5 != 2 || te.Load.L15 != 3 {
		t.Fatalf("load = %+v, want 1/2/3", te.Load)
	}
	if te.Mem.Total != 1000 || te.Mem.Used != 400 || te.Swap.Total != 2000 {
		t.Fatalf("memory = %+v / %+v", te.Mem, te.Swap)
	}
	if te.Conns == nil || te.Conns.TCP != 7 || te.Conns.UDP != 8 {
		t.Fatalf("conns = %+v, want 7/8", te.Conns)
	}
	if te.Procs != 3 || te.UptimeS != 42 {
		t.Fatalf("procs/uptime = %d/%d, want 3/42", te.Procs, te.UptimeS)
	}
	if te.Net.InTotal != 10 || te.Net.OutTotal != 20 || te.Net.InBps != 0 {
		t.Fatalf("net = %+v, want totals 10/20 and zero rates", te.Net)
	}
	if !log.contains("cpu_pct") {
		t.Fatalf("no warning for the panicking item: %v", log.warns)
	}
}

// A probe that fails must not panic and must not invent a value.
func TestAllProbesFailingLeavesZeroValues(t *testing.T) {
	boom := errors.New("boom")
	swap(t, &hostInfo, func(context.Context) (*host.InfoStat, error) { return nil, boom })
	swap(t, &cpuInfo, func(context.Context) ([]cpu.InfoStat, error) { return nil, boom })
	swap(t, &cpuCounts, func(context.Context, bool) (int, error) { return 0, boom })
	swap(t, &partitions, func(context.Context, bool) ([]disk.PartitionStat, error) { return nil, boom })
	swap(t, &interfaceAddrs, func() ([]net.Addr, error) { return nil, boom })
	swap(t, &readlink, func(string) (string, error) { return "", boom })
	swap(t, &localZoneName, func() string { return "Local" })
	swap(t, &cpuPercent, func(context.Context) ([]float64, error) { return nil, boom })
	swap(t, &loadAverage, func() (float64, float64, float64, bool) { return 0, 0, 0, false })
	swap(t, &virtualMemory, func(context.Context) (*mem.VirtualMemoryStat, error) { return nil, boom })
	swap(t, &swapMemory, func(context.Context) (*mem.SwapMemoryStat, error) { return nil, boom })
	swap(t, &netCounters, func() (uint64, uint64, bool) { return 0, 0, false })
	swap(t, &socketCounts, func() (int, int, bool) { return 0, 0, false })
	swap(t, &processPids, func(context.Context) ([]int32, error) { return nil, boom })
	swap(t, &hostUptime, func(context.Context) (uint64, error) { return 0, boom })

	log := &fakeLogger{}
	c := New(Options{Log: log})

	hi := c.HostInfo(context.Background())
	if hi.OSVersion != "" || hi.KernelVersion != "" || hi.Virtualization != "" || hi.BootTime != 0 {
		t.Fatalf("os info invented a value: %+v", hi)
	}
	if hi.CPUModel != "" || hi.CPUCores != 0 || hi.CPUThreads != 0 {
		t.Fatalf("cpu invented a value: %+v", hi)
	}
	if hi.MemTotal != 0 || hi.SwapTotal != 0 || len(hi.Disks) != 0 || len(hi.IPs.Private) != 0 || hi.Timezone != "" {
		t.Fatalf("host info invented a value: %+v", hi)
	}
	if hi.OS != runtime.GOOS || hi.Arch != runtime.GOARCH {
		t.Fatalf("os/arch = %q/%q, want the runtime values", hi.OS, hi.Arch)
	}

	te := c.Telemetry(context.Background())
	if te.CPUPct != 0 || te.Load != (wsproto.Load{}) || te.Mem != (wsproto.Usage{}) || te.Swap != (wsproto.Usage{}) {
		t.Fatalf("telemetry invented a value: %+v", te)
	}
	if te.Conns != nil {
		t.Fatalf("conns = %+v, want nil when unreadable", te.Conns)
	}
	if te.Procs != 0 || te.UptimeS != 0 || len(te.Disks) != 0 {
		t.Fatalf("telemetry invented a value: %+v", te)
	}
}

// Concurrency: the HTTP report loop and the WS telemetry loop share one
// Collector, so Telemetry() must be race free.
func TestTelemetryConcurrent(t *testing.T) {
	swap(t, &cpuPercent, func(context.Context) ([]float64, error) { return []float64{50}, nil })
	swap(t, &loadAverage, func() (float64, float64, float64, bool) { return 1, 1, 1, true })
	swap(t, &virtualMemory, func(context.Context) (*mem.VirtualMemoryStat, error) {
		return &mem.VirtualMemoryStat{Total: 1024, Used: 512}, nil
	})
	swap(t, &swapMemory, func(context.Context) (*mem.SwapMemoryStat, error) {
		return &mem.SwapMemoryStat{Total: 2048, Used: 0}, nil
	})
	swap(t, &partitions, func(context.Context, bool) ([]disk.PartitionStat, error) { return nil, nil })
	swap(t, &netCounters, func() (uint64, uint64, bool) { return 100, 200, true })
	swap(t, &socketCounts, func() (int, int, bool) { return 1, 2, true })
	swap(t, &processPids, func(context.Context) ([]int32, error) { return []int32{1}, nil })
	swap(t, &hostUptime, func(context.Context) (uint64, error) { return 7, nil })

	c := New(Options{})
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				te := c.Telemetry(context.Background())
				if te.Mem.Total != 1024 || te.Net.InTotal != 100 {
					t.Errorf("unexpected sample: %+v", te)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// Components must never lose the agent item, even when the runtime probe
// panics.
func TestPanicInComponentProbeKeepsTheAgentItem(t *testing.T) {
	log := &fakeLogger{}
	p := &fakeProbe{panicProcs: true}
	c := New(Options{Log: log, AgentVersion: "9.9.9", Components: p})

	got := c.Components(context.Background())
	if len(got.Items) != 1 {
		t.Fatalf("items = %+v, want only the agent", got.Items)
	}
	agent := got.Items[0]
	if agent.Name != "agent" || agent.Kind != "agent" || agent.State != wsproto.StateRunning || agent.Version != "9.9.9" {
		t.Fatalf("agent component = %+v", agent)
	}
	if !log.contains("supervised processes") {
		t.Fatalf("no warning for the panicking probe: %v", log.warns)
	}
}
