package telemetry

import (
	"context"
	"errors"
	"math"
	"testing"

	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"

	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

func TestClampPct(t *testing.T) {
	cases := map[float64]float64{
		-1:         0,
		0:          0,
		42.5:       42.5,
		100:        100,
		150:        100,
		math.NaN(): 0,
	}
	for in, want := range cases {
		if got := clampPct(in); got != want {
			t.Errorf("clampPct(%v) = %v, want %v", in, got, want)
		}
	}
}

func TestMemoryUsage(t *testing.T) {
	swap(t, &virtualMemory, func(context.Context) (*mem.VirtualMemoryStat, error) {
		return &mem.VirtualMemoryStat{Total: 1000, Used: 400}, nil
	})
	swap(t, &swapMemory, func(context.Context) (*mem.SwapMemoryStat, error) {
		return &mem.SwapMemoryStat{Total: 2000, Used: 100}, nil
	})
	got, sw := memoryUsage(context.Background())
	if got.Total != 1000 || got.Used != 400 || sw.Total != 2000 || sw.Used != 100 {
		t.Fatalf("memoryUsage = %+v / %+v", got, sw)
	}
}

func TestMemoryUsagePartialFailure(t *testing.T) {
	swap(t, &virtualMemory, func(context.Context) (*mem.VirtualMemoryStat, error) {
		return nil, errors.New("boom")
	})
	swap(t, &swapMemory, func(context.Context) (*mem.SwapMemoryStat, error) {
		return &mem.SwapMemoryStat{Total: 2000, Used: 100}, nil
	})
	got, sw := memoryUsage(context.Background())
	if got != (wsproto.Usage{}) {
		t.Fatalf("ram = %+v, want zero", got)
	}
	if sw.Total != 2000 {
		t.Fatalf("swap = %+v, want 2000", sw)
	}
}

func TestDiskUsageFiltersPseudoFilesystemsAndSorts(t *testing.T) {
	swap(t, &partitions, func(context.Context, bool) ([]disk.PartitionStat, error) {
		return []disk.PartitionStat{
			{Mountpoint: "/var", Fstype: "ext4"},
			{Mountpoint: "/", Fstype: "ext4"},
			{Mountpoint: "/proc", Fstype: "proc"},
			{Mountpoint: "/run", Fstype: "tmpfs"},
			{Mountpoint: "/var/lib/docker", Fstype: "overlay"},
			{Mountpoint: "/", Fstype: "ext4"}, // duplicate mount
			{Mountpoint: "", Fstype: "ext4"},  // no mount point
			{Mountpoint: "/broken", Fstype: "ext4"},
		}, nil
	})
	swap(t, &usageOf, func(_ context.Context, path string) (*disk.UsageStat, error) {
		switch path {
		case "/":
			return &disk.UsageStat{Total: 100, Used: 40}, nil
		case "/var":
			return &disk.UsageStat{Total: 200, Used: 50}, nil
		default:
			return nil, errors.New("boom")
		}
	})

	got := diskUsage(context.Background())
	if len(got) != 2 {
		t.Fatalf("disks = %+v, want / and /var", got)
	}
	if got[0].Mount != "/" || got[0].Total != 100 || got[0].Used != 40 {
		t.Fatalf("first disk = %+v", got[0])
	}
	if got[1].Mount != "/var" || got[1].Total != 200 || got[1].Used != 50 {
		t.Fatalf("second disk = %+v", got[1])
	}
}

func TestDiskUsageOnPartitionError(t *testing.T) {
	swap(t, &partitions, func(context.Context, bool) ([]disk.PartitionStat, error) {
		return nil, errors.New("boom")
	})
	if got := diskUsage(context.Background()); len(got) != 0 {
		t.Fatalf("disks = %+v, want none", got)
	}
}

func TestProcessCount(t *testing.T) {
	swap(t, &processPids, func(context.Context) ([]int32, error) { return []int32{1, 2, 3}, nil })
	if got := processCount(context.Background()); got != 3 {
		t.Fatalf("processCount = %d, want 3", got)
	}
	swap(t, &processPids, func(context.Context) ([]int32, error) { return nil, errors.New("boom") })
	if got := processCount(context.Background()); got != 0 {
		t.Fatalf("processCount on error = %d, want 0", got)
	}
}

func TestUptimeSeconds(t *testing.T) {
	swap(t, &hostUptime, func(context.Context) (uint64, error) { return 42, nil })
	if got := uptimeSeconds(context.Background()); got != 42 {
		t.Fatalf("uptimeSeconds = %d, want 42", got)
	}
	swap(t, &hostUptime, func(context.Context) (uint64, error) { return 0, errors.New("boom") })
	if got := uptimeSeconds(context.Background()); got != 0 {
		t.Fatalf("uptimeSeconds on error = %d, want 0", got)
	}
}
