//go:build linux

package telemetry

import (
	"context"
	"testing"
	"time"
)

func TestLoadAverageLinux(t *testing.T) {
	l1, l5, l15, ok := loadAverageOS()
	if !ok {
		t.Fatal("/proc/loadavg unreadable")
	}
	if l1 < 0 || l5 < 0 || l15 < 0 {
		t.Fatalf("load averages = %v/%v/%v, want non-negative", l1, l5, l15)
	}
}

func TestSocketCountsLinux(t *testing.T) {
	tcp, udp, ok := socketCountsOS()
	if !ok {
		t.Fatal("/proc/net/{tcp,udp} unreadable")
	}
	if tcp < 0 || udp < 0 {
		t.Fatalf("socket counts = %d/%d, want non-negative", tcp, udp)
	}
}

func TestSelfRSSLinux(t *testing.T) {
	rss, ok := selfRSSBytesOS()
	if !ok || rss == 0 {
		t.Fatalf("self RSS = %d/%v, want a non-zero resident size", rss, ok)
	}
}

// WP2 acceptance 2: a real sample on Linux. The bandwidth totals need a
// non-loopback interface, which a network namespace without one does not have;
// such a host is skipped rather than failed.
func TestRealSampleLinux(t *testing.T) {
	c := New(Options{})
	hi := c.HostInfo(context.Background())
	if hi.MemTotal == 0 {
		t.Fatal("mem_total = 0")
	}
	if hi.CPUCores == 0 {
		t.Fatal("cpu_cores = 0")
	}
	if hi.CPUThreads < hi.CPUCores {
		t.Fatalf("cpu_threads %d < cpu_cores %d", hi.CPUThreads, hi.CPUCores)
	}
	// A VPS carries its public address on the interface itself, so either list
	// may hold it; what must not happen is a host with an address and neither list.
	if len(hi.IPs.Private)+len(hi.IPs.Public) == 0 {
		t.Fatal("no interface address reported")
	}

	if _, _, ok := netCounters(); !ok {
		t.Skip("no non-loopback interface on this host")
	}

	first := c.Telemetry(context.Background())
	if first.Net.InTotal == 0 || first.Net.OutTotal == 0 {
		t.Fatalf("net totals = %d/%d, want the cumulative counters", first.Net.InTotal, first.Net.OutTotal)
	}
	if first.Conns == nil {
		t.Fatal("conns = nil on Linux, want the socket counts")
	}

	time.Sleep(1100 * time.Millisecond)
	second := c.Telemetry(context.Background())
	if second.TS <= first.TS {
		t.Fatalf("ts did not advance: %d then %d", first.TS, second.TS)
	}
	if second.Net.InTotal < first.Net.InTotal || second.Net.OutTotal < first.Net.OutTotal {
		t.Fatalf("totals went backwards: %+v then %+v", first.Net, second.Net)
	}
}
