//go:build !linux

package telemetry

import (
	"context"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// The Linux-only probes must report "unknown" on other platforms rather than a
// fabricated zero: that is what makes telemetry.conns null instead of {0,0}
// (design R8).
func TestPlatformProbesReportUnknown(t *testing.T) {
	if tcp, udp, ok := socketCountsOS(); ok || tcp != 0 || udp != 0 {
		t.Fatalf("socketCountsOS = %d/%d/%v, want 0/0/false", tcp, udp, ok)
	}
	if rss, ok := selfRSSBytesOS(); ok || rss != 0 {
		t.Fatalf("selfRSSBytesOS = %d/%v, want 0/false", rss, ok)
	}
	if l1, l5, l15, ok := loadAverageOS(); ok || l1 != 0 || l5 != 0 || l15 != 0 {
		t.Fatalf("loadAverageOS = %v/%v/%v/%v, want zero/false", l1, l5, l15, ok)
	}
}

// One real sample on this platform: it must not panic and must not invent the
// values the platform cannot provide.
func TestRealSampleOnThisPlatform(t *testing.T) {
	c := New(Options{})
	hi := c.HostInfo(context.Background())
	if hi.OS == "" || hi.Arch == "" {
		t.Fatalf("os/arch = %q/%q, want the runtime values", hi.OS, hi.Arch)
	}
	if hi.MemTotal == 0 {
		t.Fatal("mem_total = 0, but this platform can report RAM")
	}

	te := c.Telemetry(context.Background())
	if te.TS == 0 {
		t.Fatal("ts = 0")
	}
	if te.CPUPct < 0 || te.CPUPct > 100 {
		t.Fatalf("cpu_pct = %v, want a percentage", te.CPUPct)
	}
	if te.Conns != nil {
		t.Fatalf("conns = %+v, want nil: this platform has no /proc/net", te.Conns)
	}
	if te.Load != (wsproto.Load{}) {
		t.Fatalf("load = %+v, want zero: this platform has no /proc/loadavg", te.Load)
	}
	if te.Mem.Total == 0 {
		t.Fatal("mem.total = 0, but this platform can report RAM")
	}
}
