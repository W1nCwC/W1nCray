package telemetry

import (
	"testing"
	"time"

	gnet "github.com/shirou/gopsutil/v4/net"
)

// swap replaces a probe seam for the duration of one test.
func swap[T any](t *testing.T, p *T, v T) {
	t.Helper()
	old := *p
	*p = v
	t.Cleanup(func() { *p = old })
}

func TestRate(t *testing.T) {
	cases := []struct {
		name string
		prev uint64
		cur  uint64
		dt   time.Duration
		want uint64
	}{
		{"normal", 1000, 3000, 2 * time.Second, 1000},
		{"sub-second", 0, 500, 500 * time.Millisecond, 1000},
		{"equal counters", 4000, 4000, time.Second, 0},
		{"counter wrap", 5000, 1000, 2 * time.Second, 0},
		{"zero dt", 1000, 3000, 0, 0},
		{"negative dt", 1000, 3000, -time.Second, 0},
		{"fractional second", 0, 1500, 1500 * time.Millisecond, 1000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rate(tc.prev, tc.cur, tc.dt); got != tc.want {
				t.Fatalf("rate(%d, %d, %s) = %d, want %d", tc.prev, tc.cur, tc.dt, got, tc.want)
			}
		})
	}
}

// counterStep is one scripted answer of the netCounters seam.
type counterStep struct {
	in, out uint64
	ok      bool
}

// scriptCounters feeds a scripted sequence to the netCounters seam.
func scriptCounters(t *testing.T, seq ...counterStep) {
	t.Helper()
	i := 0
	swap(t, &netCounters, func() (uint64, uint64, bool) {
		if i >= len(seq) {
			t.Fatalf("netCounters called more than %d times", len(seq))
		}
		c := seq[i]
		i++
		return c.in, c.out, c.ok
	})
}

func TestNetSampleFirstSampleHasZeroRateButRealTotals(t *testing.T) {
	scriptCounters(t, counterStep{1000, 2000, true})
	base := time.Unix(1000, 0)

	n, snap := netSample(netSnapshot{}, base)
	if n.InBps != 0 || n.OutBps != 0 {
		t.Fatalf("first sample rates = %d/%d, want 0/0", n.InBps, n.OutBps)
	}
	if n.InTotal != 1000 || n.OutTotal != 2000 {
		t.Fatalf("first sample totals = %d/%d, want 1000/2000", n.InTotal, n.OutTotal)
	}
	if !snap.seen || !snap.at.Equal(base) {
		t.Fatalf("snapshot not recorded: %+v", snap)
	}
}

func TestNetSampleSecondSampleComputesRate(t *testing.T) {
	scriptCounters(t, counterStep{1000, 2000, true}, counterStep{3000, 4000, true})
	base := time.Unix(1000, 0)

	_, snap := netSample(netSnapshot{}, base)
	n, _ := netSample(snap, base.Add(2*time.Second))
	if n.InBps != 1000 || n.OutBps != 1000 {
		t.Fatalf("rates = %d/%d, want 1000/1000", n.InBps, n.OutBps)
	}
	if n.InTotal != 3000 || n.OutTotal != 4000 {
		t.Fatalf("totals = %d/%d, want 3000/4000", n.InTotal, n.OutTotal)
	}
}

func TestNetSampleWrapAffectsOneDirectionOnly(t *testing.T) {
	scriptCounters(t, counterStep{1000, 1000, true}, counterStep{200, 5000, true})
	base := time.Unix(1000, 0)

	_, snap := netSample(netSnapshot{}, base)
	n, _ := netSample(snap, base.Add(2*time.Second))
	if n.InBps != 0 {
		t.Fatalf("wrapped direction rate = %d, want 0", n.InBps)
	}
	if n.OutBps != 2000 {
		t.Fatalf("healthy direction rate = %d, want 2000", n.OutBps)
	}
}

func TestNetSampleNonPositiveDelta(t *testing.T) {
	scriptCounters(t, counterStep{1000, 1000, true}, counterStep{9000, 9000, true})
	base := time.Unix(1000, 0)

	_, snap := netSample(netSnapshot{}, base)
	n, _ := netSample(snap, base) // same instant: the clock did not move
	if n.InBps != 0 || n.OutBps != 0 {
		t.Fatalf("rates = %d/%d, want 0/0", n.InBps, n.OutBps)
	}
}

func TestNetSampleUnreadableKeepsPreviousSnapshot(t *testing.T) {
	scriptCounters(t,
		counterStep{1000, 1000, true},
		counterStep{0, 0, false},
		counterStep{3000, 5000, true},
	)
	base := time.Unix(1000, 0)

	_, snap := netSample(netSnapshot{}, base)
	n, snap2 := netSample(snap, base.Add(time.Second))
	if n.InTotal != 0 || n.OutTotal != 0 || n.InBps != 0 || n.OutBps != 0 {
		t.Fatalf("unreadable sample = %+v, want zero", n)
	}
	if !snap2.seen || snap2.in != 1000 || !snap2.at.Equal(base) {
		t.Fatalf("unreadable sample overwrote the snapshot: %+v", snap2)
	}
	// Four seconds after the last readable sample, so the unreadable window is
	// included in the delta instead of being counted as a jump from zero.
	n, _ = netSample(snap2, base.Add(4*time.Second))
	if n.InBps != 500 || n.OutBps != 1000 {
		t.Fatalf("rates = %d/%d, want 500/1000", n.InBps, n.OutBps)
	}
}

func TestSumCountersSkipsLoopback(t *testing.T) {
	got := []gnet.IOCountersStat{
		{Name: "lo", BytesRecv: 1, BytesSent: 2},
		{Name: "eth0", BytesRecv: 100, BytesSent: 200},
		{Name: "lo0", BytesRecv: 3, BytesSent: 4},
		{Name: "eth1", BytesRecv: 10, BytesSent: 20},
	}
	in, out, ok := sumCounters(got, map[string]bool{"lo": true})
	if !ok || in != 110 || out != 220 {
		t.Fatalf("sumCounters = %d/%d/%v, want 110/220/true", in, out, ok)
	}

	in, out, ok = sumCounters(got[:1], map[string]bool{"lo": true})
	if ok || in != 0 || out != 0 {
		t.Fatalf("all-loopback sumCounters = %d/%d/%v, want 0/0/false", in, out, ok)
	}
}

func TestLoopbackNameFallback(t *testing.T) {
	if !loopbackName("lo") || !loopbackName("lo0") || loopbackName("eth0") {
		t.Fatal("loopbackName misclassifies interface names")
	}
}
