package telemetry

import (
	"context"
	"net"
	"time"

	gnet "github.com/shirou/gopsutil/v4/net"

	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// netSnapshot is the cumulative counter set of one sample. The Collector keeps
// the previous one so it can turn counters into bytes/second.
type netSnapshot struct {
	at   time.Time
	in   uint64
	out  uint64
	seen bool
}

// netSample turns two consecutive counter reads into the contract's Net value.
// It is the only piece of sampling state in this package.
func netSample(prev netSnapshot, now time.Time) (wsproto.Net, netSnapshot) {
	in, out, ok := netCounters()
	if !ok {
		// Unreadable right now: report nothing and keep the previous snapshot.
		// Storing zeros would make the next readable sample look like a jump
		// from zero and invent a huge rate.
		return wsproto.Net{}, prev
	}
	cur := netSnapshot{at: now, in: in, out: out, seen: true}
	n := wsproto.Net{InTotal: in, OutTotal: out}
	if prev.seen {
		dt := now.Sub(prev.at)
		n.InBps = rate(prev.in, cur.in, dt)
		n.OutBps = rate(prev.out, cur.out, dt)
	}
	return n, cur
}

// rate returns the bytes/second between prev and cur. A counter that went
// backwards (32-bit wrap on mips/arm, interface reset, namespace change) yields
// 0 instead of a huge bogus value, and a non-positive dt yields 0. The two
// directions are independent: one wrapping counter must not hide the other.
func rate(prev, cur uint64, dt time.Duration) uint64 {
	if dt <= 0 || cur < prev {
		return 0
	}
	return uint64(float64(cur-prev) / dt.Seconds())
}

// netCountersOS sums the byte counters of every non-loopback interface.
// Loopback traffic is local IPC, not bandwidth, and counting it would double
// every byte the machine exchanges with itself.
func netCountersOS() (in, out uint64, ok bool) {
	counters, err := gnet.IOCountersWithContext(context.Background(), true)
	if err != nil || len(counters) == 0 {
		return 0, 0, false
	}
	return sumCounters(counters, loopbackInterfaces())
}

// sumCounters is separated from the gopsutil call so the loopback filter can be
// tested without real interfaces.
func sumCounters(counters []gnet.IOCountersStat, loopback map[string]bool) (in, out uint64, ok bool) {
	for _, c := range counters {
		if loopback[c.Name] || loopbackName(c.Name) {
			continue
		}
		in += c.BytesRecv
		out += c.BytesSent
		ok = true
	}
	return in, out, ok
}

// loopbackInterfaces asks the standard library which interfaces are loopback.
func loopbackInterfaces() map[string]bool {
	lo := map[string]bool{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return lo
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 {
			lo[ifc.Name] = true
		}
	}
	return lo
}

// loopbackName is the fallback when the interface list is unreadable.
func loopbackName(name string) bool {
	return name == "lo" || name == "lo0"
}
