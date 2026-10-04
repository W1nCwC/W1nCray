package limiter

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

func TestDeviceLimitLocal(t *testing.T) {
	l := New()
	in := l.AddInbound("n", false)
	in.SetUsers([]User{{UID: 1, Email: "a", DeviceLimit: 2}})

	s1, err := l.Acquire("n", "a", "1.1.1.1")
	if err != nil || s1 == nil {
		t.Fatalf("first ip: %v", err)
	}
	if _, err := l.Acquire("n", "a", "1.1.1.1"); err != nil {
		t.Fatalf("same ip must pass: %v", err)
	}
	if _, err := l.Acquire("n", "a", "2.2.2.2"); err != nil {
		t.Fatalf("second ip: %v", err)
	}
	if _, err := l.Acquire("n", "a", "3.3.3.3"); !errors.Is(err, ErrDeviceLimit) {
		t.Fatalf("third ip: got %v, want ErrDeviceLimit", err)
	}
}

func TestDeviceLimitReleaseAndWindow(t *testing.T) {
	l := New()
	in := l.AddInbound("n", false)
	in.SetUsers([]User{{UID: 1, Email: "a", DeviceLimit: 1}})

	s, _ := l.Acquire("n", "a", "1.1.1.1")
	s.Release()
	s.Release() // idempotent
	// Still within the report window: the IP counts as online.
	if _, err := l.Acquire("n", "a", "2.2.2.2"); !errors.Is(err, ErrDeviceLimit) {
		t.Fatalf("recently seen ip must still count: %v", err)
	}
	// After the window the idle IP is forgotten.
	in.AliveIPs(0)
	if _, err := l.Acquire("n", "a", "2.2.2.2"); err != nil {
		t.Fatalf("after window: %v", err)
	}
}

func TestDeviceLimitGlobal(t *testing.T) {
	l := New()
	in := l.AddInbound("n", false)
	in.SetUsers([]User{{UID: 7, Email: "a", DeviceLimit: 2}})

	s, _ := l.Acquire("n", "a", "1.1.1.1")
	alive := in.AliveIPs(time.Minute)
	if got := alive[7]; len(got) != 1 || got[0] != "1.1.1.1" {
		t.Fatalf("alive = %v", alive)
	}
	// Panel: 2 devices in total, one of which is ours -> one on another node.
	in.SetGlobalAlive(map[int]int{7: 2})
	if _, err := l.Acquire("n", "a", "2.2.2.2"); !errors.Is(err, ErrDeviceLimit) {
		t.Fatalf("global count must apply: %v", err)
	}
	if _, err := l.Acquire("n", "a", "1.1.1.1"); err != nil {
		t.Fatalf("known ip must pass: %v", err)
	}
	s.Release()
}

func TestUnknownUserPasses(t *testing.T) {
	l := New()
	l.AddInbound("n", false).SetUsers([]User{{UID: 1, Email: "a"}})
	if s, err := l.Acquire("n", "zzz", "1.1.1.1"); s != nil || err != nil {
		t.Fatalf("unknown user: %v %v", s, err)
	}
	if s, err := l.Acquire("other", "a", "1.1.1.1"); s != nil || err != nil {
		t.Fatalf("unknown inbound: %v %v", s, err)
	}
}

func TestSpeedLimitBuckets(t *testing.T) {
	l := New()
	in := l.AddInbound("n", false)
	in.SetUsers([]User{{UID: 1, Email: "slow", SpeedLimit: 1000}, {UID: 2, Email: "fast"}})
	s, _ := l.Acquire("n", "slow", "1.1.1.1")
	if !s.Limited() || s.Up == s.Down {
		t.Fatal("limited user needs separate up/down buckets")
	}
	f, _ := l.Acquire("n", "fast", "1.1.1.1")
	if f.Limited() {
		t.Fatal("unlimited user must not be wrapped")
	}

	// Lifting the limit updates the live bucket of open connections.
	in.UpdateUser("slow", 0, 0)
	if s.Down.Limit() != rate.Inf {
		t.Fatalf("limit = %v, want Inf", s.Down.Limit())
	}

	// alwaysWrap gives unlimited users (infinite) buckets for later limits.
	in2 := l.AddInbound("m", true)
	in2.SetUsers([]User{{UID: 2, Email: "fast"}})
	w, _ := l.Acquire("m", "fast", "1.1.1.1")
	if !w.Limited() || w.Down.Limit() != rate.Inf {
		t.Fatal("alwaysWrap must give an infinite bucket")
	}
	in2.UpdateUser("fast", 500, 0)
	if w.Down.Limit() != 500 {
		t.Fatalf("live bucket limit = %v", w.Down.Limit())
	}
}

// XrayR called rate.Limiter.WaitN with n > burst, which fails immediately and
// let the data through unthrottled.
func TestWaitNLargerThanBurst(t *testing.T) {
	lim := rate.NewLimiter(rate.Limit(100*1024), 64*1024) // 100 KiB/s, burst 64 KiB
	if err := lim.WaitN(context.Background(), 200*1024); err == nil {
		t.Fatal("expected x/time/rate to reject n > burst (the XrayR bug)")
	}
	start := time.Now()
	if err := WaitN(context.Background(), lim, 200*1024); err != nil {
		t.Fatal(err)
	}
	// 200 KiB with a 64 KiB burst at 100 KiB/s needs >= ~1.36 s.
	if el := time.Since(start); el < 1200*time.Millisecond {
		t.Fatalf("throttling too weak: %v", el)
	}
}

func TestWriterThrottles(t *testing.T) {
	lim := rate.NewLimiter(rate.Limit(256*1024), 64*1024)
	var sink countWriter
	w := NewWriter(context.Background(), &sink, lim)
	start := time.Now()
	for i := 0; i < 40; i++ { // 40 x 8 KiB = 320 KiB
		b := buf.New()
		b.Extend(buf.Size)
		if err := w.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			t.Fatal(err)
		}
	}
	// (320-64) KiB at 256 KiB/s = 1 s.
	if el := time.Since(start); el < 800*time.Millisecond {
		t.Fatalf("writer not throttled: %v", el)
	}
	if sink.n != 40*buf.Size {
		t.Fatalf("wrote %d bytes", sink.n)
	}
}

type countWriter struct{ n int }

func (c *countWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	c.n += int(mb.Len())
	buf.ReleaseMulti(mb)
	return nil
}

// sync.devices gives the user's IPs on all nodes; the check counts unique IPs
// exactly like Xboard (DeviceStateService::getDeviceCount).
func TestDeviceLimitGlobalIPs(t *testing.T) {
	l := New()
	in := l.AddInbound("n", false)
	in.SetUsers([]User{{UID: 1, Email: "a", DeviceLimit: 2}, {UID: 2, Email: "b", DeviceLimit: 1}})

	in.SetGlobalDevices(map[int][]string{1: {"9.9.9.9"}, 2: {"1.1.1.1"}})
	if _, err := l.Acquire("n", "a", "1.1.1.1"); err != nil {
		t.Fatalf("1 elsewhere + 1 here must fit a limit of 2: %v", err)
	}
	if _, err := l.Acquire("n", "a", "2.2.2.2"); !errors.Is(err, ErrDeviceLimit) {
		t.Fatalf("third unique IP: %v", err)
	}
	// The same IP on another node is one device, not two.
	if _, err := l.Acquire("n", "b", "1.1.1.1"); err != nil {
		t.Fatalf("same IP as on another node: %v", err)
	}

	// Without WebSocket data only the local IPs (and the alive list
	// estimate, 0 here) count: 9.9.9.9 elsewhere is no longer known.
	in.ClearGlobalDevices()
	if _, err := l.Acquire("n", "a", "2.2.2.2"); err != nil {
		t.Fatalf("second local IP with limit 2: %v", err)
	}
	if _, err := l.Acquire("n", "a", "3.3.3.3"); !errors.Is(err, ErrDeviceLimit) {
		t.Fatalf("third local IP: %v", err)
	}
}
