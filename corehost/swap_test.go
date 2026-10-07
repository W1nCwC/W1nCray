package corehost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/core"
	"github.com/W1nCwC/W1nCray/driver/xray"
)

// startTestCore builds and starts a bare core for the Swappable tests.
func startTestCore(t *testing.T) *core.Core {
	t.Helper()
	c, err := core.New(core.Options{
		LogLevel:   "warning",
		Connection: core.ConnectionPolicy{Handshake: 4, ConnIdle: 300, UplinkOnly: 5, DownlinkOnly: 5, BufferSize: 64},
		Forward:    &core.ForwardOptions{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestSwappableWithoutCore: every method of an empty Swappable either returns
// ErrNoCore or a zero value; none of them panics.
func TestSwappableWithoutCore(t *testing.T) {
	h := NewSwappable()
	if h.Core() != nil {
		t.Fatal("a fresh Swappable has a core")
	}
	if err := h.AddInbound(nil); !errors.Is(err, ErrNoCore) {
		t.Errorf("AddInbound = %v, want ErrNoCore", err)
	}
	if err := h.RemoveInbound("w1n-fwd/i/x"); !errors.Is(err, ErrNoCore) {
		t.Errorf("RemoveInbound = %v, want ErrNoCore", err)
	}
	if err := h.AddOutbound(nil); !errors.Is(err, ErrNoCore) {
		t.Errorf("AddOutbound = %v, want ErrNoCore", err)
	}
	if err := h.RemoveOutbound("w1n-fwd/o/x"); !errors.Is(err, ErrNoCore) {
		t.Errorf("RemoveOutbound = %v, want ErrNoCore", err)
	}
	if err := h.SetRules("w1n-fwd", nil, nil); !errors.Is(err, ErrNoCore) {
		t.Errorf("SetRules = %v, want ErrNoCore", err)
	}
	if n := h.Kill("w1n-fwd/i/x"); n != 0 {
		t.Errorf("Kill = %d, want 0", n)
	}
	if active, total := h.Conns("w1n-fwd/i/x"); active != 0 || total != 0 {
		t.Errorf("Conns = %d/%d, want 0/0", active, total)
	}
	if v, ok := h.Counter("inbound>>>w1n-fwd/i/x>>>traffic>>>uplink"); v != 0 || ok {
		t.Errorf("Counter = %d/%v, want 0/false", v, ok)
	}
	h.DropCounter("inbound>>>w1n-fwd/i/x>>>traffic>>>uplink") // must not panic
	if h.Dispatcher() != nil {
		t.Error("Dispatcher is not nil without a core")
	}
	if h.OutboundManager() != nil {
		t.Error("OutboundManager is not nil without a core")
	}
}

// TestSwappableSwapRoutesCallsToTheNewCore: after Swap the driver's calls reach
// the new core and leave the old one alone, and a Swap(nil) detaches cleanly.
func TestSwappableSwapRoutesCallsToTheNewCore(t *testing.T) {
	a, b := startTestCore(t), startTestCore(t)
	h := NewSwappable()
	h.Swap(a)
	if h.Core() != a {
		t.Fatal("Swap did not install the core")
	}

	drv := xray.New(h, xray.Options{Policy: openPolicy()})
	rt := driver.Runtime{StateDir: t.TempDir(), Log: nopLogger{}}
	target := echoServer(t, "")
	lp := freePort(t)
	in := fwd("s1", lp, target)
	art, err := drv.Render(in)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if _, err := drv.Apply(context.Background(), rt, []driver.Rendered{{Instance: in, Artifact: art}}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", lp)

	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial the forward on core A: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, 4)); err != nil {
		t.Fatalf("echo through the forward: %v", err)
	}
	if active, _ := h.Conns("w1n-fwd/i/s1"); active < 1 {
		t.Fatalf("Conns on core A = %d, want the live session", active)
	}

	// Swap: every call now reaches core B, which does not know the instance.
	// A missing-tag RemoveInbound is not an error, so the proof that the call
	// did not reach core A is that core A's listener survives it.
	h.Swap(b)
	if h.Core() != b {
		t.Fatal("Swap did not install the second core")
	}
	if active, total := h.Conns("w1n-fwd/i/s1"); active != 0 || total != 0 {
		t.Fatalf("Conns after Swap = %d/%d, want 0/0 (core B has no such instance)", active, total)
	}
	if err := h.RemoveInbound("w1n-fwd/i/s1"); err != nil {
		t.Fatalf("RemoveInbound on core B = %v, want nil (missing tag)", err)
	}
	c2, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("core A's listener is gone: the call reached the old core (%v)", err)
	}
	c2.Close()

	// Swap back: the call reaches core A again and really removes the inbound.
	h.Swap(a)
	if err := h.RemoveInbound("w1n-fwd/i/s1"); err != nil {
		t.Fatalf("RemoveInbound on core A: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		c3, derr := net.DialTimeout("tcp", addr, time.Second)
		if derr != nil {
			break
		}
		c3.Close()
		if time.Now().After(deadline) {
			t.Fatal("core A still serves the inbound that was removed through the host")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Detaching makes every call fail cleanly.
	h.Swap(nil)
	if h.Core() != nil {
		t.Fatal("Swap(nil) did not detach the core")
	}
	if err := h.AddInbound(nil); !errors.Is(err, ErrNoCore) {
		t.Errorf("AddInbound after detach = %v, want ErrNoCore", err)
	}
	if h.Dispatcher() != nil {
		t.Error("Dispatcher is not nil after detach")
	}
}
