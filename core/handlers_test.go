package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport"
)

// closeSpy is an outbound handler that records Close calls.
type closeSpy struct {
	tag    string
	closed atomic.Int32
}

func (s *closeSpy) Tag() string                               { return s.tag }
func (s *closeSpy) Dispatch(context.Context, *transport.Link) {}
func (s *closeSpy) Start() error                              { return nil }
func (s *closeSpy) Close() error                              { s.closed.Add(1); return nil }
func (s *closeSpy) SenderSettings() *serial.TypedMessage      { return nil }
func (s *closeSpy) ProxySettings() *serial.TypedMessage       { return nil }

func newTestCore(t *testing.T) *Core {
	t.Helper()
	c, err := New(exampleOptions())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func waitFor(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timeout waiting for %s", what)
}

// D-A: Xray's outbound manager only forgets a removed handler; it never closes
// it, so a handler that owns background work (a reverse bridge's redial task)
// keeps running as a zombie. RemoveOutbound must close it.
func TestRemoveOutboundClosesHandler(t *testing.T) {
	c := newTestCore(t)
	spy := &closeSpy{tag: "spy"}
	if err := c.obm.AddHandler(context.Background(), spy); err != nil {
		t.Fatal(err)
	}
	if !c.HasOutbound("spy") {
		t.Fatal("spy not registered")
	}
	if err := c.RemoveOutbound("spy"); err != nil {
		t.Fatal(err)
	}
	if c.HasOutbound("spy") {
		t.Fatal("spy still registered")
	}
	if n := spy.closed.Load(); n != 1 {
		t.Fatalf("Close called %d times, want 1", n)
	}
	// A missing tag stays a no-op and must not close anything twice.
	if err := c.RemoveOutbound("spy"); err != nil {
		t.Fatal(err)
	}
	if n := spy.closed.Load(); n != 1 {
		t.Fatalf("Close called %d times after second remove, want 1", n)
	}
}

// dumbPortal accepts TCP connections, counts them and holds them open without
// speaking any protocol. It is enough to watch whether a bridge dials.
type dumbPortal struct {
	ln    net.Listener
	count atomic.Int32
	mu    sync.Mutex
	conns []net.Conn
}

func newDumbPortal(t *testing.T) *dumbPortal {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &dumbPortal{ln: ln}
	t.Cleanup(func() { ln.Close(); p.dropAll() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.count.Add(1)
			p.mu.Lock()
			p.conns = append(p.conns, c)
			p.mu.Unlock()
			go io.Copy(io.Discard, c)
		}
	}()
	return p
}

func (p *dumbPortal) port() int { return p.ln.Addr().(*net.TCPAddr).Port }

func (p *dumbPortal) dropAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		c.Close()
	}
	p.conns = nil
}

// D-A end to end: a VLESS reverse bridge outbound redials its portal from a
// monitor task (2 s tick). Removing the outbound must stop that task;
// previously the removed handler kept redialing as a zombie.
func TestRemoveOutboundStopsReverseBridge(t *testing.T) {
	if testing.Short() {
		t.Skip("takes about 8 s")
	}
	if raceEnabled {
		// Upstream xray-core v1.260327.0 writes fields of the VLESS outbound
		// handler after its Reverse monitor goroutine may already call
		// Process (outbound.go:131 vs :159). Detected only by -race and
		// harmless in the no-race runs this assertion belongs to; tracked as
		// an upstream issue.
		t.Skip("upstream VLESS reverse has a constructor-vs-monitor data race")
	}
	c := newTestCore(t)
	p := newDumbPortal(t)

	raw := fmt.Sprintf(`{"protocol":"vless","tag":"bridge-out","settings":{"address":"127.0.0.1","port":%d,
		"id":"5783a3e7-e373-51cd-8642-c83782b807c5","encryption":"none","reverse":{"tag":"bridge-rvs"}}}`, p.port())
	var oc conf.OutboundDetourConfig
	if err := json.Unmarshal([]byte(raw), &oc); err != nil {
		t.Fatal(err)
	}
	hc, err := oc.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddOutbound(hc); err != nil {
		t.Fatal(err)
	}
	// The bridge starts its monitor 2 s after creation and dials at once.
	waitFor(t, 8*time.Second, "first bridge connection", func() bool { return p.count.Load() >= 1 })

	if err := c.RemoveOutbound("bridge-out"); err != nil {
		t.Fatal(err)
	}
	before := p.count.Load()
	// Cut the live link: a still-running bridge sees no active worker and
	// redials at its next tick.
	p.dropAll()
	time.Sleep(5 * time.Second)
	if after := p.count.Load(); after != before {
		t.Fatalf("removed reverse bridge redialed: %d new connection(s) after RemoveOutbound", after-before)
	}
}
