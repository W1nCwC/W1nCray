package corehost

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/core"
	"github.com/W1nCwC/W1nCray/driver/xray"
)

// nopLogger swallows the driver's log lines.
type nopLogger struct{}

func (nopLogger) Debugf(string, ...any) {}
func (nopLogger) Infof(string, ...any)  {}
func (nopLogger) Warnf(string, ...any)  {}
func (nopLogger) Errorf(string, ...any) {}

// openPolicy mirrors the driver's own test policy: loopback listen, private
// targets allowed.
func openPolicy() *spec.Policy {
	return &spec.Policy{
		AllowListen:     []string{"127.0.0.1", "10.0.0.0/8", "0.0.0.0"},
		PrivilegedPorts: true,
		AllowPrivate:    true,
		DenyCIDRs:       []string{"169.254.0.0/16"},
	}
}

// rig is one running core.Core, its production Host and the xray driver on
// top of them.
type rig struct {
	t   *testing.T
	c   *core.Core
	h   xray.Host
	drv *xray.Driver
	rt  driver.Runtime
}

func newRig(t *testing.T) *rig {
	t.Helper()
	c, err := core.New(core.Options{
		LogLevel:   "warning",
		Connection: core.ConnectionPolicy{Handshake: 4, ConnIdle: 300, UplinkOnly: 5, DownlinkOnly: 5, BufferSize: 64},
		// Forward turns the per-inbound/outbound byte counters on.
		Forward: &core.ForwardOptions{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	h, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	return &rig{
		t: t, c: c, h: h,
		drv: xray.New(h, xray.Options{Policy: openPolicy()}),
		rt:  driver.Runtime{StateDir: t.TempDir(), Log: nopLogger{}},
	}
}

// apply renders and applies instances through the driver's public API.
func (r *rig) apply(ins ...spec.Instance) {
	r.t.Helper()
	var set []driver.Rendered
	for _, in := range ins {
		a, err := r.drv.Render(in)
		if err != nil {
			r.t.Fatalf("render %s: %v", in.ID, err)
		}
		set = append(set, driver.Rendered{Instance: in, Artifact: a})
	}
	if _, err := r.drv.Apply(context.Background(), r.rt, set); err != nil {
		r.t.Fatalf("apply: %v", err)
	}
}

// fwd builds a TCP forward instance listening on lp and sending to target.
func fwd(id string, lp int, target string, networks ...string) spec.Instance {
	if len(networks) == 0 {
		networks = []string{"tcp"}
	}
	h, p, _ := net.SplitHostPort(target)
	return spec.Instance{
		ID: id, Enabled: true, Engine: spec.EngineXray, Kind: spec.KindForward,
		Listen:  &spec.Listen{Addr: "127.0.0.1", Ports: fmt.Sprint(lp)},
		Network: networks,
		Targets: []spec.Target{{Host: h, Ports: p}},
	}
}

// ---------------------------------------------------------------- servers

func tcpServer(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); handle(c) }()
		}
	}()
	return l.Addr().String()
}

// echoServer echoes everything; with a tag it first sends "tag\n".
func echoServer(t *testing.T, tag string) string {
	return tcpServer(t, func(c net.Conn) {
		if tag != "" {
			fmt.Fprintf(c, "%s\n", tag)
		}
		io.Copy(c, c)
	})
}

func udpEchoServer(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			pc.WriteTo(b[:n], a)
		}
	}()
	return pc.LocalAddr().String()
}

// dualEcho runs a TCP and a UDP echo server on the same loopback port.
func dualEcho(t *testing.T) (host string, port int) {
	t.Helper()
	port = freePort(t)
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			pc.WriteTo(b[:n], a)
		}
	}()
	return "127.0.0.1", port
}

// proxyServer expects a PROXY header and reports the source it announced.
func proxyServer(t *testing.T) (addr string, got chan net.Addr) {
	t.Helper()
	got = make(chan net.Addr, 16)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pl := &proxyproto.Listener{Listener: l, ReadHeaderTimeout: 2 * time.Second}
	t.Cleanup(func() { pl.Close() })
	go func() {
		for {
			c, err := pl.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				ra := c.RemoteAddr() // blocks until the header has been read
				if pc, ok := c.(*proxyproto.Conn); ok && pc.ProxyHeader() == nil {
					return
				}
				got <- ra
				io.Copy(c, c)
			}()
		}
	}()
	return l.Addr().String(), got
}

// ---------------------------------------------------------------- clients

func tcpEcho(addr string, payload []byte, skipTag bool) (string, error) {
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	tag := ""
	if skipTag {
		var line []byte
		one := make([]byte, 1)
		for {
			if _, err := io.ReadFull(c, one); err != nil {
				return "", fmt.Errorf("reading tag: %w", err)
			}
			if one[0] == '\n' {
				break
			}
			line = append(line, one[0])
		}
		tag = string(line)
	}
	werr := make(chan error, 1)
	go func() { _, err := c.Write(payload); werr <- err }()
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(c, buf); err != nil {
		return tag, fmt.Errorf("read echo: %w", err)
	}
	if err := <-werr; err != nil {
		return tag, err
	}
	if !bytes.Equal(buf, payload) {
		return tag, fmt.Errorf("echo mismatch (%d bytes)", len(buf))
	}
	return tag, nil
}

func udpEcho(addr string, payload []byte) error {
	c, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(payload); err != nil {
		return err
	}
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil {
		return err
	}
	if !bytes.Equal(buf[:n], payload) {
		return fmt.Errorf("udp echo mismatch")
	}
	return nil
}

// ---------------------------------------------------------------- helpers

func freePort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 100; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
		l.Close()
		if err != nil {
			continue
		}
		pc.Close()
		return port
	}
	t.Fatal("no free port")
	return 0
}

// freeRange returns the first port of n consecutive free ports.
func freeRange(t *testing.T, n int) int {
	t.Helper()
	for i := 0; i < 200; i++ {
		base := freePort(t)
		if base+n > 65000 {
			continue
		}
		ok := true
		var ls []io.Closer
		for p := base; p < base+n && ok; p++ {
			l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
			if err != nil {
				ok = false
				break
			}
			ls = append(ls, l)
			pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", p))
			if err != nil {
				ok = false
				break
			}
			ls = append(ls, pc)
		}
		for _, l := range ls {
			l.Close()
		}
		if ok {
			return base
		}
	}
	t.Fatal("no free port range")
	return 0
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	var x uint32 = 12345
	for i := range b {
		x = x*1664525 + 1013904223
		b[i] = byte(x >> 24)
	}
	return b
}

// waitCounters polls until every named counter has exactly the wanted value.
func waitCounters(t *testing.T, h xray.Host, want map[string]uint64) {
	t.Helper()
	// Generous: under -race the whole pipeline is several times slower and
	// the counters update as connections tear down. Follow the test deadline
	// (the gate runs packages concurrently under load); 10 minutes if the
	// test has none.
	deadline, ok := t.Deadline()
	if ok {
		deadline = deadline.Add(-60 * time.Second)
	} else {
		deadline = time.Now().Add(10 * time.Minute)
	}
	for {
		ok := true
		for name, w := range want {
			v, present := h.Counter(name)
			if !present || v != w {
				ok = false
				break
			}
		}
		if ok {
			return
		}
		if time.Now().After(deadline) {
			for name, w := range want {
				v, present := h.Counter(name)
				t.Logf("counter %s = %d (present %v), want %d", name, v, present, w)
			}
			t.Fatalf("counters did not reach the expected values")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// inCounter / outCounter build the counter names the driver harvests.
func inCounter(id, dir string) string {
	return "inbound>>>w1n-fwd/i/" + id + ">>>traffic>>>" + dir
}
func outCounter(id, dir string) string {
	return "outbound>>>w1n-fwd/o/" + id + ">>>traffic>>>" + dir
}

// ---------------------------------------------------------------- tests

// TCP direct forward plus the byte counters of the inbound and outbound.
func TestTCPForwardAndCounters(t *testing.T) {
	r := newRig(t)
	target := echoServer(t, "")
	lp := freePort(t)
	r.apply(fwd("f1", lp, target))
	addr := fmt.Sprintf("127.0.0.1:%d", lp)

	total := uint64(0)
	for _, size := range []int{1, 1000, 65536} {
		if _, err := tcpEcho(addr, randBytes(size), false); err != nil {
			t.Fatalf("tcp %d bytes: %v", size, err)
		}
		total += uint64(size)
	}
	// A plain dokodemo-door -> freedom forward is byte transparent, so every
	// counter (both directions of both handlers) equals the bytes sent.
	waitCounters(t, r.h, map[string]uint64{
		inCounter("f1", "uplink"):    total,
		inCounter("f1", "downlink"):  total,
		outCounter("f1", "uplink"):   total,
		outCounter("f1", "downlink"): total,
	})
	if _, ok := r.h.Counter("inbound>>>w1n-fwd/i/nope>>>traffic>>>uplink"); ok {
		t.Fatal("Counter reported a non-existent counter as present")
	}
	// The driver's Stats reads the same counters.
	st, err := r.drv.Stats(context.Background(), r.rt)
	if err != nil || len(st) != 1 || st[0].InstanceID != "f1" {
		t.Fatalf("stats %+v %v", st, err)
	}
	if st[0].BytesUp != total || st[0].BytesDown != total {
		t.Fatalf("stats bytes = %d/%d, want %d", st[0].BytesUp, st[0].BytesDown, total)
	}
}

// UDP direct forward.
func TestUDPForward(t *testing.T) {
	r := newRig(t)
	target := udpEchoServer(t)
	lp := freePort(t)
	r.apply(fwd("u1", lp, target, "udp"))
	addr := fmt.Sprintf("127.0.0.1:%d", lp)
	for _, size := range []int{1, 1200} {
		if err := udpEcho(addr, randBytes(size)); err != nil {
			t.Fatalf("udp %d bytes: %v", size, err)
		}
	}
}

// TCP and UDP on one instance and one port.
func TestTCPUDPForward(t *testing.T) {
	r := newRig(t)
	h, port := dualEcho(t)
	lp := freePort(t)
	r.apply(fwd("d1", lp, fmt.Sprintf("%s:%d", h, port), "tcp", "udp"))
	addr := fmt.Sprintf("127.0.0.1:%d", lp)
	if _, err := tcpEcho(addr, randBytes(4096), false); err != nil {
		t.Fatalf("tcp: %v", err)
	}
	if err := udpEcho(addr, randBytes(600)); err != nil {
		t.Fatalf("udp: %v", err)
	}
}

// A listen port range mapped one-to-one onto a target port range.
func TestPortRange(t *testing.T) {
	r := newRig(t)
	tb := freeRange(t, 3)
	var tags []string
	for i := 0; i < 3; i++ {
		tag := fmt.Sprintf("T%d", i)
		tags = append(tags, tag)
		port := tb + i
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go func() { defer c.Close(); fmt.Fprintf(c, "%s\n", tag); io.Copy(c, c) }()
			}
		}()
	}
	lb := freeRange(t, 3)
	in := fwd("rg", lb, "", "tcp")
	in.Listen.Ports = fmt.Sprintf("%d-%d", lb, lb+2)
	in.Targets = []spec.Target{{Host: "127.0.0.1", Ports: fmt.Sprintf("%d-%d", tb, tb+2)}}
	r.apply(in)
	for i := 0; i < 3; i++ {
		tag, err := tcpEcho(fmt.Sprintf("127.0.0.1:%d", lb+i), []byte("x"), true)
		if err != nil || tag != tags[i] {
			t.Fatalf("range port %d: tag %q err %v want %s", lb+i, tag, err, tags[i])
		}
	}
}

// Stop (which tears the instance down and calls Kill) aborts the established
// connection; Conns reflects the tracked session before and after.
func TestKillAbortsEstablished(t *testing.T) {
	r := newRig(t)
	target := echoServer(t, "")
	lp := freePort(t)
	r.apply(fwd("k1", lp, target))
	addr := fmt.Sprintf("127.0.0.1:%d", lp)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ping := func() error {
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte("ping")); err != nil {
			return err
		}
		buf := make([]byte, 4)
		_, err := io.ReadFull(c, buf)
		return err
	}
	if err := ping(); err != nil {
		t.Fatalf("echo through the forward: %v", err)
	}
	active, total := r.h.Conns("w1n-fwd/i/k1")
	if active < 1 || total < 1 {
		t.Fatalf("Conns = %d/%d, want the live session tracked", active, total)
	}
	if n := r.h.Kill("w1n-fwd/i/k1"); n < 1 {
		t.Fatalf("Kill returned %d, want the tracked session", n)
	}
	// The session was aborted: the next read must fail (EOF or reset).
	c.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	if _, err := c.Read(buf); err == nil {
		t.Fatal("connection survived Kill")
	}
	// The tracker deregisters through context.AfterFunc, which lags the Kill
	// itself; under -race that lag is wide, so poll instead of reading once.
	deadline := time.Now().Add(15 * time.Second)
	for {
		if active, _ := r.h.Conns("w1n-fwd/i/k1"); active == 0 {
			break
		}
		if time.Now().After(deadline) {
			active, _ := r.h.Conns("w1n-fwd/i/k1")
			t.Fatalf("Conns active = %d after Kill, want 0", active)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Stop removes the instance through the driver: the listener is gone.
	if err := r.drv.Stop(context.Background(), r.rt, "k1"); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if _, err := tcpEcho(addr, []byte("x"), false); err == nil {
		t.Fatal("stopped instance still serves")
	}
}

// Stop aborts an established connection through the driver's own teardown
// (RemoveInbound + Kill), without calling Kill by hand.
func TestStopAbortsEstablished(t *testing.T) {
	r := newRig(t)
	target := echoServer(t, "")
	lp := freePort(t)
	r.apply(fwd("s1", lp, target))
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", lp))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if err := r.drv.Stop(context.Background(), r.rt); err != nil {
		t.Fatalf("stop: %v", err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(buf[:1]); err == nil {
		t.Fatal("established connection survived Stop")
	}
}

// PROXY protocol v2 send: the target sees the real source of the client.
func TestProxyProtocolV2Send(t *testing.T) {
	r := newRig(t)
	target, got := proxyServer(t)
	lp := freePort(t)
	in := fwd("pp", lp, target)
	in.ProxyProtocolOut = 2
	r.apply(in)

	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", lp))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	local := c.LocalAddr().String()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("echo through the PROXY target: %v", err)
	}
	select {
	case a := <-got:
		if a.String() != local {
			t.Fatalf("target saw source %s, client was %s", a, local)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("target saw no PROXY header")
	}
}

// Missing tags are not errors, and the feature accessors return the instance's
// features.
func TestMissingTagsAndFeatures(t *testing.T) {
	r := newRig(t)
	if err := r.h.RemoveInbound("w1n-fwd/i/missing"); err != nil {
		t.Fatalf("RemoveInbound(missing) = %v", err)
	}
	if err := r.h.RemoveOutbound("w1n-fwd/o/missing"); err != nil {
		t.Fatalf("RemoveOutbound(missing) = %v", err)
	}
	if r.h.Dispatcher() == nil {
		t.Fatal("Dispatcher returned nil")
	}
	if r.h.OutboundManager() == nil {
		t.Fatal("OutboundManager returned nil")
	}
}

// New rejects a nil core.
func TestNewNilCore(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("New(nil) accepted")
	}
}
