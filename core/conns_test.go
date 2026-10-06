package core

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/infra/conf"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// echoServer echoes TCP streams and UDP datagrams on one port.
func echoServer(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		l.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close(); pc.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	go func() {
		b := make([]byte, 2048)
		for {
			n, a, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			pc.WriteTo(b[:n], a)
		}
	}()
	return port
}

// addForward adds a dokodemo-door inbound forwarding to the echo server.
func addForward(t *testing.T, c *Core, tag string, target int, network string) int {
	t.Helper()
	port := freePort(t)
	raw := fmt.Sprintf(`{"tag":%q,"listen":"127.0.0.1","port":%d,"protocol":"dokodemo-door",
		"settings":{"address":"127.0.0.1","port":%d,"network":%q}}`, tag, port, target, network)
	var ic conf.InboundDetourConfig
	if err := json.Unmarshal([]byte(raw), &ic); err != nil {
		t.Fatal(err)
	}
	hc, err := ic.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddInbound(hc); err != nil {
		t.Fatal(err)
	}
	return port
}

func dialEcho(t *testing.T, port int) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	roundTrip(t, conn)
	return conn
}

func roundTrip(t *testing.T, conn net.Conn) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(conn, b); err != nil || string(b) != "ping" {
		t.Fatalf("echo = %q, %v", b, err)
	}
}

// mustBeAborted waits for the connection to be closed by the other side.
func mustBeAborted(t *testing.T, conn net.Conn) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("unexpected data on an aborted connection")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("connection still open 2 s after Kill")
	}
}

// D-C: the established connections of an inbound survive its removal (Xray
// only stops the listener); the tracker makes them abortable. Only inbounds
// whose tag was passed to Watch are tracked.
func TestConnTrackerTCP(t *testing.T) {
	c := newTestCore(t)
	echo := echoServer(t)
	c.Conns().Watch("fwd-")
	fwdPort := addForward(t, c, "fwd-1", echo, "tcp")
	nodePort := addForward(t, c, "node-1", echo, "tcp") // not watched

	conn := dialEcho(t, fwdPort)
	other := dialEcho(t, nodePort)
	if got := c.Conns().Active("fwd-1"); got != 1 {
		t.Fatalf("Active(fwd-1) = %d, want 1", got)
	}
	if got := c.Conns().Total("fwd-1"); got != 1 {
		t.Fatalf("Total(fwd-1) = %d, want 1", got)
	}
	if got := c.Conns().Active("node-1"); got != 0 {
		t.Fatalf("unwatched inbound tracked: Active(node-1) = %d", got)
	}

	// Baseline of the defect: RemoveInbound does not end the connection.
	if err := c.RemoveInbound("fwd-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", fwdPort), time.Second); err == nil {
		t.Fatal("removed inbound still accepts connections")
	}
	roundTrip(t, conn)
	if got := c.Conns().Active("fwd-1"); got != 1 {
		t.Fatalf("Active after RemoveInbound = %d, want 1", got)
	}

	if n := c.Conns().Kill("fwd-1"); n != 1 {
		t.Fatalf("Kill = %d, want 1", n)
	}
	mustBeAborted(t, conn)
	waitFor(t, 2*time.Second, "Active(fwd-1) = 0", func() bool { return c.Conns().Active("fwd-1") == 0 })
	if got := c.Conns().Total("fwd-1"); got != 1 {
		t.Fatalf("Total after Kill = %d, want 1", got)
	}

	// Connections of unwatched inbounds are not touched.
	if n := c.Conns().KillAll(); n != 0 {
		t.Fatalf("KillAll = %d, want 0", n)
	}
	roundTrip(t, other)
}

// A session that ends on its own deregisters itself. The core policy of the
// test (downlinkOnly 4 s) is what delays this by about 4 s.
func TestConnTrackerEndsWhenClientCloses(t *testing.T) {
	if testing.Short() {
		t.Skip("takes about 4 s")
	}
	c := newTestCore(t)
	echo := echoServer(t)
	c.Conns().Watch("fwd-")
	port := addForward(t, c, "fwd-1", echo, "tcp")
	conn := dialEcho(t, port)
	if got := c.Conns().Active("fwd-1"); got != 1 {
		t.Fatalf("Active = %d, want 1", got)
	}
	conn.Close()
	waitFor(t, 10*time.Second, "session to deregister", func() bool { return c.Conns().Active("fwd-1") == 0 })
}

func TestRemoveInboundAndKill(t *testing.T) {
	c := newTestCore(t)
	echo := echoServer(t)
	c.Conns().Watch("fwd-")
	port := addForward(t, c, "fwd-1", echo, "tcp")
	conns := []net.Conn{dialEcho(t, port), dialEcho(t, port), dialEcho(t, port)}
	if got := c.Conns().Active("fwd-1"); got != 3 {
		t.Fatalf("Active = %d, want 3", got)
	}
	n, err := c.RemoveInboundAndKill("fwd-1")
	if err != nil || n != 3 {
		t.Fatalf("RemoveInboundAndKill = %d, %v; want 3, nil", n, err)
	}
	for _, conn := range conns {
		mustBeAborted(t, conn)
	}
}

// UDP flows have no inbound connection to close; Kill cancels their session.
func TestConnTrackerUDP(t *testing.T) {
	c := newTestCore(t)
	echo := echoServer(t)
	c.Conns().Watch("fwd-")
	port := addForward(t, c, "fwd-u", echo, "udp")

	conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 16)
	if n, err := conn.Read(b); err != nil || string(b[:n]) != "ping" {
		t.Fatalf("udp echo = %q, %v", b[:n], err)
	}
	if got := c.Conns().Active("fwd-u"); got != 1 {
		t.Fatalf("Active(fwd-u) = %d, want 1", got)
	}
	if n := c.Conns().Kill("fwd-u"); n != 1 {
		t.Fatalf("Kill = %d, want 1", n)
	}
	waitFor(t, 2*time.Second, "Active(fwd-u) = 0", func() bool { return c.Conns().Active("fwd-u") == 0 })
}
