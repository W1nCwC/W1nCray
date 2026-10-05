package xray

// In-process end-to-end tests of the reverse proxy semantics: the portal has
// no targets, the bridge's targets decide where relayed connections go, and
// nobody on the portal side can choose another destination.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	xbuf "github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"

	"github.com/W1nCwC/W1nCray/agent/spec"
)

// reversePair builds a portal and a bridge over a plain vless_enc tcp tunnel.
// bridgeTargets decide the destinations; network is shared by both halves.
func reversePair(t *testing.T, listenPorts string, bridgeTargets []spec.Target, networks ...string) (portalNode, bridgeNode *node, portal, bridge spec.Instance, tunnelAddr string) {
	t.Helper()
	portalNode, bridgeNode = newNode(t, testOpts()), newNode(t, testOpts())
	// the tunnel port must not fall into the (already released) public range
	pr, err := parsePorts(listenPorts)
	if err != nil {
		t.Fatal(err)
	}
	tp := freePort(t)
	for tp >= pr.Lo && tp <= pr.Hi {
		tp = freePort(t)
	}
	tunnelAddr = fmt.Sprintf("127.0.0.1:%d", tp)
	portal = spec.Instance{ID: "rp", Enabled: true, Engine: "xray", Kind: spec.KindReversePortal,
		Listen: &spec.Listen{Addr: "127.0.0.1", Ports: listenPorts}, Network: networks, Secret: testSecret,
		Tunnel:  &spec.Tunnel{Type: "tcp", Security: "vless_enc", Listen: tunnelAddr},
		Reverse: &spec.Reverse{Domain: testDomain}}
	bridge = spec.Instance{ID: "rb", Enabled: true, Engine: "xray", Kind: spec.KindReverseBridge, Network: networks,
		Listen:  &spec.Listen{Ports: listenPorts},
		Targets: bridgeTargets, Secret: testSecret,
		Tunnel:  &spec.Tunnel{Type: "tcp", Security: "vless_enc", Server: tunnelAddr},
		Reverse: &spec.Reverse{Domain: testDomain}}
	return
}

// countingTCP accepts connections and counts them; it never answers.
func countingTCP(t *testing.T) (addr string, count *atomic.Int64) {
	t.Helper()
	count = new(atomic.Int64)
	addr = tcpServer(t, func(c net.Conn) {
		count.Add(1)
		buf := make([]byte, 64)
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		c.Read(buf)
	})
	return
}

// countingUDP counts datagrams and echoes them (so a leak would be visible
// both as a count and as an answer from the wrong server).
func countingUDP(t *testing.T) (addr string, count *atomic.Int64) {
	t.Helper()
	count = new(atomic.Int64)
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
			count.Add(1)
			pc.WriteTo(append([]byte("EVIL:"), b[:n]...), a)
		}
	}()
	return pc.LocalAddr().String(), count
}

func destOf(t *testing.T, network xnet.Network, addr string) xnet.Destination {
	t.Helper()
	h, p := splitHP(t, addr)
	return xnet.Destination{Address: xnet.ParseAddress(h), Port: xnet.Port(p), Network: network}
}

// forgedLink opens a link on the portal node as if a user connection to the
// portal's public inbound had asked for dest: the portal's own routing rules
// (inbound tag w1n-fwd/i/<id>) send it into the reverse link.
func forgedLink(t *testing.T, n *node, id string, dest xnet.Destination) *transport.Link {
	t.Helper()
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Tag:    "w1n-fwd/i/" + id,
		Source: xnet.TCPDestination(xnet.LocalHostIP, 40000),
	})
	link, err := n.host.Dispatcher().Dispatch(ctx, dest)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	return link
}

// readTCPLine reads the first line the far end sends ("tag\n").
func readFirst(l *transport.Link, d time.Duration) (string, error) {
	tr, ok := l.Reader.(xbuf.TimeoutReader)
	if !ok {
		return "", fmt.Errorf("link reader %T has no timeout read", l.Reader)
	}
	mb, err := tr.ReadMultiBufferTimeout(d)
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	for _, x := range mb {
		b.Write(x.Bytes())
	}
	xbuf.ReleaseMulti(mb)
	return b.String(), nil
}

// The portal's users, and even a caller that talks to the portal's routing
// directly, cannot make the bridge connect anywhere but its own targets: a
// connection that asks for another destination is rewritten to the target.
func TestE2EReversePortalCannotChooseDestination(t *testing.T) {
	realAddr := echoServer(t, "REAL")
	realHost, realPort := splitHP(t, realAddr)
	evilTCP, evilTCPCount := countingTCP(t)
	evilUDP, evilUDPCount := countingUDP(t)
	// a UDP echo on the target's port so UDP has a real destination too
	pc, err := net.ListenPacket("udp", realAddr)
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
			pc.WriteTo(append([]byte("REAL:"), b[:n]...), a)
		}
	}()

	user := freePort(t)
	pn, bn, portal, bridge, _ := reversePair(t, fmt.Sprint(user),
		[]spec.Target{{Host: realHost, Ports: fmt.Sprint(realPort)}}, "tcp", "udp")
	pn.apply(portal)
	bn.apply(bridge)
	userAddr := fmt.Sprintf("127.0.0.1:%d", user)

	// the normal path: a user of the public port reaches the target
	eventually(t, 15*time.Second, "reverse link", func() error {
		tag, err := tcpEcho(userAddr, []byte("hello"), true)
		if err == nil && tag != "REAL" {
			return fmt.Errorf("tag %q", tag)
		}
		return err
	})

	// TCP: ask for the evil server, the bridge connects to the target
	l := forgedLink(t, pn, "rp", destOf(t, xnet.Network_TCP, evilTCP))
	got, err := readFirst(l, 5*time.Second)
	if err != nil || got != "REAL\n" {
		t.Fatalf("forged TCP request: got %q err %v, want the tag of the bridge's target", got, err)
	}
	// another destination class: a domain and an address that is not loopback
	for _, d := range []xnet.Destination{
		{Address: xnet.DomainAddress("evil.example"), Port: 22, Network: xnet.Network_TCP},
		{Address: xnet.ParseAddress("203.0.113.9"), Port: 80, Network: xnet.Network_TCP},
	} {
		l := forgedLink(t, pn, "rp", d)
		if got, err := readFirst(l, 5*time.Second); err != nil || got != "REAL\n" {
			t.Fatalf("forged request to %v: got %q err %v", d, got, err)
		}
	}

	// UDP: same
	ud := destOf(t, xnet.Network_UDP, evilUDP)
	ul := forgedLink(t, pn, "rp", ud)
	b := xbuf.New()
	b.Write([]byte("ping"))
	b.UDP = &ud
	if err := ul.Writer.WriteMultiBuffer(xbuf.MultiBuffer{b}); err != nil {
		t.Fatal(err)
	}
	got, err = readFirst(ul, 5*time.Second)
	if err != nil || got != "REAL:ping" {
		t.Fatalf("forged UDP request: got %q err %v, want REAL:ping", got, err)
	}

	if n := evilTCPCount.Load(); n != 0 {
		t.Fatalf("the evil TCP server received %d connection(s)", n)
	}
	if n := evilUDPCount.Load(); n != 0 {
		t.Fatalf("the evil UDP server received %d datagram(s)", n)
	}
}

// Public port n of a portal range reaches target port n of the bridge, and
// only those.
func TestE2EReversePortRange(t *testing.T) {
	targets := []string{"P1", "P2", "P3"}
	base := freeRange(t, 3) // the target range must be consecutive
	for i, tag := range targets {
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", base+i))
		if err != nil {
			t.Fatal(err)
		}
		tag := tag
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
	userBase := freeRange(t, 3)
	pn, bn, portal, bridge, _ := reversePair(t, fmt.Sprintf("%d-%d", userBase, userBase+2),
		[]spec.Target{{Host: "127.0.0.1", Ports: fmt.Sprintf("%d-%d", base, base+2)}}, "tcp")
	pn.apply(portal)
	bn.apply(bridge)
	eventually(t, 15*time.Second, "reverse link", func() error {
		_, err := tcpEcho(fmt.Sprintf("127.0.0.1:%d", userBase), []byte("x"), true)
		return err
	})
	for i, want := range targets {
		tag, err := tcpEcho(fmt.Sprintf("127.0.0.1:%d", userBase+i), []byte("x"), true)
		if err != nil || tag != want {
			t.Fatalf("public port %d: tag %q err %v, want %s", userBase+i, tag, err, want)
		}
	}
}

// Several bridge targets are balanced; the portal knows none of them.
func TestE2EReverseBalance(t *testing.T) {
	var tg []spec.Target
	for _, tag := range []string{"A", "B", "C"} {
		h, p, _ := startTagged(t, tag)
		tg = append(tg, spec.Target{Host: h, Ports: fmt.Sprint(p)})
	}
	user := freePort(t)
	pn, bn, portal, bridge, _ := reversePair(t, fmt.Sprint(user), tg, "tcp")
	bridge.Balance = &spec.Balance{Strategy: "round_robin"}
	pn.apply(portal)
	bn.apply(bridge)
	userAddr := fmt.Sprintf("127.0.0.1:%d", user)
	eventually(t, 15*time.Second, "reverse link", func() error {
		_, err := tcpEcho(userAddr, []byte("x"), true)
		return err
	})
	count := map[string]int{}
	for i := 0; i < 30; i++ {
		tag, err := tcpEcho(userAddr, []byte("x"), true)
		if err != nil {
			t.Fatal(err)
		}
		count[tag]++
	}
	t.Logf("reverse round_robin distribution over 30 connections: %v", count)
	for _, tag := range []string{"A", "B", "C"} {
		if count[tag] < 8 || count[tag] > 12 {
			t.Fatalf("round robin not (nearly) even: %v", count)
		}
	}

	// weights 1:3 and random; the portal instance is unchanged throughout
	bridge.Targets = tg[:2]
	bridge.Targets[1].Weight = 3
	bridge.Balance = &spec.Balance{Strategy: "random"}
	bn.apply(bridge)
	eventually(t, 15*time.Second, "reverse link after bridge change", func() error {
		_, err := tcpEcho(userAddr, []byte("x"), true)
		return err
	})
	count = map[string]int{}
	for i := 0; i < 80; i++ {
		tag, err := tcpEcho(userAddr, []byte("x"), true)
		if err != nil {
			t.Fatal(err)
		}
		count[tag]++
	}
	t.Logf("reverse random (A:1 B:3, C removed) over 80 connections: %v", count)
	if count["C"] != 0 || count["A"] == 0 || count["B"] == 0 {
		t.Fatalf("%v", count)
	}
}

// Both halves refuse the old "portal decides" settings through the driver's
// Validate (the same check Render and Apply run).
func TestValidateRefusesBridgeAllowAndPortalTargets(t *testing.T) {
	d := New(nil, testOpts())
	b := bridgeInst("b")
	b.Reverse.BridgeAllow = []spec.Allow{{Host: "192.168.1.10", Ports: "3389"}}
	if err := d.Validate(b); err == nil {
		t.Fatal("bridge_allow accepted on the bridge")
	}
	p := portalInst("p")
	p.Reverse.BridgeAllow = []spec.Allow{{Host: "192.168.1.10", Ports: "3389"}}
	if err := d.Validate(p); err == nil {
		t.Fatal("bridge_allow accepted on the portal")
	}
	p = portalInst("p")
	p.Targets = []spec.Target{{Host: "192.168.1.10", Ports: "3389"}}
	if err := d.Validate(p); err == nil {
		t.Fatal("targets accepted on the portal")
	}
	if err := d.Validate(portalInst("p")); err != nil {
		t.Fatalf("a portal without targets: %v", err)
	}
}
