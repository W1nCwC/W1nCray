package xray

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"

	"github.com/W1nCwC/W1nCray/agent/spec"
)

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

func fwdInst(id string, listenPort int, host string, port int, networks ...string) spec.Instance {
	if len(networks) == 0 {
		networks = []string{"tcp"}
	}
	return spec.Instance{
		ID: id, Enabled: true, Engine: spec.EngineXray, Kind: spec.KindForward,
		Listen:  &spec.Listen{Addr: "127.0.0.1", Ports: fmt.Sprint(listenPort)},
		Network: networks,
		Targets: []spec.Target{{Host: host, Ports: fmt.Sprint(port)}},
	}
}

// F1: TCP and UDP direct forwarding.
func TestE2EForwardTCPUDP(t *testing.T) {
	n := newNode(t, testOpts())
	host, port := dualEcho(t)
	lp := freePort(t)
	n.apply(fwdInst("f1", lp, host, port, "tcp", "udp"))
	addr := fmt.Sprintf("127.0.0.1:%d", lp)
	for _, size := range []int{1, 1000, 512 * 1024} {
		if _, err := tcpEcho(addr, randBytes(size), false); err != nil {
			t.Fatalf("tcp %d bytes: %v", size, err)
		}
	}
	for _, size := range []int{1, 1200} {
		if err := udpEcho(addr, randBytes(size)); err != nil {
			t.Fatalf("udp %d bytes: %v", size, err)
		}
	}
	// stats
	st, err := n.drv.Stats(bg, n.rt)
	if err != nil || len(st) != 1 || st[0].InstanceID != "f1" || st[0].BytesUp < 512*1024 || st[0].BytesDown < 512*1024 {
		t.Fatalf("stats %+v %v", st, err)
	}
	// health: every claimed port is bound
	h := n.drv.Health(bg, n.rt)
	if ih := h.Instances["f1"]; !ih.Running || !ih.Listening {
		t.Fatalf("health %+v", ih)
	}
}

// F1: port map (listen port -> own target) and one-to-one port ranges.
func TestE2EForwardPortMapAndRange(t *testing.T) {
	n := newNode(t, testOpts())
	a, b := echoServer(t, "A"), echoServer(t, "B")
	ah, ap := splitHP(t, a)
	bh, bp := splitHP(t, b)
	base := freeRange(t, 3)
	in := fwdInst("pm", base, "", 0)
	in.Listen.Ports = fmt.Sprintf("%d-%d", base, base+2)
	in.Listen.PortMap = map[string]string{
		fmt.Sprint(base):     fmt.Sprintf("%s:%d", ah, ap),
		fmt.Sprint(base + 1): fmt.Sprintf("%s:%d", bh, bp),
		fmt.Sprint(base + 2): fmt.Sprintf("%s:%d", ah, ap),
	}
	in.Targets = nil
	n.apply(in)
	for i, want := range []string{"A", "B", "A"} {
		tag, err := tcpEcho(fmt.Sprintf("127.0.0.1:%d", base+i), []byte("hello"), true)
		if err != nil || tag != want {
			t.Fatalf("port %d: tag %q err %v want %s", base+i, tag, err, want)
		}
	}

	// range one-to-one: three consecutive targets
	tb := freeRange(t, 3)
	var tags []string
	for i := 0; i < 3; i++ {
		tag := fmt.Sprintf("T%d", i)
		tags = append(tags, tag)
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", tb+i))
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
	r := fwdInst("rg", lb, "127.0.0.1", tb)
	r.Listen.Ports = fmt.Sprintf("%d-%d", lb, lb+2)
	r.Targets = []spec.Target{{Host: "127.0.0.1", Ports: fmt.Sprintf("%d-%d", tb, tb+2)}}
	n.apply(in, r)
	for i := 0; i < 3; i++ {
		tag, err := tcpEcho(fmt.Sprintf("127.0.0.1:%d", lb+i), []byte("x"), true)
		if err != nil || tag != tags[i] {
			t.Fatalf("range port %d: tag %q err %v want %s", lb+i, tag, err, tags[i])
		}
	}
}

func startTagged(t *testing.T, tag string) (host string, port int, stop func()) {
	t.Helper()
	port = freePort(t)
	var mu sync.Mutex
	var l net.Listener
	listen := func() {
		var err error
		l, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Fatal(err)
		}
		go func(l net.Listener) {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go func() { defer c.Close(); fmt.Fprintf(c, "%s\n", tag); io.Copy(c, c) }()
			}
		}(l)
	}
	listen()
	t.Cleanup(func() { mu.Lock(); l.Close(); mu.Unlock() })
	return "127.0.0.1", port, func() { mu.Lock(); l.Close(); mu.Unlock() }
}

// F1: one-to-many round robin / weights / random.
func TestE2EForwardBalance(t *testing.T) {
	n := newNode(t, testOpts())
	var targets []spec.Target
	for _, tag := range []string{"A", "B", "C"} {
		h, p, _ := startTagged(t, tag)
		targets = append(targets, spec.Target{Host: h, Ports: fmt.Sprint(p)})
	}
	lp := freePort(t)
	in := fwdInst("lb", lp, "", 0)
	in.Targets = targets
	in.Balance = &spec.Balance{Strategy: "round_robin"}
	n.apply(in)
	count := map[string]int{}
	for i := 0; i < 30; i++ {
		tag, err := tcpEcho(fmt.Sprintf("127.0.0.1:%d", lp), []byte("x"), true)
		if err != nil {
			t.Fatal(err)
		}
		count[tag]++
	}
	t.Logf("round_robin distribution over 30 connections: %v", count)
	if count["A"] != 10 || count["B"] != 10 || count["C"] != 10 {
		t.Fatalf("round robin not even: %v", count)
	}

	// weights 1:3
	in.Targets[1].Weight = 3
	in.Targets = in.Targets[:2]
	n.apply(in)
	count = map[string]int{}
	for i := 0; i < 40; i++ {
		tag, err := tcpEcho(fmt.Sprintf("127.0.0.1:%d", lp), []byte("x"), true)
		if err != nil {
			t.Fatal(err)
		}
		count[tag]++
	}
	t.Logf("weighted (A:1 B:3) distribution over 40 connections: %v", count)
	if count["A"] != 10 || count["B"] != 30 {
		t.Fatalf("weights not honoured: %v", count)
	}

	// random reaches every target
	in.Targets = targets
	in.Targets[1].Weight = 0
	in.Balance.Strategy = "random"
	n.apply(in)
	count = map[string]int{}
	for i := 0; i < 90; i++ {
		tag, err := tcpEcho(fmt.Sprintf("127.0.0.1:%d", lp), []byte("x"), true)
		if err != nil {
			t.Fatal(err)
		}
		count[tag]++
	}
	t.Logf("random distribution over 90 connections: %v", count)
	for _, tag := range []string{"A", "B", "C"} {
		if count[tag] < 10 {
			t.Fatalf("random strategy starves %s: %v", tag, count)
		}
	}
}

// Failover and health-aware round robin through the TCP health checks.
func TestE2EForwardHealthFailover(t *testing.T) {
	n := newNode(t, testOpts())
	ah, ap, stopA := startTagged(t, "A")
	bh, bp, _ := startTagged(t, "B")
	lp := freePort(t)
	in := fwdInst("fo", lp, "", 0)
	in.Targets = []spec.Target{{Host: ah, Ports: fmt.Sprint(ap)}, {Host: bh, Ports: fmt.Sprint(bp)}}
	in.Balance = &spec.Balance{Strategy: "failover", Health: &spec.Health{Type: "tcp", IntervalS: 1, TimeoutS: 1, MaxFails: 1}}
	n.apply(in)
	addr := fmt.Sprintf("127.0.0.1:%d", lp)
	for i := 0; i < 6; i++ {
		if tag, err := tcpEcho(addr, []byte("x"), true); err != nil || tag != "A" {
			t.Fatalf("primary expected: %q %v", tag, err)
		}
	}
	stopA()
	took := eventually(t, 6*time.Second, "failover to B", func() error {
		tag, err := tcpEcho(addr, []byte("x"), true)
		if err != nil {
			return err
		}
		if tag != "B" {
			return fmt.Errorf("still %s", tag)
		}
		return nil
	})
	t.Logf("failover A -> B took %s (interval 1 s)", took)
	h := n.drv.Health(bg, n.rt)
	if h.Instances["fo"].Targets[fmt.Sprintf("%s:%d", ah, ap)] {
		t.Fatalf("health still reports A alive: %+v", h.Instances["fo"].Targets)
	}
	// A comes back: traffic returns to the primary
	l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ah, ap))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); fmt.Fprintf(c, "A\n"); io.Copy(c, c) }()
		}
	}()
	took = eventually(t, 6*time.Second, "return to A", func() error {
		tag, err := tcpEcho(addr, []byte("x"), true)
		if err != nil {
			return err
		}
		if tag != "A" {
			return fmt.Errorf("still %s", tag)
		}
		return nil
	})
	t.Logf("failback B -> A took %s", took)
}

func TestE2EForwardACL(t *testing.T) {
	n := newNode(t, testOpts())
	echo := echoServer(t, "")
	h, p := splitHP(t, echo)
	lp := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", lp)
	in := fwdInst("acl", lp, h, p)
	n.apply(in)
	if _, err := tcpEcho(addr, []byte("x"), false); err != nil {
		t.Fatal(err)
	}
	in.ACL = &spec.ACL{Deny: []string{"127.0.0.0/8"}}
	n.apply(in)
	if _, err := tcpEcho(addr, []byte("x"), false); err == nil {
		t.Fatal("denied source got through")
	}
	in.ACL = &spec.ACL{Allow: []string{"192.0.2.0/24"}}
	n.apply(in)
	if _, err := tcpEcho(addr, []byte("x"), false); err == nil {
		t.Fatal("source outside the allow list got through")
	}
	in.ACL = &spec.ACL{Allow: []string{"127.0.0.1"}, Deny: []string{"10.0.0.0/8"}}
	n.apply(in)
	if _, err := tcpEcho(addr, []byte("x"), false); err != nil {
		t.Fatalf("allowed source rejected: %v", err)
	}
}

// proxyServer is a TCP server that expects a PROXY header and reports the
// source address it announced, then echoes.
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
				// RemoteAddr() blocks until the header has been read.
				ra := c.RemoteAddr()
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

func clientWithHeader(addr string, ver byte, src, dst string, payload []byte) error {
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	s, _ := net.ResolveTCPAddr("tcp", src)
	d, _ := net.ResolveTCPAddr("tcp", dst)
	h := proxyproto.HeaderProxyFromAddrs(ver, s, d)
	if _, err := h.WriteTo(c); err != nil {
		return err
	}
	if _, err := c.Write(payload); err != nil {
		return err
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(c, buf); err != nil {
		return err
	}
	return nil
}

// F6: PROXY protocol send (v1, v2), receive, pass-through.
func TestE2EProxyProtocol(t *testing.T) {
	n := newNode(t, testOpts())
	psrv, got := proxyServer(t)
	ph, pp := splitHP(t, psrv)

	// send v1 / v2
	for _, ver := range []int{1, 2} {
		lp := freePort(t)
		in := fwdInst(fmt.Sprintf("snd%d", ver), lp, ph, pp)
		in.ProxyProtocolOut = ver
		n.apply(in)
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", lp))
		if err != nil {
			t.Fatal(err)
		}
		local := c.LocalAddr().String()
		c.Write([]byte("ping"))
		buf := make([]byte, 4)
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(c, buf); err != nil {
			t.Fatalf("v%d: %v", ver, err)
		}
		c.Close()
		select {
		case a := <-got:
			t.Logf("send v%d: target saw source %s (client was %s)", ver, a, local)
			if a.String() != local {
				t.Fatalf("v%d: target saw %s, client was %s", ver, a, local)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("target saw no PROXY header")
		}
	}

	// receive: only connections with a header pass; the source is the announced one
	lp := freePort(t)
	echo := echoServer(t, "")
	eh, ep := splitHP(t, echo)
	rcv := fwdInst("rcv", lp, eh, ep)
	rcv.AcceptProxyProtocol = true
	rcv.ACL = &spec.ACL{Allow: []string{"203.0.113.9"}}
	n.apply(rcv)
	addr := fmt.Sprintf("127.0.0.1:%d", lp)
	if err := clientWithHeader(addr, 2, "203.0.113.9:1234", "198.51.100.1:80", []byte("hello")); err != nil {
		t.Fatalf("announced allowed source rejected: %v", err)
	}
	if err := clientWithHeader(addr, 1, "203.0.113.9:1234", "198.51.100.1:80", []byte("hello")); err != nil {
		t.Fatalf("v1 header: %v", err)
	}
	if err := clientWithHeader(addr, 2, "203.0.113.77:1234", "198.51.100.1:80", []byte("hello")); err == nil {
		t.Fatal("announced foreign source accepted")
	}
	// no header: REQUIRE policy drops the connection
	if _, err := tcpEcho(addr, []byte("hello"), false); err == nil {
		t.Fatal("connection without PROXY header accepted")
	}

	// pass-through: receive and re-send, the target sees the announced source
	lp2 := freePort(t)
	pt := fwdInst("pt", lp2, ph, pp)
	pt.AcceptProxyProtocol = true
	pt.ProxyProtocolOut = 2
	n.apply(rcv, pt)
	for len(got) > 0 {
		<-got
	}
	if err := clientWithHeader(fmt.Sprintf("127.0.0.1:%d", lp2), 2, "203.0.113.9:4321", "198.51.100.1:80", []byte("hello")); err != nil {
		t.Fatalf("pass-through: %v", err)
	}
	select {
	case a := <-got:
		t.Logf("pass-through: target saw source %s", a)
		if a.String() != "203.0.113.9:4321" {
			t.Fatalf("target saw %s", a)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no header at the target")
	}

	// udp + proxy_out is refused
	bad := fwdInst("bad", freePort(t), ph, pp, "tcp", "udp")
	bad.ProxyProtocolOut = 2
	if err := n.drv.Validate(bad); err == nil || !strings.Contains(err.Error(), "TCP only") {
		t.Fatalf("Validate(udp+proxy_out) = %v", err)
	}
	// public listener + accept_proxy_protocol is refused by the local policy
	pub := fwdInst("pub", freePort(t), ph, pp)
	pub.Listen.Addr = "0.0.0.0"
	pub.AcceptProxyProtocol = true
	if err := n.drv.Validate(pub); err == nil {
		t.Fatal("accept_proxy_protocol on a public listener accepted")
	} else {
		t.Logf("public accept_proxy_protocol refused: %v", err)
	}
}

// F7: instances can be added and removed while others keep running; a live
// connection of an untouched instance is not interrupted.
func TestE2EHotAddRemoveIsolation(t *testing.T) {
	n := newNode(t, testOpts())
	echo := echoServer(t, "")
	h, p := splitHP(t, echo)
	p1, p2, p3 := freePort(t), freePort(t), freePort(t)
	f1, f2, f3 := fwdInst("f1", p1, h, p), fwdInst("f2", p2, h, p), fwdInst("f3", p3, h, p)
	n.apply(f1, f2)

	// a long-lived connection through f1
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", p1))
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
		t.Fatal(err)
	}

	res := n.apply(f1, f3) // remove f2, add f3
	if len(res.Disrupted) != 0 || len(res.Restarted) != 0 {
		t.Fatalf("collateral disruption reported: %+v", res)
	}
	if err := ping(); err != nil {
		t.Fatalf("f1 connection interrupted by unrelated add/remove: %v", err)
	}
	if _, err := tcpEcho(fmt.Sprintf("127.0.0.1:%d", p3), []byte("x"), false); err != nil {
		t.Fatalf("new instance does not work: %v", err)
	}
	if _, err := tcpEcho(fmt.Sprintf("127.0.0.1:%d", p2), []byte("x"), false); err == nil {
		t.Fatal("removed instance still serves")
	}
	// a changed instance is replaced and only it is reported
	f3b := fwdInst("f3", p3, h, p)
	f3b.IdleProfile = "tcp_default" // tcp_long is the default now, so it would not change the instance
	res = n.apply(f1, f3b)
	if len(res.Restarted) != 1 || res.Restarted[0] != "f3" {
		t.Fatalf("%+v", res)
	}
	if err := ping(); err != nil {
		t.Fatalf("f1 connection interrupted by a change of f3: %v", err)
	}
	if _, err := tcpEcho(fmt.Sprintf("127.0.0.1:%d", p3), []byte("x"), false); err != nil {
		t.Fatalf("changed instance does not work: %v", err)
	}
	// Kill is called for the removed and the replaced instances' inbounds
	n.host.mu.Lock()
	kills := strings.Join(n.host.kills, ",")
	n.host.mu.Unlock()
	if !strings.Contains(kills, "w1n-fwd/i/f2") || !strings.Contains(kills, "w1n-fwd/i/f3") || strings.Contains(kills, "w1n-fwd/i/f1") {
		t.Fatalf("Kill calls: %s", kills)
	}
	// Stop removes everything
	if err := n.drv.Stop(bg, n.rt); err != nil {
		t.Fatal(err)
	}
	if _, err := tcpEcho(fmt.Sprintf("127.0.0.1:%d", p3), []byte("x"), false); err == nil {
		t.Fatal("stopped instance still serves")
	}
}
