//go:build e2e

// End to end tests against a real gost binary.
//
// Running them (needs only the gost binary of the platform you run on; every
// test starts its own gost processes on 127.0.0.1 and removes its temp dirs
// and processes afterwards):
//
// Windows (PowerShell):
//
//	$env:W1NCRAY_TEST_GOST_BIN = "C:\path\to\gost.exe"
//	go test -tags e2e -count=1 -v ./driver/gost/...
//
// Linux test machine (the official asset gost_3.3.0_linux_amd64.tar.gz;
// verify its sha256 against the GitHub release API "digest" first):
//
//	tar -xzf gost_3.3.0_linux_amd64.tar.gz gost
//	export W1NCRAY_TEST_GOST_BIN=$PWD/gost
//	GOOS=linux go test -tags e2e -count=1 -v ./driver/gost/...
//
// or build the test binary on a workstation and copy it:
//
//	GOOS=linux GOARCH=amd64 go test -tags e2e -c -o gost-e2e.test ./driver/gost
//	scp gost-e2e.test gost host:/tmp/ && ssh host 'cd /tmp && W1NCRAY_TEST_GOST_BIN=/tmp/gost ./gost-e2e.test -test.v -test.count=1'
//
// On Linux additionally check: TestE2EReloadSemantics_SIGHUP (sends SIGHUP and
// shows that it drops other instances' listeners), and compare the timing
// based tests (rate limits) which are looser on a loaded machine.
package gost

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/spec"
)

func addr(port int) string { return fmt.Sprintf("127.0.0.1:%d", port) }

// G1: direct TCP and UDP forwarding, with exact statistics.
func TestE2EForwardTCPUDPAndStats(t *testing.T) {
	n := newNode(t, Options{})
	be := startBackend(t, "")
	_, up := startUDPEcho(t)
	lp := freePorts(t, 1)
	in := fwdInst("f1", lp, be.Addr, "tcp", "udp")
	in.Targets[0].Ports = fmt.Sprint(be.Port) // tcp and udp backends differ: use a second instance for udp
	udpIn := fwdInst("f1u", lp, fmt.Sprintf("127.0.0.1:%d", up), "udp")
	in.Network = []string{"tcp"}
	n.apply(in, udpIn)

	// TCP: 3 connections, 10 x 1000 bytes each way.
	total := 0
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", addr(lp))
		if err != nil {
			t.Fatal(err)
		}
		msg := strings.Repeat("x", 999)
		for j := 0; j < 10; j++ {
			if _, err := echoOn(c, msg, false); err != nil {
				t.Fatal(err)
			}
			total += len(msg) + 1
		}
		c.Close()
	}
	if err := udpEchoOnce(addr(lp), "hello-udp"); err != nil {
		t.Fatalf("udp: %v", err)
	}
	var c driver.Counter
	eventually(t, 5*time.Second, "tcp stats", func() bool {
		c = n.stats()["f1"]
		return c.BytesUp == uint64(total) && c.BytesDown == uint64(total) && c.ConnsTotal == 3
	})
	t.Logf("tcp counters: %+v (sent %d each way)", c, total)
	u := n.stats()["f1u"]
	if u.BytesUp != 9 || u.BytesDown != 9 {
		t.Errorf("udp counters %+v, want 9/9", u)
	}
	h := n.d.Health(context.Background(), n.rt)
	for _, id := range []string{"f1", "f1u"} {
		if ih := h.Instances[id]; !ih.Running || !ih.Listening || ih.ConfigHash == "" {
			t.Errorf("health %s: %+v", id, ih)
		}
	}
}

// TCP and UDP of one instance on the same port number.
func TestE2ETCPAndUDPSameInstance(t *testing.T) {
	n := newNode(t, Options{})
	// A TCP and a UDP echo on the same port number.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	serveBackend(t, l, "")
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Skipf("udp port %d busy: %v", port, err)
	}
	t.Cleanup(func() { uc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			k, a, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			uc.WriteToUDP(buf[:k], a)
		}
	}()
	lp := freePorts(t, 1)
	n.apply(fwdInst("both", lp, addr(port), "tcp", "udp"))
	if _, err := tcpEcho(addr(lp), "t", false); err != nil {
		t.Fatalf("tcp: %v", err)
	}
	if err := udpEchoOnce(addr(lp), "u"); err != nil {
		t.Fatalf("udp: %v", err)
	}
}

// F1: port ranges (one-to-one) and port_map.
func TestE2EPortRangeAndPortMap(t *testing.T) {
	n := newNode(t, Options{})
	var bes []*tcpBackend
	for i := 0; i < 3; i++ {
		bes = append(bes, startBackend(t, fmt.Sprintf("B%d", i)))
	}
	// One-to-one needs consecutive target ports: reserve three.
	tbase := freePorts(t, 3)
	var tb []*tcpBackend
	for i := 0; i < 3; i++ {
		l, err := net.Listen("tcp", addr(tbase+i))
		if err != nil {
			t.Fatal(err)
		}
		tb = append(tb, serveBackend(t, l, fmt.Sprintf("R%d", i)))
	}
	lbase := freePorts(t, 3)
	in := spec.Instance{
		ID: "rng", Enabled: true, Engine: spec.EngineGost, Kind: spec.KindForward,
		Listen:  &spec.Listen{Addr: "127.0.0.1", Ports: fmt.Sprintf("%d-%d", lbase, lbase+2), PortMap: map[string]string{fmt.Sprint(lbase + 1): bes[2].Addr}},
		Targets: []spec.Target{{Host: "127.0.0.1", Ports: fmt.Sprintf("%d-%d", tbase, tbase+2)}},
	}
	n.apply(in)
	want := []string{"R0", "B2", "R2"}
	for i, w := range want {
		got, err := tcpEcho(addr(lbase+i), "hi", true)
		if err != nil || got != w {
			t.Errorf("listen port %d -> %q (err %v), want %q", lbase+i, got, err, w)
		}
	}
	_ = tb
}

// Round robin, random, iphash, failover and passive removal of a dead target.
func TestE2EBalanceAndPassiveHealth(t *testing.T) {
	n := newNode(t, Options{})
	b1, b2 := startBackend(t, "B1"), startBackend(t, "B2")
	mk := func(id, strat string) spec.Instance {
		in := fwdInst(id, freePorts(t, 1), b1.Addr)
		in.Targets = []spec.Target{{Host: "127.0.0.1", Ports: fmt.Sprint(b1.Port)}, {Host: "127.0.0.1", Ports: fmt.Sprint(b2.Port)}}
		in.Balance = &spec.Balance{Strategy: strat, Health: &spec.Health{Type: "tcp", MaxFails: 1, IntervalS: 30}}
		return in
	}
	rr, rnd, ih, fo := mk("rr", "round_robin"), mk("rnd", "random"), mk("ih", "iphash"), mk("fo", "failover")
	n.apply(rr, rnd, ih, fo)
	port := func(in spec.Instance) string { return addr(atoiMust(in.Listen.Ports)) }

	count := func(in spec.Instance, k int) map[string]int {
		m := map[string]int{}
		for i := 0; i < k; i++ {
			name, err := tcpEcho(port(in), "x", true)
			if err != nil {
				t.Fatalf("%s: %v", in.ID, err)
			}
			m[name]++
		}
		return m
	}
	if m := count(rr, 10); m["B1"] != 5 || m["B2"] != 5 {
		t.Errorf("round robin: %v", m)
	}
	if m := count(rnd, 60); m["B1"] < 10 || m["B2"] < 10 {
		t.Errorf("random: %v", m)
	}
	if m := count(ih, 10); !(m["B1"] == 10 || m["B2"] == 10) {
		t.Errorf("iphash from one client IP must stick to one target: %v", m)
	}
	if m := count(fo, 5); m["B1"] != 5 {
		t.Errorf("failover must use the first target: %v", m)
	}

	// Kill B1: round robin recovers after at most one failed connection and
	// then uses B2 only; failover switches to B2.
	b1.Close()
	fails := 0
	for i := 0; i < 4; i++ {
		if _, err := tcpEcho(port(rr), "x", true); err != nil {
			fails++
		}
	}
	if fails > 1 {
		t.Errorf("round robin kept sending to the dead target %d times", fails)
	}
	if m := count(rr, 10); m["B2"] != 10 {
		t.Errorf("round robin after failure: %v", m)
	}
	for i := 0; i < 2; i++ {
		tcpEcho(port(fo), "x", true)
	}
	if m := count(fo, 5); m["B2"] != 5 {
		t.Errorf("failover after failure: %v", m)
	}
}

func atoiMust(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}

// G1: ws and wss tunnels, entry -> exit in separate gost processes, TCP and UDP.
func TestE2ETunnels(t *testing.T) {
	for _, typ := range []string{"tcp", "ws", "tls", "wss", "grpc"} {
		t.Run(typ, func(t *testing.T) {
			entry, exit := newNode(t, Options{}), newNode(t, Options{})
			be := startBackend(t, "")
			ue, uport := startUDPEcho(t)
			_ = ue
			dir := t.TempDir()
			cert, key := writeCert(t, dir)
			ctl := freePorts(t, 1)
			lp := freePorts(t, 1)

			tn := func() *spec.Tunnel {
				x := &spec.Tunnel{Type: typ}
				if typ == "ws" || typ == "wss" {
					x.Path = "/tunnel"
				}
				if typ == "tls" || typ == "wss" || typ == "grpc" {
					x.Security = "tls"
				}
				return x
			}
			// The exit forwards to the TCP echo; UDP goes through a second exit instance? No:
			// one relay carries both, so the exit target must serve both protocols on one port.
			// Use the TCP backend's port for UDP as well by binding a UDP echo to it.
			uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: be.Port})
			if err != nil {
				t.Skipf("cannot bind udp %d: %v", be.Port, err)
			}
			t.Cleanup(func() { uc.Close() })
			go func() {
				buf := make([]byte, 2048)
				for {
					k, a, err := uc.ReadFromUDP(buf)
					if err != nil {
						return
					}
					uc.WriteToUDP(buf[:k], a)
				}
			}()
			_ = uport

			ex := spec.Instance{
				ID: "ex", Enabled: true, Engine: spec.EngineGost, Kind: spec.KindTunnelExit,
				Network: []string{"tcp", "udp"}, Tunnel: tn(), Secret: e2eSecret,
				Targets: []spec.Target{{Host: "127.0.0.1", Ports: fmt.Sprint(be.Port)}},
			}
			ex.Tunnel.Listen = addr(ctl)
			if ex.Tunnel.Security == "tls" {
				ex.Tunnel.Cert = &spec.Cert{Mode: "file", CertFile: cert, KeyFile: key}
			}
			en := spec.Instance{
				ID: "en", Enabled: true, Engine: spec.EngineGost, Kind: spec.KindTunnelEntry,
				Listen:  &spec.Listen{Addr: "127.0.0.1", Ports: fmt.Sprint(lp)},
				Network: []string{"tcp", "udp"}, Tunnel: tn(), Secret: e2eSecret,
			}
			en.Tunnel.Server = addr(ctl)
			if en.Tunnel.Security == "tls" {
				en.Tunnel.Cert = &spec.Cert{Mode: "file", CertFile: cert}
			}
			exit.apply(ex)
			entry.apply(en)

			if _, err := tcpEcho(addr(lp), "through-"+typ, false); err != nil {
				t.Fatalf("tcp via %s tunnel: %v", typ, err)
			}
			if err := udpEchoOnce(addr(lp), "udp-"+typ); err != nil {
				t.Fatalf("udp via %s tunnel: %v", typ, err)
			}
			// A wrong secret must not get through.
			bad := en
			bad.ID = "bad"
			bad.Secret = "WRONG-secret-WRONG-secret-1"
			bad.Listen = &spec.Listen{Addr: "127.0.0.1", Ports: fmt.Sprint(freePorts(t, 1))}
			entry.apply(en, bad)
			if _, err := tcpEcho(addr(atoiMust(bad.Listen.Ports)), "nope", false); err == nil {
				t.Error("entry with a wrong secret was served")
			}
			ec := entry.stats()["en"]
			xc := exit.stats()["ex"]
			t.Logf("%s: entry counters up=%d down=%d; exit counters up=%d down=%d (exit includes relay framing)", typ, ec.BytesUp, ec.BytesDown, xc.BytesUp, xc.BytesDown)
			want := uint64(len("through-"+typ)+1) + uint64(len("udp-"+typ))
			if ec.BytesUp != want || ec.BytesDown != want {
				t.Errorf("entry counters %+v, want %d/%d", ec, want, want)
			}
			if xc.BytesUp < want {
				t.Errorf("exit counters %+v are below the payload %d", xc, want)
			}
		})
	}
}

// A tunnel exit must only reach its fixed targets and a verifying entry must
// refuse a certificate it does not trust.
func TestE2ETunnelSecurity(t *testing.T) {
	entry, exit := newNode(t, Options{}), newNode(t, Options{})
	be := startBackend(t, "")
	other := startBackend(t, "OTHER")
	dir := t.TempDir()
	cert, key := writeCert(t, dir)
	dir2 := t.TempDir()
	cert2, _ := writeCert(t, dir2)
	ctl, lp := freePorts(t, 1), freePorts(t, 1)
	ex := spec.Instance{
		ID: "ex", Enabled: true, Engine: spec.EngineGost, Kind: spec.KindTunnelExit, Secret: e2eSecret,
		Tunnel:  &spec.Tunnel{Type: "wss", Listen: addr(ctl), Path: "/t", Security: "tls", Cert: &spec.Cert{Mode: "file", CertFile: cert, KeyFile: key}},
		Targets: []spec.Target{{Host: "127.0.0.1", Ports: fmt.Sprint(be.Port)}},
	}
	// The entry asks for OTHER, the exit must still connect to its own target.
	en := spec.Instance{
		ID: "en", Enabled: true, Engine: spec.EngineGost, Kind: spec.KindTunnelEntry, Secret: e2eSecret,
		Listen:  &spec.Listen{Addr: "127.0.0.1", Ports: fmt.Sprint(lp)},
		Targets: []spec.Target{{Host: "127.0.0.1", Ports: fmt.Sprint(other.Port)}},
		Tunnel:  &spec.Tunnel{Type: "wss", Server: addr(ctl), Path: "/t", Security: "tls", Cert: &spec.Cert{Mode: "file", CertFile: cert}},
	}
	exit.apply(ex)
	entry.apply(en)
	if _, err := tcpEcho(addr(lp), "x", false); err != nil {
		t.Fatalf("tunnel: %v", err)
	}
	if other.conns.Load() != 0 || be.conns.Load() != 1 {
		t.Errorf("exit connected to the entry-chosen target: other=%d own=%d", other.conns.Load(), be.conns.Load())
	}
	// Entry that trusts a different certificate must fail the handshake.
	lp2 := freePorts(t, 1)
	en2 := en
	en2.ID = "en2"
	en2.Listen = &spec.Listen{Addr: "127.0.0.1", Ports: fmt.Sprint(lp2)}
	tn := *en.Tunnel
	tn.Cert = &spec.Cert{Mode: "file", CertFile: cert2}
	en2.Tunnel = &tn
	entry.apply(en, en2)
	if _, err := tcpEcho(addr(lp2), "x", false); err == nil {
		t.Error("entry accepted an exit certificate that is not signed by its trust anchor")
	}
	if _, err := tcpEcho(addr(lp), "x", false); err != nil {
		t.Errorf("trusted entry broke: %v", err)
	}
}

// Open exit (allow_any_target): the entry chooses the target.
func TestE2ETunnelOpenExit(t *testing.T) {
	entry, exit := newNode(t, Options{}), newNode(t, Options{})
	be := startBackend(t, "")
	ctl, lp := freePorts(t, 1), freePorts(t, 1)
	ex := spec.Instance{
		ID: "ex", Enabled: true, Engine: spec.EngineGost, Kind: spec.KindTunnelExit, Secret: e2eSecret, AllowAnyTarget: true,
		Tunnel: &spec.Tunnel{Type: "ws", Listen: addr(ctl)},
	}
	en := fwdInst("en", lp, be.Addr)
	en.Kind = spec.KindTunnelEntry
	en.Secret = e2eSecret
	en.Tunnel = &spec.Tunnel{Type: "ws", Server: addr(ctl)}
	exit.apply(ex)
	entry.apply(en)
	if _, err := tcpEcho(addr(lp), "x", false); err != nil {
		t.Fatalf("tunnel: %v", err)
	}
}

// G1: reverse proxy, TCP and UDP, plus reconnect after the portal restarts.
func TestE2EReverse(t *testing.T) {
	bridge, portal := newNode(t, Options{}), newNode(t, Options{})
	be := startBackend(t, "")
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: be.Port})
	if err != nil {
		t.Skipf("udp %d busy", be.Port)
	}
	t.Cleanup(func() { uc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			k, a, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			uc.WriteToUDP(buf[:k], a)
		}
	}()
	ctl := freePorts(t, 1)
	pub := freePorts(t, 1)
	po := spec.Instance{
		ID: "po", Enabled: true, Engine: spec.EngineGost, Kind: spec.KindReversePortal, Secret: e2eSecret,
		Network: []string{"tcp", "udp"},
		Listen:  &spec.Listen{Addr: "127.0.0.1", Ports: fmt.Sprint(pub)},
		Tunnel:  &spec.Tunnel{Type: "ws", Listen: addr(ctl), Path: "/r"},
	}
	br := spec.Instance{
		ID: "br", Enabled: true, Engine: spec.EngineGost, Kind: spec.KindReverseBridge, Secret: e2eSecret,
		Network: []string{"tcp", "udp"},
		Listen:  &spec.Listen{Addr: "127.0.0.1", Ports: fmt.Sprint(pub)},
		Targets: []spec.Target{{Host: "127.0.0.1", Ports: fmt.Sprint(be.Port)}},
		Tunnel:  &spec.Tunnel{Type: "ws", Server: addr(ctl), Path: "/r"},
	}
	portal.apply(po)
	bridge.apply(br)
	eventually(t, 10*time.Second, "reverse tcp", func() bool { _, err := tcpEcho(addr(pub), "hello", false); return err == nil })
	if err := udpEchoOnce(addr(pub), "udp-rev"); err != nil {
		t.Fatalf("reverse udp: %v", err)
	}
	// The bridge counts the payload exactly.
	bc := bridge.stats()["br"]
	t.Logf("bridge counters %+v", bc)
	if bc.BytesUp < 6+7 {
		t.Errorf("bridge counters %+v", bc)
	}

	// Restart the portal: the bridge must reconnect on its own (<= ~10 s).
	if err := portal.d.Stop(context.Background(), portal.rt); err != nil {
		t.Fatal(err)
	}
	if _, err := tcpEcho(addr(pub), "x", false); err == nil {
		t.Error("public port still served after the portal was stopped")
	}
	t0 := time.Now()
	portal.apply(po)
	eventually(t, 30*time.Second, "bridge reconnect", func() bool { _, err := tcpEcho(addr(pub), "again", false); return err == nil })
	t.Logf("bridge reconnected %s after the portal came back", time.Since(t0).Round(100*time.Millisecond))
	if err := udpEchoOnce(addr(pub), "udp-rev2"); err != nil {
		t.Fatalf("reverse udp after reconnect: %v", err)
	}
}

// G1: PROXY protocol sending, accepting and passing through.
func TestE2EProxyProtocol(t *testing.T) {
	n := newNode(t, Options{})
	hb := startHeadBackend(t, 40)
	lpOut1, lpOut2, lpIn, lpBoth := freePorts(t, 1), freePorts(t, 1), freePorts(t, 1), freePorts(t, 1)
	out1 := fwdInst("out1", lpOut1, hb.Addr)
	out1.ProxyProtocolOut = 1
	out2 := fwdInst("out2", lpOut2, hb.Addr)
	out2.ProxyProtocolOut = 2
	in := fwdInst("in", lpIn, hb.Addr)
	in.AcceptProxyProtocol = true
	both := fwdInst("both", lpBoth, hb.Addr)
	both.AcceptProxyProtocol, both.ProxyProtocolOut = true, 2
	n.apply(out1, out2, in, both)

	send := func(port int, pre []byte) []byte {
		c, err := net.Dial("tcp", addr(port))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.Write(append(pre, []byte("payload-payload-payload-payload-payload\n")...))
		select {
		case h := <-hb.heads:
			return h
		case <-time.After(4 * time.Second):
			t.Fatal("backend saw nothing")
			return nil
		}
	}
	// v1 send: "PROXY TCP4 127.0.0.1 127.0.0.1 <sport> <dport>"
	h := send(lpOut1, nil)
	if !bytes.HasPrefix(h, []byte("PROXY TCP4 127.0.0.1 127.0.0.1 ")) {
		t.Errorf("proxy v1 header: %q", h)
	}
	// v2 send: binary signature.
	h = send(lpOut2, nil)
	if !bytes.HasPrefix(h, []byte("\r\n\r\n\x00\r\nQUIT\n")) {
		t.Errorf("proxy v2 header: %q", h)
	}
	// accept: the v1 header sent by the client is consumed, payload reaches the backend.
	h = send(lpIn, []byte("PROXY TCP4 9.9.9.9 8.8.8.8 1234 80\r\n"))
	if !bytes.HasPrefix(h, []byte("payload-")) {
		t.Errorf("accept: header was not consumed: %q", h)
	}
	// accept without a header still works (gost treats it as optional).
	h = send(lpIn, nil)
	if !bytes.HasPrefix(h, []byte("payload-")) {
		t.Errorf("accept without header: %q", h)
	}
	// passthrough: the original client address 9.9.9.9:1234 reaches the backend in a v2 header.
	h = send(lpBoth, []byte("PROXY TCP4 9.9.9.9 8.8.8.8 1234 80\r\n"))
	if !bytes.HasPrefix(h, []byte("\r\n\r\n\x00\r\nQUIT\n")) || len(h) < 28 || !bytes.Equal(h[16:20], []byte{9, 9, 9, 9}) || !bytes.Equal(h[24:26], []byte{0x04, 0xd2}) {
		t.Errorf("passthrough header: %x", h)
	}
}

// PROXY through a tunnel entry (header travels inside the tunnel to the
// target) and through a reverse bridge (real user address).
func TestE2EProxyThroughTunnelAndBridge(t *testing.T) {
	entry, exit := newNode(t, Options{}), newNode(t, Options{})
	hb := startHeadBackend(t, 12)
	ctl, lp := freePorts(t, 1), freePorts(t, 1)
	ex := spec.Instance{
		ID: "ex", Enabled: true, Engine: spec.EngineGost, Kind: spec.KindTunnelExit, Secret: e2eSecret,
		Tunnel:  &spec.Tunnel{Type: "ws", Listen: addr(ctl)},
		Targets: []spec.Target{{Host: "127.0.0.1", Ports: fmt.Sprint(hb.Port)}},
	}
	en := spec.Instance{
		ID: "en", Enabled: true, Engine: spec.EngineGost, Kind: spec.KindTunnelEntry, Secret: e2eSecret,
		Listen: &spec.Listen{Addr: "127.0.0.1", Ports: fmt.Sprint(lp)}, ProxyProtocolOut: 2,
		Tunnel: &spec.Tunnel{Type: "ws", Server: addr(ctl)},
	}
	exit.apply(ex)
	entry.apply(en)
	c, err := net.Dial("tcp", addr(lp))
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("0123456789abcdef"))
	select {
	case h := <-hb.heads:
		if !bytes.HasPrefix(h, []byte("\r\n\r\n\x00\r\nQUIT\n")) {
			t.Errorf("entry proxy_out through the tunnel: %q", h)
		}
	case <-time.After(5 * time.Second):
		t.Error("backend saw nothing through the tunnel")
	}
	c.Close()

	bridge, portal := newNode(t, Options{}), newNode(t, Options{})
	// 48 bytes: enough for a full PROXY v1 line (43-47 bytes including the
	// CRLF) plus a few payload bytes; 12 would only cover the v2 signature.
	hb2 := startHeadBackend(t, 48)
	ctl2, pub := freePorts(t, 1), freePorts(t, 1)
	po := spec.Instance{ID: "po", Enabled: true, Engine: spec.EngineGost, Kind: spec.KindReversePortal, Secret: e2eSecret,
		Listen: &spec.Listen{Addr: "127.0.0.1", Ports: fmt.Sprint(pub)}, Tunnel: &spec.Tunnel{Type: "ws", Listen: addr(ctl2)}}
	br := spec.Instance{ID: "br", Enabled: true, Engine: spec.EngineGost, Kind: spec.KindReverseBridge, Secret: e2eSecret,
		Listen: &spec.Listen{Addr: "127.0.0.1", Ports: fmt.Sprint(pub)}, ProxyProtocolOut: 1,
		Targets: []spec.Target{{Host: "127.0.0.1", Ports: fmt.Sprint(hb2.Port)}}, Tunnel: &spec.Tunnel{Type: "ws", Server: addr(ctl2)}}
	portal.apply(po)
	bridge.apply(br)
	var seen []byte
	eventually(t, 10*time.Second, "bridge proxy header", func() bool {
		c, err := net.Dial("tcp", addr(pub))
		if err != nil {
			return false
		}
		defer c.Close()
		c.Write([]byte("0123456789abcdef\n"))
		select {
		case seen = <-hb2.heads:
			return true
		case <-time.After(2 * time.Second):
			return false
		}
	})
	if !bytes.HasPrefix(seen, []byte("PROXY TCP4 127.0.0.1 ")) {
		t.Errorf("bridge proxy_out: %q", seen)
	}
}

// ACL, connection and rate limits.
func TestE2EACLAndLimits(t *testing.T) {
	n := newNode(t, Options{})
	be := startBackend(t, "")
	pDeny, pAllow, pNotAllowed, pMax := freePorts(t, 1), freePorts(t, 1), freePorts(t, 1), freePorts(t, 1)
	deny := fwdInst("deny", pDeny, be.Addr)
	deny.ACL = &spec.ACL{Deny: []string{"127.0.0.1"}}
	allow := fwdInst("allow", pAllow, be.Addr)
	allow.ACL = &spec.ACL{Allow: []string{"127.0.0.0/8"}, Deny: []string{"10.0.0.0/8"}}
	notAllowed := fwdInst("notallowed", pNotAllowed, be.Addr)
	notAllowed.ACL = &spec.ACL{Allow: []string{"10.0.0.0/8"}}
	max := fwdInst("max", pMax, be.Addr)
	max.Limits = &spec.Limits{MaxConns: 2}
	n.apply(deny, allow, notAllowed, max)

	if _, err := tcpEcho(addr(pDeny), "x", false); err == nil {
		t.Error("denied client was served")
	}
	if _, err := tcpEcho(addr(pAllow), "x", false); err != nil {
		t.Errorf("allowed client: %v", err)
	}
	if _, err := tcpEcho(addr(pNotAllowed), "x", false); err == nil {
		t.Error("client outside the allow list was served")
	}
	var conns []net.Conn
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", addr(pMax))
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		time.Sleep(100 * time.Millisecond)
	}
	ok := 0
	for _, c := range conns {
		if _, err := echoOn(c, "x", false); err == nil {
			ok++
		}
	}
	for _, c := range conns {
		c.Close()
	}
	if ok != 2 {
		t.Errorf("max_conns=2: %d of 3 connections were served", ok)
	}
}

func TestE2ERateLimits(t *testing.T) {
	n := newNode(t, Options{})
	// Sink: reads everything, closes after n bytes and signals. Source: sends n bytes on connect.
	const size = 600_000
	sinkL, _ := net.Listen("tcp", "127.0.0.1:0")
	srcL, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { sinkL.Close(); srcL.Close() })
	go func() {
		for {
			c, err := sinkL.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(io.Discard, c); c.Close() }()
		}
	}()
	go func() {
		for {
			c, err := srcL.Accept()
			if err != nil {
				return
			}
			go func() { c.Write(make([]byte, size)); c.Close() }()
		}
	}()
	pUp, pDown, pFree := freePorts(t, 1), freePorts(t, 1), freePorts(t, 1)
	up := fwdInst("up", pUp, sinkL.Addr().String())
	up.Limits = &spec.Limits{RateUpBps: 8 * 200_000} // 200 kB/s client -> target
	down := fwdInst("down", pDown, srcL.Addr().String())
	down.Limits = &spec.Limits{RateDownBps: 8 * 200_000} // 200 kB/s target -> client
	free := fwdInst("free", pFree, srcL.Addr().String())
	n.apply(up, down, free)

	timeUpload := func(port int) time.Duration {
		c, _ := net.Dial("tcp", addr(port))
		defer c.Close()
		t0 := time.Now()
		buf := make([]byte, size)
		c.Write(buf)
		c.(*net.TCPConn).CloseWrite()
		io.Copy(io.Discard, c)
		return time.Since(t0)
	}
	timeDownload := func(port int) time.Duration {
		c, _ := net.Dial("tcp", addr(port))
		defer c.Close()
		t0 := time.Now()
		io.Copy(io.Discard, c)
		return time.Since(t0)
	}
	dUp, dDown, dFree := timeUpload(pUp), timeDownload(pDown), timeDownload(pFree)
	t.Logf("upload with rate_up 200kB/s: %v; download with rate_down 200kB/s: %v; unlimited download: %v (%d bytes)", dUp, dDown, dFree, size)
	if dUp < 1500*time.Millisecond {
		t.Errorf("rate_up did not limit client->target (took %v)", dUp)
	}
	if dDown < 1500*time.Millisecond {
		t.Errorf("rate_down did not limit target->client (took %v)", dDown)
	}
	if dFree > 1500*time.Millisecond {
		t.Errorf("unlimited download was slow: %v", dFree)
	}
	if dDown < dFree*2 {
		t.Errorf("limited download should be much slower than unlimited")
	}
}

// Limits of one instance with several listen ports: shared or per port?
func TestE2ERateLimitScopeAcrossPorts(t *testing.T) {
	n := newNode(t, Options{})
	const size = 400_000
	sinkL, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { sinkL.Close() })
	go func() {
		for {
			c, err := sinkL.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(io.Discard, c); c.Close() }()
		}
	}()
	base := freePorts(t, 2)
	in := spec.Instance{
		ID: "two", Enabled: true, Engine: spec.EngineGost, Kind: spec.KindForward,
		Listen:  &spec.Listen{Addr: "127.0.0.1", Ports: fmt.Sprintf("%d-%d", base, base+1)},
		Targets: []spec.Target{{Host: "127.0.0.1", Ports: fmt.Sprint(sinkL.Addr().(*net.TCPAddr).Port)}},
		Limits:  &spec.Limits{RateUpBps: 8 * 200_000},
	}
	n.apply(in)
	t0 := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			c, _ := net.Dial("tcp", addr(p))
			defer c.Close()
			c.Write(make([]byte, size))
			c.(*net.TCPConn).CloseWrite()
			io.Copy(io.Discard, c)
		}(base + i)
	}
	wg.Wait()
	d := time.Since(t0)
	t.Logf("2 ports x %d bytes at 200 kB/s per instance: %v (shared bucket would be ~4s, per-port ~2s)", size, d)
	if d < 1500*time.Millisecond {
		t.Errorf("limit ignored: %v", d)
	}
}

// G2: changing one instance keeps the established connections of the others;
// unchanged instances are not touched; a failing instance is rolled back.
func TestE2EChangeIsolationAndRollbackOfFailure(t *testing.T) {
	n := newNode(t, Options{})
	be1, be2 := startBackend(t, "B1"), startBackend(t, "B2")
	pa, pb, pc := freePorts(t, 1), freePorts(t, 1), freePorts(t, 1)
	A, B := fwdInst("a", pa, be1.Addr), fwdInst("b", pb, be1.Addr)
	res := n.apply(A, B)
	t.Logf("cold apply: %+v", res)

	// Long-lived connections on A and B.
	open := func(port int) (net.Conn, *bufioReader) {
		c, err := net.Dial("tcp", addr(port))
		if err != nil {
			t.Fatal(err)
		}
		br := newBufioReader(c)
		if _, err := br.line(); err != nil { // greeting
			t.Fatal(err)
		}
		return c, br
	}
	ca, ra := open(pa)
	cb, rb := open(pb)
	defer ca.Close()
	defer cb.Close()
	ping := func(c net.Conn, r *bufioReader, label string) error {
		c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write([]byte(label + "\n")); err != nil {
			return err
		}
		l, err := r.line()
		if err != nil || l != label {
			return fmt.Errorf("got %q err %v", l, err)
		}
		return nil
	}
	if err := ping(ca, ra, "a0"); err != nil {
		t.Fatal(err)
	}

	// 1. Same set again: nothing is restarted.
	res = n.apply(A, B)
	if len(res.Restarted) != 0 || len(res.Disrupted) != 0 {
		t.Errorf("identical apply touched instances: %+v", res)
	}
	// 2. Change B (new target), add C, keep A.
	B2 := fwdInst("b", pb, be2.Addr)
	C := fwdInst("c", pc, be2.Addr)
	res = n.apply(A, B2, C)
	t.Logf("change apply: %+v", res)
	if len(res.Restarted) != 1 || res.Restarted[0] != "b" || len(res.Disrupted) != 0 {
		t.Errorf("expected only b restarted: %+v", res)
	}
	if err := ping(ca, ra, "a1"); err != nil {
		t.Errorf("established connection of an unchanged instance broke after changing another: %v", err)
	}
	if err := ping(cb, rb, "b1"); err != nil {
		t.Logf("established connection of the CHANGED instance: %v", err)
	} else {
		t.Log("established connection of the changed instance survives (gost does not cut accepted connections)")
	}
	if name, err := tcpEcho(addr(pb), "x", true); err != nil || name != "B2" {
		t.Errorf("new connection to changed instance: %q %v", name, err)
	}
	// 3. Remove B.
	res = n.apply(A, C)
	if err := ping(ca, ra, "a2"); err != nil {
		t.Errorf("A broke when B was removed: %v", err)
	}
	if _, err := net.DialTimeout("tcp", addr(pb), time.Second); err == nil {
		t.Error("removed instance still accepts connections")
	}

	// 4. A change that cannot bind: the instance is restored, others untouched.
	blocker, err := net.Listen("tcp", addr(freePorts(t, 1)))
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	bport := blocker.Addr().(*net.TCPAddr).Port
	Cbad := fwdInst("c", bport, be2.Addr) // c moves to a busy port
	res, err = n.applyRaw(A, Cbad)
	if err == nil || res.Failed["c"] == "" {
		t.Fatalf("expected failure for c, got %+v err %v", res, err)
	}
	t.Logf("failed apply: %v", err)
	if err := ping(ca, ra, "a3"); err != nil {
		t.Errorf("A broke during a failed apply of C: %v", err)
	}
	if name, err := tcpEcho(addr(pc), "x", true); err != nil || name != "B2" {
		t.Errorf("c was not restored after the failed change: %q %v", name, err)
	}
	h := n.d.Health(context.Background(), n.rt)
	if ih := h.Instances["c"]; !ih.Running {
		t.Errorf("health of restored c: %+v", ih)
	}
	// 5. Rollback returns to the state before the last successful Apply (A,B2,C -> A,C).
	if err := n.d.Rollback(context.Background(), n.rt); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if name, err := tcpEcho(addr(pb), "x", true); err != nil || name != "B2" {
		t.Errorf("rollback did not bring b back: %q %v", name, err)
	}
	if err := ping(ca, ra, "a4"); err != nil {
		t.Errorf("A broke during rollback: %v", err)
	}
	if err := n.d.Rollback(context.Background(), n.rt); err == nil {
		t.Error("a second rollback must fail")
	}
}

type bufioReader struct{ r *bytesReader }
type bytesReader struct {
	c   net.Conn
	buf []byte
}

func newBufioReader(c net.Conn) *bufioReader { return &bufioReader{&bytesReader{c: c}} }

func (b *bufioReader) line() (string, error) {
	r := b.r
	for {
		if i := bytes.IndexByte(r.buf, '\n'); i >= 0 {
			l := string(r.buf[:i])
			r.buf = r.buf[i+1:]
			return l, nil
		}
		tmp := make([]byte, 512)
		r.c.SetReadDeadline(time.Now().Add(3 * time.Second))
		k, err := r.c.Read(tmp)
		r.buf = append(r.buf, tmp[:k]...)
		if err != nil && k == 0 {
			return "", err
		}
	}
}

// A service that cannot bind at cold start fails alone.
func TestE2EColdStartPartialFailure(t *testing.T) {
	n := newNode(t, Options{})
	be := startBackend(t, "")
	blocker, _ := net.Listen("tcp", addr(0))
	defer blocker.Close()
	busy := blocker.Addr().(*net.TCPAddr).Port
	good := freePorts(t, 1)
	res, err := n.applyRaw(fwdInst("busy", busy, be.Addr), fwdInst("good", good, be.Addr))
	if err == nil || res.Failed["busy"] == "" || res.Failed["good"] != "" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if _, err := tcpEcho(addr(good), "x", false); err != nil {
		t.Errorf("good instance: %v", err)
	}
	blocker.Close()
	// The failed one succeeds on the next apply, the good one is untouched.
	res = n.apply(fwdInst("busy", busy, be.Addr), fwdInst("good", good, be.Addr))
	if len(res.Restarted) != 0 {
		t.Errorf("restarted %v", res.Restarted)
	}
	if _, err := tcpEcho(addr(busy), "x", false); err != nil {
		t.Errorf("busy instance after retry: %v", err)
	}
}

// Crash recovery: the supervisor restarts gost from current.json and the
// instances come back without another Apply; counters stay monotonic.
func TestE2ECrashRecovery(t *testing.T) {
	n := newNode(t, Options{})
	be := startBackend(t, "")
	lp := freePorts(t, 1)
	n.apply(fwdInst("crash", lp, be.Addr))
	for i := 0; i < 3; i++ {
		if _, err := tcpEcho(addr(lp), "payload", false); err != nil {
			t.Fatal(err)
		}
	}
	before := n.stats()["crash"]
	st := n.sup.Status(procID)
	n.sup.kill(procID)
	eventually(t, 20*time.Second, "restart", func() bool {
		s := n.sup.Status(procID)
		return s.Running && s.PID != st.PID
	})
	eventually(t, 20*time.Second, "instance back", func() bool {
		h := n.d.Health(context.Background(), n.rt)
		return h.Instances["crash"].Running
	})
	if _, err := tcpEcho(addr(lp), "after-crash", false); err != nil {
		t.Fatalf("after crash: %v", err)
	}
	after := n.stats()["crash"]
	t.Logf("counters before crash %+v after %+v", before, after)
	if after.BytesUp < before.BytesUp || after.ConnsTotal < before.ConnsTotal {
		t.Errorf("counters went backwards: %+v -> %+v", before, after)
	}
	// A further Apply of the same set after the crash must not restart anything.
	res := n.apply(fwdInst("crash", lp, be.Addr))
	if len(res.Restarted) != 0 {
		t.Errorf("apply after crash restarted %v", res.Restarted)
	}
	// Health reports a stopped process.
	if err := n.d.Stop(context.Background(), n.rt); err != nil {
		t.Fatal(err)
	}
	h := n.d.Health(context.Background(), n.rt)
	if len(h.Instances) != 0 {
		t.Errorf("health after stop: %+v", h)
	}
	if _, err := net.DialTimeout("tcp", addr(lp), time.Second); err == nil {
		t.Error("listener survived Stop()")
	}
}

// Agent restart: a new driver instance with the same state dir re-applies
// without rewriting what is already correct; credentials stay private.
func TestE2EStateFilesAndSecrets(t *testing.T) {
	entry, exit := newNode(t, Options{}), newNode(t, Options{})
	ctl, lp := freePorts(t, 1), freePorts(t, 1)
	be := startBackend(t, "")
	ex := spec.Instance{ID: "ex", Enabled: true, Engine: spec.EngineGost, Kind: spec.KindTunnelExit, Secret: e2eSecret,
		Tunnel: &spec.Tunnel{Type: "ws", Listen: addr(ctl)}, Targets: []spec.Target{{Host: "127.0.0.1", Ports: fmt.Sprint(be.Port)}}}
	en := spec.Instance{ID: "en", Enabled: true, Engine: spec.EngineGost, Kind: spec.KindTunnelEntry, Secret: e2eSecret,
		Listen: &spec.Listen{Addr: "127.0.0.1", Ports: fmt.Sprint(lp)}, Tunnel: &spec.Tunnel{Type: "ws", Server: addr(ctl)}}
	exit.apply(ex)
	entry.apply(en)
	if _, err := tcpEcho(addr(lp), "x", false); err != nil {
		t.Fatal(err)
	}
	// The secret must not be in argv, the artifact hash, or in any file
	// except the 0600 state files.
	for _, nd := range []*testNode{entry, exit} {
		ps := nd.sup.Status(procID)
		if ps.PID == 0 {
			t.Fatal("no pid")
		}
		a, _ := nd.d.Render(en)
		if strings.Contains(a.Hash, e2eSecret) {
			t.Error("secret in hash")
		}
		entries, _ := os.ReadDir(nd.rt.StateDir)
		for _, e := range entries {
			b, _ := os.ReadFile(filepath.Join(nd.rt.StateDir, e.Name()))
			has := bytes.Contains(b, []byte(e2eSecret))
			info, _ := e.Info()
			t.Logf("state file %-14s secret=%-5v mode=%v size=%d", e.Name(), has, info.Mode().Perm(), info.Size())
			if e.Name() == logFile && has {
				t.Errorf("secret in the process log")
			}
			if has && os.PathSeparator == '/' && info.Mode().Perm() != 0o600 {
				t.Errorf("%s holds the secret but has mode %v", e.Name(), info.Mode().Perm())
			}
		}
	}
	// Errors never contain the secret.
	bad := en
	bad.Listen = &spec.Listen{Addr: "127.0.0.1", Ports: fmt.Sprint(lp)} // collides with en's own port
	bad.ID = "bad"
	_, err := entry.applyRaw(en, bad)
	if err == nil {
		t.Fatal("port collision must fail")
	}
	if strings.Contains(err.Error(), e2eSecret) {
		t.Errorf("secret in error: %v", err)
	}
	// A fresh driver (agent restart) over the same state dir and a running
	// process leaves everything alone.
	d2 := New(Options{})
	res, err := d2.Apply(context.Background(), entry.rt, entry.render(en))
	if err != nil || len(res.Restarted) != 0 {
		t.Errorf("re-apply by a new driver: %+v %v", res, err)
	}
	if _, err := tcpEcho(addr(lp), "x", false); err != nil {
		t.Errorf("after re-apply: %v", err)
	}
}

// Artifacts must come from Render: a tampered artifact is refused.
func TestE2EApplyRefusesForgedArtifact(t *testing.T) {
	n := newNode(t, Options{})
	be := startBackend(t, "")
	in := fwdInst("f", freePorts(t, 1), be.Addr)
	set := n.render(in)
	set[0].Artifact.Files[fragmentFile] = bytes.ReplaceAll(set[0].Artifact.Files[fragmentFile], []byte(fmt.Sprint(be.Port)), []byte("22"))
	if _, err := n.d.Apply(context.Background(), n.rt, set); err == nil {
		t.Error("forged artifact accepted")
	}
	set = n.render(in)
	set[0].Artifact.Hash = strings.Repeat("0", 64)
	if _, err := n.d.Apply(context.Background(), n.rt, set); err == nil {
		t.Error("artifact with a wrong hash accepted")
	}
}

// G3: Prometheus statistics agree with the API statistics.
func TestE2EPrometheusStatsMatchAPI(t *testing.T) {
	api := newNode(t, Options{})
	prom := newNode(t, Options{EnableMetrics: true})
	be := startBackend(t, "")
	lp1, lp2 := freePorts(t, 1), freePorts(t, 1)
	api.apply(fwdInst("s", lp1, be.Addr))
	prom.apply(fwdInst("s", lp2, be.Addr))
	sent := 0
	for _, p := range []int{lp1, lp2} {
		sent = 0
		for i := 0; i < 5; i++ {
			c, _ := net.Dial("tcp", addr(p))
			msg := strings.Repeat("y", 499)
			for j := 0; j < 4; j++ {
				if _, err := echoOn(c, msg, false); err != nil {
					t.Fatal(err)
				}
				sent += 500
			}
			c.Close()
		}
	}
	var a, p driver.Counter
	eventually(t, 5*time.Second, "stats", func() bool {
		a, p = api.stats()["s"], prom.stats()["s"]
		return a.BytesUp == uint64(sent) && p.BytesUp == uint64(sent)
	})
	t.Logf("api %+v prometheus %+v (sent %d each way)", a, p, sent)
	if a.BytesDown != p.BytesDown || a.ConnsTotal != p.ConnsTotal || a.ConnsTotal != 5 {
		t.Errorf("api and prometheus disagree: %+v vs %+v", a, p)
	}
}

// Counters stay monotonic when services are replaced and ports removed.
func TestE2EStatsMonotonicAcrossChanges(t *testing.T) {
	n := newNode(t, Options{})
	be1, be2 := startBackend(t, ""), startBackend(t, "")
	base := freePorts(t, 2)
	mk := func(ports string, be *tcpBackend) spec.Instance {
		return spec.Instance{ID: "m", Enabled: true, Engine: spec.EngineGost, Kind: spec.KindForward,
			Listen:  &spec.Listen{Addr: "127.0.0.1", Ports: ports},
			Targets: []spec.Target{{Host: "127.0.0.1", Ports: fmt.Sprint(be.Port)}}}
	}
	n.apply(mk(fmt.Sprintf("%d-%d", base, base+1), be1))
	tx := func(p int) {
		c, _ := net.Dial("tcp", addr(p))
		echoOn(c, strings.Repeat("z", 99), false)
		c.Close()
	}
	tx(base)
	tx(base + 1)
	var c1 driver.Counter
	eventually(t, 3*time.Second, "first stats", func() bool { c1 = n.stats()["m"]; return c1.BytesUp == 200 })
	n.apply(mk(fmt.Sprintf("%d-%d", base, base+1), be2)) // both services replaced
	tx(base)
	var c2 driver.Counter
	eventually(t, 3*time.Second, "second stats", func() bool { c2 = n.stats()["m"]; return c2.BytesUp == 300 })
	n.apply(mk(fmt.Sprint(base), be2)) // port base+1 removed
	c3 := n.stats()["m"]
	t.Logf("counters %+v -> %+v -> %+v", c1, c2, c3)
	if c3.BytesUp < c2.BytesUp || c3.ConnsTotal < c2.ConnsTotal {
		t.Errorf("counters decreased: %+v -> %+v", c2, c3)
	}
}

// Full reload semantics of gost itself (the reason the driver never uses
// it): POST /config/reload on a config that does not contain the running
// services removes them, and a reload whose new service cannot bind leaves
// later services unregistered. Documented here with a real process; the
// driver is not involved.
func TestE2EGostReloadIsNotUsedBecause(t *testing.T) {
	n := newNode(t, Options{})
	be := startBackend(t, "")
	pa, pb := freePorts(t, 1), freePorts(t, 1)
	n.apply(fwdInst("a", pa, be.Addr), fwdInst("b", pb, be.Addr))
	ep, err := loadEndpoint(n.rt.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	api := newAPIClient(ep, 5*time.Second)
	// current.json lists a and b; make the file list x (bound to a's port) and y (same port) then b.
	cc := currentFromApplied(&appliedState{Instances: map[string]appliedInstance{}})
	mkSvc := func(name string, port int) service {
		return service{Name: name, Addr: addr(port), Handler: handler{Type: "tcp"}, Listener: listener{Type: "tcp"},
			Forwarder: &forwarder{Nodes: []node{{Name: "t", Addr: be.Addr}}}}
	}
	cc.Services = []service{mkSvc("x", pa), mkSvc("y", pa), mkSvc("b", pb)}
	if err := writeJSON(filepath.Join(n.rt.StateDir, currentFile), cc); err != nil {
		t.Fatal(err)
	}
	err = api.do(context.Background(), "POST", "/config/reload", nil, nil)
	t.Logf("reload with conflicting services: %v", err)
	if err == nil {
		t.Error("reload unexpectedly succeeded")
	}
	if _, derr := net.DialTimeout("tcp", addr(pb), time.Second); derr == nil {
		t.Log("b survived the failed reload")
	} else {
		t.Logf("CONFIRMED: after a failed reload service b (listed after the failing one) is gone: %v", derr)
	}
}

var _ = rand.Reader
