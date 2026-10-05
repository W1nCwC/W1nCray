package xray

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/spec"
)

// tunnelPairShared puts entry and exit on one Xray instance: Xray keeps the
// outbound manager used by sockopt.dialerProxy in a package global, so two
// instances in one process cannot both use dialerProxy (one instance per
// process in production).
var tunnelPairShared bool

// tunnelPair builds an entry (node A) and an exit (node B) for a carrier.
func tunnelPair(t *testing.T, ty, sec string, targetHost string, targetPort int, networks ...string) (a, b *node, entry, exit spec.Instance, entryPort int) {
	t.Helper()
	if len(networks) == 0 {
		networks = []string{"tcp"}
	}
	a = newNode(t, testOpts())
	b = a
	if !tunnelPairShared {
		b = newNode(t, testOpts())
	}
	tp := freePort(t)
	entryPort = freePort(t)
	tun := func() *spec.Tunnel {
		x := &spec.Tunnel{Type: ty, Security: sec}
		switch ty {
		case "ws", "wss", "xhttp":
			x.Path = "/w1n"
		case "grpc":
			x.Path = "w1n"
		}
		if sec == "tls" || sec == "tls_pin" {
			x.SNI = "tun.example.net"
		}
		return x
	}
	secret := testSecret
	exitT := tun()
	exitT.Listen = fmt.Sprintf("127.0.0.1:%d", tp)
	if sec == "tls_pin" {
		exitT.Cert = &spec.Cert{Mode: "self"}
		pin, err := SelfCertPin(secret, "tun.example.net")
		if err != nil {
			t.Fatal(err)
		}
		exitT.PinSHA256 = pin
	}
	exit = spec.Instance{
		ID: "ex", Enabled: true, Engine: "xray", Kind: spec.KindTunnelExit, Network: networks,
		Targets: []spec.Target{{Host: targetHost, Ports: fmt.Sprint(targetPort)}}, Secret: secret, Tunnel: exitT,
	}
	entryT := tun()
	entryT.Server = fmt.Sprintf("127.0.0.1:%d", tp)
	entryT.PinSHA256 = exitT.PinSHA256
	entry = spec.Instance{
		ID: "en", Enabled: true, Engine: "xray", Kind: spec.KindTunnelEntry, Network: networks,
		Listen:  &spec.Listen{Addr: "127.0.0.1", Ports: fmt.Sprint(entryPort)},
		Targets: []spec.Target{{Host: targetHost, Ports: fmt.Sprint(targetPort)}}, Secret: secret, Tunnel: entryT,
	}
	if tunnelPairShared {
		a.apply(exit, entry)
	} else {
		b.apply(exit)
		a.apply(entry)
	}
	return
}

// F2/F3: every carrier moves TCP (and UDP where noted) end to end.
func TestE2ETunnelCarriers(t *testing.T) {
	cases := []struct {
		ty, sec string
		udp     bool
	}{
		{"tcp", "vless_enc", true},
		{"tls", "tls_pin", true},
		{"ws", "vless_enc", true},
		{"wss", "tls_pin", false},
		{"grpc", "tls_pin", false},
		{"xhttp", "tls_pin", false},
		{"xhttp", "vless_enc", false},
		{"grpc", "vless_enc", false},
	}
	for _, c := range cases {
		t.Run(c.ty+"/"+c.sec, func(t *testing.T) {
			host, port := dualEcho(t)
			nets := []string{"tcp"}
			if c.udp {
				nets = append(nets, "udp")
			}
			_, _, _, _, ep := tunnelPair(t, c.ty, c.sec, host, port, nets...)
			addr := fmt.Sprintf("127.0.0.1:%d", ep)
			eventually(t, 10*time.Second, "first tcp echo", func() error {
				_, err := tcpEcho(addr, []byte("hello"), false)
				return err
			})
			// burst: large writes, several connections in parallel
			for _, size := range []int{1, 64 * 1024, 1024 * 1024} {
				if _, err := tcpEcho(addr, randBytes(size), false); err != nil {
					t.Fatalf("tcp %d bytes: %v", size, err)
				}
			}
			errs := make(chan error, 8)
			for i := 0; i < 8; i++ {
				go func() { _, err := tcpEcho(addr, randBytes(100000), false); errs <- err }()
			}
			for i := 0; i < 8; i++ {
				if err := <-errs; err != nil {
					t.Fatalf("parallel: %v", err)
				}
			}
			if c.udp {
				for _, size := range []int{1, 1200} {
					if err := udpEcho(addr, randBytes(size)); err != nil {
						t.Fatalf("udp %d: %v", size, err)
					}
				}
			}
		})
	}
}

// F3: the exit relays only declared destinations, even to a holder of the
// secret, and rejects a client with another secret.
func TestE2EExitWhitelist(t *testing.T) {
	declared := echoServer(t, "")
	other := echoServer(t, "")
	dh, dp := splitHP(t, declared)
	oh, op := splitHP(t, other)
	a, _, entry, _, ep := tunnelPair(t, "tcp", "vless_enc", dh, dp)
	eventually(t, 10*time.Second, "declared target", func() error {
		_, err := tcpEcho(fmt.Sprintf("127.0.0.1:%d", ep), []byte("hi"), false)
		return err
	})
	// second entry, same secret and tunnel, but a target the exit did not declare
	e2 := entry
	e2.ID = "en2"
	e2p := freePort(t)
	e2.Listen = &spec.Listen{Addr: "127.0.0.1", Ports: fmt.Sprint(e2p)}
	e2.Targets = []spec.Target{{Host: oh, Ports: fmt.Sprint(op)}}
	a.apply(entry, e2)
	if _, err := tcpEcho(fmt.Sprintf("127.0.0.1:%d", e2p), []byte("hi"), false); err == nil {
		t.Fatal("undeclared target reachable through the tunnel")
	}
	// same host, undeclared port
	e3 := entry
	e3.ID = "en3"
	e3p := freePort(t)
	e3.Listen = &spec.Listen{Addr: "127.0.0.1", Ports: fmt.Sprint(e3p)}
	e3.Targets = []spec.Target{{Host: dh, Ports: fmt.Sprint(dp + 1)}}
	a.apply(entry, e2, e3)
	if _, err := tcpEcho(fmt.Sprintf("127.0.0.1:%d", e3p), []byte("hi"), false); err == nil {
		t.Fatal("undeclared port reachable through the tunnel")
	}
	// wrong secret cannot use the tunnel at all
	e4 := entry
	e4.ID = "en4"
	e4.Secret = testSecret + "-wrong"
	e4p := freePort(t)
	e4.Listen = &spec.Listen{Addr: "127.0.0.1", Ports: fmt.Sprint(e4p)}
	a.apply(entry, e4)
	if _, err := tcpEcho(fmt.Sprintf("127.0.0.1:%d", e4p), []byte("hi"), false); err == nil {
		t.Fatal("client with another secret got through")
	}
	// the declared path still works
	if _, err := tcpEcho(fmt.Sprintf("127.0.0.1:%d", ep), []byte("hi"), false); err != nil {
		t.Fatal(err)
	}
}

// A pinned tunnel refuses a server whose certificate does not match the pin.
func TestE2ETLSPinMismatch(t *testing.T) {
	host, port := dualEcho(t)
	a, _, entry, _, ep := tunnelPair(t, "tls", "tls_pin", host, port)
	eventually(t, 10*time.Second, "pinned tunnel", func() error {
		_, err := tcpEcho(fmt.Sprintf("127.0.0.1:%d", ep), []byte("hi"), false)
		return err
	})
	bad := entry
	bad.Tunnel = &spec.Tunnel{}
	*bad.Tunnel = *entry.Tunnel
	bad.Tunnel.PinSHA256 = strings.Repeat("0", 64)
	a.apply(bad)
	if _, err := tcpEcho(fmt.Sprintf("127.0.0.1:%d", ep), []byte("hi"), false); err == nil {
		t.Fatal("tunnel established with a wrong pin")
	}
}

// Certificate files (file mode) work, inside the permitted directory only.
func TestE2ETLSFileCert(t *testing.T) {
	dir := t.TempDir()
	cp, kp, pin, err := SelfCert("file-cert-secret-0123456789", "tun.example.net")
	if err != nil {
		t.Fatal(err)
	}
	cf, kf := filepath.ToSlash(filepath.Join(dir, "c.pem")), filepath.ToSlash(filepath.Join(dir, "k.pem"))
	os.WriteFile(cf, []byte(cp), 0o600)
	os.WriteFile(kf, []byte(kp), 0o600)
	o := testOpts()
	o.CertRoots = []string{filepath.ToSlash(dir)}
	host, port := dualEcho(t)
	a, b := newNode(t, o), newNode(t, o)
	tp, ep := freePort(t), freePort(t)
	ex := spec.Instance{ID: "ex", Enabled: true, Engine: "xray", Kind: spec.KindTunnelExit, Network: []string{"tcp"},
		Targets: []spec.Target{{Host: host, Ports: fmt.Sprint(port)}}, Secret: testSecret,
		Tunnel: &spec.Tunnel{Type: "tls", Security: "tls_pin", Listen: fmt.Sprintf("127.0.0.1:%d", tp), SNI: "tun.example.net",
			Cert: &spec.Cert{Mode: "file", CertFile: cf, KeyFile: kf}, PinSHA256: pin}}
	en := spec.Instance{ID: "en", Enabled: true, Engine: "xray", Kind: spec.KindTunnelEntry, Network: []string{"tcp"},
		Listen:  &spec.Listen{Addr: "127.0.0.1", Ports: fmt.Sprint(ep)},
		Targets: []spec.Target{{Host: host, Ports: fmt.Sprint(port)}}, Secret: testSecret,
		Tunnel: &spec.Tunnel{Type: "tls", Security: "tls_pin", Server: fmt.Sprintf("127.0.0.1:%d", tp), SNI: "tun.example.net", PinSHA256: pin}}
	b.apply(ex)
	a.apply(en)
	eventually(t, 10*time.Second, "file cert tunnel", func() error {
		_, err := tcpEcho(fmt.Sprintf("127.0.0.1:%d", ep), []byte("hi"), false)
		return err
	})
	// renewing the files changes the effective hash, so Apply restarts the inbound
	old := b.drv.state.inst["ex"].hash
	cp2, kp2, pin2, _ := SelfCert("another-secret-0123456789abc", "tun.example.net")
	os.WriteFile(cf, []byte(cp2), 0o600)
	os.WriteFile(kf, []byte(kp2), 0o600)
	res := b.apply(ex)
	if len(res.Restarted) != 1 || b.drv.state.inst["ex"].hash == old {
		t.Fatalf("renewed certificate did not restart the inbound: %+v", res)
	}
	en.Tunnel.PinSHA256 = pin2
	a.apply(en)
	eventually(t, 10*time.Second, "renewed cert tunnel", func() error {
		_, err := tcpEcho(fmt.Sprintf("127.0.0.1:%d", ep), []byte("hi"), false)
		return err
	})
}

// F6: the client's address crosses the forward tunnel inside a PROXY header
// (entry freedom{proxyProtocol} + dialerProxy).
func TestE2EProxyCarryThroughTunnel(t *testing.T) {
	psrv, got := proxyServer(t)
	ph, pp := splitHP(t, psrv)
	tunnelPairShared = true
	defer func() { tunnelPairShared = false }()
	a, _, entry, exit, ep := tunnelPair(t, "tcp", "vless_enc", ph, pp)
	entry.ProxyProtocolOut = 2
	a.apply(exit, entry)
	var c net.Conn
	eventually(t, 10*time.Second, "tunnel", func() error {
		var err error
		c, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", ep))
		if err != nil {
			return err
		}
		c.Write([]byte("ping"))
		c.SetDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 4)
		if _, err := c.Read(buf); err != nil {
			c.Close()
			return err
		}
		return nil
	})
	local := c.LocalAddr().String()
	c.Close()
	select {
	case ra := <-got:
		t.Logf("PROXY header carried through the tunnel: target saw %s (client was %s)", ra, local)
		if ra.String() != local {
			t.Fatalf("target saw %s, client was %s", ra, local)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no PROXY header at the target")
	}
}

// countingProxy forwards TCP to dst and counts accepted connections.
func countingProxy(t *testing.T, dst string) (addr string, count *atomic.Int64) {
	t.Helper()
	count = new(atomic.Int64)
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
			count.Add(1)
			go func() {
				d, err := net.Dial("tcp", dst)
				if err != nil {
					c.Close()
					return
				}
				go func() { copyClose(d, c) }()
				copyClose(c, d)
			}()
		}
	}()
	return l.Addr().String(), count
}

func copyClose(dst, src net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			dst.Write(buf[:n])
		}
		if err != nil {
			dst.Close()
			src.Close()
			return
		}
	}
}

type revSetup struct {
	portalNode, bridgeNode *node
	portal, bridge         spec.Instance
	userPort               int
	tunnelAddr             string
	target                 string
	viaCount               *atomic.Int64
	targetHost             string
	targetPort             int
}

func newReverse(t *testing.T, carrier string) *revSetup {
	t.Helper()
	host, port := dualEcho(t)
	r := &revSetup{targetHost: host, targetPort: port}
	r.portalNode, r.bridgeNode = newNode(t, testOpts()), newNode(t, testOpts())
	tp := freePort(t)
	r.userPort = freePort(t)
	r.tunnelAddr = fmt.Sprintf("127.0.0.1:%d", tp)
	via, cnt := countingProxy(t, r.tunnelAddr)
	r.viaCount = cnt
	sec := "vless_enc"
	pt := &spec.Tunnel{Type: carrier, Security: sec, Listen: r.tunnelAddr}
	bt := &spec.Tunnel{Type: carrier, Security: sec, Server: via}
	if carrier == "ws" || carrier == "xhttp" {
		pt.Path, bt.Path = "/r", "/r"
	}
	r.portal = spec.Instance{ID: "rp", Enabled: true, Engine: "xray", Kind: spec.KindReversePortal,
		Listen: &spec.Listen{Addr: "127.0.0.1", Ports: fmt.Sprint(r.userPort)}, Network: []string{"tcp", "udp"},
		Secret: testSecret, Tunnel: pt,
		Reverse: &spec.Reverse{Domain: testDomain}}
	r.bridge = spec.Instance{ID: "rb", Enabled: true, Engine: "xray", Kind: spec.KindReverseBridge, Network: []string{"tcp", "udp"},
		Targets: []spec.Target{{Host: host, Ports: fmt.Sprint(port)}}, Secret: testSecret, Tunnel: bt,
		Reverse: &spec.Reverse{Domain: testDomain}}
	return r
}

func (r *revSetup) userAddr() string { return fmt.Sprintf("127.0.0.1:%d", r.userPort) }

func (r *revSetup) check() error {
	if _, err := tcpEcho(r.userAddr(), []byte("hello reverse"), false); err != nil {
		return fmt.Errorf("tcp: %w", err)
	}
	if err := udpEcho(r.userAddr(), []byte("hello udp")); err != nil {
		return fmt.Errorf("udp: %w", err)
	}
	return nil
}

// F5: reverse proxy for TCP and UDP.
func TestE2EReverse(t *testing.T) {
	for _, carrier := range []string{"tcp", "ws"} {
		t.Run(carrier, func(t *testing.T) {
			r := newReverse(t, carrier)
			r.portalNode.apply(r.portal)
			r.bridgeNode.apply(r.bridge)
			d := eventually(t, 15*time.Second, "reverse tcp+udp", r.check)
			t.Logf("reverse %s: first TCP+UDP exchange after %s", carrier, d)
			if _, err := tcpEcho(r.userAddr(), randBytes(1<<20), false); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// F5: after one end is killed the link is back within 5 s; removing the
// bridge instance stops all reconnects.
func TestE2EReverseRecoveryAndRemove(t *testing.T) {
	r := newReverse(t, "tcp")
	r.portalNode.apply(r.portal)
	r.bridgeNode.apply(r.bridge)
	eventually(t, 15*time.Second, "initial link", r.check)

	// (a) kill the bridge side (whole Xray instance), start a fresh one
	r.bridgeNode.kill()
	time.Sleep(300 * time.Millisecond)
	if err := r.check(); err == nil {
		t.Fatal("link still works with the bridge down")
	}
	nb := newNode(t, testOpts())
	start := time.Now()
	nb.apply(r.bridge)
	d := eventually(t, 5*time.Second, "recovery after bridge restart", r.check)
	t.Logf("bridge killed and restarted: recovered %s after the new bridge was applied (%s incl. apply)", d, time.Since(start))
	r.bridgeNode = nb

	// (b) kill the portal side, start a fresh one on the same ports
	r.portalNode.kill()
	time.Sleep(300 * time.Millisecond)
	np := newNode(t, testOpts())
	t0 := time.Now()
	np.apply(r.portal)
	d = eventually(t, 5*time.Second, "recovery after portal restart", r.check)
	t.Logf("portal killed and restarted: recovered %s after the new portal was applied (%s total)", d, time.Since(t0))
	r.portalNode = np

	// (c) portal instance removed and re-added on the same node (D-C scenario)
	if err := np.drv.Stop(bg, np.rt); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	t0 = time.Now()
	np.apply(r.portal)
	d = eventually(t, 5*time.Second, "recovery after portal Remove+Add", r.check)
	t.Logf("portal instance removed and re-added: recovered %s after Apply (%s total)", d, time.Since(t0))

	// (d) removing the bridge instance: no further tunnel connections
	if err := r.bridgeNode.drv.Stop(bg, r.bridgeNode.rt); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	before := r.viaCount.Load()
	time.Sleep(7 * time.Second)
	after := r.viaCount.Load()
	t.Logf("tunnel connections accepted in the 7 s after Remove: %d (total before %d)", after-before, before)
	if after != before {
		t.Fatalf("bridge kept reconnecting after Remove: %d new connections", after-before)
	}
	if err := r.check(); err == nil {
		t.Fatal("link still works after the bridge was removed")
	}
}

// The portal only serves the rendezvous request on its tunnel inbound: a
// holder of the secret cannot use it as a proxy.
func TestE2EPortalTunnelNotAProxy(t *testing.T) {
	r := newReverse(t, "tcp")
	r.portalNode.apply(r.portal)
	// a normal tunnel entry with the portal's secret towards the portal's tunnel port
	host, port := dualEcho(t)
	a := newNode(t, testOpts())
	ep := freePort(t)
	en := spec.Instance{ID: "en", Enabled: true, Engine: "xray", Kind: spec.KindTunnelEntry, Network: []string{"tcp"},
		Listen:  &spec.Listen{Addr: "127.0.0.1", Ports: fmt.Sprint(ep)},
		Targets: []spec.Target{{Host: host, Ports: fmt.Sprint(port)}}, Secret: testSecret,
		Tunnel: &spec.Tunnel{Type: "tcp", Security: "vless_enc", Server: r.tunnelAddr}}
	a.apply(en)
	time.Sleep(500 * time.Millisecond)
	if _, err := tcpEcho(fmt.Sprintf("127.0.0.1:%d", ep), []byte("hi"), false); err == nil {
		t.Fatal("portal tunnel inbound relayed a non-rendezvous request")
	}
}
