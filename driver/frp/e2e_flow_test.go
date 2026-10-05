//go:build e2e

package frp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/spec"
)

// ---------- helpers ----------

// startTagEcho answers every chunk with tag+chunk.
func startTagEcho(t testing.TB, tag string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(append([]byte(tag), buf[:n]...)); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// pinger keeps one TCP connection busy with ping/pong until it breaks.
type pinger struct {
	mu   sync.Mutex
	n    int
	err  error
	stop chan struct{}
	done chan struct{}
	c    net.Conn
}

func startPinger(t testing.TB, addr, tag string) *pinger {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("pinger dial %s: %v", addr, err)
	}
	p := &pinger{stop: make(chan struct{}), done: make(chan struct{}), c: c}
	t.Cleanup(p.close)
	go func() {
		defer close(p.done)
		buf := make([]byte, len(tag)+4)
		for {
			select {
			case <-p.stop:
				return
			default:
			}
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			var err error
			if _, err = c.Write([]byte("ping")); err == nil {
				if _, err = io.ReadFull(c, buf); err == nil && string(buf) != tag+"ping" {
					err = fmt.Errorf("unexpected reply %q", buf)
				}
			}
			p.mu.Lock()
			if err != nil {
				p.err = err
				p.mu.Unlock()
				return
			}
			p.n++
			p.mu.Unlock()
			time.Sleep(50 * time.Millisecond)
		}
	}()
	return p
}

func (p *pinger) state() (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.n, p.err
}

func (p *pinger) close() {
	select {
	case <-p.stop:
	default:
		close(p.stop)
	}
	_ = p.c.Close()
	<-p.done
}

// alive checks that the pinger made progress for d without an error.
func (p *pinger) alive(t testing.TB, d time.Duration, what string) {
	t.Helper()
	n0, err := p.state()
	if err != nil {
		t.Fatalf("%s: connection already broken: %v", what, err)
	}
	time.Sleep(d)
	n1, err := p.state()
	if err != nil || n1 <= n0 {
		t.Fatalf("%s: connection not alive (pings %d -> %d, err %v)", what, n0, n1, err)
	}
}

func (p *pinger) broken(t testing.TB, within time.Duration, what string) time.Duration {
	t.Helper()
	return eventually(t, within, what+" is cut", func() error {
		if _, err := p.state(); err == nil {
			return fmt.Errorf("still alive")
		}
		return nil
	})
}

func (e *env) procOf(id string) string {
	e.d.rmu.RLock()
	defer e.d.rmu.RUnlock()
	u := e.d.current[id]
	if u == nil {
		e.t.Fatalf("unknown instance %s", id)
	}
	return procID(u)
}

func (e *env) adminOf(id string) adminInfo {
	a, ok := e.d.adminFor(e.rt, id)
	if !ok {
		e.t.Fatalf("no admin info for %s", id)
	}
	return a
}

func (e *env) stats(id string) driver.Counter {
	e.t.Helper()
	cs, err := e.d.Stats(context.Background(), e.rt)
	if err != nil {
		e.t.Fatalf("stats: %v", err)
	}
	for _, c := range cs {
		if c.InstanceID == id {
			return c
		}
	}
	e.t.Fatalf("no counter for %s in %v", id, cs)
	return driver.Counter{}
}

// ---------- recovery ----------

func TestE2EReconnect(t *testing.T) {
	e := newEnv(t)
	p := newPair(t, "r", 1, []string{"tcp", "udp"}, spec.Tunnel{Type: "tcp", Security: "tls"})
	p.withEcho(t)
	e.mustApply(p.portal, p.bridge)
	e.waitUp(p.bridge.ID, 10*time.Second)
	check := func() error {
		if err := tcpRoundTrip(p.pub(0), []byte("tcp-ping")); err != nil {
			return err
		}
		return udpRoundTrip(p.pub(0), []byte("udp-ping"))
	}
	eventually(t, 5*time.Second, "initial", check)

	// 1. frps crashes; the supervisor restarts it after its back-off (1 s in
	// the test supervisor). The recovery time includes that back-off.
	t0 := time.Now()
	e.sup.Kill(e.procOf(p.portal.ID))
	eventually(t, 5*time.Second, "frps down", func() error {
		if tcpRoundTrip(p.pub(0), []byte("x")) == nil {
			return fmt.Errorf("still up")
		}
		return nil
	})
	d1 := eventually(t, 90*time.Second, "recovery after frps crash", check)
	t.Logf("RECOVERY frps crash (1 s supervisor back-off): %v after the kill", time.Since(t0))
	_ = d1

	// 2. frpc crashes.
	t0 = time.Now()
	e.sup.Kill(e.procOf(p.bridge.ID))
	eventually(t, 90*time.Second, "recovery after frpc crash", func() error {
		if time.Since(t0) < 500*time.Millisecond {
			return fmt.Errorf("too early")
		}
		return check()
	})
	t.Logf("RECOVERY frpc crash (1 s supervisor back-off): %v after the kill", time.Since(t0))

	// 3. The portal is away for 12 s: frpc has to wait out its own back-off.
	if err := e.d.Stop(context.Background(), e.rt, p.portal.ID); err != nil {
		t.Fatal(err)
	}
	time.Sleep(12 * time.Second)
	t0 = time.Now()
	e.mustApply(p.portal, p.bridge)
	eventually(t, 90*time.Second, "recovery after a 12 s portal outage", check)
	t.Logf("RECOVERY after 12 s portal outage: %v after the portal was back", time.Since(t0))
	if time.Since(t0) > 40*time.Second {
		t.Fatalf("recovery took too long: %v", time.Since(t0))
	}
}

// ---------- PROXY protocol ----------

func TestE2EProxyProtocolOut(t *testing.T) {
	for _, ver := range []int{1, 2} {
		t.Run(fmt.Sprintf("v%d", ver), func(t *testing.T) {
			e := newEnv(t)
			p := newPair(t, "pp", 1, []string{"tcp"}, spec.Tunnel{Type: "tcp", Security: "tls"})
			srv, port := startProxyEcho(t)
			p.bridge.Targets = []spec.Target{{Host: "127.0.0.1", Ports: fmt.Sprint(port)}}
			p.bridge.ProxyProtocolOut = ver
			e.mustApply(p.portal, p.bridge)
			e.waitUp(p.bridge.ID, 10*time.Second)

			c, err := net.DialTimeout("tcp", p.pub(0), 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			local := c.LocalAddr().String()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := c.Write([]byte("data-after-header")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, len("data-after-header"))
			if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "data-after-header" {
				t.Fatalf("echo through PROXY target: %q %v", buf, err)
			}
			srv.mu.Lock()
			seen := append([]string(nil), srv.seen...)
			srv.mu.Unlock()
			want := fmt.Sprintf("v%d %s", ver, local)
			if len(seen) != 1 || seen[0] != want {
				t.Fatalf("target saw %v, want [%s]", seen, want)
			}
			t.Logf("target saw PROXY header %q (client %s)", seen[0], local)
		})
	}
}

// ---------- statistics ----------

func TestE2EStatsMatchBytes(t *testing.T) {
	e := newEnv(t)
	p := newPair(t, "st", 2, []string{"tcp", "udp"}, spec.Tunnel{Type: "tcp", Security: "tls"})
	p.narrow()
	// TCP target: read 1000 bytes, answer 5000, close. UDP target: echo.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	tport := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if _, err := io.ReadFull(c, make([]byte, 1000)); err != nil {
					return
				}
				_, _ = c.Write(bytes.Repeat([]byte{'d'}, 5000))
				// Keep the connection open until the client closes it.
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", tport))
	if err != nil {
		t.Skipf("udp port %d busy: %v", tport, err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, a, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], a)
		}
	}()
	p.bridge.Targets = []spec.Target{{Host: "127.0.0.1", Ports: fmt.Sprint(tport)}}
	e.mustApply(p.portal, p.bridge)
	e.waitUp(p.bridge.ID, 10*time.Second)
	pid := p.portal.ID

	// TCP: 1000 bytes up, 5000 down; the bytes are booked when the connection
	// closes.
	c, err := net.DialTimeout("tcp", p.pub(0), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write(bytes.Repeat([]byte{'u'}, 1000)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, 5000)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "one active connection", func() error {
		if got := e.stats(pid).ConnsActive; got != 1 {
			return fmt.Errorf("ConnsActive = %d", got)
		}
		return nil
	})
	before := e.stats(pid)
	if before.BytesUp != 0 || before.BytesDown != 0 {
		t.Logf("NOTE: frps already booked bytes of the open connection: up=%d down=%d", before.BytesUp, before.BytesDown)
	} else {
		t.Logf("frps books TCP bytes only when the connection closes (open conn: up=0 down=0)")
	}
	c.Close()
	eventually(t, 10*time.Second, "tcp bytes booked", func() error {
		s := e.stats(pid)
		if s.ConnsActive != 0 || s.BytesUp != 1000 || s.BytesDown != 5000 {
			return fmt.Errorf("stats %+v, want up=1000 down=5000 active=0", s)
		}
		return nil
	})
	t.Logf("TCP stats after close: %+v (sent 1000 up, 5000 down)", e.stats(pid))

	// UDP: 10 datagrams of 100 bytes, echoed.
	uc, err := net.Dial("udp", p.pub(0))
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	for i := 0; i < 10; i++ {
		_ = uc.SetDeadline(time.Now().Add(3 * time.Second))
		msg := bytes.Repeat([]byte{byte('a' + i)}, 100)
		if _, err := uc.Write(msg); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 200)
		if n, err := uc.Read(buf); err != nil || n != 100 {
			t.Fatalf("udp reply %d %v", n, err)
		}
	}
	eventually(t, 10*time.Second, "udp bytes booked", func() error {
		s := e.stats(pid)
		if s.BytesUp != 1000+1000 || s.BytesDown != 5000+1000 {
			return fmt.Errorf("stats %+v, want up=2000 down=6000", s)
		}
		return nil
	})
	t.Logf("UDP stats: %+v (10 x 100 bytes each way added)", e.stats(pid))

	// Counters never decrease when the portal restarts (it loses its own
	// counters) and keep adding up afterwards.
	prev := e.stats(pid)
	p.portal.Listen.Ports = fmt.Sprintf("%d-%d", p.pubLo, p.pubLo+1)
	// The extra public port must be free for tcp+udp: reuse the range helper.
	res := e.mustApply(p.portal, p.bridge)
	if !contains(res.Restarted, pid) || !contains(res.Disrupted, pid) {
		t.Fatalf("portal change must restart and disrupt it: %+v", res)
	}
	e.waitUp(p.bridge.ID, 90*time.Second)
	if now := e.stats(pid); now.BytesUp < prev.BytesUp || now.BytesDown < prev.BytesDown {
		t.Fatalf("counters decreased across a restart: %+v -> %+v", prev, now)
	}
	if err := tcpRoundTripSized(p.pub(0), 1000, 5000); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "bytes after restart", func() error {
		s := e.stats(pid)
		if s.BytesUp != prev.BytesUp+1000 || s.BytesDown != prev.BytesDown+5000 {
			return fmt.Errorf("stats %+v, want up=%d down=%d", s, prev.BytesUp+1000, prev.BytesDown+5000)
		}
		return nil
	})
}

func tcpRoundTripSized(addr string, up, down int) error {
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write(bytes.Repeat([]byte{'u'}, up)); err != nil {
		return err
	}
	_, err = io.ReadFull(c, make([]byte, down))
	return err
}

func contains(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}

// ---------- frpc reload: only changed proxies are rebuilt ----------

// proxyLog returns the proxy names frpc logged as removed / added.
func proxyLog(log string) (removed, added []string) {
	for _, l := range strings.Split(log, "\n") {
		if i := strings.Index(l, "proxy removed:"); i >= 0 {
			removed = append(removed, l[i:])
		}
		if i := strings.Index(l, "proxy added:"); i >= 0 {
			added = append(added, l[i:])
		}
	}
	return
}

func replyTag(addr, payload string) (string, error) {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte(payload)); err != nil {
		return "", err
	}
	buf := make([]byte, len(payload)+1)
	if _, err := io.ReadFull(c, buf); err != nil {
		return "", err
	}
	return string(buf[:1]), nil
}

func TestE2EBridgeReloadKeepsOtherProxies(t *testing.T) {
	e := newEnv(t)
	p := newPair(t, "rl", 3, []string{"tcp"}, spec.Tunnel{Type: "tcp", Security: "tls"})
	portA, portB, portC := startTagEcho(t, "A"), startTagEcho(t, "B"), startTagEcho(t, "C")
	portD := startTagEcho(t, "D")
	build := func(ports string, targets map[int]int) spec.Instance {
		in := p.bridge
		pm := map[string]string{}
		for off, port := range targets {
			pm[fmt.Sprint(p.pubLo+off)] = fmt.Sprintf("127.0.0.1:%d", port)
		}
		in.Listen = &spec.Listen{Ports: ports, PortMap: pm}
		return in
	}
	all := p.bridge.Listen.Ports
	br := build(all, map[int]int{0: portA, 1: portB, 2: portC})
	e.mustApply(p.portal, br)
	e.waitUp(br.ID, 10*time.Second)
	pid0 := e.sup.Status(e.procOf(br.ID)).PID

	pa := startPinger(t, p.pub(0), "A")
	pb := startPinger(t, p.pub(1), "B")
	pcc := startPinger(t, p.pub(2), "C")
	pa.alive(t, time.Second, "A")

	// 1. Retarget only the middle proxy.
	br2 := build(all, map[int]int{0: portA, 1: portD, 2: portC})
	t0 := time.Now()
	res := e.mustApply(p.portal, br2)
	t.Logf("RELOAD (one proxy retargeted) took %v; result: %+v", time.Since(t0), res)
	if len(res.Restarted) != 0 || len(res.Disrupted) != 0 {
		t.Fatalf("a proxy-only change must neither restart frpc nor cut connections: %+v", res)
	}
	if got := e.sup.Status(e.procOf(br.ID)).PID; got != pid0 {
		t.Fatalf("frpc pid changed %d -> %d", pid0, got)
	}
	e.waitUp(br.ID, 10*time.Second)
	pa.alive(t, 2*time.Second, "untouched proxy A after reload")
	pcc.alive(t, time.Second, "untouched proxy C after reload")
	// MEASURED: the established connection of the rebuilt proxy survives too
	// and keeps talking to its OLD target (pinger B checks the "B" tag).
	pb.alive(t, time.Second, "established connection of the retargeted proxy B")
	eventually(t, 10*time.Second, "new connections on B reach D", func() error {
		tag, err := replyTag(p.pub(1), "hi")
		if err != nil {
			return err
		}
		if tag != "D" {
			return fmt.Errorf("got %q", tag)
		}
		return nil
	})
	removed, added := proxyLog(e.logOf(br.ID))
	t.Logf("frpc log after step 1:\n  removed: %v\n  added:   %v", removed, added)
	mid := fmt.Sprintf("[%s.t%d]", br.ID, p.pubLo+1)
	if len(removed) != 1 || !strings.Contains(removed[0], mid) {
		t.Fatalf("exactly the retargeted proxy must be removed, got %v", removed)
	}
	if len(added) != 2 || !strings.Contains(added[1], mid) || strings.Contains(added[1], fmt.Sprintf("t%d", p.pubLo)) {
		t.Fatalf("exactly the retargeted proxy must be added again, got %v", added)
	}

	// 2. Remove the last proxy from the bridge.
	br3 := build(fmt.Sprintf("%d-%d", p.pubLo, p.pubLo+1), map[int]int{0: portA, 1: portD})
	res = e.mustApply(p.portal, br3)
	t.Logf("RELOAD (one proxy removed): %+v", res)
	if len(res.Restarted) != 0 || len(res.Disrupted) != 0 {
		t.Fatalf("removing a proxy must not restart frpc: %+v", res)
	}
	pa.alive(t, time.Second, "A after removing C")
	pb.alive(t, time.Second, "B after removing C")
	pcc.alive(t, time.Second, "established connection of the removed proxy C")
	eventually(t, 10*time.Second, "new connections on C are refused", func() error {
		if _, err := replyTag(p.pub(2), "hi"); err == nil {
			return fmt.Errorf("still reachable")
		}
		return nil
	})
	if got := e.sup.Status(e.procOf(br.ID)).PID; got != pid0 {
		t.Fatalf("frpc pid changed %d -> %d", pid0, got)
	}

	// 3. A change of the common section (here the SNI) needs a restart, which
	// cuts every connection of the bridge.
	br4 := br3
	tun := *br3.Tunnel
	tun.SNI = "other.example.com"
	br4.Tunnel = &tun
	res = e.mustApply(p.portal, br4)
	t.Logf("RESTART (common section changed): %+v", res)
	if !contains(res.Restarted, br.ID) || !contains(res.Disrupted, br.ID) {
		t.Fatalf("a common-section change must restart frpc: %+v", res)
	}
	if got := e.sup.Status(e.procOf(br.ID)).PID; got == pid0 {
		t.Fatal("frpc was not restarted")
	}
	pa.broken(t, 5*time.Second, "A after the frpc restart")
	pb.broken(t, 5*time.Second, "B after the frpc restart")
	pcc.broken(t, 5*time.Second, "C after the frpc restart")
	e.waitUp(br.ID, 30*time.Second)
}

// ---------- wrong token, secrets nowhere ----------

func TestE2EBadTokenAndSecretHygiene(t *testing.T) {
	e := newEnv(t)
	p := newPair(t, "bt", 1, []string{"tcp"}, spec.Tunnel{Type: "tcp", Security: "tls"})
	p.withEcho(t)
	good := p.bridge
	p.bridge.Secret = "e2e-WRONG-token-0123456789abcdef"
	e.mustApply(p.portal, p.bridge)
	time.Sleep(4 * time.Second)
	h := e.health(p.bridge.ID)
	if !h.Running || h.Listening {
		t.Fatalf("bridge with a wrong token must run but not be registered: %+v", h)
	}
	t.Logf("bridge health with a wrong token: %+v", h)
	if err := tcpRoundTrip(p.pub(0), []byte("x")); err == nil {
		t.Fatal("traffic flowed with a wrong token")
	}
	if st := e.sup.Status(e.procOf(p.bridge.ID)); st.Restarts != 0 {
		t.Fatalf("frpc must keep retrying, not crash-loop: %+v", st)
	}
	log := e.logOf(p.bridge.ID)
	if !strings.Contains(log, "token") && !strings.Contains(log, "auth") {
		t.Logf("frpc log has no auth message:\n%s", log)
	}
	t.Logf("frpc says: %s", firstLineContaining(log, "login"))

	// Fix the token: it registers.
	e.mustApply(p.portal, good)
	e.waitUp(good.ID, 30*time.Second)
	eventually(t, 5*time.Second, "traffic", func() error { return tcpRoundTrip(p.pub(0), []byte("ok")) })

	// Hygiene: no secret in argv, logs, health or errors.
	secrets := []string{p.secret, "e2e-WRONG-token-0123456789abcdef"}
	e.sup.mu.Lock()
	for id, pr := range e.sup.procs {
		for _, a := range pr.spec.Args {
			for _, s := range secrets {
				if strings.Contains(a, s) {
					t.Fatalf("secret in argv of %s", id)
				}
			}
		}
		for _, a := range pr.spec.Env {
			for _, s := range secrets {
				if strings.Contains(a, s) {
					t.Fatalf("secret in env of %s", id)
				}
			}
		}
	}
	e.sup.mu.Unlock()
	ents, _ := os.ReadDir(dirLogs(e.rt))
	for _, f := range ents {
		b, _ := os.ReadFile(filepath.Join(dirLogs(e.rt), f.Name()))
		for _, s := range secrets {
			if bytes.Contains(b, []byte(s)) {
				t.Fatalf("secret found in %s", f.Name())
			}
		}
	}
	hh := fmt.Sprintf("%+v", e.d.Health(context.Background(), e.rt))
	for _, s := range secrets {
		if strings.Contains(hh, s) {
			t.Fatal("secret in Health output")
		}
	}
	t.Logf("no secret in %d log file(s), argv, env or Health", len(ents))
}

func firstLineContaining(s, sub string) string {
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, sub) {
			return strings.TrimSpace(l)
		}
	}
	return "(none)"
}

// ---------- allowPorts / maxPortsPerClient ----------

type rawProxy struct {
	name, typ string
	remote    int
}

// startRogue runs a hand-written frpc (not generated by the driver) with the
// portal's token: it stands for a bridge that asks for more than it may.
func startRogue(t *testing.T, e *env, p *pair, localPort int, proxies []rawProxy) (output func() string, stop func()) {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, `serverAddr = "127.0.0.1"
serverPort = %d
loginFailExit = false

[auth]
method = "token"
token = %q
additionalScopes = ["HeartBeats", "NewWorkConns"]

[log]
to = "console"
level = "info"
disablePrintColor = true
`, p.ctrl, p.secret)
	for _, x := range proxies {
		fmt.Fprintf(&b, "\n[[proxies]]\nname = %q\ntype = %q\nlocalIP = \"127.0.0.1\"\nlocalPort = %d\nremotePort = %d\n", x.name, x.typ, localPort, x.remote)
	}
	cfgPath := filepath.Join(t.TempDir(), "rogue.toml")
	if err := os.WriteFile(cfgPath, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(e.frpc, "-c", cfgPath)
	cmd.Env = minimalEnv()
	var out bytes.Buffer
	var mu sync.Mutex
	cmd.Stdout, cmd.Stderr = &lockedWriter{&mu, &out}, &lockedWriter{&mu, &out}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	stop = func() { once.Do(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }) }
	t.Cleanup(stop)
	return func() string { mu.Lock(); defer mu.Unlock(); return out.String() }, stop
}

func onlineProxies(t *testing.T, a adminInfo) map[string]bool {
	t.Helper()
	res := map[string]bool{}
	for _, typ := range []string{"tcp", "udp"} {
		ps, err := a.proxies(context.Background(), typ)
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range ps {
			if x.Status == "online" {
				res[typ+"/"+x.Name] = true
			}
		}
	}
	return res
}

func TestE2EAllowPortsAndMaxPorts(t *testing.T) {
	e := newEnv(t)
	p := newPair(t, "ap", 2, []string{"tcp"}, spec.Tunnel{Type: "tcp", Security: "tls"})
	e.mustApply(p.portal) // portal only; the "bridge" is a hand-written frpc
	a := e.adminOf(p.portal.ID)
	_, echoPort := startTCPEcho(t)
	outside := freePort(t)
	for outside >= p.pubLo && outside < p.pubLo+2 {
		outside = freePort(t)
	}

	// Phase 1: a port outside allowPorts is refused, the two inside are fine.
	out1, stop1 := startRogue(t, e, p, echoPort, []rawProxy{
		{"evil.outside", "tcp", outside}, {"ok.first", "tcp", p.pubLo}, {"ok.second", "tcp", p.pubLo + 1},
	})
	eventually(t, 15*time.Second, "permitted proxies online", func() error {
		on := onlineProxies(t, a)
		if !on["tcp/ok.first"] || !on["tcp/ok.second"] {
			return fmt.Errorf("online: %v", on)
		}
		return nil
	})
	time.Sleep(time.Second)
	if on := onlineProxies(t, a); on["tcp/evil.outside"] {
		t.Fatal("proxy outside allowPorts was accepted")
	}
	if err := tcpRoundTrip(fmt.Sprintf("127.0.0.1:%d", outside), []byte("x")); err == nil {
		t.Fatal("the outside port is listening")
	}
	srvLog := e.logOf(p.portal.ID)
	t.Logf("frps log: %s", firstLineContaining(srvLog, "evil.outside"))
	t.Logf("frpc output: %s", firstLineContaining(out1(), "evil.outside"))
	if !strings.Contains(srvLog, "[evil.outside] type [tcp] error: port not allowed") {
		t.Fatalf("expected 'port not allowed' for the outside port in the frps log:\n%s", srvLog)
	}
	stop1()
	eventually(t, 15*time.Second, "portal released the ports", func() error {
		if on := onlineProxies(t, a); len(on) != 0 {
			return fmt.Errorf("still online: %v", on)
		}
		return nil
	})

	// Phase 2: three ports asked, maxPortsPerClient allows two (2 public
	// ports x 1 network). Which one loses depends on the registration order.
	_, stop2 := startRogue(t, e, p, echoPort, []rawProxy{
		{"q.one", "tcp", p.pubLo}, {"q.two", "tcp", p.pubLo + 1}, {"q.three", "udp", p.pubLo},
	})
	defer stop2()
	eventually(t, 15*time.Second, "two proxies online", func() error {
		if n := len(onlineProxies(t, a)); n != 2 {
			return fmt.Errorf("%d online", n)
		}
		return nil
	})
	time.Sleep(2 * time.Second)
	if n := len(onlineProxies(t, a)); n != 2 {
		t.Fatalf("%d proxies online, quota is 2: %v", n, onlineProxies(t, a))
	}
	srvLog = e.logOf(p.portal.ID)
	if !strings.Contains(srvLog, "exceed the max_ports_per_client") {
		t.Fatalf("expected the quota error in the frps log:\n%s", srvLog)
	}
	t.Logf("quota: %s", firstLineContaining(srvLog, "exceed the max_ports_per_client"))
	t.Logf("online after the quota: %v", onlineProxies(t, a))
}

type lockedWriter struct {
	mu *sync.Mutex
	b  *bytes.Buffer
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

// ---------- templates: frp evaluates them, our output cannot ----------

func TestE2EFrpEvaluatesTemplates(t *testing.T) {
	e := newEnv(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "tpl.toml")
	body := "bindPort = {{ .Envs.W1NC_E2E_PORT }}\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(env ...string) (string, error) {
		cmd := exec.Command(e.frps, "verify", "-c", cfg)
		cmd.Env = append(minimalEnv(), env...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	out, err := run("W1NC_E2E_PORT=7123")
	if err != nil {
		t.Fatalf("positive control failed, frps did not substitute the template: %v\n%s", err, out)
	}
	t.Logf("POSITIVE CONTROL: with env set, frps accepted `bindPort = {{ .Envs.W1NC_E2E_PORT }}`: %s", strings.TrimSpace(out))
	out, err = run()
	if err == nil {
		t.Fatal("without the env var the file must not be valid")
	}
	t.Logf("without the env var: %s", strings.TrimSpace(out))

	// Everything the driver renders passes through `verify` unchanged (a
	// value with template syntax would have been substituted or rejected).
	for _, in := range []spec.Instance{
		func() spec.Instance {
			p := newPair(t, "tp", 2, []string{"tcp", "udp"}, spec.Tunnel{Type: "tcp", Security: "tls"})
			return p.portal
		}(),
		func() spec.Instance {
			p := newPair(t, "tp", 2, []string{"tcp", "udp"}, spec.Tunnel{Type: "tcp", Security: "tls"})
			return p.bridge
		}(),
	} {
		u := mustCompile(t, withTargets(in))
		file := filepath.Join(dir, u.mainFile())
		if err := os.WriteFile(file, u.Files[u.mainFile()], 0o600); err != nil {
			t.Fatal(err)
		}
		bin := e.frps
		if u.Role == roleBridge {
			bin = e.frpc
		}
		cmd := exec.Command(bin, "verify", "-c", file)
		cmd.Env = append(minimalEnv(), "W1NC_E2E_PORT=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s verify rejected the rendered %s: %v\n%s", filepath.Base(bin), u.Role, err, out)
		}
	}
}

func withTargets(in spec.Instance) spec.Instance {
	if in.Kind == spec.KindReverseBridge {
		in.Targets = []spec.Target{{Host: "127.0.0.1", Ports: "9000-9001"}}
	}
	return in
}

// ---------- admin endpoint ----------

func TestE2EAdminEndpointIsLocalAndAuthenticated(t *testing.T) {
	e := newEnv(t)
	p := newPair(t, "ad", 1, []string{"tcp"}, spec.Tunnel{Type: "tcp", Security: "tls"})
	p.withEcho(t)
	e.mustApply(p.portal, p.bridge)
	e.waitUp(p.bridge.ID, 10*time.Second)

	for _, id := range []string{p.portal.ID, p.bridge.ID} {
		a := e.adminOf(id)
		// No credentials: refused.
		if err := (adminInfo{Port: a.Port}).do(context.Background(), "GET", "/api/status", false, nil); err == nil {
			t.Fatalf("%s: unauthenticated API call succeeded", id)
		}
		if err := (adminInfo{Port: a.Port, User: a.User, Pass: "wrong"}).do(context.Background(), "GET", "/api/status", true, nil); err == nil && id == p.bridge.ID {
			t.Fatalf("%s: wrong password accepted", id)
		}
		path := "/api/serverinfo"
		if id == p.bridge.ID {
			path = "/api/status"
		}
		if err := a.do(context.Background(), "GET", path, true, nil); err != nil {
			t.Fatalf("%s: authenticated call failed: %v", id, err)
		}
		// Bound to loopback only: connecting through any other local address
		// must fail.
		addrs, _ := net.InterfaceAddrs()
		tried := 0
		for _, ad := range addrs {
			ipn, ok := ad.(*net.IPNet)
			if !ok || ipn.IP.IsLoopback() || ipn.IP.To4() == nil {
				continue
			}
			c, err := net.DialTimeout("tcp", net.JoinHostPort(ipn.IP.String(), fmt.Sprint(a.Port)), time.Second)
			if err == nil {
				c.Close()
				t.Fatalf("%s: admin port %d reachable on %s", id, a.Port, ipn.IP)
			}
			tried++
		}
		t.Logf("%s: admin 127.0.0.1:%d needs credentials; refused on %d non-loopback address(es)", id, a.Port, tried)
		if a.User == "" || len(a.Pass) < 32 {
			t.Fatalf("weak admin credentials")
		}
	}
	// Fresh credentials at every process start.
	a1 := e.adminOf(p.portal.ID)
	in2 := p.portal
	in2.Listen = &spec.Listen{Addr: "127.0.0.1", Ports: p.portal.Listen.Ports}
	in2.Tunnel = &spec.Tunnel{Type: "tcp", Security: "tls", Listen: p.portal.Tunnel.Listen, Cert: nil}
	in2.Network = []string{"tcp", "udp"} // changes the config: restart
	e.mustApply(in2, p.bridge)
	a2 := e.adminOf(p.portal.ID)
	if a1.Pass == a2.Pass || a1.User == a2.User {
		t.Fatal("admin credentials were reused across a restart")
	}
	if runtime.GOOS != "windows" {
		for _, path := range []string{a2.Cfg, filepath.Join(dirAdmin(e.rt), p.portal.ID+".json"), filepath.Join(e.state, currentFile)} {
			st, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if st.Mode().Perm() != 0o600 {
				t.Fatalf("%s mode %v, want 0600", path, st.Mode().Perm())
			}
		}
		st, _ := os.Stat(e.state)
		if st.Mode().Perm()&0o077 != 0 {
			t.Fatalf("state dir mode %v is group/world accessible", st.Mode().Perm())
		}
	}
}

// ---------- failure handling ----------

func TestE2EApplyFailureRestoresPreviousAndRollback(t *testing.T) {
	e := newEnv(t)
	p := newPair(t, "fr", 1, []string{"tcp"}, spec.Tunnel{Type: "tcp", Security: "tls"})
	portA, portB := startTagEcho(t, "A"), startTagEcho(t, "B")
	setTarget := func(port int) spec.Instance {
		in := p.bridge
		in.Targets = []spec.Target{{Host: "127.0.0.1", Ports: fmt.Sprint(port)}}
		return in
	}
	e.mustApply(p.portal, setTarget(portA))
	e.waitUp(p.bridge.ID, 10*time.Second)
	expect := func(tag string) {
		t.Helper()
		eventually(t, 10*time.Second, "reach "+tag, func() error {
			c, err := net.DialTimeout("tcp", p.pub(0), 2*time.Second)
			if err != nil {
				return err
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			_, _ = c.Write([]byte("z"))
			buf := make([]byte, 2)
			if _, err := io.ReadFull(c, buf); err != nil {
				return err
			}
			if string(buf) != tag+"z" {
				return fmt.Errorf("got %q", buf)
			}
			return nil
		})
	}
	expect("A")

	// 1. A portal whose control port is taken cannot start: Apply reports the
	// failure, restores the previous portal and traffic keeps flowing.
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	bad := p.portal
	badTun := *p.portal.Tunnel
	badTun.Listen = busy.Addr().String()
	bad.Tunnel = &badTun
	t0 := time.Now()
	res, err := e.apply(bad, setTarget(portA))
	if err == nil || res.Failed[bad.ID] == "" {
		t.Fatalf("a portal on a busy port must fail: err=%v res=%+v", err, res)
	}
	t.Logf("failed apply took %v: %v", time.Since(t0), res.Failed[bad.ID])
	if strings.Contains(res.Failed[bad.ID], p.secret) {
		t.Fatal("secret in error")
	}
	e.waitUp(p.bridge.ID, 90*time.Second) // bridge reconnects to the restored portal
	expect("A")
	if h := e.health(p.portal.ID); !h.Running {
		t.Fatalf("restored portal not running: %+v", h)
	}

	// 2. Rollback restores the set before the last changing Apply.
	e.mustApply(p.portal, setTarget(portB)) // reload path
	expect("B")
	if err := e.d.Rollback(context.Background(), e.rt); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	expect("A")
	t.Logf("rollback restored the previous target")

	// 3. Removing an instance from the set stops it.
	res = e.mustApply(p.portal)
	if h := e.health(p.bridge.ID); h.Running || h.ConfigHash != "" {
		t.Logf("health of removed bridge: %+v", h)
	}
	eventually(t, 5*time.Second, "bridge stopped", func() error {
		if e.sup.Status("frp/frpc-" + p.bridge.ID).Running {
			return fmt.Errorf("still running")
		}
		return nil
	})
}

// ---------- health checks ----------

func TestE2EActiveHealthCheck(t *testing.T) {
	e := newEnv(t)
	p := newPair(t, "hc", 1, []string{"tcp"}, spec.Tunnel{Type: "tcp", Security: "tls"})
	tport := freePort(t)
	p.bridge.Targets = []spec.Target{{Host: "127.0.0.1", Ports: fmt.Sprint(tport)}}
	p.bridge.Balance = &spec.Balance{Strategy: "failover", Health: &spec.Health{Type: "tcp", IntervalS: 1, TimeoutS: 1, MaxFails: 1}}
	serve := func() net.Listener {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", tport))
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
			}
		}()
		return ln
	}
	ln := serve()
	e.mustApply(p.portal, p.bridge)
	e.waitUp(p.bridge.ID, 10*time.Second)
	eventually(t, 5*time.Second, "traffic", func() error { return tcpRoundTrip(p.pub(0), []byte("x")) })

	// Target dies: frpc withdraws the proxy, the public port closes and the
	// bridge reports the target as not available.
	ln.Close()
	t0 := time.Now()
	eventually(t, 20*time.Second, "public port closed", func() error {
		c, err := net.DialTimeout("tcp", p.pub(0), 500*time.Millisecond)
		if err == nil {
			c.Close()
			return fmt.Errorf("still open")
		}
		return nil
	})
	t.Logf("HEALTH: target down detected, public port withdrawn after %v (interval 1 s, max_fails 1)", time.Since(t0))
	h := e.health(p.bridge.ID)
	if h.Listening {
		t.Fatalf("bridge must not report all proxies up: %+v", h)
	}
	t.Logf("bridge health with a dead target: %+v", h)

	ln = serve()
	defer ln.Close()
	t0 = time.Now()
	eventually(t, 30*time.Second, "traffic after the target is back", func() error { return tcpRoundTrip(p.pub(0), []byte("x")) })
	t.Logf("HEALTH: target back, public port restored after %v", time.Since(t0))
	e.waitUp(p.bridge.ID, 10*time.Second)
}

// ---------- isolation between instances ----------

func TestE2EChangingOnePortalDoesNotTouchAnother(t *testing.T) {
	e := newEnv(t)
	a := newPair(t, "ia", 2, []string{"tcp"}, spec.Tunnel{Type: "tcp", Security: "tls"})
	a.narrow()
	b := newPair(t, "ib", 1, []string{"tcp"}, spec.Tunnel{Type: "tcp", Security: "tls"})
	pa, pb := startTagEcho(t, "A"), startTagEcho(t, "B")
	a.bridge.Targets = []spec.Target{{Host: "127.0.0.1", Ports: fmt.Sprint(pa)}}
	b.bridge.Targets = []spec.Target{{Host: "127.0.0.1", Ports: fmt.Sprint(pb)}}
	e.mustApply(a.portal, a.bridge, b.portal, b.bridge)
	e.waitUp(a.bridge.ID, 10*time.Second)
	e.waitUp(b.bridge.ID, 10*time.Second)
	la := startPinger(t, a.pub(0), "A")
	lb := startPinger(t, b.pub(0), "B")
	la.alive(t, time.Second, "A")

	// Change portal A (a second public port in its allow list).
	a2 := a.portal
	a2.Listen = &spec.Listen{Addr: "127.0.0.1", Ports: fmt.Sprintf("%d-%d", a.pubLo, a.pubLo+1)}
	res := e.mustApply(a2, a.bridge, b.portal, b.bridge)
	t.Logf("apply result: %+v", res)
	if len(res.Disrupted) != 1 || res.Disrupted[0] != a.portal.ID {
		t.Fatalf("only portal A may be disrupted: %+v", res)
	}
	la.broken(t, 5*time.Second, "A's connection")
	lb.alive(t, 3*time.Second, "B's connection while A restarts")
	e.waitUp(a.bridge.ID, 90*time.Second)
	lb.alive(t, time.Second, "B's connection after A recovered")
}

func TestE2EStopCutsConnections(t *testing.T) {
	e := newEnv(t)
	p := newPair(t, "sp", 1, []string{"tcp"}, spec.Tunnel{Type: "tcp", Security: "tls"})
	pa := startTagEcho(t, "A")
	p.bridge.Targets = []spec.Target{{Host: "127.0.0.1", Ports: fmt.Sprint(pa)}}
	e.mustApply(p.portal, p.bridge)
	e.waitUp(p.bridge.ID, 10*time.Second)
	l := startPinger(t, p.pub(0), "A")
	l.alive(t, time.Second, "before stop")
	if err := e.d.Stop(context.Background(), e.rt, p.portal.ID); err != nil {
		t.Fatal(err)
	}
	l.broken(t, 5*time.Second, "connection after Stop")
	if h := e.health(p.portal.ID); h.Running {
		t.Fatalf("stopped portal reports running: %+v", h)
	}
	// Stop with no ids stops everything.
	if err := e.d.Stop(context.Background(), e.rt); err != nil {
		t.Fatal(err)
	}
	if e.sup.Status("frp/frpc-" + p.bridge.ID).Running {
		t.Fatal("bridge still running after Stop()")
	}
}

// ---------- TLS verification ----------

func TestE2ETLSVerification(t *testing.T) {
	e := newEnv(t)
	good := newPKI(t, "127.0.0.1")
	other := newPKI(t, "127.0.0.1")
	dir := t.TempDir()
	_, cert, key := good.write(t, filepath.Join(mkdir(t, dir, "good")))
	wrongCA, _, _ := other.write(t, filepath.Join(mkdir(t, dir, "other")))
	p := newPair(t, "tv", 1, []string{"tcp"}, spec.Tunnel{Type: "tcp", Security: "tls"})
	p.withEcho(t)
	p.portal.Tunnel.Cert = &spec.Cert{Mode: "file", CertFile: cert, KeyFile: key}
	p.bridge.Tunnel.Cert = &spec.Cert{Mode: "file", CertFile: wrongCA}
	e.mustApply(p.portal, p.bridge)
	time.Sleep(4 * time.Second)
	if h := e.health(p.bridge.ID); h.Listening {
		t.Fatalf("bridge trusting another CA registered: %+v", h)
	}
	t.Logf("untrusted certificate: %s", firstLineContaining(e.logOf(p.bridge.ID), "x509"))
	log := e.logOf(p.bridge.ID)
	// frp dials with a lazy TLS conn (golib's tlsAfterHook returns
	// tls.Client without a handshake), so the certificate check runs when
	// yamux writes its first stream header. frpc therefore reports either
	// the x509 error itself or the yamux session teardown it causes
	// ("session shutdown") - which of the two wins is a race. Both mean the
	// untrusted certificate was refused, so accept either, and require the
	// stronger property: the bridge never logged in.
	if !strings.Contains(log, "x509") && !strings.Contains(log, "session shutdown") {
		t.Fatalf("expected a TLS rejection (x509 or session shutdown) in the frpc log:\n%s", log)
	}
	if strings.Contains(log, "login to server success") {
		t.Fatalf("bridge logged in despite an untrusted certificate:\n%s", log)
	}
	// Correct trust anchor: works.
	caGood, _, _ := good.write(t, filepath.Join(mkdir(t, dir, "good2")))
	p.bridge.Tunnel.Cert = &spec.Cert{Mode: "file", CertFile: caGood}
	e.mustApply(p.portal, p.bridge)
	e.waitUp(p.bridge.ID, 30*time.Second)
	eventually(t, 5*time.Second, "traffic", func() error { return tcpRoundTrip(p.pub(0), []byte("v")) })
}

func mkdir(t testing.TB, base, name string) string {
	d := filepath.Join(base, name)
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}
