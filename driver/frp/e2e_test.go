//go:build e2e

// End-to-end tests against the real frps/frpc binaries.
//
// Run on a Linux test machine (the frp release for that platform unpacked in
// $FRP, a directory that holds both `frps` and `frpc`):
//
//	cd <repo> && W1NCRAY_TEST_FRP_DIR=$FRP go test -tags e2e -count=1 -v ./driver/frp/...
//
// Everything runs on loopback, uses random ports and a temp state directory
// and kills all child processes at the end. On Windows use the .exe release
// (the tests add the suffix themselves). Without W1NCRAY_TEST_FRP_DIR every
// test here is skipped. Use -run to select tests; some of them wait for
// frpc's reconnect back-off and take 10-30 s.
package frp

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/spec"
)

type env struct {
	t     testing.TB
	frps  string
	frpc  string
	sup   *testSup
	d     *Driver
	rt    driver.Runtime
	state string
}

func newEnv(t testing.TB) *env {
	dir := frpDir(t)
	e := &env{t: t, frps: filepath.Join(dir, exe("frps")), frpc: filepath.Join(dir, exe("frpc"))}
	for _, b := range []string{e.frps, e.frpc} {
		if _, err := os.Stat(b); err != nil {
			t.Fatalf("missing binary: %v", err)
		}
	}
	e.sup = newTestSup(t)
	e.state = t.TempDir()
	// t.TempDir() is created 0777&^umask (0755 with the usual umask), unlike
	// os.MkdirTemp which uses 0700. The production path tightens the state
	// directory itself (state.Store.Open), so mirror that here: the test
	// below then checks that the driver does not loosen it again.
	if err := os.Chmod(e.state, 0o700); err != nil {
		t.Fatal(err)
	}
	e.d = New()
	e.rt = driver.Runtime{
		Kernel:   driver.Installed{Path: e.frps, Version: "test"},
		StateDir: e.state,
		Sup:      e.sup,
		Log:      testLogger{t},
	}
	t.Cleanup(func() {
		_ = e.d.Stop(context.Background(), e.rt)
		if t.Failed() {
			ents, _ := os.ReadDir(dirLogs(e.rt))
			for _, f := range ents {
				b, _ := os.ReadFile(filepath.Join(dirLogs(e.rt), f.Name()))
				var keep []string
				for _, l := range strings.Split(string(b), "\n") {
					if !strings.Contains(l, "http/middleware.go") {
						keep = append(keep, l)
					}
				}
				s := strings.Join(keep, "\n")
				if len(s) > 3000 {
					s = s[len(s)-3000:]
				}
				t.Logf("---- %s ----\n%s", f.Name(), s)
			}
		}
	})
	return e
}

type testLogger struct{ t testing.TB }

func (l testLogger) Debugf(f string, a ...any) {}
func (l testLogger) Infof(f string, a ...any)  { l.t.Logf("INFO "+f, a...) }
func (l testLogger) Warnf(f string, a ...any)  { l.t.Logf("WARN "+f, a...) }
func (l testLogger) Errorf(f string, a ...any) { l.t.Logf("ERROR "+f, a...) }

func (e *env) rendered(insts ...spec.Instance) []driver.Rendered {
	var out []driver.Rendered
	for _, in := range insts {
		art, err := e.d.Render(in)
		if err != nil {
			e.t.Fatalf("render %s: %v", in.ID, err)
		}
		out = append(out, driver.Rendered{Instance: in, Artifact: art})
	}
	return out
}

func (e *env) apply(insts ...spec.Instance) (driver.ApplyResult, error) {
	e.t.Helper()
	return e.d.Apply(context.Background(), e.rt, e.rendered(insts...))
}

func (e *env) mustApply(insts ...spec.Instance) driver.ApplyResult {
	e.t.Helper()
	res, err := e.apply(insts...)
	if err != nil {
		e.t.Fatalf("apply: %v (failed: %v)", err, res.Failed)
	}
	return res
}

func (e *env) logOf(id string) string {
	b, _ := os.ReadFile(filepath.Join(dirLogs(e.rt), "i-"+id+".log"))
	return string(b)
}

func (e *env) health(id string) driver.InstanceHealth {
	return e.d.Health(context.Background(), e.rt).Instances[id]
}

// pair describes a portal+bridge pair on loopback.
type pair struct {
	ctrl    int
	pubLo   int
	n       int
	portal  spec.Instance
	bridge  spec.Instance
	secret  string
	targets []int // local target ports, one per public port
}

func newPair(t testing.TB, id string, n int, nets []string, tun spec.Tunnel) *pair {
	// One consecutive block for the control port and the public ports: two
	// independent free-range picks can collide, and the driver's validation
	// correctly refuses a public port that equals the control port.
	base := freeRange(t, n+1)
	p := &pair{ctrl: base, pubLo: base + 1, n: n, secret: "e2e-secret-" + id + "-0123456789abcdef"}
	ports := fmt.Sprint(p.pubLo)
	if n > 1 {
		ports = fmt.Sprintf("%d-%d", p.pubLo, p.pubLo+n-1)
	}
	ptun := tun
	ptun.Listen = fmt.Sprintf("127.0.0.1:%d", p.ctrl)
	btun := tun
	btun.Server = fmt.Sprintf("127.0.0.1:%d", p.ctrl)
	btun.Cert = nil
	// Portal and bridge normally live on different machines; here they share
	// one driver, so their instance ids differ.
	p.portal = spec.Instance{
		ID: id + "p", Enabled: true, Engine: spec.EngineFrp, Kind: spec.KindReversePortal,
		Network: nets, Listen: &spec.Listen{Addr: "127.0.0.1", Ports: ports}, Tunnel: &ptun, Secret: p.secret,
	}
	p.bridge = spec.Instance{
		ID: id + "b", Enabled: true, Engine: spec.EngineFrp, Kind: spec.KindReverseBridge,
		Network: nets, Listen: &spec.Listen{Ports: ports}, Tunnel: &btun, Secret: p.secret,
	}
	return p
}

// withEcho starts local echo targets (tcp and/or udp as the pair's network
// says) on consecutive free ports and points the bridge at them.
func (p *pair) withEcho(t testing.TB) {
	nets := p.bridge.Network
	tcpPorts := make([]int, p.n)
	for i := 0; i < p.n; i++ {
		// Reserve a port number free for both protocols and serve both on it.
		port := freePort(t)
		if hasNet(nets, "tcp") {
			ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
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
					go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
				}
			}()
		}
		if hasNet(nets, "udp") {
			pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
			if err != nil {
				t.Fatal(err)
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
		}
		tcpPorts[i] = port
	}
	p.targets = tcpPorts
	// Targets must be one contiguous range: build a PortMap instead.
	pm := map[string]string{}
	for i := 0; i < p.n; i++ {
		pm[fmt.Sprint(p.pubLo+i)] = fmt.Sprintf("127.0.0.1:%d", tcpPorts[i])
	}
	p.bridge.Listen.PortMap = pm
}

func (p *pair) pub(i int) string { return fmt.Sprintf("127.0.0.1:%d", p.pubLo+i) }

// waitUp waits until the bridge reports every proxy running.
func (e *env) waitUp(id string, d time.Duration) time.Duration {
	e.t.Helper()
	return eventually(e.t, d, "bridge "+id+" registered", func() error {
		h := e.health(id)
		if !h.Running || !h.Listening {
			return fmt.Errorf("running=%v listening=%v err=%q", h.Running, h.Listening, h.Err)
		}
		return nil
	})
}

func (e *env) waitBridgeUp(bridgeID string, d time.Duration) time.Duration {
	return e.waitUp(bridgeID, d)
}

// narrow restricts both sides of the pair to the first public port while the
// rest of the range stays free for a later widening.
func (p *pair) narrow() {
	p.portal.Listen.Ports = fmt.Sprint(p.pubLo)
	p.bridge.Listen.Ports = fmt.Sprint(p.pubLo)
	p.bridge.Listen.PortMap = nil
	p.n = 1
}

// ---------- tests ----------

func TestE2ETunnelMatrix(t *testing.T) {
	frpDir(t)
	certs := newPKI(t, "127.0.0.1")
	cases := []struct {
		name string
		tun  spec.Tunnel
		ca   bool // portal uses the generated cert and the bridge verifies it
	}{
		{"tcp-none", spec.Tunnel{Type: "tcp", Security: "none"}, false},
		{"tcp-tls-unverified", spec.Tunnel{Type: "tcp", Security: "tls"}, false},
		{"tcp-tls-verified", spec.Tunnel{Type: "tcp", Security: "tls"}, true},
		{"tls-type", spec.Tunnel{Type: "tls", Security: "tls"}, true},
		{"ws-none", spec.Tunnel{Type: "ws", Security: "none"}, false},
		{"ws-tls", spec.Tunnel{Type: "ws", Security: "tls"}, true},
		{"kcp-none", spec.Tunnel{Type: "kcp", Security: "none"}, false},
		{"kcp-tls", spec.Tunnel{Type: "kcp", Security: "tls"}, true},
		{"quic", spec.Tunnel{Type: "quic", Security: "tls"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			p := newPair(t, "m", 2, []string{"tcp", "udp"}, c.tun)
			p.withEcho(t)
			if c.ca {
				dir := t.TempDir()
				ca, cert, key := certs.write(t, dir)
				p.portal.Tunnel.Cert = &spec.Cert{Mode: "file", CertFile: cert, KeyFile: key}
				p.bridge.Tunnel.Cert = &spec.Cert{Mode: "file", CertFile: ca}
			}
			res := e.mustApply(p.portal, p.bridge)
			if len(res.Running) != 2 {
				t.Fatalf("running = %v", res.Running)
			}
			up := e.waitUp(p.bridge.ID, 20*time.Second)
			t.Logf("bridge registered after %v", up)
			for i := 0; i < p.n; i++ {
				payload := []byte(fmt.Sprintf("hello-%s-%d-%s", c.name, i, strings.Repeat("x", 100*i)))
				if err := tcpRoundTrip(p.pub(i), payload); err != nil {
					t.Fatalf("tcp via %s: %v", p.pub(i), err)
				}
				if err := udpRoundTrip(p.pub(i), payload); err != nil {
					t.Fatalf("udp via %s: %v", p.pub(i), err)
				}
			}
			if h := e.health(p.portal.ID); !h.Running || !h.Listening {
				t.Fatalf("portal health %+v", h)
			}
		})
	}
}
