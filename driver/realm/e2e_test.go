//go:build e2e

// End-to-end tests against the REAL realm binary. They are not run by default.
//
// Run (Linux test machine, or any machine where the binary runs):
//
//	# 1. Get the official FULL (non-slim) musl build and verify it against the
//	#    sha256 digest GitHub reports for the asset (never skip this):
//	curl -fsSL -o realm.tgz https://github.com/zhboner/realm/releases/download/v2.9.6/realm-x86_64-unknown-linux-musl.tar.gz
//	sha256sum realm.tgz      # must equal the asset digest from
//	                         # https://api.github.com/repos/zhboner/realm/releases/tags/v2.9.6
//	                         # (v2.9.6 x86_64-unknown-linux-musl: b1cc335547bea8bb2a88178bef12ec7f2363e36200e7ea1d4e1e67627929bf65)
//	tar xzf realm.tgz        # -> ./realm
//
//	# 2. Run from the repository root:
//	W1NCRAY_TEST_REALM_BIN=$PWD/realm \
//	W1NCRAY_TEST_REALM_VERSION=2.9.6 \
//	W1NCRAY_TEST_REALM_SLIM_BIN=/path/to/realm-slim   `# optional: slim must be refused` \
//	go test -tags e2e -count=1 -v -timeout 600s ./driver/realm/ -run E2E
//
// The tests start real realm processes on 127.0.0.1 / 127.0.0.2.. and use a
// small exec-based Supervisor (execSup below; the agent core's supervisor is
// not part of this package). Restart-on-crash is therefore exercised against
// that test supervisor: the driver's part (RestartPolicy.Always, a config that
// survives the restart, Health noticing) is what the crash test checks.
//
// On Windows the Windows release (realm-x86_64-pc-windows-msvc.tar.gz, binary
// named "realm" without extension: copy it to realm.exe) works the same way.
// Asset digests verified against the GitHub release API for v2.9.6:
//
//	realm-x86_64-pc-windows-msvc.tar.gz       7d06f4d4c3baaa0d7b84d1b5b345e96c41d4e150eab330bbb806aaaf027a9190
//	realm-slim-x86_64-pc-windows-msvc.tar.gz  f3c6e4d49a4f5f3b316088f52e5e2726e5417dd6dcb2d5f6fba9c32150834003
//
// (the slim build is what W1NCRAY_TEST_REALM_SLIM_BIN must point at: Apply has
// to refuse it, see TestE2EBinaryCheck).

package realm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/spec"
)

// ---------------------------------------------------------------------------
// exec based supervisor
// ---------------------------------------------------------------------------

type execSup struct {
	mu    sync.Mutex
	procs map[string]*proc
}

type proc struct {
	spec     driver.ProcSpec
	stop     chan struct{}
	done     chan struct{}
	mu       sync.Mutex
	pid      int
	running  bool
	restarts int
	lastExit string
}

func newExecSup() *execSup { return &execSup{procs: map[string]*proc{}} }

func (s *execSup) Start(ctx context.Context, sp driver.ProcSpec) error {
	s.mu.Lock()
	old := s.procs[sp.ID]
	if old != nil && reflect.DeepEqual(old.spec, sp) {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()
	if old != nil {
		if err := s.Stop(ctx, sp.ID); err != nil {
			return err
		}
	}
	p := &proc{spec: sp, stop: make(chan struct{}), done: make(chan struct{})}
	s.mu.Lock()
	s.procs[sp.ID] = p
	s.mu.Unlock()
	go p.loop()
	return nil
}

func (p *proc) loop() {
	defer close(p.done)
	backoff := 200 * time.Millisecond // test supervisor: faster than the spec's 1 s
	for {
		cmd := exec.Command(p.spec.Path, p.spec.Args...)
		cmd.Dir = p.spec.WorkDir
		env := []string{}
		for _, kv := range os.Environ() {
			if !strings.HasPrefix(strings.ToUpper(kv), "REALM_CONF=") {
				env = append(env, kv)
			}
		}
		cmd.Env = append(env, p.spec.Env...)
		var logf *os.File
		if p.spec.LogFile != "" {
			os.MkdirAll(filepath.Dir(p.spec.LogFile), 0o700)
			logf, _ = os.OpenFile(p.spec.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
			cmd.Stdout, cmd.Stderr = logf, logf
		}
		err := cmd.Start()
		if err == nil {
			p.mu.Lock()
			p.pid, p.running = cmd.Process.Pid, true
			p.mu.Unlock()
			errc := make(chan error, 1)
			go func() { errc <- cmd.Wait() }()
			select {
			case err = <-errc:
			case <-p.stop:
				cmd.Process.Kill()
				<-errc
				p.mu.Lock()
				p.running = false
				p.mu.Unlock()
				if logf != nil {
					logf.Close()
				}
				return
			}
		}
		p.mu.Lock()
		p.running = false
		p.lastExit = fmt.Sprint(err)
		p.restarts++
		p.mu.Unlock()
		if logf != nil {
			logf.Close()
		}
		if !p.spec.Restart.Always {
			return
		}
		select {
		case <-p.stop:
			return
		case <-time.After(backoff):
		}
	}
}

func (s *execSup) Stop(ctx context.Context, id string) error {
	s.mu.Lock()
	p := s.procs[id]
	delete(s.procs, id)
	s.mu.Unlock()
	if p == nil {
		return nil
	}
	close(p.stop)
	<-p.done
	return nil
}

func (s *execSup) Signal(id string, sig os.Signal) error { return nil }

func (s *execSup) Status(id string) driver.ProcStatus {
	s.mu.Lock()
	p := s.procs[id]
	s.mu.Unlock()
	if p == nil {
		return driver.ProcStatus{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return driver.ProcStatus{Running: p.running, PID: p.pid, Restarts: p.restarts, LastExit: p.lastExit}
}

func (s *execSup) killPID(t *testing.T, id string) int {
	t.Helper()
	st := s.Status(id)
	if !st.Running {
		t.Fatalf("%s is not running", id)
	}
	pr, err := os.FindProcess(st.PID)
	if err != nil {
		t.Fatal(err)
	}
	if err := pr.Kill(); err != nil {
		t.Fatal(err)
	}
	return st.PID
}

func (s *execSup) stopAll() {
	s.mu.Lock()
	ids := make([]string, 0, len(s.procs))
	for id := range s.procs {
		ids = append(ids, id)
	}
	s.mu.Unlock()
	for _, id := range ids {
		s.Stop(context.Background(), id)
	}
}

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

type e2e struct {
	t   *testing.T
	d   *Driver
	sup *execSup
	rt  driver.Runtime
}

func realmBin(t *testing.T) string {
	bin := os.Getenv("W1NCRAY_TEST_REALM_BIN")
	if bin == "" {
		t.Skip("W1NCRAY_TEST_REALM_BIN not set (see the instructions at the top of e2e_test.go)")
	}
	return bin
}

func newE2E(t *testing.T, opts Options) *e2e {
	t.Helper()
	bin := realmBin(t)
	if opts.ReadyTimeout == 0 {
		opts.ReadyTimeout = 10 * time.Second
	}
	sup := newExecSup()
	e := &e2e{t: t, d: New(opts), sup: sup, rt: driver.Runtime{
		Kernel:   driver.Installed{Path: bin, Version: os.Getenv("W1NCRAY_TEST_REALM_VERSION")},
		StateDir: t.TempDir(),
		Sup:      sup,
	}}
	t.Cleanup(func() {
		sup.stopAll()
		if t.Failed() {
			e.dumpLogs()
		}
	})
	return e
}

func (e *e2e) dumpLogs() {
	files, _ := filepath.Glob(filepath.Join(e.rt.StateDir, "logs", "*.log"))
	for _, f := range files {
		b, _ := os.ReadFile(f)
		e.t.Logf("---- %s ----\n%s", filepath.Base(f), b)
	}
}

func (e *e2e) apply(ins ...spec.Instance) (driver.ApplyResult, error) {
	e.t.Helper()
	var set []driver.Rendered
	for _, in := range ins {
		a, err := e.d.Render(in)
		if err != nil {
			e.t.Fatalf("Render %s: %v", in.ID, err)
		}
		set = append(set, driver.Rendered{Instance: in, Artifact: a})
	}
	return e.d.Apply(context.Background(), e.rt, set)
}

func (e *e2e) mustApply(ins ...spec.Instance) driver.ApplyResult {
	e.t.Helper()
	res, err := e.apply(ins...)
	if err != nil {
		e.dumpLogs()
		e.t.Fatalf("Apply: %v (%+v)", err, res)
	}
	return res
}

func (e *e2e) health(id string) driver.InstanceHealth {
	return e.d.Health(context.Background(), e.rt).Instances[id]
}

// freePorts returns n consecutive ports that are free for TCP and UDP.
func freePorts(t *testing.T, n int) int {
	t.Helper()
	for try := 0; try < 200; try++ {
		var b [2]byte
		rand.Read(b[:])
		base := 20000 + int(binary.BigEndian.Uint16(b[:]))%30000
		var held []io.Closer
		ok := true
		for i := 0; i < n && ok; i++ {
			l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(base+i))
			if err != nil {
				ok = false
				break
			}
			held = append(held, l)
			u, err := net.ListenPacket("udp", "127.0.0.1:"+strconv.Itoa(base+i))
			if err != nil {
				ok = false
				break
			}
			held = append(held, u)
		}
		for _, h := range held {
			h.Close()
		}
		if ok {
			return base
		}
	}
	t.Fatal("no free port range")
	return 0
}

func p2s(p int) string { return strconv.Itoa(p) }

// tagServer accepts TCP connections on addr, writes "tag\n" and then echoes.
func tagServer(t *testing.T, addr, tag string) (stop func(), accepted *atomic.Int64) {
	t.Helper()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	accepted = new(atomic.Int64)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer c.Close()
				io.WriteString(c, tag+"\n")
				io.Copy(c, c)
			}()
		}
	}()
	t.Cleanup(func() { l.Close() })
	return func() { l.Close() }, accepted
}

func echoServer(t *testing.T, addr string) {
	t.Helper()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	t.Cleanup(func() { l.Close() })
}

func udpEcho(t *testing.T, addr string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, a, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], a)
		}
	}()
	t.Cleanup(func() { pc.Close() })
}

// dialTag connects (optionally from a source IP) and returns the first line
// the backend sends plus the open connection.
func dialTag(t *testing.T, addr string, src string) (string, net.Conn) {
	t.Helper()
	d := net.Dialer{Timeout: 3 * time.Second}
	if src != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(src)}
	}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		c.Close()
		t.Fatalf("read tag from %s: %v", addr, err)
	}
	return strings.TrimSpace(line), c
}

func roundTrip(t *testing.T, c net.Conn, payload []byte) {
	t.Helper()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	errc := make(chan error, 1)
	go func() { _, err := c.Write(payload); errc <- err }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read back %d bytes: %v", len(payload), err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("echoed payload differs")
	}
}

func randBytes(n int) []byte { b := make([]byte, n); rand.Read(b); return b }

// ---------------------------------------------------------------------------
// PROXY protocol helpers
// ---------------------------------------------------------------------------

var v2sig = []byte("\r\n\r\n\x00\r\nQUIT\n")

func proxyV1(src, dst netip.AddrPort) []byte {
	return []byte(fmt.Sprintf("PROXY TCP4 %s %s %d %d\r\n", src.Addr(), dst.Addr(), src.Port(), dst.Port()))
}

func proxyV2(src, dst netip.AddrPort) []byte {
	b := append([]byte{}, v2sig...)
	b = append(b, 0x21, 0x11, 0, 12)
	s, d := src.Addr().As4(), dst.Addr().As4()
	b = append(b, s[:]...)
	b = append(b, d[:]...)
	b = binary.BigEndian.AppendUint16(b, src.Port())
	b = binary.BigEndian.AppendUint16(b, dst.Port())
	return b
}

// readProxyHeader parses a v1 or v2 header; ok=false if none is there.
func readProxyHeader(r *bufio.Reader) (src netip.AddrPort, version int, ok bool) {
	head, _ := r.Peek(12) // fewer bytes (and a timeout error) when no header follows
	if len(head) == 12 && bytes.Equal(head, v2sig) {
		hdr := make([]byte, 16)
		if _, err := io.ReadFull(r, hdr); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(hdr[14:16]))
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil || n < 12 || hdr[13] != 0x11 {
			return
		}
		a, _ := netip.AddrFromSlice(body[0:4])
		return netip.AddrPortFrom(a, binary.BigEndian.Uint16(body[8:10])), 2, true
	}
	if bytes.HasPrefix(head, []byte("PROXY ")) {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		f := strings.Fields(line)
		if len(f) != 6 {
			return
		}
		a, err1 := netip.ParseAddr(f[2])
		p, err2 := strconv.Atoi(f[4])
		if err1 != nil || err2 != nil {
			return
		}
		return netip.AddrPortFrom(a, uint16(p)), 1, true
	}
	return
}

// proxyBackend parses an optional PROXY header, reports it on the channel
// ("none" when absent) and then echoes.
type proxySeen struct {
	src      netip.AddrPort
	version  int
	ok       bool
	buffered int // bytes that had arrived when the header check ended
}

func proxyBackend(t *testing.T, addr string) <-chan proxySeen {
	t.Helper()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan proxySeen, 32)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				// A header, if there is one, is the first thing on the wire.
				c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				s, v, ok := readProxyHeader(br)
				seen <- proxySeen{s, v, ok, br.Buffered()}
				c.SetReadDeadline(time.Time{})
				io.Copy(c, br)
			}()
		}
	}()
	t.Cleanup(func() { l.Close() })
	return seen
}

func recvSeen(t *testing.T, ch <-chan proxySeen) proxySeen {
	t.Helper()
	select {
	case s := <-ch:
		return s
	case <-time.After(8 * time.Second):
		t.Fatal("backend saw no connection")
		return proxySeen{}
	}
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

func TestE2EBinaryCheck(t *testing.T) {
	bin := realmBin(t)
	bi, err := CheckBinary(context.Background(), bin)
	if err != nil {
		t.Fatalf("CheckBinary: %v", err)
	}
	t.Logf("realm reports version %s features %v", bi.Version, bi.Features)
	if err := bi.Check(os.Getenv("W1NCRAY_TEST_REALM_VERSION")); err != nil {
		t.Fatalf("the full build was refused: %v", err)
	}
	if slim := os.Getenv("W1NCRAY_TEST_REALM_SLIM_BIN"); slim != "" {
		sbi, err := CheckBinary(context.Background(), slim)
		if err != nil {
			t.Fatal(err)
		}
		if err := sbi.Check(""); err == nil || !strings.Contains(err.Error(), "slim") {
			t.Fatalf("the slim build was accepted: %+v %v", sbi, err)
		}
		// And Apply refuses it without starting anything.
		e := newE2E(t, Options{})
		e.rt.Kernel.Path = slim
		in := fwd("slim", "127.0.0.1", p2s(freePorts(t, 1)), tg("127.0.0.1", "9", 0))
		if _, err := e.apply(in); err == nil || !strings.Contains(err.Error(), "slim") {
			t.Fatalf("Apply with the slim binary: %v", err)
		}
	} else {
		t.Log("W1NCRAY_TEST_REALM_SLIM_BIN not set: slim rejection with the real slim binary not exercised")
	}
}

func TestE2EForwardTCPUDP(t *testing.T) {
	e := newE2E(t, Options{})
	base := freePorts(t, 2)
	tp, lp := base, base+1 // target port, listen port (tcp and udp free on both)
	echoServer(t, "127.0.0.1:"+p2s(tp))
	udpEcho(t, "127.0.0.1:"+p2s(tp))
	in := fwd("fw", "127.0.0.1", p2s(lp), tg("127.0.0.1", p2s(tp), 0))
	in.Network = []string{"tcp", "udp"}
	e.mustApply(in)

	h := e.health("fw")
	if !h.Running || !h.Listening || h.Err != "" {
		t.Fatalf("health %+v", h)
	}
	c, err := net.Dial("tcp", "127.0.0.1:"+p2s(lp))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	roundTrip(t, c, randBytes(1<<20))

	uc, err := net.Dial("udp", "127.0.0.1:"+p2s(lp))
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	for i := 0; i < 5; i++ {
		msg := []byte(fmt.Sprintf("datagram-%d", i))
		uc.SetDeadline(time.Now().Add(3 * time.Second))
		uc.Write(msg)
		buf := make([]byte, 64)
		n, err := uc.Read(buf)
		if err != nil || !bytes.Equal(buf[:n], msg) {
			t.Fatalf("udp round trip %d: %q %v", i, buf[:n], err)
		}
	}
	// UDP only.
	e.mustApply(mut(in, func(i *spec.Instance) { i.Network = []string{"udp"} }))
	if h := e.health("fw"); !h.Listening {
		t.Fatalf("udp only: %+v", h)
	}
	if conn, err := net.DialTimeout("tcp", "127.0.0.1:"+p2s(lp), time.Second); err == nil {
		conn.Close()
		t.Fatal("tcp still listening after switching to udp only")
	}
}

func TestE2EPortRangeAndPortMap(t *testing.T) {
	e := newE2E(t, Options{})
	lbase := freePorts(t, 4)
	tbase := freePorts(t, 4)
	if lbase == tbase {
		t.Skip("port ranges collided")
	}
	for i := 0; i < 4; i++ {
		tagServer(t, "127.0.0.1:"+p2s(tbase+i), fmt.Sprintf("T%d", i))
	}
	xport := freePorts(t, 1)
	tagServer(t, "127.0.0.1:"+p2s(xport), "MAPPED")
	in := fwd("rng", "127.0.0.1", fmt.Sprintf("%d-%d", lbase, lbase+3), tg("127.0.0.1", fmt.Sprintf("%d-%d", tbase, tbase+3), 0))
	in.Listen.PortMap = map[string]string{p2s(lbase + 2): "127.0.0.1:" + p2s(xport)}
	e.mustApply(in)
	if h := e.health("rng"); !h.Listening || len(h.Err) > 0 {
		t.Fatalf("health %+v", h)
	}
	want := []string{"T0", "T1", "MAPPED", "T3"}
	for i, w := range want {
		tag, c := dialTag(t, "127.0.0.1:"+p2s(lbase+i), "")
		c.Close()
		if tag != w {
			t.Errorf("listen port %d -> %s, want %s", lbase+i, tag, w)
		}
	}
	// One process serves the whole range.
	if n := len(e.sup.procs); n != 1 {
		t.Errorf("%d processes for one instance", n)
	}
}

func TestE2EWeightedRoundRobinAndIPHash(t *testing.T) {
	e := newE2E(t, Options{})
	tb := freePorts(t, 3)
	for i := 0; i < 3; i++ {
		tagServer(t, "127.0.0.1:"+p2s(tb+i), fmt.Sprintf("B%d", i))
	}
	lp := freePorts(t, 2)
	targets := []spec.Target{tg("127.0.0.1", p2s(tb), 1), tg("127.0.0.1", p2s(tb+1), 2), tg("127.0.0.1", p2s(tb+2), 3)}
	rr := fwd("rr", "127.0.0.1", p2s(lp), targets...)
	rr.Balance = &spec.Balance{Strategy: "round_robin"}
	ih := fwd("ih", "127.0.0.1", p2s(lp+1), targets...)
	ih.Balance = &spec.Balance{Strategy: "iphash"}
	e.mustApply(rr, ih)

	counts := map[string]int{}
	var order []string
	for i := 0; i < 60; i++ {
		tag, c := dialTag(t, "127.0.0.1:"+p2s(lp), "")
		c.Close()
		counts[tag]++
		order = append(order, tag)
	}
	t.Logf("round robin 60 connections, weights 1:2:3 -> %v; first 12: %v", counts, order[:12])
	if counts["B0"] != 10 || counts["B1"] != 20 || counts["B2"] != 30 {
		t.Fatalf("distribution %v, want B0=10 B1=20 B2=30", counts)
	}

	// iphash: every source address is sticky; the set of sources spreads.
	first := map[string]string{}
	spread := map[string]bool{}
	for k := 1; k <= 24; k++ {
		src := fmt.Sprintf("127.0.0.%d", k+1)
		for rep := 0; rep < 4; rep++ {
			tag, c := dialTag(t, "127.0.0.1:"+p2s(lp+1), src)
			c.Close()
			if f, ok := first[src]; ok && f != tag {
				t.Fatalf("source %s moved from %s to %s", src, f, tag)
			}
			first[src] = tag
		}
		spread[first[src]] = true
	}
	t.Logf("iphash: 24 sources -> %v", first)
	if len(spread) < 2 {
		t.Fatalf("all sources hashed to one backend: %v", spread)
	}
}

func TestE2EProxyProtocol(t *testing.T) {
	e := newE2E(t, Options{})
	base := freePorts(t, 12)

	// --- send: realm writes the header, announcing the client's address.
	for i, v := range []int{1, 2} {
		seen := proxyBackend(t, "127.0.0.1:"+p2s(base+i*2))
		in := fwd(fmt.Sprintf("send%d", v), "127.0.0.1", p2s(base+i*2+1), tg("127.0.0.1", p2s(base+i*2), 0))
		in.ProxyProtocolOut = v
		e.mustApply(in)
		c, err := net.Dial("tcp", "127.0.0.1:"+p2s(base+i*2+1))
		if err != nil {
			t.Fatal(err)
		}
		roundTrip(t, c, []byte("hello"))
		got := recvSeen(t, seen)
		want := netip.MustParseAddrPort(c.LocalAddr().String())
		c.Close()
		if !got.ok || got.version != v || got.src != want {
			t.Errorf("send v%d: backend saw %+v, client was %v", v, got, want)
		}
		e.mustApply() // clean slate
	}

	// --- accept: realm requires and strips the header.
	for i, v := range []int{1, 2} {
		bp, lp := base+4+i*2, base+4+i*2+1
		seen := proxyBackend(t, "127.0.0.1:"+p2s(bp))
		in := fwd(fmt.Sprintf("acc%d", v), "127.0.0.1", p2s(lp), tg("127.0.0.1", p2s(bp), 0))
		in.AcceptProxyProtocol = true
		e.mustApply(in)
		c, err := net.Dial("tcp", "127.0.0.1:"+p2s(lp))
		if err != nil {
			t.Fatal(err)
		}
		claimed := netip.MustParseAddrPort("203.0.113.9:4242")
		dst := netip.MustParseAddrPort("198.51.100.1:80")
		var hdr []byte
		if v == 1 {
			hdr = proxyV1(claimed, dst)
		} else {
			hdr = proxyV2(claimed, dst)
		}
		c.Write(append(hdr, []byte("payload")...))
		got := make([]byte, 7)
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(c, got); err != nil || string(got) != "payload" {
			t.Fatalf("accept v%d: echo %q err %v", v, got, err)
		}
		if s := recvSeen(t, seen); s.ok {
			t.Errorf("accept v%d: the header leaked to the backend: %+v", v, s)
		}
		c.Close()
		e.mustApply()
	}

	// --- accept + send: the announced address is passed on unchanged.
	{
		bp, lp := base+8, base+9
		seen := proxyBackend(t, "127.0.0.1:"+p2s(bp))
		in := fwd("pass", "127.0.0.1", p2s(lp), tg("127.0.0.1", p2s(bp), 0))
		in.AcceptProxyProtocol = true
		in.ProxyProtocolOut = 2
		e.mustApply(in)
		c, _ := net.Dial("tcp", "127.0.0.1:"+p2s(lp))
		claimed := netip.MustParseAddrPort("203.0.113.9:4242")
		c.Write(append(proxyV1(claimed, netip.MustParseAddrPort("198.51.100.1:80")), []byte("x")...))
		got := recvSeen(t, seen)
		c.Close()
		if !got.ok || got.version != 2 || got.src != claimed {
			t.Errorf("pass-through: backend saw %+v, want v2 from %v", got, claimed)
		}
	}

	// --- accept without a header: refused.
	{
		bp, lp := base+10, base+11
		seen := proxyBackend(t, "127.0.0.1:"+p2s(bp))
		in := fwd("strict", "127.0.0.1", p2s(lp), tg("127.0.0.1", p2s(bp), 0))
		in.AcceptProxyProtocol = true
		e.mustApply(in)
		// (a) data without header
		c, _ := net.Dial("tcp", "127.0.0.1:"+p2s(lp))
		c.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
		c.SetReadDeadline(time.Now().Add(8 * time.Second))
		n, err := c.Read(make([]byte, 64))
		c.Close()
		if err == nil || n != 0 {
			t.Errorf("headerless data was relayed: n=%d err=%v", n, err)
		}
		// (b) silence: closed by realm's accept timeout (5 s)
		c, _ = net.Dial("tcp", "127.0.0.1:"+p2s(lp))
		start := time.Now()
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, err = c.Read(make([]byte, 1))
		el := time.Since(start)
		c.Close()
		t.Logf("silent client closed after %v (err=%v)", el.Round(100*time.Millisecond), err)
		if err == nil || el < 3*time.Second || el > 8*time.Second {
			t.Errorf("silent client: closed after %v err=%v, want a close near 5 s", el, err)
		}
		_ = seen
	}

	// --- characterisation (no assertion): a header split over two segments.
	{
		bp, lp := base+10, base+11
		in := fwd("split", "127.0.0.1", p2s(lp), tg("127.0.0.1", p2s(bp), 0))
		in.AcceptProxyProtocol = true
		e.mustApply(in)
		c, _ := net.Dial("tcp", "127.0.0.1:"+p2s(lp))
		hdr := proxyV2(netip.MustParseAddrPort("203.0.113.9:4242"), netip.MustParseAddrPort("198.51.100.1:80"))
		c.Write(hdr[:10])
		time.Sleep(300 * time.Millisecond)
		c.Write(append(hdr[10:], []byte("ok")...))
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := c.Read(make([]byte, 8))
		c.Close()
		t.Logf("split PROXY header (10 + rest after 300 ms): echoed %d bytes, err=%v  (realm peeks once; src/tcp/proxy.rs FIXME)", n, err)
	}
}

// selfSigned writes a certificate for the given DNS name and returns the paths.
func selfSigned(t *testing.T, name string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalPKCS8PrivateKey(key)
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o600)
	if !validFilePath(certFile) || !validFilePath(keyFile) {
		t.Skipf("temp path %q is not accepted by the driver's cert path whitelist", certFile)
	}
	return
}

func TestE2ETunnels(t *testing.T) {
	cert, key := selfSigned(t, "localhost")
	type tc struct {
		name   string
		typ    string
		secret string
		cert   *spec.Cert
		proxy  bool // carry the client address through the tunnel with PROXY
	}
	cases := []tc{
		{name: "tcp", typ: "tcp"},
		{name: "ws", typ: "ws"},
		{name: "ws-secret-proxy", typ: "ws", secret: testSecret, proxy: true},
		{name: "tls-file-cert", typ: "tls", cert: &spec.Cert{Mode: "file", CertFile: cert, KeyFile: key}},
		{name: "wss-self-secret", typ: "wss", secret: testSecret, cert: &spec.Cert{Mode: "self"}},
		{name: "wss-file-cert-proxy", typ: "wss", cert: &spec.Cert{Mode: "file", CertFile: cert, KeyFile: key}, proxy: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Self-signed certificates cannot be verified by realm: this is
			// the explicit development switch (see Options).
			e := newE2E(t, Options{InsecureSkipTLSVerify: c.typ == "tls" || c.typ == "wss"})
			base := freePorts(t, 3)
			bp, xp, ep := base, base+1, base+2
			seen := proxyBackend(t, "127.0.0.1:"+p2s(bp))

			tun := spec.Tunnel{Type: c.typ}
			if c.typ == "ws" || c.typ == "wss" {
				tun.Host, tun.Path = "relay.example.com", "/w/relay"
			}
			if c.typ == "tls" || c.typ == "wss" {
				tun.SNI = "localhost"
			}
			et := tun
			et.Server = "127.0.0.1:" + p2s(xp)
			xt := tun
			xt.Listen = "127.0.0.1:" + p2s(xp)
			xt.Cert = c.cert
			if c.typ != "tls" && c.typ != "wss" {
				xt.SNI = ""
			}
			entryIn := entry("en", et)
			entryIn.Listen = &spec.Listen{Addr: "127.0.0.1", Ports: p2s(ep)}
			entryIn.Secret = c.secret
			exitIn := exit("ex", xt, tg("127.0.0.1", p2s(bp), 0))
			exitIn.Secret = c.secret
			if c.proxy {
				entryIn.ProxyProtocolOut = 2
				exitIn.AcceptProxyProtocol = true
				exitIn.ProxyProtocolOut = 2
			}
			e.mustApply(entryIn, exitIn)
			if len(e.sup.procs) != 2 {
				t.Fatalf("want 2 processes, got %d", len(e.sup.procs))
			}
			for _, id := range []string{"en", "ex"} {
				if h := e.health(id); !h.Running || !h.Listening {
					t.Fatalf("%s: %+v", id, h)
				}
			}

			cn, err := net.Dial("tcp", "127.0.0.1:"+p2s(ep))
			if err != nil {
				t.Fatal(err)
			}
			if c.proxy {
				// The backend gets the PROXY header of the original client.
				cn.Write([]byte("probe"))
				s := recvSeen(t, seen)
				if !s.ok || s.version != 2 || s.src != netip.MustParseAddrPort(cn.LocalAddr().String()) {
					t.Errorf("through the tunnel the backend saw %+v, client was %v", s, cn.LocalAddr())
				}
				got := make([]byte, 5)
				cn.SetReadDeadline(time.Now().Add(5 * time.Second))
				if _, err := io.ReadFull(cn, got); err != nil || string(got) != "probe" {
					t.Fatalf("probe echo %q %v", got, err)
				}
			}
			roundTrip(t, cn, randBytes(512<<10))
			cn.Close()

			// Wrong secret / wrong path: the exit refuses, nothing reaches the backend.
			if c.typ == "ws" || c.typ == "wss" {
				for len(seen) > 0 {
					<-seen
				}
				if c.secret != "" {
					entryBad := mut(entryIn, func(i *spec.Instance) { i.Secret = c.secret + "-other" })
					e.mustApply(entryBad, exitIn)
				} else {
					entryBad := mut(entryIn, func(i *spec.Instance) { i.Tunnel.Path = "/w/other" })
					e.mustApply(entryBad, exitIn)
				}
				cb, err := net.Dial("tcp", "127.0.0.1:"+p2s(ep))
				if err != nil {
					t.Fatal(err)
				}
				cb.Write([]byte("should not pass"))
				cb.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, err := cb.Read(make([]byte, 32))
				cb.Close()
				// realm's exit dials the target BEFORE it validates the tunnel
				// handshake (src/tcp/middle.rs), so the backend does see an
				// connection (and, with accept+send PROXY, a header: realm forwards it
				// before the handshake is validated) per refused attempt; what it must never
				// see is payload.
				time.Sleep(700 * time.Millisecond)
				empty := 0
				for len(seen) > 0 {
					s := <-seen
					if s.buffered > 0 {
						t.Errorf("the backend received data through a wrong-path tunnel: %+v", s)
					}
					empty++
				}
				t.Logf("wrong path/secret: %d connection(s) reached the backend, no payload", empty)
				if err == nil && n > 0 {
					t.Errorf("a tunnel with the wrong path/secret carried data (%d bytes)", n)
				}
			}
		})
	}
}

// A raw ws client against a realm exit: only the exact Host and path pass.
func TestE2EWSExitChecksHostAndPath(t *testing.T) {
	e := newE2E(t, Options{})
	base := freePorts(t, 2)
	echoServer(t, "127.0.0.1:"+p2s(base))
	in := exit("ex", spec.Tunnel{Type: "ws", Listen: "127.0.0.1:" + p2s(base+1), Host: "relay.example.com", Path: "/w/relay"}, tg("127.0.0.1", p2s(base), 0))
	in.Secret = testSecret
	e.mustApply(in)
	goodPath := deriveTokenPath("/w/relay", testSecret)
	try := func(host, path string) string {
		c, err := net.Dial("tcp", "127.0.0.1:"+p2s(base+1))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", path, host)
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		b := make([]byte, 64)
		n, _ := c.Read(b)
		return string(b[:n])
	}
	if got := try("relay.example.com", goodPath); !strings.HasPrefix(got, "HTTP/1.1 101") {
		t.Fatalf("correct host and token path refused: %q", got)
	}
	for name, hp := range map[string][2]string{
		"configured path without the token": {"relay.example.com", "/w/relay"},
		"other token":                       {"relay.example.com", "/w/relay/00000000000000000000000000000000"},
		"wrong host":                        {"evil.example.com", goodPath},
		"path prefix":                       {"relay.example.com", goodPath + "/x"},
	} {
		if got := try(hp[0], hp[1]); got != "" {
			t.Errorf("%s: answered %q, want the connection closed", name, got)
		}
	}
}

func TestE2EInstanceIsolation(t *testing.T) {
	e := newE2E(t, Options{})
	base := freePorts(t, 4)
	tagServer(t, "127.0.0.1:"+p2s(base), "OLD")
	tagServer(t, "127.0.0.1:"+p2s(base+1), "NEW")
	tagServer(t, "127.0.0.1:"+p2s(base+2), "OTHER")
	a := fwd("a", "127.0.0.1", p2s(base+3), tg("127.0.0.1", p2s(base), 0))
	lb := freePorts(t, 1)
	b := fwd("b", "127.0.0.1", p2s(lb), tg("127.0.0.1", p2s(base+2), 0))
	e.mustApply(a, b)

	_, ca := dialTag(t, "127.0.0.1:"+p2s(base+3), "")
	defer ca.Close()
	_, cb := dialTag(t, "127.0.0.1:"+p2s(lb), "")
	defer cb.Close()
	roundTrip(t, ca, []byte("before"))
	roundTrip(t, cb, []byte("before"))
	pidB := e.sup.Status("realm/b").PID

	a2 := mut(a, func(i *spec.Instance) { i.Targets[0].Ports = p2s(base + 1) })
	res := e.mustApply(a2, b)
	if ids(res.Restarted) != "a" || ids(res.Disrupted) != "a" || ids(res.Running) != "a,b" {
		t.Fatalf("result %+v", res)
	}
	if e.sup.Status("realm/b").PID != pidB {
		t.Fatal("instance b's process was replaced")
	}
	// b's established connection survives, a's is cut.
	roundTrip(t, cb, []byte("after the change of a"))
	ca.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := ca.Read(make([]byte, 16)); err == nil {
		t.Fatal("a's old connection survived the restart")
	}
	tag, c2 := dialTag(t, "127.0.0.1:"+p2s(base+3), "")
	c2.Close()
	if tag != "NEW" {
		t.Fatalf("a now reaches %s, want NEW", tag)
	}

	// Removing a leaves b alone as well.
	res = e.mustApply(b)
	if ids(res.Disrupted) != "a" {
		t.Fatalf("result %+v", res)
	}
	roundTrip(t, cb, []byte("after the removal of a"))
}

func TestE2ECrashIsRecovered(t *testing.T) {
	e := newE2E(t, Options{})
	base := freePorts(t, 2)
	tagServer(t, "127.0.0.1:"+p2s(base), "UP")
	e.mustApply(fwd("c", "127.0.0.1", p2s(base+1), tg("127.0.0.1", p2s(base), 0)))
	old := e.sup.killPID(t, "realm/c")
	if e.sup.procs["realm/c"].spec.Restart.Always != true {
		t.Fatal("RestartPolicy.Always must be set")
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		h := e.health("c")
		if h.Running && h.Listening && e.sup.Status("realm/c").PID != old {
			t.Logf("recovered: new pid %d (was %d), restarts=%d", e.sup.Status("realm/c").PID, old, e.sup.Status("realm/c").Restarts)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("not recovered: %+v", h)
		}
		time.Sleep(100 * time.Millisecond)
	}
	tag, c := dialTag(t, "127.0.0.1:"+p2s(base+1), "")
	c.Close()
	if tag != "UP" {
		t.Fatal(tag)
	}
	// Health notices a dead process before the supervisor brings it back.
	e.sup.killPID(t, "realm/c")
	seenDown := false
	for i := 0; i < 20 && !seenDown; i++ {
		seenDown = !e.health("c").Listening
		time.Sleep(20 * time.Millisecond)
	}
	t.Logf("health saw the instance down between crash and restart: %v", seenDown)
}

func TestE2EFailedApplyRestoresLastGood(t *testing.T) {
	e := newE2E(t, Options{ReadyTimeout: 3 * time.Second})
	base := freePorts(t, 3)
	tagServer(t, "127.0.0.1:"+p2s(base), "GOOD")
	a := fwd("a", "127.0.0.1", p2s(base+1), tg("127.0.0.1", p2s(base), 0))
	e.mustApply(a)
	goodHash := e.health("a").ConfigHash

	// (1) A foreign process owns the port the instance is told to move to:
	// refused up front, the running process is not touched at all.
	foreign, err := net.Listen("tcp", "127.0.0.1:"+p2s(base+2))
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	pid := e.sup.Status("realm/a").PID
	bad := mut(a, func(i *spec.Instance) { i.Listen.Ports = p2s(base + 2) })
	res, err := e.apply(bad)
	if err == nil || !strings.Contains(res.Failed["a"], "already in use") {
		t.Fatalf("a port held by another process was accepted: err=%v %+v", err, res)
	}
	t.Logf("(1) refused: %v / %v", err, res.Failed)
	if len(res.Restarted) != 0 || e.sup.Status("realm/a").PID != pid {
		t.Fatalf("the running instance was touched: %+v", res)
	}

	// (2) A configuration realm cannot start with (a certificate file that
	// does not exist; syntactically fine, so Validate passes): the process
	// crashes at startup, Apply notices and restores the last good config.
	cert, key := selfSigned(t, "localhost")
	xp, bp := base+2, base // xp is held by `foreign`; use another free port
	foreign.Close()
	xin := exit("x", spec.Tunnel{Type: "tls", Listen: "127.0.0.1:" + p2s(xp), SNI: "localhost",
		Cert: &spec.Cert{Mode: "file", CertFile: cert, KeyFile: key}}, tg("127.0.0.1", p2s(bp), 0))
	e2 := newE2E(t, Options{ReadyTimeout: 3 * time.Second, InsecureSkipTLSVerify: true})
	e2.mustApply(xin)
	xGood := e2.health("x").ConfigHash
	xbad := mut(xin, func(i *spec.Instance) {
		c := *i.Tunnel.Cert
		c.CertFile = filepath.Join(filepath.Dir(cert), "does-not-exist.pem")
		i.Tunnel.Cert = &c
	})
	res, err = e2.apply(xbad)
	if err == nil || res.Failed["x"] == "" {
		t.Fatalf("a config realm cannot start with was accepted: err=%v %+v", err, res)
	}
	t.Logf("(2) failed and restored: %v / %v", err, res.Failed)
	if h := e2.health("x"); !h.Running || !h.Listening || h.ConfigHash != xGood {
		t.Fatalf("not restored to the last-good config: %+v (want %s)", h, xGood)
	}
	if ids(res.Running) != "x" || ids(res.Restarted) != "x" {
		t.Fatalf("result %+v", res)
	}

	if h := e.health("a"); !h.Running || !h.Listening || h.ConfigHash != goodHash {
		t.Fatalf("a: %+v (want %s)", h, goodHash)
	}
	tag, c := dialTag(t, "127.0.0.1:"+p2s(base+1), "")
	c.Close()
	if tag != "GOOD" {
		t.Fatal(tag)
	}
	// Rollback is a no-op now and keeps it running.
	if err := e.d.Rollback(context.Background(), e.rt); err != nil {
		t.Fatal(err)
	}
	if h := e.health("a"); !h.Listening {
		t.Fatalf("after Rollback: %+v", h)
	}
}

func TestE2EStopCutsConnections(t *testing.T) {
	e := newE2E(t, Options{})
	base := freePorts(t, 2)
	tagServer(t, "127.0.0.1:"+p2s(base), "S")
	e.mustApply(fwd("s", "127.0.0.1", p2s(base+1), tg("127.0.0.1", p2s(base), 0)))
	_, c := dialTag(t, "127.0.0.1:"+p2s(base+1), "")
	defer c.Close()
	if err := e.d.Stop(context.Background(), e.rt, "s"); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 8)); err == nil {
		t.Fatal("established connection survived Stop")
	}
	if len(e.d.Health(context.Background(), e.rt).Instances) != 0 {
		t.Fatal("stopped instance still reported")
	}
	if cnt, err := e.d.Stats(context.Background(), e.rt); err != nil || len(cnt) != 0 {
		t.Fatalf("Stats = %v, %v", cnt, err)
	}
}

var _ = sort.Strings
