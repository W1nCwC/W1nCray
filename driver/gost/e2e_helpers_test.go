//go:build e2e

package gost

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/spec"
)

// ---- supervisor for tests ----

// testSup is a minimal driver.Supervisor: it runs the child, restarts it when
// it exits unless it was stopped, and keeps the status the driver reads.
type testSup struct {
	mu    sync.Mutex
	procs map[string]*tproc
}

type tproc struct {
	spec     driver.ProcSpec
	cmd      *exec.Cmd
	stopped  bool
	done     chan struct{}
	st       driver.ProcStatus
	restarts int
}

func newTestSup(t *testing.T) *testSup {
	s := &testSup{procs: map[string]*tproc{}}
	t.Cleanup(func() {
		s.mu.Lock()
		ids := make([]string, 0, len(s.procs))
		for id := range s.procs {
			ids = append(ids, id)
		}
		s.mu.Unlock()
		for _, id := range ids {
			_ = s.Stop(context.Background(), id)
		}
	})
	return s
}

func (s *testSup) Start(ctx context.Context, p driver.ProcSpec) error {
	s.mu.Lock()
	if old, ok := s.procs[p.ID]; ok {
		if reflect.DeepEqual(old.spec, p) && old.st.Running {
			s.mu.Unlock()
			return nil
		}
		s.mu.Unlock()
		_ = s.Stop(ctx, p.ID)
		s.mu.Lock()
	}
	tp := &tproc{spec: p, done: make(chan struct{})}
	s.procs[p.ID] = tp
	s.mu.Unlock()
	go s.run(tp)
	return nil
}

func (s *testSup) run(tp *tproc) {
	defer close(tp.done)
	for {
		cmd := exec.Command(tp.spec.Path, tp.spec.Args...)
		cmd.Dir = tp.spec.WorkDir
		cmd.Env = append(os.Environ(), tp.spec.Env...)
		lf, err := os.OpenFile(tp.spec.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err == nil {
			cmd.Stdout, cmd.Stderr = lf, lf
		}
		s.mu.Lock()
		if tp.stopped {
			s.mu.Unlock()
			if lf != nil {
				lf.Close()
			}
			return
		}
		err = cmd.Start()
		if err == nil {
			tp.cmd = cmd
			tp.st = driver.ProcStatus{Running: true, PID: cmd.Process.Pid, Restarts: tp.restarts, Since: time.Now()}
		} else {
			tp.st.LastExit = err.Error()
		}
		s.mu.Unlock()
		if err == nil {
			werr := cmd.Wait()
			s.mu.Lock()
			tp.st.Running = false
			tp.st.LastExit = fmt.Sprint(werr)
			s.mu.Unlock()
		}
		if lf != nil {
			lf.Close()
		}
		s.mu.Lock()
		stop := tp.stopped || !tp.spec.Restart.Always
		tp.restarts++
		s.mu.Unlock()
		if stop {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func (s *testSup) Stop(ctx context.Context, id string) error {
	s.mu.Lock()
	tp := s.procs[id]
	if tp == nil {
		s.mu.Unlock()
		return nil
	}
	tp.stopped = true
	cmd := tp.cmd
	s.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	select {
	case <-tp.done:
	case <-time.After(10 * time.Second):
		return fmt.Errorf("process %s did not stop", id)
	}
	s.mu.Lock()
	delete(s.procs, id)
	s.mu.Unlock()
	return nil
}

func (s *testSup) Signal(id string, sig os.Signal) error { return nil }

func (s *testSup) Status(id string) driver.ProcStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	if tp := s.procs[id]; tp != nil {
		return tp.st
	}
	return driver.ProcStatus{}
}

// kill terminates the child without telling the supervisor (a crash).
func (s *testSup) kill(id string) {
	s.mu.Lock()
	tp := s.procs[id]
	var cmd *exec.Cmd
	if tp != nil {
		cmd = tp.cmd
	}
	s.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

// ---- environment ----

type testLog struct{ t *testing.T }

func (l testLog) Debugf(f string, a ...any) {}
func (l testLog) Infof(f string, a ...any)  { l.t.Logf("INFO "+f, a...) }
func (l testLog) Warnf(f string, a ...any)  { l.t.Logf("WARN "+f, a...) }
func (l testLog) Errorf(f string, a ...any) { l.t.Logf("ERROR "+f, a...) }

func gostBin(t *testing.T) string {
	bin := os.Getenv("W1NCRAY_TEST_GOST_BIN")
	if bin == "" {
		t.Skip("W1NCRAY_TEST_GOST_BIN is not set")
	}
	abs, err := filepath.Abs(bin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("gost binary: %v", err)
	}
	return abs
}

// testNode is one driver instance with its own supervisor and state directory,
// i.e. one agent host. (Named testNode to avoid the gost forwarder "node"
// type in model.go.)
type testNode struct {
	t   *testing.T
	d   *Driver
	rt  driver.Runtime
	sup *testSup
}

func newNode(t *testing.T, opts Options) *testNode {
	t.Helper()
	bin := gostBin(t)
	// t.Cleanup is LIFO: register the TempDir removal BEFORE the supervisor
	// cleanup, so gost processes are stopped (and gost.log released) before
	// the directory is removed. On Windows an open log file cannot be
	// unlinked, which failed every e2e test at TempDir cleanup.
	dir := filepath.Join(t.TempDir(), "state")
	sup := newTestSup(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return &testNode{
		t: t, d: New(opts), sup: sup,
		rt: driver.Runtime{Kernel: driver.Installed{Path: bin, Version: "3.3.0"}, StateDir: dir, Sup: sup, Log: testLog{t}},
	}
}

func (n *testNode) render(ins ...spec.Instance) []driver.Rendered {
	n.t.Helper()
	var set []driver.Rendered
	for _, in := range ins {
		a, err := n.d.Render(in)
		if err != nil {
			n.t.Fatalf("render %s: %v", in.ID, err)
		}
		set = append(set, driver.Rendered{Instance: in, Artifact: a})
	}
	return set
}

func (n *testNode) apply(ins ...spec.Instance) driver.ApplyResult {
	n.t.Helper()
	res, err := n.d.Apply(context.Background(), n.rt, n.render(ins...))
	if err != nil || len(res.Failed) > 0 {
		n.t.Fatalf("apply: %v failed=%v", err, res.Failed)
	}
	return res
}

func (n *testNode) applyRaw(ins ...spec.Instance) (driver.ApplyResult, error) {
	return n.d.Apply(context.Background(), n.rt, n.render(ins...))
}

func (n *testNode) stats() map[string]driver.Counter {
	n.t.Helper()
	cs, err := n.d.Stats(context.Background(), n.rt)
	if err != nil {
		n.t.Fatalf("stats: %v", err)
	}
	m := map[string]driver.Counter{}
	for _, c := range cs {
		m[c.InstanceID] = c
	}
	return m
}

func eventually(t *testing.T, timeout time.Duration, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if f() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// ---- network helpers ----

var portMu sync.Mutex

// freePorts returns n consecutive ports free for tcp and udp on 127.0.0.1.
// It searches below the default ephemeral port ranges (Linux 32768-60999,
// Windows 49152-65535): the OS can otherwise hand a just-probed port out as
// the source port of an unrelated connection before the kernel under test
// binds it, which fails with EADDRINUSE.
func freePorts(t *testing.T, n int) int {
	t.Helper()
	portMu.Lock()
	defer portMu.Unlock()
	for try := 0; try < 500; try++ {
		base := 20000 + mrand.IntN(11000)
		ok := base+n < 31000
		var held []io.Closer
		for i := 0; ok && i < n; i++ {
			a := fmt.Sprintf("127.0.0.1:%d", base+i)
			tl, err := net.Listen("tcp", a)
			if err != nil {
				ok = false
				break
			}
			held = append(held, tl)
			ul, err := net.ListenPacket("udp", a)
			if err != nil {
				ok = false
				break
			}
			held = append(held, ul)
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

type tcpBackend struct {
	l      net.Listener
	Addr   string
	Port   int
	name   string
	conns  atomic.Int64
	closed atomic.Bool
}

// startBackend serves an echo; with a name it first writes "<name>\n".
func startBackend(t *testing.T, name string) *tcpBackend {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return serveBackend(t, l, name)
}

func serveBackend(t *testing.T, l net.Listener, name string) *tcpBackend {
	b := &tcpBackend{l: l, Addr: l.Addr().String(), Port: l.Addr().(*net.TCPAddr).Port, name: name}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			b.conns.Add(1)
			go func() {
				defer c.Close()
				if name != "" {
					fmt.Fprintf(c, "%s\n", name)
				}
				io.Copy(c, c)
			}()
		}
	}()
	t.Cleanup(func() { b.Close() })
	return b
}

func (b *tcpBackend) Close() {
	if b.closed.CompareAndSwap(false, true) {
		b.l.Close()
	}
}

func startUDPEcho(t *testing.T) (*net.UDPConn, int) {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, a, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			c.WriteToUDP(buf[:n], a)
		}
	}()
	t.Cleanup(func() { c.Close() })
	return c, c.LocalAddr().(*net.UDPAddr).Port
}

// roundTrip sends msg on a new TCP connection and reads the echo; with
// skipGreeting it first consumes the backend's name line.
func tcpEcho(addr, msg string, greeting bool) (string, error) {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	return echoOn(c, msg, greeting)
}

func echoOn(c net.Conn, msg string, greeting bool) (string, error) {
	c.SetDeadline(time.Now().Add(3 * time.Second))
	br := bufio.NewReader(c)
	name := ""
	if greeting {
		l, err := br.ReadString('\n')
		if err != nil {
			return "", err
		}
		name = strings.TrimSpace(l)
	}
	if _, err := c.Write([]byte(msg + "\n")); err != nil {
		return name, err
	}
	l, err := br.ReadString('\n')
	if err != nil {
		return name, err
	}
	if strings.TrimSpace(l) != msg {
		return name, fmt.Errorf("echo mismatch: %q", l)
	}
	return name, nil
}

func udpEchoOnce(addr, msg string) error {
	c, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	defer c.Close()
	for i := 0; i < 3; i++ { // UDP may lose the first datagram while the session is set up
		c.SetDeadline(time.Now().Add(1500 * time.Millisecond))
		if _, err = c.Write([]byte(msg)); err != nil {
			return err
		}
		buf := make([]byte, 2048)
		var n int
		if n, err = c.Read(buf); err == nil {
			if string(buf[:n]) != msg {
				return fmt.Errorf("udp echo mismatch %q", buf[:n])
			}
			return nil
		}
	}
	return err
}

// headBackend records the first bytes of every connection, then echoes.
type headBackend struct {
	*tcpBackend
	heads chan []byte
}

func startHeadBackend(t *testing.T, n int) *headBackend {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hb := &headBackend{heads: make(chan []byte, 16)}
	hb.tcpBackend = &tcpBackend{l: l, Addr: l.Addr().String(), Port: l.Addr().(*net.TCPAddr).Port}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				c.SetReadDeadline(time.Now().Add(3 * time.Second))
				b, _ := br.Peek(n)
				hb.heads <- append([]byte(nil), b...)
				c.SetReadDeadline(time.Time{})
				io.Copy(c, br)
			}()
		}
	}()
	t.Cleanup(func() { hb.Close() })
	return hb
}

// ---- certificates ----

func writeCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "w1ncray-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	return
}

// ---- instance builders ----

func fwdInst(id string, port int, target string, networks ...string) spec.Instance {
	h, p, _ := net.SplitHostPort(target)
	return spec.Instance{
		ID: id, Enabled: true, Engine: spec.EngineGost, Kind: spec.KindForward,
		Listen:  &spec.Listen{Addr: "127.0.0.1", Ports: fmt.Sprint(port)},
		Network: networks,
		Targets: []spec.Target{{Host: h, Ports: p}},
	}
}

const e2eSecret = "e2e-secret-e2e-secret-0123"
