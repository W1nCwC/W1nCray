//go:build e2e

package frp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// frpDir returns the directory with frps/frpc or skips the test.
func frpDir(t testing.TB) string {
	t.Helper()
	d := os.Getenv("W1NCRAY_TEST_FRP_DIR")
	if d == "" {
		t.Skip("W1NCRAY_TEST_FRP_DIR is not set")
	}
	return d
}

func exe(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

// ---------- a process supervisor good enough for the tests ----------

type tproc struct {
	spec    driver.ProcSpec
	cmd     *exec.Cmd
	stopped bool
	done    chan struct{}
}

type testSup struct {
	t        testing.TB
	mu       sync.Mutex
	procs    map[string]*tproc
	restarts map[string]int
	lastExit map[string]string
	backoff  time.Duration
	wg       sync.WaitGroup
}

func newTestSup(t testing.TB) *testSup {
	s := &testSup{t: t, procs: map[string]*tproc{}, restarts: map[string]int{}, lastExit: map[string]string{}, backoff: time.Second}
	t.Cleanup(func() { _ = s.Stop(context.Background(), ""); s.StopAll(); s.wg.Wait() })
	return s
}

func (s *testSup) StopAll() {
	s.mu.Lock()
	ids := make([]string, 0, len(s.procs))
	for id := range s.procs {
		ids = append(ids, id)
	}
	s.mu.Unlock()
	for _, id := range ids {
		_ = s.Stop(context.Background(), id)
	}
}

func (s *testSup) launch(p *tproc) error {
	cmd := exec.Command(p.spec.Path, p.spec.Args...)
	cmd.Dir = p.spec.WorkDir
	cmd.Env = append(minimalEnv(), p.spec.Env...)
	var lf *os.File
	if p.spec.LogFile != "" {
		var err error
		lf, err = os.OpenFile(p.spec.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return err
		}
		cmd.Stdout, cmd.Stderr = lf, lf
	}
	if err := cmd.Start(); err != nil {
		if lf != nil {
			lf.Close()
		}
		return err
	}
	// Status/Signal read these under s.mu; publish them under it too.
	s.mu.Lock()
	p.cmd = cmd
	p.done = make(chan struct{})
	s.mu.Unlock()
	s.wg.Add(1)
	go func(cmd *exec.Cmd, done chan struct{}) {
		defer s.wg.Done()
		err := cmd.Wait()
		if lf != nil {
			lf.Close()
		}
		s.mu.Lock()
		s.lastExit[p.spec.ID] = fmt.Sprint(err)
		stopped := p.stopped
		s.mu.Unlock()
		close(done)
		if stopped || !p.spec.Restart.Always {
			return
		}
		time.Sleep(s.backoff)
		s.mu.Lock()
		if p.stopped || s.procs[p.spec.ID] != p {
			s.mu.Unlock()
			return
		}
		s.restarts[p.spec.ID]++
		s.mu.Unlock()
		if err := s.launch(p); err != nil {
			s.t.Logf("restart %s: %v", p.spec.ID, err)
		}
	}(cmd, p.done)
	return nil
}

func (s *testSup) Start(ctx context.Context, spec driver.ProcSpec) error {
	s.mu.Lock()
	if old, ok := s.procs[spec.ID]; ok {
		if reflect.DeepEqual(old.spec, spec) && old.cmd != nil {
			select {
			case <-old.done:
			default:
				s.mu.Unlock()
				return nil
			}
		}
		s.mu.Unlock()
		_ = s.Stop(ctx, spec.ID)
		s.mu.Lock()
	}
	p := &tproc{spec: spec}
	s.procs[spec.ID] = p
	s.mu.Unlock()
	return s.launch(p)
}

func (s *testSup) Stop(ctx context.Context, id string) error {
	s.mu.Lock()
	if id == "" {
		s.mu.Unlock()
		return nil
	}
	p, ok := s.procs[id]
	if !ok {
		s.mu.Unlock()
		return nil
	}
	p.stopped = true
	cmd, done := p.cmd, p.done
	delete(s.procs, id)
	s.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		if runtime.GOOS != "windows" {
			_ = cmd.Process.Signal(syscall.SIGTERM)
		} else {
			_ = cmd.Process.Kill()
		}
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	}
	return nil
}

func (s *testSup) Signal(id string, sig os.Signal) error {
	s.mu.Lock()
	p, ok := s.procs[id]
	var cmd *exec.Cmd
	if ok {
		cmd = p.cmd
	}
	s.mu.Unlock()
	if !ok || cmd == nil || cmd.Process == nil {
		return errors.New("no such process")
	}
	return cmd.Process.Signal(sig)
}

func (s *testSup) Status(id string) driver.ProcStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.procs[id]
	st := driver.ProcStatus{Restarts: s.restarts[id], LastExit: s.lastExit[id]}
	if !ok || p.cmd == nil {
		return st
	}
	select {
	case <-p.done:
	default:
		st.Running = true
		st.PID = p.cmd.Process.Pid
	}
	return st
}

// Kill terminates the process like a crash: the restart policy applies.
func (s *testSup) Kill(id string) {
	s.mu.Lock()
	p := s.procs[id]
	s.mu.Unlock()
	if p != nil && p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
}

// ---------- network helpers ----------

func freePort(t testing.TB) int {
	t.Helper()
	for i := 0; i < 100; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		l.Close()
		if pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			pc.Close()
			return port
		}
	}
	t.Fatal("no free port")
	return 0
}

// freeRange returns the first port of n consecutive ports free for tcp+udp.
func freeRange(t testing.TB, n int) int {
	t.Helper()
	for try := 0; try < 200; try++ {
		base := 30000 + int(randInt(20000))
		ok := true
		for i := 0; i < n && ok; i++ {
			l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", base+i))
			if err != nil {
				ok = false
				break
			}
			l.Close()
			pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", base+i))
			if err != nil {
				ok = false
				break
			}
			pc.Close()
		}
		if ok {
			return base
		}
	}
	t.Fatal("no free port range")
	return 0
}

func randInt(n int64) int64 {
	v, _ := rand.Int(rand.Reader, big.NewInt(n))
	return v.Int64()
}

type echoSrv struct {
	ln    net.Listener
	mu    sync.Mutex
	conns int
}

// startTCPEcho serves a tagged echo: every received chunk is returned
// unchanged. Port 0 picks a free port.
func startTCPEcho(t testing.TB) (*echoSrv, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &echoSrv{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns++
			s.mu.Unlock()
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return s, ln.Addr().(*net.TCPAddr).Port
}

func startUDPEcho(t testing.TB) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
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
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// tcpRoundTrip dials addr, sends payload and expects it back.
func tcpRoundTrip(addr string, payload []byte) error {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(payload); err != nil {
		return err
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if !bytes.Equal(got, payload) {
		return errors.New("payload mismatch")
	}
	return nil
}

func udpRoundTrip(addr string, payload []byte) error {
	c, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	defer c.Close()
	for try := 0; try < 3; try++ { // UDP may lose the first datagram while the proxy settles
		_ = c.SetDeadline(time.Now().Add(1500 * time.Millisecond))
		if _, err := c.Write(payload); err != nil {
			return err
		}
		buf := make([]byte, len(payload)+16)
		n, err := c.Read(buf)
		if err == nil {
			if !bytes.Equal(buf[:n], payload) {
				return errors.New("udp payload mismatch")
			}
			return nil
		}
	}
	return errors.New("udp: no reply")
}

// eventually polls f until it returns nil or the timeout expires.
func eventually(t testing.TB, d time.Duration, what string, f func() error) time.Duration {
	t.Helper()
	start := time.Now()
	var err error
	for time.Since(start) < d {
		if err = f(); err == nil {
			return time.Since(start)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s: not satisfied within %v: %v", what, d, err)
	return 0
}

// ---------- PROXY protocol listener ----------

// proxyHeader reads a PROXY v1 or v2 header and returns the source address.
func readProxyHeader(r *bufio.Reader) (netip.AddrPort, string, error) {
	peek, err := r.Peek(5)
	if err != nil {
		return netip.AddrPort{}, "", err
	}
	if string(peek) == "PROXY" {
		line, err := r.ReadString('\n')
		if err != nil {
			return netip.AddrPort{}, "", err
		}
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) != 6 {
			return netip.AddrPort{}, "v1", fmt.Errorf("bad v1 header %q", line)
		}
		ap, err := netip.ParseAddrPort(net.JoinHostPort(f[2], f[4]))
		return ap, "v1", err
	}
	sig := []byte("\r\n\r\n\x00\r\nQUIT\n")
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return netip.AddrPort{}, "", err
	}
	if !bytes.Equal(hdr[:12], sig) {
		return netip.AddrPort{}, "", errors.New("no PROXY header")
	}
	n := int(hdr[14])<<8 | int(hdr[15])
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return netip.AddrPort{}, "", err
	}
	// Byte 12 is version<<4|command (0x21 = v2 PROXY), byte 13 is
	// family<<4|protocol.
	if hdr[12] != 0x21 {
		return netip.AddrPort{}, "v2", fmt.Errorf("unexpected v2 version/command %#x", hdr[12])
	}
	switch hdr[13] >> 4 {
	case 1: // IPv4
		if n < 12 {
			return netip.AddrPort{}, "v2", errors.New("short v4 block")
		}
		a, _ := netip.AddrFromSlice(body[0:4])
		return netip.AddrPortFrom(a, uint16(body[8])<<8|uint16(body[9])), "v2", nil
	case 2: // IPv6
		if n < 36 {
			return netip.AddrPort{}, "v2", errors.New("short v6 block")
		}
		a, _ := netip.AddrFromSlice(body[0:16])
		return netip.AddrPortFrom(a, uint16(body[32])<<8|uint16(body[33])), "v2", nil
	}
	return netip.AddrPort{}, "v2", errors.New("unsupported address family")
}

type proxySrv struct {
	mu   sync.Mutex
	seen []string // "<version> <src>"
}

func startProxyEcho(t testing.TB) (*proxySrv, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &proxySrv{}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				ap, ver, err := readProxyHeader(r)
				s.mu.Lock()
				if err != nil {
					s.seen = append(s.seen, "err:"+err.Error())
				} else {
					s.seen = append(s.seen, ver+" "+ap.String())
				}
				s.mu.Unlock()
				_, _ = io.Copy(c, r)
			}()
		}
	}()
	return s, ln.Addr().(*net.TCPAddr).Port
}

// ---------- certificates ----------

type pki struct {
	caPEM, certPEM, keyPEM []byte
}

func newPKI(t testing.TB, ips ...string) pki {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "w1nc-test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "frp-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, ip := range ips {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	return pki{
		caPEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}),
	}
}

func (p pki) write(t testing.TB, dir string) (ca, cert, key string) {
	t.Helper()
	ca, cert, key = filepath.Join(dir, "ca.pem"), filepath.Join(dir, "srv.pem"), filepath.Join(dir, "srv.key")
	for path, b := range map[string][]byte{ca: p.caPEM, cert: p.certPEM, key: p.keyPEM} {
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return
}
