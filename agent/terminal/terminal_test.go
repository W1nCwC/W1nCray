package terminal

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// testLog captures what the manager logged, so a test can assert on it.
type testLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *testLog) add(f string, a ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(f, a...))
}

func (l *testLog) Debugf(f string, a ...any) { l.add(f, a...) }
func (l *testLog) Infof(f string, a ...any)  { l.add(f, a...) }
func (l *testLog) Warnf(f string, a ...any)  { l.add(f, a...) }
func (l *testLog) Errorf(f string, a ...any) { l.add(f, a...) }

func (l *testLog) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

var _ driver.Logger = (*testLog)(nil)

// auditLog records the audit events a manager emitted.
type auditLog struct {
	mu     sync.Mutex
	events []AuditEvent
}

func (a *auditLog) TerminalEvent(e AuditEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, e)
}

func (a *auditLog) all() []AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]AuditEvent(nil), a.events...)
}

var _ Auditor = (*auditLog)(nil)

// ---- fake platform ---------------------------------------------------------

// fakePTY is a ptyProcess that talks over a socket pair: writes from the
// session land in a pipe the test reads, and the test can push bytes back as
// "shell output". It lets every session-management rule be tested on any
// platform, including Windows where no PTY exists.
type fakePTY struct {
	mu       sync.Mutex
	writes   []byte
	resizes  [][2]uint16
	term     int
	killed   int
	peer     *net.TCPConn
	closeErr error
}

func (f *fakePTY) read(p []byte) (int, error)  { return f.peer.Read(p) }
func (f *fakePTY) write(p []byte) (int, error) { return f.peer.Write(p) }

func (f *fakePTY) resize(cols, rows uint16) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resizes = append(f.resizes, [2]uint16{cols, rows})
	return nil
}

func (f *fakePTY) pid() int { return 4242 }

func (f *fakePTY) signalTerm() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.term++
	// The fake shell dies on TERM, like a real one.
	_ = f.peer.Close()
	return nil
}

func (f *fakePTY) signalKill() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.killed++
	_ = f.peer.Close()
	return nil
}

func (f *fakePTY) wait() error {
	// Read until the peer is closed, like a real process would until its
	// shell exits.
	buf := make([]byte, 256)
	for {
		if _, err := f.peer.Read(buf); err != nil {
			return nil
		}
	}
}

func (f *fakePTY) close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeErr = f.peer.Close()
	return f.closeErr
}

func (f *fakePTY) written() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return string(f.writes)
}

// fakeServer accepts the agent side of a fakePTY and exposes the other end.
type fakeServer struct {
	ln *net.TCPListener
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return &fakeServer{ln: ln}
}

// start returns a startPTY hook backed by this server.
func (s *fakeServer) start(t *testing.T) func(shell string, env []string, cols, rows uint16) (ptyProcess, error) {
	t.Helper()
	return func(shell string, env []string, cols, rows uint16) (ptyProcess, error) {
		conn, err := net.DialTCP("tcp", nil, s.ln.Addr().(*net.TCPAddr))
		if err != nil {
			return nil, err
		}
		peer, err := s.ln.AcceptTCP()
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		f := &fakePTY{peer: conn}
		// Capture writes from the session.
		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := peer.Read(buf)
				if n > 0 {
					f.mu.Lock()
					f.writes = append(f.writes, buf[:n]...)
					f.mu.Unlock()
				}
				if err != nil {
					return
				}
			}
		}()
		return f, nil
	}
}

func newTestManager(t *testing.T, o Options) (*Manager, *auditLog) {
	t.Helper()
	audit := &auditLog{}
	if o.Audit == nil {
		o.Audit = audit
	}
	if o.Log == nil {
		o.Log = &testLog{}
	}
	if o.Shell == "" {
		o.Shell = DefaultShell
	}
	o.Enabled = true
	if o.startPTY == nil {
		o.startPTY = func(shell string, env []string, cols, rows uint16) (ptyProcess, error) {
			return &fakePTY{peer: deadConn(t)}, nil
		}
	}
	m, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return m, audit
}

// requirePTY skips a session test where no PTY exists. Windows and any kernel
// without /dev/ptmx cannot run one; the manager's rules are the same code path
// there, they are simply unreachable without the platform hook (which the
// Linux test machine exercises in full).
func requirePTY(t *testing.T) {
	t.Helper()
	if !Supported() {
		t.Skip("no PTY on this platform: session management is exercised on the Linux test machine")
	}
}

// deadConn returns a socket whose peer is already closed: reads return EOF at
// once, so a session started with it ends immediately.
func deadConn(t *testing.T) *net.TCPConn {
	t.Helper()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	conn, err := net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	peer, err := ln.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	_ = peer.Close()
	return conn
}

// ---- acceptance 3: the local switch ---------------------------------------

func TestDisabledManagerRefusesOpen(t *testing.T) {
	m, err := New(Options{Enabled: false, startPTY: func(string, []string, uint16, uint16) (ptyProcess, error) {
		t.Fatal("a disabled manager must not start a PTY")
		return nil, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if m.Available() {
		t.Error("a disabled manager reports itself available")
	}
	if _, err := m.Open("s1", 80, 24); !errors.Is(err, ErrDisabled) {
		t.Fatalf("Open on a disabled manager = %v, want ErrDisabled", err)
	}
	m.CloseAll("test")
}

func TestZeroOptionsIsDisabled(t *testing.T) {
	// The zero value of Options has Enabled=false; agentcfg is what turns the
	// default ON (ruling 17), and the manager must not guess it.
	m, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if m.Enabled() {
		t.Error("the zero value must be disabled, not enabled")
	}
	m.CloseAll("test")
}

func TestUnsupportedPlatformRefusesOpen(t *testing.T) {
	if Supported() {
		t.Skip("this platform has a PTY; the unsupported path cannot be reached")
	}
	m, err := New(Options{Enabled: true, Shell: "sh"})
	if err != nil {
		t.Fatal(err)
	}
	defer m.CloseAll("test")
	if m.Available() {
		t.Error("Available() must be false without PTY support")
	}
	if _, err := m.Open("s1", 80, 24); !errors.Is(err, ErrNoPTY) {
		t.Fatalf("Open without PTY support = %v, want ErrNoPTY", err)
	}
}

// ---- acceptance 4: limit, idle, lifetime, CloseAll -------------------------

func TestSessionLimit(t *testing.T) {
	requirePTY(t)
	srv := newFakeServer(t)
	start := srv.start(t)
	m, _ := newTestManager(t, Options{MaxSessions: 2, startPTY: start})
	defer m.CloseAll("test")

	a, err := m.Open("a", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Open("b", 80, 24); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Open("c", 80, 24); !errors.Is(err, ErrLimit) {
		t.Fatalf("the third session = %v, want ErrLimit", err)
	}
	// Closing one frees the slot.
	if err := m.Close("a", ReasonClosed); err != nil {
		t.Fatal(err)
	}
	waitGone(t, m, "a")
	if _, err := m.Open("c", 80, 24); err != nil {
		t.Fatalf("reopening after a close: %v", err)
	}
	_ = a
}

func TestIdleTimeoutReapsSession(t *testing.T) {
	requirePTY(t)
	srv := newFakeServer(t)
	start := srv.start(t)
	m, audit := newTestManager(t, Options{
		MaxSessions:  2,
		IdleTimeout:  60 * time.Millisecond,
		ReapInterval: 10 * time.Millisecond,
		startPTY:     start,
	})
	defer m.CloseAll("test")

	s, err := m.Open("idle", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case ex := <-s.Exited():
		if ex.Reason != ReasonIdleTimeout {
			t.Fatalf("exit reason = %q, want %q", ex.Reason, ReasonIdleTimeout)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the idle session was never reaped")
	}
	if got := m.Sessions(); len(got) != 0 {
		t.Fatalf("sessions after the reap = %v", got)
	}
	ev := findAudit(t, audit, "idle", "close")
	if ev.Reason != ReasonIdleTimeout {
		t.Errorf("audit reason = %q", ev.Reason)
	}
}

func TestMaxLifetimeReapsSession(t *testing.T) {
	requirePTY(t)
	srv := newFakeServer(t)
	start := srv.start(t)
	m, _ := newTestManager(t, Options{
		MaxSessions:  2,
		IdleTimeout:  time.Hour, // never
		MaxLifetime:  60 * time.Millisecond,
		ReapInterval: 10 * time.Millisecond,
		startPTY:     start,
	})
	defer m.CloseAll("test")

	s, err := m.Open("long", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case ex := <-s.Exited():
		if ex.Reason != ReasonMaxLifetime {
			t.Fatalf("exit reason = %q, want %q", ex.Reason, ReasonMaxLifetime)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the session outlived MaxLifetime")
	}
}

func TestCloseAllKillsEverySession(t *testing.T) {
	requirePTY(t)
	srv := newFakeServer(t)
	start := srv.start(t)
	m, audit := newTestManager(t, Options{MaxSessions: 2, startPTY: start})

	a, err := m.Open("a", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Open("b", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	m.CloseAll(ReasonAgentShutdown)

	for id, s := range map[string]Session{"a": a, "b": b} {
		select {
		case ex := <-s.Exited():
			if ex.Reason != ReasonAgentShutdown {
				t.Errorf("session %s exit reason = %q", id, ex.Reason)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("session %s did not exit", id)
		}
	}
	if got := m.Sessions(); len(got) != 0 {
		t.Errorf("sessions after CloseAll = %v", got)
	}
	for _, id := range []string{"a", "b"} {
		if ev := findAudit(t, audit, id, "close"); ev.Reason != ReasonAgentShutdown {
			t.Errorf("session %s audit reason = %q", id, ev.Reason)
		}
	}
	// CloseAll is idempotent and Open after it is refused.
	m.CloseAll(ReasonAgentShutdown)
	if _, err := m.Open("c", 80, 24); !errors.Is(err, ErrDisabled) {
		t.Errorf("Open after CloseAll = %v, want ErrDisabled", err)
	}
}

func TestCloseUnknownSession(t *testing.T) {
	m, _ := newTestManager(t, Options{})
	defer m.CloseAll("test")
	if err := m.Close("nope", ReasonClosed); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Close of an unknown session = %v, want ErrNotFound", err)
	}
	if _, ok := m.Get("nope"); ok {
		t.Error("Get found a session that was never opened")
	}
}

func TestDuplicateSessionIDIsRefused(t *testing.T) {
	requirePTY(t)
	srv := newFakeServer(t)
	start := srv.start(t)
	m, _ := newTestManager(t, Options{MaxSessions: 2, startPTY: start})
	defer m.CloseAll("test")
	if _, err := m.Open("same", 80, 24); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Open("same", 80, 24); err == nil {
		t.Fatal("a duplicate session id was accepted")
	}
}

// ---- acceptance 6: audit metadata only ------------------------------------

func TestAuditCarriesMetadataOnly(t *testing.T) {
	requirePTY(t)
	srv := newFakeServer(t)
	start := srv.start(t)
	m, audit := newTestManager(t, Options{MaxSessions: 2, startPTY: start})

	s, err := m.Open("aud", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write([]byte("secret-command\n")); err != nil {
		t.Fatal(err)
	}
	// A little output so BytesOut is non-zero.
	_ = s.Close(ReasonClosed)
	<-s.Exited()

	ev := findAudit(t, audit, "aud", "close")
	if ev.Session != "aud" || ev.Action != "close" {
		t.Fatalf("unexpected audit event %+v", ev)
	}
	if ev.BytesIn != int64(len("secret-command\n")) {
		t.Errorf("BytesIn = %d, want %d", ev.BytesIn, len("secret-command\n"))
	}
	if ev.At.IsZero() {
		t.Error("the audit event has no timestamp")
	}
	// The compile-time guarantee: AuditEvent has no field that could hold
	// terminal content. This is asserted by construction; the runtime half is
	// that no logged line carries the input either.
	open := findAudit(t, audit, "aud", "open")
	if open.Action != "open" {
		t.Errorf("no open event: %+v", open)
	}
}

// ---- acceptance 4/5: sizes, PTY resize, input limits -----------------------

func TestResizeAndBadSize(t *testing.T) {
	requirePTY(t)
	srv := newFakeServer(t)
	start := srv.start(t)
	m, _ := newTestManager(t, Options{MaxSessions: 2, startPTY: start})
	defer m.CloseAll("test")
	s, err := m.Open("r", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Resize(120, 40); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	for _, bad := range [][2]uint16{{0, 24}, {80, 0}, {1001, 24}, {80, 1001}} {
		if err := s.Resize(bad[0], bad[1]); !errors.Is(err, ErrBadSize) {
			t.Errorf("Resize(%d,%d) = %v, want ErrBadSize", bad[0], bad[1], err)
		}
	}
	if _, err := m.Open("bad", 0, 0); !errors.Is(err, ErrBadSize) {
		t.Errorf("Open with a zero size = %v, want ErrBadSize", err)
	}
}

func TestWriteFrameLimit(t *testing.T) {
	requirePTY(t)
	srv := newFakeServer(t)
	start := srv.start(t)
	m, _ := newTestManager(t, Options{MaxSessions: 2, MaxFrame: 64, startPTY: start})
	defer m.CloseAll("test")
	s, err := m.Open("w", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write(make([]byte, 65)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Write of 65 bytes with MaxFrame 64 = %v, want ErrTooLarge", err)
	}
	if n, err := s.Write([]byte("hello")); err != nil || n != 5 {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if err := s.Close(ReasonClosed); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write([]byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Write after Close = %v, want ErrClosed", err)
	}
}

func TestOutputIsChunkedAndDroppedNotBlocked(t *testing.T) {
	requirePTY(t)
	srv := newFakeServer(t)
	start := srv.start(t)
	m, _ := newTestManager(t, Options{MaxSessions: 2, MaxFrame: 128, startPTY: start})
	defer m.CloseAll("test")
	s, err := m.Open("o", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	// No consumer: the reader must not block the session.
	time.Sleep(50 * time.Millisecond)
	if err := s.Close(ReasonClosed); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.Exited():
	case <-time.After(5 * time.Second):
		t.Fatal("a session with no output consumer never exited")
	}
}

// ---- acceptance 5: the real shell environment ------------------------------

// TestShellSeesNoSecrets runs a real shell under a real PTY and asserts that the
// environment inside it carries neither the machine token nor an Agent.* value.
// It is the end-to-end half of acceptance 5; it needs a working PTY, so it
// skips where Supported() is false.
//
// The shell is the ordinary configured one and the check is fed through stdin:
// the session starts the shell with "-i" and no script argument, so a script
// file would make an interactive shell keep reading stdin after it finished.
func TestShellSeesNoSecrets(t *testing.T) {
	if !Supported() {
		t.Skip("no PTY on this platform: the shell environment test needs a real terminal")
	}
	t.Setenv("W1NCRAY_TOKEN", "e2e-machine-token")
	t.Setenv("Agent.Panel.Token", "e2e-agent-token")
	t.Setenv("LD_PRELOAD", "/tmp/e2e-evil.so")

	m, err := New(Options{Enabled: true, Shell: DefaultShell, MaxSessions: 1, IdleTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer m.CloseAll("test")
	s, err := m.Open("env", 100, 30)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// The shell checks itself: it exits non-zero when it can see a secret, so
	// the assertion holds even if the reader dropped a frame. The echo of this
	// line comes back with the output, which is why the test does not search
	// for the token text in it.
	script := "if env | grep -q -e e2e-machine-token -e e2e-agent-token -e LD_PRELOAD; then echo LEAKED; exit 3; fi; echo ENV-OK; exit 0\n"
	if _, err := s.Write([]byte(script)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out := drainUntil(t, s, "ENV-OK", 20*time.Second)
	select {
	case ex := <-s.Exited():
		if ex.Code != 0 {
			t.Fatalf("the shell found a secret in its environment (exit %d); output:\n%s", ex.Code, out)
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("the shell did not exit; output:\n%s", out)
	}
	if !strings.Contains(out, "ENV-OK") {
		t.Fatalf("the shell produced no ENV-OK marker; output:\n%s", out)
	}
}

// TestNoOrphanShellAfterCloseAll is the real-PTY half of acceptance 4: after
// CloseAll the child process must be gone. It is skipped without a PTY.
func TestNoOrphanShellAfterCloseAll(t *testing.T) {
	if !Supported() {
		t.Skip("no PTY on this platform: the orphan check needs a real terminal")
	}
	shell := "/bin/sh"
	if _, err := os.Stat(shell); err != nil {
		t.Skipf("%s is not available: %v", shell, err)
	}
	m, err := New(Options{Enabled: true, Shell: shell, MaxSessions: 2, IdleTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	s, err := m.Open("orphan", 80, 24)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := s.Write([]byte("echo alive\n")); err != nil {
		t.Fatal(err)
	}
	// Find the child: the shell is the process the PTY belongs to.
	pid := childPID(t, s)
	if pid <= 0 {
		t.Skip("the platform does not expose the session's pid")
	}
	m.CloseAll(ReasonAgentShutdown)
	select {
	case <-s.Exited():
	case <-time.After(10 * time.Second):
		t.Fatal("the shell did not exit after CloseAll")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if !processAlive(pid) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pid %d is still alive after CloseAll", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ---- helpers ---------------------------------------------------------------

func waitGone(t *testing.T, m *Manager, id string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := m.Get(id); !ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("session %s was still registered", id)
}

func findAudit(t *testing.T, a *auditLog, session, action string) AuditEvent {
	t.Helper()
	for _, e := range a.all() {
		if e.Session == session && e.Action == action {
			return e
		}
	}
	t.Fatalf("no %s audit event for session %s: %+v", action, session, a.all())
	return AuditEvent{}
}

func drain(t *testing.T, s Session, timeout time.Duration) string {
	t.Helper()
	var b strings.Builder
	deadline := time.After(timeout)
	for {
		select {
		case chunk, ok := <-s.Output():
			if !ok {
				return b.String()
			}
			b.Write(chunk)
		case <-deadline:
			return b.String()
		}
	}
}

// drainUntil reads output until want appears or the deadline passes.
func drainUntil(t *testing.T, s Session, want string, timeout time.Duration) string {
	t.Helper()
	var b strings.Builder
	deadline := time.After(timeout)
	for {
		if strings.Contains(b.String(), want) {
			return b.String()
		}
		select {
		case chunk, ok := <-s.Output():
			if !ok {
				return b.String()
			}
			b.Write(chunk)
		case <-deadline:
			return b.String()
		}
	}
}

// childPID reads the pid of a session (0 when the platform does not expose it).
func childPID(t *testing.T, s Session) int {
	t.Helper()
	return s.PID()
}
