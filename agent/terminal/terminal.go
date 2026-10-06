// Package terminal is the agent's interactive terminal (PLAN v9 D8 / WP-G6).
//
// It is the ONLY package under agent/ that may start a shell. Everything else
// stays bound by agent/supervisor/noshell_test.go, which whitelists exactly
// this package with a written reason (design section 3.8). The whitelist is
// fixed by agent/terminal/noshell_allow_test.go and by the security-model
// section of docs/AGENT.md, so the exception cannot grow unnoticed.
//
// The terminal is a LOCAL gate: the panel can never open it on a machine whose
// agent.yml says `Terminal: {Enabled: false}`, and a platform whose PTY cannot
// be created never declares the capability at all (Supported reports it at
// runtime, not at build time).
//
// Safety properties:
//   - at most Options.MaxSessions concurrent sessions (the contract and the
//     config refuse more than 2);
//   - a session is reclaimed after Options.IdleTimeout of silence and after
//     Options.MaxLifetime in total, whatever the panel does;
//   - CloseAll kills every child process group, so the agent never leaves an
//     orphaned shell behind;
//   - the child gets exactly the allowlisted environment of env.go: never the
//     machine token, never an Agent.* value, never LD_PRELOAD;
//   - the audit events carry metadata only. AuditEvent has no content field at
//     all, which is a compile-time guarantee, not a convention.
package terminal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// Defaults of the terminal policy (D8: at most two sessions per machine, idle
// 15 minutes, hard limit 4 hours).
const (
	DefaultShell       = "/bin/sh" // OpenWrt has no bash
	DefaultMaxSessions = 2
	DefaultIdleTimeout = 15 * time.Minute
	DefaultMaxLifetime = 4 * time.Hour
	// DefaultMaxFrame bounds one inbound term.input frame. The contract caps
	// term.input at 64 KiB (docs/WS-PROTOCOL.md section 4).
	DefaultMaxFrame = 64 << 10
)

// Exit reasons reported in Exit.Reason.
const (
	ReasonExit          = "exit"           // the shell exited on its own
	ReasonClosed        = "closed"         // the panel closed the session
	ReasonIdleTimeout   = "idle_timeout"   // Options.IdleTimeout of silence
	ReasonMaxLifetime   = "max_lifetime"   // Options.MaxLifetime in total
	ReasonAgentShutdown = "agent_shutdown" // CloseAll
	// ReasonDisconnected ends a session whose panel link went away. A session
	// belongs to the connection that opened it: the panel deletes its own state
	// on the same event (its onClose synthesises reason=agent_disconnected), so
	// the agent must not keep a shell nobody can address. The spelling matches
	// the panel's synthetic reason so the browser shows one message for both
	// halves of the same event.
	ReasonDisconnected = "agent_disconnected"
)

// Errors the manager returns. They are sentinel values so a caller (the
// WebSocket dispatcher) can map them onto the contract's error codes.
var (
	ErrDisabled = errors.New("terminal disabled by local policy")
	ErrLimit    = errors.New("terminal session limit reached")
	ErrNoPTY    = errors.New("no pseudo-terminal is available on this platform")
	ErrNotFound = errors.New("no such terminal session")
	ErrClosed   = errors.New("terminal session is closed")
	ErrTooLarge = errors.New("terminal input exceeds the frame limit")
	ErrBadSize  = errors.New("terminal size must be between 1x1 and 1000x1000")
)

// Options configures a Manager. The zero value is usable: New materialises the
// defaults above.
type Options struct {
	// Enabled is the local switch. It has no default of its own here: the
	// caller passes agentcfg's resolved value, which is ON unless the machine
	// explicitly opted out (ruling 17). A disabled manager refuses every Open.
	Enabled bool
	// Shell is the program a session runs, started as an argv array and never
	// through a command string. Default /bin/sh.
	Shell string
	// MaxSessions is the concurrent-session limit. Default 2, and the package
	// refuses anything above that (agentcfg.MaxTerminalSessions).
	MaxSessions int
	// IdleTimeout closes a session that saw no traffic for that long.
	// Default 15m. A negative value disables the idle reaper.
	IdleTimeout time.Duration
	// MaxLifetime is the hard session lifetime. Default 4h. A negative value
	// disables the lifetime reaper.
	MaxLifetime time.Duration
	// MaxFrame bounds one Write (one term.input frame). Default 64 KiB.
	MaxFrame int
	// ReapInterval is how often the reaper checks the deadlines. Default 30s,
	// clamped to at most a quarter of the shortest deadline so a test can
	// drive it with millisecond timeouts.
	ReapInterval time.Duration
	// Audit receives the metadata-only open/close events. Nil drops them.
	Audit Auditor
	// Log receives the manager's own events; never terminal content.
	Log driver.Logger
	// Now is the clock; nil uses time.Now. Injectable so tests do not sleep.
	Now func() time.Time
	// startPTY is the platform hook (pty_unix.go / pty_unsupported.go). It is
	// a field so tests can substitute a fake process on any platform.
	startPTY func(shell string, env []string, cols, rows uint16) (ptyProcess, error)
}

// Session is one interactive shell. Output and Exited are closed when the
// session ends; a consumer must drain Output until it closes.
type Session interface {
	ID() string
	// Write sends panel input to the PTY. It refuses a payload larger than
	// MaxFrame and a session that is already closing.
	Write(p []byte) (int, error)
	Resize(cols, rows uint16) error
	// Close asks the shell to stop. reason is one of the Reason* constants
	// (empty means ReasonClosed). It is idempotent.
	Close(reason string) error
	// Output carries the PTY's bytes, already split into MaxFrame-sized
	// chunks. Frames are dropped (never buffered without bound) when the
	// consumer cannot keep up.
	Output() <-chan []byte
	// Exited carries exactly one Exit when the shell is gone.
	Exited() <-chan Exit
	BytesIn() int64
	BytesOut() int64
	// Started is when the shell was started; the audit event uses it.
	Started() time.Time
	// PID is the shell's process id (0 when the platform does not expose it).
	// It is diagnostic only: nothing kills a process by pid lookup.
	PID() int
}

// Exit is the outcome of a session.
type Exit struct {
	Code   int
	Reason string
}

// AuditEvent is the metadata of one session lifecycle change. It has no
// content field: the terminal bytes can never reach the audit trail, because
// there is nowhere to put them (design section 2.4, WP-G6 acceptance 6).
type AuditEvent struct {
	Session   string
	Action    string // open | close
	At        time.Time
	DurationS int64
	BytesIn   int64
	BytesOut  int64
	Reason    string
}

// Auditor receives the terminal audit events.
type Auditor interface {
	TerminalEvent(AuditEvent)
}

// AuditorFunc adapts a function to Auditor.
type AuditorFunc func(AuditEvent)

// TerminalEvent implements Auditor.
func (f AuditorFunc) TerminalEvent(e AuditEvent) { f(e) }

// Manager owns the live sessions of one agent process.
type Manager struct {
	opts Options

	// audit is the sink, stored atomically because bootstrap installs it after
	// the manager exists (once the WebSocket channel is up).
	auditor atomic.Pointer[auditSink]

	mu       sync.Mutex
	sessions map[string]*session
	closed   bool
	wg       sync.WaitGroup

	reapStop chan struct{}
	reapDone chan struct{}

	// seq makes an auto-generated session id unique within this process even
	// when two frames arrive in the same nanosecond.
	seq atomic.Uint64

	nowFn func() time.Time
}

// auditSink boxes an Auditor so it can live in an atomic.Pointer.
type auditSink struct{ Auditor }

// New builds a Manager. It never fails because the platform has no PTY: a
// machine without one simply never declares the terminal capability
// (Supported()), and the manager stays inert.
func New(o Options) (*Manager, error) {
	if o.Shell == "" {
		o.Shell = DefaultShell
	}
	if o.MaxSessions <= 0 {
		o.MaxSessions = DefaultMaxSessions
	}
	if o.IdleTimeout == 0 {
		o.IdleTimeout = DefaultIdleTimeout
	}
	if o.MaxLifetime == 0 {
		o.MaxLifetime = DefaultMaxLifetime
	}
	if o.MaxFrame <= 0 {
		o.MaxFrame = DefaultMaxFrame
	}
	if o.ReapInterval <= 0 {
		o.ReapInterval = defaultReapInterval(o.IdleTimeout, o.MaxLifetime)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.startPTY == nil {
		o.startPTY = startPTY
	}
	m := &Manager{
		opts:     o,
		sessions: map[string]*session{},
		nowFn:    o.Now,
		reapStop: make(chan struct{}),
		reapDone: make(chan struct{}),
	}
	if o.Audit != nil {
		m.auditor.Store(&auditSink{Auditor: o.Audit})
	}
	go m.reaper()
	return m, nil
}

// defaultReapInterval keeps the reaper cheap for the production deadlines and
// still able to enforce a millisecond deadline in a test.
func defaultReapInterval(idle, lifetime time.Duration) time.Duration {
	shortest := idle
	if shortest <= 0 || (lifetime > 0 && lifetime < shortest) {
		shortest = lifetime
	}
	if shortest <= 0 {
		return 30 * time.Second
	}
	iv := shortest / 4
	if iv < time.Millisecond {
		iv = time.Millisecond
	}
	if iv > 30*time.Second {
		iv = 30 * time.Second
	}
	return iv
}

// Options returns the materialised options (defaults applied).
func (m *Manager) Options() Options { return m.opts }

// SetAuditor installs (or replaces) the audit sink. bootstrap builds the
// manager at Boot, before the panel channel exists, and installs the event
// frame sink once the WebSocket is up.
func (m *Manager) SetAuditor(a Auditor) {
	if m == nil {
		return
	}
	if a == nil {
		m.auditor.Store(nil)
		return
	}
	m.auditor.Store(&auditSink{Auditor: a})
}

// Enabled reports the local switch.
func (m *Manager) Enabled() bool { return m.opts.Enabled }

// Available reports whether a session could actually be started here: the local
// switch is on and this platform can create a PTY. It is what the capability
// list must use, so a machine without /dev/ptmx never promises a terminal.
func (m *Manager) Available() bool {
	return m != nil && m.opts.Enabled && Supported()
}

// Open starts a session. An empty id is generated. It returns ErrDisabled when
// the local switch is off, ErrLimit when MaxSessions are already running, and
// ErrNoPTY when this platform cannot create a PTY.
func (m *Manager) Open(id string, cols, rows uint16) (Session, error) {
	if m == nil || !m.opts.Enabled {
		return nil, ErrDisabled
	}
	if !Supported() {
		return nil, ErrNoPTY
	}
	cols, rows, err := normalizeSize(cols, rows)
	if err != nil {
		return nil, err
	}
	if id == "" {
		id = m.nextID()
	}
	// The limit and the duplicate check are taken without holding the lock
	// while the PTY starts; they are re-checked under the lock before the
	// session is registered, which is what makes them authoritative.
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, ErrDisabled
	}
	if _, dup := m.sessions[id]; dup {
		m.mu.Unlock()
		return nil, fmt.Errorf("terminal session %q already exists", id)
	}
	if len(m.sessions) >= m.opts.MaxSessions {
		m.mu.Unlock()
		return nil, ErrLimit
	}
	m.mu.Unlock()

	s, err := m.start(id, cols, rows)
	if err != nil {
		return nil, err
	}

	// Register the session and count it in the WaitGroup under the lock that
	// CloseAll takes before it waits. A session therefore either gets in before
	// CloseAll set m.closed (and is closed by it) or sees m.closed and is
	// killed here: no shell can be left behind.
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		_ = s.Close(ReasonAgentShutdown)
		return nil, ErrDisabled
	}
	if _, dup := m.sessions[id]; dup {
		m.mu.Unlock()
		_ = s.Close(ReasonClosed)
		return nil, fmt.Errorf("terminal session %q already exists", id)
	}
	if len(m.sessions) >= m.opts.MaxSessions {
		m.mu.Unlock()
		_ = s.Close(ReasonClosed)
		return nil, ErrLimit
	}
	m.sessions[id] = s
	m.wg.Add(1)
	m.mu.Unlock()

	go m.finalize(s)
	m.audit(AuditEvent{Session: id, Action: "open", At: m.now()})
	m.logf().Infof("terminal: session %s opened (%s %dx%d)", id, m.opts.Shell, cols, rows)
	return s, nil
}

// Get returns a live session.
func (m *Manager) Get(id string) (Session, bool) {
	if m == nil {
		return nil, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return nil, false
	}
	return s, true
}

// Close ends one session. Closing an unknown session is ErrNotFound.
func (m *Manager) Close(id, reason string) error {
	s, ok := m.Get(id)
	if !ok {
		return ErrNotFound
	}
	return s.Close(reason)
}

// CloseAll ends every session and waits for their child processes. It is called
// when the agent exits (and when the panel link goes away), so a shell can
// never outlive the agent. reason is one of the Reason* constants.
func (m *Manager) CloseAll(reason string) {
	if m == nil {
		return
	}
	if reason == "" {
		reason = ReasonAgentShutdown
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	live := make([]*session, 0, len(m.sessions))
	for _, s := range m.sessions {
		live = append(live, s)
	}
	m.mu.Unlock()

	for _, s := range live {
		_ = s.Close(reason)
	}
	m.wg.Wait()

	close(m.reapStop)
	<-m.reapDone
	if n := len(live); n > 0 {
		m.logf().Infof("terminal: closed %d session(s): %s", n, reason)
	}
}

// Sessions lists the live session ids, sorted.
func (m *Manager) Sessions() []string {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// start builds the PTY, the child process and the reader. It is the only place
// that touches the platform hook.
func (m *Manager) start(id string, cols, rows uint16) (*session, error) {
	now := m.now()
	ctx, cancel := context.WithCancel(context.Background())
	proc, err := m.opts.startPTY(m.opts.Shell, SanitizeEnv(), cols, rows)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("terminal: starting %s: %w", m.opts.Shell, err)
	}
	s := &session{
		mgr:     m,
		id:      id,
		ctx:     ctx,
		cancel:  cancel,
		proc:    proc,
		output:  make(chan []byte, 64),
		exited:  make(chan Exit, 1),
		done:    make(chan struct{}),
		started: now,
		reason:  ReasonExit,
	}
	s.activity.Store(now.UnixNano())
	go s.readLoop()
	return s, nil
}

// finalize waits for the child, records the exit, removes the session and
// reports the audit event. It is one goroutine per session, bounded by the
// session limit.
func (m *Manager) finalize(s *session) {
	defer m.wg.Done()
	err := s.proc.wait()
	code := exitCode(err)
	reason := s.closeReason()
	close(s.done)

	// The audit record goes out before the session leaves the registry and before the
	// exit is announced, so whoever sees the session gone (or the exit) can rely on the
	// close event having been delivered.
	ended := m.now()
	m.audit(AuditEvent{
		Session:   s.id,
		Action:    "close",
		At:        ended,
		DurationS: int64(ended.Sub(s.started) / time.Second),
		BytesIn:   s.BytesIn(),
		BytesOut:  s.BytesOut(),
		Reason:    reason,
	})

	m.mu.Lock()
	if cur, ok := m.sessions[s.id]; ok && cur == s {
		delete(m.sessions, s.id)
	}
	m.mu.Unlock()

	select {
	case s.exited <- Exit{Code: code, Reason: reason}:
	default:
	}
	close(s.exited)
	_ = s.proc.close()

	m.logf().Infof("terminal: session %s closed: %s (code %d, %d in / %d out, %s)",
		s.id, reason, code, s.BytesIn(), s.BytesOut(), ended.Sub(s.started).Round(time.Second))
}

// reaper closes sessions that hit the idle or the lifetime deadline.
func (m *Manager) reaper() {
	defer close(m.reapDone)
	t := time.NewTicker(m.opts.ReapInterval)
	defer t.Stop()
	for {
		select {
		case <-m.reapStop:
			return
		case <-t.C:
			m.reapOnce()
		}
	}
}

func (m *Manager) reapOnce() {
	now := m.now()
	m.mu.Lock()
	live := make([]*session, 0, len(m.sessions))
	for _, s := range m.sessions {
		live = append(live, s)
	}
	m.mu.Unlock()
	for _, s := range live {
		switch {
		case m.opts.MaxLifetime > 0 && now.Sub(s.started) >= m.opts.MaxLifetime:
			m.logf().Infof("terminal: session %s hit the %s lifetime limit", s.id, m.opts.MaxLifetime)
			_ = s.Close(ReasonMaxLifetime)
		case m.opts.IdleTimeout > 0 && now.UnixNano()-s.lastActivity() >= int64(m.opts.IdleTimeout):
			m.logf().Infof("terminal: session %s was idle for %s", s.id, m.opts.IdleTimeout)
			_ = s.Close(ReasonIdleTimeout)
		}
	}
}

// RecoverOrphans is the start-up hook for shells a previous agent run left
// behind. The agent has no way to recognise "a shell that belonged to a dead
// agent" safely: matching a pid would need the pid to be recorded and then
// still be the same process (pid reuse), and killing by process name is
// forbidden. What the agent does instead is prevent the orphan in the first
// place: every session runs in its own process group and CloseAll kills that
// group, and a normal exit always runs CloseAll. A hard kill (SIGKILL of the
// agent) can still leave a shell; it is reported here so an operator sees it.
//
// The method exists so the shutdown/start-up path has one documented answer,
// and it never kills anything.
func (m *Manager) RecoverOrphans() int {
	m.logf().Debugf("terminal: no orphan recovery is performed (shells run in their own process group and CloseAll reaps them); a SIGKILLed agent may leave a shell behind")
	return 0
}

// ---- session ---------------------------------------------------------------

type session struct {
	mgr    *Manager
	id     string
	ctx    context.Context
	cancel context.CancelFunc
	proc   ptyProcess

	output   chan []byte
	exited   chan Exit
	done     chan struct{}
	started  time.Time
	activity atomic.Int64

	bytesIn  atomic.Int64
	bytesOut atomic.Int64

	mu       sync.Mutex
	reason   string
	killOnce sync.Once
	closed   atomic.Bool
}

var _ Session = (*session)(nil)

func (s *session) ID() string { return s.id }

func (s *session) Started() time.Time { return s.started }

func (s *session) PID() int { return s.proc.pid() }

func (s *session) BytesIn() int64 { return s.bytesIn.Load() }

func (s *session) BytesOut() int64 { return s.bytesOut.Load() }

func (s *session) Output() <-chan []byte { return s.output }

func (s *session) Exited() <-chan Exit { return s.exited }

func (s *session) Write(p []byte) (int, error) {
	if s.closed.Load() {
		return 0, ErrClosed
	}
	if len(p) > s.mgr.opts.MaxFrame {
		return 0, fmt.Errorf("%w: %d bytes (limit %d)", ErrTooLarge, len(p), s.mgr.opts.MaxFrame)
	}
	if len(p) == 0 {
		return 0, nil
	}
	n, err := s.proc.write(p)
	if n > 0 {
		s.bytesIn.Add(int64(n))
		s.touch()
	}
	if err != nil {
		return n, fmt.Errorf("terminal: writing to session %s: %w", s.id, err)
	}
	return n, nil
}

func (s *session) Resize(cols, rows uint16) error {
	if s.closed.Load() {
		return ErrClosed
	}
	cols, rows, err := normalizeSize(cols, rows)
	if err != nil {
		return err
	}
	if err := s.proc.resize(cols, rows); err != nil {
		return fmt.Errorf("terminal: resizing session %s: %w", s.id, err)
	}
	s.touch()
	return nil
}

// Close stops the session. It is idempotent: the first reason wins.
func (s *session) Close(reason string) error {
	if reason == "" {
		reason = ReasonClosed
	}
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	s.setReason(reason)
	s.touch()
	s.cancel()
	s.kill()
	return nil
}

// kill terminates the shell's process group: TERM first, then KILL if it is
// still alive after a short grace period. It returns immediately; the child is
// reaped by finalize, and CloseAll waits for that.
func (s *session) kill() {
	s.killOnce.Do(func() {
		if s.proc.pid() <= 0 {
			return
		}
		_ = s.proc.signalTerm()
		go func() {
			select {
			case <-s.done:
				// The shell stopped on TERM.
			case <-time.After(killGrace):
				_ = s.proc.signalKill()
			}
		}()
	})
}

// killGrace is how long a shell may take to honour SIGTERM before the session
// escalates to SIGKILL.
const killGrace = 2 * time.Second

// readLoop pumps the PTY into the output channel. Frames are dropped when the
// consumer is slower than the shell, which is correct for a live stream.
func (s *session) readLoop() {
	defer close(s.output)
	max := s.mgr.opts.MaxFrame
	buf := make([]byte, max)
	for {
		n, err := s.proc.read(buf)
		if n > 0 {
			s.bytesOut.Add(int64(n))
			s.touch()
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			select {
			case s.output <- chunk:
			case <-s.ctx.Done():
				return
			default:
				// The consumer is behind: drop this chunk rather than block
				// the shell. The panel re-reads the screen on the next frame.
				s.mgr.logf().Debugf("terminal: session %s dropped %d output byte(s) (consumer behind)", s.id, n)
			}
		}
		if err != nil {
			if err != io.EOF && !errors.Is(err, os.ErrClosed) && !s.closed.Load() {
				s.mgr.logf().Debugf("terminal: session %s read: %v", s.id, err)
			}
			return
		}
		if s.closed.Load() {
			return
		}
	}
}

func (s *session) touch() { s.activity.Store(s.mgr.now().UnixNano()) }

func (s *session) lastActivity() int64 { return s.activity.Load() }

func (s *session) setReason(r string) {
	s.mu.Lock()
	s.reason = r
	s.mu.Unlock()
}

func (s *session) closeReason() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reason == "" {
		return ReasonExit
	}
	return s.reason
}

// ---- helpers ---------------------------------------------------------------

// normalizeSize bounds a terminal size. A zero size is a protocol violation
// (the panel always sends cols and rows); it is refused rather than guessed.
func normalizeSize(cols, rows uint16) (uint16, uint16, error) {
	if cols == 0 || rows == 0 || cols > 1000 || rows > 1000 {
		return 0, 0, fmt.Errorf("%w: %dx%d", ErrBadSize, cols, rows)
	}
	return cols, rows, nil
}

// exitCode turns a Wait error into the shell's exit status. A killed process
// reports -1, which is what the contract's term.exit can carry.
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

func (m *Manager) nextID() string {
	return fmt.Sprintf("t%d-%d", os.Getpid(), m.seq.Add(1))
}

func (m *Manager) now() time.Time {
	if m.nowFn != nil {
		return m.nowFn()
	}
	return time.Now()
}

func (m *Manager) audit(e AuditEvent) {
	s := m.auditor.Load()
	if s == nil || s.Auditor == nil {
		return
	}
	// The auditor is called outside the manager lock and never with content:
	// AuditEvent has no content field.
	s.Auditor.TerminalEvent(e)
}

func (m *Manager) logf() driver.Logger {
	if m.opts.Log == nil {
		return nopLog{}
	}
	return m.opts.Log
}

type nopLog struct{}

func (nopLog) Debugf(string, ...any) {}
func (nopLog) Infof(string, ...any)  {}
func (nopLog) Warnf(string, ...any)  {}
func (nopLog) Errorf(string, ...any) {}

// ShellName reports the shell a session runs, for a log line.
func (m *Manager) ShellName() string { return m.opts.Shell }

// String renders the manager's local state for a log line.
func (m *Manager) String() string {
	if m == nil {
		return "terminal(<nil>)"
	}
	state := "off"
	if m.opts.Enabled {
		state = "on"
	}
	if !Supported() {
		state += ", unsupported"
	}
	return fmt.Sprintf("terminal(%s, %s, %d session(s))", state, m.opts.Shell, len(m.Sessions()))
}
