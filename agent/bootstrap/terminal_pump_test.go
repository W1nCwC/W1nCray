package bootstrap

// These tests cover the agent terminal "output pump" (WP-G6, TERM-PUMP): the
// frames the agent must send after a term.open (term.opened, term.data,
// term.exit) and the session lifetime rules around them. They drive the
// adapter with a fake session and a fake frame outlet, so they run on any
// platform; the real-/bin/sh end-to-end case at the bottom skips without a PTY.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/W1nCwC/W1nCray/agent/terminal"
	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// ---- fakes -----------------------------------------------------------------

// fakeSession is a terminal.Session without a PTY: the test decides what the
// "shell" produced and when it exited. Its lifecycle mirrors the manager's:
// Output is closed first, then Exited carries the single outcome.
type fakeSession struct {
	id string

	mu     sync.Mutex
	ended  bool
	reason string

	output chan []byte
	exited chan terminal.Exit
}

var _ terminal.Session = (*fakeSession)(nil)

func newFakeSession(id string) *fakeSession {
	return &fakeSession{
		id:     id,
		output: make(chan []byte, 64),
		exited: make(chan terminal.Exit, 1),
	}
}

func (s *fakeSession) ID() string                     { return s.id }
func (s *fakeSession) Write(p []byte) (int, error)    { return len(p), nil }
func (s *fakeSession) Resize(cols, rows uint16) error { return nil }
func (s *fakeSession) Output() <-chan []byte          { return s.output }
func (s *fakeSession) Exited() <-chan terminal.Exit   { return s.exited }
func (s *fakeSession) BytesIn() int64                 { return 0 }
func (s *fakeSession) BytesOut() int64                { return 0 }
func (s *fakeSession) Started() time.Time             { return time.Time{} }
func (s *fakeSession) PID() int                       { return 0 }

// Close ends the session like the manager does: a killed shell reports no exit
// code, which the contract carries as -1.
func (s *fakeSession) Close(reason string) error {
	s.finish(-1, reason)
	return nil
}

// finish ends the session exactly once, whatever the reason.
func (s *fakeSession) finish(code int, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		return
	}
	s.ended = true
	s.reason = reason
	close(s.output)
	select {
	case s.exited <- terminal.Exit{Code: code, Reason: reason}:
	default:
	}
	close(s.exited)
}

func (s *fakeSession) closeReason() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reason
}

// fakeManager is a terminal manager over fake sessions.
type fakeManager struct {
	mu       sync.Mutex
	sessions map[string]*fakeSession
	openErr  error
}

var _ termManager = (*fakeManager)(nil)

func newFakeManager() *fakeManager {
	return &fakeManager{sessions: map[string]*fakeSession{}}
}

func (m *fakeManager) Open(id string, cols, rows uint16) (terminal.Session, error) {
	if m.openErr != nil {
		return nil, m.openErr
	}
	s := newFakeSession(id)
	m.mu.Lock()
	m.sessions[id] = s
	m.mu.Unlock()
	return s, nil
}

func (m *fakeManager) Get(id string) (terminal.Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return nil, false
	}
	return s, true
}

func (m *fakeManager) Close(id, reason string) error {
	s, ok := m.Get(id)
	if !ok {
		return terminal.ErrNotFound
	}
	return s.Close(reason)
}

func (m *fakeManager) Sessions() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func (m *fakeManager) session(id string) *fakeSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[id]
}

// recordedFrame is one frame the adapter sent.
type recordedFrame struct {
	t    string
	body []byte
}

// frameRecorder is the fake panel side: it records every frame and can be told
// to fail, which is how a dropped connection is simulated.
type frameRecorder struct {
	mu     sync.Mutex
	frames []recordedFrame
	err    error
}

func (r *frameRecorder) send(t string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	r.frames = append(r.frames, recordedFrame{t: t, body: raw})
	return nil
}

func (r *frameRecorder) failWith(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.err = err
}

func (r *frameRecorder) snapshot() []recordedFrame {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recordedFrame(nil), r.frames...)
}

// waitForOutput polls the recorded term.data frames until the decoded stream
// contains want, or the deadline passes (it then returns what it saw).
func (r *frameRecorder) waitForOutput(t *testing.T, want string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	got := ""
	for {
		var b strings.Builder
		for _, fr := range r.snapshot() {
			if fr.t == wsproto.TypeTermData {
				b.Write(decodeData(t, fr))
			}
		}
		got = b.String()
		if strings.Contains(got, want) || time.Now().After(deadline) {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// ---- helpers ---------------------------------------------------------------

// waitPumps blocks until every output pump returned, which is how a test
// proves that a closed session leaves no goroutine behind.
func waitPumps(t *testing.T, term *wsTerminal, timeout time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		term.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Fatal("a terminal output pump did not exit")
	}
}

func frameTypes(frames []recordedFrame) []string {
	out := make([]string, 0, len(frames))
	for _, f := range frames {
		out = append(out, f.t)
	}
	return out
}

func mustDecode(t *testing.T, fr recordedFrame, out any) {
	t.Helper()
	if err := json.Unmarshal(fr.body, out); err != nil {
		t.Fatalf("decode %s payload %s: %v", fr.t, fr.body, err)
	}
}

func decodeData(t *testing.T, fr recordedFrame) []byte {
	t.Helper()
	var body termDataBody
	mustDecode(t, fr, &body)
	raw, err := base64.StdEncoding.DecodeString(body.Data)
	if err != nil {
		t.Fatalf("term.data carries invalid base64 %q: %v", body.Data, err)
	}
	return raw
}

// ---- the frame order -------------------------------------------------------

// TestTerminalPumpSendsOpenedThenDataThenOneExit covers the contract's frame
// order: term.opened comes first, the PTY bytes follow in order as term.data,
// and exactly one term.exit closes the session.
func TestTerminalPumpSendsOpenedThenDataThenOneExit(t *testing.T) {
	m := newFakeManager()
	rec := &frameRecorder{}
	term := &wsTerminal{m: m, send: rec.send, log: nopLog{}}

	if err := term.Open("s1", 80, 24); err != nil {
		t.Fatalf("Open: %v", err)
	}
	s := m.session("s1")
	s.output <- []byte("first ")
	s.output <- []byte("second")
	s.finish(0, terminal.ReasonExit)
	waitPumps(t, term, 5*time.Second)

	frames := rec.snapshot()
	if got := frameTypes(frames); len(got) != 4 {
		t.Fatalf("frames = %v, want term.opened + 2 term.data + term.exit", got)
	}
	if frames[0].t != wsproto.TypeTermOpened {
		t.Fatalf("first frame = %q, want term.opened before any term.data", frames[0].t)
	}
	var opened termOpenedBody
	mustDecode(t, frames[0], &opened)
	if opened.Session != "s1" {
		t.Errorf("term.opened session = %q, want s1", opened.Session)
	}
	for i, want := range []string{"first ", "second"} {
		fr := frames[1+i]
		if fr.t != wsproto.TypeTermData {
			t.Fatalf("frame %d = %q, want term.data", i+1, fr.t)
		}
		if got := string(decodeData(t, fr)); got != want {
			t.Errorf("term.data[%d] = %q, want %q", i, got, want)
		}
	}
	if frames[3].t != wsproto.TypeTermExit {
		t.Fatalf("last frame = %q, want term.exit", frames[3].t)
	}
	var exit termExitBody
	mustDecode(t, frames[3], &exit)
	if exit.Session != "s1" || exit.Code != 0 || exit.Reason != terminal.ReasonExit {
		t.Errorf("term.exit = %+v", exit)
	}
}

// TestTerminalPumpChunksLargeOutputInOrder covers the frame-size rule: one
// term.data never carries more than termDataChunk raw bytes (so its base64
// stays far below the 256 KiB limit), and the reassembled stream is byte-for-
// byte the PTY stream.
func TestTerminalPumpChunksLargeOutputInOrder(t *testing.T) {
	m := newFakeManager()
	rec := &frameRecorder{}
	term := &wsTerminal{m: m, send: rec.send, log: nopLog{}}
	if err := term.Open("s1", 80, 24); err != nil {
		t.Fatalf("Open: %v", err)
	}
	payload := make([]byte, 3*termDataChunk+17)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	s := m.session("s1")
	s.output <- payload
	s.finish(0, terminal.ReasonExit)
	waitPumps(t, term, 5*time.Second)

	frames := rec.snapshot()
	if len(frames) < 2 || frames[0].t != wsproto.TypeTermOpened || frames[len(frames)-1].t != wsproto.TypeTermExit {
		t.Fatalf("frames = %v", frameTypes(frames))
	}
	var joined []byte
	parts := 0
	for _, fr := range frames[1 : len(frames)-1] {
		if fr.t != wsproto.TypeTermData {
			t.Fatalf("frame %q between opened and exit", fr.t)
		}
		raw := decodeData(t, fr)
		if len(raw) > termDataChunk {
			t.Fatalf("one term.data carried %d raw bytes, limit %d", len(raw), termDataChunk)
		}
		joined = append(joined, raw...)
		parts++
	}
	if parts != 4 {
		t.Errorf("term.data frames = %d, want 4 (three full chunks and the tail)", parts)
	}
	if !bytes.Equal(joined, payload) {
		t.Errorf("reassembled %d bytes differ from the %d PTY bytes", len(joined), len(payload))
	}
}

// TestTerminalPumpSplitsOnBytesNotRunes covers the UTF-8 boundary rule: the
// split is by byte, exactly like a PTY read boundary, so a multi-byte rune can
// span two frames. The browser reassembles with a streaming decoder; the pump
// must not try to keep characters whole (it has no idea where the stream ends).
func TestTerminalPumpSplitsOnBytesNotRunes(t *testing.T) {
	m := newFakeManager()
	rec := &frameRecorder{}
	term := &wsTerminal{m: m, send: rec.send, log: nopLog{}}
	if err := term.Open("s1", 80, 24); err != nil {
		t.Fatalf("Open: %v", err)
	}
	// One byte short of the split, then a 3-byte rune: the byte split lands
	// inside the rune.
	payload := bytes.Repeat([]byte("a"), termDataChunk-1)
	payload = append(payload, []byte("→")...)
	payload = append(payload, bytes.Repeat([]byte("é"), 32)...)

	s := m.session("s1")
	s.output <- payload
	s.finish(0, terminal.ReasonExit)
	waitPumps(t, term, 5*time.Second)

	frames := rec.snapshot()
	if len(frames) < 3 {
		t.Fatalf("frames = %v", frameTypes(frames))
	}
	first := decodeData(t, frames[1])
	if utf8.Valid(first) {
		t.Fatal("the first term.data ended on a character boundary: the pump must split on bytes")
	}
	var joined []byte
	for _, fr := range frames[1 : len(frames)-1] {
		joined = append(joined, decodeData(t, fr)...)
	}
	if !bytes.Equal(joined, payload) {
		t.Error("the reassembled stream differs from the PTY stream")
	}
	if !utf8.Valid(joined) {
		t.Error("the reassembled stream is not valid UTF-8")
	}
}

// TestTerminalPumpSendsOneExitAfterTheLastData pins the exit contract: exactly
// one term.exit, carrying the shell's code, after the last term.data.
func TestTerminalPumpSendsOneExitAfterTheLastData(t *testing.T) {
	m := newFakeManager()
	rec := &frameRecorder{}
	term := &wsTerminal{m: m, send: rec.send, log: nopLog{}}
	if err := term.Open("s1", 80, 24); err != nil {
		t.Fatalf("Open: %v", err)
	}
	s := m.session("s1")
	s.output <- []byte("bye")
	s.finish(7, terminal.ReasonExit)
	waitPumps(t, term, 5*time.Second)

	frames := rec.snapshot()
	exits := 0
	for _, fr := range frames {
		if fr.t == wsproto.TypeTermExit {
			exits++
		}
	}
	if exits != 1 {
		t.Fatalf("term.exit frames = %d, want exactly 1", exits)
	}
	last := frames[len(frames)-1]
	if last.t != wsproto.TypeTermExit {
		t.Fatalf("last frame = %q, want term.exit after the last term.data", last.t)
	}
	var exit termExitBody
	mustDecode(t, last, &exit)
	if exit.Code != 7 || exit.Reason != terminal.ReasonExit {
		t.Errorf("term.exit = %+v, want code 7 reason %q", exit, terminal.ReasonExit)
	}
}

// TestTerminalPumpExitsAfterClose covers the panel-initiated end: term.close
// closes the session, the pump reports the exit once and the goroutine is gone.
func TestTerminalPumpExitsAfterClose(t *testing.T) {
	m := newFakeManager()
	rec := &frameRecorder{}
	term := &wsTerminal{m: m, send: rec.send, log: nopLog{}}
	if err := term.Open("s1", 80, 24); err != nil {
		t.Fatalf("Open: %v", err)
	}
	s := m.session("s1")
	s.output <- []byte("partial")
	if err := term.Close("s1"); err != nil {
		t.Fatalf("Close: %v", err)
	}
	waitPumps(t, term, 5*time.Second)

	if got := s.closeReason(); got != terminal.ReasonClosed {
		t.Errorf("close reason = %q, want %q", got, terminal.ReasonClosed)
	}
	frames := rec.snapshot()
	last := frames[len(frames)-1]
	if last.t != wsproto.TypeTermExit {
		t.Fatalf("last frame = %q, want term.exit", last.t)
	}
	var exit termExitBody
	mustDecode(t, last, &exit)
	if exit.Reason != terminal.ReasonClosed {
		t.Errorf("term.exit reason = %q, want %q", exit.Reason, terminal.ReasonClosed)
	}
}

// ---- failure paths ---------------------------------------------------------

// TestTerminalPumpClosesTheSessionWhenSendingFails covers the dead-link rule: a
// send that fails means nobody will receive the output, so the session is
// closed (reason agent_disconnected) instead of buffering into the void.
func TestTerminalPumpClosesTheSessionWhenSendingFails(t *testing.T) {
	m := newFakeManager()
	rec := &frameRecorder{}
	term := &wsTerminal{m: m, send: rec.send, log: nopLog{}}
	if err := term.Open("s1", 80, 24); err != nil {
		t.Fatalf("Open: %v", err)
	}
	s := m.session("s1")
	rec.failWith(errors.New("ws: not connected"))
	s.output <- []byte("nobody will receive this")
	waitPumps(t, term, 5*time.Second)

	if got := s.closeReason(); got != terminal.ReasonDisconnected {
		t.Errorf("close reason = %q, want %q", got, terminal.ReasonDisconnected)
	}
	if types := frameTypes(rec.snapshot()); len(types) != 1 || types[0] != wsproto.TypeTermOpened {
		t.Errorf("frames after the failed send = %v, want only the term.opened", types)
	}
}

// TestTerminalOpenClosesTheSessionWhenOpenedCannotBeSent covers the same rule
// for the announcement: a session whose term.opened never left the machine must
// not keep a shell alive.
func TestTerminalOpenClosesTheSessionWhenOpenedCannotBeSent(t *testing.T) {
	m := newFakeManager()
	rec := &frameRecorder{err: errors.New("ws: not connected")}
	term := &wsTerminal{m: m, send: rec.send, log: nopLog{}}

	if err := term.Open("s1", 80, 24); err == nil {
		t.Fatal("Open succeeded with a dead link")
	}
	if got := m.session("s1").closeReason(); got != terminal.ReasonDisconnected {
		t.Errorf("close reason = %q, want %q", got, terminal.ReasonDisconnected)
	}
	waitPumps(t, term, time.Second)
}

// TestTerminalOpenRefusedSendsNoOpenedFrame covers the refusal rule: a disabled
// terminal, the session limit and a PTY that will not start are the
// dispatcher's term.error, never a term.opened.
func TestTerminalOpenRefusedSendsNoOpenedFrame(t *testing.T) {
	m := newFakeManager()
	m.openErr = terminal.ErrLimit
	rec := &frameRecorder{}
	term := &wsTerminal{m: m, send: rec.send, log: nopLog{}}

	if err := term.Open("s1", 80, 24); !errors.Is(err, terminal.ErrLimit) {
		t.Fatalf("Open = %v, want ErrLimit", err)
	}
	if err := term.Open("s2", 0, 24); err == nil {
		t.Error("Open accepted a zero size")
	}
	if frames := rec.snapshot(); len(frames) != 0 {
		t.Errorf("a refused Open sent %v", frameTypes(frames))
	}
	waitPumps(t, term, time.Second)
}

// TestTerminalDisconnectedClosesEveryLiveSession covers the reconnect rule: a
// terminal session does not survive the connection that opened it, so every
// live session is closed (and its pump exits) when the socket ends. CloseAll is
// not the tool here: it latches the manager shut for the next connection.
func TestTerminalDisconnectedClosesEveryLiveSession(t *testing.T) {
	m := newFakeManager()
	rec := &frameRecorder{}
	term := &wsTerminal{m: m, send: rec.send, log: nopLog{}}
	for _, id := range []string{"a", "b"} {
		if err := term.Open(id, 80, 24); err != nil {
			t.Fatalf("Open %s: %v", id, err)
		}
	}
	term.Disconnected()
	waitPumps(t, term, 5*time.Second)

	for _, id := range []string{"a", "b"} {
		if got := m.session(id).closeReason(); got != terminal.ReasonDisconnected {
			t.Errorf("session %s close reason = %q, want %q", id, got, terminal.ReasonDisconnected)
		}
	}
	exits := map[string]int{}
	for _, fr := range rec.snapshot() {
		if fr.t != wsproto.TypeTermExit {
			continue
		}
		var exit termExitBody
		mustDecode(t, fr, &exit)
		exits[exit.Session]++
		if exit.Reason != terminal.ReasonDisconnected {
			t.Errorf("term.exit for %s = %+v", exit.Session, exit)
		}
	}
	if exits["a"] != 1 || exits["b"] != 1 {
		t.Errorf("term.exit counts = %v, want one per session", exits)
	}
}

// ---- the real shell (Linux only) -------------------------------------------

// TestTerminalPumpEndToEndRealShell is the end-to-end case: a real /bin/sh
// under a real PTY, driven through the adapter exactly like the dispatcher
// does. It sends "echo W1NCRAY_OK", expects that marker in a term.data, then
// sends "exit" and expects a term.exit after the last data frame.
//
// It needs a PTY, so it skips on Windows and on any kernel without /dev/ptmx
// (the Linux test machine runs it).
func TestTerminalPumpEndToEndRealShell(t *testing.T) {
	if !terminal.Supported() {
		t.Skip("no PTY on this platform: the real-shell pump test runs on the Linux test machine")
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skipf("/bin/sh is not available: %v", err)
	}
	mgr, err := terminal.New(terminal.Options{
		Enabled:     true,
		Shell:       "/bin/sh",
		MaxSessions: 1,
		IdleTimeout: time.Minute,
		Log:         nopLog{},
	})
	if err != nil {
		t.Fatalf("terminal.New: %v", err)
	}
	defer mgr.CloseAll(terminal.ReasonAgentShutdown)

	rec := &frameRecorder{}
	term := &wsTerminal{m: mgr, send: rec.send, log: nopLog{}}
	if err := term.Open("e2e", 100, 30); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if types := frameTypes(rec.snapshot()); len(types) != 1 || types[0] != wsproto.TypeTermOpened {
		t.Fatalf("frames after Open = %v, want a single term.opened first", types)
	}
	if err := term.Input("e2e", []byte("echo W1NCRAY_OK\n")); err != nil {
		t.Fatalf("Input: %v", err)
	}
	out := rec.waitForOutput(t, "W1NCRAY_OK", 20*time.Second)
	if !strings.Contains(out, "W1NCRAY_OK") {
		t.Fatalf("no term.data carried the marker; output so far:\n%s", out)
	}
	if err := term.Input("e2e", []byte("exit\n")); err != nil {
		t.Fatalf("Input exit: %v", err)
	}
	waitPumps(t, term, 20*time.Second)

	frames := rec.snapshot()
	last := frames[len(frames)-1]
	if last.t != wsproto.TypeTermExit {
		t.Fatalf("last frame = %q, want term.exit after the last term.data", last.t)
	}
	var exit termExitBody
	mustDecode(t, last, &exit)
	if exit.Session != "e2e" {
		t.Errorf("term.exit session = %q, want e2e", exit.Session)
	}
	if exit.Code != 0 {
		t.Errorf("term.exit code = %d, want 0 for the exit builtin", exit.Code)
	}
	exits := 0
	for _, fr := range frames {
		if fr.t == wsproto.TypeTermExit {
			exits++
		}
	}
	if exits != 1 {
		t.Errorf("term.exit frames = %d, want exactly 1", exits)
	}
}

// TestTerminalPumpExitsOnCloseAll covers the shutdown rule on a real PTY:
// CloseAll ends the shell, the pump reports the shutdown and the goroutine is
// gone (no leak on the way out). It needs a PTY and skips elsewhere.
func TestTerminalPumpExitsOnCloseAll(t *testing.T) {
	if !terminal.Supported() {
		t.Skip("no PTY on this platform: the CloseAll pump test runs on the Linux test machine")
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skipf("/bin/sh is not available: %v", err)
	}
	mgr, err := terminal.New(terminal.Options{
		Enabled:     true,
		Shell:       "/bin/sh",
		MaxSessions: 1,
		IdleTimeout: time.Minute,
		Log:         nopLog{},
	})
	if err != nil {
		t.Fatalf("terminal.New: %v", err)
	}
	rec := &frameRecorder{}
	term := &wsTerminal{m: mgr, send: rec.send, log: nopLog{}}
	if err := term.Open("bye", 100, 30); err != nil {
		t.Fatalf("Open: %v", err)
	}

	mgr.CloseAll(terminal.ReasonAgentShutdown)
	waitPumps(t, term, 20*time.Second)

	frames := rec.snapshot()
	last := frames[len(frames)-1]
	if last.t != wsproto.TypeTermExit {
		t.Fatalf("last frame = %q, want term.exit", last.t)
	}
	var exit termExitBody
	mustDecode(t, last, &exit)
	if exit.Reason != terminal.ReasonAgentShutdown {
		t.Errorf("term.exit reason = %q, want %q", exit.Reason, terminal.ReasonAgentShutdown)
	}
}
