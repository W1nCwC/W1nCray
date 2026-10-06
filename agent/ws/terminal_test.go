package ws

import (
	"encoding/base64"
	"errors"
	"sync"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// stubTerminal records the frames the dispatcher routed to it. It is the
// dispatcher-side half of WP-G6: agent/terminal owns the session rules, this
// proves the frames reach it with the payload the contract prescribes.
type stubTerminal struct {
	mu      sync.Mutex
	opens   []termCall
	inputs  [][]byte
	resizes []termCall
	closes  []string
	err     error
}

type termCall struct {
	session string
	cols    int
	rows    int
}

func (s *stubTerminal) Open(session string, cols, rows int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.opens = append(s.opens, termCall{session, cols, rows})
	return s.err
}

func (s *stubTerminal) Input(session string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inputs = append(s.inputs, append([]byte(nil), data...))
	return s.err
}

func (s *stubTerminal) Resize(session string, cols, rows int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resizes = append(s.resizes, termCall{session, cols, rows})
	return s.err
}

func (s *stubTerminal) Close(session string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closes = append(s.closes, session)
	return s.err
}

func (s *stubTerminal) snapshot() (opens, resizes []termCall, inputs [][]byte, closes []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]termCall(nil), s.opens...), append([]termCall(nil), s.resizes...),
		append([][]byte(nil), s.inputs...), append([]string(nil), s.closes...)
}

// TestTermFramesReachTheTerminalSink covers the happy path of the term.*
// routing: open/input/resize/close reach the sink, and term.input carries the
// DECODED bytes (the contract base64-encodes terminal data inside d).
func TestTermFramesReachTheTerminalSink(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	term := &stubTerminal{}
	ag := newAgentUnderTest(t, ts, AgentOptions{Terminal: term}, Options{})
	cancel, _ := runAgent(t, ag)
	defer cancel()

	tc, _ := handshake(t, ts, "session-1", 5, 15)
	tc.sendType(t, wsproto.TypeTermOpen, "t1", map[string]any{"session": "sess-1", "cols": 120, "rows": 40})
	tc.sendType(t, wsproto.TypeTermInput, "t2", map[string]any{"session": "sess-1", "data": base64.StdEncoding.EncodeToString([]byte("ls /\r"))})
	tc.sendType(t, wsproto.TypeTermResize, "t3", map[string]any{"session": "sess-1", "cols": 80, "rows": 24})
	tc.sendType(t, wsproto.TypeTermClose, "t4", map[string]any{"session": "sess-1"})
	// The dispatcher answers nothing on success; a ping after the frames is
	// the barrier that proves they were all processed (one reader goroutine).
	tc.sendType(t, wsproto.TypePing, "", nil)
	tc.recvType(t, wsproto.TypePong)

	opens, resizes, inputs, closes := term.snapshot()
	if len(opens) != 1 || opens[0] != (termCall{"sess-1", 120, 40}) {
		t.Errorf("opens = %+v", opens)
	}
	if len(inputs) != 1 || string(inputs[0]) != "ls /\r" {
		t.Errorf("inputs = %q, want the decoded bytes", inputs)
	}
	if len(resizes) != 1 || resizes[0] != (termCall{"sess-1", 80, 24}) {
		t.Errorf("resizes = %+v", resizes)
	}
	if len(closes) != 1 || closes[0] != "sess-1" {
		t.Errorf("closes = %v", closes)
	}
}

// TestTermInputRefusesInvalidBase64 covers the payload rule: the contract
// carries base64, so a frame that is not base64 is answered with an error
// frame instead of feeding garbage to the shell.
func TestTermInputRefusesInvalidBase64(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	term := &stubTerminal{}
	ag := newAgentUnderTest(t, ts, AgentOptions{Terminal: term}, Options{})
	cancel, _ := runAgent(t, ag)
	defer cancel()

	tc, _ := handshake(t, ts, "session-1", 5, 15)
	tc.sendType(t, wsproto.TypeTermInput, "t1", map[string]any{"session": "sess-1", "data": "not base64!!"})
	env := tc.recvType(t, wsproto.TypeError)
	var body wsproto.ErrorBody
	decodeInto(t, env, &body)
	if body.Code != wsproto.ErrCodeBadPayload {
		t.Errorf("error code = %q, want bad_payload", body.Code)
	}
	if _, _, inputs, _ := term.snapshot(); len(inputs) != 0 {
		t.Errorf("the sink received %q despite the bad payload", inputs)
	}
}

// TestTermErrorFromTheSinkIsReported covers the failure path: a refused session
// (limit reached, no such session, disabled) becomes term.error with the
// sink's message, so the panel can tell what happened.
func TestTermErrorFromTheSinkIsReported(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	term := &stubTerminal{err: errors.New("terminal session limit reached")}
	ag := newAgentUnderTest(t, ts, AgentOptions{Terminal: term}, Options{})
	cancel, _ := runAgent(t, ag)
	defer cancel()

	tc, _ := handshake(t, ts, "session-1", 5, 15)
	tc.sendType(t, wsproto.TypeTermOpen, "t1", map[string]any{"session": "sess-1", "cols": 80, "rows": 24})
	env := tc.recvType(t, wsproto.TypeTermError)
	var body struct {
		Session string `json:"session"`
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	decodeInto(t, env, &body)
	if body.Code != "terminal_error" {
		t.Errorf("term.error code = %q, want terminal_error", body.Code)
	}
	if body.Session != "sess-1" {
		t.Errorf("term.error session = %q", body.Session)
	}
	if body.Message == "" {
		t.Error("term.error carries no message")
	}
}

// TestTermOpenWithoutASessionIsRefused keeps the dispatcher from opening a
// session the panel cannot address afterwards.
func TestTermOpenWithoutASessionIsRefused(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	term := &stubTerminal{}
	ag := newAgentUnderTest(t, ts, AgentOptions{Terminal: term}, Options{})
	cancel, _ := runAgent(t, ag)
	defer cancel()

	tc, _ := handshake(t, ts, "session-1", 5, 15)
	tc.sendType(t, wsproto.TypeTermOpen, "t1", map[string]any{"cols": 80, "rows": 24})
	env := tc.recvType(t, wsproto.TypeTermError)
	var body struct {
		Session string `json:"session"`
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	decodeInto(t, env, &body)
	if body.Session != "" {
		t.Errorf("term.error session = %q, want empty", body.Session)
	}
	if body.Message == "" {
		t.Error("term.error carries no message")
	}
	if opens, _, _, _ := term.snapshot(); len(opens) != 0 {
		t.Errorf("the sink was called with an empty session: %+v", opens)
	}
}
