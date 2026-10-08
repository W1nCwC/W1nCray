// This file is the production side of WP-G6: it builds the interactive
// terminal manager (D8) and the confined file manager (D9) from the resolved
// local policy, and reports their audit events to the panel as event frames.
//
// Both managers are optional by construction. A machine whose agent.yml sets
// Terminal.Enabled=false, or whose kernel has no PTY, gets no terminal manager
// and therefore never declares the capability; a machine without file roots
// gets no file manager and no file_* commands. A capability is a promise
// (docs/WS-PROTOCOL.md section 7 ruling 1).

package bootstrap

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/fileops"
	"github.com/W1nCwC/W1nCray/agent/terminal"
	"github.com/W1nCwC/W1nCray/agent/ws"
	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// termManager is the slice of *terminal.Manager the adapter uses. It is an
// interface so the frame pump can be driven with a fake session on any
// platform; the real manager is the only production implementation.
type termManager interface {
	Open(id string, cols, rows uint16) (terminal.Session, error)
	Get(id string) (terminal.Session, bool)
	Close(id, reason string) error
	Sessions() []string
}

// termDataChunk is the largest raw PTY chunk that goes into one term.data
// frame. 48 KiB raw becomes 64 KiB of base64, far below the contract's 256 KiB
// frame limit (docs/WS-PROTOCOL.md section 1). A larger chunk is split on a
// byte boundary and never on a character boundary: the browser decodes the
// reassembled stream with a streaming UTF-8 decoder, so a multi-byte sequence
// spanning two frames is reassembled, not corrupted.
const termDataChunk = 48 << 10

// wsTerminal adapts a terminal manager to the WebSocket dispatcher's
// TerminalSink, and it is the output pump the sink was missing: Open sends
// term.opened before anything else, one goroutine per session forwards
// session.Output() as term.data and the session's end as term.exit. Without the
// pump a PTY exists on the machine while the browser waits forever on
// "connecting" (term.opened is never sent).
//
// The error text stays the dispatcher's business: a refused frame is answered
// with term.error{code:"terminal_error"}, so the sentinels below only need to
// be recognisable.
type wsTerminal struct {
	m termManager
	// send queues one agent -> panel frame. It is nil when no panel link is
	// wired (unit tests): the pump then only drains the session.
	send func(t string, body any) error
	log  driver.Logger

	// wg counts the live output pumps. It is what lets a test prove that a
	// closed session (and a CloseAll) leaves no goroutine behind.
	wg sync.WaitGroup
}

var _ ws.TerminalSink = (*wsTerminal)(nil)

// setSend wires the frame outlet. remote.go calls it once the ws.Agent exists
// and before Run starts, so no pump can observe a half-wired adapter.
func (t *wsTerminal) setSend(send func(t string, body any) error) { t.send = send }

// Open starts a session and immediately announces it. term.opened precedes
// every term.data of the session (docs/WS-PROTOCOL.md section 3); a failure to
// announce it means the socket is gone, and a session nobody can reach must not
// keep a shell alive.
func (t *wsTerminal) Open(session string, cols, rows int) error {
	if cols <= 0 || rows <= 0 || cols > 1000 || rows > 1000 {
		return fmt.Errorf("invalid terminal size %dx%d", cols, rows)
	}
	s, err := t.m.Open(session, uint16(cols), uint16(rows))
	if err != nil {
		// The dispatcher answers term.error (terminal_error) and no term.opened
		// is sent for a session that does not exist.
		return err
	}
	if err := t.sendFrame(wsproto.TypeTermOpened, termOpenedBody{Session: s.ID()}); err != nil {
		t.closeSession(s, terminal.ReasonDisconnected)
		return err
	}
	t.startPump(s)
	return nil
}

func (t *wsTerminal) Input(session string, data []byte) error {
	s, ok := t.m.Get(session)
	if !ok {
		return terminal.ErrNotFound
	}
	_, err := s.Write(data)
	return err
}

func (t *wsTerminal) Resize(session string, cols, rows int) error {
	s, ok := t.m.Get(session)
	if !ok {
		return terminal.ErrNotFound
	}
	if cols <= 0 || rows <= 0 || cols > 1000 || rows > 1000 {
		return fmt.Errorf("invalid terminal size %dx%d", cols, rows)
	}
	return s.Resize(uint16(cols), uint16(rows))
}

func (t *wsTerminal) Close(session string) error {
	if _, ok := t.m.Get(session); !ok {
		return terminal.ErrNotFound
	}
	return t.m.Close(session, terminal.ReasonClosed)
}

// Disconnected ends every live session when the panel connection goes away. A
// terminal session belongs to one connection: the panel deletes its own state
// on the same event (TerminalChannel::onClose), and a shell that outlived its
// socket would be an orphan nobody can address or close. CloseAll is not used
// here because it latches the manager shut, which would refuse the sessions of
// the next connection.
func (t *wsTerminal) Disconnected() {
	for _, id := range t.m.Sessions() {
		if err := t.m.Close(id, terminal.ReasonDisconnected); err != nil {
			t.logf().Warnf("agent: closing terminal session %s after the panel link dropped: %v", id, err)
		}
	}
}

// ---- the output pump -------------------------------------------------------

// termOpenedBody, termDataBody and termExitBody are the wire payloads of the
// agent -> panel terminal frames (docs/WS-PROTOCOL.md section 3). Named types
// keep the field names from drifting away from the contract.
type termOpenedBody struct {
	Session string `json:"session"`
}

type termDataBody struct {
	Session string `json:"session"`
	Data    string `json:"data"`
}

type termExitBody struct {
	Session string `json:"session"`
	Code    int    `json:"code"`
	Reason  string `json:"reason,omitempty"`
}

// startPump forwards one session's output and exit to the panel. It is one
// goroutine per session, bounded by the manager's session limit.
func (t *wsTerminal) startPump(s terminal.Session) {
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		t.pump(s)
	}()
}

// pump reads session.Output() until it closes, sends every chunk as term.data
// (split so one frame stays well under the 256 KiB limit, in order) and then
// sends exactly one term.exit after the last data frame.
//
// A send failure means the connection is gone: the session is closed instead of
// buffering output nobody will receive. The remaining output is still drained,
// so the PTY reader is never blocked by a consumer that stopped consuming
// (agent/terminal's "drop rather than block" policy).
func (t *wsTerminal) pump(s terminal.Session) {
	dead := false
	for chunk := range s.Output() {
		if dead {
			continue
		}
		for len(chunk) > 0 {
			n := len(chunk)
			if n > termDataChunk {
				n = termDataChunk
			}
			err := t.sendFrame(wsproto.TypeTermData, termDataBody{
				Session: s.ID(),
				Data:    base64.StdEncoding.EncodeToString(chunk[:n]),
			})
			if err != nil {
				dead = true
				t.logf().Warnf("agent: terminal session %s: cannot send output, closing the session: %v", s.ID(), err)
				t.closeSession(s, terminal.ReasonDisconnected)
				break
			}
			chunk = chunk[n:]
		}
	}
	// Output is closed: the shell is gone. Exited carries the single outcome
	// and finalize closes it right after the last read, so this cannot wait
	// forever.
	ex, ok := <-s.Exited()
	if !ok {
		// A session that ended without an outcome is reported as an unknown
		// exit rather than silently swallowed.
		ex = terminal.Exit{Code: -1, Reason: terminal.ReasonExit}
	}
	// The exit frame is the last one of the session: every term.data above is
	// already queued and the pump sends nothing afterwards, so exactly one
	// term.exit follows the last term.data. It is attempted even after a failed
	// send: that failure may have been transient (a full queue), and a session
	// that ended must be reported once either way. A dead link makes this a
	// no-op, and the panel synthesises the same exit on the disconnect.
	if err := t.sendFrame(wsproto.TypeTermExit, termExitBody{
		Session: s.ID(),
		Code:    ex.Code,
		Reason:  ex.Reason,
	}); err != nil {
		t.logf().Debugf("agent: terminal session %s: cannot report the exit: %v", s.ID(), err)
	}
}

func (t *wsTerminal) closeSession(s terminal.Session, reason string) {
	if err := s.Close(reason); err != nil {
		t.logf().Debugf("agent: closing terminal session %s: %v", s.ID(), err)
	}
}

// sendFrame is the one place a terminal frame leaves the adapter, so the nil
// outlet (no panel link) is handled once.
func (t *wsTerminal) sendFrame(typ string, body any) error {
	if t.send == nil {
		return nil
	}
	return t.send(typ, body)
}

func (t *wsTerminal) logf() driver.Logger {
	if t.log == nil {
		return nopLog{}
	}
	return t.log
}

// terminalEventKind is the event kind the panel sees for a terminal session
// open/close. The payload carries metadata only: AuditEvent has no content
// field, and the byte counts are the audit trail the contract asks for
// (docs/WS-PROTOCOL.md section 6).
const terminalEventKind = "terminal.session"

// newTerminalManager builds the terminal manager when the local switch is on
// and this machine can really create a PTY. It returns nil otherwise, which is
// exactly what makes term.open answer term.error{terminal_disabled} and keeps
// the capability out of hello.capabilities.
func newTerminalManager(o terminal.Options, log driver.Logger) *terminal.Manager {
	if !o.Enabled {
		log.Infof("agent: interactive terminal disabled locally (Terminal.Enabled: false)")
		return nil
	}
	if !terminal.Supported() {
		log.Infof("agent: no pseudo-terminal on this platform; the terminal capability is not declared")
		return nil
	}
	o.Log = log
	m, err := terminal.New(o)
	if err != nil {
		// New materialises defaults and cannot fail for a policy reason; a
		// failure here means the options are unusable, and the safe answer is
		// "no terminal" rather than a half-built one.
		log.Warnf("agent: interactive terminal not started: %v", err)
		return nil
	}
	log.Infof("agent: interactive terminal enabled (shell %s, at most %d session(s), idle %s, max %s)",
		m.Options().Shell, m.Options().MaxSessions, m.Options().IdleTimeout, m.Options().MaxLifetime)
	return m
}

// terminalAuditor turns terminal audit events into event frames. It carries the
// metadata (session, action, duration, byte counts, reason) and nothing else.
type terminalAuditor struct {
	events opscmdEventSink
	log    driver.Logger
}

// opscmdEventSink is the event reporter the WebSocket agent implements. It is
// declared as a small interface so this file does not depend on the concrete
// agent type.
type opscmdEventSink interface {
	SendEvent(kind, level, message string)
}

// TerminalEvent implements terminal.Auditor.
func (a terminalAuditor) TerminalEvent(e terminal.AuditEvent) {
	if a.events == nil {
		return
	}
	level := "info"
	if e.Action == "close" && e.Reason != terminal.ReasonExit && e.Reason != terminal.ReasonClosed {
		// A session reclaimed by a deadline or by the agent's shutdown is
		// worth noticing; a normal exit is not.
		level = "warn"
	}
	// The message is a JSON object of metadata only. The panel records it in
	// the audit trail (who/what/when/how long/how many bytes), never the bytes
	// themselves.
	payload, err := json.Marshal(map[string]any{
		"session":    e.Session,
		"action":     e.Action,
		"at":         e.At.Unix(),
		"duration_s": e.DurationS,
		"bytes_in":   e.BytesIn,
		"bytes_out":  e.BytesOut,
		"reason":     e.Reason,
	})
	if err != nil {
		a.log.Warnf("agent: cannot encode the terminal audit event for session %s: %v", e.Session, err)
		return
	}
	a.events.SendEvent(terminalEventKind, level, string(payload))
}

// newFileOps builds the confined file manager from the resolved roots. It
// returns nil when the machine can serve nothing: no root at all AND not
// unrestricted. An unrestricted machine (Files.Unrestricted, or the terminal
// default that follows from it) needs no root — the panel names absolute paths
// — so its file_* commands exist with an empty root list.
func newFileOps(o fileops.Options, log driver.Logger) (*fileops.Ops, error) {
	if len(o.Roots) == 0 && !o.IsUnrestricted() {
		return nil, nil
	}
	o.Log = log
	return fileops.New(o)
}

// FileRoots maps the resolved Files.Roots of the local policy onto the named
// roots the panel addresses. The naming rule lives here because this is where
// the two directories are known:
//
//   - the xray configuration directory (where config.yml lives) is "xray";
//   - the agent state directory is "state";
//   - anything else gets a stable name derived from its base directory.
//
// The panel sends a root name and a relative path, so the name is the whole
// handle; it never sees an absolute path it could aim somewhere else.
func FileRoots(roots []string, xrayDir, stateDir string) []fileops.Root {
	out := make([]fileops.Root, 0, len(roots))
	seen := map[string]bool{}
	for _, r := range roots {
		name := ""
		switch {
		case sameDir(r, xrayDir):
			name = "xray"
		case sameDir(r, stateDir):
			name = "state"
		default:
			name = filepath.Base(filepath.Clean(r))
		}
		if name == "" || name == "." || name == string(filepath.Separator) {
			name = "root"
		}
		// A duplicate name would make one root unreachable; disambiguate
		// deterministically rather than silently dropping it.
		base := name
		for i := 2; seen[name]; i++ {
			name = base + "-" + strconv.Itoa(i)
		}
		seen[name] = true
		out = append(out, fileops.Root{Name: name, Path: r})
	}
	return out
}

// sameDir compares two directories, tolerating a trailing separator and the
// platform's case rules.
func sameDir(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	ca, cb := filepath.Clean(a), filepath.Clean(b)
	if filepath.Separator == '\\' {
		return strings.EqualFold(ca, cb)
	}
	return ca == cb
}
