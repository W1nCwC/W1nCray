// This file is the panel -> agent routing table. It is the single place that
// decides what an inbound frame does, so phase 2/3 features only add a branch
// here instead of growing a second decoder.

package ws

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync/atomic"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// errorRateLimit is how often one connection may answer with an error frame.
// The panel answers unknown types too; without a cap, a panel that floods
// garbage would be answered by a flood of our own (design section 2.2).
const errorRateLimit = time.Second

// defaultCmdTTLS is used when a cmd frame carries no ttl_s. The panel's HTTP
// commands default to five minutes, and a WS command that never expires would
// keep a stale id alive forever.
const defaultCmdTTLS = 300

// TerminalSink is the terminal implementation (agent/terminal). A nil sink
// means "this agent has no terminal": every term.* frame is answered with
// term.error{code:"terminal_disabled"} instead of being silently dropped, so
// the panel can tell "not supported" from "lost on the wire".
//
// *terminal.Manager implements it directly; the interface lives here so the
// transport never imports the terminal package.
type TerminalSink interface {
	Open(session string, cols, rows int) error
	Input(session string, data []byte) error
	Resize(session string, cols, rows int) error
	Close(session string) error
}

// TerminalDisconnecter is the optional extension of TerminalSink that owns live
// sessions. The Agent calls Disconnected when a connection ends, because a
// terminal session does not survive the socket that opened it: the panel drops
// its own half on the same event, and a shell nobody can address would be an
// orphan. A sink that does not implement it (a test stub, an HTTP-only agent)
// is simply left alone.
type TerminalDisconnecter interface {
	Disconnected()
}

// Hooks are the caller side of the dispatcher. Every field is optional; a nil
// hook turns the corresponding frame into an explicit error answer where the
// contract has one.
type Hooks struct {
	Hello   func() wsproto.Hello
	HelloOK func(wsproto.HelloOK)
	// Command executes one command and answers cmd.result. The id is the
	// envelope id; ttlS is the effective relative ttl in seconds (the default
	// when the frame carried none).
	Command func(id string, cmd wsproto.Cmd, ttlS int)
	// Hint tells the agent to pull the named resource now.
	Hint func(what string)
	// Event reports a local event to the caller (used by the Agent to push an
	// "event" frame).
	Event func(kind, level, message string)
	// Terminal serves term.open/input/resize/close. Nil (no local terminal, or
	// Terminal.Enabled=false) answers every term.* frame with
	// term.error{terminal_disabled}.
	Terminal TerminalSink
	// Send writes one frame back to the panel. A nil Send makes the dispatcher
	// read-only, which is only useful in unit tests.
	Send func(env wsproto.Envelope) error
	// Disconnect is called after a connection ended and before the next dial
	// (Handler.Disconnected). It is what lets a sink that owns per-connection
	// state — the terminal — clean up.
	Disconnect func(err error)
	// Log receives the dispatcher's own events; never a token or a payload.
	Log driver.Logger
	// Now is the clock used for the error rate limit; nil uses time.Now. It is
	// injectable so tests do not sleep.
	Now func() time.Time
}

// Dispatcher routes inbound frames to the runtime. It implements Handler.
type Dispatcher struct {
	hooks Hooks
	// lastError is the UnixNano of the last error frame sent on the current
	// connection. It is atomic because Disconnected (the Run goroutine) resets
	// it while the reader may still be finishing a Frame call.
	lastError atomic.Int64
}

var _ Handler = (*Dispatcher)(nil)

// NewDispatcher builds a dispatcher from hooks.
func NewDispatcher(h Hooks) *Dispatcher {
	return &Dispatcher{hooks: h}
}

// SetSend wires the frame writer. It is called once by the Agent after the
// Client exists.
func (d *Dispatcher) SetSend(send func(env wsproto.Envelope) error) { d.hooks.Send = send }

// Reset forgets the per-connection error budget, so a fresh connection gets a
// fresh allowance. Disconnected calls it.
func (d *Dispatcher) Reset() { d.lastError.Store(0) }

// Hello is the first frame of a connection. It is forwarded to the hook; a nil
// hook still produces a (zero) hello, because the panel needs the envelope to
// start a session.
func (d *Dispatcher) Hello() wsproto.Hello {
	if d.hooks.Hello == nil {
		return wsproto.Hello{}
	}
	return d.hooks.Hello()
}

// HelloOK is called after the transport accepted the panel's answer.
func (d *Dispatcher) HelloOK(ok wsproto.HelloOK) {
	if d.hooks.HelloOK != nil {
		d.hooks.HelloOK(ok)
	}
}

// Disconnected forwards the connection end: it forgets the per-connection
// error budget and tells a per-connection sink (the terminal) to clean up.
func (d *Dispatcher) Disconnected(err error) {
	d.Reset()
	if d.hooks.Disconnect != nil {
		d.hooks.Disconnect(err)
	}
}

// Frame is the routing table.
func (d *Dispatcher) Frame(env wsproto.Envelope) {
	switch env.T {
	case wsproto.TypeHelloOK:
		// Already accepted by the transport (session id, online flag).
		var ok wsproto.HelloOK
		if err := Decode(env, &ok); err != nil {
			d.answerError(env.ID, wsproto.ErrCodeBadPayload, err.Error())
			return
		}
		d.HelloOK(ok)
	case wsproto.TypePing:
		d.send(wsproto.Envelope{T: wsproto.TypePong})
	case wsproto.TypePong:
		// Liveness only: the transport already extended the read deadline.
	case wsproto.TypeCmd:
		d.handleCmd(env)
	case wsproto.TypeHint:
		d.handleHint(env)
	case wsproto.TypeError:
		var body wsproto.ErrorBody
		if err := Decode(env, &body); err == nil {
			d.logf().Warnf("ws: panel error %s: %s", body.Code, body.Message)
		} else {
			d.logf().Warnf("ws: panel error frame: %v", err)
		}
	case wsproto.TypeTermOpen, wsproto.TypeTermInput, wsproto.TypeTermResize, wsproto.TypeTermClose:
		d.handleTerm(env)
	default:
		// Unknown t: answer and keep going (docs/WS-PROTOCOL.md section 2).
		d.answerError(env.ID, wsproto.ErrCodeUnknownType, "unknown message type "+env.T)
	}
}

func (d *Dispatcher) handleCmd(env wsproto.Envelope) {
	var cmd wsproto.Cmd
	if err := Decode(env, &cmd); err != nil {
		d.answerError(env.ID, wsproto.ErrCodeBadPayload, err.Error())
		return
	}
	if env.ID == "" {
		// A command without an id cannot be answered, and executing it would
		// be unanswerable work: refuse it.
		d.answerError("", wsproto.ErrCodeBadPayload, "cmd without id")
		return
	}
	if d.hooks.Command == nil {
		d.answerError(env.ID, wsproto.ErrCodeNotSupported, "commands are not wired")
		return
	}
	ttl := cmd.TTLS
	if ttl <= 0 {
		ttl = defaultCmdTTLS
	}
	d.hooks.Command(env.ID, cmd, ttl)
}

func (d *Dispatcher) handleHint(env wsproto.Envelope) {
	var hint wsproto.Hint
	if err := Decode(env, &hint); err != nil {
		d.answerError(env.ID, wsproto.ErrCodeBadPayload, err.Error())
		return
	}
	switch hint.What {
	case "desired":
		if d.hooks.Hint == nil {
			d.answerError(env.ID, wsproto.ErrCodeNotSupported, "hint desired is not wired")
			return
		}
		d.hooks.Hint(hint.What)
	case "nodes":
		if d.hooks.Hint == nil {
			d.answerError(env.ID, wsproto.ErrCodeNotSupported, "xray nodes are not enabled on this machine")
			return
		}
		d.hooks.Hint(hint.What)
	case "files":
		if d.hooks.Hint == nil {
			d.answerError(env.ID, wsproto.ErrCodeNotSupported, "managed files are not enabled on this machine")
			return
		}
		d.hooks.Hint(hint.What)
	case "manifest":
		// Phase 2 capability. Ruling 5 of the protocol: never silently
		// ignored, always an explicit answer.
		d.answerError(env.ID, wsproto.ErrCodeNotSupported, "hint "+hint.What+" is not supported by this agent")
	case "":
		d.answerError(env.ID, wsproto.ErrCodeBadPayload, "hint without what")
	default:
		d.answerError(env.ID, wsproto.ErrCodeUnknownHint, "unknown hint "+hint.What)
	}
}

// handleTerm answers every term.* frame when no terminal is available. The
// local policy gate (Terminal.Enabled) is the caller's: it simply passes a nil
// TerminalSink.
func (d *Dispatcher) handleTerm(env wsproto.Envelope) {
	session := termSession(env)
	if d.hooks.Terminal == nil {
		d.answerTermError(env.ID, session, "terminal_disabled", "the interactive terminal is disabled on this machine")
		return
	}
	var (
		payload struct {
			Session string `json:"session"`
			Data    string `json:"data"`
			Cols    int    `json:"cols"`
			Rows    int    `json:"rows"`
		}
		err error
	)
	if err = Decode(env, &payload); err != nil {
		d.answerError(env.ID, wsproto.ErrCodeBadPayload, err.Error())
		return
	}
	if payload.Session == "" {
		payload.Session = session
	}
	// Every term.* frame is addressed by session. A term.open without one would
	// create a session the panel cannot name afterwards, so it is refused
	// before the sink sees it.
	if payload.Session == "" {
		d.answerTermError(env.ID, "", "terminal_error", "term."+strings.TrimPrefix(env.T, "term.")+" carries no session")
		return
	}
	switch env.T {
	case wsproto.TypeTermOpen:
		err = d.hooks.Terminal.Open(payload.Session, payload.Cols, payload.Rows)
	case wsproto.TypeTermInput:
		// The contract carries terminal bytes base64 encoded inside d
		// (docs/WS-PROTOCOL.md section 1), so the raw payload string is not
		// the input.
		var data []byte
		if data, err = base64.StdEncoding.DecodeString(payload.Data); err == nil {
			err = d.hooks.Terminal.Input(payload.Session, data)
		} else {
			d.answerError(env.ID, wsproto.ErrCodeBadPayload, "term.input data is not valid base64")
			return
		}
	case wsproto.TypeTermResize:
		err = d.hooks.Terminal.Resize(payload.Session, payload.Cols, payload.Rows)
	case wsproto.TypeTermClose:
		err = d.hooks.Terminal.Close(payload.Session)
	}
	if err != nil {
		d.answerTermError(env.ID, payload.Session, "terminal_error", err.Error())
	}
}

// termSession reads the session id of a term.* frame without failing on the
// rest of the payload, so the terminal_disabled answer can echo it.
func termSession(env wsproto.Envelope) string {
	var payload struct {
		Session string `json:"session"`
	}
	_ = json.Unmarshal(env.D, &payload)
	return payload.Session
}

// answerError sends an error frame, rate limited to one per second per
// connection.
func (d *Dispatcher) answerError(id, code, message string) {
	d.logf().Debugf("ws: answering %s error: %s", id, code)
	if !d.allowError() {
		return
	}
	d.send(ErrorFrame(id, code, message))
}

// answerTermError answers a term.* frame with term.error, which is what the
// contract prescribes when a session cannot be served.
func (d *Dispatcher) answerTermError(id, session, code, message string) {
	d.logf().Debugf("ws: terminal %s refused: %s", session, code)
	if !d.allowError() {
		return
	}
	body := map[string]any{"session": session, "code": code, "message": message}
	env, err := Encode(wsproto.TypeTermError, id, body)
	if err != nil {
		return
	}
	d.send(env)
}

// allowError reports whether an error frame may be sent now, and records it.
// One error frame per errorRateLimit keeps a panel that floods garbage from
// being answered by a flood of our own.
func (d *Dispatcher) allowError() bool {
	now := d.now().UnixNano()
	last := d.lastError.Load()
	if last != 0 && now-last < int64(errorRateLimit) {
		return false
	}
	d.lastError.Store(now)
	return true
}

func (d *Dispatcher) send(env wsproto.Envelope) {
	if d.hooks.Send == nil {
		return
	}
	if err := d.hooks.Send(env); err != nil {
		d.logf().Debugf("ws: cannot send %s: %v", env.T, err)
	}
}

func (d *Dispatcher) now() time.Time {
	if d.hooks.Now != nil {
		return d.hooks.Now()
	}
	return time.Now()
}

func (d *Dispatcher) logf() driver.Logger {
	if d.hooks.Log == nil {
		return nopLog{}
	}
	return d.hooks.Log
}

// commandExpiry converts the contract's relative ttl_s into the absolute unix
// second the shared command entry point expects. 0 means "never expires".
func commandExpiry(now time.Time, ttlS int) int64 {
	if ttlS <= 0 {
		return 0
	}
	return now.Add(time.Duration(ttlS) * time.Second).Unix()
}
