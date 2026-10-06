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
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/fileops"
	"github.com/W1nCwC/W1nCray/agent/terminal"
	"github.com/W1nCwC/W1nCray/agent/ws"
)

// wsTerminal adapts *terminal.Manager to the WebSocket dispatcher's
// TerminalSink. The only real difference is the error text: the dispatcher
// answers a refused frame with term.error{code:"terminal_error"}, so each
// sentinel becomes a sentence an operator can act on.
type wsTerminal struct{ m *terminal.Manager }

var _ ws.TerminalSink = wsTerminal{}

func (t wsTerminal) Open(session string, cols, rows int) error {
	if cols <= 0 || rows <= 0 || cols > 1000 || rows > 1000 {
		return fmt.Errorf("invalid terminal size %dx%d", cols, rows)
	}
	_, err := t.m.Open(session, uint16(cols), uint16(rows))
	return err
}

func (t wsTerminal) Input(session string, data []byte) error {
	s, ok := t.m.Get(session)
	if !ok {
		return terminal.ErrNotFound
	}
	_, err := s.Write(data)
	return err
}

func (t wsTerminal) Resize(session string, cols, rows int) error {
	s, ok := t.m.Get(session)
	if !ok {
		return terminal.ErrNotFound
	}
	if cols <= 0 || rows <= 0 || cols > 1000 || rows > 1000 {
		return fmt.Errorf("invalid terminal size %dx%d", cols, rows)
	}
	return s.Resize(uint16(cols), uint16(rows))
}

func (t wsTerminal) Close(session string) error {
	if _, ok := t.m.Get(session); !ok {
		return terminal.ErrNotFound
	}
	return t.m.Close(session, terminal.ReasonClosed)
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
// returns nil when no root is configured: the file_* commands then do not exist
// and the "files" capability is not declared.
func newFileOps(o fileops.Options, log driver.Logger) (*fileops.Ops, error) {
	if len(o.Roots) == 0 {
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
