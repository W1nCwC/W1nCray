package ws

// Tests for the two additive pieces the terminal output pump needs from the
// transport: a generic frame outlet (SendFrame) and a per-connection cleanup
// signal for a sink that owns live sessions (TerminalDisconnecter).

import (
	"sync"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// discTerminal is a TerminalSink that also owns sessions: it counts the
// connection-end notifications.
type discTerminal struct {
	mu   sync.Mutex
	disc int
}

var (
	_ TerminalSink         = (*discTerminal)(nil)
	_ TerminalDisconnecter = (*discTerminal)(nil)
)

func (d *discTerminal) Open(string, int, int) error   { return nil }
func (d *discTerminal) Input(string, []byte) error    { return nil }
func (d *discTerminal) Resize(string, int, int) error { return nil }
func (d *discTerminal) Close(string) error            { return nil }

func (d *discTerminal) Disconnected() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.disc++
}

func (d *discTerminal) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.disc
}

// TestAgentTellsTheTerminalSinkWhenTheConnectionEnds covers the rule that a
// terminal session does not outlive its socket: the Agent forwards the
// transport's Disconnected to a sink that opts in.
func TestAgentTellsTheTerminalSinkWhenTheConnectionEnds(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	term := &discTerminal{}
	ag := newAgentUnderTest(t, ts, AgentOptions{Terminal: term}, Options{})
	cancel, _ := runAgent(t, ag)
	defer cancel()

	tc, _ := handshake(t, ts, "session-1", 5, 15)
	waitConnected(t, ag.Client(), "session-1")
	tc.closeNow()

	waitFor(t, func() bool { return term.count() > 0 },
		"the terminal sink was not told the connection ended")
}

// TestAgentSendFrameReachesThePanel covers the frame outlet the pump uses:
// SendFrame encodes the contract payload and puts it on the wire.
func TestAgentSendFrameReachesThePanel(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	ag := newAgentUnderTest(t, ts, AgentOptions{}, Options{})
	cancel, _ := runAgent(t, ag)
	defer cancel()

	tc, _ := handshake(t, ts, "session-1", 5, 15)
	waitConnected(t, ag.Client(), "session-1")

	if err := ag.SendFrame(wsproto.TypeTermOpened, map[string]any{"session": "s1"}); err != nil {
		t.Fatalf("SendFrame: %v", err)
	}
	env := tc.recvType(t, wsproto.TypeTermOpened)
	var body struct {
		Session string `json:"session"`
	}
	decodeInto(t, env, &body)
	if body.Session != "s1" {
		t.Errorf("term.opened session = %q, want s1", body.Session)
	}
}
