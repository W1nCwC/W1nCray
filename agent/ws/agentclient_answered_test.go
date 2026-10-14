package ws

import (
	"testing"

	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// TestAnsweredCommandIsNotSentAgain locks the shared-dedup contract: when
// Commands.Execute reports ErrAnswered (the id was already handled on the other
// channel, or the implementation delivered the result itself), the Agent must
// send no cmd.result, or the panel would see two answers for one id.
func TestAnsweredCommandIsNotSentAgain(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	cmds := &stubCommands{err: ErrAnswered}
	ag := newAgentUnderTest(t, ts, AgentOptions{Commands: cmds}, Options{})
	cancel, _ := runAgent(t, ag)
	defer cancel()

	tc, _ := handshake(t, ts, "session-1", 5, 15)
	tc.sendType(t, wsproto.TypeCmd, "dup-1", wsproto.Cmd{Type: "refresh"})
	// A ping after the command orders the wire: if the Agent had answered, the
	// cmd.result would arrive before the pong.
	tc.sendType(t, wsproto.TypePing, "", nil)
	if env := tc.recv(t); env.T != wsproto.TypePong {
		t.Fatalf("got a %s frame, want pong: an answered command must not be sent again", env.T)
	}
	if _, n := cmds.counts(); n != 1 {
		t.Errorf("executed %d commands, want 1", n)
	}
}
