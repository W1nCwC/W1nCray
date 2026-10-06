package bootstrap

import (
	"testing"

	"github.com/W1nCwC/W1nCray/agent/agentcfg"
	"github.com/W1nCwC/W1nCray/agent/ws"
)

// TestStreamsReportTerminalSessions pins the optional ws.SessionCounter the
// capability watchdog uses to defer a reconnect while a terminal is live: the
// runtime adapter must implement it, and a runtime without a terminal manager
// (nil) must report none instead of panicking.
func TestStreamsReportTerminalSessions(t *testing.T) {
	counter, ok := (&Runtime{}).Streams(nil, &agentcfg.Config{}).(ws.SessionCounter)
	if !ok {
		t.Fatal("runtimeStreams does not implement ws.SessionCounter")
	}
	if n := counter.TerminalSessions(); n != 0 {
		t.Errorf("TerminalSessions() without a terminal manager = %d, want 0", n)
	}

	// A zero runtimeStreams (nil runtime) must be safe too.
	var zero ws.Streams = runtimeStreams{}
	sc, ok := zero.(ws.SessionCounter)
	if !ok {
		t.Fatal("runtimeStreams does not implement ws.SessionCounter")
	}
	if n := sc.TerminalSessions(); n != 0 {
		t.Errorf("TerminalSessions() on a zero runtimeStreams = %d, want 0", n)
	}
}
