package panelclient

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
)

// reportBodies returns the decoded bodies of the /report calls the panel saw,
// in order.
func reportBodies(t *testing.T, p *panelSrv) []map[string]any {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []map[string]any
	for _, c := range p.calls {
		if c.endpoint != "report" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(c.raw, &m); err != nil {
			t.Fatalf("report body is not JSON: %v (%s)", err, c.raw)
		}
		out = append(out, m)
	}
	return out
}

// TestReportSuppressesAndRestoresHost covers design section 3.3: while the
// WebSocket telemetry channel is up, /report carries no host key at all; a
// disconnect (Connected() false) restores it on the very next report.
func TestReportSuppressesAndRestoresHost(t *testing.T) {
	p := newPanel(t)
	c := newClient(t, p.srv)
	var suppress atomic.Bool
	cpu := 12.5
	r, err := NewRunner(c, &fakeApp{}, RunnerOptions{
		InstanceID:   runnerID,
		Host:         func() *HostStat { return &HostStat{CPU: &cpu} },
		SuppressHost: suppress.Load,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// WebSocket offline: the HTTP report still carries the load.
	if err := r.reportOnce(ctx); err != nil {
		t.Fatal(err)
	}
	// WebSocket handshaken: the socket owns the load, the body has no host.
	suppress.Store(true)
	if err := r.reportOnce(ctx); err != nil {
		t.Fatal(err)
	}
	// WebSocket gone: the host comes back immediately.
	suppress.Store(false)
	if err := r.reportOnce(ctx); err != nil {
		t.Fatal(err)
	}

	bodies := reportBodies(t, p)
	if len(bodies) != 3 {
		t.Fatalf("panel saw %d reports, want 3", len(bodies))
	}
	if _, ok := bodies[0]["host"]; !ok {
		t.Errorf("report 1 (WebSocket offline) has no host key: %v", bodies[0])
	}
	if _, ok := bodies[1]["host"]; ok {
		t.Errorf("report 2 (WebSocket online) still carries host: %v", bodies[1])
	}
	if _, ok := bodies[2]["host"]; !ok {
		t.Errorf("report 3 (WebSocket gone) did not restore host: %v", bodies[2])
	}
	// The suppression must not remove the rest of the report.
	if bodies[1]["schema"] != float64(1) || bodies[1]["seq"] == nil || bodies[1]["instances"] == nil {
		t.Errorf("suppressed report lost fields: %v", bodies[1])
	}
}

// TestConfigCarriesTheDeclaredFeatures covers ruling 1: the HTTP config request
// must carry exactly the capability list hello.capabilities declared.
func TestConfigCarriesTheDeclaredFeatures(t *testing.T) {
	p := newPanel(t)
	c := newClient(t, p.srv)
	want := []string{"telemetry", "xray_nodes"}
	r, err := NewRunner(c, &fakeApp{}, RunnerOptions{InstanceID: runnerID, Features: want})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.pullOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	var body ConfigRequest
	found := false
	for _, call := range p.calls {
		if call.endpoint != "config" {
			continue
		}
		if err := json.Unmarshal(call.raw, &body); err != nil {
			t.Fatalf("config body is not JSON: %v", err)
		}
		found = true
	}
	if !found {
		t.Fatal("the panel saw no config request")
	}
	if len(body.Features) != len(want) || body.Features[0] != want[0] || body.Features[1] != want[1] {
		t.Errorf("config.features = %v, want %v", body.Features, want)
	}
	if got := r.InstanceID(); got != runnerID {
		t.Errorf("InstanceID() = %q, want %q", got, runnerID)
	}
}

// TestExecuteCommandDeduplicatesAcrossChannels covers design section 3.4: the
// HTTP command lists and the WebSocket cmd frames share one id space, so the
// same id runs once and is answered once; an answer that was not delivered is
// not marked and a redelivery runs again.
func TestExecuteCommandDeduplicatesAcrossChannels(t *testing.T) {
	p := newPanel(t)
	c := newClient(t, p.srv)
	app := &fakeApp{}
	r, err := NewRunner(c, app, RunnerOptions{InstanceID: runnerID})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Channel A (the HTTP runner) executes and answers.
	r.runCommand(ctx, Command{ID: "dup-1", Type: CmdDumpState})
	if n := p.count("command-result"); n != 1 {
		t.Fatalf("HTTP channel answered %d times, want 1", n)
	}

	// Channel B (the WebSocket adapter) gets the same id: it must neither
	// execute nor answer again.
	status, result, err := r.ExecuteCommand(ctx, "dup-1", CmdDumpState, nil, 0)
	if !errors.Is(err, ErrCommandAnswered) {
		t.Fatalf("duplicate id = (%q, %s, %v), want ErrCommandAnswered", status, result, err)
	}
	if n := p.count("command-result"); n != 1 {
		t.Fatalf("the duplicate was answered: %d command results", n)
	}

	// The reverse order: the WebSocket runs it first, the HTTP redelivery is
	// then refused.
	if _, _, err := r.ExecuteCommand(ctx, "dup-2", CmdRefresh, nil, 0); err != nil {
		t.Fatalf("first execution: %v", err)
	}
	r.MarkAnswered("dup-2")
	r.runCommand(ctx, Command{ID: "dup-2", Type: CmdRefresh})
	if n := p.count("command-result"); n != 1 {
		t.Fatalf("the HTTP redelivery answered a WS command: %d command results", n)
	}

	// An answer that was not delivered is not marked: the panel's redelivery
	// must run (and answer) again.
	if _, _, err := r.ExecuteCommand(ctx, "retry-1", CmdDumpState, nil, 0); err != nil {
		t.Fatalf("retry first: %v", err)
	}
	if _, _, err := r.ExecuteCommand(ctx, "retry-1", CmdDumpState, nil, 0); err != nil {
		t.Fatalf("an undelivered result must stay executable: %v", err)
	}

	// An expired command is answered "expired" once and still remembered by the
	// caller; the whitelist lives here too.
	status, result, err = r.ExecuteCommand(ctx, "old-1", "rm -rf /", nil, 1)
	if err != nil {
		t.Fatalf("expired command: %v", err)
	}
	if status != ResultExpired || len(result) != 0 {
		t.Errorf("expired command = (%q, %s), want expired with no result", status, result)
	}
	if status, _, _ := r.ExecuteCommand(ctx, "bad-1", "kernel_install", nil, 0); status != ResultFailed {
		t.Errorf("unwhitelisted command status = %q, want failed", status)
	}
	// An empty id cannot be de-duplicated or answered.
	if _, _, err := r.ExecuteCommand(ctx, "", CmdRefresh, nil, 0); !errors.Is(err, ErrCommandAnswered) {
		t.Errorf("empty id error = %v, want ErrCommandAnswered", err)
	}
}

// TestNewInstanceIDIsUsable checks the exported generator the WebSocket hello
// shares with the HTTP link.
func TestNewInstanceIDIsUsable(t *testing.T) {
	a, b := NewInstanceID(), NewInstanceID()
	if len(a) != 8 || len(b) != 8 {
		t.Fatalf("instance ids %q / %q, want 8 hex characters", a, b)
	}
	if a == b {
		t.Errorf("two instance ids are identical: %q", a)
	}
}
