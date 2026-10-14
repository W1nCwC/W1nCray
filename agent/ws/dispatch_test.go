package ws

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// stubStreams is a Streams implementation whose cadence the test controls.
type stubStreams struct {
	mu         sync.Mutex
	telemetry  int
	components int
	items      []wsproto.Component
}

func (s *stubStreams) HostInfo(context.Context) wsproto.HostInfo {
	return wsproto.HostInfo{Hostname: "test-host", OS: "linux", Arch: "amd64"}
}

func (s *stubStreams) Telemetry(context.Context) wsproto.Telemetry {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.telemetry++
	return wsproto.Telemetry{TS: time.Now().Unix(), CPUPct: 1.5}
}

func (s *stubStreams) Components(context.Context) wsproto.Components {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.components++
	return wsproto.Components{TS: time.Now().Unix(), Items: append([]wsproto.Component(nil), s.items...)}
}

func (s *stubStreams) Kernels() []wsproto.KernelEntry { return nil }

func (s *stubStreams) Policy() wsproto.Policy {
	return wsproto.Policy{Terminal: false, Files: wsproto.FilesPolicy{Roots: []string{"/etc/W1nCray"}}}
}

func (s *stubStreams) Capabilities() []string {
	return []string{wsproto.CapTelemetry, wsproto.CapKernel}
}

// TerminalSupported is part of ws.Streams; this stub has no terminal.
func (s *stubStreams) TerminalSupported() bool { return false }

func (s *stubStreams) setItems(items ...wsproto.Component) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = items
}

// stubCommands records the commands it was asked to run.
type stubCommands struct {
	mu       sync.Mutex
	refreshs int
	execs    []stubExec
	result   any
	err      error
	status   string
}

type stubExec struct {
	id        string
	typ       string
	expiresAt int64
}

func (c *stubCommands) Execute(_ context.Context, id string, cmd wsproto.Cmd, expiresAt int64) (string, any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.execs = append(c.execs, stubExec{id: id, typ: cmd.Type, expiresAt: expiresAt})
	if c.err != nil {
		return c.status, nil, c.err
	}
	return "done", c.result, nil
}

func (c *stubCommands) Refresh() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refreshs++
}

func (c *stubCommands) counts() (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.refreshs, len(c.execs)
}

// stubNodes records the node synchronisations.
type stubNodes struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (n *stubNodes) SyncXrayNodes(context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.calls++
	return n.err
}

func (n *stubNodes) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.calls
}

// stubFiles records the managed-file synchronisations.
type stubFiles struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (f *stubFiles) SyncFiles(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.err
}

func (f *stubFiles) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// newAgentUnderTest wires an Agent against the test server.
func newAgentUnderTest(t *testing.T, ts *testServer, o AgentOptions, opts Options) *Agent {
	t.Helper()
	if opts.URL == "" {
		opts.URL = ts.url()
	}
	opts.MachineID = 7
	opts.Token = "secret-token"
	opts.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	if opts.PingEvery == 0 {
		opts.PingEvery = 200 * time.Millisecond
	}
	if opts.SilenceTimeout == 0 {
		opts.SilenceTimeout = 3 * time.Second
	}
	if opts.HelloTimeout == 0 {
		opts.HelloTimeout = 2 * time.Second
	}
	if opts.BackoffMin == 0 {
		opts.BackoffMin = 20 * time.Millisecond
	}
	if opts.BackoffMax == 0 {
		opts.BackoffMax = 60 * time.Millisecond
	}
	if opts.Log == nil {
		opts.Log = &recordLogger{}
	}
	ag, err := NewAgent(opts, o)
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	return ag
}

func TestAgentSendsHelloAndTelemetryComponentsOnNegotiatedCadence(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	streams := &stubStreams{}
	streams.setItems(wsproto.Component{Name: "agent", Kind: "agent", State: wsproto.StateRunning})
	cmds := &stubCommands{}
	ag := newAgentUnderTest(t, ts, AgentOptions{
		Streams:    streams,
		Commands:   cmds,
		InstanceID: "instance-9",
		Log:        &recordLogger{},
	}, Options{})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ag.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Agent.Run did not return")
		}
	}()

	tc := ts.waitConn(t)
	helloEnv := tc.recvType(t, wsproto.TypeHello)
	var hello wsproto.Hello
	decodeInto(t, helloEnv, &hello)
	if hello.InstanceID != "instance-9" || hello.Seq != 1 {
		t.Errorf("hello = %+v", hello)
	}
	if hello.HostInfo.Hostname != "test-host" {
		t.Errorf("hello.host_info = %+v", hello.HostInfo)
	}
	if len(hello.Capabilities) != 2 {
		t.Errorf("hello.capabilities = %v", hello.Capabilities)
	}
	if hello.Policy.Files.Roots[0] != "/etc/W1nCray" {
		t.Errorf("hello.policy = %+v", hello.Policy)
	}

	// Negotiate a fast cadence so the test does not sleep for real.
	tc.send(t, helloOKEnv(t, "session-1", 1, 1))

	// One telemetry frame arrives immediately (the first page load must have
	// data), then the ticker keeps them coming.
	tc.recvType(t, wsproto.TypeTelemetry)
	tc.recvType(t, wsproto.TypeTelemetry)
	tc.recvType(t, wsproto.TypeComponents)

	// A state change sends components without waiting for the ticker.
	streams.setItems(wsproto.Component{Name: "agent", Kind: "agent", State: wsproto.StateFailed})
	env := tc.recvType(t, wsproto.TypeComponents)
	var comps wsproto.Components
	decodeInto(t, env, &comps)
	if len(comps.Items) != 1 || comps.Items[0].State != wsproto.StateFailed {
		t.Errorf("components after a state change = %+v", comps.Items)
	}
}

func TestAgentAnswersCmdWithCmdResult(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	cmds := &stubCommands{result: map[string]any{"kernels": []string{"xray"}}}
	ag := newAgentUnderTest(t, ts, AgentOptions{Commands: cmds}, Options{})
	cancel, done := runAgent(t, ag)
	defer cancel()

	tc, _ := handshake(t, ts, "session-1", 5, 15)
	cmdEnv, err := Encode(wsproto.TypeCmd, "cmd-42", wsproto.Cmd{Type: "kernel_list", TTLS: 60})
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now()
	tc.send(t, cmdEnv)

	env := tc.recvType(t, wsproto.TypeCmdResult)
	if env.ID != "cmd-42" {
		t.Errorf("cmd.result id = %q, want cmd-42", env.ID)
	}
	var res wsproto.CmdResult
	decodeInto(t, env, &res)
	if res.Status != "done" {
		t.Errorf("status = %q, want done", res.Status)
	}
	if res.Result == nil {
		t.Error("result payload is empty")
	}

	cmds.mu.Lock()
	defer cmds.mu.Unlock()
	if len(cmds.execs) != 1 {
		t.Fatalf("executed %d commands, want 1", len(cmds.execs))
	}
	got := cmds.execs[0]
	if got.id != "cmd-42" || got.typ != "kernel_list" {
		t.Errorf("executed %+v", got)
	}
	// ttl_s is relative: the hook receives an absolute unix second.
	if got.expiresAt < before.Add(59*time.Second).Unix() || got.expiresAt > before.Add(61*time.Second).Unix() {
		t.Errorf("expiresAt = %d, want about now+60s", got.expiresAt)
	}
	select {
	case <-done:
		t.Fatal("Agent.Run returned while the test was still running")
	default:
	}
}

func TestAgentCmdWithoutIDIsRefused(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	cmds := &stubCommands{}
	ag := newAgentUnderTest(t, ts, AgentOptions{Commands: cmds}, Options{})
	cancel, _ := runAgent(t, ag)
	defer cancel()

	tc, _ := handshake(t, ts, "session-1", 5, 15)
	tc.sendType(t, wsproto.TypeCmd, "", wsproto.Cmd{Type: "refresh"})

	env := tc.recvType(t, wsproto.TypeError)
	var body wsproto.ErrorBody
	decodeInto(t, env, &body)
	if body.Code != wsproto.ErrCodeBadPayload {
		t.Errorf("code = %q, want bad_payload", body.Code)
	}
	if _, n := cmds.counts(); n != 0 {
		t.Errorf("executed %d commands without an id", n)
	}
}

func TestHintsDispatchAndRefusals(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	cmds := &stubCommands{}
	nodes := &stubNodes{}
	files := &stubFiles{}
	ag := newAgentUnderTest(t, ts, AgentOptions{Commands: cmds, Nodes: nodes, Files: files}, Options{})
	cancel, _ := runAgent(t, ag)
	defer cancel()

	tc, _ := handshake(t, ts, "session-1", 5, 15)

	// desired: wake the pull loop.
	tc.sendType(t, wsproto.TypeHint, "h1", wsproto.Hint{What: "desired"})
	waitFor(t, func() bool {
		r, _ := cmds.counts()
		return r == 1
	}, "hint desired did not refresh")

	// nodes: hand it to the local gate.
	tc.sendType(t, wsproto.TypeHint, "h2", wsproto.Hint{What: "nodes"})
	waitFor(t, func() bool { return nodes.count() == 1 }, "hint nodes did not reach the toggle")

	// files: hand it to the managed-file hook (WP-G5).
	tc.sendType(t, wsproto.TypeHint, "h3", wsproto.Hint{What: "files"})
	waitFor(t, func() bool { return files.count() == 1 }, "hint files did not reach the managed-file hook")

	// manifest is still phase 2: an explicit not_supported, never silence.
	tc.sendType(t, wsproto.TypeHint, "h4", wsproto.Hint{What: "manifest"})
	env := tc.recvType(t, wsproto.TypeError)
	var body wsproto.ErrorBody
	decodeInto(t, env, &body)
	if body.Code != wsproto.ErrCodeNotSupported {
		t.Errorf("hint manifest code = %q, want not_supported", body.Code)
	}
	if env.ID != "h4" {
		t.Errorf("error id = %q, want h4", env.ID)
	}

	// The connection survives an error answer.
	tc.sendType(t, wsproto.TypePing, "", nil)
	tc.recvType(t, wsproto.TypePong)
}

func TestUnknownHintIsAnswered(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	ag := newAgentUnderTest(t, ts, AgentOptions{}, Options{})
	cancel, _ := runAgent(t, ag)
	defer cancel()

	tc, _ := handshake(t, ts, "session-1", 5, 15)
	tc.sendType(t, wsproto.TypeHint, "h9", wsproto.Hint{What: "everything"})
	env := tc.recvType(t, wsproto.TypeError)
	var body wsproto.ErrorBody
	decodeInto(t, env, &body)
	if body.Code != wsproto.ErrCodeUnknownHint {
		t.Errorf("code = %q, want unknown_hint", body.Code)
	}
}

func TestUnknownTypeIsAnsweredAndConnectionSurvives(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	ag := newAgentUnderTest(t, ts, AgentOptions{}, Options{})
	cancel, _ := runAgent(t, ag)
	defer cancel()

	tc, _ := handshake(t, ts, "session-1", 5, 15)
	tc.sendType(t, wsproto.TypeHello, "u1", map[string]any{"nonsense": true})
	env := tc.recvType(t, wsproto.TypeError)
	if env.ID != "u1" {
		t.Errorf("error id = %q, want u1", env.ID)
	}
	var body wsproto.ErrorBody
	decodeInto(t, env, &body)
	if body.Code != wsproto.ErrCodeUnknownType {
		t.Errorf("code = %q, want unknown_type", body.Code)
	}
	// Still alive.
	tc.sendType(t, wsproto.TypePing, "", nil)
	tc.recvType(t, wsproto.TypePong)
}

func TestTermFramesAnswerTerminalDisabled(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	ag := newAgentUnderTest(t, ts, AgentOptions{}, Options{})
	cancel, _ := runAgent(t, ag)
	defer cancel()

	tc, _ := handshake(t, ts, "session-1", 5, 15)
	tc.sendType(t, wsproto.TypeTermOpen, "t1", map[string]any{"session": "sess-1", "cols": 80, "rows": 24})
	env := tc.recvType(t, wsproto.TypeTermError)
	if env.ID != "t1" {
		t.Errorf("term.error id = %q, want t1", env.ID)
	}
	var body struct {
		Session string `json:"session"`
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	decodeInto(t, env, &body)
	if body.Code != "terminal_disabled" {
		t.Errorf("term.error code = %q, want terminal_disabled", body.Code)
	}
	if body.Session != "sess-1" {
		t.Errorf("term.error session = %q, want sess-1", body.Session)
	}
}

func TestErrorFramesAreRateLimited(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	ag := newAgentUnderTest(t, ts, AgentOptions{}, Options{})
	cancel, _ := runAgent(t, ag)
	defer cancel()

	tc, _ := handshake(t, ts, "session-1", 5, 15)
	// A flood of unknown types must not turn into a flood of our own error
	// frames (the reader is busy reading, not amplifying).
	for i := 0; i < 100; i++ {
		tc.sendType(t, "bogus.type", "x", map[string]any{"i": i})
	}
	time.Sleep(300 * time.Millisecond)

	tc.mu.Lock()
	frames := append([][]byte(nil), tc.raw...)
	tc.mu.Unlock()
	errors := 0
	for _, raw := range frames {
		var env wsproto.Envelope
		if err := json.Unmarshal(raw, &env); err == nil && env.T == wsproto.TypeError {
			errors++
		}
	}
	if errors == 0 {
		t.Fatal("no error frame was sent at all")
	}
	if errors > 2 {
		t.Errorf("sent %d error frames for 100 unknown types, want at most 2 (1/s)", errors)
	}
	// The connection is still healthy.
	tc.sendType(t, wsproto.TypePing, "", nil)
	tc.recvType(t, wsproto.TypePong)
}

func TestDispatcherRefusesCommandWhenNotWired(t *testing.T) {
	sent := make(chan wsproto.Envelope, 4)
	d := NewDispatcher(Hooks{
		Send: func(env wsproto.Envelope) error {
			sent <- env
			return nil
		},
		Now: func() time.Time { return time.Unix(1000, 0) },
	})
	env, err := Encode(wsproto.TypeCmd, "c1", wsproto.Cmd{Type: "refresh"})
	if err != nil {
		t.Fatal(err)
	}
	d.Frame(env)
	select {
	case got := <-sent:
		if got.T != wsproto.TypeError || got.ID != "c1" {
			t.Fatalf("got %+v, want an error frame for c1", got)
		}
	case <-time.After(time.Second):
		t.Fatal("no answer")
	}
}

func TestDispatcherHintFilesWithoutCommands(t *testing.T) {
	sent := make(chan wsproto.Envelope, 4)
	d := NewDispatcher(Hooks{
		Send: func(env wsproto.Envelope) error {
			sent <- env
			return nil
		},
	})
	env, err := Encode(wsproto.TypeHint, "h1", wsproto.Hint{What: "files"})
	if err != nil {
		t.Fatal(err)
	}
	d.Frame(env)
	got := <-sent
	var body wsproto.ErrorBody
	decodeInto(t, got, &body)
	if body.Code != wsproto.ErrCodeNotSupported {
		t.Errorf("code = %q", body.Code)
	}
}

func TestClampIntervals(t *testing.T) {
	cases := []struct {
		name     string
		tel      int
		comp     int
		wantTel  int
		wantComp int
	}{
		{"zero means default", 0, 0, DefaultTelemetryIntervalS, DefaultComponentsIntervalS},
		{"negative means default", -5, -1, DefaultTelemetryIntervalS, DefaultComponentsIntervalS},
		{"below the minimum", -100, 0, DefaultTelemetryIntervalS, DefaultComponentsIntervalS},
		{"inside", 10, 30, 10, 30},
		{"at the maximum", 300, 3600, 300, 3600},
		{"above the maximum", 1_000_000, 1_000_000, 300, 3600},
		{"one second", 1, 1, 1, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := wsproto.Intervals{TelemetryS: tc.tel, ComponentsS: tc.comp}
			got := clampIntervals(in)
			if got.TelemetryS != tc.wantTel || got.ComponentsS != tc.wantComp {
				t.Errorf("clampIntervals(%+v) = %+v, want telemetry %d components %d", in, got, tc.wantTel, tc.wantComp)
			}
		})
	}
}

func TestEncodeDecodeAndErrorFrame(t *testing.T) {
	env, err := Encode(wsproto.TypeHint, "h1", wsproto.Hint{What: "desired"})
	if err != nil {
		t.Fatal(err)
	}
	if env.T != wsproto.TypeHint || env.ID != "h1" {
		t.Fatalf("envelope = %+v", env)
	}
	var hint wsproto.Hint
	if err := Decode(env, &hint); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if hint.What != "desired" {
		t.Errorf("hint = %+v", hint)
	}

	// Strict decoding rejects a panel that invents fields.
	env.D = json.RawMessage(`{"what":"desired","surprise":1}`)
	if err := Decode(env, &hint); err == nil {
		t.Error("Decode accepted an unknown field")
	}

	// A nil payload yields an empty d, and an empty d decodes to the zero
	// value (ping/pong carry no payload).
	ping, err := Encode(wsproto.TypePing, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ping.D) != 0 {
		t.Errorf("ping payload = %s, want empty", ping.D)
	}
	if err := Decode(ping, &hint); err != nil {
		t.Errorf("Decode of an empty payload: %v", err)
	}

	errFrame := ErrorFrame("id-1", wsproto.ErrCodeUnknownType, "nope")
	if errFrame.T != wsproto.TypeError || errFrame.ID != "id-1" {
		t.Fatalf("error frame = %+v", errFrame)
	}
	var body wsproto.ErrorBody
	decodeInto(t, errFrame, &body)
	if body.Code != wsproto.ErrCodeUnknownType || body.Message != "nope" {
		t.Errorf("error body = %+v", body)
	}

	if _, err := Encode("bad", "", make(chan int)); err == nil {
		t.Error("Encode accepted an unmarshalable payload")
	}
}

func TestStrictEnvelopeRejectsUnknownTopLevelField(t *testing.T) {
	var env wsproto.Envelope
	if err := strictUnmarshal([]byte(`{"t":"ping","extra":1}`), &env); err == nil {
		t.Error("strictUnmarshal accepted an unknown envelope field")
	}
	if err := strictUnmarshal([]byte(`{"t":"ping"}`), &env); err != nil {
		t.Errorf("strictUnmarshal rejected a valid envelope: %v", err)
	}
}

// runAgent starts an Agent and returns a stop function.
func runAgent(t *testing.T, ag *Agent) (context.CancelFunc, chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ag.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Agent.Run did not return after cancel")
		}
	})
	return cancel, done
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(msg)
}

// TestAgentRunReturnsWhenContextIsCancelled checks the agent side of the
// shutdown contract: Run must return promptly and leave no sender behind.
func TestAgentRunReturnsWhenContextIsCancelled(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	streams := &stubStreams{}
	ag := newAgentUnderTest(t, ts, AgentOptions{Streams: streams}, Options{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ag.Run(ctx) }()

	handshake(t, ts, "session-1", 1, 1)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Agent.Run did not return after cancel")
	}
}
