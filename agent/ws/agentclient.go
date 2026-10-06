// This file joins the transport with the agent runtime: it builds the hello,
// drives the telemetry/components cadence the panel negotiated, answers
// commands and turns hints into pulls. It is the only place in agent/ws that
// knows what a command or a hint means.

package ws

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// CommandQueueTimeout bounds how long a cmd.result waits for room in the send
// queue. A result that cannot be delivered must not be remembered as answered,
// so it is worth a short block (design section 3.2).
const CommandQueueTimeout = 2 * time.Second

// capabilityReconnectThrottle bounds how often a capability change may force a
// reconnect. The set is compared against the last hello, so an unchanged set
// never triggers; a set that keeps flapping between two values must not turn
// into a reconnect loop either.
const capabilityReconnectThrottle = 30 * time.Second

// ErrAnswered is returned by Commands.Execute when the Agent must not answer
// the command itself: either the implementation already delivered the result
// (for example over the shared HTTP runner) or the id was answered on the
// other channel. The panel must see exactly one result per command id
// (docs/WS-PROTOCOL.md section 7 ruling 7), so the Agent then sends nothing.
var ErrAnswered = errors.New("ws: command already answered")

// eventQueueSize is how many local events may wait for a connection. Events are
// best effort: when the queue is full the oldest are simply lost, which is
// correct for live data that is never replayed.
const eventQueueSize = 16

// Streams is what the WS layer needs from the agent runtime. bootstrap
// implements it; the interface keeps ws free of bootstrap/panel imports.
type Streams interface {
	HostInfo(ctx context.Context) wsproto.HostInfo
	Telemetry(ctx context.Context) wsproto.Telemetry
	Components(ctx context.Context) wsproto.Components
	Kernels() []wsproto.KernelEntry
	Policy() wsproto.Policy
	Capabilities() []string
	// TerminalSupported reports whether this machine could really serve a
	// terminal session: the local switch is on and the platform has a PTY. The
	// capability list must agree with it (protocol ruling 1).
	TerminalSupported() bool
}

// SessionCounter is an optional extension of Streams: an implementation that
// can report live terminal sessions. The capability watchdog uses it to defer a
// reconnect that would interrupt a user's terminal. A Streams that does not
// implement it is treated as having no session, which keeps the interface small
// for fakes and for a runtime without a terminal.
type SessionCounter interface {
	// TerminalSessions is the number of live interactive terminal sessions.
	TerminalSessions() int
}

// Commands is the single command entry point, shared with the HTTP Runner so
// the whitelist, the de-duplication and the result encoding exist exactly once
// (design section 3.4).
type Commands interface {
	// Execute runs one command. expiresAt is an absolute unix second (0 = no
	// expiry). status is one of accepted | done | failed.
	Execute(ctx context.Context, id string, c wsproto.Cmd, expiresAt int64) (status string, result any, err error)
	// Refresh wakes the pull loop.
	Refresh()
}

// NodeToggle reconciles the xray node controllers (D3). A nil value means
// "not wired": the hint is answered with not_supported instead of being
// ignored.
type NodeToggle interface {
	// SyncXrayNodes pulls this machine's node list and makes the running node
	// controllers match it: an empty list stops every node, otherwise the
	// listed nodes run. The local policy gate lives inside the implementation,
	// so a remote hint can never relax it.
	SyncXrayNodes(ctx context.Context) error
}

// FileSync applies the managed files of the last desired state (D4/D5). A nil
// value means "not wired": a "files" hint is answered with not_supported
// instead of being ignored (protocol ruling 5).
type FileSync interface {
	SyncFiles(ctx context.Context) error
}

// AgentOptions configures NewAgent.
type AgentOptions struct {
	// Streams supplies hello, telemetry and components. It may be nil, in
	// which case the agent only carries commands and events.
	Streams Streams
	// Commands is the shared command entry point. It may be nil.
	Commands Commands
	// Nodes is the D3 hook. It may be nil.
	Nodes NodeToggle
	// Terminal serves the term.* frames (agent/terminal, phase 3). It may be
	// nil: the dispatcher then answers every term.* frame with
	// term.error{code:"terminal_disabled"}, which is what a machine with
	// Terminal.Enabled=false or without a PTY must do.
	Terminal TerminalSink
	// Files is the managed-file hook (a "files" hint, D4/D5). It may be nil:
	// the hint is then answered with not_supported instead of being ignored.
	Files FileSync
	// Log receives the agent's events.
	Log driver.Logger
	// InstanceID is reported in hello.instance_id.
	InstanceID string
	// AgentVersion is reported in hello.agent_version ("dev" when empty).
	AgentVersion string
	// Now is the clock the capability watchdog uses for its reconnect
	// throttle; nil uses time.Now. It is injectable so a test does not have to
	// wait 30 s.
	Now func() time.Time
}

// Agent is the ready-to-run unit: it owns the Client and the periodic senders.
type Agent struct {
	client     *Client
	dispatcher *Dispatcher
	streams    Streams
	commands   Commands
	nodes      NodeToggle
	files      FileSync
	terminal   TerminalSink
	log        driver.Logger
	instanceID string
	version    string

	events chan wsproto.Envelope

	// wake tells the sender that a new session started, so the first telemetry
	// frame is sent immediately instead of waiting for a tick.
	wake chan struct{}

	// cmdCtx is the context commands run under: the agent's, not the frame's.
	cmdMu  sync.Mutex
	cmdCtx context.Context

	// intervals is the cadence the panel negotiated in hello.ok. The reader
	// writes it, the sender reads it.
	intMu     sync.Mutex
	telemetry time.Duration
	comp      time.Duration

	// capMu guards sentCaps, which hello (the connect goroutine) writes and the
	// sender reads.
	capMu sync.Mutex
	// sentCaps is the canonical capability set of the last hello sent. It is
	// the reference the watchdog compares the runtime against: the panel reads
	// capabilities from the hello of a connection, so a difference means a
	// reconnect with a fresh hello.
	sentCaps []string

	// nowFn is the capability watchdog's clock (time.Now when nil).
	nowFn func() time.Time
	// lastCapReconnect is when a capability change last forced a reconnect. It
	// is touched only by the sender goroutine.
	lastCapReconnect time.Time
}

// NewAgent builds the client and the dispatcher. The Options are the
// transport's; the AgentOptions are the runtime's.
func NewAgent(o Options, a AgentOptions) (*Agent, error) {
	ag := &Agent{
		streams:    a.Streams,
		commands:   a.Commands,
		nodes:      a.Nodes,
		files:      a.Files,
		terminal:   a.Terminal,
		log:        a.Log,
		instanceID: a.InstanceID,
		version:    a.AgentVersion,
		events:     make(chan wsproto.Envelope, eventQueueSize),
		wake:       make(chan struct{}, 1),
		telemetry:  time.Duration(DefaultTelemetryIntervalS) * time.Second,
		comp:       time.Duration(DefaultComponentsIntervalS) * time.Second,
		nowFn:      a.Now,
	}
	disp := NewDispatcher(Hooks{
		Hello:      ag.hello,
		HelloOK:    ag.helloOK,
		Command:    ag.execute,
		Hint:       ag.onHint,
		Event:      ag.queueEvent,
		Log:        a.Log,
		Terminal:   a.Terminal, // nil = term.error{terminal_disabled}
		Disconnect: ag.onDisconnect,
	})
	ag.dispatcher = disp

	client, err := New(o, disp)
	if err != nil {
		return nil, err
	}
	ag.client = client
	disp.SetSend(client.Send)
	return ag, nil
}

// Client returns the underlying transport, for callers that need Connected().
func (a *Agent) Client() *Client { return a.client }

// Dispatcher returns the frame router, so callers can add hooks before Run.
func (a *Agent) Dispatcher() *Dispatcher { return a.dispatcher }

// SendFrame encodes one agent -> panel frame and queues it on the current
// connection. Unlike SendEvent it reports the transport error, which is what a
// stream that must react to a dead link (the terminal pump) needs: a failed
// send means the socket is gone, not that a best-effort frame was dropped.
func (a *Agent) SendFrame(t string, body any) error {
	env, err := Encode(t, "", body)
	if err != nil {
		return err
	}
	return a.client.Send(env)
}

// onDisconnect tells a terminal sink that owns live sessions to drop them: a
// session belongs to the connection that opened it (the panel deletes its own
// state at the same moment).
func (a *Agent) onDisconnect(error) {
	d, ok := a.terminal.(TerminalDisconnecter)
	if !ok {
		return
	}
	d.Disconnected()
}

// Run blocks until ctx is cancelled: it starts the client and the event
// sender, and stops both before returning.
func (a *Agent) Run(ctx context.Context) error {
	a.cmdMu.Lock()
	a.cmdCtx = ctx
	a.cmdMu.Unlock()

	// The sender is a child of Run, so it cannot outlive it: the wait below is
	// what keeps the "no goroutine left behind" guarantee.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.sender(ctx)
	}()
	err := a.client.Run(ctx)
	wg.Wait()
	return err
}

// SendEvent pushes an "event" frame (best effort; dropped when offline).
func (a *Agent) SendEvent(kind, level, message string) {
	a.queueEvent(kind, level, message)
}

// queueEvent encodes a local event and hands it to the sender. It never blocks
// the reader, which is the goroutine that calls it.
func (a *Agent) queueEvent(kind, level, message string) {
	env, err := Encode(wsproto.TypeEvent, "", map[string]any{
		"kind":    kind,
		"level":   level,
		"message": message,
	})
	if err != nil {
		a.logf().Warnf("ws: cannot encode %s event: %v", kind, err)
		return
	}
	select {
	case a.events <- env:
	default:
		// Best effort: events are live data and are not replayed.
		a.logf().Debugf("ws: dropping event %s (queue full)", kind)
	}
}

// hello builds the first frame of a connection.
func (a *Agent) hello() wsproto.Hello {
	h := wsproto.Hello{
		AgentVersion: a.version,
		InstanceID:   a.instanceID,
		Seq:          a.client.NextHelloSeq(),
	}
	if a.streams == nil {
		// No runtime wired: still send a hello so the panel can open a session
		// instead of timing out on a silent socket.
		return h
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	h.HostInfo = a.streams.HostInfo(ctx)
	// The platform repeats the two fields the device sample already knows, so
	// the panel does not have to dig into host_info for them (R14).
	h.Platform = wsproto.Platform{OS: h.HostInfo.OS, Arch: h.HostInfo.Arch}
	h.Capabilities = a.streams.Capabilities()
	// The watchdog compares against what this hello actually carried, so an
	// unchanged set never triggers a reconnect.
	a.rememberCapabilities(h.Capabilities)
	h.Policy = a.streams.Policy()
	h.Kernels = a.streams.Kernels()
	return h
}

// rememberCapabilities records the canonical set the last hello declared.
func (a *Agent) rememberCapabilities(caps []string) {
	sent := canonicalCaps(caps)
	a.capMu.Lock()
	a.sentCaps = sent
	a.capMu.Unlock()
}

// checkCapabilities compares the runtime's capability set with the one the last
// hello declared and, when they differ, ends the connection so the next hello
// carries the new set. The protocol allows exactly one hello per connection
// (a second is answered with unexpected_type by the panel gateway) and has no
// "capabilities changed" frame, so a reconnect is the only honest way to
// publish a capability that became ready after the handshake — a signed kernel
// manifest arriving, an updater becoming ready.
//
// The comparison is a set: order and repetition do not matter. A set that
// changes back and forth cannot drive more than one reconnect per
// capabilityReconnectThrottle, and a live terminal session defers the
// reconnect until the user's session ends.
func (a *Agent) checkCapabilities() {
	if a.streams == nil || !a.client.Connected() {
		// Offline (or no runtime): the next hello is built from the current
		// state anyway, so there is nothing to publish.
		return
	}
	current := canonicalCaps(a.streams.Capabilities())
	a.capMu.Lock()
	sent := a.sentCaps
	a.capMu.Unlock()
	if equalCapabilities(current, sent) {
		return
	}
	// A terminal session in flight must not be interrupted: the reconnect would
	// kill it. The next tick re-checks, so the change is published once the
	// session ends.
	if a.terminalBusy() {
		return
	}
	now := a.now()
	if !a.lastCapReconnect.IsZero() && now.Sub(a.lastCapReconnect) < capabilityReconnectThrottle {
		return
	}
	a.lastCapReconnect = now
	a.logf().Infof("ws: capability set changed (%s -> %s), reconnecting with a fresh hello",
		capabilityList(sent), capabilityList(current))
	a.client.RequestReconnect("capabilities changed")
}

// terminalBusy reports whether a live terminal session would be interrupted by
// a reconnect. A Streams without the optional SessionCounter is treated as
// having none.
func (a *Agent) terminalBusy() bool {
	if a.streams == nil {
		return false
	}
	sc, ok := a.streams.(SessionCounter)
	if !ok || sc == nil {
		return false
	}
	return sc.TerminalSessions() > 0
}

// canonicalCaps returns a sorted, duplicate-free copy of caps: hello.capabilities
// is a set (docs/WS-PROTOCOL.md section 3), so two lists that differ only in
// order or repetition describe the same machine.
func canonicalCaps(caps []string) []string {
	if len(caps) == 0 {
		return nil
	}
	out := append([]string(nil), caps...)
	sort.Strings(out)
	n := 1
	for i := 1; i < len(out); i++ {
		if out[i] != out[n-1] {
			out[n] = out[i]
			n++
		}
	}
	return out[:n]
}

// equalCapabilities compares two canonical capability sets.
func equalCapabilities(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// capabilityList renders a set for the log line.
func capabilityList(caps []string) string {
	if len(caps) == 0 {
		return "none"
	}
	return strings.Join(caps, ",")
}

// now is the watchdog's clock.
func (a *Agent) now() time.Time {
	if a.nowFn != nil {
		return a.nowFn()
	}
	return time.Now()
}

// helloOK applies the negotiated cadence and wakes the sender, so the first
// telemetry frame goes out immediately: a panel page that just opened must not
// wait a full interval for data.
func (a *Agent) helloOK(ok wsproto.HelloOK) {
	iv := clampIntervals(ok.Intervals)
	a.intMu.Lock()
	a.telemetry = time.Duration(iv.TelemetryS) * time.Second
	a.comp = time.Duration(iv.ComponentsS) * time.Second
	a.intMu.Unlock()
	select {
	case a.wake <- struct{}{}:
	default:
		// A wake-up is already pending: the sender will see the session.
	}
}

// intervals returns the current cadence.
func (a *Agent) intervals() (telemetry, comp time.Duration) {
	a.intMu.Lock()
	defer a.intMu.Unlock()
	return a.telemetry, a.comp
}

// sender drives the telemetry and components cadence and flushes queued
// events. It only runs while a session is up: before hello.ok there is no
// cadence, and after a disconnect there is nobody to send to.
func (a *Agent) sender(ctx context.Context) {
	var (
		session   string
		telemetry = time.NewTicker(time.Duration(DefaultTelemetryIntervalS) * time.Second)
		comp      = time.NewTicker(time.Duration(DefaultComponentsIntervalS) * time.Second)
		lastComp  []byte
	)
	defer telemetry.Stop()
	defer comp.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.wake:
			// A session started: the check below adopts the cadence and sends
			// the first frames right away.
		case env := <-a.events:
			if a.client.Connected() {
				a.sendOrDrop(env)
			}
		case <-telemetry.C:
			if !a.client.Connected() {
				continue
			}
			a.sendTelemetry(ctx)
			// A state change is reported as soon as it is seen, not only on
			// the components tick (docs/WS-PROTOCOL.md section 3): the
			// telemetry cadence is the faster of the two, so it is where the
			// comparison happens.
			lastComp = a.sendComponentsIfChanged(ctx, lastComp)
		case <-comp.C:
			if !a.client.Connected() {
				continue
			}
			lastComp = a.sendComponents(ctx)
		}

		// A new session (first one, or after a reconnect) means: adopt the
		// negotiated cadence and send one telemetry frame right away, so a
		// freshly opened panel page has data without waiting a full interval.
		cur := a.client.Session()
		if cur != "" && cur != session {
			session = cur
			t, c := a.intervals()
			telemetry.Reset(t)
			comp.Reset(c)
			lastComp = nil
			a.sendTelemetry(ctx)
			lastComp = a.sendComponents(ctx)
		} else if cur == "" {
			session = ""
		}

		// The capability set is not static: a signed kernel manifest arriving
		// or an updater becoming ready makes a capability servable after the
		// hello. Every cadence cycle re-checks it; a change reconnects so the
		// panel sees a hello that carries it.
		a.checkCapabilities()
	}
}

// sendTelemetry samples and sends one telemetry frame.
func (a *Agent) sendTelemetry(ctx context.Context) {
	if a.streams == nil {
		return
	}
	tel := a.streams.Telemetry(ctx)
	env, err := Encode(wsproto.TypeTelemetry, "", tel)
	if err != nil {
		a.logf().Warnf("ws: cannot encode telemetry: %v", err)
		return
	}
	a.sendOrDrop(env)
}

// sampleComponents collects the component list and fingerprints it. The
// fingerprint ignores ts: a state change is what matters, not the clock.
func (a *Agent) sampleComponents(ctx context.Context) (wsproto.Components, []byte, bool) {
	if a.streams == nil {
		return wsproto.Components{}, nil, false
	}
	items := a.streams.Components(ctx)
	fp, err := json.Marshal(items.Items)
	if err != nil {
		a.logf().Warnf("ws: cannot fingerprint components: %v", err)
		return wsproto.Components{}, nil, false
	}
	return items, fp, true
}

// sendComponents sends one components frame unconditionally (the interval
// case) and returns the fingerprint that was sent.
func (a *Agent) sendComponents(ctx context.Context) []byte {
	items, fp, ok := a.sampleComponents(ctx)
	if !ok {
		return nil
	}
	env, err := Encode(wsproto.TypeComponents, "", items)
	if err != nil {
		a.logf().Warnf("ws: cannot encode components: %v", err)
		return nil
	}
	if !a.sendOrDrop(env) {
		return nil
	}
	return fp
}

// sendComponentsIfChanged sends a components frame only when the state moved,
// so a change is reported between two components ticks.
func (a *Agent) sendComponentsIfChanged(ctx context.Context, last []byte) []byte {
	items, fp, ok := a.sampleComponents(ctx)
	if !ok {
		return last
	}
	if last != nil && bytes.Equal(fp, last) {
		return last
	}
	env, err := Encode(wsproto.TypeComponents, "", items)
	if err != nil {
		a.logf().Warnf("ws: cannot encode components: %v", err)
		return last
	}
	if !a.sendOrDrop(env) {
		return last
	}
	return fp
}

// sendOrDrop queues a frame without blocking. Telemetry and components are
// live data: a full queue means the panel is slower than the machine, and the
// next tick will carry fresher numbers anyway.
func (a *Agent) sendOrDrop(env wsproto.Envelope) bool {
	switch err := a.client.Send(env); {
	case err == nil:
		return true
	case err == ErrQueueFull:
		a.logf().Debugf("ws: dropping %s frame (queue full)", env.T)
	case err == ErrOffline:
		// The connection went away between the check and the send.
	default:
		a.logf().Warnf("ws: cannot send %s: %v", env.T, err)
	}
	return false
}

// execute runs one command and answers it with cmd.result. A result that
// cannot be delivered is logged and not remembered as answered by the shared
// runner, so the panel's HTTP fallback can still deliver it.
//
// Commands.Execute is called from the reader goroutine, so it must return
// promptly: a long command answers "accepted" and finishes in its own worker
// (ruling 7), because the reader is not reading while this hook runs.
func (a *Agent) execute(id string, cmd wsproto.Cmd, ttlS int) {
	if a.commands == nil {
		a.replyResult(id, "failed", nil, "commands are not wired")
		return
	}
	a.cmdMu.Lock()
	ctx := a.cmdCtx
	a.cmdMu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	expiresAt := commandExpiry(time.Now(), ttlS)

	// Long commands answer "accepted" first (ruling 7). The shared runner
	// decides the final status; this hook only forwards it.
	status, result, err := a.commands.Execute(ctx, id, cmd, expiresAt)
	if errors.Is(err, ErrAnswered) {
		// The implementation owns the answer (it de-duplicates across the
		// HTTP and WS channels and may have delivered the result itself):
		// sending a frame here would answer one command twice.
		return
	}
	body := wsproto.CmdResult{Status: status, Result: result}
	if err != nil {
		if status == "" {
			body.Status = "failed"
		}
		body.Error = err.Error()
	}
	if body.Status == "" {
		body.Status = "done"
	}
	env, encErr := Encode(wsproto.TypeCmdResult, id, body)
	if encErr != nil {
		a.logf().Warnf("ws: cannot encode cmd.result for %s: %v", id, encErr)
		return
	}
	// A cmd.result must not be silently dropped: wait briefly for room.
	if sendErr := a.client.SendWait(ctx, env, CommandQueueTimeout); sendErr != nil {
		a.logf().Warnf("ws: cmd.result for %s not delivered: %v", id, sendErr)
	}
}

// replyResult answers a command we cannot even start.
func (a *Agent) replyResult(id, status string, result any, msg string) {
	env, err := Encode(wsproto.TypeCmdResult, id, wsproto.CmdResult{Status: status, Result: result, Error: msg})
	if err != nil {
		return
	}
	a.sendOrDrop(env)
}

// onHint turns a hint into the matching pull. The dispatcher has already
// rejected the hints this agent cannot serve.
//
// It runs in the reader goroutine: "desired" only wakes the pull loop, and
// "nodes" must hand the pull to the node controller rather than performing a
// long HTTP fetch inline, or the reader would stop reading. The "files" hint is
// the exception: it is a managed-file apply (download, validate, replace,
// reload) and the reader must not block on it, so it runs in its own goroutine
// and reports its outcome through the event channel and the log.
func (a *Agent) onHint(what string) {
	switch what {
	case "desired":
		if a.commands == nil {
			return
		}
		a.commands.Refresh()
	case "nodes":
		if a.nodes == nil {
			return
		}
		a.cmdMu.Lock()
		ctx := a.cmdCtx
		a.cmdMu.Unlock()
		if ctx == nil {
			ctx = context.Background()
		}
		// The panel asks for the machine's node list; the agent pulls it and
		// starts whatever the local policy allows.
		if err := a.nodes.SyncXrayNodes(ctx); err != nil {
			a.logf().Warnf("ws: xray nodes hint refused: %v", err)
		}
	case "files":
		if a.files == nil {
			return
		}
		a.cmdMu.Lock()
		ctx := a.cmdCtx
		a.cmdMu.Unlock()
		if ctx == nil {
			ctx = context.Background()
		}
		// The apply is long (up to tens of megabytes) and must not block the
		// frame reader: a second hint arriving while one runs is dropped by the
		// applier's own serialisation.
		go func() {
			if err := a.files.SyncFiles(ctx); err != nil {
				a.logf().Warnf("ws: files hint refused: %v", err)
				a.SendEvent("files.apply_failed", "warn", err.Error())
				return
			}
			a.SendEvent("files.applied", "info", "managed files applied from the files hint")
		}()
	}
}

func (a *Agent) logf() driver.Logger {
	if a.log == nil {
		return nopLog{}
	}
	return a.log
}
