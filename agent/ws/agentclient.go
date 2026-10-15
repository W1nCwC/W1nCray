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
	"sync/atomic"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/wsproto"
	"github.com/W1nCwC/W1nCray/agent/xrayapi"
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

// eventQueueSize is the hand-off buffer between the event producers (the
// runtime, the dispatcher) and the sender goroutine. It is deliberately small:
// the sender drains it into the eventBacklog below, which is what survives a
// missing session.
const eventQueueSize = 16

// pendingEventLimit caps how many event frames may wait for a session. Events
// are the one stream that is replayed after a reconnect (docs/WS-PROTOCOL.md
// section 7 ruling 14): a rollback reported by a process that has not
// handshaken yet must still reach the panel. Beyond the limit the oldest frame
// is dropped and counted, so a long outage cannot grow the agent without bound.
const pendingEventLimit = 64

// maxEventSendAttempts bounds the retries of one queued event. A frame whose
// send fails is retried on the next flush; after this many failed attempts it
// is dropped, so a single dead frame can never stall every later event.
const maxEventSendAttempts = 3

// pendingEvent is one event frame waiting for a session, with the number of
// failed send attempts it already cost.
type pendingEvent struct {
	env      wsproto.Envelope
	attempts int
}

// Audit stream bounds. They are the contract's (wsproto) plus the pull loop's
// own cadence, and they live here so a test can pin them.
const (
	// DefaultAuditPullInterval is how often the agent asks the kernel for the
	// next page while collection is on. more=true makes the loop pull again
	// immediately instead of waiting for this tick.
	DefaultAuditPullInterval = 3 * time.Second
	// AuditMaxFrameRate is the contract's send cap: at most five audit.log
	// frames per second, whatever the kernel offers.
	AuditMaxFrameRate = 5
	// auditMinFrameGap is the minimum spacing between two audit.log frames.
	auditMinFrameGap = time.Second / AuditMaxFrameRate
	// MaxAuditFrameBytes caps one audit.log frame at 128 KiB, below the
	// transport's wsproto.MaxFrame: a page is trimmed to fit rather than
	// refused, so a kernel line of the maximum length cannot make the agent
	// drop the whole page.
	MaxAuditFrameBytes = 128 << 10
	// auditProbeFirstDelay and auditProbeMaxDelay shape the bounded support
	// probe: a machine whose kernel has no collector is asked a handful of
	// times after start-up (and again after a failed pull) and then left alone,
	// because "off" must not cost a periodic request forever.
	auditProbeFirstDelay = time.Second
	auditProbeMaxDelay   = 32 * time.Second
	// auditFailBackoffMin/Max bound the retry delay after a failed pull, so a
	// kernel that is restarting is retried quickly and a broken one is not
	// hammered.
	auditFailBackoffMin = time.Second
	auditFailBackoffMax = 30 * time.Second
	// auditMaxBurst bounds how many pages one iteration may follow when the
	// kernel keeps reporting more=true. The frame rate cap already bounds the
	// rate; this only keeps one loop pass finite.
	auditMaxBurst = 8
)

// auditProbeDelays is the fixed probe schedule: eight bounded attempts, then
// silence until a pull fails (which re-arms the probe).
var auditProbeDelays = []time.Duration{
	0,
	auditProbeFirstDelay,
	2 * auditProbeFirstDelay,
	4 * auditProbeFirstDelay,
	8 * auditProbeFirstDelay,
	16 * auditProbeFirstDelay,
	auditProbeMaxDelay,
	auditProbeMaxDelay,
}

// ErrAuditUnsupported is what an AuditSource returns from SetEnabled when the
// kernel predates the collector. The kernel client (agent/xraysvc) has its own
// sentinel; bootstrap's adapter maps it onto this one, so this package never
// imports the kernel layer.
var ErrAuditUnsupported = errors.New("ws: the kernel does not serve the access-log collector")

// AuditSource is the kernel side of the audit stream: the local access-log
// collector (agent/xraysvc.AuditClient implements it through a small adapter in
// bootstrap). A nil source means this agent has no Xray kernel at all: the
// capability is not declared, audit_ctl answers not_supported, and nothing is
// ever pulled.
type AuditSource interface {
	// Supported reports whether the kernel serves the collector (its status
	// document's audit bit, or the route itself). An error means "not known
	// yet", which is treated as unsupported.
	Supported(ctx context.Context) (bool, error)
	// Batch pulls one bounded page with a sequence number greater than after.
	Batch(ctx context.Context, after uint64, max int) (AuditPage, error)
	// SetEnabled turns the kernel's collection on or off. It returns
	// ErrAuditUnsupported when the kernel has no collector.
	SetEnabled(ctx context.Context, enabled bool) error
}

// AuditPage is one page of the kernel's collector. Supported is false when the
// kernel predates the route; Batch then carries nothing.
type AuditPage struct {
	Batch     xrayapi.AuditBatch
	Supported bool
}

// auditSupportSink is the optional extension of Streams that lets the audit
// loop publish the kernel's support bit into the capability set. bootstrap's
// runtimeStreams implements it; a fake that does not is simply not told, and
// declares the capability from its own Capabilities list.
type auditSupportSink interface {
	// SetAuditSupported records what the kernel's status reported.
	SetAuditSupported(bool)
}

// auditState is the audit stream's state. It is touched by the reader
// (helloOK, panel errors), by the command path (SetAuditEnabled) and by the
// sender goroutine (the pull loop), so every field is guarded by mu.
type auditState struct {
	// session is the panel session whose hello.ok was adopted. The pull loop
	// does nothing until it equals the client's current session: a capability
	// the panel never answered must not start a stream.
	session string
	// enabled is what the panel asked for: hello.ok.audit.enabled, or an
	// audit_ctl command. It survives a reconnect when a command set it, and is
	// re-stated by every hello.ok (the panel is the authority).
	enabled bool
	// applied is what the agent last told the kernel (SetEnabled). It is the
	// kernel's state as far as the agent knows, so an enable is sent once.
	applied bool
	// appliedEpoch is the kernel epoch the applied state belongs to. A new
	// epoch means the kernel restarted, its switch is off again, and the
	// enable must be re-sent.
	appliedEpoch int64
	// cursor is the last sequence number the panel acknowledged by receiving a
	// frame. It only moves after a successful send, so a frame that never left
	// is retried instead of being skipped.
	cursor uint64
	// pending is a page that is ready but was not sent yet because the frame
	// rate cap (five per second) was reached.
	pending *wsproto.AuditLog
	// stopped is set for the rest of a session when the panel answers an
	// audit.log frame with unknown_type or not_supported: the panel does not
	// manage audit here, so the agent stops sending until the next session.
	stopped bool
	// nextProbe is when the support probe runs, and probeLeft is what is left
	// of the bounded schedule (nil once it ran out).
	probeLeft []time.Duration
	nextProbe time.Time
	// probing is set while the schedule is exhausted: no more probes until a
	// pull fails.
	probing bool
	// failBackoff is the current retry delay after a failed pull, and nextPull
	// is when the next request to the kernel may be made (zero = now).
	failBackoff time.Duration
	nextPull    time.Time
	// lastFrame is when the last audit.log frame was handed to the transport,
	// which is what the frame rate cap measures.
	lastFrame time.Time
}

// eventBacklog is the sender's bounded queue of event frames that could not be
// delivered yet: no session is up, or the send failed. Only the sender
// goroutine touches items, so it needs no lock; dropped is atomic because
// DroppedEvents reads it from another goroutine.
type eventBacklog struct {
	limit   int
	maxTry  int
	items   []pendingEvent
	dropped atomic.Int64
}

func newEventBacklog() *eventBacklog {
	return &eventBacklog{limit: pendingEventLimit, maxTry: maxEventSendAttempts}
}

// push queues env for the next session. When the backlog is full the oldest
// frame is evicted (the freshest event is the useful one) and returned so the
// caller can log it; the eviction is counted.
func (b *eventBacklog) push(env wsproto.Envelope) (evicted *wsproto.Envelope) {
	if b.limit <= 0 {
		return nil
	}
	if len(b.items) >= b.limit {
		old := b.items[0].env
		evicted = &old
		b.items = b.items[1:]
		b.dropped.Add(1)
	}
	b.items = append(b.items, pendingEvent{env: env})
	return evicted
}

// flush sends queued frames in order until the backlog is empty or a send
// fails. A failed frame keeps its place at the head and is retried on the next
// flush; after maxTry failures it is dropped (returned) and counted, so one
// frame whose send keeps failing cannot block the queue forever.
func (b *eventBacklog) flush(send func(wsproto.Envelope) bool) (dropped []wsproto.Envelope) {
	for len(b.items) > 0 {
		it := b.items[0]
		if send(it.env) {
			b.items = b.items[1:]
			continue
		}
		it.attempts++
		if b.maxTry > 0 && it.attempts >= b.maxTry {
			dropped = append(dropped, it.env)
			b.dropped.Add(1)
			b.items = b.items[1:]
			continue
		}
		b.items[0] = it
		return dropped
	}
	return dropped
}

// length is the number of frames waiting for a session.
func (b *eventBacklog) length() int {
	if b == nil {
		return 0
	}
	return len(b.items)
}

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
	// Audit is the Xray kernel's access-log collector (W1NCRAY-D2). It may be
	// nil: the "audit" capability is then never declared, no frame is ever
	// pulled and audit_ctl answers not_supported.
	Audit AuditSource
	// AuditPullInterval overrides the pull cadence (default
	// DefaultAuditPullInterval). Tests use it so a case does not sleep 3 s.
	AuditPullInterval time.Duration
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
	auditSrc   AuditSource
	auditEvery time.Duration
	log        driver.Logger
	instanceID string
	version    string

	events chan wsproto.Envelope

	// auditMu guards audit. The reader (helloOK, panel errors), the command
	// path and the sender goroutine all touch it; the lock is never held
	// across a request.
	auditMu sync.Mutex
	audit   auditState

	// auditWake asks the sender to re-evaluate the audit state right away
	// (a hello.ok arrived, audit_ctl ran, or the socket came back) instead of
	// waiting for the next pull tick.
	auditWake chan struct{}

	// supportMu guards supportSeen, the last support verdict published to the
	// Streams: the loop only tells it when the answer changed.
	supportMu   sync.Mutex
	supportSeen bool

	// backlog holds event frames that could not be delivered yet: the session
	// is not up, or a send failed. It is replayed in order once a session
	// starts, so an event produced before the handshake (the watchdog's
	// self_update.rolled_back) is not lost. Only the sender goroutine touches
	// it.
	backlog *eventBacklog

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
		auditSrc:   a.Audit,
		auditEvery: a.AuditPullInterval,
		log:        a.Log,
		instanceID: a.InstanceID,
		version:    a.AgentVersion,
		events:     make(chan wsproto.Envelope, eventQueueSize),
		backlog:    newEventBacklog(),
		wake:       make(chan struct{}, 1),
		auditWake:  make(chan struct{}, 1),
		telemetry:  time.Duration(DefaultTelemetryIntervalS) * time.Second,
		comp:       time.Duration(DefaultComponentsIntervalS) * time.Second,
		nowFn:      a.Now,
	}
	if ag.auditEvery <= 0 {
		ag.auditEvery = DefaultAuditPullInterval
	}
	ag.audit = auditState{
		probeLeft:   append([]time.Duration(nil), auditProbeDelays...),
		failBackoff: auditFailBackoffMin,
	}
	// One bounded support probe before the first hello, so a machine whose
	// kernel serves the collector declares the capability in its very first
	// hello instead of after a capability reconnect. The call is bounded by the
	// source's own timeout, and its failure only means "not declared yet".
	if ag.auditSrc != nil {
		ag.probeAuditSupport(context.Background())
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
		Error:      ag.onErrorFrame,
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
		// The sender is the goroutine that talks to the kernel (the audit
		// stream) as well as to the panel. A panic there must never take the
		// agent down with it: it is logged and the sender ends, which leaves
		// the socket to the reconnect loop.
		defer func() {
			if r := recover(); r != nil {
				a.logf().Errorf("ws: sender recovered from a panic: %v", r)
			}
		}()
		a.sender(ctx)
	}()
	err := a.client.Run(ctx)
	wg.Wait()
	return err
}

// SendEvent pushes an "event" frame. An event produced while no session is up
// is buffered (bounded) and replayed in order after the next handshake; only
// overflow beyond the backlog limit is dropped.
func (a *Agent) SendEvent(kind, level, message string) {
	a.queueEvent(kind, level, message)
}

// DroppedEvents reports how many event frames the sender has given up on:
// evicted because the backlog was full, or dropped after too many failed
// sends. A delivered frame is never counted.
func (a *Agent) DroppedEvents() int64 {
	if a.backlog == nil {
		return 0
	}
	return a.backlog.dropped.Load()
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
		// The sender is behind by a whole hand-off buffer: this frame is lost.
		// The backlog itself is bounded and counts its own drops; this path is
		// only reachable when the sender goroutine is not draining at all.
		a.logf().Warnf("ws: dropping event %s (sender is behind)", kind)
	}
}

// enqueueEvent moves one event frame into the backlog that survives a missing
// session. It replaces the old "consume and drop while offline" behaviour that
// lost the watchdog's self_update.rolled_back (REG3-2).
func (a *Agent) enqueueEvent(env wsproto.Envelope) {
	if a.backlog == nil {
		return
	}
	if evicted := a.backlog.push(env); evicted != nil {
		a.logf().Warnf("ws: event backlog full (%d), dropping oldest event %s",
			a.backlog.limit, eventKind(*evicted))
	}
}

// flushEvents replays the backlog, in order, now that a session is up. A frame
// whose send fails keeps its place and is retried on the next flush; one that
// exhausts maxEventSendAttempts is dropped with a warning and counted.
func (a *Agent) flushEvents() {
	if a.backlog == nil {
		return
	}
	for _, env := range a.backlog.flush(a.sendOrDrop) {
		a.logf().Warnf("ws: dropping event %s after %d failed sends",
			eventKind(env), a.backlog.maxTry)
	}
}

// eventKind reads the kind out of an encoded event frame for a log line.
func eventKind(env wsproto.Envelope) string {
	var body struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(env.D, &body); err == nil && body.Kind != "" {
		return body.Kind
	}
	return env.T
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
	// The panel's audit switch belongs to this session: it is the authority
	// (the state is in-memory only and is re-stated by every hello.ok). A
	// panel that omits the field leaves the current state alone, which is what
	// keeps an audit_ctl command in force.
	a.adoptAuditSession(ok.Session)
	if ok.Audit != nil {
		a.auditMu.Lock()
		a.audit.enabled = ok.Audit.Enabled
		a.audit.stopped = false
		a.auditMu.Unlock()
	}
	a.wakeAudit()
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
// events. Telemetry and components only go out while a session is up; events
// are different: a frame that cannot be delivered (no session, or a send that
// failed) waits in the bounded backlog and is replayed, in order, once a
// session starts.
func (a *Agent) sender(ctx context.Context) {
	var (
		session   string
		telemetry = time.NewTicker(time.Duration(DefaultTelemetryIntervalS) * time.Second)
		comp      = time.NewTicker(time.Duration(DefaultComponentsIntervalS) * time.Second)
		auditTick = time.NewTicker(a.auditEvery)
		lastComp  []byte
	)
	defer telemetry.Stop()
	defer comp.Stop()
	defer auditTick.Stop()

	for {
		select {
		case <-ctx.Done():
			a.auditShutdown()
			return
		case <-a.wake:
			// A session started: the check below adopts the cadence, sends
			// the first frames right away and replays the event backlog.
		case <-a.auditWake:
			// The audit state changed (hello.ok, audit_ctl, a reconnect): the
			// audit check below reacts without waiting for its tick.
		case env := <-a.events:
			a.enqueueEvent(env)
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
		case <-auditTick.C:
			// The audit stream has its own cadence (3 s, or the test's), so it
			// never rides on the telemetry interval the panel negotiated.
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

		// Events that could not be delivered are replayed here, in order, on
		// the first iteration of a session. While offline this is skipped, so
		// the backlog keeps growing (bounded) instead of losing frames.
		if a.client.Connected() {
			a.flushEvents()
		}

		// The access-log stream: off by default, so this costs a couple of
		// cheap checks and nothing else until the panel (or a command) turns
		// it on. A page waiting for room under the frame rate cap is retried
		// on the audit tick above.
		a.sendAudit(ctx)

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

// ---- access-log audit stream (W1NCRAY-D2) ----------------------------------
//
// The kernel keeps the access lines in its own bounded ring buffer; this side
// only asks for the next page and forwards it. The rules the stream follows:
//
//   - off by default, and only the panel turns it on: hello.ok.audit.enabled or
//     an audit_ctl command. Nothing is pulled and nothing is sent before that,
//     so a machine that never enables audit pays for nothing;
//   - at most one page per pull tick (3 s), immediately again while the kernel
//     reports more=true, and never more than five frames per second;
//   - the cursor only moves after a frame was really handed to the transport,
//     so a page that could not be sent is retried, not skipped;
//   - the switch is in-memory only: every session re-states it in hello.ok, and
//     a kernel that restarted (a new epoch) is enabled again;
//   - a panel that answers unknown_type or not_supported stops the stream for
//     the rest of the session.

// AuditSupported reports whether the audit capability is declared right now: a
// source is wired and the kernel's status reported the collector. bootstrap's
// Streams calls it for hello.capabilities.
func (a *Agent) AuditSupported() bool {
	return a != nil && a.auditSrc != nil && a.auditSupport()
}

// SetAuditEnabled turns the access-log stream on or off (the audit_ctl
// command). It never blocks: the state is applied by the sender, which is also
// where the kernel's own switch is written. It reports the state that will be
// in force.
func (a *Agent) SetAuditEnabled(enabled bool) bool {
	if a == nil || a.auditSrc == nil {
		return false
	}
	a.auditMu.Lock()
	a.audit.enabled = enabled
	// A command is an explicit instruction for this session: it overrides the
	// "the panel said no" latch, so turning audit back on works.
	a.audit.stopped = false
	a.auditMu.Unlock()
	a.wakeAudit()
	return enabled
}

// AuditEnabled reports whether the stream is on right now.
func (a *Agent) AuditEnabled() bool {
	if a == nil || a.auditSrc == nil {
		return false
	}
	a.auditMu.Lock()
	defer a.auditMu.Unlock()
	return a.audit.enabled
}

// AuditSource returns the wired kernel collector (nil when there is none).
func (a *Agent) AuditSource() AuditSource {
	if a == nil {
		return nil
	}
	return a.auditSrc
}

// wakeAudit asks the sender to re-evaluate the audit state now.
func (a *Agent) wakeAudit() {
	if a == nil || a.auditWake == nil {
		return
	}
	select {
	case a.auditWake <- struct{}{}:
	default:
		// A wake-up is already pending: the sender will see the state.
	}
}

// auditSession adopts the current session once the panel answered it. Until
// then the stream does nothing, because hello.ok is the panel's permission (and
// its audit switch) and a capability nobody answered must not start a pull. It
// returns the adopted session ("" when there is none).
func (a *Agent) auditSession(current string) string {
	if current == "" {
		return ""
	}
	a.auditMu.Lock()
	defer a.auditMu.Unlock()
	if a.audit.session != current {
		// A new panel session: a rejection belonged to the previous one, and a
		// page that was waiting for room belongs to it too.
		a.audit.stopped = false
		a.audit.pending = nil
		a.audit.session = ""
		return ""
	}
	return a.audit.session
}

// adoptAuditSession records that the panel answered session (helloOK).
func (a *Agent) adoptAuditSession(session string) {
	if session == "" {
		return
	}
	a.auditMu.Lock()
	a.audit.session = session
	a.auditMu.Unlock()
}

// auditWanted is the state the loop must bring about for the adopted session:
// the session, and whether the stream must be on.
func (a *Agent) auditWanted(current string) (session string, on bool) {
	a.auditMu.Lock()
	defer a.auditMu.Unlock()
	if a.audit.session == "" || a.audit.session != current {
		return "", false
	}
	if a.audit.stopped {
		return a.audit.session, false
	}
	return a.audit.session, a.audit.enabled
}

// sendAudit is one iteration of the audit stream, driven by the sender loop. It
// is cheap when the feature is off or unavailable.
func (a *Agent) sendAudit(ctx context.Context) {
	if a.auditSrc == nil {
		return
	}
	current := a.client.Session()
	if !a.client.Connected() || current == "" {
		// Offline: nothing is pulled (the kernel's ring buffer keeps the lines
		// and its dropped counter reports what overflowed). A page waiting for
		// room belongs to the connection that was lost.
		a.auditMu.Lock()
		a.audit.pending = nil
		a.auditMu.Unlock()
		return
	}
	a.auditSession(current)
	session, on := a.auditWanted(current)
	if session == "" {
		// The panel has not answered this session yet: only keep the
		// capability knowledge fresh, so a hello built later can declare it.
		a.probeAuditSupport(ctx)
		return
	}
	if !on {
		a.applyAudit(ctx, false)
		a.auditMu.Lock()
		a.audit.pending = nil
		a.auditMu.Unlock()
		return
	}
	if !a.auditSupport() {
		// The kernel cannot serve the collector (or not yet): probe on the
		// bounded schedule and send nothing.
		a.probeAuditSupport(ctx)
		return
	}
	a.applyAudit(ctx, true)
	if !a.sendPendingAudit() {
		// The frame rate cap (or a full send queue) is reached: the page stays
		// pending and the audit tick retries it.
		return
	}
	if a.auditBackoff(time.Now()) {
		// A pull failed and its retry delay has not passed yet. A page that
		// was refused by the transport is still retried above, so the back-off
		// only delays new requests to a kernel that is not answering.
		return
	}
	more := a.pullAudit(ctx)
	// A page that reports more=true is followed immediately (bounded by the
	// frame rate cap), so a kernel backlog is drained at the contract's five
	// frames per second instead of one page per pull tick.
	for i := 0; more && i < auditMaxBurst; i++ {
		if !a.sendPendingAudit() {
			return
		}
		more = a.pullAudit(ctx)
	}
}

// auditBackoff reports whether a failed pull is still inside its retry delay.
func (a *Agent) auditBackoff(now time.Time) bool {
	a.auditMu.Lock()
	defer a.auditMu.Unlock()
	return !a.audit.nextPull.IsZero() && now.Before(a.audit.nextPull)
}

// sendPendingAudit sends the page that is waiting when the frame rate cap
// allows it, and reports whether the loop may pull another one.
func (a *Agent) sendPendingAudit() bool {
	a.auditMu.Lock()
	page := a.audit.pending
	if page == nil {
		a.auditMu.Unlock()
		return true
	}
	if !a.auditFrameAllowed(time.Now()) {
		a.auditMu.Unlock()
		return false
	}
	a.auditMu.Unlock()

	env, err := Encode(wsproto.TypeAuditLog, "", page)
	if err != nil {
		a.logf().Warnf("ws: cannot encode audit.log: %v", err)
		return true
	}
	if !a.sendAuditFrame(env) {
		// The frame did not enter the transport: the cursor must not move, so
		// the page is kept and retried on the next iteration.
		return false
	}
	a.auditMu.Lock()
	a.auditFrameSent(time.Now())
	a.audit.cursor = page.ToSeq
	a.audit.pending = nil
	a.auditMu.Unlock()
	return true
}

// sendAuditFrame hands one audit.log frame to the transport. Unlike telemetry,
// an audit page is not live data: a frame the queue could not accept must be
// retried, never dropped, or the panel would silently lose access lines. A
// connection that is already gone (ErrOffline) is the one exception: the page
// cannot reach the panel anyway, so it is reported as sent and the cursor
// moves on; the kernel keeps its own bounded buffer (and reports the overflow
// in dropped) while the stream is paused, and the next session starts from a
// fresh hello.ok.
func (a *Agent) sendAuditFrame(env wsproto.Envelope) bool {
	err := a.client.Send(env)
	switch {
	case err == nil:
		return true
	case err == ErrQueueFull:
		a.logf().Debugf("ws: audit.log frame not queued (queue full); the page will be retried")
		return false
	case err == ErrOffline:
		return true
	default:
		a.logf().Warnf("ws: cannot send audit.log: %v", err)
		return true
	}
}

// pullAudit asks the kernel for the next page and queues it for sending. The
// cursor only moves when the frame really left (sendPendingAudit). It reports
// whether the page the kernel answered says more=true, which is what makes the
// loop pull again immediately.
func (a *Agent) pullAudit(ctx context.Context) bool {
	a.auditMu.Lock()
	after := a.audit.cursor
	a.auditMu.Unlock()

	pctx, cancel := context.WithTimeout(ctx, a.auditEvery)
	page, err := a.auditSrc.Batch(pctx, after, wsproto.MaxAuditItems)
	cancel()
	if err != nil {
		a.auditFailed("拉取内核访问日志失败", err)
		return false
	}
	if !page.Supported {
		// The kernel predates the route: the capability is not real. Log it
		// once and stop advertising it.
		a.setAuditSupport(false)
		a.auditFailed("Xray 内核不支持访问日志采集（/audit 不存在）", nil)
		return false
	}
	a.setAuditSupport(true)
	a.auditOK()

	batch := page.Batch
	a.auditMu.Lock()
	if batch.Epoch != 0 && batch.Epoch != a.audit.appliedEpoch {
		// The kernel restarted: the cursor belongs to a process that is gone
		// and its switch is off again. Start from its current position, and
		// let the next iteration send the enable again.
		a.audit.appliedEpoch = batch.Epoch
		a.audit.applied = false
		a.audit.cursor = 0
	}
	a.auditMu.Unlock()

	if len(batch.Items) == 0 {
		return false
	}
	frame := auditFrame(batch)
	if frame == nil {
		return false
	}
	a.auditMu.Lock()
	a.audit.pending = frame
	a.auditMu.Unlock()
	return batch.More
}

// auditFailed records a pull failure and backs off, re-arming the support probe
// so a kernel that was replaced (or has not started yet) is re-checked.
func (a *Agent) auditFailed(what string, err error) {
	a.auditMu.Lock()
	backoff := a.audit.failBackoff
	if backoff <= 0 {
		backoff = auditFailBackoffMin
	}
	a.audit.failBackoff = min(backoff*2, auditFailBackoffMax)
	a.audit.probing = false
	a.audit.probeLeft = append([]time.Duration(nil), auditProbeDelays...)
	a.audit.nextProbe = time.Now().Add(backoff)
	a.audit.nextPull = time.Now().Add(backoff)
	a.auditMu.Unlock()
	if err != nil {
		a.logf().Warnf("ws: %s: %v", what, err)
		return
	}
	a.logf().Warnf("ws: %s", what)
}

// auditOK resets the failure backoff after a good pull.
func (a *Agent) auditOK() {
	a.auditMu.Lock()
	a.audit.failBackoff = auditFailBackoffMin
	a.audit.nextPull = time.Time{}
	a.auditMu.Unlock()
}

// applyAudit makes the kernel's switch match want, once. The state is
// remembered per epoch: a kernel that restarted is enabled again, and an
// unchanged state costs no request at all.
func (a *Agent) applyAudit(ctx context.Context, want bool) {
	a.auditMu.Lock()
	if a.audit.applied == want {
		a.auditMu.Unlock()
		return
	}
	a.auditMu.Unlock()

	sctx, cancel := context.WithTimeout(ctx, a.auditEvery)
	err := a.auditSrc.SetEnabled(sctx, want)
	cancel()
	if err != nil {
		if errors.Is(err, ErrAuditUnsupported) {
			// An old kernel: a fact, not a transient failure. The capability
			// goes away and the probe stops re-arming.
			a.setAuditSupport(false)
			a.auditMu.Lock()
			a.audit.enabled = false
			a.audit.probing = true
			a.audit.probeLeft = nil
			a.auditMu.Unlock()
			a.logf().Warnf("ws: Xray 内核不支持访问日志采集，已关闭审计转发")
			return
		}
		// The state is left as it was, so the next iteration retries.
		a.logf().Warnf("ws: 设置内核访问日志采集开关失败: %v", err)
		return
	}
	a.auditMu.Lock()
	a.audit.applied = want
	a.auditMu.Unlock()
	if want {
		a.logf().Infof("ws: 内核访问日志采集已开启，开始转发 audit.log")
		return
	}
	a.logf().Infof("ws: 内核访问日志采集已关闭，停止转发 audit.log")
}

// auditFrameAllowed reports whether the frame rate cap (five audit.log frames
// per second) allows a send now. It does not record anything: auditFrameSent
// does that once the frame really entered the transport, so a frame the queue
// refused does not consume the budget of a frame that never left. The caller
// holds auditMu.
func (a *Agent) auditFrameAllowed(now time.Time) bool {
	if a.audit.lastFrame.IsZero() {
		return true
	}
	return now.Sub(a.audit.lastFrame) >= auditMinFrameGap
}

// auditFrameSent records that one audit.log frame entered the transport, which
// is what the frame rate cap measures. The caller holds auditMu.
func (a *Agent) auditFrameSent(now time.Time) {
	a.audit.lastFrame = now
}

// probeAuditSupport asks the kernel whether it serves the collector, on the
// bounded schedule, and publishes the answer into the capability set. It never
// blocks the sender for long: the answer is what a hello built later carries.
func (a *Agent) probeAuditSupport(ctx context.Context) {
	a.auditMu.Lock()
	if a.audit.probing || a.audit.probeLeft == nil {
		a.auditMu.Unlock()
		return
	}
	now := time.Now()
	if !a.audit.nextProbe.IsZero() && now.Before(a.audit.nextProbe) {
		a.auditMu.Unlock()
		return
	}
	delay := a.audit.probeLeft[0]
	a.audit.probeLeft = a.audit.probeLeft[1:]
	if len(a.audit.probeLeft) == 0 {
		// The schedule ran out: stay quiet until a pull fails.
		a.audit.probing = true
	}
	a.audit.nextProbe = now.Add(delay)
	a.auditMu.Unlock()

	pctx, cancel := context.WithTimeout(ctx, a.auditEvery)
	supported, err := a.auditSrc.Supported(pctx)
	cancel()
	switch {
	case err != nil:
		// Not known yet (the kernel may still be starting): leave the
		// capability as it is and let the next probe decide.
		a.logf().Debugf("ws: 探测内核审计支持失败: %v", err)
	case supported:
		a.setAuditSupport(true)
		// The kernel serves the collector; from here on the answer is kept
		// fresh by the status reads the components view already performs, so
		// the probe schedule is not needed.
		a.auditMu.Lock()
		a.audit.probing = true
		a.audit.probeLeft = nil
		a.auditMu.Unlock()
	default:
		a.setAuditSupport(false)
		// The kernel answered and does not serve the collector: that is a fact
		// about this kernel version, so the schedule ends here.
		a.auditMu.Lock()
		a.audit.probing = true
		a.audit.probeLeft = nil
		a.auditMu.Unlock()
	}
}

// auditSupport reports the current support bit.
func (a *Agent) auditSupport() bool {
	a.supportMu.Lock()
	defer a.supportMu.Unlock()
	return a.supportSeen
}

// setAuditSupport publishes the kernel's support bit to the Streams (which is
// what hello.capabilities reads) and remembers it.
func (a *Agent) setAuditSupport(supported bool) {
	a.supportMu.Lock()
	changed := a.supportSeen != supported
	a.supportSeen = supported
	a.supportMu.Unlock()
	if !changed {
		return
	}
	if sink, ok := a.streams.(auditSupportSink); ok && sink != nil {
		sink.SetAuditSupported(supported)
	}
	if supported {
		a.logf().Infof("ws: Xray 内核支持访问日志采集，hello 将声明 audit 能力")
		return
	}
	a.logf().Infof("ws: Xray 内核不支持访问日志采集，hello 不声明 audit 能力")
}

// onPanelAuditError stops the audit stream for the rest of the session. The
// panel answers a frame type it does not know with unknown_type and a feature
// it does not serve with not_supported; either way this panel does not manage
// audit here, and continuing to send would only repeat the error.
func (a *Agent) onPanelAuditError() {
	if a.auditSrc == nil {
		return
	}
	a.auditMu.Lock()
	already := a.audit.stopped
	a.audit.stopped = true
	a.audit.pending = nil
	a.auditMu.Unlock()
	if already {
		return
	}
	a.logf().Warnf("ws: 面板不接受 audit.log（unknown_type/not_supported），本会话停止发送审计日志")
}

// onErrorFrame is the dispatcher's Error hook: it decides whether a panel error
// was about the audit stream. The panel answers an unknown frame type with
// unknown_type and an unsupported feature with not_supported, and audit.log is
// the one stream an older panel may not know. Everything else is left to the
// log the dispatcher already wrote.
func (a *Agent) onErrorFrame(body wsproto.ErrorBody) {
	if a.auditSrc == nil {
		return
	}
	switch body.Code {
	case wsproto.ErrCodeUnknownType, wsproto.ErrCodeNotSupported:
		a.onPanelAuditError()
	}
}

// auditShutdown turns the kernel's collection off when the agent stops. The
// kernel outlives the agent, and a collector nobody consumes would only fill
// its ring buffer.
func (a *Agent) auditShutdown() {
	if a.auditSrc == nil {
		return
	}
	a.auditMu.Lock()
	applied := a.audit.applied
	a.auditMu.Unlock()
	if !applied {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := a.auditSrc.SetEnabled(ctx, false); err != nil {
		a.logf().Debugf("ws: 关闭内核访问日志采集: %v", err)
		return
	}
	a.auditMu.Lock()
	a.audit.applied = false
	a.auditMu.Unlock()
}

// auditFrame maps one kernel page onto the panel's audit.log payload and trims
// it to MaxAuditFrameBytes. The mapping is a copy: the wire types are
// deliberately independent, so the kernel cannot change the panel's contract by
// accident. A page whose first item alone does not fit is dropped rather than
// sent, and the cursor then stays where it is.
func auditFrame(batch xrayapi.AuditBatch) *wsproto.AuditLog {
	if len(batch.Items) == 0 {
		return nil
	}
	items := make([]wsproto.AuditItem, 0, len(batch.Items))
	for _, it := range batch.Items {
		items = append(items, wsproto.AuditItem{T: it.T, L: it.L})
	}
	frame := &wsproto.AuditLog{
		Epoch:   batch.Epoch,
		FromSeq: batch.FromSeq,
		ToSeq:   batch.ToSeq,
		Dropped: batch.Dropped,
		Items:   items,
	}
	// Trim to the frame bound: the kernel's own cap (400 items of up to 512
	// bytes) can exceed 128 KiB once the JSON overhead is counted.
	for len(frame.Items) > 1 {
		if auditFrameSize(frame) <= MaxAuditFrameBytes {
			break
		}
		frame.Items = frame.Items[:len(frame.Items)-1]
		frame.ToSeq = frame.FromSeq + uint64(len(frame.Items)) - 1
	}
	if auditFrameSize(frame) > MaxAuditFrameBytes {
		// Even one item does not fit: this page cannot be forwarded, and the
		// cursor stays so the loss is a visible gap rather than a lie.
		return nil
	}
	return frame
}

// auditFrameSize is the encoded size of one audit.log frame. The envelope's
// fixed overhead is included through Encode, so the bound is the real wire size
// and not just the payload.
func auditFrameSize(frame *wsproto.AuditLog) int {
	env, err := Encode(wsproto.TypeAuditLog, "", frame)
	if err != nil {
		return MaxAuditFrameBytes + 1
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return MaxAuditFrameBytes + 1
	}
	return len(raw)
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
