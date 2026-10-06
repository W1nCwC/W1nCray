// This file implements the Runner: the pull loop (POST /config, apply, POST
// /ack) and the report loop (POST /report) that keep the agent in step with the
// panel (contract sections 3.1 to 3.5).
//
// The Runner is strictly best effort towards the panel. Whatever happens on the
// network (unreachable panel, 429, 5xx, garbage answers) is logged and retried
// with backoff, and never touches the instances that are already running: the
// only way the Runner changes the machine is Applier.Apply with a desired state
// that decoded strictly.

package panelclient

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	mrand "math/rand/v2"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/reconcile"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// Timing defaults and limits.
const (
	// DefaultInterval is the default pull and report interval.
	DefaultInterval = 30 * time.Second
	// MinInterval and MaxInterval clamp the configured intervals.
	MinInterval = 10 * time.Second
	MaxInterval = 300 * time.Second

	// backoffStart and backoffMax bound the retry delay after a failure.
	backoffStart = 30 * time.Second
	backoffMax   = 5 * time.Minute

	// jitterFraction is the +/- randomisation applied to every wait.
	jitterFraction = 0.2

	// seenCommands is how many command ids are remembered for deduplication.
	seenCommands = 256

	// minScrubSecret mirrors the reconciler: shorter strings match too much.
	minScrubSecret = 8
)

// API is the part of *Client the Runner uses. It is an interface so tests can
// observe the traffic; *Client satisfies it.
type API interface {
	Config(ctx context.Context, req ConfigRequest) (ConfigResponse, error)
	Ack(ctx context.Context, req AckRequest) error
	Report(ctx context.Context, req ReportRequest) (ReportResponse, error)
	CommandResult(ctx context.Context, req CommandResultRequest) error
	Manifest(ctx context.Context, req ManifestRequest) (ManifestResponse, error)
	Blob(ctx context.Context, req BlobRequest) (BlobResponse, error)
}

var _ API = (*Client)(nil)

// CommandRunner executes the non-trivial command types (kernel_*, self_update,
// file_*, files_apply). The Runner owns the whitelist's built-in types
// (refresh, dump_state), the expiry check and the id de-duplication; it hands
// everything else to this interface, which answers "unsupported command" for a
// type it does not know. A nil runner leaves every other type answered with
// "unsupported command", exactly like before the operations framework existed
// (design section 2.1).
type CommandRunner interface {
	Execute(ctx context.Context, c Command) (status string, result json.RawMessage)
}

// Applier is what the Runner needs from the agent runtime (a
// *reconcile.Reconciler behind a thin adapter in production).
type Applier interface {
	// Apply makes d the running state. The report is meaningful even when the
	// error is not nil.
	Apply(ctx context.Context, d spec.Desired) (reconcile.Report, error)
	// Last returns the report of the most recent Apply.
	Last() (reconcile.Report, bool)
	// Health compares the applied state with reality once.
	Health(ctx context.Context) reconcile.HealthReport
	// Stats returns the cumulative counters of the running instances.
	Stats(ctx context.Context) []driver.Counter
}

// Clock abstracts time so tests do not depend on real sleeping.
type Clock interface {
	Now() time.Time
	// After waits for d (the Runner always also selects on its context).
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// RunnerOptions configures NewRunner. The zero value of every field is usable.
type RunnerOptions struct {
	// AgentVersion is reported in /config ("dev" when empty).
	AgentVersion string
	// Engines are the engines registered on this machine (sent in /config).
	Engines []string
	// Kernels returns the installed external kernels by name and version; it
	// is called on every pull and may be nil.
	Kernels func() map[string]string
	// KernelsList returns the structured installed-kernel list sent as
	// "kernel_entries" in /config, /report and the ack report (design section
	// 3.3). It is optional; a failure or an empty list omits the field and
	// never blocks the pull or the report.
	KernelsList func() ([]wsproto.KernelEntry, error)
	// Commands executes the command types the Runner does not implement
	// itself. It may be nil (unsupported command, as before).
	Commands CommandRunner
	// PullInterval and ReportInterval default to 30s and are clamped to
	// [MinInterval, MaxInterval].
	PullInterval   time.Duration
	ReportInterval time.Duration
	// Log receives the Runner's events. It never receives a desired state, a
	// secret or the token.
	Log driver.Logger
	// Clock and Rand are injectable for tests. Rand returns a value in [0,1).
	Clock Clock
	Rand  func() float64
	// InstanceID, when set, replaces the random id generated by Run.
	InstanceID string
	// Host samples the machine load; nil uses the machine's real sampler. It
	// may return nil when nothing is available.
	Host func() *HostStat
	// SuppressHost, when non-nil, is consulted before every report: a true
	// result omits the host payload. The WebSocket telemetry channel carries
	// the same numbers, and two writers would interleave on the panel
	// (docs/WS-PROTOCOL.md section 3, design section 3.3). A nil function
	// never suppresses.
	SuppressHost func() bool
	// Features is the capability list sent in /config; it must be exactly the
	// list the agent declared in hello.capabilities (ruling 1). Nil sends no
	// "features" key.
	Features []string
	// FeaturesFunc, when set, is called for every pull and takes precedence
	// over Features. The capability list can change while the agent runs (a
	// signed manifest arriving later is what makes the kernel commands
	// servable), and the panel must always see the list the current hello
	// declares. An empty result sends no "features" key.
	FeaturesFunc func() []string
	// Manifest, when non-nil, enables the signed kernel manifest sync loop:
	// the Runner fetches GET /manifest and hands the body to this sink, which
	// verifies it locally. A nil sink disables the loop entirely.
	Manifest ManifestSink
	// ManifestPersistPath is where an accepted manifest is written (0600,
	// temporary file + rename). Empty disables persistence.
	ManifestPersistPath string
	// ManifestInterval is how often the manifest is re-fetched after a
	// success. It defaults to DefaultManifestInterval and is clamped to
	// [MinManifestInterval, MaxManifestInterval].
	ManifestInterval time.Duration
	// OnConnected, when non-nil, is called exactly once, from the pull loop,
	// after the panel answered a /config request: the link is proven. The
	// self-update start-up watchdog uses it to confirm a committed update.
	OnConnected func()
}

// Runner pulls the desired state, applies it, acknowledges the outcome,
// reports the runtime status and executes whitelisted commands.
type Runner struct {
	api   API
	app   Applier
	log   driver.Logger
	clock Clock
	rand  func() float64

	version       string
	engines       []string
	kernels       func() map[string]string
	kernelEntries func() ([]wsproto.KernelEntry, error)
	commands      CommandRunner
	pull          time.Duration
	report        time.Duration
	host          func() *HostStat
	// suppressHost is consulted on every report; features travels in /config.
	suppressHost func() bool
	features     []string
	featuresFunc func() []string
	fixedID      string

	manifest      ManifestSink
	manifestPath  string
	manifestEvery time.Duration

	// onConnected is called once, on the first successful pull.
	onConnected   func()
	connectedOnce sync.Once

	refresh chan struct{} // capacity 1: coalesces refresh requests

	mu           sync.Mutex
	instanceID   string
	haveRev      int64
	haveHash     string
	pendingAck   *AckRequest
	seq          uint64
	secrets      []string
	seen         map[string]struct{}
	seenOrder    []string
	inflight     map[string]bool
	manifestETag string
}

type nopLog struct{}

func (nopLog) Debugf(string, ...any) {}
func (nopLog) Infof(string, ...any)  {}
func (nopLog) Warnf(string, ...any)  {}
func (nopLog) Errorf(string, ...any) {}

// NewRunner builds a Runner. api and app are required.
func NewRunner(api API, app Applier, o RunnerOptions) (*Runner, error) {
	if api == nil || app == nil {
		return nil, errors.New("panelclient: runner needs an API and an Applier")
	}
	r := &Runner{
		api:           api,
		app:           app,
		log:           o.Log,
		clock:         o.Clock,
		rand:          o.Rand,
		version:       o.AgentVersion,
		engines:       append([]string(nil), o.Engines...),
		kernels:       o.Kernels,
		kernelEntries: o.KernelsList,
		commands:      o.Commands,
		pull:          ClampInterval(o.PullInterval),
		report:        ClampInterval(o.ReportInterval),
		host:          o.Host,
		suppressHost:  o.SuppressHost,
		features:      append([]string(nil), o.Features...),
		featuresFunc:  o.FeaturesFunc,
		fixedID:       o.InstanceID,
		manifest:      o.Manifest,
		manifestPath:  o.ManifestPersistPath,
		manifestEvery: ClampManifestInterval(o.ManifestInterval),
		onConnected:   o.OnConnected,
		refresh:       make(chan struct{}, 1),
		seen:          map[string]struct{}{},
		inflight:      map[string]bool{},
	}
	if r.log == nil {
		r.log = nopLog{}
	}
	if r.clock == nil {
		r.clock = realClock{}
	}
	if r.rand == nil {
		r.rand = mrand.Float64
	}
	if r.version == "" {
		r.version = "dev"
	}
	if r.host == nil {
		r.host = defaultHost
	}
	return r, nil
}

// ClampInterval returns DefaultInterval for d <= 0 and otherwise d limited to
// [MinInterval, MaxInterval].
func ClampInterval(d time.Duration) time.Duration {
	switch {
	case d <= 0:
		return DefaultInterval
	case d < MinInterval:
		return MinInterval
	case d > MaxInterval:
		return MaxInterval
	}
	return d
}

// Run blocks until ctx is cancelled and then returns ctx.Err(). It starts the
// pull and the report loop; both stop promptly on cancellation.
func (r *Runner) Run(ctx context.Context) error {
	id := r.fixedID
	if id == "" {
		id = newInstanceID()
	}
	r.mu.Lock()
	r.instanceID = id
	r.seq = 0
	r.mu.Unlock()
	r.log.Infof("panel: link started (instance %s, pull every %s, report every %s)", id, r.pull, r.report)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); r.pullLoop(ctx) }()
	go func() { defer wg.Done(); r.reportLoop(ctx) }()
	if r.manifest != nil {
		wg.Add(1)
		go func() { defer wg.Done(); r.manifestLoop(ctx) }()
		r.log.Infof("panel: kernel manifest sync started (every %s)", r.manifestEvery)
	}
	wg.Wait()
	r.log.Infof("panel: link stopped")
	return ctx.Err()
}

// newInstanceID returns 8 random hex characters.
func newInstanceID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand does not fail in practice; the id only has to differ
		// between runs, so fall back to the clock.
		return fmt.Sprintf("%08x", uint32(time.Now().UnixNano()))
	}
	return hex.EncodeToString(b)
}

// NewInstanceID returns the random id the Runner uses for one run. It is
// exported so a caller that also opens the WebSocket channel can report the
// same instance id in hello.instance_id as the HTTP link.
func NewInstanceID() string { return newInstanceID() }

// ---- loops -----------------------------------------------------------------

// jitter randomises d by +/- jitterFraction.
func (r *Runner) jitter(d time.Duration) time.Duration {
	return r.jitterBy(d, jitterFraction)
}

// jitterBy randomises d by +/- frac. A misbehaving random source is treated as
// the middle of the band.
func (r *Runner) jitterBy(d time.Duration, frac float64) time.Duration {
	f := r.rand()
	if f < 0 || f >= 1 || math.IsNaN(f) {
		f = 0.5
	}
	return time.Duration(float64(d) * (1 - frac + 2*frac*f))
}

// backoff is the failure delay: 30s, doubling, capped at 5 minutes.
type backoff struct{ cur time.Duration }

func (b *backoff) fail() time.Duration {
	switch {
	case b.cur == 0:
		b.cur = backoffStart
	case b.cur*2 > backoffMax:
		b.cur = backoffMax
	default:
		b.cur *= 2
	}
	return b.cur
}

func (b *backoff) reset() { b.cur = 0 }

// wait blocks for d, or until ctx ends, or (when allowRefresh) until a refresh
// is requested. It reports false when ctx ended.
func (r *Runner) wait(ctx context.Context, d time.Duration, allowRefresh bool) bool {
	var refresh <-chan struct{}
	if allowRefresh {
		refresh = r.refresh
	}
	select {
	case <-ctx.Done():
		return false
	case <-r.clock.After(d):
	case <-refresh:
	}
	return ctx.Err() == nil
}

func (r *Runner) pullLoop(ctx context.Context) {
	var bo backoff
	var delay time.Duration // the first pull happens immediately
	for first := true; ; first = false {
		if !first && !r.wait(ctx, delay, true) {
			return
		}
		if ctx.Err() != nil {
			return
		}
		err := r.safely("pull", func() error { return r.pullOnce(ctx) })
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			delay = r.jitter(max(r.pull, bo.fail()))
			r.log.Warnf("panel: pull failed, retrying in %s: %v", delay.Round(time.Second), err)
		default:
			bo.reset()
			delay = r.jitter(r.pull)
		}
	}
}

func (r *Runner) reportLoop(ctx context.Context) {
	var bo backoff
	delay := r.jitter(r.report)
	for {
		if !r.wait(ctx, delay, false) {
			return
		}
		err := r.safely("report", func() error { return r.reportOnce(ctx) })
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			delay = r.jitter(max(r.report, bo.fail()))
			r.log.Warnf("panel: report failed, retrying in %s: %v", delay.Round(time.Second), err)
		default:
			bo.reset()
			delay = r.jitter(r.report)
		}
	}
}

// safely runs f and turns a panic into an error, so a bug in one round can
// never take the agent process (and the forwarding it serves) down.
func (r *Runner) safely(what string, f func() error) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("%s panicked: %v", what, p)
		}
	}()
	return f()
}

// ---- pull ------------------------------------------------------------------

func (r *Runner) id() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.instanceID
}

func (r *Runner) have() (int64, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.haveRev, r.haveHash
}

// kernelEntryList collects the structured kernel list, or nil when it is
// unavailable. A collection failure is a missing field, never a failed pull or
// report (design section 3.3).
func (r *Runner) kernelEntryList() []wsproto.KernelEntry {
	if r.kernelEntries == nil {
		return nil
	}
	list, err := r.kernelEntries()
	if err != nil {
		r.log.Debugf("panel: cannot collect the structured kernel list: %v", err)
		return nil
	}
	if len(list) == 0 {
		return nil
	}
	return list
}

// reconcileKernelEntries converts the wire kernel entries into the local mirror
// type the reconciler's report uses, so agent/reconcile needs no wire import
// (design section 2.1).
func reconcileKernelEntries(in []wsproto.KernelEntry) []reconcile.KernelEntry {
	out := make([]reconcile.KernelEntry, len(in))
	for i, e := range in {
		out[i] = reconcile.KernelEntry{
			Name:        e.Name,
			Version:     e.Version,
			Current:     e.Current,
			Previous:    e.Previous,
			Path:        e.Path,
			SizeBytes:   e.SizeBytes,
			InstalledAt: e.InstalledAt,
			InUse:       e.InUse,
		}
	}
	return out
}

// pullOnce is one POST /config round, including the apply and the ack.
func (r *Runner) pullOnce(ctx context.Context) error {
	// An outcome the panel has not seen yet goes first: it is the freshest
	// truth, and if it cannot be delivered the panel is unreachable anyway.
	if err := r.flushAck(ctx); err != nil {
		return err
	}

	rev, hash := r.have()
	req := ConfigRequest{
		Schema:       Schema,
		InstanceID:   r.id(),
		AgentVersion: r.version,
		HaveRevision: rev,
		HaveHash:     hash,
		Platform:     Platform{OS: runtime.GOOS, Arch: runtime.GOARCH},
		Engines:      append([]string{}, r.engines...),
	}
	if r.featuresFunc != nil {
		// Recomputed every pull: a capability that appears while the agent
		// runs (the kernel installer gets a signed manifest) must reach the
		// panel without a restart.
		if f := r.featuresFunc(); len(f) > 0 {
			req.Features = append([]string{}, f...)
		}
	} else if len(r.features) > 0 {
		req.Features = append([]string{}, r.features...)
	}
	if r.kernels != nil {
		req.Kernels = r.kernels()
	}
	req.KernelEntries = r.kernelEntryList()
	resp, err := r.api.Config(ctx, req)
	if err != nil {
		return err
	}
	if r.onConnected != nil {
		// The panel answered: the link is proven. Called at most once, even
		// when every later pull succeeds too.
		r.connectedOnce.Do(r.onConnected)
	}

	if !resp.Unchanged {
		if err := r.applyResponse(ctx, resp); err != nil {
			r.handleCommands(ctx, resp.Commands)
			return err
		}
	}
	r.handleCommands(ctx, resp.Commands)
	return nil
}

// applyResponse applies the desired state of resp and sends the ack. It returns
// an error only when the ack could not be delivered (the apply outcome itself,
// good or bad, is reported through the ack, not through the error).
func (r *Runner) applyResponse(ctx context.Context, resp ConfigResponse) error {
	d, err := resp.Desired()
	if err != nil {
		var bad *ErrBadDesired
		if !errors.As(err, &bad) {
			bad = &ErrBadDesired{Err: err}
		}
		r.log.Warnf("panel: revision %d rejected without applying: %v", resp.Revision, bad)
		rep := reconcile.Report{
			Revision:  resp.Revision,
			Hash:      resp.Hash,
			Status:    reconcile.StatusRejected,
			Message:   bad.Error(),
			Instances: []reconcile.InstanceReport{},
			At:        r.clock.Now(),
		}
		return r.sendAck(ctx, resp, rep)
	}

	secrets := collectSecrets(d)
	r.mu.Lock()
	r.secrets = secrets
	haveRev, haveHash := r.haveRev, r.haveHash
	r.mu.Unlock()

	if haveRev > 0 && resp.Revision < haveRev && resp.Hash != haveHash {
		r.log.Warnf("panel: revision went backwards (%d -> %d) with a different hash; applying it anyway", haveRev, resp.Revision)
	}

	rep, applyErr := r.app.Apply(ctx, d)
	if rep.Status == "" {
		// Apply did not hand back a usable report: say what is known.
		msg := "apply returned no report"
		if applyErr != nil {
			msg = applyErr.Error()
		}
		rep = reconcile.Report{
			Revision: resp.Revision,
			Hash:     resp.Hash,
			Status:   reconcile.StatusFailed,
			Message:  msg,
			At:       r.clock.Now(),
		}
	}
	if rep.Instances == nil {
		rep.Instances = []reconcile.InstanceReport{}
	}
	// The ack carries the same structured kernel list as /report, so a panel
	// that just applied a revision sees what is installed without waiting for
	// the next report.
	if entries := r.kernelEntryList(); len(entries) > 0 {
		rep.KernelEntries = reconcileKernelEntries(entries)
	}
	rep = scrubReport(rep, secrets)

	if rep.Status == reconcile.StatusApplied {
		r.mu.Lock()
		r.haveRev, r.haveHash = resp.Revision, resp.Hash
		r.mu.Unlock()
		r.log.Infof("panel: applied revision %d (%d instance(s))", resp.Revision, len(rep.Instances))
	} else {
		r.log.Warnf("panel: revision %d was not applied: %s: %s", resp.Revision, rep.Status, rep.Message)
	}
	return r.sendAck(ctx, resp, rep)
}

// sendAck records the ack as the latest undelivered one and tries to deliver it.
func (r *Runner) sendAck(ctx context.Context, resp ConfigResponse, rep reconcile.Report) error {
	ack := AckRequest{
		Schema:     Schema,
		InstanceID: r.id(),
		Revision:   resp.Revision,
		Hash:       resp.Hash,
		Report:     rep,
	}
	r.mu.Lock()
	r.pendingAck = &ack
	r.mu.Unlock()
	return r.flushAck(ctx)
}

// flushAck delivers the pending ack, if any. A failed delivery keeps it for the
// next round, except for answers that will never succeed.
func (r *Runner) flushAck(ctx context.Context) error {
	r.mu.Lock()
	ack := r.pendingAck
	r.mu.Unlock()
	if ack == nil {
		return nil
	}
	if err := r.api.Ack(ctx, *ack); err != nil {
		if permanent(err) {
			r.log.Warnf("panel: dropping the ack of revision %d, the panel refuses it: %v", ack.Revision, err)
			r.clearAck(ack)
			return nil
		}
		return fmt.Errorf("ack of revision %d not delivered (will retry): %w", ack.Revision, err)
	}
	r.clearAck(ack)
	return nil
}

func (r *Runner) clearAck(ack *AckRequest) {
	r.mu.Lock()
	if r.pendingAck == ack {
		r.pendingAck = nil
	}
	r.mu.Unlock()
}

// permanent reports whether err is an answer a retry cannot change: a client
// error of the panel other than auth failures, rate limits and timeouts.
func permanent(err error) bool {
	var api *APIError
	if !errors.As(err, &api) {
		return false
	}
	switch api.Status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusRequestTimeout, http.StatusTooManyRequests:
		return false
	}
	return api.Status >= 400 && api.Status < 500
}

// ---- report ----------------------------------------------------------------

// reportOnce is one POST /report round.
func (r *Runner) reportOnce(ctx context.Context) error {
	rev, hash := r.have()
	last, hasLast := r.app.Last()
	counters := r.app.Stats(ctx)
	health := r.app.Health(ctx)

	r.mu.Lock()
	r.seq++
	seq, id := r.seq, r.instanceID
	r.mu.Unlock()

	req := ReportRequest{
		Schema:          Schema,
		InstanceID:      id,
		Seq:             seq,
		TS:              r.clock.Now().Unix(),
		AppliedRevision: rev,
		AppliedHash:     hash,
		Health:          health,
		Instances:       mergeInstances(last, hasLast, counters),
	}
	// While the WebSocket telemetry channel is up it carries the load; the
	// HTTP report then omits "host" entirely so the panel has one writer at a
	// time (design section 3.3). A disconnected WebSocket restores it at once.
	if r.suppressHost == nil || !r.suppressHost() {
		req.Host = r.host()
	}
	if hasLast && len(last.Kernels) > 0 {
		req.Kernels = last.Kernels
	}
	req.KernelEntries = r.kernelEntryList()
	resp, err := r.api.Report(ctx, req)
	if err != nil {
		return err
	}
	r.handleCommands(ctx, resp.Commands)
	return nil
}

// mergeInstances joins the instances of the last report with the counters by
// instance id. An engine without counters leaves the pointers nil.
func mergeInstances(last reconcile.Report, hasLast bool, counters []driver.Counter) []InstanceStat {
	byID := make(map[string]driver.Counter, len(counters))
	for _, c := range counters {
		byID[c.InstanceID] = c
	}
	out := []InstanceStat{}
	used := map[string]bool{}
	if hasLast {
		for _, in := range last.Instances {
			st := InstanceStat{ID: in.ID, State: in.State, Engine: in.Engine}
			if c, ok := byID[in.ID]; ok {
				st.setCounter(c)
				used[in.ID] = true
			}
			out = append(out, st)
		}
	}
	// A counter whose instance the last report does not list belongs to a
	// running instance of an earlier apply; it is still running.
	for _, c := range counters {
		if used[c.InstanceID] {
			continue
		}
		used[c.InstanceID] = true
		st := InstanceStat{ID: c.InstanceID, State: reconcile.StateRunning}
		st.setCounter(c)
		out = append(out, st)
	}
	return out
}

func (s *InstanceStat) setCounter(c driver.Counter) {
	up, down, active, total := c.BytesUp, c.BytesDown, c.ConnsActive, c.ConnsTotal
	s.BytesUp, s.BytesDown, s.ConnsActive, s.ConnsTotal = &up, &down, &active, &total
}

// ---- commands --------------------------------------------------------------

// handleCommands executes the whitelisted commands. A failure to deliver a
// result is logged; the command is then not remembered, so a redelivery by the
// panel is answered again.
func (r *Runner) handleCommands(ctx context.Context, cmds []Command) {
	for _, c := range cmds {
		if ctx.Err() != nil {
			return
		}
		r.runCommand(ctx, c)
	}
}

// ErrCommandAnswered is returned by ExecuteCommand for a command id that was
// already handled (on either channel): the caller must not answer it again, or
// the panel would see two results for one command id (ruling 7).
var ErrCommandAnswered = errors.New("panelclient: command already answered")

// ExecuteCommand runs one whitelisted command and returns its result without
// sending it: the caller delivers the result and then calls MarkAnswered. It is
// the single entry point shared by the HTTP command lists and the WebSocket cmd
// frames, so the whitelist, the expiry check and the id de-duplication exist
// exactly once (design section 3.4).
//
// expiresAt is an absolute unix second (0 = no expiry). ErrCommandAnswered
// means the id was already executed and must not be executed or answered again.
func (r *Runner) ExecuteCommand(ctx context.Context, id, typ string, args json.RawMessage, expiresAt int64) (string, json.RawMessage, error) {
	if id == "" {
		// A command without an id cannot be de-duplicated or answered.
		return "", nil, ErrCommandAnswered
	}
	r.mu.Lock()
	if _, dup := r.seen[id]; dup || r.inflight[id] {
		r.mu.Unlock()
		return "", nil, ErrCommandAnswered
	}
	r.inflight[id] = true
	r.mu.Unlock()

	// The slot is released here for a command that finished inline, and by
	// MarkAnswered/ReleaseCommand for a long one. The deferred release also
	// covers a handler that panics, so a crash cannot wedge an id forever.
	keepInflight := false
	defer func() {
		if keepInflight {
			return
		}
		r.mu.Lock()
		delete(r.inflight, id)
		r.mu.Unlock()
	}()

	status, result := r.execute(ctx, Command{ID: id, Type: typ, Args: args, ExpiresAt: expiresAt})
	if status == ResultAccepted {
		// A long command owns the id until its final result is delivered: the
		// accepted answer and the final one share the id, and a redelivery in
		// between must not run the command twice (design section 3.1 point 5).
		// MarkAnswered (or ReleaseCommand) clears the slot.
		keepInflight = true
	}
	return status, result, nil
}

// MarkAnswered records that the result of id reached the panel, so a
// redelivery on either channel is ignored. It also releases the in-flight slot
// a long command held. A result that could not be delivered must not be
// marked: the panel is expected to send the command again.
func (r *Runner) MarkAnswered(id string) {
	r.mu.Lock()
	delete(r.inflight, id)
	r.mu.Unlock()
	r.remember(id)
}

// ReleaseCommand forgets an in-flight id without remembering it, so a
// redelivery runs the command again. The channels call it when a result they
// were meant to deliver could not be sent (a long command's final result in
// particular): keeping the slot would make the panel's redelivery a no-op and
// leave the command unanswered forever.
func (r *Runner) ReleaseCommand(id string) {
	r.mu.Lock()
	delete(r.inflight, id)
	r.mu.Unlock()
}

// DeliverResult sends the final result of a long command (one that already
// answered "accepted" over the same or the other channel) and remembers the
// id. A delivery that fails releases the id so the panel's redelivery runs the
// command again.
func (r *Runner) DeliverResult(ctx context.Context, id, status string, result json.RawMessage) error {
	err := r.api.CommandResult(ctx, CommandResultRequest{
		Schema:     Schema,
		InstanceID: r.id(),
		ID:         id,
		Status:     status,
		Result:     result,
	})
	if err != nil {
		r.ReleaseCommand(id)
		return err
	}
	r.MarkAnswered(id)
	return nil
}

// RequestRefresh wakes the pull loop, so the desired state is pulled now
// instead of at the end of the interval (the "refresh" command and the
// "desired" hint).
func (r *Runner) RequestRefresh() {
	select {
	case r.refresh <- struct{}{}:
	default: // a refresh is already pending
	}
}

// InstanceID returns the id this link uses: the configured one before Run, the
// generated one once it is running ("" when neither exists yet). The WebSocket
// hello reports the same id, so both channels identify one agent run.
func (r *Runner) InstanceID() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.instanceID != "" {
		return r.instanceID
	}
	return r.fixedID
}

func (r *Runner) runCommand(ctx context.Context, c Command) {
	if c.ID == "" {
		r.log.Warnf("panel: ignoring a command without an id")
		return
	}
	status, result, err := r.ExecuteCommand(ctx, c.ID, c.Type, c.Args, c.ExpiresAt)
	if errors.Is(err, ErrCommandAnswered) {
		// Already executed (or unanswerable): never execute or answer twice.
		return
	}
	if err != nil {
		r.log.Warnf("panel: command %q not executed: %v", c.ID, err)
		return
	}
	err = r.api.CommandResult(ctx, CommandResultRequest{
		Schema:     Schema,
		InstanceID: r.id(),
		ID:         c.ID,
		Status:     status,
		Result:     result,
	})
	if err != nil {
		r.log.Warnf("panel: result of command %q not delivered: %v", c.ID, err)
		return
	}
	if status == ResultAccepted {
		// Only the accepted half is on the wire: the id stays in flight until
		// the final result of the long command is delivered.
		return
	}
	r.MarkAnswered(c.ID)
}

// execute runs one command and returns its status and result.
func (r *Runner) execute(ctx context.Context, c Command) (string, json.RawMessage) {
	if c.ExpiresAt != 0 && r.clock.Now().Unix() >= c.ExpiresAt {
		r.log.Infof("panel: command %q expired", c.ID)
		return ResultExpired, nil
	}
	switch c.Type {
	case CmdRefresh:
		r.RequestRefresh()
		rev, _ := r.have()
		return ResultDone, mustJSON(map[string]int64{"revision": rev})
	case CmdDumpState:
		return ResultDone, r.dumpState(ctx)
	}
	// Everything else is the operations registry's business: it holds the
	// whitelist of the types it serves and answers "unsupported command" for
	// the rest (design section 2.1). Without a registry the answer is the same
	// as before the registry existed.
	if r.commands != nil {
		return r.commands.Execute(ctx, c)
	}
	r.log.Warnf("panel: refusing unsupported command type %q", c.Type)
	return ResultFailed, mustJSON(map[string]string{"error": "unsupported command"})
}

// dumpState is the result of the dump_state command: the last report and the
// health, scrubbed of every secret the Runner has seen.
func (r *Runner) dumpState(ctx context.Context) json.RawMessage {
	r.mu.Lock()
	secrets := r.secrets
	r.mu.Unlock()
	out := struct {
		Report *reconcile.Report      `json:"report"`
		Health reconcile.HealthReport `json:"health"`
	}{Health: r.app.Health(ctx)}
	if rep, ok := r.app.Last(); ok {
		rep = scrubReport(rep, secrets)
		out.Report = &rep
	}
	return mustJSON(out)
}

func (r *Runner) remember(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.seen[id]; ok {
		return
	}
	r.seen[id] = struct{}{}
	r.seenOrder = append(r.seenOrder, id)
	for len(r.seenOrder) > seenCommands {
		delete(r.seen, r.seenOrder[0])
		r.seenOrder = r.seenOrder[1:]
	}
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{"error":"encode failed"}`)
	}
	return b
}

// ---- secret scrubbing (defence in depth) -----------------------------------

// collectSecrets lists the instance secrets of d that are long enough to be
// searched for in text.
func collectSecrets(d spec.Desired) []string {
	var out []string
	seen := map[string]bool{}
	for _, in := range d.Instances {
		if len(in.Secret) >= minScrubSecret && !seen[in.Secret] {
			seen[in.Secret] = true
			out = append(out, in.Secret)
		}
	}
	return out
}

func scrubText(s string, secrets []string) string {
	for _, sec := range secrets {
		if strings.Contains(s, sec) {
			s = strings.ReplaceAll(s, sec, "***")
		}
	}
	return s
}

// scrubReport returns a copy of rep with every secret replaced in the free
// text fields. The reconciler already does this; doing it again here means a
// future leak in the reconciler cannot reach the panel through the Runner.
func scrubReport(rep reconcile.Report, secrets []string) reconcile.Report {
	if len(secrets) == 0 {
		return rep
	}
	rep.Message = scrubText(rep.Message, secrets)
	if len(rep.ValidationErrors) > 0 {
		ves := append(rep.ValidationErrors[:0:0], rep.ValidationErrors...)
		for i := range ves {
			ves[i].Message = scrubText(ves[i].Message, secrets)
		}
		rep.ValidationErrors = ves
	}
	ins := make([]reconcile.InstanceReport, len(rep.Instances))
	for i, in := range rep.Instances {
		in.Error = scrubText(in.Error, secrets)
		if in.Considered != nil {
			m := make(map[string]string, len(in.Considered))
			for k, v := range in.Considered {
				m[k] = scrubText(v, secrets)
			}
			in.Considered = m
		}
		ins[i] = in
	}
	rep.Instances = ins
	return rep
}
