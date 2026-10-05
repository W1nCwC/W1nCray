// Package reconcile turns a desired state into running kernels. It validates
// the desired state against the local policy, chooses an engine for every
// instance, renders and preflights the result, makes sure the needed kernels
// are installed, applies per driver, checks health, and rolls everything back
// to the last good state if any step fails.
//
// Outcome vocabulary (see Status): rejected and failed leave the running
// configuration untouched; rolled_back means the last good state was restored
// (and the failed hash is blocked until the desired state changes); partial
// means the restore itself was incomplete.
//
// Evidence levels for callers: Apply is serialised; Health may run at any time
// and reports "skipped" while an Apply is in flight.
package reconcile

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/portledger"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/agent/state"
	"github.com/W1nCwC/W1nCray/agent/validate"
)

// KernelEnsurer is what the reconciler needs from the kernel manager. It is
// declared here so this package does not import the kernel package.
type KernelEnsurer interface {
	// Ensure makes the pinned kernel available (installing it if needed) and
	// returns what to run. An empty pin.Version means the manager's default.
	Ensure(ctx context.Context, pin spec.KernelPin) (driver.Installed, error)
	// Available reports whether the kernel can be used on this machine at all
	// (platform covered by the signed manifest, not revoked, ...), with a
	// human readable reason when it cannot.
	Available(name string) (ok bool, reason string)
}

// Defaults for the optional Reconciler fields.
const (
	DefaultHealthWindow    = 3 * time.Second
	DefaultHealthInterval  = 200 * time.Millisecond
	DefaultRollbackTimeout = 30 * time.Second
)

// BuiltinVersion is reported as the kernel version of non-external drivers.
const BuiltinVersion = "builtin"

// Reconciler applies desired states. The exported fields are configuration
// and must not be changed while an Apply is running.
type Reconciler struct {
	Drivers map[string]driver.Driver
	Kernels KernelEnsurer
	Sup     driver.Supervisor
	Policy  spec.Policy
	// State persists the desired and last good state and gives each driver its
	// private directory. Required.
	State *state.Store
	// Ports is the port ledger; a fresh one is created if nil.
	Ports *portledger.Ledger
	Log   driver.Logger

	// ValidateOpts configures the validator (resolver, timeout).
	ValidateOpts validate.Options
	// HealthWindow is how long Apply waits for the new configuration to become
	// healthy (default 3s; negative means a single check).
	HealthWindow time.Duration
	// HealthInterval is the polling interval inside the window (default 200ms).
	HealthInterval time.Duration
	// RollbackTimeout bounds the rollback after a failure (default 30s). The
	// rollback runs even if the Apply context was cancelled.
	RollbackTimeout time.Duration
	// RequireStats makes engines without traffic counters ineligible. (The
	// desired-state schema has no per-instance metering flag yet.)
	RequireStats bool
	// FreeSpace returns the free bytes where kernels are installed; nil
	// disables the disk space check.
	FreeSpace func() (int64, error)
	// Now is the clock (tests); default time.Now.
	Now func() time.Time

	mu       sync.Mutex // serialises Apply and Resume
	applying atomic.Bool

	inited       bool
	cur          *applied // last successfully applied state
	blockedHash  string
	blockedWhy   string
	lastDrivers  map[string]bool // drivers that ran instances in the last good state
	lastRuntimes map[string]driver.Runtime
	secrets      []string // of the Apply in flight, for scrubbing log lines

	snapMu  sync.RWMutex
	last    Report // outcome of the most recent Apply
	hasLast bool
}

// applied is an immutable record of a successfully applied desired state.
type applied struct {
	desired spec.Desired
	hash    string
	report  Report
	sets    map[string][]driver.Rendered
	rts     map[string]driver.Runtime
	claims  []driver.PortClaim
	engines map[string]string
}

type planned struct {
	idx    int
	in     spec.Instance // engine resolved
	driver string
	art    driver.Artifact
}

type nopLog struct{}

func (nopLog) Debugf(string, ...any) {}
func (nopLog) Infof(string, ...any)  {}
func (nopLog) Warnf(string, ...any)  {}
func (nopLog) Errorf(string, ...any) {}

func (r *Reconciler) logger() driver.Logger {
	if r.Log != nil {
		return r.Log
	}
	return nopLog{}
}

func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Reconciler) logf(level, format string, args ...any) {
	msg := scrub(fmt.Sprintf(format, args...), r.secrets)
	l := r.logger()
	switch level {
	case "warn":
		l.Warnf("reconcile: %s", msg)
	case "error":
		l.Errorf("reconcile: %s", msg)
	default:
		l.Infof("reconcile: %s", msg)
	}
}

// scrubbedError carries a message with secrets removed and keeps the sentinel
// reachable through errors.Is.
type scrubbedError struct {
	msg  string
	base error
}

func (e *scrubbedError) Error() string { return e.msg }
func (e *scrubbedError) Unwrap() error { return e.base }

func (r *Reconciler) errorf(base error, format string, args ...any) error {
	return &scrubbedError{msg: scrub(base.Error()+": "+fmt.Sprintf(format, args...), r.secrets), base: base}
}

// init loads persisted bookkeeping once.
func (r *Reconciler) init() error {
	if r.inited {
		return nil
	}
	if r.State == nil {
		return errors.New("reconcile: State store is required")
	}
	if r.Ports == nil {
		r.Ports = portledger.New()
	}
	if r.lastDrivers == nil {
		r.lastDrivers = map[string]bool{}
	}
	if r.lastRuntimes == nil {
		r.lastRuntimes = map[string]driver.Runtime{}
	}
	h, why, err := r.State.LoadBlocked()
	if err != nil {
		r.logf("warn", "cannot read blocked state: %v", err)
	}
	r.blockedHash, r.blockedWhy = h, why
	r.inited = true
	return nil
}

// Last returns the report of the most recent Apply.
func (r *Reconciler) Last() (Report, bool) {
	r.snapMu.RLock()
	defer r.snapMu.RUnlock()
	return r.last.clone(), r.hasLast
}

func (r *Reconciler) currentApplied() *applied {
	r.snapMu.RLock()
	defer r.snapMu.RUnlock()
	return r.cur
}

// Apply makes d the running state. The returned Report is always meaningful;
// the error is nil only for StatusApplied (including the no-op repeat of an
// already applied hash) and otherwise wraps one of ErrRejected, ErrFailed,
// ErrRolledBack, ErrPartial or ErrBlocked.
func (r *Reconciler) Apply(ctx context.Context, d spec.Desired) (Report, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.applying.Store(true)
	defer r.applying.Store(false)

	r.secrets = collectSecrets(d)
	defer func() { r.secrets = nil }()

	rep, err := r.apply(ctx, d)
	scrubReport(&rep, r.secrets)
	r.snapMu.Lock()
	r.last, r.hasLast = rep.clone(), true
	r.snapMu.Unlock()
	return rep, err
}

// Resume applies the persisted last good state, for use at start-up. It
// returns (zero Report, nil) if nothing was persisted.
func (r *Reconciler) Resume(ctx context.Context) (Report, error) {
	r.mu.Lock()
	if err := r.init(); err != nil {
		r.mu.Unlock()
		return Report{}, err
	}
	sn, ok, err := r.State.LoadLastGood()
	if err != nil {
		r.mu.Unlock()
		return Report{}, fmt.Errorf("reconcile: %w", err)
	}
	if !ok {
		r.mu.Unlock()
		return Report{}, nil
	}
	for _, eng := range sn.Engines {
		r.lastDrivers[eng] = true
	}
	r.mu.Unlock()
	return r.Apply(ctx, sn.Desired)
}

func baseInstances(d spec.Desired) []InstanceReport {
	out := make([]InstanceReport, len(d.Instances))
	for i, in := range d.Instances {
		ir := InstanceReport{ID: in.ID, Requested: in.Engine, State: StateNotApplied}
		if !in.Enabled {
			ir.State = StateDisabled
		}
		out[i] = ir
	}
	return out
}

func (r *Reconciler) apply(ctx context.Context, d spec.Desired) (Report, error) {
	if err := r.init(); err != nil {
		return Report{Revision: d.Revision, Hash: state.Hash(d), Status: StatusFailed, Message: err.Error(), At: r.now(), Instances: baseInstances(d)}, err
	}
	hash := state.Hash(d)
	rep := Report{Revision: d.Revision, Hash: hash, At: r.now(), Instances: baseInstances(d)}
	pol := validate.NormalizePolicy(r.Policy)

	// Same content as what runs: nothing to do.
	if cur := r.currentApplied(); cur != nil && cur.hash == hash {
		out := cur.report.clone()
		out.Revision, out.At, out.Message = d.Revision, rep.At, "unchanged: this desired state is already applied"
		return out, nil
	}
	// Same content as what already failed: do not hammer the machine.
	if r.blockedHash != "" && r.blockedHash == hash {
		rep.Status, rep.Blocked = StatusRolledBack, true
		rep.Message = "this desired state failed before and is blocked until it changes"
		if r.blockedWhy != "" {
			rep.Message += ": " + r.blockedWhy
		}
		return rep, r.errorf(ErrBlocked, "%s", r.blockedWhy)
	}

	// 1. validate
	if errs := validate.Desired(d, pol, r.ValidateOpts); len(errs) > 0 {
		rep.Status = StatusRejected
		rep.ValidationErrors = errs
		rep.Message = fmt.Sprintf("desired state rejected: %d validation error(s)", len(errs))
		for _, e := range errs {
			if e.Index >= 0 && e.Index < len(rep.Instances) {
				ir := &rep.Instances[e.Index]
				if ir.State != StateRejected {
					ir.State, ir.Error = StateRejected, e.Field+": "+e.Message
				}
			}
		}
		return rep, r.errorf(ErrRejected, "%s", errs[0].Error())
	}

	// 2. choose engines, render
	plans, ok := r.plan(d, pol, &rep)
	if !ok {
		rep.Status = StatusRejected
		return rep, r.errorf(ErrRejected, "%s", rep.Message)
	}

	// 3. ports: static conflicts + real bind probe
	claims := allClaims(plans)
	if conflicts := r.Ports.Preflight(ctx, claims); len(conflicts) > 0 {
		for _, c := range conflicts {
			r.markConflict(&rep, c)
		}
		rep.Status = StatusRejected
		rep.Message = fmt.Sprintf("port conflict: %s", conflicts[0])
		if len(conflicts) > 1 {
			rep.Message += fmt.Sprintf(" (and %d more)", len(conflicts)-1)
		}
		return rep, r.errorf(ErrRejected, "%s", rep.Message)
	}

	// 4. kernels
	byDriver := groupByDriver(plans)
	names := sortedKeys(byDriver)
	rts := map[string]driver.Runtime{}
	rep.Kernels = map[string]string{}
	for _, name := range names {
		rt, err := r.runtime(ctx, d, name)
		if err != nil {
			rep.Status = StatusFailed
			rep.Message = fmt.Sprintf("kernel for engine %q is not available: %v", name, err)
			for _, p := range byDriver[name] {
				rep.Instances[p.idx].State = StateFailed
				rep.Instances[p.idx].Error = err.Error()
			}
			return rep, r.errorf(ErrFailed, "%s", rep.Message)
		}
		rts[name] = rt
		rep.Kernels[name] = rt.Kernel.Version
		if rt.Kernel.Version == "" {
			rep.Kernels[name] = BuiltinVersion
		}
	}
	// Drivers that ran instances before but have none now still need a call
	// (empty set) so their instances are removed.
	all := append([]string(nil), names...)
	for n := range r.lastDrivers {
		if _, in := byDriver[n]; !in && r.Drivers[n] != nil {
			rt, err := r.removalRuntime(n)
			if err != nil {
				rep.Status = StatusFailed
				rep.Message = fmt.Sprintf("cannot prepare driver %q for removal: %v", n, err)
				return rep, r.errorf(ErrFailed, "%s", rep.Message)
			}
			rts[n] = rt
			all = append(all, n)
		}
	}
	sort.Strings(all)

	if err := r.State.SaveDesired(d); err != nil {
		rep.Status = StatusFailed
		rep.Message = "cannot persist the desired state: " + err.Error()
		return rep, r.errorf(ErrFailed, "%s", rep.Message)
	}

	// 5. apply, driver by driver
	sets := map[string][]driver.Rendered{}
	for _, name := range names {
		set := make([]driver.Rendered, 0, len(byDriver[name]))
		for _, p := range byDriver[name] {
			set = append(set, driver.Rendered{Instance: p.in, Artifact: p.art})
		}
		sets[name] = set
	}
	prevClaims := r.Ports.Claims()
	var touched []string
	failedInst := map[int]string{}
	var failure, errDriver string
	for _, name := range all {
		touched = append(touched, name)
		res, err := r.callApply(ctx, name, rts[name], sets[name])
		if err != nil {
			failure = fmt.Sprintf("engine %q failed to apply: %v", name, err)
			errDriver = name
			// A driver-level error does not say which instance is at fault.
			// Instances that were not running before cannot be running now, so
			// they are the failed ones; instances that were running are reported
			// as rolled back to what they were.
			for _, p := range byDriver[name] {
				if !r.wasRunning(name, p.in.ID) {
					failedInst[p.idx] = err.Error()
				}
			}
			break
		}
		if len(res.Failed) > 0 {
			ids := make([]string, 0, len(res.Failed))
			for id := range res.Failed {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			failure = fmt.Sprintf("engine %q could not run %d instance(s): %s: %s", name, len(ids), ids[0], res.Failed[ids[0]])
			for _, p := range byDriver[name] {
				if msg, bad := res.Failed[p.in.ID]; bad {
					failedInst[p.idx] = msg
				}
			}
			break
		}
	}

	// 6. health window
	var plan *applied
	if failure == "" {
		engines := map[string]string{}
		for _, p := range plans {
			engines[p.in.ID] = p.driver
		}
		plan = &applied{desired: d, hash: hash, sets: sets, rts: rts, claims: claims, engines: engines}
		r.Ports.Commit(claims)
		diffs := r.waitHealthy(ctx, plan)
		if len(diffs) > 0 {
			failure = fmt.Sprintf("health check failed: %s", diffs[0].describe())
			if len(diffs) > 1 {
				failure += fmt.Sprintf(" (and %d more)", len(diffs)-1)
			}
			for _, df := range diffs {
				for _, p := range plans {
					if p.in.ID == df.Instance {
						failedInst[p.idx] = df.describe()
					}
				}
			}
		}
	}

	if failure != "" {
		out := r.fail(ctx, rep, plans, touched, errDriver, rts, prevClaims, failedInst, failure, hash)
		base := ErrRolledBack
		if out.Status == StatusPartial {
			base = ErrPartial
		}
		return out, r.errorf(base, "%s", failure)
	}

	// 7. success
	for _, p := range plans {
		ir := &rep.Instances[p.idx]
		ir.State, ir.Engine, ir.ConfigHash = StateRunning, p.driver, p.art.Hash
	}
	fillPorts(&rep, plans)
	rep.Status = StatusApplied
	rep.Message = fmt.Sprintf("applied %d instance(s)", len(plans))
	if err := r.State.SaveLastGood(d, plan.engines); err != nil {
		r.logf("warn", "cannot persist last_good: %v", err)
		rep.Message += "; warning: last good state could not be saved: " + err.Error()
	}
	if err := r.State.ClearBlocked(); err != nil {
		r.logf("warn", "cannot clear blocked hash: %v", err)
	}
	r.blockedHash, r.blockedWhy = "", ""
	r.lastDrivers = map[string]bool{}
	for _, n := range names {
		r.lastDrivers[n] = true
	}
	for n, rt := range rts {
		r.lastRuntimes[n] = rt
	}
	plan.report = rep.clone()
	r.snapMu.Lock()
	r.cur = plan
	r.snapMu.Unlock()
	r.logf("info", "applied revision %d (%s): %d instance(s) on %d engine(s)", d.Revision, shortHash(hash), len(plans), len(names))
	return rep, nil
}

// wasRunning reports whether the last applied state ran this instance on that
// driver.
func (r *Reconciler) wasRunning(driverName, id string) bool {
	cur := r.currentApplied()
	if cur == nil {
		return false
	}
	for _, rd := range cur.sets[driverName] {
		if rd.Instance.ID == id {
			return true
		}
	}
	return false
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func (df Diff) describe() string {
	if df.Detail == "" {
		return fmt.Sprintf("%s: %s", df.Instance, df.Kind)
	}
	return fmt.Sprintf("%s: %s (%s)", df.Instance, df.Kind, df.Detail)
}

// plan selects engines and renders every enabled instance, recording the
// outcome in rep. ok is false if any instance cannot be planned.
func (r *Reconciler) plan(d spec.Desired, pol spec.Policy, rep *Report) (plans []planned, ok bool) {
	bad := 0
	for i, in := range d.Instances {
		if !in.Enabled {
			continue
		}
		ir := &rep.Instances[i]
		sel, err := r.selectEngine(in, pol)
		ir.Considered = sel.considered
		if err != nil {
			ir.State, ir.Error = StateRejected, err.Error()
			bad++
			continue
		}
		ir.Engine = sel.engine
		in.Engine = sel.engine
		var art driver.Artifact
		err = protect("render", func() (e error) { art, e = r.Drivers[sel.engine].Render(in); return })
		if err == nil && art.Hash == "" {
			err = errors.New("driver returned an artifact without a hash")
		}
		if err == nil {
			for _, c := range art.PortClaims {
				if c.Owner != in.ID {
					err = fmt.Errorf("driver claimed a port for %q on behalf of this instance", c.Owner)
					break
				}
			}
		}
		if err != nil {
			ir.State, ir.Error = StateRejected, "render: "+err.Error()
			bad++
			continue
		}
		plans = append(plans, planned{idx: i, in: in, driver: sel.engine, art: art})
	}
	if bad > 0 {
		rep.Message = fmt.Sprintf("%d instance(s) cannot be applied", bad)
		for _, ir := range rep.Instances {
			if ir.State == StateRejected {
				rep.Message += fmt.Sprintf("; first: %s: %s", ir.ID, ir.Error)
				break
			}
		}
		return nil, false
	}
	return plans, true
}

func allClaims(plans []planned) []driver.PortClaim {
	var out []driver.PortClaim
	for _, p := range plans {
		out = append(out, p.art.PortClaims...)
	}
	return out
}

func groupByDriver(plans []planned) map[string][]planned {
	m := map[string][]planned{}
	for _, p := range plans {
		m[p.driver] = append(m[p.driver], p)
	}
	for _, ps := range m {
		sort.Slice(ps, func(i, j int) bool { return ps[i].in.ID < ps[j].in.ID })
	}
	return m
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func fillPorts(rep *Report, plans []planned) {
	for _, p := range plans {
		rep.Instances[p.idx].Ports = compactClaims(p.art.PortClaims)
	}
}

func (r *Reconciler) markConflict(rep *Report, c portledger.Conflict) {
	owners := map[string]bool{}
	for _, cl := range []struct{ o string }{{c.A.Owner}, {c.B.Owner}} {
		if cl.o != "" && !strings.HasPrefix(cl.o, portledger.ReservedPrefix) {
			owners[cl.o] = true
		}
	}
	for i := range rep.Instances {
		ir := &rep.Instances[i]
		if owners[ir.ID] && ir.State != StateRejected {
			ir.State, ir.Error = StateRejected, "port conflict: "+c.String()
		}
	}
}

// runtime ensures the kernel for a driver and builds its Runtime.
func (r *Reconciler) runtime(ctx context.Context, d spec.Desired, name string) (driver.Runtime, error) {
	drv := r.Drivers[name]
	caps := drv.Caps()
	rt := driver.Runtime{Sup: r.Sup, Log: r.logger()}
	if caps.External {
		if r.Kernels == nil {
			return rt, errors.New("no kernel manager")
		}
		pin := spec.KernelPin{Name: name}
		for _, k := range d.Kernels {
			if k.Name == name {
				pin = k
			}
		}
		inst, err := r.Kernels.Ensure(ctx, pin)
		if err != nil {
			return rt, err
		}
		rt.Kernel = inst
	} else {
		rt.Kernel = driver.Installed{Version: BuiltinVersion}
	}
	dir, err := r.State.DriverDir(name)
	if err != nil {
		return rt, err
	}
	rt.StateDir = dir
	return rt, nil
}

// removalRuntime is the Runtime for a driver that is being emptied: the kernel
// it ran last time (no installation is attempted).
func (r *Reconciler) removalRuntime(name string) (driver.Runtime, error) {
	rt, ok := r.lastRuntimes[name]
	if !ok {
		rt = driver.Runtime{Kernel: driver.Installed{}}
	}
	rt.Sup, rt.Log = r.Sup, r.logger()
	dir, err := r.State.DriverDir(name)
	if err != nil {
		return rt, err
	}
	rt.StateDir = dir
	return rt, nil
}

// protect turns a driver panic into an error: a buggy driver must not take
// the agent (and every other kernel) down.
func protect(what string, f func() error) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("driver panic in %s: %v", what, p)
		}
	}()
	return f()
}

func (r *Reconciler) callApply(ctx context.Context, name string, rt driver.Runtime, set []driver.Rendered) (res driver.ApplyResult, err error) {
	err = protect("apply", func() (e error) { res, e = r.Drivers[name].Apply(ctx, rt, set); return })
	return
}

// fail restores the last good state after a failed apply.
func (r *Reconciler) fail(ctx context.Context, rep Report, plans []planned, touched []string, errDriver string, rts map[string]driver.Runtime,
	prevClaims []driver.PortClaim, failedInst map[int]string, failure, hash string) Report {

	r.logf("error", "%s; rolling back", failure)
	timeout := r.RollbackTimeout
	if timeout <= 0 {
		timeout = DefaultRollbackTimeout
	}
	rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()

	rbErr := map[string]error{}
	for i := len(touched) - 1; i >= 0; i-- {
		name := touched[i]
		drv := r.Drivers[name]
		var err error
		switch {
		case name == errDriver && r.lastDrivers[name]:
			// The driver contract: a failed Apply restores the previous good
			// configuration itself. Calling Rollback now would undo it twice.
		case r.lastDrivers[name]:
			err = protect("rollback", func() error { return drv.Rollback(rbCtx, rts[name]) })
		default:
			// nothing good to go back to for this driver: leave it stopped
			err = protect("stop", func() error { return drv.Stop(rbCtx, rts[name]) })
		}
		if err != nil {
			rbErr[name] = err
			r.logf("error", "rollback of engine %q failed: %v", name, err)
		}
	}
	// Do not trust the restore blindly: the previous state must be healthy again.
	if cur := r.currentApplied(); cur != nil && len(rbErr) == 0 {
		if diffs := r.waitHealthy(rbCtx, cur); len(diffs) > 0 {
			rbErr["verify"] = fmt.Errorf("the previous state is not healthy after the rollback: %s", diffs[0].describe())
		}
	}
	r.Ports.Commit(prevClaims)

	rep.Status = StatusRolledBack
	rep.Message = "apply failed, last good state restored: " + failure
	if len(rbErr) > 0 {
		rep.Status = StatusPartial
		var parts []string
		for _, n := range sortedKeys(rbErr) {
			parts = append(parts, fmt.Sprintf("%s: %v", n, rbErr[n]))
		}
		rep.Message = "apply failed and the rollback was incomplete (" + strings.Join(parts, "; ") + "): " + failure
	}
	touchedSet := map[string]bool{}
	for _, n := range touched {
		touchedSet[n] = true
	}
	for _, p := range plans {
		ir := &rep.Instances[p.idx]
		ir.Engine = p.driver
		ir.Ports = compactClaims(p.art.PortClaims)
		switch {
		case failedInst[p.idx] != "":
			ir.State, ir.Error = StateFailed, failedInst[p.idx]
		case touchedSet[p.driver]:
			ir.State = StateRolledBack
		}
	}

	if err := r.State.SaveBlocked(hash, scrub(failure, r.secrets)); err != nil {
		r.logf("warn", "cannot persist blocked hash: %v", err)
	}
	r.blockedHash, r.blockedWhy = hash, scrub(failure, r.secrets)
	return rep
}

// ---- health -------------------------------------------------------------

// checkPlan compares the plan with reality: driver health per instance, then
// a bind probe of every claimed port, so a driver that claims to listen while
// the port is free is caught.
func (r *Reconciler) checkPlan(ctx context.Context, a *applied) []Diff {
	var diffs []Diff
	for _, name := range sortedKeys(a.sets) {
		drv := r.Drivers[name]
		if drv == nil {
			for _, rd := range a.sets[name] {
				diffs = append(diffs, Diff{Instance: rd.Instance.ID, Kind: "driver_missing", Detail: name})
			}
			continue
		}
		var h driver.Health
		if err := protect("health", func() error { h = drv.Health(ctx, a.rts[name]); return nil }); err != nil {
			for _, rd := range a.sets[name] {
				diffs = append(diffs, Diff{Instance: rd.Instance.ID, Kind: "not_running", Detail: err.Error()})
			}
			continue
		}
		want := map[string]bool{}
		for _, rd := range a.sets[name] {
			id := rd.Instance.ID
			want[id] = true
			ih, ok := h.Instances[id]
			switch {
			case !ok:
				diffs = append(diffs, Diff{Instance: id, Kind: "missing", Detail: "the engine does not know this instance"})
			case !ih.Running:
				diffs = append(diffs, Diff{Instance: id, Kind: "not_running", Detail: ih.Err})
			case ih.ConfigHash != rd.Artifact.Hash:
				diffs = append(diffs, Diff{Instance: id, Kind: "hash_mismatch", Detail: "running configuration differs from the applied one"})
			case len(rd.Artifact.PortClaims) > 0 && !ih.Listening:
				diffs = append(diffs, Diff{Instance: id, Kind: "not_listening", Detail: ih.Err})
			}
		}
		for id := range h.Instances {
			if !want[id] {
				diffs = append(diffs, Diff{Instance: id, Kind: "unexpected", Detail: "running but not in the applied state"})
			}
		}
	}
	// Cross-check with the ledger: ports the engine claims to serve must be
	// really bound.
	bad := map[string]bool{}
	for _, d := range diffs {
		bad[d.Instance] = true
	}
	for _, f := range r.Ports.CheckClaims(ctx, a.claims) {
		if f.Kind != portledger.FindNotListening || bad[f.Claim.Owner] {
			continue
		}
		bad[f.Claim.Owner] = true
		diffs = append(diffs, Diff{Instance: f.Claim.Owner, Kind: "port_not_bound", Detail: claimText(f.Claim)})
	}
	sort.SliceStable(diffs, func(i, j int) bool {
		if diffs[i].Instance != diffs[j].Instance {
			return diffs[i].Instance < diffs[j].Instance
		}
		return diffs[i].Kind < diffs[j].Kind
	})
	return diffs
}

func claimText(c driver.PortClaim) string {
	return fmt.Sprintf("%s %s:%d", c.Proto, c.Addr, c.Port)
}

// waitHealthy polls checkPlan until it is clean or the window ends.
func (r *Reconciler) waitHealthy(ctx context.Context, a *applied) []Diff {
	window := r.HealthWindow
	if window == 0 {
		window = DefaultHealthWindow
	}
	interval := r.HealthInterval
	if interval <= 0 {
		interval = DefaultHealthInterval
	}
	deadline := time.Now().Add(window)
	for {
		diffs := r.checkPlan(ctx, a)
		if len(diffs) == 0 || window < 0 || !time.Now().Before(deadline) {
			return diffs
		}
		select {
		case <-ctx.Done():
			return diffs
		case <-time.After(interval):
		}
	}
}

// Health compares the applied state with reality once. The caller schedules
// it (for example every report interval). While an Apply is running it returns
// a report with Skipped set instead of racing the apply.
func (r *Reconciler) Health(ctx context.Context) HealthReport {
	hr := HealthReport{At: r.now()}
	if r.applying.Load() {
		hr.Skipped = "an apply is in progress"
		return hr
	}
	a := r.currentApplied()
	if a == nil {
		hr.Skipped = "nothing has been applied"
		return hr
	}
	hr.Revision, hr.Hash = a.desired.Revision, a.hash
	hr.Diffs = r.checkPlan(ctx, a)
	hr.OK = len(hr.Diffs) == 0
	return hr
}

// Stats collects the cumulative counters of every driver that runs
// instances. Drivers that fail are skipped (and logged).
func (r *Reconciler) Stats(ctx context.Context) []driver.Counter {
	a := r.currentApplied()
	if a == nil {
		return nil
	}
	var out []driver.Counter
	for _, name := range sortedKeys(a.sets) {
		drv := r.Drivers[name]
		if drv == nil {
			continue
		}
		var cs []driver.Counter
		err := protect("stats", func() (e error) { cs, e = drv.Stats(ctx, a.rts[name]); return })
		if err != nil {
			// not r.logf: that reads state owned by Apply, and Stats may run concurrently
			r.logger().Warnf("reconcile: stats of engine %q: %v", name, err)
			continue
		}
		out = append(out, cs...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].InstanceID < out[j].InstanceID })
	return out
}
