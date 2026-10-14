package reconcile

import (
	"context"
	"fmt"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// reattacher is the optional driver capability Reattach uses: a driver whose
// host can be replaced while it keeps its instance list. Reattach recreates
// every instance the driver currently runs on the host it now points at; the
// previous host is gone (for example an in-process core that was rebuilt) and
// must not be touched.
//
// It is declared here, like KernelEnsurer, so this package does not import the
// driver packages that implement it. The in-process xray engine (driver/xray,
// deleted in v11 D5) was the only implementer; no built-in driver has a
// replaceable host any more, so Reattach reports an error for every engine.
type reattacher interface {
	Reattach(ctx context.Context, rt driver.Runtime) error
}

// DetachHost runs swap under the reconciler's lock. The panel calls it before
// it closes the core behind a driver's host: once it returns no Apply is in
// flight, and the driver's later calls reach the detached host (and fail
// cleanly) instead of a closed core. The driver's instance list is kept, so a
// later Reattach can bring it back on a new host.
func (r *Reconciler) DetachHost(swap func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if swap != nil {
		swap()
	}
}

// Reattach recreates every instance of one engine on its (replaced) host. swap,
// when non-nil, installs the new host and runs under the reconciler's lock, so
// it can never interleave with an Apply. The other engines are not touched:
// their instances, processes and connections keep running.
//
// The returned report is the last applied report with the state of the engine's
// instances refreshed; the error is nil only when they were recreated and are
// healthy again.
func (r *Reconciler) Reattach(ctx context.Context, engine string, swap func()) (Report, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.applying.Store(true)
	defer r.applying.Store(false)

	if err := r.init(); err != nil {
		return Report{Status: StatusFailed, Message: err.Error(), At: r.now()}, err
	}
	if swap != nil {
		swap()
	}
	cur := r.currentApplied()
	if cur == nil {
		return Report{Status: StatusApplied, Message: "nothing has been applied", At: r.now()}, nil
	}
	rep := cur.report.clone()
	rep.At = r.now()
	set := cur.sets[engine]
	if len(set) == 0 {
		rep.Message = fmt.Sprintf("no %s instance to reattach", engine)
		return rep, nil
	}
	drv := r.Drivers[engine]
	ra, ok := drv.(reattacher)
	if drv == nil || !ok {
		err := fmt.Errorf("reconcile: engine %q cannot reattach its host", engine)
		rep.Status, rep.Message = StatusFailed, err.Error()
		return rep, r.errorf(ErrFailed, "%s", err)
	}
	rt, ok := cur.rts[engine]
	if !ok {
		rt = driver.Runtime{}
	}
	if err := protect("reattach", func() error { return ra.Reattach(ctx, rt) }); err != nil {
		rep.Status = StatusFailed
		rep.Message = fmt.Sprintf("reattach of engine %q failed: %v", engine, err)
		markInstances(&rep, set, StateFailed, err.Error())
		return rep, r.errorf(ErrFailed, "%s", rep.Message)
	}
	// Health-check only the reattached engine: the other engines were not
	// touched, so their health must not turn a reattach into a false failure.
	view := &applied{
		sets: map[string][]driver.Rendered{engine: set},
		rts:  map[string]driver.Runtime{engine: rt},
	}
	for _, rd := range set {
		view.claims = append(view.claims, rd.Artifact.PortClaims...)
	}
	if diffs := r.checkPlan(ctx, view); len(diffs) > 0 {
		rep.Status = StatusFailed
		rep.Message = fmt.Sprintf("reattach of engine %q: %s", engine, diffs[0].describe())
		if len(diffs) > 1 {
			rep.Message += fmt.Sprintf(" (and %d more)", len(diffs)-1)
		}
		bad := map[string]string{}
		for _, df := range diffs {
			if _, seen := bad[df.Instance]; !seen {
				bad[df.Instance] = df.describe()
			}
		}
		for _, rd := range set {
			if msg, isBad := bad[rd.Instance.ID]; isBad {
				markInstances(&rep, []driver.Rendered{rd}, StateFailed, msg)
			}
		}
		return rep, r.errorf(ErrFailed, "%s", rep.Message)
	}
	rep.Status = StatusApplied
	rep.Message = fmt.Sprintf("reattached %d %s instance(s)", len(set), engine)
	markInstances(&rep, set, StateRunning, "")
	for _, rd := range set {
		for i := range rep.Instances {
			if rep.Instances[i].ID == rd.Instance.ID {
				rep.Instances[i].Engine = engine
				rep.Instances[i].ConfigHash = rd.Artifact.Hash
			}
		}
	}
	return rep, nil
}

// markInstances sets the state and error of the given rendered instances in the
// report. Ids the report does not know are ignored.
func markInstances(rep *Report, set []driver.Rendered, state, errMsg string) {
	ids := make(map[string]bool, len(set))
	for _, rd := range set {
		ids[rd.Instance.ID] = true
	}
	for i := range rep.Instances {
		if ids[rep.Instances[i].ID] {
			rep.Instances[i].State, rep.Instances[i].Error = state, errMsg
		}
	}
}
