package reconcile

import (
	"context"
	"errors"
	"fmt"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// Stop stops every instance the reconciler currently manages: it calls Stop on
// each driver that ran instances in the last applied state (which also ends
// the supervised child processes and releases in-process listeners), releases
// the port ledger and forgets the in-memory applied state, so a following
// Resume or Apply starts from scratch.
//
// Unlike applying an empty desired state, Stop leaves everything persisted
// untouched (desired.json, last_good.json, the blocked marker): it is the
// "the agent is going down" operation, not a configuration change, and a
// later Resume brings the same instances back.
//
// Stop is idempotent and serialised with Apply and Resume. A driver that fails
// to stop does not prevent the others from being stopped; the errors are
// joined. A driver whose Stop failed stays on the list of drivers a later
// Apply will empty, because it may still be running.
func (r *Reconciler) Stop(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	cur := r.currentApplied()
	names := map[string]bool{}
	if cur != nil {
		for n := range cur.sets {
			names[n] = true
		}
	}
	for n := range r.lastDrivers {
		names[n] = true
	}

	var errs []error
	stopped := map[string]bool{}
	for _, name := range sortedKeys(names) {
		drv := r.Drivers[name]
		if drv == nil {
			// Nothing in this process can stop an engine that is not registered.
			r.logf("warn", "cannot stop engine %q: driver is not registered", name)
			continue
		}
		rt, err := r.stopRuntime(cur, name)
		if err != nil {
			errs = append(errs, fmt.Errorf("stop engine %q: %w", name, err))
			continue
		}
		if err := protect("stop", func() error { return drv.Stop(ctx, rt) }); err != nil {
			r.logf("error", "stopping engine %q failed: %v", name, err)
			errs = append(errs, fmt.Errorf("stop engine %q: %w", name, err))
			continue
		}
		stopped[name] = true
	}

	for n := range stopped {
		delete(r.lastDrivers, n)
		delete(r.lastRuntimes, n)
	}
	if r.Ports != nil {
		r.Ports.Commit(nil)
	}
	r.snapMu.Lock()
	r.cur = nil
	r.snapMu.Unlock()

	if len(stopped) > 0 || len(errs) > 0 {
		r.logf("info", "stopped %d engine(s); persisted state kept", len(stopped))
	}
	return errors.Join(errs...)
}

// stopRuntime is the Runtime a driver is stopped with: the one it was applied
// with, or (for a driver only known from the persisted last good state) the
// one a removal would use.
func (r *Reconciler) stopRuntime(cur *applied, name string) (driver.Runtime, error) {
	if cur != nil {
		if rt, ok := cur.rts[name]; ok {
			return rt, nil
		}
	}
	return r.removalRuntime(name)
}
