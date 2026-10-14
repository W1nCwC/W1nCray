// This file is the instance-level restart the managed-file layer needs: when a
// file the panel delivered changed, the instances whose desired state
// references it have to pick the new bytes up without a full re-apply and
// without touching any other instance.
//
// It is deliberately not a second Apply: the desired state is unchanged, so
// validation, engine selection, port preflight, the firewall and the persisted
// last-good state all stay as they are. What changes is only the content of a
// file the engines read at start-up (today a tunnel certificate pair), so the
// drivers are asked to restart exactly those instances with the same restart
// semantics a spec change uses for them (driver.Driver.RestartInstances).

package reconcile

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// Restarter is implemented by a driver that can restart single instances of
// its last applied set. It is an optional capability on top of
// driver.Driver.RestartInstances, checked here so the reconciler can degrade
// with a clear reason instead of a nil call (a driver built by hand in a
// test).
type Restarter interface {
	RestartInstances(ctx context.Context, rt driver.Runtime, ids []string) ([]string, error)
}

// RestartInstances restarts the named instances of the last applied state so
// they re-read files they loaded at start-up. It is what the managed-file
// applier calls after it replaced a file an instance's spec references
// (agent/certreload decides which instances those are).
//
// The ids are data, never a new configuration: an id that is not part of the
// last applied state is ignored, nothing is validated again, no port is
// preflighted, the firewall is not re-synced and the last-good state is not
// rewritten. Each instance is restarted through its own driver, so an engine
// with one process per instance replaces only that process and an engine that
// hosts several instances in one process recreates only the named services
// (see driver.Driver.RestartInstances).
//
// It returns the ids that were really restarted and an error that lists every
// instance whose restart failed. A failure never undoes the file change: the
// new file is already in place and validated, so restoring the bytes would
// only re-install the certificate the panel just renewed. The panel sees the
// failure in the files_apply result and in the log (existing channels).
func (r *Reconciler) RestartInstances(ctx context.Context, ids []string) ([]string, error) {
	if r == nil || len(ids) == 0 {
		return nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.init(); err != nil {
		return nil, err
	}
	cur := r.currentApplied()
	if cur == nil {
		return nil, nil
	}

	// Only instances that really run are candidates: a disabled or removed
	// instance has no process to restart, and the next apply brings it up
	// with the new file anyway.
	engineOf := map[string]string{}
	for name, set := range cur.sets {
		for _, rd := range set {
			engineOf[rd.Instance.ID] = name
		}
	}
	want := map[string]bool{}
	for _, id := range ids {
		if _, ok := engineOf[id]; ok {
			want[id] = true
		}
	}
	if len(want) == 0 {
		return nil, nil
	}

	// Group the requests per engine: one RestartInstances call per driver.
	perEngine := map[string][]string{}
	for id := range want {
		name := engineOf[id]
		perEngine[name] = append(perEngine[name], id)
	}
	names := make([]string, 0, len(perEngine))
	for name := range perEngine {
		names = append(names, name)
	}
	sort.Strings(names)

	var (
		restarted []string
		errs      []error
	)
	for _, name := range names {
		drv := r.Drivers[name]
		if drv == nil {
			errs = append(errs, fmt.Errorf("engine %q is no longer registered", name))
			continue
		}
		rs, ok := drv.(Restarter)
		if !ok {
			errs = append(errs, fmt.Errorf("engine %q cannot restart a single instance", name))
			continue
		}
		rt, err := r.restartRuntime(name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		engineIDs := perEngine[name]
		sort.Strings(engineIDs)
		got, err := rs.RestartInstances(ctx, rt, engineIDs)
		if err != nil {
			errs = append(errs, err)
		}
		restarted = append(restarted, got...)
	}
	sort.Strings(restarted)
	if len(restarted) > 0 {
		r.logf("info", "restarted %d instance(s) after a managed file changed: %v", len(restarted), restarted)
	}
	return restarted, errors.Join(errs...)
}

// restartRuntime builds the driver runtime of an engine that is already
// running, without ensuring a kernel: the instances are up, so their kernel is
// the one of the last successful apply. It mirrors removalRuntime (the runtime
// of a driver whose set is not part of this apply).
func (r *Reconciler) restartRuntime(name string) (driver.Runtime, error) {
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
