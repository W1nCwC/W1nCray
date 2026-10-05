package gost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// desiredInst is one instance as Apply receives it, with its parsed fragment.
type desiredInst struct {
	id   string
	hash string
	frag fragment
}

// Apply implements driver.Driver.
//
// It makes gost run exactly the given instances. Per instance the hash is
// compared with the committed one; unchanged instances are not touched,
// changed or new ones are applied service by service through gost's API (so
// other instances keep their connections) and verified, and an instance that
// fails is restored to its previous definition while the others proceed.
// When the process is not running (first start, crash that the supervisor has
// not healed yet, agent restart) it is started with an empty service list
// first and the instances are added one by one, so a service that cannot bind
// fails alone instead of taking the whole process down at startup.
func (d *Driver) Apply(ctx context.Context, rt driver.Runtime, set []driver.Rendered) (driver.ApplyResult, error) {
	d.rt.mu.Lock()
	defer d.rt.mu.Unlock()
	desired, err := d.desiredFromRendered(set)
	if err != nil {
		return driver.ApplyResult{Failed: map[string]string{}}, err
	}
	return d.apply(ctx, rt, desired, true)
}

// desiredFromRendered checks that every artifact is genuine: it must be what
// Render produces for its instance, so nothing but validated input can reach
// gost even if a caller hands Apply a hand-made artifact.
func (d *Driver) desiredFromRendered(set []driver.Rendered) ([]desiredInst, error) {
	seen := map[string]bool{}
	out := make([]desiredInst, 0, len(set))
	for _, r := range set {
		id := r.Instance.ID
		if seen[id] {
			return nil, fmt.Errorf("gost: duplicate instance id %q in set", id)
		}
		seen[id] = true
		want, err := d.Render(r.Instance)
		if err != nil {
			return nil, fmt.Errorf("gost: instance %q: %w", id, err)
		}
		if want.Hash != r.Artifact.Hash || hashFiles(r.Artifact.Files) != want.Hash {
			return nil, fmt.Errorf("gost: instance %q: artifact does not match the instance (re-render it)", id)
		}
		var f fragment
		if err := json.Unmarshal(r.Artifact.Files[fragmentFile], &f); err != nil {
			return nil, fmt.Errorf("gost: instance %q: bad fragment: %w", id, err)
		}
		out = append(out, desiredInst{id: id, hash: want.Hash, frag: f})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out, nil
}

// apply is Apply without the locking and artifact checks; the caller holds
// d.rt.mu. commitPrevious controls whether the replaced state becomes the
// Rollback target.
func (d *Driver) apply(ctx context.Context, rt driver.Runtime, desired []desiredInst, commitPrevious bool) (driver.ApplyResult, error) {
	res := driver.ApplyResult{Failed: map[string]string{}}
	if err := checkRuntime(rt); err != nil {
		return res, err
	}
	old, err := loadApplied(rt.StateDir, appliedFile)
	if err != nil {
		return res, err
	}
	secrets := stateSecrets(old, desired)

	if len(desired) == 0 {
		if err := d.stopProcess(ctx, rt); err != nil {
			return res, redactErr(err, secrets)
		}
		if err := d.commit(rt, &appliedState{Instances: map[string]appliedInstance{}}, old, commitPrevious); err != nil {
			return res, err
		}
		return res, nil
	}

	api, cold, wasRunning, err := d.ensureProcess(ctx, rt)
	if err != nil {
		return res, redactErr(err, secrets)
	}
	base := old
	if cold {
		// A fresh process knows none of the previously applied instances.
		base = &appliedState{Instances: map[string]appliedInstance{}}
		if wasRunning {
			res.Disrupted = old.ids() // the old process was killed
		}
	}

	next := base.clone()
	desiredIDs := map[string]bool{}
	for _, di := range desired {
		desiredIDs[di.id] = true
	}

	// Removals first: they free ports the new definitions may want.
	for _, id := range base.ids() {
		if desiredIDs[id] {
			continue
		}
		of := base.Instances[id].Fragment
		if err := d.changeFragment(ctx, rt, api, id, &of, nil); err != nil {
			res.Failed[id] = redactStr(err.Error(), secrets)
			continue
		}
		delete(next.Instances, id)
		d.dropInstanceStats(id)
	}

	for _, di := range desired {
		prev, had := base.Instances[di.id]
		if had && prev.Hash == di.hash {
			res.Running = append(res.Running, di.id)
			continue
		}
		var oldFrag *fragment
		if had {
			oldFrag = &prev.Fragment
		}
		f := di.frag
		if err := d.changeFragment(ctx, rt, api, di.id, oldFrag, &f); err != nil {
			res.Failed[di.id] = redactStr(err.Error(), secrets)
			logf(rt, "gost: instance %s failed: %s", di.id, redactStr(err.Error(), secrets))
			continue
		}
		next.Instances[di.id] = appliedInstance{Hash: di.hash, Fragment: di.frag}
		res.Running = append(res.Running, di.id)
		if had || cold {
			res.Restarted = append(res.Restarted, di.id)
		}
	}

	if err := d.commit(rt, next, old, commitPrevious); err != nil {
		return res, err
	}
	if len(next.Instances) == 0 {
		// Nothing runs: do not keep an idle gost around.
		if err := d.stopProcess(ctx, rt); err != nil {
			return res, redactErr(err, secrets)
		}
	}
	sort.Strings(res.Running)
	sort.Strings(res.Restarted)
	sort.Strings(res.Disrupted)
	if len(res.Failed) > 0 {
		ids := make([]string, 0, len(res.Failed))
		for id := range res.Failed {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		var parts []string
		for _, id := range ids {
			parts = append(parts, id+": "+res.Failed[id])
		}
		return res, fmt.Errorf("gost: %d instance(s) failed: %s", len(ids), strings.Join(parts, "; "))
	}
	return res, nil
}

// commit makes next the applied state: current.json (what a restarted gost
// loads) first, then applied.json, and the old state becomes previous.
func (d *Driver) commit(rt driver.Runtime, next, old *appliedState, commitPrevious bool) error {
	dir := rt.StateDir
	if err := writeJSON(filepath.Join(dir, currentFile), currentFromApplied(next)); err != nil {
		return fmt.Errorf("gost: write %s: %w", currentFile, err)
	}
	if commitPrevious && !sameApplied(next, old) {
		if err := writeJSON(filepath.Join(dir, previousFile), old); err != nil {
			return fmt.Errorf("gost: write %s: %w", previousFile, err)
		}
	}
	if !commitPrevious {
		_ = os.Remove(filepath.Join(dir, previousFile))
	}
	if err := writeJSON(filepath.Join(dir, appliedFile), next); err != nil {
		return fmt.Errorf("gost: write %s: %w", appliedFile, err)
	}
	return nil
}

func sameApplied(a, b *appliedState) bool {
	if len(a.Instances) != len(b.Instances) {
		return false
	}
	for id, v := range a.Instances {
		if w, ok := b.Instances[id]; !ok || w.Hash != v.Hash {
			return false
		}
	}
	return true
}

// Rollback implements driver.Driver: it re-applies the state that was in
// effect before the last committed Apply. It can be used once per Apply.
func (d *Driver) Rollback(ctx context.Context, rt driver.Runtime) error {
	d.rt.mu.Lock()
	defer d.rt.mu.Unlock()
	if err := checkRuntime(rt); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(rt.StateDir, previousFile)); err != nil {
		return errors.New("gost: no previous configuration to roll back to")
	}
	prev, err := loadApplied(rt.StateDir, previousFile)
	if err != nil {
		return err
	}
	var desired []desiredInst
	for _, id := range prev.ids() {
		desired = append(desired, desiredInst{id: id, hash: prev.Instances[id].Hash, frag: prev.Instances[id].Fragment})
	}
	res, err := d.apply(ctx, rt, desired, false)
	if err != nil {
		return err
	}
	if len(res.Failed) > 0 {
		return fmt.Errorf("gost: rollback incomplete: %d instance(s) failed", len(res.Failed))
	}
	return nil
}

// Stop implements driver.Driver. With no ids it stops the process (cutting
// every connection); otherwise it removes the given instances from gost.
// Removing an instance closes its listeners but cannot cut connections that
// were already accepted (gost API behaviour, see the package comment).
func (d *Driver) Stop(ctx context.Context, rt driver.Runtime, ids ...string) error {
	d.rt.mu.Lock()
	defer d.rt.mu.Unlock()
	if err := checkRuntime(rt); err != nil {
		return err
	}
	old, err := loadApplied(rt.StateDir, appliedFile)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		if err := d.stopProcess(ctx, rt); err != nil {
			return err
		}
		d.rt.acc = map[string]*svcAcc{}
		d.rt.retired = map[string]rawStats{}
		return d.commit(rt, &appliedState{Instances: map[string]appliedInstance{}}, old, true)
	}
	drop := map[string]bool{}
	for _, id := range ids {
		drop[id] = true
	}
	var desired []desiredInst
	for _, id := range old.ids() {
		if !drop[id] {
			desired = append(desired, desiredInst{id: id, hash: old.Instances[id].Hash, frag: old.Instances[id].Fragment})
		}
	}
	res, err := d.apply(ctx, rt, desired, true)
	if err != nil {
		return err
	}
	if len(res.Failed) > 0 {
		return fmt.Errorf("gost: stop incomplete: %d instance(s) failed", len(res.Failed))
	}
	return nil
}

func checkRuntime(rt driver.Runtime) error {
	if rt.Sup == nil {
		return errors.New("gost: runtime has no supervisor")
	}
	if rt.Kernel.Path == "" || !filepath.IsAbs(rt.Kernel.Path) {
		return errors.New("gost: runtime kernel path must be absolute")
	}
	if rt.StateDir == "" || !filepath.IsAbs(rt.StateDir) {
		return errors.New("gost: runtime state dir must be absolute")
	}
	return nil
}

func logf(rt driver.Runtime, format string, args ...any) {
	if rt.Log != nil {
		rt.Log.Warnf(format, args...)
	}
}

// ---- process lifecycle ----

func (d *Driver) procSpec(rt driver.Runtime) driver.ProcSpec {
	return driver.ProcSpec{
		ID:   procID,
		Path: rt.Kernel.Path,
		// gost merges the two files left to right: static settings, then the
		// services. A path containing " -- " would make gost split its own
		// command line (it re-executes itself per segment), so such state
		// directories are rejected in ensureProcess.
		Args:        []string{"-C", filepath.Join(rt.StateDir, baseFile), "-C", filepath.Join(rt.StateDir, currentFile)},
		WorkDir:     rt.StateDir,
		LogFile:     filepath.Join(rt.StateDir, logFile),
		Restart:     driver.RestartPolicy{Always: true, MinBackoff: time.Second, MaxBackoff: 30 * time.Second, ResetAfter: 2 * time.Minute},
		StopTimeout: 5 * time.Second,
	}
}

func (d *Driver) stopProcess(ctx context.Context, rt driver.Runtime) error {
	if rt.Sup.Status(procID).Running {
		if err := rt.Sup.Stop(ctx, procID); err != nil {
			return fmt.Errorf("gost: stop process: %w", err)
		}
	}
	return nil
}

// ensureProcess returns an API client for a running gost, starting the
// process when needed. cold reports that the process was (re)started and runs
// no services; wasRunning that a running process had to be replaced.
func (d *Driver) ensureProcess(ctx context.Context, rt driver.Runtime) (api *apiClient, cold, wasRunning bool, err error) {
	if strings.Contains(" "+strings.Join(d.procSpec(rt).Args, "  ")+" ", " -- ") {
		return nil, false, false, errors.New("gost: state directory path must not contain \" -- \" (gost would split its command line)")
	}
	st := rt.Sup.Status(procID)
	if st.Running {
		if ep, e := loadEndpoint(rt.StateDir); e == nil {
			api = newAPIClient(ep, d.opts.APITimeout)
			if d.waitAPI(ctx, rt, api, 3*time.Second) == nil {
				return api, false, true, nil
			}
		}
		wasRunning = true
	}
	api, err = d.startProcess(ctx, rt)
	if err != nil {
		return nil, false, wasRunning, err
	}
	// A new process has new service objects: all counters restart.
	d.rt.acc = map[string]*svcAcc{}
	return api, true, wasRunning, nil
}

func (d *Driver) startProcess(ctx context.Context, rt driver.Runtime) (*apiClient, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		ep, err := newEndpoint(d.opts.EnableMetrics)
		if err != nil {
			return nil, fmt.Errorf("gost: allocate api address: %w", err)
		}
		bc := baseConfig{
			API:      apiConf{Addr: ep.Addr, Auth: auth{Username: ep.User, Password: ep.Pass}},
			Log:      logConf{Level: d.opts.LogLevel, Format: "text"},
			Services: []service{},
		}
		if d.opts.EnableMetrics {
			bc.Metrics = &metricConf{Addr: ep.MetricsAddr, Path: "/metrics", Auth: auth{Username: ep.User, Password: ep.Pass}}
		}
		if err := os.MkdirAll(rt.StateDir, 0o700); err != nil {
			return nil, err
		}
		if err := writeJSON(filepath.Join(rt.StateDir, baseFile), bc); err != nil {
			return nil, err
		}
		if err := writeJSON(filepath.Join(rt.StateDir, endpointFile), ep); err != nil {
			return nil, err
		}
		// Start empty; instances are added through the API.
		if err := writeJSON(filepath.Join(rt.StateDir, currentFile), currentConfig{Services: []service{}}); err != nil {
			return nil, err
		}
		_ = rt.Sup.Stop(ctx, procID)
		if err := rt.Sup.Start(ctx, d.procSpec(rt)); err != nil {
			return nil, fmt.Errorf("gost: start process: %w", err)
		}
		api := newAPIClient(ep, d.opts.APITimeout)
		if lastErr = d.waitAPI(ctx, rt, api, d.opts.ReadyTimeout); lastErr == nil {
			return api, nil
		}
		tail := tailFile(filepath.Join(rt.StateDir, logFile), 2048)
		_ = rt.Sup.Stop(ctx, procID)
		if tail != "" {
			lastErr = fmt.Errorf("%w; gost output: %s", lastErr, tail)
		}
	}
	return nil, fmt.Errorf("gost: process did not become ready: %w", lastErr)
}

func (d *Driver) waitAPI(ctx context.Context, rt driver.Runtime, api *apiClient, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var err error
	for {
		if err = api.ping(ctx); err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("api not ready: %w", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// ---- change engine ----

// obj is one gost API object with its canonical JSON.
type obj struct {
	kind string
	name string
	body []byte
}

type objSet struct {
	deps []obj // admissions, limiters, climiters, chains in creation order
	svcs []obj
	refs map[string][]string // service name -> names of the deps it references
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic("gost: marshal: " + err.Error())
	}
	return b
}

func (f *fragment) objects() objSet {
	var s objSet
	s.refs = map[string][]string{}
	if f == nil {
		return s
	}
	for _, a := range f.Admissions {
		s.deps = append(s.deps, obj{kindAdmission, a.Name, mustJSON(a)})
	}
	for _, l := range f.Limiters {
		s.deps = append(s.deps, obj{kindLimiter, l.Name, mustJSON(l)})
	}
	for _, l := range f.CLimiters {
		s.deps = append(s.deps, obj{kindCLimiter, l.Name, mustJSON(l)})
	}
	for _, c := range f.Chains {
		s.deps = append(s.deps, obj{kindChain, c.Name, mustJSON(c)})
	}
	for _, sv := range f.Services {
		s.svcs = append(s.svcs, obj{kindService, sv.Name, mustJSON(sv)})
		var refs []string
		refs = append(refs, sv.Admissions...)
		for _, r := range []string{sv.Limiter, sv.CLimiter, sv.Handler.Chain, sv.Listener.Chain} {
			if r != "" {
				refs = append(refs, r)
			}
		}
		s.refs[sv.Name] = refs
	}
	return s
}

func byName(list []obj) map[string]obj {
	m := make(map[string]obj, len(list))
	for _, o := range list {
		m[o.kind+"/"+o.name] = o
	}
	return m
}

// txn records undo actions while a fragment is changed.
type txn struct {
	d    *Driver
	ctx  context.Context
	api  *apiClient
	undo []func(context.Context) error
}

func (t *txn) push(f func(context.Context) error) { t.undo = append(t.undo, f) }

// rollback runs the undo actions in reverse order with a fresh context, so a
// cancelled caller context cannot leave a half applied instance behind.
func (t *txn) rollback() error {
	ctx, cancel := context.WithTimeout(context.Background(), 4*t.d.opts.ReadyTimeout)
	defer cancel()
	var errs []error
	for i := len(t.undo) - 1; i >= 0; i-- {
		if err := t.undo[i](ctx); err != nil {
			errs = append(errs, err)
		}
	}
	t.undo = nil
	return errors.Join(errs...)
}

func isBindErr(err error) bool {
	var ae *apiError
	if !errors.As(err, &ae) {
		return false
	}
	m := strings.ToLower(ae.Msg)
	return strings.Contains(m, "address already in use") ||
		strings.Contains(m, "only one usage of each socket address") ||
		strings.Contains(m, "bind:")
}

// retryBind retries f while the failure is a port that has not been released
// yet (UDP based listeners free their socket slightly after Close).
func retryBind(ctx context.Context, f func(context.Context) error) error {
	var err error
	for i := 0; i < 10; i++ {
		if err = f(ctx); err == nil || !isBindErr(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(i+1) * 150 * time.Millisecond):
		}
	}
	return err
}

func (t *txn) create(o obj) error {
	do := func(ctx context.Context) error { return t.api.create(ctx, o.kind, o.body) }
	if o.kind == kindService {
		do = func(ctx context.Context) error {
			return retryBind(ctx, func(ctx context.Context) error { return t.api.create(ctx, o.kind, o.body) })
		}
	}
	if err := do(t.ctx); err != nil {
		return fmt.Errorf("create %s %s: %w", singular(o.kind), o.name, err)
	}
	t.push(func(ctx context.Context) error {
		if err := t.api.remove(ctx, o.kind, o.name); err != nil {
			return fmt.Errorf("undo create %s %s: %w", singular(o.kind), o.name, err)
		}
		return nil
	})
	return nil
}

func (t *txn) replace(oldO, newO obj) error {
	put := func(ctx context.Context, o obj) error {
		if o.kind == kindService {
			return retryBind(ctx, func(ctx context.Context) error { return t.api.update(ctx, o.kind, o.name, o.body) })
		}
		return t.api.update(ctx, o.kind, o.name, o.body)
	}
	if err := put(t.ctx, newO); err != nil {
		// A failed PUT of a service has already closed the old one inside
		// gost; put the old definition back before reporting.
		if newO.kind == kindService {
			rctx, cancel := context.WithTimeout(context.Background(), t.d.opts.ReadyTimeout)
			defer cancel()
			if rerr := put(rctx, oldO); rerr != nil {
				return fmt.Errorf("replace %s %s: %w (restoring the old definition also failed: %v)", singular(newO.kind), newO.name, err, rerr)
			}
		}
		return fmt.Errorf("replace %s %s: %w", singular(newO.kind), newO.name, err)
	}
	t.push(func(ctx context.Context) error {
		if err := put(ctx, oldO); err != nil {
			return fmt.Errorf("undo replace %s %s: %w", singular(oldO.kind), oldO.name, err)
		}
		return nil
	})
	return nil
}

func (t *txn) remove(o obj) error {
	if err := t.api.remove(t.ctx, o.kind, o.name); err != nil {
		return fmt.Errorf("remove %s %s: %w", singular(o.kind), o.name, err)
	}
	t.push(func(ctx context.Context) error {
		do := func(ctx context.Context) error { return t.api.create(ctx, o.kind, o.body) }
		if o.kind == kindService {
			if err := retryBind(ctx, do); err != nil {
				return fmt.Errorf("undo remove %s %s: %w", singular(o.kind), o.name, err)
			}
			return nil
		}
		if err := do(ctx); err != nil {
			return fmt.Errorf("undo remove %s %s: %w", singular(o.kind), o.name, err)
		}
		return nil
	})
	return nil
}

func singular(kind string) string { return strings.TrimSuffix(kind, "s") }

// changeFragment moves instance id from old to nw (either may be nil). On any
// failure everything done for the instance is undone and the error returned.
func (d *Driver) changeFragment(ctx context.Context, rt driver.Runtime, api *apiClient, id string, old, nw *fragment) error {
	oldS, newS := old.objects(), nw.objects()
	oldDeps, newDeps := byName(oldS.deps), byName(newS.deps)
	oldSvcs := byName(oldS.svcs)

	// Fold the counters of the services that are about to be replaced.
	if snap, err := api.services(ctx); err == nil {
		d.observeAll(snap)
	}

	t := &txn{d: d, ctx: ctx, api: api}
	fail := func(err error) error {
		if rerr := t.rollback(); rerr != nil {
			err = fmt.Errorf("%w (rollback incomplete: %v)", err, rerr)
		}
		return err
	}

	// 1. Dependencies: create new ones, replace changed ones.
	changedDeps := map[string]bool{}
	for _, o := range newS.deps {
		key := o.kind + "/" + o.name
		prev, existed := oldDeps[key]
		switch {
		case !existed:
			if err := t.create(o); err != nil {
				return fail(err)
			}
			changedDeps[o.name] = true
		case !bytes.Equal(prev.body, o.body):
			if err := t.replace(prev, o); err != nil {
				return fail(err)
			}
			changedDeps[o.name] = true
		}
	}

	// 2. Services: create, or replace when they or something they reference
	// changed. A replaced service gets a new gost object, so its counters
	// are retired first.
	var touched []string
	for _, o := range newS.svcs {
		key := o.kind + "/" + o.name
		prev, existed := oldSvcs[key]
		if !existed {
			if err := t.create(o); err != nil {
				return fail(err)
			}
			touched = append(touched, o.name)
			continue
		}
		stale := !bytes.Equal(prev.body, o.body)
		for _, r := range newS.refs[o.name] {
			if changedDeps[r] {
				stale = true
			}
		}
		if !stale {
			continue
		}
		d.retireService(o.name)
		if err := t.replace(prev, o); err != nil {
			return fail(err)
		}
		touched = append(touched, o.name)
	}

	// 3. Services that are gone.
	newSvcs := byName(newS.svcs)
	for _, o := range oldS.svcs {
		if _, ok := newSvcs[o.kind+"/"+o.name]; ok {
			continue
		}
		d.retireService(o.name)
		d.dropServiceStats(id, o.name)
		if err := t.remove(o); err != nil {
			return fail(err)
		}
	}

	// 4. Dependencies that are gone (after the services that used them).
	for _, o := range oldS.deps {
		if _, ok := newDeps[o.kind+"/"+o.name]; ok {
			continue
		}
		if err := t.remove(o); err != nil {
			return fail(err)
		}
	}

	// 5. Verify that every touched service is serving.
	if err := d.waitServices(ctx, api, touched); err != nil {
		return fail(err)
	}
	return nil
}

// waitServices waits until the named services report state "ready".
func (d *Driver) waitServices(ctx context.Context, api *apiClient, names []string) error {
	if len(names) == 0 {
		return nil
	}
	deadline := time.Now().Add(d.opts.ReadyTimeout)
	var bad string
	for {
		snap, err := api.services(ctx)
		if err != nil {
			return fmt.Errorf("verify services: %w", err)
		}
		bad = ""
		for _, n := range names {
			s, ok := snap[n]
			switch {
			case !ok || s.Status == nil:
				bad = fmt.Sprintf("service %s is not registered", n)
			case s.Status.State == "ready":
			case s.Status.State == "failed" || s.Status.State == "closed":
				return fmt.Errorf("service %s is %s: %s", n, s.Status.State, s.lastEvent())
			default:
				bad = fmt.Sprintf("service %s is %s", n, s.Status.State)
			}
			if bad != "" {
				break
			}
		}
		if bad == "" {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for services: %s", bad)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// ---- secrets ----

func fragSecrets(f fragment) []string {
	var out []string
	for _, s := range f.Services {
		if s.Handler.Auth != nil && s.Handler.Auth.Password != "" {
			out = append(out, s.Handler.Auth.Password)
		}
	}
	for _, c := range f.Chains {
		for _, h := range c.Hops {
			for _, n := range h.Nodes {
				if n.Connector.Auth != nil && n.Connector.Auth.Password != "" {
					out = append(out, n.Connector.Auth.Password)
				}
			}
		}
	}
	return out
}

func stateSecrets(old *appliedState, desired []desiredInst) []string {
	var out []string
	for _, v := range old.Instances {
		out = append(out, fragSecrets(v.Fragment)...)
	}
	for _, di := range desired {
		out = append(out, fragSecrets(di.frag)...)
	}
	return out
}

func redactStr(s string, secrets []string) string {
	for _, sec := range secrets {
		if sec != "" {
			s = strings.ReplaceAll(s, sec, "[redacted]")
		}
	}
	return s
}

func redactErr(err error, secrets []string) error {
	if err == nil {
		return nil
	}
	return errors.New(redactStr(err.Error(), secrets))
}
