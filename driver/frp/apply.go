package frp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

func procID(u *unit) string {
	if u.Role == rolePortal {
		return "frp/frps-" + u.ID
	}
	return "frp/frpc-" + u.ID
}

func instDir(rt driver.Runtime, id string) string { return filepath.Join(dirRun(rt), "i-"+id) }

// binFor returns the binary that runs the unit.
func binFor(rt driver.Runtime, u *unit) (string, error) {
	frps, frpc, err := Binaries(rt.Kernel.Path)
	if err != nil {
		return "", err
	}
	if u.Role == rolePortal {
		return frps, nil
	}
	return frpc, nil
}

func minimalEnv() []string {
	env := []string{"PATH=" + os.Getenv("PATH")}
	if runtime.GOOS == "windows" {
		env = append(env, "SYSTEMROOT="+os.Getenv("SYSTEMROOT"))
	}
	// No http_proxy & friends: frpc would route its tunnel through them.
	return env
}

// runVerify runs "<bin> verify -c cfg": frp's own schema and value check, no
// network access. The program is started with an argv array and no shell.
func runVerify(ctx context.Context, bin, cfg string) error {
	cmd := exec.CommandContext(ctx, bin, "verify", "-c", cfg)
	cmd.Env = minimalEnv()
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(out.String())
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return fmt.Errorf("frp: %s rejected the generated config: %v: %s", filepath.Base(bin), err, msg)
	}
	return nil
}

func (d *Driver) verify(ctx context.Context, bin, cfg string) error {
	if d.verifyFn != nil {
		return d.verifyFn(ctx, bin, cfg)
	}
	ctx, cancel := context.WithTimeout(ctx, d.timing.verify)
	defer cancel()
	return runVerify(ctx, bin, cfg)
}

func (d *Driver) loadCurrent(rt driver.Runtime) error {
	d.rmu.RLock()
	loaded := len(d.current) > 0
	d.rmu.RUnlock()
	if loaded {
		return nil
	}
	cur, err := loadState(rt, currentFile)
	if err != nil {
		return err
	}
	d.rmu.Lock()
	if len(d.current) == 0 {
		d.current = cur
	}
	d.rmu.Unlock()
	return nil
}

func (d *Driver) setCurrent(rt driver.Runtime, cur map[string]*unit) error {
	d.rmu.Lock()
	d.current = cur
	d.rmu.Unlock()
	return saveState(rt, currentFile, cur)
}

func (d *Driver) snapshotCurrent() map[string]*unit {
	d.rmu.RLock()
	defer d.rmu.RUnlock()
	out := make(map[string]*unit, len(d.current))
	for k, v := range d.current {
		out[k] = v
	}
	return out
}

func (d *Driver) adminFor(rt driver.Runtime, id string) (adminInfo, bool) {
	d.rmu.RLock()
	a, ok := d.admins[id]
	d.rmu.RUnlock()
	if ok {
		return a, true
	}
	// A driver created after the process was started (same agent, new
	// Driver value) finds the credentials in the 0600 state file.
	if a, ok := loadAdmin(rt, id); ok {
		d.setAdmin(id, a)
		return a, true
	}
	return adminInfo{}, false
}

func (d *Driver) setAdmin(id string, a adminInfo) {
	d.rmu.Lock()
	d.admins[id] = a
	d.rmu.Unlock()
}

func (d *Driver) dropAdmin(rt driver.Runtime, id string) {
	d.rmu.Lock()
	delete(d.admins, id)
	d.rmu.Unlock()
	removeAdmin(rt, id)
}

// Apply implements driver.Driver.
func (d *Driver) Apply(ctx context.Context, rt driver.Runtime, set []driver.Rendered) (driver.ApplyResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	res := driver.ApplyResult{Failed: map[string]string{}}
	desired := map[string]*unit{}
	for _, r := range set {
		if !r.Instance.Enabled {
			continue
		}
		u, err := compile(r.Instance)
		if err != nil {
			res.Failed[r.Instance.ID] = err.Error()
			continue
		}
		if r.Artifact.Hash != u.Hash {
			res.Failed[r.Instance.ID] = "frp: artifact does not match the instance (render again)"
			continue
		}
		if _, dup := desired[u.ID]; dup {
			res.Failed[u.ID] = "frp: duplicate instance id"
			continue
		}
		desired[u.ID] = u
	}
	err := d.applySet(ctx, rt, desired, true, &res)
	if err == nil && len(res.Failed) > 0 {
		err = fmt.Errorf("frp: %d instance(s) failed to apply", len(res.Failed))
	}
	return res, err
}

// Rollback implements driver.Driver: it restores the set that was running
// before the most recent Apply that changed anything.
func (d *Driver) Rollback(ctx context.Context, rt driver.Runtime) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := ensureDirs(rt); err != nil {
		return err
	}
	lg, err := loadState(rt, lastGoodFile)
	if err != nil {
		return err
	}
	res := driver.ApplyResult{Failed: map[string]string{}}
	if err := d.applySet(ctx, rt, lg, false, &res); err != nil {
		return err
	}
	if len(res.Failed) > 0 {
		return fmt.Errorf("frp: rollback failed for %d instance(s)", len(res.Failed))
	}
	return nil
}

// applySet makes the running processes match desired. When keepLastGood is
// true and anything changed, the previous current set is saved as last-good.
func (d *Driver) applySet(ctx context.Context, rt driver.Runtime, desired map[string]*unit, keepLastGood bool, res *driver.ApplyResult) error {
	if res.Failed == nil {
		res.Failed = map[string]string{}
	}
	if err := ensureDirs(rt); err != nil {
		return err
	}
	if rt.Sup == nil {
		return errors.New("frp: no supervisor in runtime")
	}
	if _, _, err := Binaries(rt.Kernel.Path); err != nil {
		return err
	}
	if err := d.loadCurrent(rt); err != nil {
		return err
	}
	prev := d.snapshotCurrent()
	next := map[string]*unit{}
	changed := false

	// 1. Remove what is no longer wanted.
	for _, id := range sortedKeys(prev) {
		if _, keep := desired[id]; keep {
			continue
		}
		changed = true
		d.removeUnit(ctx, rt, prev[id])
	}

	// 2. Portals first (the bridges then connect at once), then bridges.
	ids := sortedKeys(desired)
	sort.SliceStable(ids, func(i, j int) bool {
		return desired[ids[i]].Role == rolePortal && desired[ids[j]].Role != rolePortal
	})
	for _, id := range ids {
		nu := desired[id]
		old := prev[id]
		if old != nil && old.Role != nu.Role {
			// An id switching role: treat as remove + add.
			d.removeUnit(ctx, rt, old)
			old = nil
		}
		before := len(res.Restarted) + len(res.Disrupted)
		err := d.applyUnit(ctx, rt, old, nu, res)
		if err != nil {
			res.Failed[id] = err.Error()
			// applyUnit restores the previous unit when it can; report what
			// is really running.
			if old != nil && rt.Sup.Status(procID(old)).Running {
				next[id] = old
				res.Running = append(res.Running, id)
			}
			changed = true
			continue
		}
		next[id] = nu
		res.Running = append(res.Running, id)
		if old == nil || old.Hash != nu.Hash || len(res.Restarted)+len(res.Disrupted) != before {
			changed = true
		}
	}

	if keepLastGood && changed {
		if err := saveState(rt, lastGoodFile, prev); err != nil {
			return err
		}
	}
	return d.setCurrent(rt, next)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (d *Driver) removeUnit(ctx context.Context, rt driver.Runtime, u *unit) {
	d.stopProc(ctx, rt, u)
	d.dropAdmin(rt, u.ID)
	_ = os.RemoveAll(instDir(rt, u.ID))
	d.rmu.Lock()
	delete(d.stats, u.ID)
	d.rmu.Unlock()
}

func (d *Driver) stopProc(ctx context.Context, rt driver.Runtime, u *unit) {
	p := procID(u)
	if rt.Sup.Status(p).Running {
		_ = rt.Sup.Stop(ctx, p)
	}
}

func (d *Driver) applyUnit(ctx context.Context, rt driver.Runtime, old, nu *unit, res *driver.ApplyResult) error {
	proc := procID(nu)
	running := rt.Sup.Status(proc).Running
	_, haveAdmin := d.adminFor(rt, nu.ID)

	if old != nil && old.Hash == nu.Hash && running && haveAdmin {
		return nil
	}
	if nu.Role == roleBridge && old != nil && running && haveAdmin && old.CommonHash == nu.CommonHash {
		return d.reloadBridge(ctx, rt, old, nu, res)
	}

	// Full (re)start.
	err := d.startUnit(ctx, rt, nu)
	if err == nil {
		res.Restarted = append(res.Restarted, nu.ID)
		if running {
			res.Disrupted = append(res.Disrupted, nu.ID)
		}
		d.rebaseStats(nu.ID)
		return nil
	}
	// The failed start has stopped the process; bring the previous unit back.
	if old != nil {
		if rerr := d.startUnit(ctx, rt, old); rerr != nil {
			return fmt.Errorf("%w (and restoring the previous configuration failed: %v)", err, rerr)
		}
		d.rebaseStats(nu.ID)
		return fmt.Errorf("%w (previous configuration restored)", err)
	}
	return err
}

// startUnit (re)starts the process of u with a fresh config file and fresh
// admin credentials, and waits until it answers.
func (d *Driver) startUnit(ctx context.Context, rt driver.Runtime, u *unit) error {
	bin, err := binFor(rt, u)
	if err != nil {
		return err
	}
	if _, err := os.Stat(bin); err != nil {
		return fmt.Errorf("frp: binary not found: %s", filepath.Base(bin))
	}
	dir := instDir(rt, u.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	proc := procID(u)

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		a, err := newAdmin()
		if err != nil {
			return err
		}
		a.Cfg = filepath.Join(dir, "cfg-"+a.User[len("w1nc-"):]+".toml")
		text := append(append([]byte(nil), u.Files[u.mainFile()]...), adminSection(a)...)
		if err := writeFileAtomic(a.Cfg, text); err != nil {
			return err
		}
		if err := d.verify(ctx, bin, a.Cfg); err != nil {
			_ = os.Remove(a.Cfg)
			return err // not retryable: the generated config is wrong
		}
		d.stopProc(ctx, rt, u)
		d.rmu.Lock()
		delete(d.admins, u.ID)
		d.rmu.Unlock()

		spec := driver.ProcSpec{
			ID:          proc,
			Path:        bin,
			Args:        []string{"-c", a.Cfg},
			WorkDir:     dir,
			LogFile:     filepath.Join(dirLogs(rt), "i-"+u.ID+".log"),
			Restart:     driver.RestartPolicy{Always: true, MinBackoff: time.Second, MaxBackoff: 30 * time.Second, ResetAfter: 2 * time.Minute},
			StopTimeout: 5 * time.Second,
		}
		if err := rt.Sup.Start(ctx, spec); err != nil {
			lastErr = fmt.Errorf("frp: start %s: %w", filepath.Base(bin), err)
			_ = os.Remove(a.Cfg)
			continue
		}
		if err := d.waitReady(ctx, rt, u, a); err != nil {
			lastErr = err
			_ = rt.Sup.Stop(ctx, proc)
			_ = os.Remove(a.Cfg)
			continue
		}
		if err := saveAdmin(rt, u.ID, a); err != nil {
			_ = rt.Sup.Stop(ctx, proc)
			return err
		}
		d.setAdmin(u.ID, a)
		d.cleanCfgs(dir, a.Cfg)
		return nil
	}
	return lastErr
}

func (d *Driver) cleanCfgs(dir, keep string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		p := filepath.Join(dir, e.Name())
		if p != keep && strings.HasPrefix(e.Name(), "cfg-") {
			_ = os.Remove(p)
		}
	}
}

func (d *Driver) waitReady(ctx context.Context, rt driver.Runtime, u *unit, a adminInfo) error {
	proc := procID(u)
	deadline := d.now().Add(d.timing.ready)
	for {
		if a.healthy(ctx) && (u.Role != rolePortal || controlUp(u)) {
			return nil
		}
		if !d.now().Before(deadline) {
			st := rt.Sup.Status(proc)
			msg := "did not become ready in time"
			if !st.Running && st.LastExit != "" {
				msg = "exited: " + st.LastExit
			}
			return fmt.Errorf("frp: %s %s (see the log of instance %s)", filepath.Base(proc), msg, u.ID)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (d *Driver) reloadBridge(ctx context.Context, rt driver.Runtime, old, nu *unit, res *driver.ApplyResult) error {
	a, _ := d.adminFor(rt, nu.ID)
	bin, err := binFor(rt, nu)
	if err != nil {
		return err
	}
	oldBytes, err := os.ReadFile(a.Cfg)
	if err != nil {
		return fmt.Errorf("frp: read running config: %w", err)
	}
	text := append(append([]byte(nil), nu.Files[nu.mainFile()]...), adminSection(a)...)
	next := filepath.Join(filepath.Dir(a.Cfg), "next.toml")
	if err := writeFileAtomic(next, text); err != nil {
		return err
	}
	if err := d.verify(ctx, bin, next); err != nil {
		_ = os.Remove(next)
		return err
	}
	if err := os.Rename(next, a.Cfg); err != nil {
		_ = os.Remove(next)
		return err
	}
	if err := a.reload(ctx); err != nil {
		// Put the previous file back and resync frpc with it.
		_ = writeFileAtomic(a.Cfg, oldBytes)
		_ = a.reload(ctx)
		return fmt.Errorf("frp: reload refused: %w", err)
	}
	// frpc rebuilds only the proxies whose definition changed, and an
	// established connection survives even the rebuild of its own proxy (it
	// keeps talking to the old target until it ends; verified in the e2e
	// suite), so nothing is reported as disrupted.
	d.settle(ctx, a)
	return nil
}

// settle waits briefly until frpc has picked every proxy up (best effort).
func (d *Driver) settle(ctx context.Context, a adminInfo) {
	deadline := d.now().Add(d.timing.reloadSettl)
	for d.now().Before(deadline) && ctx.Err() == nil {
		st, err := a.status(ctx)
		if err == nil {
			busy := false
			for _, p := range st {
				if p.Status == "new" || p.Status == "wait start" {
					busy = true
				}
			}
			if !busy {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Stop implements driver.Driver: it stops the processes of the given
// instances (all when ids is empty). Stopping the process closes every
// established connection of that instance.
func (d *Driver) Stop(ctx context.Context, rt driver.Runtime, ids ...string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if rt.Sup == nil {
		return errors.New("frp: no supervisor in runtime")
	}
	if err := d.loadCurrent(rt); err != nil {
		return err
	}
	cur := d.snapshotCurrent()
	if len(ids) == 0 {
		ids = sortedKeys(cur)
	}
	var errs []string
	for _, id := range ids {
		u, ok := cur[id]
		if !ok {
			continue
		}
		p := procID(u)
		if rt.Sup.Status(p).Running {
			if err := rt.Sup.Stop(ctx, p); err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", id, err))
				continue
			}
		}
		d.dropAdmin(rt, id)
		d.rebaseStats(id)
	}
	if len(errs) > 0 {
		return errors.New("frp: stop: " + strings.Join(errs, "; "))
	}
	return nil
}
