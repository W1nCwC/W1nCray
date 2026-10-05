package realm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/spec"
)

// On-disk layout below Runtime.StateDir (0700 directories, 0600 files):
//
//	state.json            what Apply last applied / last verified good, per instance
//	run/<id>/realm.json   the configuration the instance's process reads (-c)
//	good/<id>/realm.json  copy of the last configuration that passed the
//	                      readiness check (what Rollback restores)
//	logs/<id>.log         stdout+stderr of the process (rotated by the supervisor)
//
// Instance ids are validated against idRe before they are used in a path.

const stateVersion = 1

type instState struct {
	Hash    string      `json:"hash"`
	FileSHA string      `json:"file_sha256"`
	Claims  []claimJSON `json:"claims"`
}

type claimJSON struct {
	Proto string `json:"proto"`
	Addr  string `json:"addr"`
	Port  int    `json:"port"`
}

type stateFile struct {
	Version int                  `json:"version"`
	Applied map[string]instState `json:"applied"`
	Good    map[string]instState `json:"good"`
}

func (s instState) portClaims(owner string) []driver.PortClaim {
	out := make([]driver.PortClaim, len(s.Claims))
	for i, c := range s.Claims {
		out[i] = driver.PortClaim{Proto: c.Proto, Addr: c.Addr, Port: c.Port, Owner: owner}
	}
	return out
}

func toClaimJSON(cs []driver.PortClaim) []claimJSON {
	out := make([]claimJSON, len(cs))
	for i, c := range cs {
		out[i] = claimJSON{c.Proto, c.Addr, c.Port}
	}
	return out
}

func statePath(rt driver.Runtime) string { return filepath.Join(rt.StateDir, "state.json") }
func runDir(rt driver.Runtime, id string) string {
	return filepath.Join(rt.StateDir, "run", id)
}
func goodDir(rt driver.Runtime, id string) string {
	return filepath.Join(rt.StateDir, "good", id)
}
func logPath(rt driver.Runtime, id string) string {
	return filepath.Join(rt.StateDir, "logs", id+".log")
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// writeFileAtomic writes data to path with mode 0600 (directories 0700) via a
// temporary file in the same directory.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".realm-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(data)
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(tmp)
		return werr
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func loadState(rt driver.Runtime) (*stateFile, error) {
	st := &stateFile{Version: stateVersion, Applied: map[string]instState{}, Good: map[string]instState{}}
	b, err := os.ReadFile(statePath(rt))
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	var in stateFile
	if err := json.Unmarshal(b, &in); err != nil {
		return nil, fmt.Errorf("realm: state file %s is corrupt: %w", statePath(rt), err)
	}
	if in.Version != stateVersion {
		return nil, fmt.Errorf("realm: state file version %d not supported", in.Version)
	}
	for id, s := range in.Applied {
		if idRe.MatchString(id) {
			st.Applied[id] = s
		}
	}
	for id, s := range in.Good {
		if idRe.MatchString(id) {
			st.Good[id] = s
		}
	}
	return st, nil
}

func (st *stateFile) save(rt driver.Runtime) error {
	st.Version = stateVersion
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(statePath(rt), append(b, '\n'))
}

func logf(rt driver.Runtime, level, format string, a ...any) {
	if rt.Log == nil {
		return
	}
	switch level {
	case "warn":
		rt.Log.Warnf(format, a...)
	case "error":
		rt.Log.Errorf(format, a...)
	default:
		rt.Log.Infof(format, a...)
	}
}

func checkRuntime(rt driver.Runtime) error {
	if rt.StateDir == "" {
		return errors.New("realm: Runtime.StateDir is empty")
	}
	if rt.Sup == nil {
		return errors.New("realm: Runtime.Sup is nil")
	}
	return nil
}

func (d *Driver) procSpec(rt driver.Runtime, id, hash string) driver.ProcSpec {
	dir := runDir(rt, id)
	return driver.ProcSpec{
		ID:   procPrefix + id,
		Path: rt.Kernel.Path,
		Args: []string{"-c", filepath.Join(dir, configName)},
		// The hash makes a changed configuration a different ProcSpec, so
		// even a supervisor that only compares specs restarts the process.
		// REALM_CONF is deliberately never set: realm lets it override -c.
		Env:     []string{"W1NCRAY_CONFIG_HASH=" + hash},
		WorkDir: dir,
		LogFile: logPath(rt, id),
		Restart: driver.RestartPolicy{
			Always:     true,
			MinBackoff: time.Second,
			MaxBackoff: 30 * time.Second,
			ResetAfter: 2 * time.Minute,
		},
		StopTimeout: 5 * time.Second,
	}
}

// want is one instance to run after validation.
type want struct {
	id     string
	in     spec.Instance
	cfg    []byte
	hash   string
	claims []driver.PortClaim
	state  instState
}

// prepare re-validates and re-renders the instance and insists that the
// artifact handed in by the core is exactly what this driver renders for it,
// so the file that gets executed is always the one Validate approved.
func (d *Driver) prepare(r driver.Rendered) (*want, error) {
	art, err := d.Render(r.Instance)
	if err != nil {
		return nil, err
	}
	if r.Artifact.Hash != art.Hash {
		return nil, errors.New("realm: artifact does not match the instance (stale or tampered); render it again")
	}
	if len(r.Artifact.Files) != 1 || !bytes.Equal(r.Artifact.Files[configName], art.Files[configName]) {
		return nil, errors.New("realm: artifact files do not match the instance")
	}
	cfg := art.Files[configName]
	return &want{
		id: r.Instance.ID, in: r.Instance, cfg: cfg, hash: art.Hash, claims: art.PortClaims,
		state: instState{Hash: art.Hash, FileSHA: sha256Hex(cfg), Claims: toClaimJSON(art.PortClaims)},
	}, nil
}

// Apply makes exactly the given set run: one supervised process per enabled
// instance. Unchanged instances are not touched; a changed one is restarted
// (and only that one); instances absent from set (or disabled) are stopped. A
// (re)started instance must accept connections on every claimed port within
// Options.ReadyTimeout, otherwise its last verified configuration is restored
// (or, for a new instance, it is stopped) and it is reported in
// ApplyResult.Failed. Apply then returns a non-nil error as well, but the
// ApplyResult is always valid.
func (d *Driver) Apply(ctx context.Context, rt driver.Runtime, set []driver.Rendered) (driver.ApplyResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	res := driver.ApplyResult{Failed: map[string]string{}}
	if err := checkRuntime(rt); err != nil {
		return res, err
	}
	st, err := loadState(rt)
	if err != nil {
		return res, err
	}

	// 1. Validate and render everything. A bad instance is that instance's
	// failure; it never stops the others.
	wants := map[string]*want{}
	seen := map[string]bool{}
	for _, r := range set {
		id := r.Instance.ID
		if !idRe.MatchString(id) {
			return res, fieldErr("id", "must match [a-z0-9_-]{1,40}, got %s", show(id))
		}
		if seen[id] {
			return res, fieldErr("id", "duplicate instance id %s", show(id))
		}
		seen[id] = true
		if !r.Instance.Enabled {
			continue
		}
		w, err := d.prepare(r)
		if err != nil {
			res.Failed[id] = err.Error()
			continue
		}
		wants[id] = w
	}

	// 2. The binary must be the full build. Nothing has been touched yet.
	if len(wants) > 0 {
		if err := d.checkKernel(ctx, rt.Kernel.Path, rt.Kernel.Version); err != nil {
			return res, err
		}
	}

	// A background context for cleanup/restoration that must complete even if
	// the caller's context is cancelled halfway.
	bg := context.WithoutCancel(ctx)

	// 3. Stop what is no longer wanted. Instances whose new configuration was
	// invalid keep running their old one.
	var removed []string
	for id := range st.Applied {
		if _, ok := wants[id]; ok {
			continue
		}
		if _, bad := res.Failed[id]; bad {
			continue
		}
		removed = append(removed, id)
	}
	sort.Strings(removed)
	for _, id := range removed {
		if err := rt.Sup.Stop(bg, procPrefix+id); err != nil {
			res.Failed[id] = "stop: " + err.Error()
			continue
		}
		res.Disrupted = append(res.Disrupted, id)
		os.RemoveAll(runDir(rt, id))
		os.RemoveAll(goodDir(rt, id))
		delete(st.Applied, id)
		delete(st.Good, id)
		logf(rt, "info", "realm: instance %s removed", id)
	}

	// 4. Write configurations and (re)start changed or missing processes.
	ids := make([]string, 0, len(wants))
	for id := range wants {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var pending []string
	for _, id := range ids {
		w := wants[id]
		cur, had := st.Applied[id]
		running := rt.Sup.Status(procPrefix + id).Running
		cfgPath := filepath.Join(runDir(rt, id), configName)
		if had && cur.Hash == w.hash && running && fileMatches(cfgPath, cur.FileSHA) {
			res.Running = append(res.Running, id)
			continue
		}
		// Preflight: a port that is already bound by someone else must not
		// be claimed. Ports the instance's own running process holds are
		// exempt. The running instance is left untouched on refusal.
		own := map[string]bool{}
		if had && running {
			for _, c := range cur.portClaims(id) {
				own[claimText(c)] = true
			}
		}
		var fresh []driver.PortClaim
		for _, c := range w.claims {
			if !own[claimText(c)] {
				fresh = append(fresh, c)
			}
		}
		if taken := d.busy(fresh); len(taken) > 0 {
			res.Failed[id] = "port(s) already in use by another process: " + strings.Join(taken, ", ")
			continue
		}
		if err := writeFileAtomic(cfgPath, w.cfg); err != nil {
			res.Failed[id] = "write config: " + err.Error()
			continue
		}
		if err := os.MkdirAll(filepath.Dir(logPath(rt, id)), 0o700); err != nil {
			res.Failed[id] = "log dir: " + err.Error()
			continue
		}
		changed := had && running && cur.Hash != w.hash
		if changed {
			// The old process is replaced (or at least may have been): its
			// connections are gone either way.
			res.Restarted = append(res.Restarted, id)
			res.Disrupted = append(res.Disrupted, id)
		}
		if err := rt.Sup.Start(ctx, d.procSpec(rt, id, w.hash)); err != nil {
			res.Failed[id] = "start: " + err.Error()
			d.restoreOrStop(bg, rt, st, id, w.hash, &res)
			continue
		}
		pending = append(pending, id)
	}

	// 5. Wait for the (re)started instances, concurrently.
	type outcome struct {
		id  string
		err error
	}
	outs := make(chan outcome, len(pending))
	var wg sync.WaitGroup
	for _, id := range pending {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			outs <- outcome{id, d.waitReady(ctx, rt, id, wants[id].claims)}
		}(id)
	}
	wg.Wait()
	close(outs)
	results := map[string]error{}
	for o := range outs {
		results[o.id] = o.err
	}
	for _, id := range pending {
		w := wants[id]
		if err := results[id]; err != nil {
			res.Failed[id] = err.Error()
			logf(rt, "warn", "realm: instance %s failed to become ready: %v", id, err)
			d.restoreOrStop(bg, rt, st, id, w.hash, &res)
			continue
		}
		if err := d.markGood(rt, st, w); err != nil {
			res.Failed[id] = "record last-good: " + err.Error()
			continue
		}
		st.Applied[id] = w.state
		res.Running = append(res.Running, id)
		logf(rt, "info", "realm: instance %s running (config %.12s)", id, w.hash)
	}
	sort.Strings(res.Running)

	if err := st.save(rt); err != nil {
		return res, err
	}
	if len(res.Failed) > 0 {
		failed := make([]string, 0, len(res.Failed))
		for id := range res.Failed {
			failed = append(failed, id)
		}
		sort.Strings(failed)
		return res, fmt.Errorf("realm: %d instance(s) failed: %s", len(failed), strings.Join(failed, ", "))
	}
	return res, nil
}

func fileMatches(path, wantSHA string) bool {
	b, err := os.ReadFile(path)
	return err == nil && sha256Hex(b) == wantSHA
}

// markGood records the instance's configuration as the last verified one.
func (d *Driver) markGood(rt driver.Runtime, st *stateFile, w *want) error {
	if err := writeFileAtomic(filepath.Join(goodDir(rt, w.id), configName), w.cfg); err != nil {
		return err
	}
	st.Good[w.id] = w.state
	return nil
}

// restoreOrStop handles an instance whose new configuration (failedHash)
// could not be started or did not become ready: restore the last verified
// configuration when it is a different one, otherwise stop the instance. It
// updates st.Applied and, for a restored instance, res.Running.
func (d *Driver) restoreOrStop(ctx context.Context, rt driver.Runtime, st *stateFile, id, failedHash string, res *driver.ApplyResult) {
	g, ok := st.Good[id]
	switch {
	case ok && g.Hash != failedHash:
		err := d.restore(ctx, rt, id, g)
		if err == nil {
			st.Applied[id] = g
			res.Running = append(res.Running, id)
			logf(rt, "warn", "realm: instance %s restored to last-good config %.12s", id, g.Hash)
			return
		}
		res.Failed[id] += "; restoring last-good failed: " + err.Error()
	case ok:
		// The last-good configuration itself no longer works (for example its
		// port was taken). Leave the supervised process retrying; Health
		// reports the state.
		st.Applied[id] = g
		return
	}
	rt.Sup.Stop(ctx, procPrefix+id)
	os.RemoveAll(runDir(rt, id))
	delete(st.Applied, id)
}

// restore puts the last-good configuration of the instance back and starts it.
func (d *Driver) restore(ctx context.Context, rt driver.Runtime, id string, g instState) error {
	b, err := os.ReadFile(filepath.Join(goodDir(rt, id), configName))
	if err != nil {
		return err
	}
	if sha256Hex(b) != g.FileSHA {
		return errors.New("last-good copy does not match its recorded checksum")
	}
	if err := writeFileAtomic(filepath.Join(runDir(rt, id), configName), b); err != nil {
		return err
	}
	if err := rt.Sup.Start(ctx, d.procSpec(rt, id, g.Hash)); err != nil {
		return err
	}
	return d.waitReady(ctx, rt, id, g.portClaims(id))
}

// Rollback restores the last good configuration written by Apply: every
// instance whose running configuration differs from its last verified one is
// switched back; instances that never became good are stopped.
func (d *Driver) Rollback(ctx context.Context, rt driver.Runtime) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := checkRuntime(rt); err != nil {
		return err
	}
	st, err := loadState(rt)
	if err != nil {
		return err
	}
	if len(st.Good) > 0 {
		if err := d.checkKernel(ctx, rt.Kernel.Path, rt.Kernel.Version); err != nil {
			return err
		}
	}
	var errs []error
	gids := make([]string, 0, len(st.Good))
	for id := range st.Good {
		gids = append(gids, id)
	}
	sort.Strings(gids)
	for _, id := range gids {
		g := st.Good[id]
		cur, had := st.Applied[id]
		if had && cur.Hash == g.Hash && rt.Sup.Status(procPrefix+id).Running {
			continue
		}
		if err := d.restore(ctx, rt, id, g); err != nil {
			errs = append(errs, fmt.Errorf("instance %s: %w", id, err))
			continue
		}
		st.Applied[id] = g
	}
	for id := range st.Applied {
		if _, ok := st.Good[id]; ok {
			continue
		}
		if err := rt.Sup.Stop(ctx, procPrefix+id); err != nil {
			errs = append(errs, fmt.Errorf("instance %s: stop: %w", id, err))
			continue
		}
		os.RemoveAll(runDir(rt, id))
		delete(st.Applied, id)
	}
	if err := st.save(rt); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Stop stops the given instances (all when ids is empty). realm has no way to
// close individual connections: stopping the process cuts them all. The last
// verified configuration is kept for Rollback.
func (d *Driver) Stop(ctx context.Context, rt driver.Runtime, ids ...string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := checkRuntime(rt); err != nil {
		return err
	}
	st, err := loadState(rt)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		for id := range st.Applied {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	var errs []error
	for _, id := range ids {
		if !idRe.MatchString(id) {
			errs = append(errs, fieldErr("id", "invalid instance id %s", show(id)))
			continue
		}
		_, known := st.Applied[id]
		if !known && !rt.Sup.Status(procPrefix+id).Running {
			continue
		}
		if err := rt.Sup.Stop(ctx, procPrefix+id); err != nil {
			errs = append(errs, fmt.Errorf("instance %s: %w", id, err))
			continue
		}
		os.RemoveAll(runDir(rt, id))
		delete(st.Applied, id)
	}
	if err := st.save(rt); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Stats: realm has no statistics interface of any kind. Returning nothing
// (and Caps.Stats "none") tells the panel to grey out metering.
func (d *Driver) Stats(ctx context.Context, rt driver.Runtime) ([]driver.Counter, error) {
	return nil, nil
}

// Health reports, per applied instance, whether the process is alive, whether
// every claimed port accepts a probe, and which configuration is running.
// realm has no health checks of its own, so Targets is never filled.
func (d *Driver) Health(ctx context.Context, rt driver.Runtime) driver.Health {
	h := driver.Health{Instances: map[string]driver.InstanceHealth{}}
	if checkRuntime(rt) != nil {
		return h
	}
	st, err := loadState(rt)
	if err != nil {
		return h
	}
	for id, a := range st.Applied {
		ps := rt.Sup.Status(procPrefix + id)
		ih := driver.InstanceHealth{Running: ps.Running, ConfigHash: a.Hash}
		var problems []string
		if !ps.Running {
			p := "process not running"
			if ps.LastExit != "" {
				p += " (last exit: " + ps.LastExit + ")"
			}
			problems = append(problems, p)
		} else if bad := d.unbound(a.portClaims(id)); len(bad) > 0 {
			problems = append(problems, "not listening: "+strings.Join(bad, ", "))
		} else {
			ih.Listening = true
		}
		if !fileMatches(filepath.Join(runDir(rt, id), configName), a.FileSHA) {
			problems = append(problems, "configuration file changed on disk or missing since apply")
		}
		ih.Err = strings.Join(problems, "; ")
		h.Instances[id] = ih
	}
	return h
}

// waitReady polls until the process runs and every claimed port is bound.
func (d *Driver) waitReady(ctx context.Context, rt driver.Runtime, id string, claims []driver.PortClaim) error {
	deadline := time.Now().Add(d.opts.ReadyTimeout)
	if !d.opts.noStartGrace {
		// Port probing binds free ports for a moment (see bindProbe); give
		// the process time to claim its own first.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(startGrace):
		}
	}
	last := "process not running"
	for {
		ps := rt.Sup.Status(procPrefix + id)
		if !ps.Running {
			last = "process not running"
			if ps.LastExit != "" {
				last += " (last exit: " + ps.LastExit + ")"
			}
		} else if free := d.unbound(claims); len(free) == 0 {
			return nil
		} else {
			last = "not listening: " + strings.Join(free, ", ")
		}
		if time.Now().After(deadline) {
			return errors.New("not ready after " + d.opts.ReadyTimeout.String() + ": " + last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func claimText(c driver.PortClaim) string {
	return c.Proto + " " + net.JoinHostPort(c.Addr, strconv.Itoa(c.Port))
}

// portInUse reports whether something is bound to the claimed address.
func (d *Driver) portInUse(c driver.PortClaim) bool {
	if d.opts.portInUse != nil {
		return d.opts.portInUse(c)
	}
	return bindProbe(c)
}

// each runs f for every claim (at most 32 at a time) and returns the texts of
// the claims for which keep is true, sorted.
func (d *Driver) each(claims []driver.PortClaim, keep func(driver.PortClaim) bool) []string {
	var (
		mu  sync.Mutex
		out []string
		wg  sync.WaitGroup
		sem = make(chan struct{}, 32)
	)
	for _, c := range claims {
		wg.Add(1)
		sem <- struct{}{}
		go func(c driver.PortClaim) {
			defer wg.Done()
			defer func() { <-sem }()
			if keep(c) {
				mu.Lock()
				out = append(out, claimText(c))
				mu.Unlock()
			}
		}(c)
	}
	wg.Wait()
	sort.Strings(out)
	return out
}

// unbound returns the claims nothing is bound to.
func (d *Driver) unbound(claims []driver.PortClaim) []string {
	return d.each(claims, func(c driver.PortClaim) bool { return !d.portInUse(c) })
}

// busy returns the claims that something is already bound to.
func (d *Driver) busy(claims []driver.PortClaim) []string {
	return d.each(claims, d.portInUse)
}

// bindProbe asks whether an address is taken by trying to bind it. It has no
// side effect on the instance's targets: connecting to a realm listener would
// make realm dial the target first (src/tcp/middle.rs connects before it
// reads anything), so a connect probe would hit every target of every port on
// every Health call. A port that is free is bound for an instant and released;
// realm may lose a bind race against that only in the microseconds between
// two probes, which is why waitReady lets the process start first.
//
// The limitation: "in use" cannot tell realm from a foreign process. Apply
// compensates by refusing to start an instance on a port that was already in
// use before it started (preflight), so a port that is in use afterwards was
// bound by the instance's own process.
func bindProbe(c driver.PortClaim) bool {
	addr := net.JoinHostPort(c.Addr, strconv.Itoa(c.Port))
	var err error
	switch c.Proto {
	case "tcp":
		var l net.Listener
		if l, err = net.Listen("tcp", addr); err == nil {
			l.Close()
			return false
		}
	case "udp":
		var pc net.PacketConn
		if pc, err = net.ListenPacket("udp", addr); err == nil {
			pc.Close()
			return false
		}
	default:
		return false
	}
	return isAddrInUse(err)
}

// isAddrInUse recognises "the address is taken". Windows reports a port held
// by an exclusive socket as WSAEACCES (10013, observed with realm 2.9.6 on
// Windows); on Unix EACCES means a privileged port and is not "in use".
func isAddrInUse(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	if errno == syscall.EADDRINUSE {
		return true
	}
	return runtime.GOOS == "windows" && (uintptr(errno) == 10048 || uintptr(errno) == 10013)
}
