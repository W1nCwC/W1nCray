// Package supervisor runs and watches the external kernel processes of the
// agent. It implements driver.Supervisor.
//
// Safety properties:
//   - processes are started from an argv array via os/exec; there is no shell;
//   - the child gets a minimal base environment plus the spec's Env;
//   - on unix every child leads its own process group, so stopping a process
//     also stops the helpers it spawned;
//   - stdout and stderr go to a size-rotated log file (mode 0600) and a logging
//     problem can never kill the child;
//   - crashed processes restart with exponential backoff that resets after a
//     stable run.
//
// Orphans (children left behind when the agent itself crashed) are handled by
// RecoverOrphans: with a PID directory configured every child is recorded in
// <PIDDir>/<id>.pid. At start-up the agent calls RecoverOrphans, which
// terminates a recorded process when /proc/<pid>/exe proves it is the same
// binary (Linux). The old child cannot be adopted: its stdout/stderr pipe to
// the dead agent is gone, so it would die on its next log write. Where /proc is
// unavailable (Windows, macOS) the identity cannot be verified, so the stale
// record is dropped with a warning and the process is left alone rather than
// risk killing an unrelated process that reused the pid.
package supervisor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// Defaults.
const (
	DefaultMinBackoff  = time.Second
	DefaultMaxBackoff  = 30 * time.Second
	DefaultResetAfter  = 2 * time.Minute
	DefaultStopTimeout = 5 * time.Second
	DefaultLogMaxBytes = 10 << 20
	DefaultLogKeep     = 3

	// killGrace bounds how long we wait for a SIGKILLed process to be reaped.
	killGrace = 10 * time.Second
	// waitDelay bounds how long Wait blocks on output pipes that a surviving
	// grandchild still holds open after the child exited.
	waitDelay = 2 * time.Second
)

// BinLabeler makes one kernel binary executable on an SELinux machine before it
// is started. *selinux.Labeler implements it; nil disables labelling.
type BinLabeler interface {
	EnsureBinT(ctx context.Context, path string) error
}

// Options configures a Supervisor. The zero value is usable.
type Options struct {
	// Log receives supervisor events (never process arguments or environment).
	Log driver.Logger
	// PIDDir, if set, is where <id>.pid files are kept (mode 0700 directory).
	PIDDir string
	// Labeler is applied to a child's binary before it is started. It is a
	// no-op when SELinux is off and idempotent per path.
	Labeler BinLabeler
	// LogMaxBytes is the size at which a log file rotates (default 10 MiB).
	LogMaxBytes int64
	// LogKeep is how many rotated files are kept (default 3; negative keeps none).
	LogKeep int
	// BaseEnv replaces the minimal inherited environment (default: PATH, HOME,
	// TMPDIR, TZ, LANG, LC_ALL and, on Windows, SYSTEMROOT/TEMP/TMP/COMSPEC).
	BaseEnv []string
}

// Supervisor implements driver.Supervisor.
type Supervisor struct {
	opts Options
	log  driver.Logger

	startMu sync.Mutex // serialises Start and Stop
	mu      sync.Mutex // guards procs and closed
	procs   map[string]*entry
	closed  bool

	// hookSleep, if set, observes every restart delay (tests only).
	hookSleep func(id string, d time.Duration)
}

var _ driver.Supervisor = (*Supervisor)(nil)

type nopLog struct{}

func (nopLog) Debugf(string, ...any) {}
func (nopLog) Infof(string, ...any)  {}
func (nopLog) Warnf(string, ...any)  {}
func (nopLog) Errorf(string, ...any) {}

// New returns a supervisor.
func New(o Options) *Supervisor {
	if o.LogMaxBytes <= 0 {
		o.LogMaxBytes = DefaultLogMaxBytes
	}
	if o.LogKeep == 0 {
		o.LogKeep = DefaultLogKeep
	}
	if o.BaseEnv == nil {
		o.BaseEnv = defaultBaseEnv()
	}
	var l driver.Logger = nopLog{}
	if o.Log != nil {
		l = o.Log
	}
	return &Supervisor{opts: o, log: l, procs: map[string]*entry{}}
}

func defaultBaseEnv() []string {
	keys := []string{"PATH", "HOME", "TMPDIR", "TZ", "LANG", "LC_ALL", "SYSTEMROOT", "TEMP", "TMP", "COMSPEC", "PATHEXT"}
	var env []string
	for _, k := range keys {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func applyDefaults(p driver.ProcSpec) driver.ProcSpec {
	r := &p.Restart
	if r.MinBackoff <= 0 {
		r.MinBackoff = DefaultMinBackoff
	}
	if r.MaxBackoff <= 0 {
		r.MaxBackoff = DefaultMaxBackoff
	}
	if r.MaxBackoff < r.MinBackoff {
		r.MaxBackoff = r.MinBackoff
	}
	if r.ResetAfter <= 0 {
		r.ResetAfter = DefaultResetAfter
	}
	if p.StopTimeout <= 0 {
		p.StopTimeout = DefaultStopTimeout
	}
	return p
}

// specHash identifies a process spec for idempotent Start. Only a digest is
// kept, so environment values never sit in memory twice or in logs.
func specHash(p driver.ProcSpec) string {
	b, _ := json.Marshal(p)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// nextBackoff returns how long to wait before restarting after a process that
// ran for ranFor, and the backoff to use after that. cur is the current
// backoff (Min for the first crash). A run of at least ResetAfter resets the
// backoff to Min first.
func nextBackoff(cur, ranFor time.Duration, p driver.RestartPolicy) (sleep, next time.Duration) {
	if ranFor >= p.ResetAfter || cur < p.MinBackoff {
		cur = p.MinBackoff
	}
	sleep = cur
	next = cur * 2
	if next > p.MaxBackoff || next < cur {
		next = p.MaxBackoff
	}
	return sleep, next
}

// Start implements driver.Supervisor. It ensures the process is running: an
// identical spec that is already supervised and alive is left untouched, a
// different spec replaces the old process (stop, then start), and a process
// that has exited without a restart policy is started again. The first spawn
// is synchronous so a missing binary is reported to the caller; ctx only
// bounds the replacement of an old process, it does not tie the child's
// lifetime to the call.
func (s *Supervisor) Start(ctx context.Context, p driver.ProcSpec) error {
	if p.ID == "" {
		return errors.New("supervisor: empty process id")
	}
	if p.Path == "" {
		return fmt.Errorf("supervisor: %s: empty path", p.ID)
	}
	// A kernel under the agent's state directory keeps the etc_t type; on an
	// SELinux machine that would start it in init_t, where it cannot bind its
	// ports or sockets. Label it before the first spawn (agent/selinux).
	if s.opts.Labeler != nil {
		if err := s.opts.Labeler.EnsureBinT(ctx, p.Path); err != nil {
			return fmt.Errorf("supervisor: %s: %w", p.ID, err)
		}
	}
	p = applyDefaults(p)
	hash := specHash(p)

	s.startMu.Lock()
	defer s.startMu.Unlock()

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("supervisor: shut down")
	}
	old := s.procs[p.ID]
	s.mu.Unlock()
	if old != nil {
		if old.hash == hash && old.alive() {
			return nil
		}
		s.mu.Lock()
		delete(s.procs, p.ID)
		s.mu.Unlock()
		if err := old.stop(ctx); err != nil {
			return fmt.Errorf("supervisor: %s: replacing old process: %w", p.ID, err)
		}
	}

	e := &entry{s: s, spec: p, hash: hash, stopCh: make(chan struct{}), killCh: make(chan struct{}), done: make(chan struct{})}
	if p.LogFile != "" {
		lf, err := openLog(p.LogFile, s.opts.LogMaxBytes, s.opts.LogKeep)
		if err != nil {
			return fmt.Errorf("supervisor: %s: %w", p.ID, err)
		}
		e.logf = lf
	}
	first, err := e.launch()
	if err != nil {
		if e.logf != nil {
			_ = e.logf.Close()
		}
		return fmt.Errorf("supervisor: %s: %w", p.ID, err)
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		e.begin(first)
		go e.run(first)
		_ = e.stop(ctx)
		return errors.New("supervisor: shut down")
	}
	s.procs[p.ID] = e
	s.mu.Unlock()
	e.begin(first)
	go e.run(first)
	s.log.Infof("supervisor: started %s (pid %d)", p.ID, first.cmd.Process.Pid)
	return nil
}

// Stop implements driver.Supervisor: SIGTERM to the process group, SIGKILL
// after StopTimeout (Windows: kill). Unknown ids are not an error. If ctx
// expires first the process is killed immediately and ctx.Err is returned
// after it has been reaped.
func (s *Supervisor) Stop(ctx context.Context, id string) error {
	s.startMu.Lock()
	defer s.startMu.Unlock()
	s.mu.Lock()
	e := s.procs[id]
	delete(s.procs, id)
	s.mu.Unlock()
	if e == nil {
		return nil
	}
	return e.stop(ctx)
}

// Signal implements driver.Supervisor: it delivers sig to the process itself
// (not its group). It fails if the process is not running.
func (s *Supervisor) Signal(id string, sig os.Signal) error {
	s.mu.Lock()
	e := s.procs[id]
	s.mu.Unlock()
	if e == nil {
		return fmt.Errorf("supervisor: unknown process %q", id)
	}
	e.mu.Lock()
	cur := e.cur
	e.mu.Unlock()
	if cur == nil {
		return fmt.Errorf("supervisor: %s is not running", id)
	}
	return cur.cmd.Process.Signal(sig)
}

// Status implements driver.Supervisor. An unknown id yields the zero value.
func (s *Supervisor) Status(id string) driver.ProcStatus {
	s.mu.Lock()
	e := s.procs[id]
	s.mu.Unlock()
	if e == nil {
		return driver.ProcStatus{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.st
}

// IDs returns the supervised process ids (including ones that have exited
// without a restart policy), in no particular order.
func (s *Supervisor) IDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.procs))
	for id := range s.procs {
		ids = append(ids, id)
	}
	return ids
}

// Shutdown stops every process concurrently and refuses further Starts. It
// returns the first error of the individual stops (for example ctx expiry,
// after force-killing whatever was left).
func (s *Supervisor) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.closed = true
	es := make([]*entry, 0, len(s.procs))
	for _, e := range s.procs {
		es = append(es, e)
	}
	s.procs = map[string]*entry{}
	s.mu.Unlock()

	errs := make(chan error, len(es))
	for _, e := range es {
		go func(e *entry) { errs <- e.stop(ctx) }(e)
	}
	var first error
	for range es {
		if err := <-errs; err != nil && first == nil {
			first = err
		}
	}
	return first
}

// ---- one supervised process ---------------------------------------------

type running struct {
	cmd     *exec.Cmd
	waitCh  chan error
	started time.Time
}

type entry struct {
	s    *Supervisor
	spec driver.ProcSpec
	hash string
	logf *logFile

	stopCh   chan struct{}
	stopOnce sync.Once
	killCh   chan struct{}
	killOnce sync.Once
	done     chan struct{}

	mu  sync.Mutex
	st  driver.ProcStatus
	cur *running
}

func (e *entry) alive() bool {
	select {
	case <-e.done:
		return false
	default:
		return true
	}
}

// launch spawns the process once.
func (e *entry) launch() (*running, error) {
	//nolint:noshell -- the program is an installed kernel binary from the
	// signed manifest (kernelx verified its hash before it was unpacked), and
	// the arguments are an argv array from the driver, never a command string.
	cmd := exec.Command(e.spec.Path, e.spec.Args...)
	env := make([]string, 0, len(e.s.opts.BaseEnv)+len(e.spec.Env))
	env = append(env, e.s.opts.BaseEnv...)
	env = append(env, e.spec.Env...)
	cmd.Env = env
	cmd.Dir = e.spec.WorkDir
	if e.logf != nil {
		// Same writer for both streams: os/exec then uses a single copier.
		cmd.Stdout = e.logf
		cmd.Stderr = e.logf
	}
	cmd.WaitDelay = waitDelay
	setProcAttr(cmd)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	r := &running{cmd: cmd, waitCh: make(chan error, 1), started: time.Now()}
	go func() { r.waitCh <- cmd.Wait() }()
	e.writePID(r)
	return r, nil
}

// begin publishes the first running process.
func (e *entry) begin(r *running) {
	e.mu.Lock()
	e.cur = r
	e.st = driver.ProcStatus{Running: true, PID: r.cmd.Process.Pid, Since: r.started}
	e.mu.Unlock()
}

func (e *entry) setRunning(r *running) {
	e.mu.Lock()
	e.cur = r
	e.st.Running = true
	e.st.PID = r.cmd.Process.Pid
	e.st.Since = r.started
	e.st.Restarts++
	e.mu.Unlock()
}

func (e *entry) setExited(msg string) {
	e.removePID()
	e.mu.Lock()
	e.cur = nil
	e.st.Running = false
	e.st.PID = 0
	e.st.LastExit = msg
	e.mu.Unlock()
}

func describeExit(r *running, err error) string {
	switch {
	case err == nil:
		return "exit status 0"
	case errors.Is(err, exec.ErrWaitDelay):
		if ps := r.cmd.ProcessState; ps != nil {
			return ps.String() + " (output pipe still held by a child process)"
		}
	}
	return err.Error()
}

func (e *entry) run(cur *running) {
	defer close(e.done)
	defer e.finish()
	pol := e.spec.Restart
	backoff := pol.MinBackoff
	for {
		select {
		case err := <-cur.waitCh:
			// Whatever the leader left running in its group must not outlive
			// it (it may hold ports the restarted process needs).
			sweepGroup(cur.cmd.Process.Pid)
			msg := describeExit(cur, err)
			e.setExited(msg)
			e.s.log.Warnf("supervisor: %s exited: %s", e.spec.ID, msg)
			if !pol.Always {
				return
			}
			var sleep time.Duration
			sleep, backoff = nextBackoff(backoff, time.Since(cur.started), pol)
			for {
				if h := e.s.hookSleep; h != nil {
					h(e.spec.ID, sleep)
				}
				t := time.NewTimer(sleep)
				select {
				case <-t.C:
				case <-e.stopCh:
					t.Stop()
					return
				}
				next, lerr := e.launch()
				if lerr == nil {
					cur = next
					e.setRunning(next)
					e.s.log.Infof("supervisor: restarted %s (pid %d)", e.spec.ID, next.cmd.Process.Pid)
					break
				}
				e.mu.Lock()
				e.st.LastExit = "restart failed: " + lerr.Error()
				e.mu.Unlock()
				e.s.log.Errorf("supervisor: restarting %s failed: %v", e.spec.ID, lerr)
				sleep, backoff = nextBackoff(backoff, 0, pol)
			}
		case <-e.stopCh:
			e.terminate(cur)
			return
		}
	}
}

// terminate stops the running process: graceful signal, then kill.
func (e *entry) terminate(cur *running) {
	_ = termProc(cur.cmd.Process)
	t := time.NewTimer(e.spec.StopTimeout)
	defer t.Stop()
	var err error
	got := false
	select {
	case err = <-cur.waitCh:
		got = true
	case <-t.C:
	case <-e.killCh:
	}
	if !got {
		_ = killProc(cur.cmd.Process)
		select {
		case err = <-cur.waitCh:
		case <-time.After(killGrace):
			e.s.log.Errorf("supervisor: %s did not exit after SIGKILL", e.spec.ID)
			e.setExited("stopped by supervisor: process did not exit after kill")
			return
		}
	}
	// The leader is gone; make sure nothing it spawned stays behind.
	sweepGroup(cur.cmd.Process.Pid)
	e.setExited("stopped by supervisor: " + describeExit(cur, err))
}

// finish releases the log file and pid record after the loop ended.
func (e *entry) finish() {
	e.removePID()
	if e.logf != nil {
		_ = e.logf.Close()
	}
}

func (e *entry) stop(ctx context.Context) error {
	e.stopOnce.Do(func() { close(e.stopCh) })
	select {
	case <-e.done:
		return nil
	case <-ctx.Done():
		e.killOnce.Do(func() { close(e.killCh) })
		<-e.done
		return ctx.Err()
	}
}
