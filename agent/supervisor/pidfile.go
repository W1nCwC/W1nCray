package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// pidRecord is the content of <PIDDir>/<id>.pid.
type pidRecord struct {
	ID      string    `json:"id"`
	PID     int       `json:"pid"`
	Path    string    `json:"path"`
	Exe     string    `json:"exe,omitempty"` // Path with symlinks resolved at launch
	Started time.Time `json:"started"`
}

func escapeID(id string) string {
	var sb strings.Builder
	for i := 0; i < len(id); i++ {
		c := id[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' {
			sb.WriteByte(c)
		} else {
			fmt.Fprintf(&sb, "%%%02X", c)
		}
	}
	return sb.String()
}

func (s *Supervisor) pidPath(id string) string {
	return filepath.Join(s.opts.PIDDir, escapeID(id)+".pid")
}

func (e *entry) writePID(r *running) {
	dir := e.s.opts.PIDDir
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		e.s.log.Warnf("supervisor: pid dir: %v", err)
		return
	}
	rec := pidRecord{ID: e.spec.ID, PID: r.cmd.Process.Pid, Path: e.spec.Path, Started: r.started}
	if exe, err := filepath.EvalSymlinks(r.cmd.Path); err == nil {
		rec.Exe = exe
	}
	b, _ := json.Marshal(rec)
	tmp := e.s.pidPath(e.spec.ID) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		e.s.log.Warnf("supervisor: pid file for %s: %v", e.spec.ID, err)
		return
	}
	if err := os.Rename(tmp, e.s.pidPath(e.spec.ID)); err != nil {
		_ = os.Remove(tmp)
		e.s.log.Warnf("supervisor: pid file for %s: %v", e.spec.ID, err)
	}
}

func (e *entry) removePID() {
	if e.s.opts.PIDDir != "" {
		_ = os.Remove(e.s.pidPath(e.spec.ID))
	}
}

// Orphan describes what RecoverOrphans did with one pid record.
type Orphan struct {
	ID     string
	PID    int
	Action string // terminated | stale | reused | unverified
}

// procExe returns the executable of a process where the platform can tell
// (Linux /proc); ok=false means identity cannot be verified.
func procExe(pid int) (string, bool) {
	if runtime.GOOS != "linux" {
		return "", false
	}
	p, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return "", false
	}
	return strings.TrimSuffix(p, " (deleted)"), true
}

// RecoverOrphans handles children left behind by a previous agent run. Call
// it once at start-up, before starting processes. For each pid record:
//   - process gone: record removed ("stale");
//   - process alive and verified (Linux: /proc/<pid>/exe equals the recorded
//     binary): its process group is terminated (SIGTERM, then SIGKILL after
//     DefaultStopTimeout) and the record removed ("terminated");
//   - process alive but running another binary: the pid was reused, record
//     removed, process untouched ("reused");
//   - identity cannot be verified (non-Linux): record removed, process
//     untouched, warning logged ("unverified").
//
// Records of processes this supervisor currently manages are skipped.
func (s *Supervisor) RecoverOrphans(ctx context.Context) ([]Orphan, error) {
	dir := s.opts.PIDDir
	if dir == "" {
		return nil, nil
	}
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("supervisor: %w", err)
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".pid") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	var out []Orphan
	for _, n := range names {
		path := filepath.Join(dir, n)
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var rec pidRecord
		if err := json.Unmarshal(b, &rec); err != nil || rec.PID <= 1 {
			_ = os.Remove(path)
			out = append(out, Orphan{ID: rec.ID, PID: rec.PID, Action: "stale"})
			continue
		}
		s.mu.Lock()
		_, managed := s.procs[rec.ID]
		s.mu.Unlock()
		if managed {
			continue
		}
		o := Orphan{ID: rec.ID, PID: rec.PID}
		switch {
		case rec.PID == os.Getpid() || !pidAlive(rec.PID):
			o.Action = "stale"
		default:
			exe, ok := procExe(rec.PID)
			switch {
			case !ok:
				o.Action = "unverified"
				s.log.Warnf("supervisor: %s: pid %d from a previous run is alive but its identity cannot be verified here; leaving it alone", rec.ID, rec.PID)
			case exe != filepath.Clean(rec.Exe) && exe != filepath.Clean(rec.Path):
				o.Action = "reused"
			default:
				s.log.Warnf("supervisor: terminating orphan %s (pid %d) left by a previous run", rec.ID, rec.PID)
				terminatePID(ctx, rec.PID, DefaultStopTimeout)
				o.Action = "terminated"
			}
		}
		_ = os.Remove(path)
		out = append(out, o)
	}
	return out, nil
}

// terminatePID asks the process group of pid to stop, then kills it.
func terminatePID(ctx context.Context, pid int, grace time.Duration) {
	_ = signalPID(pid, false)
	if waitGone(ctx, pid, grace) {
		return
	}
	_ = signalPID(pid, true)
	waitGone(ctx, pid, 2*time.Second)
}

func waitGone(ctx context.Context, pid int, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if !pidAlive(pid) {
			return true
		}
		select {
		case <-ctx.Done():
			return !pidAlive(pid)
		case <-time.After(25 * time.Millisecond):
		}
	}
	return !pidAlive(pid)
}
