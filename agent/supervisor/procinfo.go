package supervisor

import (
	"context"
	"fmt"
)

// PIDAlive reports whether a live process has this pid, using the same test the
// supervisor uses for its own children (a zombie does not count as alive on
// Linux). It is exported so the kernel manager can tell "this version is
// running" from a stale pid record without duplicating the platform code.
func PIDAlive(pid int) bool { return pidAlive(pid) }

// ProcExe returns the executable a process is actually running where the
// platform can tell (Linux /proc/<pid>/exe). ok=false means the identity cannot
// be verified here, and the caller must not trust the pid alone.
func ProcExe(pid int) (string, bool) { return procExe(pid) }

// Restart stops id and starts it again with the same spec (the same binary,
// argv and environment). It is what the component_restart command uses: only a
// supervised kernel process can be restarted, never the agent itself, which is
// not supervised. An unknown id is an error.
func (s *Supervisor) Restart(ctx context.Context, id string) error {
	s.mu.Lock()
	e := s.procs[id]
	s.mu.Unlock()
	if e == nil {
		return fmt.Errorf("supervisor: unknown process %q", id)
	}
	spec := e.spec
	if err := s.Stop(ctx, id); err != nil {
		return err
	}
	return s.Start(ctx, spec)
}
