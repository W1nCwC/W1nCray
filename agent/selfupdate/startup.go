package selfupdate

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Startup is the start-up state of a process that may be the result of a
// committed self-update. It is created once, early in the agent's run, and is
// how the process:
//
//   - reports a rollback the helper performed before this start
//     (self_update.rolled_back), and
//   - confirms the pending update once it reached the panel, or reports
//     self_update.stalled when it never does.
//
// A process that started but cannot reach the panel is never rolled back by
// itself: a panel outage is not a broken binary (protocol ruling 11).
type Startup struct {
	up      *Updater
	pending Pending
	has     bool

	mu        sync.Mutex
	confirmed bool
	done      chan struct{}
}

// BeginStartup reads the update markers. It does not report anything: the
// caller consumes the rollback marker with TakeRollback at the moment it has a
// channel to report on (the WebSocket event sink), and confirms with Confirm
// once the panel link is up.
func (u *Updater) BeginStartup() *Startup {
	s := &Startup{up: u, done: make(chan struct{})}
	if p, ok := u.Pending(); ok {
		s.pending, s.has = p, true
	}
	return s
}

// Pending reports the committed update this process is running from.
func (s *Startup) Pending() (Pending, bool) { return s.pending, s.has }

// TakeRollback returns the rollback the helper recorded before this start and
// removes the marker, so the event is reported exactly once.
func (s *Startup) TakeRollback() (Rollback, bool) { return s.up.TakeRollback() }

// Confirm marks the pending update as proven and stops the stalled watchdog.
// It is a no-op after the first call and when nothing is pending.
func (s *Startup) Confirm() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.confirmed {
		return nil
	}
	s.confirmed = true
	close(s.done)
	if !s.has {
		return nil
	}
	return s.up.Confirm()
}

// Confirmed reports whether Confirm already ran.
func (s *Startup) Confirmed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.confirmed
}

// WatchStalled reports self_update.stalled when the pending update was not
// confirmed within the confirm window. It returns immediately and stops at
// once when Confirm happens or ctx is done. It never rolls back.
func (s *Startup) WatchStalled(ctx context.Context, report func(kind, level, message string)) {
	if !s.has {
		return
	}
	t := time.NewTimer(s.up.confirmWindow)
	defer t.Stop()
	select {
	case <-s.done:
		return
	case <-ctx.Done():
		return
	case <-t.C:
	}
	if report == nil {
		s.up.log.Warnf("selfupdate: version %s has not reached the panel within %s; not rolling back",
			s.pending.Version, s.up.confirmWindow)
		return
	}
	report("self_update.stalled", "warn", fmt.Sprintf(
		"version %s has not reached the panel within %s; it is not rolled back automatically",
		s.pending.Version, s.up.confirmWindow))
}
