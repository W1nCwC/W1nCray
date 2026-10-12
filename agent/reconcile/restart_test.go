package reconcile

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/reconcile/internal/testdriver"
	"github.com/W1nCwC/W1nCray/agent/spec"
)

// TestRestartInstancesRestartsOnlyTheNamedInstances is the reconciler rule the
// managed-file layer relies on: after a file changed, the instances that
// reference it are restarted one by one, and every other instance keeps
// running untouched.
func TestRestartInstancesRestartsOnlyTheNamedInstances(t *testing.T) {
	e := newEnv(t)
	a := fwd(t, "a", spec.EngineGost)
	b := fwd(t, "b", spec.EngineGost)
	c := fwd(t, "c", spec.EngineRealm)
	e.mustApply(desired(1, a, b, c))

	got, err := e.r.RestartInstances(context.Background(), []string{"a", "c"})
	if err != nil {
		t.Fatalf("RestartInstances: %v", err)
	}
	eq(t, "restarted", got, []string{"a", "c"})
	if n := e.gost.CountCalls("restart:a"); n != 1 {
		t.Errorf("gost restart:a calls = %d, want 1", n)
	}
	if n := e.gost.CountCalls("restart:b"); n != 0 {
		t.Errorf("gost restarted b: %v", e.gost.Calls())
	}
	if n := e.realm.CountCalls("restart:c"); n != 1 {
		t.Errorf("realm restart:c calls = %d, want 1", n)
	}
	// A restart is not an apply: no instance is re-planned, re-rendered or
	// re-applied.
	if n := e.gost.CountCalls("apply:"); n != 1 {
		t.Errorf("gost applies = %d, want the single initial apply", n)
	}
	if n := e.realm.CountCalls("apply:"); n != 1 {
		t.Errorf("realm applies = %d, want the single initial apply", n)
	}
	// Everything is still running and healthy.
	eq(t, "gost running", e.gost.Running(), []string{"a", "b"})
	eq(t, "realm running", e.realm.Running(), []string{"c"})
	if hr := e.r.Health(context.Background()); !hr.OK {
		t.Errorf("health after the restart: %+v", hr.Diffs)
	}
}

// TestRestartInstancesIgnoresUnknownInstances: an id that is not part of the
// last applied state (a disabled instance, or one removed since) has no
// process to restart and is not an error.
func TestRestartInstancesIgnoresUnknownInstances(t *testing.T) {
	e := newEnv(t)
	a := fwd(t, "a", spec.EngineGost)
	e.mustApply(desired(1, a))

	got, err := e.r.RestartInstances(context.Background(), []string{"ghost", "a"})
	if err != nil {
		t.Fatalf("RestartInstances: %v", err)
	}
	eq(t, "restarted", got, []string{"a"})
	if n := e.gost.CountCalls("restart:ghost"); n != 0 {
		t.Errorf("an unknown instance reached the driver: %v", e.gost.Calls())
	}
}

// TestRestartInstancesWithoutAnAppliedStateIsANoOp: before the first apply
// there is nothing to restart.
func TestRestartInstancesWithoutAnAppliedStateIsANoOp(t *testing.T) {
	e := newEnv(t)
	got, err := e.r.RestartInstances(context.Background(), []string{"a"})
	if err != nil || len(got) != 0 {
		t.Fatalf("RestartInstances = (%v, %v), want (none, nil)", got, err)
	}
}

// TestRestartInstancesEmptyIDsIsANoOp: the managed-file layer may compute an
// empty set; that must never touch a driver.
func TestRestartInstancesEmptyIDsIsANoOp(t *testing.T) {
	e := newEnv(t)
	a := fwd(t, "a", spec.EngineGost)
	e.mustApply(desired(1, a))
	if got, err := e.r.RestartInstances(context.Background(), nil); err != nil || len(got) != 0 {
		t.Fatalf("RestartInstances(nil) = (%v, %v)", got, err)
	}
	if n := e.gost.CountCalls("restart:"); n != 0 {
		t.Errorf("an empty set reached the driver: %v", e.gost.Calls())
	}
}

// TestRestartInstancesReportsAMissingEngine: a driver that was unregistered
// after the apply (the registry changed under the reconciler) is reported, and
// the instances of the engines that are still there are restarted. The same
// guard covers a driver that does not implement the optional Restarter
// capability (the driver.Driver contract requires RestartInstances, so this is
// the reachable half of that check).
func TestRestartInstancesReportsAMissingEngine(t *testing.T) {
	e := newEnv(t)
	a := fwd(t, "a", spec.EngineGost)
	c := fwd(t, "c", spec.EngineRealm)
	e.mustApply(desired(1, a, c))
	delete(e.r.Drivers, "gost")

	got, err := e.r.RestartInstances(context.Background(), []string{"a", "c"})
	if err == nil || !strings.Contains(err.Error(), "gost") {
		t.Fatalf("err = %v, want a reason naming the engine", err)
	}
	eq(t, "restarted", got, []string{"c"})
}

// failingRestarter is a driver whose restart always fails: the reconciler has
// to report it and keep the instances that were restarted.
type failingRestarter struct {
	*testdriver.Fake
}

func (f failingRestarter) RestartInstances(context.Context, driver.Runtime, []string) ([]string, error) {
	return nil, errors.New("instance a: process did not start")
}

// TestRestartInstancesReportsAFailedRestart: a failed restart is reported (the
// panel's alert channel) without undoing anything.
func TestRestartInstancesReportsAFailedRestart(t *testing.T) {
	e := newEnv(t)
	a := fwd(t, "a", spec.EngineGost)
	c := fwd(t, "c", spec.EngineRealm)
	e.mustApply(desired(1, a, c))
	e.r.Drivers["gost"] = failingRestarter{Fake: e.gost}

	got, err := e.r.RestartInstances(context.Background(), []string{"a", "c"})
	if err == nil || !strings.Contains(err.Error(), "process did not start") {
		t.Fatalf("err = %v, want the driver reason", err)
	}
	eq(t, "restarted", got, []string{"c"})
}
