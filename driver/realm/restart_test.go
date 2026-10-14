package realm

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// restartSup wraps the in-memory fake with the single-process restart the
// managed-file reload uses (the production supervisor's Stop + Start).
type restartSup struct {
	*fakeSup
	restarts []string
	err      error
}

func (s *restartSup) Restart(ctx context.Context, id string) error {
	if s.err != nil {
		return s.err
	}
	s.restarts = append(s.restarts, id)
	p := s.fakeSup.procs[id].spec
	if err := s.fakeSup.Stop(ctx, id); err != nil {
		return err
	}
	return s.fakeSup.Start(ctx, p)
}

// TestRestartInstancesRestartsOnlyTheNamedProcesses: a managed-file change
// restarts the named instances' own processes and leaves every other instance
// (and its listeners) untouched.
func TestRestartInstancesRestartsOnlyTheNamedProcesses(t *testing.T) {
	e := newEnv(t)
	sup := &restartSup{fakeSup: e.sup}
	e.rt.Sup = sup

	a := fwd("alpha", "127.0.0.1", "8001", tg("10.0.0.1", "80", 0))
	b := fwd("beta", "127.0.0.1", "8002", tg("10.0.0.2", "80", 0))
	if _, err := e.apply(t, a, b); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	sup.take()

	got, err := e.d.RestartInstances(context.Background(), e.rt, []string{"alpha", "ghost"})
	if err != nil {
		t.Fatalf("RestartInstances: %v", err)
	}
	if strings.Join(got, ",") != "alpha" {
		t.Errorf("restarted = %v, want [alpha]", got)
	}
	if strings.Join(sup.restarts, ",") != "realm/alpha" {
		t.Errorf("supervisor restarts = %v, want [realm/alpha]", sup.restarts)
	}
	if ev := strings.Join(sup.take(), ","); ev != "stop realm/alpha,start realm/alpha" {
		t.Errorf("events = %s (beta must not appear)", ev)
	}
	// The other instance is still there, and so is alpha.
	if !sup.Status("realm/beta").Running {
		t.Error("beta was touched")
	}
	h := e.d.Health(context.Background(), e.rt)
	if !h.Instances["alpha"].Running || !h.Instances["beta"].Running {
		t.Errorf("health after the restart: %+v", h.Instances)
	}
}

// TestRestartInstancesReportsAFailureAndKeepsGoing: a process that cannot be
// restarted is reported; the others are still restarted.
func TestRestartInstancesReportsAFailureAndKeepsGoing(t *testing.T) {
	e := newEnv(t)
	sup := &restartSup{fakeSup: e.sup, err: errors.New("stop: input/output error")}
	e.rt.Sup = sup

	a := fwd("alpha", "127.0.0.1", "8001", tg("10.0.0.1", "80", 0))
	if _, err := e.apply(t, a); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	got, err := e.d.RestartInstances(context.Background(), e.rt, []string{"alpha"})
	if err == nil || !strings.Contains(err.Error(), "alpha") {
		t.Fatalf("err = %v, want a failure naming the instance", err)
	}
	if len(got) != 0 {
		t.Errorf("restarted = %v, want none", got)
	}
}

// TestRestartInstancesSkipsInstancesThatAreNotRunning: an id that is not part
// of the applied state (or whose process is gone) is not an error and is not
// reported as restarted.
func TestRestartInstancesSkipsInstancesThatAreNotRunning(t *testing.T) {
	e := newEnv(t)
	sup := &restartSup{fakeSup: e.sup}
	e.rt.Sup = sup

	a := fwd("alpha", "127.0.0.1", "8001", tg("10.0.0.1", "80", 0))
	if _, err := e.apply(t, a); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	sup.kill("realm/alpha")

	got, err := e.d.RestartInstances(context.Background(), e.rt, []string{"alpha"})
	if err != nil {
		t.Fatalf("RestartInstances: %v", err)
	}
	if len(got) != 0 || len(sup.restarts) != 0 {
		t.Errorf("restarted = %v, supervisor restarts = %v, want none", got, sup.restarts)
	}
}

// TestRestartInstancesWithoutASupervisorRestarterIsAnError: a supervisor that
// cannot restart one process must be reported, not ignored.
func TestRestartInstancesWithoutASupervisorRestarterIsAnError(t *testing.T) {
	e := newEnv(t)
	if _, err := e.d.RestartInstances(context.Background(), e.rt, []string{"alpha"}); err == nil {
		t.Fatal("a supervisor without Restart was accepted")
	}
}

var _ driver.Supervisor = (*restartSup)(nil)
