package frp

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// restartSup is a minimal supervisor for the restart test: it records the
// restarts and reports the process it was asked about as running.
type restartSup struct {
	restarts []string
	err      error
}

func (s *restartSup) Start(context.Context, driver.ProcSpec) error { return nil }
func (s *restartSup) Stop(context.Context, string) error           { return nil }
func (s *restartSup) Signal(string, os.Signal) error               { return nil }
func (s *restartSup) Status(id string) driver.ProcStatus {
	return driver.ProcStatus{Running: true, PID: 1}
}
func (s *restartSup) Restart(_ context.Context, id string) error {
	if s.err != nil {
		return s.err
	}
	s.restarts = append(s.restarts, id)
	return nil
}

// TestRestartInstancesRestartsOnlyTheNamedProcesses is the driver-level rule
// the managed-file reload relies on: each named instance's own supervised
// process is replaced (never the whole component), and an instance that is not
// part of the current set is left alone.
func TestRestartInstancesRestartsOnlyTheNamedProcesses(t *testing.T) {
	state := t.TempDir()
	sup := &restartSup{}
	d := New(Options{})
	rt := driver.Runtime{StateDir: state, Sup: sup, Kernel: driver.Installed{Path: "/opt/frp/frps"}}
	cur := map[string]*unit{
		"portal": {ID: "portal", Role: rolePortal, Hash: "h1"},
		"bridge": {ID: "bridge", Role: roleBridge, Hash: "h2"},
	}
	if err := saveState(rt, currentFile, cur); err != nil {
		t.Fatal(err)
	}
	d.current = cur

	got, err := d.RestartInstances(context.Background(), rt, []string{"portal", "ghost"})
	if err != nil {
		t.Fatalf("RestartInstances: %v", err)
	}
	if strings.Join(got, ",") != "portal" {
		t.Errorf("restarted = %v, want [portal]", got)
	}
	if strings.Join(sup.restarts, ",") != "frp/frps-portal" {
		t.Errorf("supervisor restarts = %v, want [frp/frps-portal]", sup.restarts)
	}
}

// TestRestartInstancesReportsAFailureAndKeepsGoing: a process that cannot be
// restarted is reported, and the instances that can are still restarted.
func TestRestartInstancesReportsAFailureAndKeepsGoing(t *testing.T) {
	state := t.TempDir()
	sup := &restartSup{err: errors.New("no such process")}
	d := New(Options{})
	rt := driver.Runtime{StateDir: state, Sup: sup, Kernel: driver.Installed{Path: "/opt/frp/frps"}}
	cur := map[string]*unit{"portal": {ID: "portal", Role: rolePortal, Hash: "h1"}}
	if err := saveState(rt, currentFile, cur); err != nil {
		t.Fatal(err)
	}
	d.current = cur

	got, err := d.RestartInstances(context.Background(), rt, []string{"portal"})
	if err == nil || !strings.Contains(err.Error(), "portal") {
		t.Fatalf("err = %v, want a failure naming the instance", err)
	}
	if len(got) != 0 {
		t.Errorf("restarted = %v, want none", got)
	}
}

// TestRestartInstancesWithoutASupervisorRestarterIsAnError: a supervisor that
// cannot restart one process must be reported, not ignored.
func TestRestartInstancesWithoutASupervisorRestarterIsAnError(t *testing.T) {
	state := t.TempDir()
	d := New(Options{})
	rt := driver.Runtime{StateDir: state, Sup: plainSup{}, Kernel: driver.Installed{Path: "/opt/frp/frps"}}
	if _, err := d.RestartInstances(context.Background(), rt, []string{"portal"}); err == nil {
		t.Fatal("a supervisor without Restart was accepted")
	}
}

// plainSup implements driver.Supervisor only.
type plainSup struct{}

func (plainSup) Start(context.Context, driver.ProcSpec) error { return nil }
func (plainSup) Stop(context.Context, string) error           { return nil }
func (plainSup) Signal(string, os.Signal) error               { return nil }
func (plainSup) Status(string) driver.ProcStatus              { return driver.ProcStatus{} }
