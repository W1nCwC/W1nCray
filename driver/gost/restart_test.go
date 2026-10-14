package gost

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// downSup is a supervisor whose process is not running: it is what a restart
// request must refuse instead of pretending it restarted anything.
type downSup struct{}

func (downSup) Start(context.Context, driver.ProcSpec) error { return nil }
func (downSup) Stop(context.Context, string) error           { return nil }
func (downSup) Signal(string, os.Signal) error               { return nil }
func (downSup) Status(string) driver.ProcStatus              { return driver.ProcStatus{} }
func (downSup) Restart(context.Context, string) error        { return nil }

// kernelPath is an absolute path for the (never started) kernel binary: the
// driver checks that the runtime names one before it touches the process.
func kernelPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "gost")
}

// TestRestartInstancesRefusesWhenTheProcessIsNotRunning: the gost process
// hosts every instance, so a restart request while it is down is an error, not
// a silent success.
func TestRestartInstancesRefusesWhenTheProcessIsNotRunning(t *testing.T) {
	d := New(Options{})
	rt := driver.Runtime{StateDir: t.TempDir(), Sup: downSup{}, Kernel: driver.Installed{Path: kernelPath(t)}}
	got, err := d.RestartInstances(context.Background(), rt, []string{"exit"})
	if err == nil || !strings.Contains(err.Error(), "not running") {
		t.Fatalf("err = %v, want a not-running error", err)
	}
	if len(got) != 0 {
		t.Errorf("restarted = %v, want none", got)
	}
}

// TestRestartInstancesWithoutIDsIsANoOp: the managed-file layer may call with
// an empty set; that must never touch the process.
func TestRestartInstancesWithoutIDsIsANoOp(t *testing.T) {
	d := New(Options{})
	rt := driver.Runtime{StateDir: t.TempDir(), Sup: downSup{}, Kernel: driver.Installed{Path: kernelPath(t)}}
	got, err := d.RestartInstances(context.Background(), rt, nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("RestartInstances(nil) = (%v, %v)", got, err)
	}
}
