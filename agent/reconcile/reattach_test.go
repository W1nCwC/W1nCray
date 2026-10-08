package reconcile

import (
	"context"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/spec"
)

// TestReattachRebuildsOnlyTheNamedEngine: Reattach recreates the instances of
// one engine on its new host and leaves every other engine running untouched.
func TestReattachRebuildsOnlyTheNamedEngine(t *testing.T) {
	e := newEnv(t)
	d := desired(1, fwd(t, "x1", "xray"), fwd(t, "g1", "gost"))
	d.Kernels = []spec.KernelPin{{Name: "gost"}}
	e.mustApply(d)
	eq(t, "xray running", e.xray.Running(), []string{"x1"})
	eq(t, "gost running", e.gost.Running(), []string{"g1"})

	swapped := false
	rep, err := e.r.Reattach(context.Background(), "xray", func() { swapped = true })
	if err != nil {
		t.Fatalf("Reattach: %v\n%s", err, dumpReport(rep))
	}
	if !swapped {
		t.Fatal("the swap function was not called")
	}
	if rep.Status != StatusApplied {
		t.Fatalf("status = %s: %s", rep.Status, rep.Message)
	}
	if got := inst(rep, "x1").State; got != StateRunning {
		t.Errorf("xray instance state = %s, want running", got)
	}
	if got := inst(rep, "x1").ConfigHash; got == "" {
		t.Error("the reattached instance reports no config hash")
	}
	if n := e.xray.CountCalls("reattach"); n != 1 {
		t.Errorf("xray reattach calls = %d, want 1", n)
	}

	// The other engine was not touched at all: no reattach, no stop, and its
	// instance is still running.
	if n := e.gost.CountCalls("reattach"); n != 0 {
		t.Errorf("gost reattach calls = %d, want 0", n)
	}
	if n := e.gost.CountCalls("stop:"); n != 0 {
		t.Errorf("gost stop calls = %d, want 0", n)
	}
	eq(t, "gost still running", e.gost.Running(), []string{"g1"})
}

// TestReattachWithoutAppliedState: a reattach before anything was applied is a
// no-op, not an error.
func TestReattachWithoutAppliedState(t *testing.T) {
	e := newEnv(t)
	rep, err := e.r.Reattach(context.Background(), "xray", nil)
	if err != nil {
		t.Fatalf("Reattach: %v", err)
	}
	if rep.Status != StatusApplied {
		t.Fatalf("status = %s, want applied", rep.Status)
	}
	if n := e.xray.CountCalls("reattach"); n != 0 {
		t.Errorf("xray reattach calls = %d, want 0", n)
	}
}
