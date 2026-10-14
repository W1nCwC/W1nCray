package reconcile

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/spec"
)

// fakeFirewall records the instance sets it is asked to sync and reports them
// open (unless configured otherwise).
type fakeFirewall struct {
	mu      sync.Mutex
	calls   [][]spec.Instance
	open    map[string]bool
	skipped map[string]string
	err     error
}

func (f *fakeFirewall) Sync(_ context.Context, instances []spec.Instance) (map[string]bool, map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]spec.Instance(nil), instances...))
	if f.err != nil {
		return nil, f.skipped, f.err
	}
	out := map[string]bool{}
	for _, in := range instances {
		if _, skip := f.skipped[in.ID]; skip {
			continue // no rule, so not open (mirrors fwopen)
		}
		if f.open == nil || f.open[in.ID] {
			out[in.ID] = true
		}
	}
	return out, f.skipped, nil
}

func (f *fakeFirewall) synced() [][]spec.Instance {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]spec.Instance(nil), f.calls...)
}

// TestFirewallOpenIsReportedPerInstance: the reconciler drives the firewall
// after a successful apply and copies its per-instance answer into the report.
func TestFirewallOpenIsReportedPerInstance(t *testing.T) {
	e := newEnv(t)
	f := &fakeFirewall{}
	e.r.Firewall = f
	a := fwd(t, "a", "xray")
	b := fwd(t, "b", "xray")
	rep := e.mustApply(desired(1, a, b))
	if !inst(rep, "a").FirewallOpen || !inst(rep, "b").FirewallOpen {
		t.Fatalf("firewall_open not reported: %s", dumpReport(rep))
	}
	calls := f.synced()
	if len(calls) != 1 || len(calls[0]) != 2 {
		t.Fatalf("firewall calls = %v", calls)
	}
	// The firewall sees the desired instances, not the report.
	if calls[0][0].ID != "a" || calls[0][1].ID != "b" {
		t.Fatalf("firewall saw %v", calls[0])
	}
	// An instance the firewall leaves closed is reported false. The desired
	// state must differ in content (the hash ignores the revision), so a is
	// changed a little.
	f.open = map[string]bool{"a": true}
	a2 := a
	a2.Targets = []spec.Target{{Host: "198.51.100.77", Ports: "443"}}
	rep = e.mustApply(desired(2, a2, b))
	if !inst(rep, "a").FirewallOpen || inst(rep, "b").FirewallOpen {
		t.Fatalf("firewall_open did not follow Sync: %s", dumpReport(rep))
	}
}

// TestNilFirewallReportsClosed: a machine where the agent does not manage its
// firewall reports every instance as not opened.
func TestNilFirewallReportsClosed(t *testing.T) {
	e := newEnv(t)
	rep := e.mustApply(desired(1, fwd(t, "a", "xray")))
	if inst(rep, "a").FirewallOpen {
		t.Fatalf("firewall_open = true without a firewall: %s", dumpReport(rep))
	}
}

// TestFirewallFailureDoesNotRollBack: the instances keep running (local
// forwarding works), the report says the ports are not open, and the message
// carries the reason.
func TestFirewallFailureDoesNotRollBack(t *testing.T) {
	e := newEnv(t)
	f := &fakeFirewall{err: errors.New("uci: Invalid argument")}
	e.r.Firewall = f
	rep, err := e.apply(desired(1, fwd(t, "a", "xray")))
	if err != nil || rep.Status != StatusApplied {
		t.Fatalf("a firewall failure must not fail the apply: %v %s", err, dumpReport(rep))
	}
	if inst(rep, "a").FirewallOpen {
		t.Fatalf("firewall_open = true after a failure")
	}
	if !strings.Contains(rep.Message, "firewall rules could not be applied") {
		t.Fatalf("message = %q", rep.Message)
	}
	if len(e.xray.Running()) == 0 {
		t.Fatal("the instance was torn down by a firewall failure")
	}
}

// TestFirewallSkippedInstancesAreReported: an instance the firewall could not
// derive a rule for is reported closed and named in the message, so a missing
// rule is diagnosable from the report alone.
func TestFirewallSkippedInstancesAreReported(t *testing.T) {
	e := newEnv(t)
	f := &fakeFirewall{skipped: map[string]string{"a": `listen ports "0": port 0 out of range 1-65535`}}
	e.r.Firewall = f
	rep := e.mustApply(desired(1, fwd(t, "a", "xray")))
	if inst(rep, "a").FirewallOpen {
		t.Fatalf("firewall_open = true for a skipped instance: %s", dumpReport(rep))
	}
	if !strings.Contains(rep.Message, "firewall rules missing for a (") {
		t.Fatalf("message does not name the skipped instance: %q", rep.Message)
	}
}

// persistedErr models the firewall error that committed the rules but could not
// activate them (fwopen.ReloadError), matched structurally by the reconciler.
type persistedErr struct{}

func (persistedErr) Error() string        { return "reload failed after 3 attempt(s)" }
func (persistedErr) RulesPersisted() bool { return true }

// TestFirewallPersistedButInactive: a reload failure after the commit is
// reported as saved-but-not-active, not as a lost configuration, while the
// instances still report their ports closed.
func TestFirewallPersistedButInactive(t *testing.T) {
	e := newEnv(t)
	e.r.Firewall = &fakeFirewall{err: persistedErr{}}
	rep, err := e.apply(desired(1, fwd(t, "a", "xray")))
	if err != nil || rep.Status != StatusApplied {
		t.Fatalf("a firewall failure must not fail the apply: %v %s", err, dumpReport(rep))
	}
	if inst(rep, "a").FirewallOpen {
		t.Fatalf("firewall_open = true while the reload failed")
	}
	if !strings.Contains(rep.Message, "saved but not active") {
		t.Fatalf("message = %q, want the saved-but-not-active wording", rep.Message)
	}
	if !strings.Contains(rep.Message, "next successful reload") {
		t.Fatalf("message = %q, want it to say when the rules take effect", rep.Message)
	}
}

// TestFirewallFollowsRollback: a failed apply restores the last good state, and
// the firewall is re-synced with the instances that are running again.
func TestFirewallFollowsRollback(t *testing.T) {
	e := newEnv(t)
	f := &fakeFirewall{}
	e.r.Firewall = f
	a := fwd(t, "a", "xray")
	e.mustApply(desired(1, a))

	b := fwd(t, "b", "xray")
	e.xray.FailApply = map[string]string{"b": "boom"}
	rep, err := e.apply(desired(2, a, b))
	if !errors.Is(err, ErrRolledBack) {
		t.Fatalf("%v %s", err, dumpReport(rep))
	}
	calls := f.synced()
	if len(calls) != 2 {
		t.Fatalf("firewall calls = %v", calls)
	}
	if len(calls[1]) != 1 || calls[1][0].ID != "a" {
		t.Fatalf("firewall was not restored to the last good instances: %v", calls[1])
	}
	if !inst(rep, "a").FirewallOpen {
		t.Fatalf("the restored instance is not reported open: %s", dumpReport(rep))
	}
}

// TestReconcileFirewallUsesLastAppliedState: the start-up pass syncs with what
// is applied, and with nothing when no state was applied.
func TestReconcileFirewallUsesLastAppliedState(t *testing.T) {
	e := newEnv(t)
	f := &fakeFirewall{}
	e.r.Firewall = f
	if err := e.r.ReconcileFirewall(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls := f.synced()
	if len(calls) != 1 || calls[0] != nil {
		t.Fatalf("start-up reconcile = %v, want one empty sync", calls)
	}
	a := fwd(t, "a", "xray")
	e.mustApply(desired(1, a))
	if err := e.r.ReconcileFirewall(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls = f.synced()
	last := calls[len(calls)-1]
	if len(last) != 1 || last[0].ID != "a" {
		t.Fatalf("start-up reconcile after an apply = %v", last)
	}
}

// TestReconcileFirewallWithoutManagerIsANoOp keeps the exported entry point
// safe on a machine that does not manage its firewall.
func TestReconcileFirewallWithoutManagerIsANoOp(t *testing.T) {
	e := newEnv(t)
	if err := e.r.ReconcileFirewall(context.Background()); err != nil {
		t.Fatal(err)
	}
}
