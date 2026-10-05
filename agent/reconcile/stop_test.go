package reconcile

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/reconcile/internal/testdriver"
	"github.com/W1nCwC/W1nCray/agent/state"
)

func dialable(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

type persisted struct {
	desired, lastGood state.Snapshot
	blockedHash       string
}

func loadPersisted(t *testing.T, st *state.Store) persisted {
	t.Helper()
	var p persisted
	d, ok, err := st.LoadDesired()
	if err != nil || !ok {
		t.Fatalf("LoadDesired: ok=%v err=%v", ok, err)
	}
	lg, ok, err := st.LoadLastGood()
	if err != nil || !ok {
		t.Fatalf("LoadLastGood: ok=%v err=%v", ok, err)
	}
	h, _, err := st.LoadBlocked()
	if err != nil {
		t.Fatal(err)
	}
	p.desired, p.lastGood, p.blockedHash = d, lg, h
	return p
}

func TestStopKeepsPersistedStateAndReleasesEverything(t *testing.T) {
	e := newEnv(t)
	g := fwd(t, "g", "gost")
	x := fwd(t, "x", "xray")
	rep := e.mustApply(desired(4, g, x))
	gAddr := "127.0.0.1:" + g.Listen.Ports
	xAddr := "127.0.0.1:" + x.Listen.Ports
	if !dialable(gAddr) || !dialable(xAddr) {
		t.Fatal("instances are not reachable after apply")
	}
	if len(e.ports.Claims()) != 2 {
		t.Fatalf("ledger claims before stop: %v", e.ports.Claims())
	}
	before := loadPersisted(t, e.st)

	if err := e.r.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// every driver was stopped with no ids (= all instances)
	if e.gost.CountCalls("stop:") != 1 || e.xray.CountCalls("stop:") != 1 {
		t.Fatalf("stop calls: gost=%v xray=%v", e.gost.Calls(), e.xray.Calls())
	}
	if got := e.gost.Calls(); got[len(got)-1] != "stop:" {
		t.Fatalf("gost was not stopped for all instances: %v", got)
	}
	eq(t, "gost running", e.gost.Running(), nil)
	eq(t, "xray running", e.xray.Running(), nil)
	if dialable(gAddr) || dialable(xAddr) {
		t.Fatal("listeners still reachable after Stop")
	}
	if c := e.ports.Claims(); len(c) != 0 {
		t.Fatalf("port ledger not released: %v", c)
	}
	if e.r.currentApplied() != nil {
		t.Fatal("in-memory applied state not cleared")
	}
	if hr := e.r.Health(context.Background()); hr.Skipped == "" || hr.OK {
		t.Fatalf("Health after Stop = %+v, want skipped", hr)
	}

	// persisted state is byte-for-byte the same (SavedAt included: not rewritten)
	after := loadPersisted(t, e.st)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("persisted state changed by Stop:\nbefore %+v\nafter  %+v", before, after)
	}
	if after.lastGood.Hash != rep.Hash || len(after.lastGood.Desired.Instances) != 2 {
		t.Fatalf("last_good content wrong: %+v", after.lastGood)
	}
}

func TestStopIsIdempotentAndSafeOnFreshReconciler(t *testing.T) {
	e := newEnv(t)
	// never applied: nothing to do, no driver is touched
	if err := e.r.Stop(context.Background()); err != nil {
		t.Fatalf("Stop on fresh reconciler: %v", err)
	}
	if e.gost.CountCalls("stop:")+e.xray.CountCalls("stop:") != 0 {
		t.Fatal("a driver was stopped although nothing was applied")
	}

	e.mustApply(desired(1, fwd(t, "g", "gost"), fwd(t, "x", "xray")))
	for i := 0; i < 3; i++ {
		if err := e.r.Stop(context.Background()); err != nil {
			t.Fatalf("Stop #%d: %v", i+1, err)
		}
	}
	if n := e.gost.CountCalls("stop:"); n != 1 {
		t.Fatalf("gost stopped %d times, want exactly 1 (idempotent)", n)
	}
	loadPersisted(t, e.st)
}

// stopFailer makes Stop fail (until healed) without stopping anything.
type stopFailer struct {
	*testdriver.Fake
	fail atomic.Bool
	n    atomic.Int32
}

func (s *stopFailer) Stop(ctx context.Context, rt driver.Runtime, ids ...string) error {
	s.n.Add(1)
	if s.fail.Load() {
		return errors.New("kernel refused to stop")
	}
	return s.Fake.Stop(ctx, rt, ids...)
}

func TestStopContinuesAfterDriverErrorAndJoinsErrors(t *testing.T) {
	e := newEnv(t)
	bad := &stopFailer{Fake: e.gost}
	bad.fail.Store(true)
	e.r.Drivers["gost"] = bad
	e.mustApply(desired(1, fwd(t, "g", "gost"), fwd(t, "x", "xray"), fwd(t, "r", "realm")))
	before := loadPersisted(t, e.st)

	err := e.r.Stop(context.Background())
	if err == nil || !strings.Contains(err.Error(), `stop engine "gost"`) || !strings.Contains(err.Error(), "kernel refused to stop") {
		t.Fatalf("Stop error = %v", err)
	}
	// the other drivers were still stopped, and the ledger / applied state are reset
	eq(t, "xray running", e.xray.Running(), nil)
	eq(t, "realm running", e.realm.Running(), nil)
	eq(t, "gost still running (its Stop failed)", e.gost.Running(), []string{"g"})
	if e.r.currentApplied() != nil || len(e.ports.Claims()) != 0 {
		t.Fatal("applied state / ledger not reset after a partial Stop")
	}
	if after := loadPersisted(t, e.st); !reflect.DeepEqual(before, after) {
		t.Fatal("persisted state changed by a failing Stop")
	}

	// a second error joins with the first: two failing drivers
	e2 := newEnv(t)
	b1 := &stopFailer{Fake: e2.gost}
	b2 := &stopFailer{Fake: e2.realm}
	b1.fail.Store(true)
	b2.fail.Store(true)
	e2.r.Drivers["gost"], e2.r.Drivers["realm"] = b1, b2
	e2.mustApply(desired(1, fwd(t, "g", "gost"), fwd(t, "r", "realm"), fwd(t, "x", "xray")))
	err = e2.r.Stop(context.Background())
	if err == nil || !strings.Contains(err.Error(), `"gost"`) || !strings.Contains(err.Error(), `"realm"`) {
		t.Fatalf("joined error = %v", err)
	}
	eq(t, "xray running", e2.xray.Running(), nil)

	// the driver that failed is retried by the next Stop and then really stops
	bad.fail.Store(false)
	if err := e.r.Stop(context.Background()); err != nil {
		t.Fatalf("retry Stop: %v", err)
	}
	eq(t, "gost running after retry", e.gost.Running(), nil)
	if n := bad.n.Load(); n != 2 {
		t.Fatalf("failing driver Stop called %d times, want 2", n)
	}
	// ... and only the failed one: xray was not stopped a second time
	if n := e.xray.CountCalls("stop:"); n != 1 {
		t.Fatalf("xray stopped %d times, want 1", n)
	}
}

func TestStopThenResumeRestoresSameDesired(t *testing.T) {
	e := newEnv(t)
	g := fwd(t, "g", "gost")
	x := fwd(t, "x", "xray")
	first := e.mustApply(desired(4, g, x))
	if err := e.r.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	eq(t, "running after Stop", append(e.gost.Running(), e.xray.Running()...), nil)

	rep, err := e.r.Resume(context.Background())
	if err != nil || rep.Status != StatusApplied || rep.Hash != first.Hash {
		t.Fatalf("Resume after Stop: %v\n%s", err, dumpReport(rep))
	}
	eq(t, "gost", e.gost.Running(), []string{"g"})
	eq(t, "xray", e.xray.Running(), []string{"x"})
	if !dialable("127.0.0.1:"+g.Listen.Ports) || !dialable("127.0.0.1:"+x.Listen.Ports) {
		t.Fatal("instances not reachable after Resume")
	}
	if len(e.ports.Claims()) != 2 {
		t.Fatalf("ledger after Resume: %v", e.ports.Claims())
	}

	// Stop -> Apply of the very same state is a real apply again, not a no-op
	if err := e.r.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	rep, err = e.r.Apply(context.Background(), desired(5, g, x))
	if err != nil || rep.Status != StatusApplied || rep.Message != "applied 2 instance(s)" {
		t.Fatalf("Apply after Stop: %v\n%s", err, dumpReport(rep))
	}
	eq(t, "gost", e.gost.Running(), []string{"g"})
}

func TestStopDoesNotEmptyDriversThatAreGoneFromDesired(t *testing.T) {
	// After Stop the in-memory "drivers to empty" list is clean: a later Apply
	// that no longer uses gost must not call gost at all.
	e := newEnv(t)
	e.mustApply(desired(1, fwd(t, "g", "gost")))
	if err := e.r.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls := len(e.gost.Calls())
	e.mustApply(desired(2, fwd(t, "x", "xray")))
	if got := e.gost.Calls(); len(got) != calls {
		t.Fatalf("gost touched after Stop: %v", got[calls:])
	}
}

func TestStopWaitsForApplyInFlight(t *testing.T) {
	e := newEnv(t)
	e.gost.ApplyDelay = 150 * time.Millisecond
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := e.apply(desired(1, fwd(t, "g", "gost"))); err != nil {
			t.Errorf("apply: %v", err)
		}
	}()
	for i := 0; e.gost.CountCalls("apply:") == 0; i++ {
		if i > 500 {
			t.Fatal("apply never started")
		}
		time.Sleep(2 * time.Millisecond)
	}
	if err := e.r.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	default:
		t.Fatal("Stop returned while an Apply was still in flight (not serialised)")
	}
	// the Apply finished first, then Stop tore it down
	eq(t, "gost running", e.gost.Running(), nil)
	if e.r.currentApplied() != nil {
		t.Fatal("applied state survived Stop")
	}
	if _, ok, _ := e.st.LoadLastGood(); !ok {
		t.Fatal("last_good lost")
	}
}
