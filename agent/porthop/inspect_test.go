package porthop

import (
	"context"
	"testing"
)

func TestInspectReadsTheRecordedRulesInAFreshProcess(t *testing.T) {
	dir := t.TempDir()
	f := newFake()
	m1 := New(Config{Enabled: true, StateDir: dir, Exec: f, Checker: okChecker{}})
	if err := m1.Apply(context.Background(), []Rule{r12}); err != nil {
		t.Fatal(err)
	}
	before := f.count("nft -f")

	m2 := New(Config{Enabled: true, StateDir: dir, Exec: f, Checker: okChecker{}})
	st := m2.Inspect(context.Background())

	if !st.Available || st.Backend != "nft" || len(st.Rules) != 1 || !st.Rules[0].OK || st.Rules[0].NodeID != 12 {
		t.Fatalf("status = %+v", st)
	}
	if f.count("nft -f") != before {
		t.Fatal("Inspect changed the firewall")
	}

	// Somebody flushed the firewall: the recorded rule is reported missing.
	f.mu.Lock()
	f.nftInstalled = map[string]string{}
	f.mu.Unlock()
	st = New(Config{Enabled: true, StateDir: dir, Exec: f, Checker: okChecker{}}).Inspect(context.Background())
	if len(st.Rules) != 1 || st.Rules[0].OK {
		t.Fatalf("status after a flush = %+v", st)
	}
}

func TestInspectWithNothingRecordedOrNoBackend(t *testing.T) {
	st := New(Config{Enabled: true, StateDir: t.TempDir(), Exec: newFake(), Checker: okChecker{}}).Inspect(context.Background())
	if !st.Available || len(st.Rules) != 0 || st.Note != "no rules recorded" {
		t.Fatalf("status = %+v", st)
	}

	f := newFake()
	f.nftCheckOK, f.hasIpt = false, false
	st = New(Config{Enabled: true, StateDir: t.TempDir(), Exec: f, Checker: okChecker{}}).Inspect(context.Background())
	if st.Available || st.LastError == "" {
		t.Fatalf("status without a backend = %+v", st)
	}
}
