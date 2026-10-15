package xraynode

import (
	"fmt"
	"testing"
	"time"
)

// ---- the debounce state machine (no sleep, no clock) ---------------------

// TestMachineDebounceSingleChangeReloadsAfterWindow: one changed version opens a
// window and is reported exactly once, at the deadline and not before.
func TestMachineDebounceSingleChangeReloadsAfterWindow(t *testing.T) {
	t0 := time.Unix(1000, 0)
	d := machineDebounce{current: "v1"}

	d.observe("v2", t0)
	if got, ok := d.due(t0); ok {
		t.Fatalf("due right after the change = (%q, true), want no reload", got)
	}
	if got, ok := d.due(t0.Add(machineDebounceWindow - time.Nanosecond)); ok {
		t.Fatalf("due one nanosecond early = (%q, true), want no reload", got)
	}
	got, ok := d.due(t0.Add(machineDebounceWindow))
	if !ok || got != "v2" {
		t.Fatalf("due at the deadline = (%q, %v), want (v2, true)", got, ok)
	}
	if got, ok := d.due(t0.Add(machineDebounceWindow + time.Second)); ok {
		t.Fatalf("due fired twice: (%q, true)", got)
	}
}

// TestMachineDebounceWindowCollapsesChanges: two changes inside one window
// reload once, with the latest version, and the second change does not push the
// deadline back.
func TestMachineDebounceWindowCollapsesChanges(t *testing.T) {
	t0 := time.Unix(2000, 0)
	d := machineDebounce{current: "v1"}

	d.observe("v2", t0)
	d.observe("v3", t0.Add(10*time.Second))

	if got, ok := d.due(t0.Add(machineDebounceWindow - time.Nanosecond)); ok {
		t.Fatalf("due before the original deadline = (%q, true), want no reload", got)
	}
	got, ok := d.due(t0.Add(machineDebounceWindow))
	if !ok || got != "v3" {
		t.Fatalf("due at the original deadline = (%q, %v), want (v3, true)", got, ok)
	}
	if got, ok := d.due(t0.Add(machineDebounceWindow + 10*time.Second)); ok {
		t.Fatalf("due fired twice: (%q, true)", got)
	}
}

// TestMachineDebounceRepeatedChangeKeepsTheSameDeadline: a change that arrives
// while the window is open only replaces the pending version; it must not extend
// the window.
func TestMachineDebounceRepeatedChangeKeepsTheSameDeadline(t *testing.T) {
	t0 := time.Unix(2500, 0)
	d := machineDebounce{current: "v1"}

	d.observe("v2", t0)
	if left := d.timeLeft(t0.Add(5 * time.Second)); left != machineDebounceWindow-5*time.Second {
		t.Fatalf("timeLeft after the first change = %s", left)
	}
	d.observe("v3", t0.Add(20*time.Second))
	if left := d.timeLeft(t0.Add(20 * time.Second)); left != machineDebounceWindow-20*time.Second {
		t.Fatalf("timeLeft after the second change = %s, want the original deadline", left)
	}
}

// TestMachineDebounceVersionRestoredCancels: when the panel reports the running
// version again inside the window, the window is dropped and nothing reloads.
func TestMachineDebounceVersionRestoredCancels(t *testing.T) {
	t0 := time.Unix(3000, 0)
	d := machineDebounce{current: "v1"}

	d.observe("v2", t0)
	d.observe("v1", t0.Add(10*time.Second))

	if got, ok := d.due(t0.Add(machineDebounceWindow)); ok {
		t.Fatalf("due after the version was restored = (%q, true), want no reload", got)
	}
	if left := d.timeLeft(t0.Add(machineDebounceWindow)); left >= 0 {
		t.Fatalf("timeLeft = %s, want no window", left)
	}
}

// TestMachineDebounceUnchangedVersionNeverReloads: an unchanged version never
// opens a window, so due stays false at any time.
func TestMachineDebounceUnchangedVersionNeverReloads(t *testing.T) {
	t0 := time.Unix(4000, 0)
	d := machineDebounce{current: "v1"}

	for i := 0; i < 3; i++ {
		d.observe("v1", t0.Add(time.Duration(i)*10*time.Second))
		if left := d.timeLeft(t0.Add(time.Duration(i) * 10 * time.Second)); left >= 0 {
			t.Fatalf("observation %d opened a window (timeLeft %s)", i, left)
		}
	}
	if got, ok := d.due(t0.Add(machineDebounceWindow)); ok {
		t.Fatalf("due without a change = (%q, true), want no reload", got)
	}
}

// ---- wiring: machineWatch really debounces --------------------------------

// TestMachineDebounceWatchWaitsForTheWindow: with a short poll interval and a
// short debounce window, a changed version is not reloaded when it is first
// seen; the single reload happens once the window expires and uses the newest
// version, even though the version changed again inside the window.
func TestMachineDebounceWatchWaitsForTheWindow(t *testing.T) {
	oldPoll := machinePollInterval
	machinePollInterval = 50 * time.Millisecond
	t.Cleanup(func() { machinePollInterval = oldPoll })
	oldWindow := machineDebounceWindow
	machineDebounceWindow = 400 * time.Millisecond
	t.Cleanup(func() { machineDebounceWindow = oldWindow })

	port1, port2, port3 := freePort(t), freePort(t), freePort(t)
	fp := newMachineFakePanel(t)
	fp.ports = map[int]int{1: port1, 2: port2, 3: port3}
	fp.setNodes([]map[string]any{machineNodeJSON(1, "a", 1)}, "v1")

	path := writeMachineConfig(t, t.TempDir(), fp.srv.URL, "")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	p := New(path, cfg)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	waitNodes(t, p, 1, "initial discovery")
	before := p.lastReloadAt.Load()

	// The panel adds a node: the version changes and the watcher must wait for
	// the whole window before it reloads.
	changedAt := time.Now()
	fp.setNodes([]map[string]any{machineNodeJSON(1, "a", 1), machineNodeJSON(2, "b", 2)}, "v2")
	time.Sleep(machineDebounceWindow / 2)
	if got := len(panelNodes(t, p)); got != 1 {
		t.Fatalf("%d controllers %s after the change, want 1: the reload was not debounced", got, machineDebounceWindow/2)
	}
	if got := p.lastReloadAt.Load(); got != before {
		t.Fatal("the instance reloaded before the debounce window expired")
	}

	// The panel moves on again while the window is open: the deadline is not
	// extended, and the one reload that follows uses the newest version.
	fp.setNodes([]map[string]any{machineNodeJSON(1, "a", 1), machineNodeJSON(2, "b", 2), machineNodeJSON(3, "c", 3)}, "v3")
	deadline := changedAt.Add(machineDebounceWindow + 5*time.Second)
	for p.lastReloadAt.Load() == before {
		if time.Now().After(deadline) {
			t.Fatal("the debounced reload never happened")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if elapsed := time.Since(changedAt); elapsed < machineDebounceWindow {
		t.Fatalf("the reload happened %s after the change, before the %s window expired", elapsed, machineDebounceWindow)
	}
	waitNodes(t, p, 3, "after the debounce window expired")
	if fp.configHitsFor(2) == 0 || fp.configHitsFor(3) == 0 {
		t.Error("the reload did not use the newest version")
	}
	waitDial(t, fmt.Sprintf("127.0.0.1:%d", port2), true, 15*time.Second, "the added node listens after the debounced reload")

	// One reload only, and the deadline was not pushed back by the second
	// change: the node count and the reload stamp stay put afterwards.
	settled := p.lastReloadAt.Load()
	quiet := time.Now().Add(2 * machineDebounceWindow)
	for time.Now().Before(quiet) {
		if n := len(panelNodes(t, p)); n != 3 {
			t.Fatalf("%d controllers after the debounced reload, want 3", n)
		}
		if got := p.lastReloadAt.Load(); got != settled {
			t.Fatal("the debounce reloaded more than once")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
