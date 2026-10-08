package selfupdate

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"
)

// TestWatchdogKeepsASlowButHealthyNewAgent is the D-M7 regression test: the
// service manager needs longer than the old 10 s window to bring the new
// process up (respawn delay plus a slow start-up on a 2 vCPU OpenWrt 25.12),
// but the process does come up and confirm. The watchdog must keep the update.
//
// It failed before the fix: with DefaultAliveWindow = 10 s the watchdog rolled
// the healthy update back at t+10s, the install path became the old binary and
// the pending marker was cleared.
func TestWatchdogKeepsASlowButHealthyNewAgent(t *testing.T) {
	up, exe, state := watchdogFixture(t)
	clock := &fakeClock{t: time.Unix(1000, 0)}

	// Longer than the old 10 s window, shorter than the new architecture
	// default (60 s on amd64/arm64, 180 s on the slower targets).
	const startupDelay = 25 * time.Second
	if startupDelay <= 10*time.Second {
		t.Fatal("the test must start slower than the old 10 s window to be a regression test")
	}
	alive, _ := DefaultWatchdogWindows(runtime.GOARCH)
	if startupDelay >= alive {
		t.Fatalf("startupDelay %s must stay inside the current window %s", startupDelay, alive)
	}
	appearedAt := time.Unix(1000, 0).Add(startupDelay)
	confirmed := false
	probe := func() (int, bool) {
		if clock.now().Before(appearedAt) {
			// The single-instance lock still names the process that exited.
			return 0, false
		}
		return 4242, true
	}
	// AliveWindow and Deadline stay zero on purpose: the test exercises the
	// defaults, which is exactly what used to be too small.
	h := HelperOptions{
		ExePath: exe, StateDir: state, LockPath: filepath.Join(state, "config.yml.lock"),
	}
	sleep := func(d time.Duration) {
		clock.sleep(d)
		if !confirmed && !clock.now().Before(appearedAt) {
			confirmed = true
			if err := up.Confirm(); err != nil {
				t.Errorf("Confirm: %v", err)
			}
		}
	}
	if err := runWatchdog(context.Background(), h, probe, clock.now, sleep, nopLog{}); err != nil {
		t.Fatalf("runWatchdog: %v", err)
	}
	if !confirmed {
		t.Fatal("the test never confirmed the update; the watchdog stopped early")
	}
	if got := readFile(t, exe); got != "NEW-BINARY" {
		t.Fatalf("exe = %q, want the new binary kept (a slow start must not be rolled back)", got)
	}
	if _, ok := up.TakeRollback(); ok {
		t.Error("a slow but healthy start must not record a rollback")
	}
	if _, err := os.Stat(up.OldPath()); !os.IsNotExist(err) {
		t.Error("a confirmed update must clean the backup")
	}
}

// TestReadyMarkerRoundTrip covers MarkReady/ReadyMarker and the cleanup on
// Confirm and Rollback.
func TestReadyMarkerRoundTrip(t *testing.T) {
	up, _, _ := watchdogFixture(t)
	if _, ok := up.ReadyMarker(); ok {
		t.Fatal("no marker was written yet")
	}
	if err := up.MarkReady(); err != nil {
		t.Fatalf("MarkReady: %v", err)
	}
	m, ok := up.ReadyMarker()
	if !ok {
		t.Fatal("the marker must be readable after MarkReady")
	}
	if m.Version != "0.5.0" || m.PID != os.Getpid() {
		t.Fatalf("marker = %+v, want the running version and pid", m)
	}
	if err := up.Confirm(); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if _, ok := up.ReadyMarker(); ok {
		t.Error("Confirm must clear the ready marker")
	}

	up2, _, _ := watchdogFixture(t)
	if err := up2.MarkReady(); err != nil {
		t.Fatal(err)
	}
	if err := up2.Rollback("test"); err != nil {
		t.Fatal(err)
	}
	if _, ok := up2.ReadyMarker(); ok {
		t.Error("Rollback must clear the ready marker")
	}
}

// TestDefaultWatchdogWindowsAreArchitectureAware pins the D-M7 window rule:
// the slow targets get a longer window than the fast ones, and every window
// leaves the deadline room to fire the rollback rule first.
func TestDefaultWatchdogWindowsAreArchitectureAware(t *testing.T) {
	fastAlive, fastDeadline := DefaultWatchdogWindows("amd64")
	slowAlive, slowDeadline := DefaultWatchdogWindows("mips")
	if fastAlive <= 10*time.Second {
		t.Errorf("the amd64 window %s must cover a service manager restart delay plus a slow start", fastAlive)
	}
	if slowAlive <= fastAlive {
		t.Errorf("the slow-target window %s must be longer than the amd64 one %s", slowAlive, fastAlive)
	}
	if fastDeadline <= fastAlive || slowDeadline <= slowAlive {
		t.Errorf("deadlines must stay above their windows: amd64 %s/%s, mips %s/%s",
			fastAlive, fastDeadline, slowAlive, slowDeadline)
	}
	// arm64 shares the fast default.
	if a, d := DefaultWatchdogWindows("arm64"); a != fastAlive || d != fastDeadline {
		t.Errorf("arm64 windows = %s/%s, want %s/%s", a, d, fastAlive, fastDeadline)
	}
}

// TestWatchdogRaisesADeadlineBelowTheWindow keeps a misconfigured budget honest:
// a deadline that expires first would turn every slow start into a "stalled,
// kept" update and the machine would never be rolled back to a working binary.
func TestWatchdogRaisesADeadlineBelowTheWindow(t *testing.T) {
	up, exe, state := watchdogFixture(t)
	clock := &fakeClock{t: time.Unix(1000, 0)}
	probe := func() (int, bool) { return 0, false }
	h := watchdogBudget(exe, state)
	h.AliveWindow = 30 * time.Second
	h.Deadline = 5 * time.Second
	if err := runWatchdog(context.Background(), h, probe, clock.now, clock.sleep, nopLog{}); err != nil {
		t.Fatalf("runWatchdog: %v", err)
	}
	if _, ok := up.Pending(); ok {
		t.Fatal("the rollback must still fire: a deadline below the window must not win")
	}
	if got := readFile(t, exe); got != "OLD-BINARY" {
		t.Errorf("exe = %q, want the previous binary restored", got)
	}
}

// TestServiceBackendCommands covers the three service managers and the
// no-manager fallback the rollback has to handle (R1-16): the Xray stop and
// the agent restart must be right on each of them, and absent (nil) when no
// service manager owns the process.
func TestServiceBackendCommands(t *testing.T) {
	systemd := func(p string) bool { return p == "/run/systemd/system" }
	openrc := func(p string) bool { return p == "/sbin/openrc-run" }
	procd := func(p string) bool { return p == "/sbin/procd" || p == "/etc/rc.common" }
	none := func(string) bool { return false }

	cases := []struct {
		name        string
		exists      func(string) bool
		wantStop    []string
		wantRestart [][]string
	}{
		{
			name: "systemd", exists: systemd,
			wantStop:    []string{"systemctl", "stop", "W1nCray-xray"},
			wantRestart: [][]string{{"systemctl", "reset-failed", "W1nCray.service"}, {"systemctl", "restart", "W1nCray.service"}},
		},
		{
			name: "openrc", exists: openrc,
			wantStop:    []string{"rc-service", "W1nCray-xray", "stop"},
			wantRestart: [][]string{{"rc-service", "W1nCray", "restart"}},
		},
		{
			name: "procd", exists: procd,
			wantStop:    []string{"/etc/init.d/W1nCray-xray", "stop"},
			wantRestart: [][]string{{"/etc/init.d/W1nCray", "restart"}},
		},
		{
			name: "no service manager", exists: none,
			wantStop: nil, wantRestart: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := stopXrayCommand(tc.exists); !reflect.DeepEqual(got, tc.wantStop) {
				t.Errorf("stopXrayCommand = %v, want %v", got, tc.wantStop)
			}
			if got := restartAgentCommand("", tc.exists); !reflect.DeepEqual(got, tc.wantRestart) {
				t.Errorf("restartAgentCommand = %v, want %v", got, tc.wantRestart)
			}
		})
	}
	// A detected systemd unit name wins over the conventional one.
	if got := restartAgentCommand("W1nCray-custom.service", systemd); got[0][2] != "W1nCray-custom.service" {
		t.Errorf("restartAgentCommand must use the detected unit: %v", got)
	}
}

// TestRollbackStopsTheXrayServiceBeforeRestoringTheBinary is the R1-16
// regression test: a rollback to the in-process-Xray 0.5.x agent must stop the
// W1nCray-xray service first, and it must do so while the failed binary is
// still installed (before the previous binary is renamed back).
func TestRollbackStopsTheXrayServiceBeforeRestoringTheBinary(t *testing.T) {
	up, exe, state := watchdogFixture(t)

	oldRun, oldExists := runServiceCommand, serviceExists
	t.Cleanup(func() { runServiceCommand, serviceExists = oldRun, oldExists })
	serviceExists = func(p string) bool { return p == "/run/systemd/system" }
	var calls [][]string
	var exeAtStop string
	runServiceCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		argv := append([]string{name}, args...)
		if len(calls) == 0 {
			// The first call is the Xray stop, and it must happen while the
			// failed binary is still installed: the whole point of R1-16 is
			// that the service is down before the in-process-Xray 0.5.x
			// binary can come back.
			exeAtStop = readFile(t, exe)
		}
		calls = append(calls, argv)
		return nil, nil
	}

	h := watchdogBudget(exe, state)
	h.Unit = "W1nCray.service"
	if err := rollbackAndRestart(up, h, "test rollback", nopLog{}); err != nil {
		t.Fatalf("rollbackAndRestart: %v", err)
	}
	want := [][]string{
		{"systemctl", "stop", "W1nCray-xray"},
		{"systemctl", "reset-failed", "W1nCray.service"},
		{"systemctl", "restart", "W1nCray.service"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("service calls = %v, want %v", calls, want)
	}
	if exeAtStop != "NEW-BINARY" {
		t.Errorf("the Xray service was stopped after the rollback (exe = %q); it must be stopped first", exeAtStop)
	}
	if got := readFile(t, exe); got != "OLD-BINARY" {
		t.Errorf("exe = %q, want the previous binary restored", got)
	}
	if _, ok := up.Pending(); ok {
		t.Error("the rollback must clear the pending marker")
	}
}

// TestRollbackLogsWhenNoServiceManagerExists covers the fallback: with no
// systemd/OpenRC/procd the rollback still restores the binary and says that the
// operator has to start it.
func TestRollbackLogsWhenNoServiceManagerExists(t *testing.T) {
	up, exe, state := watchdogFixture(t)
	oldExists := serviceExists
	t.Cleanup(func() { serviceExists = oldExists })
	serviceExists = func(string) bool { return false }

	h := watchdogBudget(exe, state)
	if err := rollbackAndRestart(up, h, "test rollback", nopLog{}); err != nil {
		t.Fatalf("rollbackAndRestart: %v", err)
	}
	if got := readFile(t, exe); got != "OLD-BINARY" {
		t.Errorf("exe = %q, want the previous binary restored without a service manager", got)
	}
}
