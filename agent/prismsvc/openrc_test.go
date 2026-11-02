package prismsvc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/prismapi"
)

// initRoot builds a fake root holding the given files (relative paths).
func initRoot(t *testing.T, files ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, f := range files {
		p := filepath.Join(root, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("W1NCRAY_PRISM_RUNTIME_DIR", filepath.Join(root, "run", "prism"))
	t.Setenv("W1NCRAY_PRISM_STATE_DIR", filepath.Join(root, "var", "prism"))

	return root
}

func openrcRoot(t *testing.T) string {
	t.Helper()
	return initRoot(t, "sbin/openrc-run", "run/openrc/softlevel")
}

func (r *fakeRunner) reset() {
	r.mu.Lock()
	r.calls = nil
	r.mu.Unlock()
}

func (r *fakeRunner) seq() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.calls, "|")
}

func newOpenRC(t *testing.T, r *fakeRunner, path, version string, orphan func(context.Context, string) error) (*Manager, string) {
	t.Helper()
	root := openrcRoot(t)
	m, err := New(Options{
		Root: root, Kernels: fakeKernels{inst: driver.Installed{Path: path, Version: version}}, Runner: r,
		Status: healthy, HealthInterval: time.Millisecond, RecoverOrphan: orphan,
	})
	if err != nil {
		t.Fatal(err)
	}

	return m, root
}

func TestProcdWithoutASupervisorIsUnsupported(t *testing.T) {
	root := initRoot(t, "sbin/procd")
	m, err := New(Options{Root: root, Kernels: fakeKernels{inst: driver.Installed{Path: "/k/prism"}}})
	if err != nil {
		t.Fatal(err)
	}

	if err := m.Ensure(context.Background()); !errors.Is(err, ErrUnsupportedInit) {
		t.Fatalf("err = %v", err)
	}
	if m.Backend() != "" {
		t.Fatalf("backend = %q", m.Backend())
	}
}

func TestProcdWithASupervisorUsesTheAgentBackend(t *testing.T) {
	root := initRoot(t, "sbin/procd")
	m, err := New(Options{Root: root, Kernels: fakeKernels{inst: driver.Installed{Path: "/k/prism"}}, Sup: &fakeSup{}})
	if err != nil || m.Backend() != BackendAgent {
		t.Fatalf("backend = %q err = %v", m.Backend(), err)
	}
}

func TestOpenRCInstalledButNotRunningUsesTheAgentBackendOrIsUnsupported(t *testing.T) {
	root := initRoot(t, "sbin/openrc-run") // no run/openrc/softlevel
	m, err := New(Options{Root: root, Kernels: fakeKernels{inst: driver.Installed{Path: "/k/prism"}}, Sup: &fakeSup{}})
	if err != nil || m.Backend() != BackendAgent {
		t.Fatalf("with a supervisor: backend = %q err = %v", m.Backend(), err)
	}
	m, err = New(Options{Root: root, Kernels: fakeKernels{inst: driver.Installed{Path: "/k/prism"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Ensure(context.Background()); !errors.Is(err, ErrUnsupportedInit) {
		t.Fatalf("without a supervisor: err = %v", err)
	}
}

func TestSystemdWinsOverOpenRC(t *testing.T) {
	root := initRoot(t, "sbin/openrc-run", "run/openrc/softlevel", "run/systemd/system/.keep")
	m, err := New(Options{Root: root, Kernels: fakeKernels{}, Sup: &fakeSup{}})
	if err != nil || m.Backend() != BackendSystemd {
		t.Fatalf("backend = %q err = %v", m.Backend(), err)
	}
}

func TestRunningOpenRCIsTheOpenRCBackendEvenWithASupervisor(t *testing.T) {
	m, err := New(Options{Root: openrcRoot(t), Kernels: fakeKernels{}, Sup: &fakeSup{}})
	if err != nil || m.Backend() != BackendOpenRC {
		t.Fatalf("backend = %q err = %v", m.Backend(), err)
	}
}

func TestOpenRCEnsureWritesTheScriptEnablesAndStarts(t *testing.T) {
	r := &fakeRunner{}
	m, root := newOpenRC(t, r, "/opt/w1ncray/prism/W1nCray-prism", "0.1.0", nil)

	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}

	scriptPath := filepath.Join(root, "etc", "init.d", ServiceName)
	raw, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	for _, want := range []string{
		"#!/sbin/openrc-run",
		"supervisor=\"supervise-daemon\"",
		"command=\"/opt/w1ncray/prism/W1nCray-prism\"",
		"command_args=\"run --socket unix:" + SocketPath() + " --state " + KernelStateDir() + "\"",
		"respawn_delay=5",
		"respawn_max=0",
		"retry=\"TERM/10/KILL/5\"",
		"rc_ulimit=\"-n 1048576\"",
		"output_log=\"/var/log/W1nCray-prism.log\"",
		"error_log=\"/var/log/W1nCray-prism.log\"",
		"need localmount",
		"[ -x \"$command\" ]",
		"checkpath -d -m 0700 -o root:root " + filepath.Dir(SocketPath()),
		"checkpath -d -m 0700 -o root:root " + KernelStateDir(),
		"10485760",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "rc_need") || strings.Contains(strings.ToLower(script), "sing-box") {
		t.Fatalf("the script must not depend on the agent:\n%s", script)
	}
	if st, err := os.Stat(scriptPath); err != nil || (os.PathSeparator == '/' && st.Mode().Perm() != 0o755) {
		t.Fatalf("script stat: %v %v", st, err)
	}
	want := "rc-update add W1nCray-prism default|rc-service W1nCray-prism status|rc-service W1nCray-prism start"
	if got := r.seq(); got != want {
		t.Fatalf("calls = %q, want %q", got, want)
	}
	if st := m.Status(context.Background()); st.ManagedBy != ManagedByService || st.Backend != BackendOpenRC {
		t.Fatalf("status = %+v", st)
	}
}

func TestOpenRCHealthyUnchangedServiceIsLeftAlone(t *testing.T) {
	r := &fakeRunner{}
	m, _ := newOpenRC(t, r, "/k/prism", "0.1.0", nil)
	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.reset()

	for i := 0; i < 3; i++ {
		if err := m.Ensure(context.Background()); err != nil {
			t.Fatal(err)
		}
	}

	for _, c := range r.calls {
		if c != "rc-service W1nCray-prism status" {
			t.Fatalf("an idle Ensure ran %q (calls %v)", c, r.calls)
		}
	}
}

func TestOpenRCAnotherBinaryRestartsARunningService(t *testing.T) {
	r := &fakeRunner{}
	m, _ := newOpenRC(t, r, "/k/prism-0.1.0", "0.1.0", nil)
	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	m.o.Kernels = fakeKernels{inst: driver.Installed{Path: "/k/prism-0.2.0", Version: "0.2.0"}}
	r.reset()

	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}

	if !r.has("rc-service W1nCray-prism restart") || !r.has("rc-update add W1nCray-prism default") {
		t.Fatalf("calls = %v, want rc-update add and a restart", r.calls)
	}
	if r.has("rc-service W1nCray-prism start") {
		t.Fatalf("a running service must be restarted, not started: %v", r.calls)
	}
}

func TestOpenRCUnhealthyRunningServiceIsRestarted(t *testing.T) {
	r := &fakeRunner{rcUp: true}
	answers := true
	m, err := New(Options{
		Root: openrcRoot(t), Kernels: fakeKernels{inst: driver.Installed{Path: "/k/prism", Version: "0.1.0"}}, Runner: r,
		HealthInterval: time.Millisecond,
		Status: func(context.Context) (prismapi.Status, error) {
			if answers {
				return prismapi.Status{State: "running"}, nil
			}
			return prismapi.Status{}, errors.New("no socket")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Ensure(context.Background()); err != nil { // first pass: new script, restart
		t.Fatal(err)
	}
	r.reset()
	answers = false
	m.o.HealthTimeout = 20 * time.Millisecond

	err = m.Ensure(context.Background()) // unhealthy: restarts, then the wait fails

	if err == nil || !r.has("rc-service W1nCray-prism restart") {
		t.Fatalf("err = %v calls = %v", err, r.calls)
	}
}

func TestOpenRCBriefUnhealthinessIsLeftToTheSupervisor(t *testing.T) {
	r := &fakeRunner{rcUp: true}
	var calls int
	down := false
	m, err := New(Options{
		Root: openrcRoot(t), Kernels: fakeKernels{inst: driver.Installed{Path: "/k/prism", Version: "0.1.0"}}, Runner: r,
		HealthInterval: time.Millisecond, HealthTimeout: 200 * time.Millisecond,
		Status: func(context.Context) (prismapi.Status, error) {
			if !down {
				return prismapi.Status{State: "running", Version: "0.1.0"}, nil
			}
			calls++
			if calls < 3 { // the supervisor is respawning the kernel
				return prismapi.Status{}, errors.New("no socket")
			}
			return prismapi.Status{State: "running", Version: "0.1.0"}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.reset()
	down = true

	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}

	if r.has("rc-service W1nCray-prism restart") || r.has("rc-service W1nCray-prism start") {
		t.Fatalf("a kernel that comes back by itself must not be restarted: %v", r.calls)
	}
}

func TestOpenRCRcUpdateIsNotRepeatedEveryPass(t *testing.T) {
	r := &fakeRunner{}
	m, _ := newOpenRC(t, r, "/k/prism", "0.1.0", nil)
	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.reset()
	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.has("rc-update") {
		t.Fatalf("calls = %v", r.calls)
	}
}

func TestOpenRCRcUpdateFailureIsReportedAndRetried(t *testing.T) {
	r := &fakeRunner{fail: map[string]error{"rc-update add": errors.New("exit 1")}}
	m, _ := newOpenRC(t, r, "/k/prism", "0.1.0", nil)
	if err := m.Ensure(context.Background()); err == nil || !strings.Contains(err.Error(), "启用") {
		t.Fatalf("err = %v", err)
	}
	r.fail = nil
	r.reset()
	if err := m.Ensure(context.Background()); err != nil || !r.has("rc-update add") {
		t.Fatalf("retry: err = %v calls = %v", err, r.calls)
	}
}

func TestOpenRCOrphanIsRecoveredOnceBeforeTheFirstStart(t *testing.T) {
	r := &fakeRunner{}
	var order []string
	orphan := func(_ context.Context, id string) error {
		order = append(order, id+"@"+strconv.Itoa(len(r.calls)))
		return nil
	}
	m, _ := newOpenRC(t, r, "/k/prism", "0.1.0", orphan)

	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.rcUp = false
	if err := m.Ensure(context.Background()); err != nil { // a later start must not call it again
		t.Fatal(err)
	}

	// once, after rc-update add + status, before start
	if len(order) != 1 || order[0] != "prism@2" || r.calls[2] != "rc-service W1nCray-prism start" {
		t.Fatalf("order = %v calls = %v", order, r.calls)
	}
}

func TestOpenRCOrphanFailureIsRetriedNextPass(t *testing.T) {
	r := &fakeRunner{}
	n := 0
	m, _ := newOpenRC(t, r, "/k/prism", "0.1.0", func(context.Context, string) error {
		n++
		if n == 1 {
			return errors.New("boom")
		}
		return nil
	})
	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.rcUp = false
	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("orphan calls = %d", n)
	}
}

func TestOpenRCStopAndRemove(t *testing.T) {
	r := &fakeRunner{}
	m, root := newOpenRC(t, r, "/k/prism", "0.1.0", nil)
	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.reset()

	if err := m.Stop(context.Background()); err != nil || !r.has("rc-service W1nCray-prism stop") {
		t.Fatalf("stop: err = %v calls = %v", err, r.calls)
	}
	r.reset()
	if err := m.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := "rc-service W1nCray-prism stop|rc-update del W1nCray-prism default"
	if got := r.seq(); got != want {
		t.Fatalf("remove calls = %q, want %q", got, want)
	}
	if _, err := os.Stat(filepath.Join(root, "etc", "init.d", ServiceName)); !os.IsNotExist(err) {
		t.Fatalf("the script is still there: %v", err)
	}
	r.reset()
	if err := m.Remove(context.Background()); err != nil || len(r.calls) != 0 {
		t.Fatalf("second remove: err = %v calls = %v", err, r.calls)
	}
}

func TestOpenRCStatusReadsTheExitCode(t *testing.T) {
	r := &fakeRunner{}
	m, err := New(Options{
		Root: openrcRoot(t), Kernels: fakeKernels{inst: driver.Installed{Path: "/k/prism", Version: "0.1.0"}}, Runner: r,
		Status: func(context.Context) (prismapi.Status, error) { return prismapi.Status{}, errors.New("no socket") },
	})
	if err != nil {
		t.Fatal(err)
	}

	if st := m.Status(context.Background()); st.State != StateStopped || st.ManagedBy != ManagedByService {
		t.Fatalf("status = %+v", st)
	}
	r.rcUp = true
	if st := m.Status(context.Background()); st.State != StateRunning {
		t.Fatalf("status = %+v", st)
	}
}

func TestSystemdRemoveStopsDisablesAndDeletesTheUnit(t *testing.T) {
	root := systemdRoot(t)
	r := &fakeRunner{}
	m, _ := New(Options{Root: root, Kernels: fakeKernels{inst: driver.Installed{Path: "/k/prism"}}, Runner: r, Status: healthy})
	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.reset()

	if err := m.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}

	want := "systemctl stop W1nCray-prism|systemctl disable W1nCray-prism|systemctl daemon-reload"
	if got := r.seq(); got != want {
		t.Fatalf("calls = %q, want %q", got, want)
	}
	if _, err := os.Stat(filepath.Join(root, "etc", "systemd", "system", ServiceName+".service")); !os.IsNotExist(err) {
		t.Fatalf("the unit is still there: %v", err)
	}
	if st := m.Status(context.Background()); st.ManagedBy != ManagedByService {
		t.Fatalf("status = %+v", st)
	}
}

func TestAgentBackendRemoveStopsTheChild(t *testing.T) {
	root := initRoot(t)
	sup := &fakeSup{}
	m, err := New(Options{Root: root, Kernels: fakeKernels{inst: driver.Installed{Path: "/k/prism"}}, Sup: sup, Status: healthy})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Remove(context.Background()); err != nil || len(sup.stopped) != 1 {
		t.Fatalf("err = %v stopped = %v", err, sup.stopped)
	}
	if st := m.Status(context.Background()); st.ManagedBy != ManagedByAgent {
		t.Fatalf("status = %+v", st)
	}
}

// goldenSystemdUnit is the unit text of v0.12.0, byte for byte. A running
// kernel is restarted when its unit changes, which would cut the traffic it
// carries, so this text must not change by accident.
const goldenSystemdUnit = "[Unit]\n" +
	"Description=W1nCray Prism kernel\n" +
	"After=network-online.target nss-lookup.target\n" +
	"Wants=network-online.target\n" +
	"\n" +
	"[Service]\n" +
	"Type=simple\n" +
	"User=root\n" +
	"ExecStart=/opt/w1ncray/prism/W1nCray-prism run --socket unix:/run/W1nCray-prism/prism.sock --state /var/lib/W1nCray-prism\n" +
	"Restart=always\n" +
	"RestartSec=5\n" +
	"LimitNOFILE=1048576\n" +
	"RuntimeDirectory=W1nCray-prism\n" +
	"RuntimeDirectoryMode=0700\n" +
	"StateDirectory=W1nCray-prism\n" +
	"StateDirectoryMode=0700\n" +
	"\n" +
	"[Install]\n" +
	"WantedBy=multi-user.target\n"

func TestSystemdUnitIsByteForByteTheV0120Text(t *testing.T) {
	t.Setenv("W1NCRAY_PRISM_RUNTIME_DIR", "")
	t.Setenv("W1NCRAY_PRISM_STATE_DIR", "")
	// filepath.Join uses backslashes on a Windows dev machine; the unit text is
	// for Linux, so compare with forward slashes.
	got := strings.ReplaceAll(systemdUnit("/opt/w1ncray/prism/W1nCray-prism"), "\\", "/")
	if got != goldenSystemdUnit {
		t.Fatalf("the systemd unit changed:\n--- got\n%s\n--- want\n%s", got, goldenSystemdUnit)
	}
}

// A supervise-daemon that died leaves the kernel running and still holding the
// control socket, and OpenRC reports "unsupervised" — not "crashed". Reading
// that as stopped made the agent start a second kernel that could not bind
// (handoff 98, verified on a real Alpine boot).
func TestOpenRCUnsupervisedIsAFailureNotAStop(t *testing.T) {
	r := &fakeRunner{rcStatus: " * status: unsupervised"}
	m, _ := newOpenRC(t, r, "/opt/w1ncray/prism/W1nCray-prism", "0.1.0", nil)

	if got := m.openrcState(context.Background()); got != StateFailed {
		t.Fatalf("openrcState(unsupervised) = %q, want %q", got, StateFailed)
	}
}

func TestOpenRCUnsupervisedIsRestartedRatherThanStarted(t *testing.T) {
	r := &fakeRunner{rcStatus: " * status: unsupervised"}
	m, _ := newOpenRC(t, r, "/opt/w1ncray/prism/W1nCray-prism", "0.1.0", nil)
	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Put the service back into the unsupervised state and run another pass.
	r.mu.Lock()
	r.calls = nil
	r.rcUp = false
	r.rcStatus = " * status: unsupervised"
	r.mu.Unlock()
	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}

	r.mu.Lock()
	calls := append([]string(nil), r.calls...)
	r.mu.Unlock()
	restarted, started := false, false
	for _, c := range calls {
		if c == "rc-service "+ServiceName+" restart" {
			restarted = true
		}
		if c == "rc-service "+ServiceName+" start" {
			started = true
		}
	}
	if !restarted {
		t.Fatalf("calls = %v, want a restart", calls)
	}
	if started {
		t.Fatalf("calls = %v, a plain start would collide with the kernel still holding the socket", calls)
	}
}
