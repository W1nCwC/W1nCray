package prismsvc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/prismapi"
)

type fakeKernels struct {
	inst driver.Installed
	err  error
}

func (k fakeKernels) Current(string) (driver.Installed, error) { return k.inst, k.err }

type fakeRunner struct {
	mu     sync.Mutex
	calls  []string
	active string // what "systemctl is-active" answers
	rcUp   bool   // what "rc-service <svc> status" answers (exit 0)
	fail   map[string]error
}

func (r *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	line := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, line)
	for k, err := range r.fail {
		if strings.Contains(line, k) {
			return []byte("boom"), err
		}
	}
	if name == "rc-service" && len(args) == 2 {
		switch args[1] {
		case "status":
			if r.rcUp {
				return nil, nil
			}
			return []byte(" * status: stopped"), errors.New("exit status 3")
		case "start", "restart":
			r.rcUp = true
		case "stop":
			r.rcUp = false
		}
		return nil, nil
	}
	if len(args) > 0 && args[0] == "is-active" {
		return []byte(r.active), nil
	}
	if len(args) > 0 && args[0] == "start" {
		r.active = "active"
	}
	return nil, nil
}

func (r *fakeRunner) has(prefix string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

type fakeSup struct {
	started []driver.ProcSpec
	stopped []string
	running bool
}

func (s *fakeSup) Start(_ context.Context, p driver.ProcSpec) error {
	s.started = append(s.started, p)
	s.running = true
	return nil
}

func (s *fakeSup) Stop(_ context.Context, id string) error {
	s.stopped = append(s.stopped, id)
	s.running = false
	return nil
}

func (s *fakeSup) Status(string) driver.ProcStatus { return driver.ProcStatus{Running: s.running} }

func systemdRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "run", "systemd", "system"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("W1NCRAY_PRISM_RUNTIME_DIR", filepath.Join(root, "run", "prism"))
	t.Setenv("W1NCRAY_PRISM_STATE_DIR", filepath.Join(root, "var", "prism"))

	return root
}

func healthy(context.Context) (prismapi.Status, error) {
	return prismapi.Status{API: 1, State: "running"}, nil
}

func TestEnsureWritesTheUnitStartsTheServiceAndWaitsForTheApi(t *testing.T) {
	root := systemdRoot(t)
	r := &fakeRunner{}
	m, err := New(Options{Root: root, Kernels: fakeKernels{inst: driver.Installed{Path: "/opt/w1ncray/prism/W1nCray-prism", Version: "0.1.0"}}, Runner: r, Status: healthy, HealthInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}

	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}

	unit, err := os.ReadFile(filepath.Join(root, "etc", "systemd", "system", ServiceName+".service"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ExecStart=/opt/w1ncray/prism/W1nCray-prism run --socket unix:",
		"RuntimeDirectory=W1nCray-prism",
		"StateDirectory=W1nCray-prism",
		"Restart=always",
	} {
		if !strings.Contains(string(unit), want) {
			t.Fatalf("the unit lacks %q:\n%s", want, unit)
		}
	}
	if strings.Contains(string(unit), "RuntimeDirectory=W1nCray\n") {
		t.Fatal("the unit shares the Xray kernel's runtime directory")
	}
	for _, want := range []string{"systemctl daemon-reload", "systemctl enable W1nCray-prism", "systemctl start W1nCray-prism"} {
		if !r.has(want) {
			t.Fatalf("missing call %q in %v", want, r.calls)
		}
	}
	if r.has("systemctl restart") {
		t.Fatal("a fresh install must start, not restart")
	}
}

func TestAHealthyServiceWithAnUnchangedUnitIsLeftAlone(t *testing.T) {
	root := systemdRoot(t)
	r := &fakeRunner{active: "active"}
	m, _ := New(Options{Root: root, Kernels: fakeKernels{inst: driver.Installed{Path: "/k/prism", Version: "0.1.0"}}, Runner: r, Status: healthy})
	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.calls = nil
	r.mu.Unlock()

	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}

	if r.has("systemctl start") || r.has("systemctl restart") || r.has("systemctl daemon-reload") {
		t.Fatalf("an idle Ensure touched the service: %v", r.calls)
	}
}

func TestAnotherBinaryRestartsAnActiveService(t *testing.T) {
	root := systemdRoot(t)
	r := &fakeRunner{active: "active"}
	m, _ := New(Options{Root: root, Kernels: fakeKernels{inst: driver.Installed{Path: "/k/prism-0.1.0", Version: "0.1.0"}}, Runner: r, Status: healthy})
	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	m.o.Kernels = fakeKernels{inst: driver.Installed{Path: "/k/prism-0.2.0", Version: "0.2.0"}}
	r.mu.Lock()
	r.calls = nil
	r.mu.Unlock()

	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}

	if !r.has("systemctl restart W1nCray-prism") {
		t.Fatalf("calls = %v, want a restart", r.calls)
	}
}

func TestNotInstalledIsReported(t *testing.T) {
	root := systemdRoot(t)
	m, _ := New(Options{Root: root, Kernels: fakeKernels{err: errors.New("none")}, Runner: &fakeRunner{}})

	if err := m.Ensure(context.Background()); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("err = %v", err)
	}
	if st := m.Status(context.Background()); st.State != StateNotInstalled {
		t.Fatalf("state = %s", st.State)
	}
}

func TestAStartThatNeverAnswersIsAnError(t *testing.T) {
	root := systemdRoot(t)
	m, _ := New(Options{
		Root: root, Kernels: fakeKernels{inst: driver.Installed{Path: "/k/prism"}}, Runner: &fakeRunner{},
		Status:        func(context.Context) (prismapi.Status, error) { return prismapi.Status{}, errors.New("no socket") },
		HealthTimeout: 30 * time.Millisecond, HealthInterval: 5 * time.Millisecond,
	})

	err := m.Ensure(context.Background())

	if err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Fatalf("err = %v", err)
	}
}

func TestASystemctlFailureIsReported(t *testing.T) {
	root := systemdRoot(t)
	r := &fakeRunner{fail: map[string]error{"systemctl enable": errors.New("exit 1")}}
	m, _ := New(Options{Root: root, Kernels: fakeKernels{inst: driver.Installed{Path: "/k/prism"}}, Runner: r, Status: healthy})

	if err := m.Ensure(context.Background()); err == nil || !strings.Contains(err.Error(), "启用") {
		t.Fatalf("err = %v", err)
	}
}

func TestWithoutSystemdTheAgentSupervisorRunsTheKernel(t *testing.T) {
	root := t.TempDir()
	t.Setenv("W1NCRAY_PRISM_RUNTIME_DIR", filepath.Join(root, "run"))
	t.Setenv("W1NCRAY_PRISM_STATE_DIR", filepath.Join(root, "state"))
	sup := &fakeSup{}
	m, err := New(Options{Root: root, Kernels: fakeKernels{inst: driver.Installed{Path: "/k/prism"}}, Sup: sup, StateDir: root, Status: healthy})
	if err != nil {
		t.Fatal(err)
	}
	if m.Backend() != BackendAgent {
		t.Fatalf("backend = %s", m.Backend())
	}

	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}

	if len(sup.started) != 1 || sup.started[0].Path != "/k/prism" || sup.started[0].Args[0] != "run" || !sup.started[0].Restart.Always {
		t.Fatalf("started = %+v", sup.started)
	}
	if err := m.Stop(context.Background()); err != nil || len(sup.stopped) != 1 {
		t.Fatalf("stop: err=%v stopped=%v", err, sup.stopped)
	}
}

func TestRunningOpenRCWithoutASupervisorIsTheOpenRCBackend(t *testing.T) {
	root := openrcRoot(t)
	m, err := New(Options{Root: root, Kernels: fakeKernels{inst: driver.Installed{Path: "/k/prism"}}})
	if err != nil {
		t.Fatal(err)
	}

	if m.Backend() != BackendOpenRC {
		t.Fatalf("backend = %q", m.Backend())
	}
}

func TestStatusPrefersTheKernelsOwnAnswer(t *testing.T) {
	root := systemdRoot(t)
	m, _ := New(Options{Root: root, Kernels: fakeKernels{inst: driver.Installed{Path: "/k/prism", Version: "0.1.0"}}, Runner: &fakeRunner{},
		Status: func(context.Context) (prismapi.Status, error) {
			return prismapi.Status{State: "failed", LastError: "bad config"}, nil
		}})

	st := m.Status(context.Background())

	if st.State != StateFailed || st.Error != "bad config" || st.Version != "0.1.0" {
		t.Fatalf("status = %+v", st)
	}
}
