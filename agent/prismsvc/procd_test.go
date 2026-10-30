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

const procdBin = "/opt/w1ncray/kernels/prism/0.3.1/W1nCray-prism"

func procdRoot(t *testing.T) string {
	t.Helper()
	return initRoot(t, "sbin/procd", "etc/rc.common")
}

func newProcd(t *testing.T, r *fakeRunner, path, version string, orphan func(context.Context, string) error) (*Manager, string) {
	t.Helper()
	root := procdRoot(t)
	m, err := New(Options{
		Root: root, Kernels: fakeKernels{inst: driver.Installed{Path: path, Version: version}}, Runner: r,
		Status: healthy, HealthInterval: time.Millisecond, RecoverOrphan: orphan,
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.Backend() != BackendProcd {
		t.Fatalf("backend = %q", m.Backend())
	}

	return m, root
}

func procdScriptIn(root string) string {
	return filepath.Join(root, "etc", "init.d", ServiceName)
}

func TestProcdWithRcCommonIsTheProcdBackend(t *testing.T) {
	// a supervisor being available does not matter: the service survives the agent
	m, err := New(Options{Root: procdRoot(t), Kernels: fakeKernels{}, Sup: &fakeSup{}})
	if err != nil || m.Backend() != BackendProcd {
		t.Fatalf("backend = %q err = %v", m.Backend(), err)
	}
	m, err = New(Options{Root: procdRoot(t), Kernels: fakeKernels{}})
	if err != nil || m.Backend() != BackendProcd {
		t.Fatalf("without a supervisor: backend = %q err = %v", m.Backend(), err)
	}
}

func TestProcdWithoutRcCommonKeepsTheOldBehaviour(t *testing.T) {
	root := initRoot(t, "sbin/procd")
	m, err := New(Options{Root: root, Kernels: fakeKernels{}, Sup: &fakeSup{}})
	if err != nil || m.Backend() != BackendAgent {
		t.Fatalf("backend = %q err = %v", m.Backend(), err)
	}
	m, err = New(Options{Root: root, Kernels: fakeKernels{inst: driver.Installed{Path: "/k/prism"}}})
	if err != nil || m.Backend() != "" {
		t.Fatalf("backend = %q err = %v", m.Backend(), err)
	}
	if err := m.Ensure(context.Background()); !errors.Is(err, ErrUnsupportedInit) {
		t.Fatalf("err = %v", err)
	}
}

func TestSystemdAndRunningOpenRCWinOverProcd(t *testing.T) {
	root := initRoot(t, "sbin/procd", "etc/rc.common", "run/systemd/system/.keep")
	m, _ := New(Options{Root: root, Kernels: fakeKernels{}, Sup: &fakeSup{}})
	if m.Backend() != BackendSystemd {
		t.Fatalf("backend = %q", m.Backend())
	}
	root = initRoot(t, "sbin/procd", "etc/rc.common", "sbin/openrc-run", "run/openrc/softlevel")
	m, _ = New(Options{Root: root, Kernels: fakeKernels{}, Sup: &fakeSup{}})
	if m.Backend() != BackendOpenRC {
		t.Fatalf("backend = %q", m.Backend())
	}
}

func TestProcdScriptText(t *testing.T) {
	t.Setenv("W1NCRAY_PRISM_RUNTIME_DIR", "/run/W1nCray-prism")
	t.Setenv("W1NCRAY_PRISM_STATE_DIR", "/var/lib/W1nCray-prism")
	got := strings.ReplaceAll(procdScript("/opt/w1ncray/prism/W1nCray-prism"), "\\", "/")
	for _, want := range []string{
		"#!/bin/sh /etc/rc.common\n",
		"USE_PROCD=1\n",
		"START=95\n",
		"STOP=10\n",
		"start_service() {\n",
		"[ -x \"/opt/w1ncray/prism/W1nCray-prism\" ]",
		"mkdir -p \"/run/W1nCray-prism\" \"/var/lib/W1nCray-prism\"\n",
		"chmod 0700 \"/run/W1nCray-prism\" \"/var/lib/W1nCray-prism\"\n",
		"procd_open_instance\n",
		"procd_set_param command \"/opt/w1ncray/prism/W1nCray-prism\" run --socket unix:/run/W1nCray-prism/prism.sock --state /var/lib/W1nCray-prism\n",
		"procd_set_param respawn 3600 5 0\n",
		"procd_set_param limits nofile=1048576\n",
		"procd_set_param stdout 1\n",
		"procd_set_param stderr 1\n",
		"procd_close_instance\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("script lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "service_triggers") || strings.Contains(strings.ToLower(got), "sing-box") {
		t.Fatalf("unexpected content:\n%s", got)
	}
	// the argument vector is the one of the systemd and OpenRC backends
	args := "run --socket unix:" + SocketPath() + " --state " + KernelStateDir()
	if !strings.Contains(systemdUnit("/b"), "ExecStart=/b "+args) || !strings.Contains(procdScript("/b"), "\"/b\" "+args) {
		t.Fatal("the procd command line differs from the systemd one")
	}
}

func TestProcdEnsureWritesTheScriptEnablesAndStarts(t *testing.T) {
	r := &fakeRunner{}
	m, root := newProcd(t, r, procdBin, "0.3.1", nil)

	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}

	script := procdScriptIn(root)
	st, err := os.Stat(script)
	if err != nil || (os.PathSeparator == '/' && st.Mode().Perm() != 0o755) {
		t.Fatalf("script stat: %v %v", st, err)
	}
	raw, _ := os.ReadFile(script)
	if string(raw) != procdScript(procdBin) {
		t.Fatalf("script = %q", raw)
	}
	want := script + " enable|" + script + " running|" + script + " start"
	if got := r.seq(); got != want {
		t.Fatalf("calls = %q, want %q", got, want)
	}
	if st := m.Status(context.Background()); st.ManagedBy != ManagedByService || st.Backend != BackendProcd || st.State != StateRunning {
		t.Fatalf("status = %+v", st)
	}
}

func TestProcdSysupgradeConfIsMaintained(t *testing.T) {
	r := &fakeRunner{}
	base := filepath.Join(t.TempDir(), "w1ncray")
	bin := filepath.Join(base, "kernels", "prism", "0.3.1", "W1nCray-prism")
	m, root := newProcd(t, r, bin, "0.3.1", nil)
	conf := filepath.Join(root, "etc", "sysupgrade.conf")
	if err := os.MkdirAll(filepath.Dir(conf), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(conf, []byte("/etc/other\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := m.Ensure(context.Background()); err != nil { // never duplicated
		t.Fatal(err)
	}

	raw, _ := os.ReadFile(conf)
	want := "/etc/other\n" + procdScriptIn(root) + "\n" + base + "\n"
	if string(raw) != want {
		t.Fatalf("sysupgrade.conf = %q, want %q", raw, want)
	}

	// Remove drops the script line only
	if err := m.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(conf)
	want = "/etc/other\n" + base + "\n"
	if string(raw) != want {
		t.Fatalf("after remove: %q, want %q", raw, want)
	}
}

func TestProcdKernelPathOutsideTheKernelsLayoutAddsNoDirectory(t *testing.T) {
	r := &fakeRunner{}
	m, root := newProcd(t, r, "/k/prism", "0.3.1", nil)
	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(root, "etc", "sysupgrade.conf"))
	if string(raw) != procdScriptIn(root)+"\n" {
		t.Fatalf("sysupgrade.conf = %q", raw)
	}
}

func TestProcdHealthyUnchangedServiceIsLeftAlone(t *testing.T) {
	r := &fakeRunner{}
	m, root := newProcd(t, r, procdBin, "0.3.1", nil)
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
		if c != procdScriptIn(root)+" running" {
			t.Fatalf("an idle Ensure ran %q (calls %v)", c, r.calls)
		}
	}
}

func TestProcdAnotherBinaryRestartsARunningService(t *testing.T) {
	r := &fakeRunner{}
	m, root := newProcd(t, r, "/k/prism-0.1.0", "0.1.0", nil)
	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	m.o.Kernels = fakeKernels{inst: driver.Installed{Path: "/k/prism-0.2.0", Version: "0.2.0"}}
	r.reset()

	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}

	script := procdScriptIn(root)
	if !r.has(script+" restart") || !r.has(script+" enable") || r.has(script+" start") {
		t.Fatalf("calls = %v, want enable and a restart (not a start)", r.calls)
	}
}

func TestProcdUnhealthyRunningServiceIsRestartedAfterTheWindow(t *testing.T) {
	r := &fakeRunner{rcUp: true}
	answers := true
	m, err := New(Options{
		Root: procdRoot(t), Kernels: fakeKernels{inst: driver.Installed{Path: "/k/prism", Version: "0.1.0"}}, Runner: r,
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
	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.reset()
	answers = false
	m.o.HealthTimeout = 20 * time.Millisecond

	err = m.Ensure(context.Background())

	if err == nil || !r.has(procdScriptIn(m.o.Root)+" restart") {
		t.Fatalf("err = %v calls = %v", err, r.calls)
	}
}

func TestProcdBriefUnhealthinessIsLeftToTheSupervisor(t *testing.T) {
	r := &fakeRunner{rcUp: true}
	var calls int
	down := false
	m, err := New(Options{
		Root: procdRoot(t), Kernels: fakeKernels{inst: driver.Installed{Path: "/k/prism", Version: "0.1.0"}}, Runner: r,
		HealthInterval: time.Millisecond, HealthTimeout: 200 * time.Millisecond,
		Status: func(context.Context) (prismapi.Status, error) {
			if !down {
				return prismapi.Status{State: "running", Version: "0.1.0"}, nil
			}
			calls++
			if calls < 3 { // procd is respawning the kernel
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

	script := procdScriptIn(m.o.Root)
	if r.has(script+" restart") || r.has(script+" start") {
		t.Fatalf("a kernel that comes back by itself must not be restarted: %v", r.calls)
	}
}

func TestProcdEnableIsNotRepeatedButRetriedAfterAFailure(t *testing.T) {
	r := &fakeRunner{}
	m, root := newProcd(t, r, "/k/prism", "0.1.0", nil)
	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.reset()
	if err := m.Ensure(context.Background()); err != nil || r.has(procdScriptIn(root)+" enable") {
		t.Fatalf("err = %v calls = %v", err, r.calls)
	}

	r2 := &fakeRunner{fail: map[string]error{" enable": errors.New("exit 1")}}
	m2, root2 := newProcd(t, r2, "/k/prism", "0.1.0", nil)
	if err := m2.Ensure(context.Background()); err == nil || !strings.Contains(err.Error(), "启用") {
		t.Fatalf("err = %v", err)
	}
	r2.fail = nil
	r2.reset()
	if err := m2.Ensure(context.Background()); err != nil || !r2.has(procdScriptIn(root2)+" enable") {
		t.Fatalf("retry: err = %v calls = %v", err, r2.calls)
	}
}

func TestProcdOrphanIsRecoveredOnceBeforeTheFirstStart(t *testing.T) {
	r := &fakeRunner{}
	var order []string
	orphan := func(_ context.Context, id string) error {
		order = append(order, id+"@"+strconv.Itoa(len(r.calls)))
		return nil
	}
	m, root := newProcd(t, r, "/k/prism", "0.1.0", orphan)

	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.rcUp = false
	if err := m.Ensure(context.Background()); err != nil { // a later start must not call it again
		t.Fatal(err)
	}

	// once, after enable + running, before start
	if len(order) != 1 || order[0] != "prism@2" || r.calls[2] != procdScriptIn(root)+" start" {
		t.Fatalf("order = %v calls = %v", order, r.calls)
	}
}

func TestProcdStopAndRemove(t *testing.T) {
	r := &fakeRunner{}
	m, root := newProcd(t, r, procdBin, "0.3.1", nil)
	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	script := procdScriptIn(root)
	r.reset()

	if err := m.Stop(context.Background()); err != nil || !r.has(script+" stop") {
		t.Fatalf("stop: err = %v calls = %v", err, r.calls)
	}
	r.reset()
	if err := m.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, want := r.seq(), script+" stop|"+script+" disable"; got != want {
		t.Fatalf("remove calls = %q, want %q", got, want)
	}
	if _, err := os.Stat(script); !os.IsNotExist(err) {
		t.Fatalf("the script is still there: %v", err)
	}
	raw, _ := os.ReadFile(filepath.Join(root, "etc", "sysupgrade.conf"))
	if strings.Contains(string(raw), script) {
		t.Fatalf("sysupgrade.conf still lists the script: %q", raw)
	}
	r.reset()
	if err := m.Remove(context.Background()); err != nil || len(r.calls) != 0 {
		t.Fatalf("second remove: err = %v calls = %v", err, r.calls)
	}
	if err := m.Stop(context.Background()); err != nil || len(r.calls) != 0 {
		t.Fatalf("stop without a script: err = %v calls = %v", err, r.calls)
	}
}

func TestProcdRemoveGoesOnWhenDisableFails(t *testing.T) {
	r := &fakeRunner{}
	m, root := newProcd(t, r, procdBin, "0.3.1", nil)
	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.fail = map[string]error{" disable": errors.New("exit 1")}

	if err := m.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(procdScriptIn(root)); !os.IsNotExist(err) {
		t.Fatalf("the script is still there: %v", err)
	}
}

func TestProcdStatusReadsTheRunningCommand(t *testing.T) {
	r := &fakeRunner{}
	m, err := New(Options{
		Root: procdRoot(t), Kernels: fakeKernels{inst: driver.Installed{Path: "/k/prism", Version: "0.1.0"}}, Runner: r,
		Status: func(context.Context) (prismapi.Status, error) { return prismapi.Status{}, errors.New("no socket") },
	})
	if err != nil {
		t.Fatal(err)
	}

	if st := m.Status(context.Background()); st.State != StateStopped || st.ManagedBy != ManagedByService || st.Backend != BackendProcd {
		t.Fatalf("status = %+v", st)
	}
	r.rcUp = true
	if st := m.Status(context.Background()); st.State != StateRunning {
		t.Fatalf("status = %+v", st)
	}
}

// A kernel base that moves (a changed StateDir or KernelsDir) must not stay
// listed: sysupgrade would then back up both trees, and the bigger backup is
// what overflowed a small /boot (handoff 89). The user's own lines are kept.
func TestProcdMovedKernelBaseIsRemovedFromSysupgradeConf(t *testing.T) {
	r := &fakeRunner{}
	root := procdRoot(t)
	conf := filepath.Join(root, "etc", "sysupgrade.conf")
	if err := os.MkdirAll(filepath.Dir(conf), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(conf, []byte("/etc/user-line\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ensure := func(bin string) {
		m, err := New(Options{
			Root: root, Kernels: fakeKernels{inst: driver.Installed{Path: bin, Version: "0.3.1"}},
			Runner: r, Status: healthy, HealthInterval: time.Millisecond,
		})
		if err != nil {
			t.Fatal(err)
		}
		if m.Backend() != BackendProcd {
			t.Fatalf("backend = %q", m.Backend())
		}
		if err := m.Ensure(context.Background()); err != nil {
			t.Fatal(err)
		}
	}

	oldBase := filepath.Join(root, "old", "state", "kernels")
	newBase := filepath.Join(root, "new", "state", "kernels")
	ensure(filepath.Join(oldBase, "kernels", "prism", "0.3.1", "W1nCray-prism"))
	ensure(filepath.Join(newBase, "kernels", "prism", "0.3.1", "W1nCray-prism"))

	raw, err := os.ReadFile(conf)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	if strings.Contains(got, oldBase) {
		t.Fatalf("sysupgrade.conf still lists the old kernel base: %q", got)
	}
	if !strings.Contains(got, newBase) {
		t.Fatalf("sysupgrade.conf does not list the new kernel base: %q", got)
	}
	if !strings.Contains(got, "/etc/user-line") {
		t.Fatalf("sysupgrade.conf lost the user's line: %q", got)
	}
}
