package xraysvc

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
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/agent/xrayapi"
	"github.com/W1nCwC/W1nCray/kernel/install"
)

// ---- fixtures --------------------------------------------------------------

// fakeKernels is the kernel manager surface with a scripted current version.
type fakeKernels struct {
	mu       sync.Mutex
	current  driver.Installed
	curErr   error
	ensureFn func(pin spec.KernelPin) (driver.Installed, error)
	rollback driver.Installed
	rbErr    error
	onRback  func()
	ensured  []spec.KernelPin
	removed  []string
}

func (f *fakeKernels) Ensure(_ context.Context, pin spec.KernelPin) (driver.Installed, error) {
	f.mu.Lock()
	f.ensured = append(f.ensured, pin)
	fn := f.ensureFn
	f.mu.Unlock()
	var (
		inst driver.Installed
		err  error
	)
	if fn != nil {
		inst, err = fn(pin)
	} else {
		inst, err = f.Current("")
	}
	if err == nil {
		f.mu.Lock()
		f.current, f.curErr = inst, nil
		f.mu.Unlock()
	}
	return inst, err
}

func (f *fakeKernels) Current(string) (driver.Installed, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.curErr != nil {
		return driver.Installed{}, f.curErr
	}
	return f.current, nil
}

func (f *fakeKernels) Rollback(string) (driver.Installed, error) {
	f.mu.Lock()
	fn := f.onRback
	if f.rbErr != nil {
		err := f.rbErr
		f.mu.Unlock()
		return driver.Installed{}, err
	}
	f.current = f.rollback
	inst := f.rollback
	f.mu.Unlock()
	if fn != nil {
		fn()
	}
	return inst, nil
}

func (f *fakeKernels) Remove(name, version string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, name+"@"+version)
	f.current = driver.Installed{}
	f.curErr = errors.New("not installed")
	return nil
}

func (f *fakeKernels) List() ([]install.Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.curErr != nil || f.current.Version == "" {
		return nil, nil
	}
	return []install.Entry{{
		Name: "xray", Version: f.current.Version, Current: true, Path: f.current.Path,
	}}, nil
}

// fakeStatus is the kernel status endpoint.
type fakeStatus struct {
	mu      sync.Mutex
	running bool
	err     error
}

func (f *fakeStatus) Status(context.Context) (xrayapi.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return xrayapi.Status{}, f.err
	}
	return xrayapi.Status{Running: f.running}, nil
}

func (f *fakeStatus) CheckStaged(context.Context, string, []string) (xrayapi.StagedResult, error) {
	return xrayapi.StagedResult{OK: true}, nil
}

func (f *fakeStatus) WaitReloaded(context.Context, string) error { return nil }

func (f *fakeStatus) setRunning(v bool) {
	f.mu.Lock()
	f.running = v
	f.mu.Unlock()
}

// fakeRunner records service-manager commands and simulates systemd's state.
type fakeRunner struct {
	mu      sync.Mutex
	calls   []string
	active  bool
	order   *[]string
	respond func(name string, args []string) ([]byte, error)
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if f.order != nil {
		*f.order = append(*f.order, name+" "+strings.Join(args, " "))
	}
	respond := f.respond
	if respond == nil && name == "systemctl" && len(args) > 0 {
		switch args[0] {
		case "is-active":
			if f.active {
				f.mu.Unlock()
				return []byte("active\n"), nil
			}
			f.mu.Unlock()
			return []byte("inactive\n"), errors.New("exit status 3")
		case "start", "restart":
			f.active = true
		case "stop":
			f.active = false
		}
	}
	f.mu.Unlock()
	if respond != nil {
		return respond(name, args)
	}
	return nil, nil
}

func (f *fakeRunner) seq() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// fakeLabeler records the SELinux labelling calls the manager makes.
type fakeLabeler struct {
	mu    sync.Mutex
	calls int
	err   error
	order *[]string
}

func (f *fakeLabeler) LabelKernels(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.order != nil {
		*f.order = append(*f.order, "label")
	}
	return f.err
}

func (f *fakeLabeler) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// fakeSup is the agent supervisor for the fallback backend.
type fakeSup struct {
	mu       sync.Mutex
	specs    []driver.ProcSpec
	running  bool
	lastExit string
}

func (f *fakeSup) Start(_ context.Context, p driver.ProcSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.specs = append(f.specs, p)
	f.running = true
	return nil
}

func (f *fakeSup) Stop(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.running = false
	return nil
}

func (f *fakeSup) Status(string) driver.ProcStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return driver.ProcStatus{Running: f.running, LastExit: f.lastExit}
}

// tmpRoot creates a temporary filesystem root with the given markers (a path
// ending in "/" is a directory, otherwise a file).
func tmpRoot(t *testing.T, markers ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, m := range markers {
		p := filepath.Join(root, filepath.FromSlash(strings.TrimSuffix(m, "/")))
		if strings.HasSuffix(m, "/") {
			if err := os.MkdirAll(p, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// installedKernel creates a fake kernel binary under root and returns its path.
func installedKernel(t *testing.T, root, version string) string {
	t.Helper()
	bin := filepath.Join(root, "kernels", "xray", version, "W1nCray-xray")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

type fixture struct {
	root    string
	kern    *fakeKernels
	status  *fakeStatus
	run     *fakeRunner
	sup     *fakeSup
	label   *fakeLabeler
	order   *[]string
	config  string
	manager *Manager
}

func newFixture(t *testing.T, markers ...string) *fixture {
	t.Helper()
	root := tmpRoot(t, markers...)
	config := filepath.Join(root, "config.yml")
	if err := os.WriteFile(config, []byte("Log: {Level: warning}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	order := &[]string{}
	f := &fixture{
		root:   root,
		kern:   &fakeKernels{curErr: errors.New("not installed")},
		status: &fakeStatus{running: true},
		run:    &fakeRunner{order: order},
		sup:    &fakeSup{},
		label:  &fakeLabeler{order: order},
		order:  order,
		config: config,
	}
	m, err := New(Options{
		Root:           root,
		Kernels:        f.kern,
		ConfigPath:     config,
		StateDir:       filepath.Join(root, "state"),
		Status:         f.status,
		Sup:            f.sup,
		Labeler:        f.label,
		Runner:         f.run,
		HealthTimeout:  100 * time.Millisecond,
		HealthInterval: time.Millisecond,
		StatusTimeout:  50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.manager = m
	return f
}

// installFake makes the kernel manager report version as installed.
func (f *fixture) installFake(t *testing.T, version string) string {
	t.Helper()
	bin := installedKernel(t, f.root, version)
	f.kern.mu.Lock()
	f.kern.current = driver.Installed{Path: bin, Version: version}
	f.kern.curErr = nil
	f.kern.mu.Unlock()
	return bin
}

// ---- tests -----------------------------------------------------------------

func TestBackendDetection(t *testing.T) {
	for _, c := range []struct {
		name    string
		markers []string
		want    string
	}{
		{"systemd", []string{"run/systemd/system/"}, BackendSystemd},
		{"openrc", []string{"sbin/openrc-run"}, BackendOpenRC},
		{"procd", []string{"sbin/procd", "etc/rc.common"}, BackendProcd},
		{"agent fallback", nil, BackendAgent},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, c.markers...)
			if got := f.manager.Backend(); got != c.want {
				t.Fatalf("backend = %q, want %q", got, c.want)
			}
		})
	}

	// Without an init system and without a supervisor there is no backend.
	root := tmpRoot(t)
	if _, err := New(Options{
		Root: root, Kernels: &fakeKernels{}, ConfigPath: filepath.Join(root, "config.yml"),
		Runner: &fakeRunner{},
	}); err == nil {
		t.Fatal("a machine with no backend and no supervisor must be refused")
	}
}

func TestSystemdInstall(t *testing.T) {
	f := newFixture(t, "run/systemd/system/")
	bin := installedKernel(t, f.root, "1.0.0")
	f.kern.ensureFn = func(spec.KernelPin) (driver.Installed, error) {
		return driver.Installed{Path: bin, Version: "1.0.0"}, nil
	}
	if err := f.manager.Install(context.Background(), "1.0.0"); err != nil {
		t.Fatalf("Install: %v", err)
	}

	unitPath := filepath.Join(f.root, "etc", "systemd", "system", "W1nCray-xray.service")
	raw, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatalf("unit file: %v", err)
	}
	unit := string(raw)
	for _, want := range []string{
		"Description=W1nCray Xray kernel",
		"After=network-online.target",
		"ExecStart=" + bin + " run -c " + f.config,
		"Restart=always",
		"RestartSec=5",
		"LimitNOFILE=1048576",
		"WorkingDirectory=" + filepath.Dir(f.config),
		// The status socket lives in the runtime directory, not in /etc.
		"RuntimeDirectory=W1nCray",
		"RuntimeDirectoryMode=0755",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit lacks %q:\n%s", want, unit)
		}
	}

	want := []string{
		"systemctl daemon-reload",
		"systemctl enable " + ServiceName,
		"systemctl start " + ServiceName,
	}
	if got := f.run.seq(); !equalStrings(got, want) {
		t.Fatalf("commands = %v, want %v", got, want)
	}

	st, err := f.manager.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.State != StateRunning || st.Version != "1.0.0" || st.Backend != BackendSystemd || st.ManagedBy != "service" {
		t.Fatalf("status = %+v", st)
	}

	// A repeated install with the same unit must not restart the service.
	f.run.mu.Lock()
	f.run.calls = nil
	f.run.mu.Unlock()
	if err := f.manager.Install(context.Background(), "1.0.0"); err != nil {
		t.Fatalf("second Install: %v", err)
	}
	if got := f.run.seq(); contains(got, "systemctl restart "+ServiceName) {
		t.Fatalf("a repeated install restarted the service: %v", got)
	}
}

// TestInstallLabelsTheKernelBeforeStartingIt is the SELinux requirement: the
// kernel tree carries bin_t before the service starts, otherwise the process
// runs in init_t and cannot bind its status socket (agent/selinux).
func TestInstallLabelsTheKernelBeforeStartingIt(t *testing.T) {
	f := newFixture(t, "run/systemd/system/")
	bin := installedKernel(t, f.root, "1.0.0")
	f.kern.ensureFn = func(spec.KernelPin) (driver.Installed, error) {
		return driver.Installed{Path: bin, Version: "1.0.0"}, nil
	}
	if err := f.manager.Install(context.Background(), "1.0.0"); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if f.label.count() == 0 {
		t.Fatal("Install did not label the kernel tree")
	}
	order := *f.order
	firstStart := -1
	for i, s := range order {
		if s == "systemctl start "+ServiceName {
			firstStart = i
			break
		}
	}
	if firstStart < 0 {
		t.Fatalf("the service was never started: %v", order)
	}
	for i, s := range order {
		if s == "label" && i > firstStart {
			t.Fatalf("the kernel was labelled after the service started: %v", order)
		}
	}
}

// TestLabelFailureStopsTheStart: when the label cannot be applied the manager
// must not start a kernel that SELinux will kill.
func TestLabelFailureStopsTheStart(t *testing.T) {
	f := newFixture(t, "run/systemd/system/")
	bin := installedKernel(t, f.root, "1.0.0")
	f.kern.ensureFn = func(spec.KernelPin) (driver.Installed, error) {
		return driver.Installed{Path: bin, Version: "1.0.0"}, nil
	}
	f.label.err = errors.New("semanage: no such file")
	err := f.manager.Install(context.Background(), "1.0.0")
	if err == nil || !strings.Contains(err.Error(), "SELinux") {
		t.Fatalf("Install error = %v, want a labelling failure", err)
	}
	if got := f.run.seq(); contains(got, "systemctl start "+ServiceName) {
		t.Fatalf("the service was started despite the labelling failure: %v", got)
	}
}

func TestOpenRCInstall(t *testing.T) {
	f := newFixture(t, "sbin/openrc-run")
	bin := installedKernel(t, f.root, "1.0.0")
	f.kern.ensureFn = func(spec.KernelPin) (driver.Installed, error) {
		return driver.Installed{Path: bin, Version: "1.0.0"}, nil
	}
	if err := f.manager.Install(context.Background(), ""); err != nil {
		t.Fatalf("Install: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(f.root, "etc", "init.d", ServiceName))
	if err != nil {
		t.Fatalf("init script: %v", err)
	}
	script := string(raw)
	for _, want := range []string{
		"#!/sbin/openrc-run",
		`supervisor="supervise-daemon"`,
		`command="` + bin + `"`,
		`command_args="run -c ` + f.config + `"`,
		`rc_ulimit="-n 1048576"`,
		"mkdir -p /run/W1nCray",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %q:\n%s", want, script)
		}
	}
	want := []string{
		"rc-update add " + ServiceName + " default",
		"rc-service " + ServiceName + " start",
	}
	if got := f.run.seq(); !equalStrings(got, want) {
		t.Fatalf("commands = %v, want %v", got, want)
	}
}

func TestProcdInstallAndSysupgradeDedupe(t *testing.T) {
	f := newFixture(t, "sbin/procd", "etc/rc.common")
	bin := installedKernel(t, f.root, "1.0.0")
	f.kern.ensureFn = func(spec.KernelPin) (driver.Installed, error) {
		return driver.Installed{Path: bin, Version: "1.0.0"}, nil
	}
	ctx := context.Background()
	if err := f.manager.Install(ctx, ""); err != nil {
		t.Fatalf("Install: %v", err)
	}

	want := []string{
		filepath.Join(f.root, "etc", "init.d", ServiceName) + " enable",
		filepath.Join(f.root, "etc", "init.d", ServiceName) + " start",
	}
	if got := f.run.seq(); !equalStrings(got, want) {
		t.Fatalf("commands = %v, want %v", got, want)
	}

	// A second install must not duplicate the sysupgrade entries.
	if err := f.manager.Install(ctx, ""); err != nil {
		t.Fatalf("second Install: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(f.root, "etc", "init.d", ServiceName))
	if err != nil {
		t.Fatalf("init script: %v", err)
	}
	script := string(raw)
	for _, want := range []string{
		"#!/bin/sh /etc/rc.common",
		"USE_PROCD=1",
		`procd_set_param command "` + bin + `" run -c "` + f.config + `"`,
		"procd_set_param respawn",
		"mkdir -p /run/W1nCray",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %q:\n%s", want, script)
		}
	}

	sc, err := os.ReadFile(filepath.Join(f.root, "etc", "sysupgrade.conf"))
	if err != nil {
		t.Fatalf("sysupgrade.conf: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(sc)), "\n")
	if len(lines) != 2 {
		t.Fatalf("sysupgrade.conf = %q, want two deduplicated lines", string(sc))
	}
	if lines[0] != filepath.Join(f.root, "etc", "init.d", ServiceName) {
		t.Errorf("sysupgrade.conf line 0 = %q", lines[0])
	}
	if lines[1] != filepath.Join(f.root, "kernels") {
		t.Errorf("sysupgrade.conf line 1 = %q", lines[1])
	}

	// Remove drops the init-script entry again but keeps the kernel dir.
	if _, err := f.manager.Remove(ctx); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	sc, err = os.ReadFile(filepath.Join(f.root, "etc", "sysupgrade.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sc), ServiceName) {
		t.Fatalf("sysupgrade.conf still lists the init script: %q", string(sc))
	}
}

// TestRemoveIsIdempotentWhenTheServiceIsGone covers D-M2: on a machine where
// the service was never installed (or was already removed), Remove must answer
// success. systemd refuses to stop a unit that is not loaded, and that refusal
// is exactly the state the caller asked for -- not a failure to report.
func TestRemoveIsIdempotentWhenTheServiceIsGone(t *testing.T) {
	f := newFixture(t, "run/systemd/system/")
	unitPath := filepath.Join(f.root, "etc", "systemd", "system", ServiceName+".service")
	// systemd's real behaviour: stop/disable of a unit whose file does not
	// exist fails with "Unit ... not loaded".
	f.run.respond = func(name string, args []string) ([]byte, error) {
		if name == "systemctl" && len(args) > 0 && (args[0] == "stop" || args[0] == "disable") {
			if _, err := os.Stat(unitPath); err != nil {
				return []byte("Failed to " + args[0] + " " + ServiceName + ".service: Unit " + ServiceName + ".service not loaded."), errors.New("exit status 5")
			}
		}
		return nil, nil
	}

	removed, err := f.manager.Remove(context.Background())
	if err != nil {
		t.Fatalf("Remove without an installed service must succeed, got: %v", err)
	}
	if removed {
		t.Error("Remove reported a removal although nothing was installed")
	}
	// Idempotent: a second call is a no-op too.
	if removed, err := f.manager.Remove(context.Background()); err != nil || removed {
		t.Fatalf("second Remove = (%v, %v), want (false, nil)", removed, err)
	}
	if got := f.run.seq(); contains(got, "systemctl stop "+ServiceName) || contains(got, "systemctl disable "+ServiceName) {
		t.Errorf("Remove ran stop/disable for a service that does not exist: %v", got)
	}
}

// TestServiceAbsentRecognisesEveryInitSystem pins the phrases that mean "the
// service is not there" for the three supported init systems. Anything else
// stays fatal: idempotency must not swallow a real failure (D-M2).
func TestServiceAbsentRecognisesEveryInitSystem(t *testing.T) {
	for _, msg := range []string{
		"systemctl stop W1nCray-xray: exit status 5: Failed to stop W1nCray-xray.service: Unit W1nCray-xray.service not loaded.",
		"systemctl disable W1nCray-xray: exit status 1: Failed to disable unit: Unit W1nCray-xray.service does not exist",
		"rc-service W1nCray-xray stop: exit status 1: rc-service: service `W1nCray-xray' does not exist",
		"/etc/init.d/W1nCray-xray stop: exit status 1: not found",
		"systemctl stop W1nCray-xray: Unit W1nCray-xray.service not-found",
	} {
		if !serviceAbsent(errors.New(msg)) {
			t.Errorf("serviceAbsent(%q) = false, want true", msg)
		}
	}
	for _, msg := range []string{
		"systemctl stop W1nCray-xray: exit status 1: Operation not permitted",
		"systemctl stop W1nCray-xray: exit status 1: Failed to connect to bus",
	} {
		if serviceAbsent(errors.New(msg)) {
			t.Errorf("serviceAbsent(%q) = true, want false", msg)
		}
	}
}

func TestUpgradeHealthFailureRollsBack(t *testing.T) {	f := newFixture(t, "run/systemd/system/")
	oldBin := installedKernel(t, f.root, "1.0.0")
	newBin := installedKernel(t, f.root, "2.0.0")
	f.kern.current = driver.Installed{Path: oldBin, Version: "1.0.0"}
	f.kern.curErr = nil
	f.kern.rollback = driver.Installed{Path: oldBin, Version: "1.0.0"}
	f.kern.onRback = func() { f.status.setRunning(true) }
	f.kern.ensureFn = func(pin spec.KernelPin) (driver.Installed, error) {
		if pin.Version == "2.0.0" {
			f.status.setRunning(false)
			return driver.Installed{Path: newBin, Version: "2.0.0"}, nil
		}
		f.status.setRunning(true)
		return driver.Installed{Path: oldBin, Version: "1.0.0"}, nil
	}

	err := f.manager.Upgrade(context.Background(), "2.0.0")
	if err == nil || !strings.Contains(err.Error(), "已回滚") {
		t.Fatalf("Upgrade error = %v, want a rollback report", err)
	}
	raw, rerr := os.ReadFile(filepath.Join(f.root, "etc", "systemd", "system", "W1nCray-xray.service"))
	if rerr != nil {
		t.Fatal(rerr)
	}
	if !strings.Contains(string(raw), oldBin) {
		t.Fatalf("the unit was not repointed at the previous version:\n%s", string(raw))
	}
	if st, _ := f.manager.Status(context.Background()); st.Version != "1.0.0" {
		t.Fatalf("current version = %q, want the rolled-back 1.0.0", st.Version)
	}
}

func TestInstallHealthFailureLeavesNoService(t *testing.T) {
	f := newFixture(t, "run/systemd/system/")
	bin := installedKernel(t, f.root, "1.0.0")
	f.kern.ensureFn = func(spec.KernelPin) (driver.Installed, error) {
		f.status.setRunning(false)
		return driver.Installed{Path: bin, Version: "1.0.0"}, nil
	}
	err := f.manager.Install(context.Background(), "1.0.0")
	if err == nil || !strings.Contains(err.Error(), "running") {
		t.Fatalf("Install error = %v, want a health-check failure", err)
	}
	unitPath := filepath.Join(f.root, "etc", "systemd", "system", "W1nCray-xray.service")
	if _, serr := os.Stat(unitPath); !os.IsNotExist(serr) {
		t.Fatalf("the unit file was left behind: %v", serr)
	}
	if got := f.run.seq(); !contains(got, "systemctl stop "+ServiceName) {
		t.Fatalf("the service was not stopped: %v", got)
	}
}

func TestEnsureFailedLeavesNoService(t *testing.T) {
	f := newFixture(t, "run/systemd/system/")
	f.kern.ensureFn = func(spec.KernelPin) (driver.Installed, error) {
		return driver.Installed{}, errors.New("manifest refused")
	}
	if err := f.manager.Install(context.Background(), ""); err == nil {
		t.Fatal("Install must fail")
	}
	unitPath := filepath.Join(f.root, "etc", "systemd", "system", "W1nCray-xray.service")
	if _, err := os.Stat(unitPath); !os.IsNotExist(err) {
		t.Fatalf("a failed Ensure wrote the unit file: %v", err)
	}
	if got := f.run.seq(); len(got) != 0 {
		t.Fatalf("a failed Ensure ran commands: %v", got)
	}
}

func TestRemoveKeepsConfiguration(t *testing.T) {
	f := newFixture(t, "run/systemd/system/")
	bin := installedKernel(t, f.root, "1.0.0")
	f.kern.current = driver.Installed{Path: bin, Version: "1.0.0"}
	f.kern.curErr = nil
	// The service file is there (the machine was installed at some point), so
	// Remove really has to stop and disable it.
	unitPath := filepath.Join(f.root, "etc", "systemd", "system", ServiceName+".service")
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitPath, []byte("unit"), 0o644); err != nil {
		t.Fatal(err)
	}
	route := filepath.Join(f.root, "route.json")
	if err := os.WriteFile(route, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	removed, err := f.manager.Remove(context.Background())
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if !removed {
		t.Error("Remove did not report the removal of an installed service")
	}
	if _, err := os.Stat(unitPath); !os.IsNotExist(err) {
		t.Fatalf("the unit file was not removed: %v", err)
	}
	if _, err := os.Stat(f.config); err != nil {
		t.Fatalf("config.yml was removed: %v", err)
	}
	if _, err := os.Stat(route); err != nil {
		t.Fatalf("a managed file was removed: %v", err)
	}
	if len(f.kern.removed) != 1 || f.kern.removed[0] != "xray@" {
		t.Fatalf("kernel removal = %v, want the whole kernel", f.kern.removed)
	}
	if got := f.run.seq(); !contains(got, "systemctl disable "+ServiceName) {
		t.Fatalf("the service was not disabled: %v", got)
	}
}

// TestStatusPrefersTheKernelEndpoint covers the state mapping: the kernel's own
// endpoint decides when it answers, and the init system decides when it does
// not.
func TestStatusPrefersTheKernelEndpoint(t *testing.T) {
	f := newFixture(t, "run/systemd/system/")
	f.installFake(t, "1.0.0")
	unitDir := filepath.Join(f.root, "etc", "systemd", "system")
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unitDir, ServiceName+".service"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	f.status.setRunning(true)
	if st, _ := f.manager.Status(ctx); st.State != StateRunning {
		t.Fatalf("endpoint running -> %q, want running", st.State)
	}
	f.status.setRunning(false)
	if st, _ := f.manager.Status(ctx); st.State != StateFailed {
		t.Fatalf("endpoint reachable but not running -> %q, want failed", st.State)
	}
	f.status.mu.Lock()
	f.status.err = errors.New("dial unix: connection refused")
	f.status.mu.Unlock()
	if st, _ := f.manager.Status(ctx); st.State != StateStopped {
		t.Fatalf("unreachable endpoint with a stopped service -> %q, want stopped", st.State)
	}
}

func TestStatusNotInstalled(t *testing.T) {
	f := newFixture(t, "run/systemd/system/")
	st, err := f.manager.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.State != StateNotInstalled || st.Version != "" {
		t.Fatalf("status = %+v", st)
	}
}

// TestEnsureRunningWiresAnAlreadyInstalledKernel is the 0.5.x migration path:
// the panel installed the kernel through kernel_install before the agent knew
// about the service, so only the service file has to be written.
func TestEnsureRunningWiresAnAlreadyInstalledKernel(t *testing.T) {
	f := newFixture(t, "run/systemd/system/")
	bin := installedKernel(t, f.root, "0.6.0")
	f.kern.current = driver.Installed{Path: bin, Version: "0.6.0"}
	f.kern.curErr = nil
	if err := f.manager.EnsureRunning(context.Background()); err != nil {
		t.Fatalf("EnsureRunning: %v", err)
	}
	if len(f.kern.ensured) != 0 {
		t.Fatalf("an installed kernel must not be installed again: %v", f.kern.ensured)
	}
	if _, err := os.Stat(filepath.Join(f.root, "etc", "systemd", "system", "W1nCray-xray.service")); err != nil {
		t.Fatalf("the unit file was not written: %v", err)
	}
}

// TestEnsureRunningInstallsWhenMissing is the other migration path: nothing is
// installed, so the kernel comes from the signed manifest first.
func TestEnsureRunningInstallsWhenMissing(t *testing.T) {
	f := newFixture(t, "run/systemd/system/")
	bin := installedKernel(t, f.root, "0.6.0")
	f.kern.ensureFn = func(pin spec.KernelPin) (driver.Installed, error) {
		if pin.Name != "xray" || pin.Version != "" {
			t.Errorf("Ensure pin = %+v, want xray@newest", pin)
		}
		return driver.Installed{Path: bin, Version: "0.6.0"}, nil
	}
	if err := f.manager.EnsureRunning(context.Background()); err != nil {
		t.Fatalf("EnsureRunning: %v", err)
	}
	if len(f.kern.ensured) != 1 {
		t.Fatalf("Ensure calls = %v, want one", f.kern.ensured)
	}
}

// TestAgentBackendRunsUnderTheSupervisor covers the fallback: no init system,
// so the agent supervisor owns the kernel and the status says so.
func TestAgentBackendRunsUnderTheSupervisor(t *testing.T) {
	f := newFixture(t)
	bin := installedKernel(t, f.root, "1.0.0")
	f.kern.ensureFn = func(spec.KernelPin) (driver.Installed, error) {
		return driver.Installed{Path: bin, Version: "1.0.0"}, nil
	}
	if err := f.manager.Install(context.Background(), ""); err != nil {
		t.Fatalf("Install: %v", err)
	}
	f.sup.mu.Lock()
	if len(f.sup.specs) != 1 {
		f.sup.mu.Unlock()
		t.Fatalf("supervisor specs = %v", f.sup.specs)
	}
	got := f.sup.specs[0]
	f.sup.mu.Unlock()
	if got.ID != agentProcID || got.Path != bin || !equalStrings(got.Args, []string{"run", "-c", f.config}) {
		t.Fatalf("supervised spec = %+v", got)
	}
	if got.WorkDir != filepath.Dir(f.config) {
		t.Fatalf("WorkDir = %q", got.WorkDir)
	}
	st, err := f.manager.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.State != StateRunning || st.Backend != BackendAgent || st.ManagedBy != "agent" {
		t.Fatalf("status = %+v", st)
	}
}

// ---- helpers ---------------------------------------------------------------

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
