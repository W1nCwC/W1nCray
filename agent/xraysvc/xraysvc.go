// Package xraysvc manages the Xray kernel (the W1nCray-xray program) as a
// service of its own, the way the agent manages gost/realm/frp as child
// processes but with one crucial difference: the Xray kernel carries user
// traffic, so it must not stop when the agent restarts, upgrades or crashes.
//
// It installs the kernel from the signed manifest (kernelx), writes the
// service definition for the machine's init system, starts it and checks the
// kernel's own status endpoint for health; an upgrade that does not come up
// healthy is rolled back to the previous version.
//
// Every path and every service-file line is generated here from the agent's own
// configuration. Nothing the panel sends can name a path or a command.
package xraysvc

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/agent/xrayapi"
	"github.com/W1nCwC/W1nCray/kernel"
	"github.com/W1nCwC/W1nCray/kernel/install"
)

// ServiceName is the fixed name of the service, its unit file and its init
// script. It is never taken from the panel.
const ServiceName = "W1nCray-xray"

// Backends: how the Xray kernel is supervised on this machine.
const (
	BackendSystemd = "systemd"
	BackendOpenRC  = "openrc"
	BackendProcd   = "procd"
	// BackendAgent is the fallback: the agent's own supervisor runs the kernel
	// as a child process, so it stops when the agent stops (like gost).
	BackendAgent = "agent"
)

// Service states.
const (
	StateRunning      = "running"
	StateStopped      = "stopped"
	StateFailed       = "failed"
	StateInstalling   = "installing"
	StateNotInstalled = "not_installed"
)

// Status is the service manager's view of the Xray kernel on this machine.
type Status struct {
	// Backend is systemd | openrc | procd | agent.
	Backend string `json:"backend"`
	// State is running | stopped | failed | installing | not_installed.
	State string `json:"state"`
	// ManagedBy is "service" when an init system owns the kernel and "agent"
	// when the agent's supervisor does.
	ManagedBy string `json:"managed_by,omitempty"`
	// Version and Path describe the installed current version, when there is
	// one.
	Version string `json:"version,omitempty"`
	Path    string `json:"path,omitempty"`
	// UnitPath is the service file the manager owns ("" for the agent backend).
	UnitPath string `json:"unit_path,omitempty"`
	// Error carries a backend failure that made the state "failed".
	Error string `json:"error,omitempty"`
}

// Kernels is the kernel installer surface the manager needs. The production
// implementation is *kernelx.Ensurer.
type Kernels interface {
	Ensure(ctx context.Context, pin spec.KernelPin) (driver.Installed, error)
	// EnsureForce installs for an explicit operator request, bypassing and
	// clearing the automatic retry back-off (D-M3). Install and Upgrade use it;
	// the start-up migration (EnsureRunning) keeps Ensure.
	EnsureForce(ctx context.Context, pin spec.KernelPin) (driver.Installed, error)
	Current(name string) (driver.Installed, error)
	Rollback(name string) (driver.Installed, error)
	// Remove deletes one version; an empty version removes the whole kernel,
	// including the current one.
	Remove(name, version string) error
	List() ([]install.Entry, error)
}

// Supervisor is the agent supervisor surface the fallback backend uses.
// *supervisor.Supervisor implements it.
type Supervisor interface {
	Start(ctx context.Context, p driver.ProcSpec) error
	Stop(ctx context.Context, id string) error
	Status(id string) driver.ProcStatus
}

// Labeler makes the installed kernel binaries executable on an SELinux
// machine (bin_t) before the service is started. *kernelx.Ensurer implements
// it; nil disables labelling (tests, non-Linux builds).
type Labeler interface {
	LabelKernels(ctx context.Context) error
}

// Options configures a Manager. Kernels and ConfigPath are required.
type Options struct {
	// Root prefixes every service-file path ("" is "/"). Tests use a temporary
	// root; production leaves it empty.
	Root string
	// Kernels installs, switches and removes kernel versions.
	Kernels Kernels
	// ConfigPath is the absolute path of config.yml: the kernel is started with
	// "run -c <ConfigPath>" and its status endpoint lives next to it.
	ConfigPath string
	// KernelsDir is the kernel install base directory (added to
	// /etc/sysupgrade.conf on OpenWrt). Optional.
	KernelsDir string
	// StateDir is the agent state directory (the fallback backend keeps the
	// child's log and pid files under it).
	StateDir string
	// Status reads the kernel's status endpoint for health checks and the
	// components view. Nil skips the health check.
	Status xrayapi.Service
	// Sup is the agent supervisor for the fallback backend. Nil makes the
	// agent backend unusable on a machine with no init system.
	Sup Supervisor
	// Labeler makes the kernel binaries bin_t on an SELinux machine, without
	// which the service starts in init_t and cannot bind its status socket
	// (agent/selinux). Nil skips it.
	Labeler Labeler
	// Runner executes service-manager commands (default ExecRunner).
	Runner Runner
	// Log receives the manager's events.
	Log driver.Logger
	// HealthTimeout is how long a start/restart may take to report running
	// (default 30s).
	HealthTimeout time.Duration
	// HealthInterval is how often the status endpoint is polled while waiting
	// for health (default 500ms).
	HealthInterval time.Duration
	// RemoveTimeout is how long Remove waits for the fallback backend's child
	// process to exit before refusing with in_use (default 10s).
	RemoveTimeout time.Duration
	// StatusTimeout bounds one health-check status read (default 2s).
	StatusTimeout time.Duration
	// Backend overrides backend detection (tests).
	Backend string
}

// Manager installs, upgrades, rolls back, restarts and removes the Xray kernel
// service. It is safe for concurrent use; the mutating operations are
// serialised.
type Manager struct {
	opts    Options
	backend backend
	log     driver.Logger

	mu         sync.Mutex
	installing atomic.Bool
}

// New builds a Manager and detects the machine's service backend.
func New(o Options) (*Manager, error) {
	if o.Kernels == nil {
		return nil, errors.New("xraysvc: a kernel manager is required")
	}
	if o.ConfigPath == "" {
		return nil, errors.New("xraysvc: ConfigPath is required")
	}
	if o.Runner == nil {
		o.Runner = ExecRunner{}
	}
	if o.HealthTimeout <= 0 {
		o.HealthTimeout = 30 * time.Second
	}
	if o.HealthInterval <= 0 {
		o.HealthInterval = 500 * time.Millisecond
	}
	if o.RemoveTimeout <= 0 {
		o.RemoveTimeout = 10 * time.Second
	}
	if o.StatusTimeout <= 0 {
		o.StatusTimeout = 2 * time.Second
	}
	log := o.Log
	if log == nil {
		log = nopLog{}
	}
	m := &Manager{opts: o, log: log}
	be, err := newBackend(o, base{root: o.Root, run: o.Runner})
	if err != nil {
		return nil, err
	}
	m.backend = be
	return m, nil
}

// Backend reports the detected service backend.
func (m *Manager) Backend() string { return m.backend.name() }

// ConfigDir returns the directory of config.yml (the kernel's working
// directory).
func (m *Manager) ConfigDir() string { return filepath.Dir(m.opts.ConfigPath) }

// Status reports the installed version and the service state.
func (m *Manager) Status(ctx context.Context) (Status, error) {
	st := Status{
		Backend:   m.backend.name(),
		ManagedBy: m.backend.managedBy(),
		UnitPath:  m.backend.unitPath(),
	}
	if m.installing.Load() {
		st.State = StateInstalling
		return st, nil
	}
	cur, err := m.opts.Kernels.Current(xrayapi.KernelName)
	if err != nil {
		st.State = StateNotInstalled
		return st, nil
	}
	st.Version, st.Path = cur.Version, cur.Path
	if !m.backend.exists() {
		st.State = StateNotInstalled
		return st, nil
	}
	// The kernel's own status endpoint is the truth when it answers: it says
	// whether the Xray instance is really serving. When it does not answer, the
	// init system decides: a service that is not up is "stopped" (or "failed"
	// when the init system says so), and a service the init system still calls
	// active is "running" (the endpoint may simply not be ready yet).
	//
	// The agent backend is the exception: the child belongs to this process's
	// supervisor, which is the only authority on whether it is running (a
	// leftover socket from a previous agent run must not be believed).
	if m.opts.Status != nil && m.backend.managedBy() == "service" {
		sctx, cancel := context.WithTimeout(ctx, m.opts.StatusTimeout)
		ks, kerr := m.opts.Status.Status(sctx)
		cancel()
		if kerr == nil {
			if ks.Running {
				st.State = StateRunning
			} else {
				st.State = StateFailed
				st.Error = ks.LastError
			}
			return st, nil
		}
	}
	state, err := m.backend.active(ctx)
	if err != nil {
		st.State = StateFailed
		st.Error = err.Error()
		return st, nil
	}
	st.State = state
	return st, nil
}

// EnsureRunning brings the kernel service up when the machine needs Xray. It
// is what the start-up migration calls: an installed kernel is only (re)wired
// and started, a missing one is installed from the signed manifest first.
func (m *Manager) EnsureRunning(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cur, err := m.opts.Kernels.Current(xrayapi.KernelName)
	if err != nil {
		m.log.Infof("xraysvc: 检测到 Xray 节点配置，正在安装 Xray 内核")
		m.installing.Store(true)
		defer m.installing.Store(false)
		inst, err := m.opts.Kernels.Ensure(ctx, spec.KernelPin{Name: xrayapi.KernelName})
		if err != nil {
			return err
		}
		return m.activate(ctx, inst, false)
	}
	if st, serr := m.Status(ctx); serr == nil && st.State == StateRunning {
		return nil
	}
	return m.activate(ctx, cur, false)
}

// Install makes the requested version current and the service running. An
// empty version selects the newest one the signed manifest offers for this
// machine. It is idempotent: the same version with the same unit file is not
// restarted. A health-check failure leaves no half-installed service behind: a
// machine that was already serving traffic keeps the version it was serving,
// and only a machine that had no running service is cleaned up. A failed
// same-version reinstall is retried on that version and is never demoted to the
// previous one.
func (m *Manager) Install(ctx context.Context, version string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// What has to survive a failed install is read before the installing flag
	// hides it: Status reports "installing" while the flag is set, so the
	// version and the service state must be captured first.
	prev, perr := m.opts.Kernels.Current(xrayapi.KernelName)
	wasRunning := m.serviceRunning(ctx)

	m.installing.Store(true)
	defer m.installing.Store(false)

	inst, err := m.opts.Kernels.EnsureForce(ctx, pin(version))
	if err != nil {
		return err
	}
	if err := m.activate(ctx, inst, false); err != nil {
		return m.restoreAfterFailedInstall(ctx, err, inst, prev, perr, wasRunning)
	}
	return nil
}

// serviceRunning reports whether the service is up right now, using the same
// rules as Status. A state that cannot be read is "not running": nothing is
// preserved that cannot be named.
func (m *Manager) serviceRunning(ctx context.Context) bool {
	st, err := m.Status(ctx)
	return err == nil && st.State == StateRunning
}

// restoreAfterFailedInstall undoes a failed Install. A machine that was already
// serving traffic is rolled back to the version it was serving, exactly like a
// failed Upgrade; the half-written service is only deleted when there was
// nothing running to preserve (R1-1/R1-5).
//
// A same-version reinstall is the exception (F4b). EnsureForce installs the
// version that is already current, so kernel/install.commit leaves the previous
// pointer alone and current still names the running version; Rollback would
// therefore move the machine to an older version nobody asked for and mark the
// version it was already running as failed. The same version is restarted once
// more instead, and the service and the current version are kept either way.
func (m *Manager) restoreAfterFailedInstall(ctx context.Context, cause error, inst, prev driver.Installed, perr error, wasRunning bool) error {
	if !wasRunning {
		// The kernel is installed but the service never came up healthy:
		// remove what this call wrote so the machine is not left with a
		// service that cannot start.
		if derr := m.deactivate(ctx); derr != nil {
			m.log.Warnf("xraysvc: 清理未通过健康检查的服务: %v", derr)
		}
		return cause
	}
	if perr != nil || prev.Path == "" {
		// The service was up but the version it ran cannot be named: deleting
		// the service would take a working Xray down, so leave it in place and
		// report the failure instead.
		return fmt.Errorf("%w（安装前有正在运行的 Xray 服务，但无法确定其版本，未自动恢复）", cause)
	}
	if prev.Version == inst.Version && prev.Path == inst.Path {
		// The install did not switch versions: there is nothing to roll back
		// to, and the previous pointer names an older version the operator
		// never asked for. Retry the same version with a restart instead.
		m.log.Warnf("xraysvc: 同版本重装 %s 健康检查失败，重启重试（不回滚、不降级）", inst.Version)
		if werr := m.activate(ctx, inst, true); werr != nil {
			return fmt.Errorf("%w（同版本重装 %s 健康检查失败，重启重试仍未通过: %v；保留当前版本与服务，未降级）", cause, inst.Version, werr)
		}
		m.log.Infof("xraysvc: 同版本重装 %s 已通过重启恢复", inst.Version)
		return nil
	}
	rb, rerr := m.opts.Kernels.Rollback(xrayapi.KernelName)
	if rerr != nil {
		return fmt.Errorf("%w（恢复安装前运行的 %s 失败: %v）", cause, prev.Version, rerr)
	}
	if werr := m.activate(ctx, rb, true); werr != nil {
		return fmt.Errorf("%w（已回滚到 %s，但服务仍未通过健康检查: %v）", cause, rb.Version, werr)
	}
	return fmt.Errorf("安装 %s 失败，已恢复到安装前运行的 %s: %w", inst.Version, rb.Version, cause)
}

// Upgrade installs version, repoints the service at it, restarts and checks
// health. When the new version does not come up, the previous version is made
// current again, the service is repointed at it and restarted, and the failure
// is returned with the rollback outcome.
func (m *Manager) Upgrade(ctx context.Context, version string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.installing.Store(true)
	defer m.installing.Store(false)

	prev, perr := m.opts.Kernels.Current(xrayapi.KernelName)
	inst, err := m.opts.Kernels.EnsureForce(ctx, pin(version))
	if err != nil {
		return err
	}
	if err := m.activate(ctx, inst, true); err != nil {
		if perr != nil || prev.Path == "" {
			return err
		}
		rb, rerr := m.opts.Kernels.Rollback(xrayapi.KernelName)
		if rerr != nil {
			return fmt.Errorf("%w（回滚到上一版本失败: %v）", err, rerr)
		}
		if werr := m.activate(ctx, rb, true); werr != nil {
			return fmt.Errorf("%w（已回滚到 %s，但服务仍未通过健康检查: %v）", err, rb.Version, werr)
		}
		return fmt.Errorf("升级到 %s 失败，已回滚到 %s: %w", inst.Version, rb.Version, err)
	}
	return nil
}

// Rollback makes the previous kernel version current, repoints the service at
// it, restarts and checks health.
func (m *Manager) Rollback(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	inst, err := m.opts.Kernels.Rollback(xrayapi.KernelName)
	if err != nil {
		return err
	}
	return m.activate(ctx, inst, true)
}

// Start starts the service on the installed current version. A machine without
// an installed kernel is refused (use Install).
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cur, err := m.opts.Kernels.Current(xrayapi.KernelName)
	if err != nil {
		return fmt.Errorf("%s 服务未安装（先执行 install）", ServiceName)
	}
	return m.activate(ctx, cur, false)
}

// Stop stops the service without disabling it.
func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.backend.stop(ctx)
}

// Restart restarts the service on the current version.
func (m *Manager) Restart(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cur, err := m.opts.Kernels.Current(xrayapi.KernelName)
	if err != nil {
		return fmt.Errorf("%s 服务未安装", ServiceName)
	}
	if err := m.labelKernels(ctx); err != nil {
		return err
	}
	if _, err := m.backend.writeUnit(cur.Path, m.opts.ConfigPath, m.ConfigDir()); err != nil {
		return err
	}
	if err := m.backend.enable(ctx); err != nil {
		return fmt.Errorf("启用 %s 服务: %w", ServiceName, err)
	}
	if err := m.backend.restart(ctx); err != nil {
		return fmt.Errorf("重启 %s 服务: %w", ServiceName, err)
	}
	return m.waitHealthy(ctx)
}

// Remove stops and disables the service, deletes its service file and removes
// every installed version of the kernel. config.yml and the managed files are
// kept: reinstalling restores the service.
//
// It is idempotent (D-M2). A machine where the service was never installed, or
// where it is already gone, answers success with removed=false: a missing
// service is never an error, because "not installed" is exactly the state the
// caller asked for. The rest of the cleanup still runs (an init-script entry in
// /etc/sysupgrade.conf, kernel files left behind by a partial removal).
func (m *Manager) Remove(ctx context.Context) (removed bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// "Removed something" is decided before the cleanup: a service file that is
	// really there, or any installed version. The agent backend has no unit
	// file of its own (unitPath is ""), so only the kernel list counts there.
	removed = m.backend.unitPath() != "" && m.backend.exists()
	if list, lerr := m.opts.Kernels.List(); lerr == nil {
		for _, e := range list {
			if e.Name == xrayapi.KernelName {
				removed = true
				break
			}
		}
	}

	derr := m.deactivate(ctx)
	// The fallback backend runs the kernel as a child of the agent's
	// supervisor. Deleting the kernel directory while that process is still
	// alive removes the binary of a running program (and the rollback pointer
	// with it), so the removal waits for the exit and refuses otherwise
	// (R1-8).
	if werr := m.waitChildGone(ctx); werr != nil {
		if derr != nil {
			return removed, fmt.Errorf("%v；%w", derr, werr)
		}
		return removed, werr
	}
	rerr := m.opts.Kernels.Remove(xrayapi.KernelName, "")
	if rerr != nil && !errors.Is(rerr, kernel.ErrNotInstalled) {
		if derr != nil {
			return removed, fmt.Errorf("%v；删除内核文件: %w", derr, rerr)
		}
		return removed, rerr
	}
	return removed, derr
}

// waitChildGone waits for the fallback backend's child process to really exit
// after it was stopped, and reports kernel.ErrInUse (in_use) when it is still
// alive at the deadline. Backends whose process belongs to an init system
// return immediately: their process is the init system's to stop, and the
// manager never waits on a service it does not own.
func (m *Manager) waitChildGone(ctx context.Context) error {
	b, ok := m.backend.(*agentBackend)
	if !ok {
		return nil
	}
	deadline := time.Now().Add(m.opts.RemoveTimeout)
	for {
		if !b.running() {
			return nil
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			break
		}
		t := time.NewTimer(m.opts.HealthInterval)
		select {
		case <-ctx.Done():
			t.Stop()
		case <-t.C:
		}
	}
	return kernel.Newf(kernel.ErrInUse, xrayapi.KernelName, "",
		"内核进程在 %s 内没有退出；内核文件保留，稍后重试 remove", m.opts.RemoveTimeout)
}

// activate writes the service definition, enables the service, starts it (or
// restarts it when a version switch requires it) and waits for the kernel's
// status endpoint to report running.
//
// restart=false means "bring the requested version up". A fresh machine is
// started, but a service that is already running is *restarted* when the
// service definition changed or the running kernel reports another version: the
// init systems' start is a no-op for a unit that is already active, so a plain
// start would leave the old process serving traffic while the unit file and the
// current pointer already name the new version (R1-1/R1-5).
func (m *Manager) activate(ctx context.Context, inst driver.Installed, restart bool) error {
	if inst.Path == "" {
		return errors.New("xraysvc: 内核版本没有可执行文件路径")
	}
	// The label must be in place before the service starts: a kernel binary
	// under /etc keeps the etc_t type and would run in init_t (agent/selinux).
	if err := m.labelKernels(ctx); err != nil {
		return err
	}
	// Whether a service definition existed *before* this write separates a
	// fresh install (nothing can be running) from a re-point of a live service.
	existed := m.backend.exists()
	changed, err := m.backend.writeUnit(inst.Path, m.opts.ConfigPath, m.ConfigDir())
	if err != nil {
		return err
	}
	if err := m.backend.enable(ctx); err != nil {
		return fmt.Errorf("启用 %s 服务: %w", ServiceName, err)
	}
	if !restart {
		restart = m.mustRestart(ctx, existed, changed, inst)
	}
	if restart {
		if err := m.backend.restart(ctx); err != nil {
			return fmt.Errorf("重启 %s 服务: %w", ServiceName, err)
		}
	} else if err := m.backend.start(ctx); err != nil {
		return fmt.Errorf("启动 %s 服务: %w", ServiceName, err)
	}
	return m.waitHealthy(ctx)
}

// mustRestart decides whether an activation that was not asked to restart has
// to replace the running kernel process instead of issuing a plain start. A
// service manager's start is a no-op for a unit that is already active, so
// starting is only correct when nothing is running.
func (m *Manager) mustRestart(ctx context.Context, existed, changed bool, inst driver.Installed) bool {
	if !existed {
		// The service was never defined on this machine: there is no process
		// of this service to replace.
		return false
	}
	// A running kernel that reports another version than the one being
	// activated is the clearest reason to restart, whatever the unit file
	// says: an earlier attempt may already have written it.
	if v, ok := m.runningKernelVersion(ctx); ok && v != "" && v != inst.Version {
		return true
	}
	if !changed {
		// The unit file already names this binary, so what runs is the
		// intended version (or nothing runs): a plain start is enough. This is
		// what keeps a same-version reinstall from restarting the service.
		return false
	}
	state, err := m.backend.active(ctx)
	if err != nil {
		// The service manager cannot tell: replacing the process is the safe
		// choice, because a plain start would silently do nothing if it is up.
		return true
	}
	return state == StateRunning
}

// runningKernelVersion asks the kernel's own status endpoint which version is
// executing. ok is false when there is no endpoint, when an init system does
// not own the process, or when the endpoint does not answer: an unanswered
// endpoint says nothing about the running version.
func (m *Manager) runningKernelVersion(ctx context.Context) (string, bool) {
	if m.opts.Status == nil || m.backend.managedBy() != "service" {
		return "", false
	}
	sctx, cancel := context.WithTimeout(ctx, m.opts.StatusTimeout)
	defer cancel()
	st, err := m.opts.Status.Status(sctx)
	if err != nil || !st.Running {
		return "", false
	}
	return st.Version, true
}

// deactivate stops and disables the service and removes its service file. The
// errors are joined but a failure never stops the removal from continuing.
//
// A service that is not there cannot be stopped or disabled: systemd answers
// "Unit ... not loaded", OpenRC "service ... does not exist" and procd
// "not found", and all three mean the desired state already holds (D-M2). The
// skip is by the service file, and serviceAbsent covers a stale init-system
// view of a file that was just deleted.
func (m *Manager) deactivate(ctx context.Context) error {
	var errs []error
	if m.backend.unitPath() != "" && !m.backend.exists() {
		m.log.Infof("xraysvc: %s 服务不存在，跳过 stop/disable（幂等卸载）", ServiceName)
	} else {
		if err := m.backend.stop(ctx); err != nil && !serviceAbsent(err) {
			errs = append(errs, fmt.Errorf("停止 %s 服务: %w", ServiceName, err))
		}
		if err := m.backend.disable(ctx); err != nil && !serviceAbsent(err) {
			errs = append(errs, fmt.Errorf("禁用 %s 服务: %w", ServiceName, err))
		}
	}
	if err := m.backend.removeUnit(); err != nil {
		errs = append(errs, fmt.Errorf("删除 %s 服务文件: %w", ServiceName, err))
	}
	return errors.Join(errs...)
}

// serviceAbsent reports whether a stop/disable failure only means the init
// system does not know the service. That is the desired state of a removal, not
// an error to report (D-M2); anything else (a permission problem, a broken
// init system) stays fatal.
func serviceAbsent(err error) bool {
	s := strings.ToLower(err.Error())
	for _, phrase := range []string{"not loaded", "not-found", "not found", "does not exist", "unrecognized service", "no such service"} {
		if strings.Contains(s, phrase) {
			return true
		}
	}
	return false
}

// labelKernels applies the SELinux label the kernel binaries need before the
// service can start. A machine with SELinux off, or without the labelling
// tools, is a no-op (agent/selinux decides).
func (m *Manager) labelKernels(ctx context.Context) error {
	if m.opts.Labeler == nil {
		return nil
	}
	if err := m.opts.Labeler.LabelKernels(ctx); err != nil {
		return fmt.Errorf("设置内核 SELinux 标签: %w", err)
	}
	return nil
}

// waitHealthy polls the kernel's status endpoint until it reports running.
func (m *Manager) waitHealthy(ctx context.Context) error {
	if m.opts.Status == nil {
		return nil
	}
	deadline := time.Now().Add(m.opts.HealthTimeout)
	last := error(errors.New("状态接口尚未报告 running"))
	for {
		sctx, cancel := context.WithTimeout(ctx, m.opts.StatusTimeout)
		st, err := m.opts.Status.Status(sctx)
		cancel()
		switch {
		case err == nil && st.Running:
			return nil
		case err != nil:
			last = err
		default:
			last = errors.New("状态接口报告 running=false")
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			break
		}
		t := time.NewTimer(m.opts.HealthInterval)
		select {
		case <-ctx.Done():
			t.Stop()
		case <-t.C:
		}
	}
	return fmt.Errorf("Xray 服务未在 %s 内报告 running: %v", m.opts.HealthTimeout, last)
}

// pin builds the kernel pin of a requested version ("" selects the newest).
func pin(version string) spec.KernelPin {
	return spec.KernelPin{Name: xrayapi.KernelName, Version: version}
}

type nopLog struct{}

func (nopLog) Debugf(string, ...any) {}
func (nopLog) Infof(string, ...any)  {}
func (nopLog) Warnf(string, ...any)  {}
func (nopLog) Errorf(string, ...any) {}
