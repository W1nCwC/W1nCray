package xraysvc

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// Runner runs one external command and returns its combined output. It is an
// argv array, never a shell.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// ExecRunner runs commands with os/exec.
type ExecRunner struct{}

// Run implements Runner.
func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	// name is a fixed service-manager command (systemctl, rc-service,
	// rc-update) or the agent-generated init script; args is an argv array,
	// never a command string.
	return exec.CommandContext(ctx, name, args...).CombinedOutput() //nolint:noshell -- fixed service-manager command or agent-generated init script
}

// agentProcID is the supervisor id of the kernel in the fallback backend.
const agentProcID = "xray"

// backend owns the machine-specific half of the service management: where the
// service definition lives, how it is enabled/started/stopped and how its
// state is read.
type backend interface {
	// name is the backend name reported in the status.
	name() string
	// managedBy is "service" (an init system owns the process) or "agent"
	// (the agent supervisor does).
	managedBy() string
	// unitPath is the service file the manager owns ("" for the agent
	// backend).
	unitPath() string
	// exists reports whether the service definition is in place.
	exists() bool
	// writeUnit writes (or rewrites) the service definition for bin and
	// configPath, and reports whether its content changed.
	writeUnit(bin, configPath, configDir string) (bool, error)
	// removeUnit deletes the service definition (the agent backend stops the
	// child instead).
	removeUnit() error
	// enable makes the service start at boot.
	enable(ctx context.Context) error
	// disable undoes enable.
	disable(ctx context.Context) error
	start(ctx context.Context) error
	stop(ctx context.Context) error
	restart(ctx context.Context) error
	// active reports running | stopped | failed.
	active(ctx context.Context) (string, error)
}

// newBackend detects the machine's service backend. A machine with none of the
// three init systems falls back to the agent's own supervisor; without a
// supervisor there is nothing that could keep the kernel running.
func newBackend(o Options, b base) (backend, error) {
	switch o.Backend {
	case BackendSystemd:
		return systemdBackend{b}, nil
	case BackendOpenRC:
		return openrcBackend{b}, nil
	case BackendProcd:
		return procdBackend{b}, nil
	case BackendAgent:
		return newAgentBackend(o, b)
	case "":
	default:
		return nil, fmt.Errorf("xraysvc: unknown backend %q", o.Backend)
	}
	switch {
	case b.exists("run/systemd/system"):
		return systemdBackend{b}, nil
	case b.exists("sbin/openrc-run"):
		return openrcBackend{b}, nil
	case b.exists("sbin/procd") && b.exists("etc/rc.common"):
		return procdBackend{b}, nil
	default:
		return newAgentBackend(o, b)
	}
}

func newAgentBackend(o Options, b base) (backend, error) {
	if o.Sup == nil {
		return nil, fmt.Errorf("xraysvc: 没有检测到可用的服务管理器（systemd / OpenRC / procd），且 agent supervisor 不可用")
	}
	return &agentBackend{base: b, sup: o.Sup, stateDir: o.StateDir, log: o.Log}, nil
}

// base carries the filesystem root and the command runner shared by every
// backend.
type base struct {
	root string
	run  Runner
}

// path resolves a slash-separated absolute path under the root.
func (b base) path(p string) string {
	if b.root == "" {
		return "/" + strings.TrimPrefix(p, "/")
	}
	return filepath.Join(b.root, filepath.FromSlash(strings.TrimPrefix(p, "/")))
}

// exists reports whether a slash-separated absolute path exists under the root.
func (b base) exists(p string) bool {
	_, err := os.Stat(b.path(p))
	return err == nil
}

// oneLine collapses a command's output to one short line for an error message.
func oneLine(b []byte) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// ---- systemd ---------------------------------------------------------------

type systemdBackend struct{ base }

const systemdUnitPath = "etc/systemd/system/" + ServiceName + ".service"

func (b systemdBackend) name() string      { return BackendSystemd }
func (b systemdBackend) managedBy() string { return "service" }
func (b systemdBackend) unitPath() string  { return b.path(systemdUnitPath) }
func (b systemdBackend) exists() bool      { return b.base.exists(systemdUnitPath) }

func (b systemdBackend) writeUnit(bin, configPath, configDir string) (bool, error) {
	return writeIfChanged(b.unitPath(), systemdUnit(bin, configPath, configDir), 0o644)
}

func (b systemdBackend) removeUnit() error { return removeIfExists(b.unitPath()) }

func (b systemdBackend) call(ctx context.Context, args ...string) error {
	out, err := b.run.Run(ctx, "systemctl", args...)
	if err != nil {
		return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, oneLine(out))
	}
	return nil
}

func (b systemdBackend) enable(ctx context.Context) error {
	if err := b.call(ctx, "daemon-reload"); err != nil {
		return err
	}
	return b.call(ctx, "enable", ServiceName)
}

func (b systemdBackend) disable(ctx context.Context) error {
	return b.call(ctx, "disable", ServiceName)
}

func (b systemdBackend) start(ctx context.Context) error { return b.call(ctx, "start", ServiceName) }
func (b systemdBackend) stop(ctx context.Context) error  { return b.call(ctx, "stop", ServiceName) }

func (b systemdBackend) restart(ctx context.Context) error {
	if err := b.call(ctx, "daemon-reload"); err != nil {
		return err
	}
	return b.call(ctx, "restart", ServiceName)
}

func (b systemdBackend) active(ctx context.Context) (string, error) {
	out, err := b.run.Run(ctx, "systemctl", "is-active", ServiceName)
	s := strings.TrimSpace(string(out))
	if s == "" && err != nil {
		return "", fmt.Errorf("systemctl is-active %s: %w", ServiceName, err)
	}
	switch s {
	case "active", "activating", "reloading":
		return StateRunning, nil
	case "failed":
		return StateFailed, nil
	default:
		return StateStopped, nil
	}
}

// ---- OpenRC ----------------------------------------------------------------

type openrcBackend struct{ base }

const openrcScriptPath = "etc/init.d/" + ServiceName

func (b openrcBackend) name() string      { return BackendOpenRC }
func (b openrcBackend) managedBy() string { return "service" }
func (b openrcBackend) unitPath() string  { return b.path(openrcScriptPath) }
func (b openrcBackend) exists() bool      { return b.base.exists(openrcScriptPath) }

func (b openrcBackend) writeUnit(bin, configPath, configDir string) (bool, error) {
	return writeIfChanged(b.unitPath(), openrcScript(bin, configPath, configDir), 0o755)
}

func (b openrcBackend) removeUnit() error { return removeIfExists(b.unitPath()) }

func (b openrcBackend) call(ctx context.Context, args ...string) error {
	out, err := b.run.Run(ctx, "rc-service", args...)
	if err != nil {
		return fmt.Errorf("rc-service %s: %w: %s", strings.Join(args, " "), err, oneLine(out))
	}
	return nil
}

func (b openrcBackend) enable(ctx context.Context) error {
	out, err := b.run.Run(ctx, "rc-update", "add", ServiceName, "default")
	if err != nil {
		return fmt.Errorf("rc-update add %s default: %w: %s", ServiceName, err, oneLine(out))
	}
	return nil
}

func (b openrcBackend) disable(ctx context.Context) error {
	out, err := b.run.Run(ctx, "rc-update", "del", ServiceName, "default")
	if err != nil {
		return fmt.Errorf("rc-update del %s default: %w: %s", ServiceName, err, oneLine(out))
	}
	return nil
}

func (b openrcBackend) start(ctx context.Context) error   { return b.call(ctx, ServiceName, "start") }
func (b openrcBackend) stop(ctx context.Context) error    { return b.call(ctx, ServiceName, "stop") }
func (b openrcBackend) restart(ctx context.Context) error { return b.call(ctx, ServiceName, "restart") }

func (b openrcBackend) active(ctx context.Context) (string, error) {
	out, err := b.run.Run(ctx, "rc-service", ServiceName, "status")
	if err == nil {
		return StateRunning, nil
	}
	if strings.Contains(string(out), "crashed") {
		return StateFailed, nil
	}
	return StateStopped, nil
}

// ---- procd (OpenWrt) -------------------------------------------------------

type procdBackend struct{ base }

func (b procdBackend) name() string      { return BackendProcd }
func (b procdBackend) managedBy() string { return "service" }
func (b procdBackend) unitPath() string  { return b.path(openrcScriptPath) }
func (b procdBackend) exists() bool      { return b.base.exists(openrcScriptPath) }

func (b procdBackend) writeUnit(bin, configPath, configDir string) (bool, error) {
	changed, err := writeIfChanged(b.unitPath(), procdScript(bin, configPath, configDir, gomemLimit(b.root)), 0o755)
	if err != nil {
		return changed, err
	}
	// OpenWrt's sysupgrade keeps only /etc/config and the listed paths: the
	// kernel directory and the init script must survive a firmware upgrade.
	entries := []string{b.initEntry()}
	if dir := kernelBaseDir(bin); dir != "" {
		entries = append(entries, dir)
	}
	if err := ensureSysupgrade(b.path("etc/sysupgrade.conf"), entries...); err != nil {
		return changed, err
	}
	return changed, nil
}

// initEntry is the sysupgrade.conf line of the init script (the real host path,
// without the test/chroot root prefix).
func (b procdBackend) initEntry() string {
	if b.root == "" {
		return "/" + openrcScriptPath
	}
	return b.path(openrcScriptPath)
}

func (b procdBackend) removeUnit() error {
	err := removeIfExists(b.unitPath())
	if derr := dropSysupgrade(b.path("etc/sysupgrade.conf"), b.initEntry()); derr != nil && err == nil {
		err = derr
	}
	return err
}

func (b procdBackend) scriptCall(ctx context.Context, args ...string) error {
	script := b.unitPath()
	out, err := b.run.Run(ctx, script, args...)
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", script, strings.Join(args, " "), err, oneLine(out))
	}
	return nil
}

func (b procdBackend) enable(ctx context.Context) error  { return b.scriptCall(ctx, "enable") }
func (b procdBackend) disable(ctx context.Context) error { return b.scriptCall(ctx, "disable") }
func (b procdBackend) start(ctx context.Context) error   { return b.scriptCall(ctx, "start") }
func (b procdBackend) stop(ctx context.Context) error    { return b.scriptCall(ctx, "stop") }
func (b procdBackend) restart(ctx context.Context) error { return b.scriptCall(ctx, "restart") }

func (b procdBackend) active(ctx context.Context) (string, error) {
	// `status` reports "running" for a dead instance on OpenWrt <= 23.05; use
	// `running`, like install.sh does.
	if _, err := b.run.Run(ctx, b.unitPath(), "running"); err == nil {
		return StateRunning, nil
	}
	return StateStopped, nil
}

// kernelBaseDir derives the kernel install base directory from a kernel binary
// path (<base>/kernels/<name>/<version>/<binary>): three levels up.
func kernelBaseDir(bin string) string {
	if bin == "" {
		return ""
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(bin)))
}

// ---- agent supervisor fallback ---------------------------------------------

// agentBackend runs the kernel as a child of the agent's supervisor, like
// gost/realm/frp. The kernel then stops when the agent stops; the status says
// managed_by "agent" so the panel can tell the user.
type agentBackend struct {
	base
	sup      Supervisor
	stateDir string
	log      driver.Logger

	mu     sync.Mutex
	bin    string
	config string
}

func (b *agentBackend) name() string      { return BackendAgent }
func (b *agentBackend) managedBy() string { return "agent" }
func (b *agentBackend) unitPath() string  { return "" }

// exists is always true: the service definition of the fallback backend is the
// agent itself, which is by definition present. A machine with a kernel
// installed but no running child reports "stopped".
func (b *agentBackend) exists() bool { return true }

func (b *agentBackend) writeUnit(bin, configPath, configDir string) (bool, error) {
	b.mu.Lock()
	b.bin, b.config = bin, configPath
	b.mu.Unlock()
	// Always report a change: the supervisor's Start is idempotent for an
	// identical spec, so this only makes activate use restart (which is Start).
	return true, nil
}

func (b *agentBackend) removeUnit() error { return b.stop(context.Background()) }

func (b *agentBackend) enable(context.Context) error  { return nil }
func (b *agentBackend) disable(context.Context) error { return nil }

// start and restart are the same thing here: the supervisor's Start is
// idempotent for an identical spec, so it only replaces the child when the
// binary or its arguments changed.
func (b *agentBackend) start(ctx context.Context) error { return b.restart(ctx) }

func (b *agentBackend) spec() (driver.ProcSpec, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.bin == "" || b.config == "" {
		return driver.ProcSpec{}, fmt.Errorf("xraysvc: %s 的启动参数尚未设置", ServiceName)
	}
	configDir := filepath.Dir(b.config)
	spec := driver.ProcSpec{
		ID:      agentProcID,
		Path:    b.bin,
		Args:    []string{"run", "-c", b.config},
		Env:     []string{"XRAY_LOCATION_ASSET=" + configDir},
		WorkDir: configDir,
		Restart: driver.RestartPolicy{Always: true},
	}
	if b.stateDir != "" {
		spec.LogFile = filepath.Join(b.stateDir, "log", "W1nCray-xray.log")
	}
	return spec, nil
}

func (b *agentBackend) restart(ctx context.Context) error {
	spec, err := b.spec()
	if err != nil {
		return err
	}
	if err := b.sup.Start(ctx, spec); err != nil {
		return fmt.Errorf("agent supervisor 启动 %s: %w", ServiceName, err)
	}
	return nil
}

func (b *agentBackend) stop(ctx context.Context) error {
	if err := b.sup.Stop(ctx, agentProcID); err != nil {
		return fmt.Errorf("agent supervisor 停止 %s: %w", ServiceName, err)
	}
	return nil
}

func (b *agentBackend) active(context.Context) (string, error) {
	st := b.sup.Status(agentProcID)
	switch {
	case st.Running:
		return StateRunning, nil
	case st.LastExit != "":
		return StateFailed, nil
	default:
		return StateStopped, nil
	}
}

// running reports whether the supervised child is still alive. Remove uses it
// to refuse deleting the kernel files of a process that has not exited (R1-8).
func (b *agentBackend) running() bool {
	if b.sup == nil {
		return false
	}
	return b.sup.Status(agentProcID).Running
}

// ---- file helpers ----------------------------------------------------------

// writeIfChanged writes content to path when the file does not already hold
// exactly that content, and reports whether it wrote. The parent directory is
// created if needed.
func writeIfChanged(path, content string, perm os.FileMode) (bool, error) {
	if old, err := os.ReadFile(path); err == nil && string(old) == content {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), perm); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	return true, nil
}

// removeIfExists deletes a file, tolerating an already missing one.
func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
