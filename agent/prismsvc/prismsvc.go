// Package prismsvc runs the W1nCray-prism kernel as a service of its own, the
// way xraysvc does for the Xray kernel: the kernel carries user traffic, so it
// must not stop when the agent restarts, upgrades or crashes.
//
// The kernel binary is installed by the generic kernel installer (the panel's
// kernel_install command pins the release asset). This package only writes the
// service definition, starts the service and waits until the kernel's control
// API answers. It supports systemd and OpenRC (the kernel is then a service of
// its own and survives the agent) and, on a machine without a supported
// service manager, the agent's own supervisor (the kernel then stops with the
// agent). procd is not supported yet; a procd machine without the supervisor
// reports why instead of guessing.
//
// Every path and every service-file line is generated here from the agent's
// own configuration. Nothing the panel sends can name a path or a command.
package prismsvc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/prismapi"
	"github.com/W1nCwC/W1nCray/agent/xraysvc"
)

// ServiceName is the fixed name of the service and its unit file.
const ServiceName = "W1nCray-prism"

// BinaryName is the installed file name of the kernel.
const BinaryName = "W1nCray-prism"

// Backends.
const (
	BackendSystemd = "systemd"
	BackendOpenRC  = "openrc"
	BackendAgent   = "agent"
)

// ManagedBy values of Status.
const (
	ManagedByService = "service"
	ManagedByAgent   = "agent"
)

// Service states.
const (
	StateRunning      = "running"
	StateStopped      = "stopped"
	StateFailed       = "failed"
	StateNotInstalled = "not_installed"
)

// ErrNotInstalled means no Prism kernel is installed on this machine.
var ErrNotInstalled = errors.New("prismsvc: the Prism kernel is not installed (install it from the panel first)")

// ErrUnsupportedInit means the machine runs an init system this package does
// not drive and no agent supervisor is available.
var ErrUnsupportedInit = errors.New("prismsvc: this machine's init system (procd) is not supported by the Prism kernel yet")

// Kernels is the kernel installer surface the manager needs
// (*kernelx.Ensurer implements it).
type Kernels interface {
	Current(name string) (driver.Installed, error)
}

// Options configures a Manager.
type Options struct {
	// Root prefixes every service-file path ("" is "/"); tests use a temp dir.
	Root string
	// Kernels resolves the installed binary.
	Kernels Kernels
	// StateDir is the agent state directory (the fallback backend keeps its
	// child's log under it).
	StateDir string
	// Runner executes service-manager commands (default xraysvc.ExecRunner).
	Runner xraysvc.Runner
	// Sup is the agent supervisor for the fallback backend (nil: none).
	Sup xraysvc.Supervisor
	// Status reads the kernel's control API for health checks (nil: skipped).
	Status func(ctx context.Context) (prismapi.Status, error)
	// Log receives the manager's events.
	Log driver.Logger
	// HealthTimeout is how long a start may take to answer (default 30 s).
	HealthTimeout time.Duration
	// HealthInterval is how often the API is polled meanwhile (default 500 ms).
	HealthInterval time.Duration
	// RecoverOrphan ends a leftover kernel process an earlier agent run
	// started under the supervisor (nil: skipped). The OpenRC backend calls it
	// once before its first start so two kernels never fight for the socket.
	RecoverOrphan func(ctx context.Context, id string) error
	// Backend overrides detection (tests).
	Backend string
}

// Manager is safe for concurrent use; Ensure and Stop are serialised.
type Manager struct {
	o       Options
	backend string
	mu      sync.Mutex

	// OpenRC bookkeeping (guarded by mu).
	enabled  bool // rc-update add succeeded in this process
	migrated bool // the supervisor's leftover was dealt with
}

// New builds a Manager and detects the service backend.
func New(o Options) (*Manager, error) {
	if o.Kernels == nil {
		return nil, errors.New("prismsvc: a kernel manager is required")
	}
	if o.Runner == nil {
		o.Runner = xraysvc.ExecRunner{}
	}
	if o.HealthTimeout <= 0 {
		o.HealthTimeout = 30 * time.Second
	}
	if o.HealthInterval <= 0 {
		o.HealthInterval = 500 * time.Millisecond
	}
	m := &Manager{o: o}
	be := o.Backend
	if be == "" {
		switch {
		case exists(o.Root, "run/systemd/system"):
			be = BackendSystemd
		case exists(o.Root, "sbin/openrc-run") && exists(o.Root, openrcSoftlevel):
			be = BackendOpenRC // OpenRC is the running init
		case exists(o.Root, "sbin/openrc-run"), exists(o.Root, "sbin/procd"):
			// OpenRC installed but not running as init (a container, say), or
			// procd: only the agent's supervisor can run the kernel.
			if o.Sup == nil {
				m.backend = ""
				return m, nil // Ensure reports ErrUnsupportedInit
			}
			be = BackendAgent
		default:
			be = BackendAgent
		}
	}
	if be == BackendAgent && o.Sup == nil {
		return nil, errors.New("prismsvc: no init system was found and the agent supervisor is not available")
	}
	m.backend = be

	return m, nil
}

// Backend reports the detected backend ("" when unsupported).
func (m *Manager) Backend() string { return m.backend }

// SocketPath is the control socket the kernel is started with.
func SocketPath() string {
	return filepath.Join(runtimeDir(), prismapi.SocketName)
}

func runtimeDir() string {
	if d := os.Getenv("W1NCRAY_PRISM_RUNTIME_DIR"); d != "" {
		return d
	}
	return "/run/" + prismapi.RuntimeDirName
}

// KernelStateDir is the kernel's state directory.
func KernelStateDir() string {
	if d := os.Getenv("W1NCRAY_PRISM_STATE_DIR"); d != "" {
		return d
	}
	return "/var/lib/" + prismapi.StateDirName
}

// Ensure brings the kernel service up: the unit is written, enabled and
// started, a changed binary restarts it, and the call returns once the control
// API answers. An already healthy kernel is left alone.
func (m *Manager) Ensure(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.backend == "" {
		return ErrUnsupportedInit
	}
	cur, err := m.o.Kernels.Current(prismapi.KernelName)
	if err != nil || cur.Path == "" {
		return ErrNotInstalled
	}
	switch m.backend {
	case BackendSystemd:
		return m.ensureSystemd(ctx, cur)
	case BackendOpenRC:
		return m.ensureOpenRC(ctx, cur)
	default:
		return m.ensureAgent(ctx, cur)
	}
}

// Stop stops the service (the installation and the unit stay).
func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch m.backend {
	case BackendSystemd:
		if !exists(m.o.Root, systemdUnitPath) {
			return nil
		}
		return m.systemctl(ctx, "stop", ServiceName)
	case BackendOpenRC:
		if !exists(m.o.Root, openrcScriptPath) {
			return nil
		}
		return m.rcService(ctx, "stop")
	case BackendAgent:
		return m.o.Sup.Stop(ctx, agentProcID)
	}
	return nil
}

// Remove stops the service and removes its definition (the unit or init
// script and the boot-time enablement). The installed kernel file stays. It
// works for every backend and is safe to repeat.
func (m *Manager) Remove(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch m.backend {
	case BackendSystemd:
		return m.removeSystemd(ctx)
	case BackendOpenRC:
		return m.removeOpenRC(ctx)
	case BackendAgent:
		return m.o.Sup.Stop(ctx, agentProcID)
	}
	return nil
}

// Status reports the installed version and the service state.
type Status struct {
	Backend string
	// ManagedBy is "service" when the kernel is a service of its own (it
	// survives the agent) and "agent" when the agent's supervisor runs it.
	ManagedBy string
	State     string
	Version   string
	Path      string
	Error     string
}

// Status reads the service state.
func (m *Manager) Status(ctx context.Context) Status {
	st := Status{Backend: m.backend}
	switch m.backend {
	case BackendSystemd, BackendOpenRC:
		st.ManagedBy = ManagedByService
	case BackendAgent:
		st.ManagedBy = ManagedByAgent
	}
	cur, err := m.o.Kernels.Current(prismapi.KernelName)
	if err != nil || cur.Path == "" {
		st.State = StateNotInstalled
		return st
	}
	st.Version, st.Path = cur.Version, cur.Path
	if m.o.Status != nil {
		sctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		ks, kerr := m.o.Status(sctx)
		cancel()
		if kerr == nil {
			if ks.State == "failed" {
				st.State, st.Error = StateFailed, ks.LastError
			} else {
				st.State = StateRunning
			}
			return st
		}
	}
	switch m.backend {
	case BackendSystemd:
		out, _ := m.o.Runner.Run(ctx, "systemctl", "is-active", ServiceName)
		switch strings.TrimSpace(string(out)) {
		case "active", "activating":
			st.State = StateRunning
		case "failed":
			st.State = StateFailed
		default:
			st.State = StateStopped
		}
	case BackendOpenRC:
		st.State = m.openrcState(ctx)
	case BackendAgent:
		if m.o.Sup.Status(agentProcID).Running {
			st.State = StateRunning
		} else {
			st.State = StateStopped
		}
	default:
		st.State, st.Error = StateStopped, ErrUnsupportedInit.Error()
	}
	return st
}

func (m *Manager) logf(format string, args ...any) {
	if m.o.Log != nil {
		m.o.Log.Infof(format, args...)
	}
}

func exists(root, p string) bool {
	_, err := os.Stat(resolve(root, p))
	return err == nil
}

func resolve(root, p string) string {
	if root == "" {
		return "/" + strings.TrimPrefix(p, "/")
	}
	return filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(p, "/")))
}

// waitHealthy polls the control API until it answers.
func (m *Manager) waitHealthy(ctx context.Context) error {
	if m.o.Status == nil {
		return nil
	}
	deadline := time.Now().Add(m.o.HealthTimeout)
	var last error
	for {
		sctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		_, err := m.o.Status(sctx)
		cancel()
		if err == nil {
			return nil
		}
		last = err
		if time.Now().After(deadline) {
			return fmt.Errorf("prismsvc: the kernel did not answer within %s: %w", m.o.HealthTimeout, last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(m.o.HealthInterval):
		}
	}
}
