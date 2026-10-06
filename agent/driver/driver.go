// Package driver defines the interface between the agent core and a kernel
// driver (xray, gost, frp, realm). A driver turns declarative instances into
// that kernel's configuration and runs them; it never executes anything the
// panel supplied verbatim: every external command is an argv array and every
// field that reaches a config file is validated or strongly typed.
//
// Contract owner: the agent core. Do not change this file from a driver
// package; request additions from the owner instead.
package driver

import (
	"context"
	"os"
	"time"

	"github.com/W1nCwC/W1nCray/agent/spec"
)

// Logger is satisfied by *logrus.Entry.
type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

// Caps declares what a driver can do. The core uses it to reject
// unsupported instance features and to choose an engine for "auto"; the
// panel uses it to grey out options. Values must be accurate: a capability
// that is not implemented and tested must not be claimed.
type Caps struct {
	Name    string      // xray | gost | frp | realm
	Kinds   []spec.Kind // supported instance kinds
	Network []string    // "tcp", "udp"

	TunnelTypes []string // tunnel carriers usable for entry/exit/reverse
	Reverse     bool

	ProxyIn     bool // accept PROXY protocol on the listener (TCP)
	ProxyOut    bool // send PROXY protocol (TCP)
	ProxyOutUDP bool // always false in practice

	Balance     []string // strategies
	HealthCheck string   // none | passive | active

	Stats  string // none | counters | prometheus | api
	Reload string // none | hot | signal | api
	// DisruptsOnChange is true if changing one instance can drop live
	// connections of other instances of the same driver.
	DisruptsOnChange bool

	External      bool  // needs a kernel binary managed by the kernel manager
	InstalledSize int64 // approximate installed bytes of the kernel (0 for builtin)
}

// Installed describes the kernel binary the driver will run.
type Installed struct {
	Path    string // absolute path; empty for the builtin xray
	Version string
}

// Runtime is what the core hands to a driver on every call.
type Runtime struct {
	Kernel   Installed
	StateDir string // driver-private writable directory (0700), holds last-good config
	Sup      Supervisor
	Log      Logger
}

// Rendered is an instance with its rendered, deterministic artifact.
type Rendered struct {
	Instance spec.Instance
	Artifact Artifact
}

// Artifact is the output of Render: pure function of the instance (and the
// driver version), so equal inputs give equal hashes.
type Artifact struct {
	Files      map[string][]byte // relative name -> content (config files)
	Hash       string            // sha256 hex over Files and driver-relevant args
	PortClaims []PortClaim
}

// PortClaim is a listener the instance will bind.
type PortClaim struct {
	Proto string // tcp | udp
	Addr  string
	Port  int
	Owner string // instance id
}

// ApplyResult reports what Apply did, per instance id.
type ApplyResult struct {
	Running   []string
	Failed    map[string]string // id -> error
	Restarted []string          // instances whose process/listener was restarted
	// Disrupted lists instances whose established connections were cut
	// (including collateral ones).
	Disrupted []string
}

// Counter is a cumulative traffic/connection counter for one instance.
// Values never decrease within one driver process lifetime; the panel
// handles resets.
type Counter struct {
	InstanceID  string
	BytesUp     uint64 // client -> target
	BytesDown   uint64
	ConnsActive uint64
	ConnsTotal  uint64
}

// InstanceHealth is the observed state of one instance.
type InstanceHealth struct {
	Running bool
	Err     string
	// ConfigHash is the artifact hash actually running.
	ConfigHash string
	// Listening reports whether every claimed port accepted a probe.
	Listening bool
	// Targets holds per-target liveness when the driver knows it.
	Targets map[string]bool
}

// Health is the driver-wide state, keyed by instance id.
type Health struct {
	Instances map[string]InstanceHealth
}

// Driver is implemented once per kernel.
type Driver interface {
	Caps() Caps

	// Validate checks engine-specific constraints (features the engine
	// lacks, values it cannot express). It must not touch the system.
	Validate(in spec.Instance) error
	// Render is a pure, deterministic function.
	Render(in spec.Instance) (Artifact, error)

	// Apply makes the kernel run exactly the given set of this driver's
	// instances (full set, not a delta). The driver diffs against what it
	// last applied (kept in rt.StateDir), changes as little as possible,
	// keeps the previous good configuration, and on failure restores it.
	Apply(ctx context.Context, rt Runtime, set []Rendered) (ApplyResult, error)
	// Rollback restores the last good configuration written by Apply.
	Rollback(ctx context.Context, rt Runtime) error
	// Stop stops the given instances (all if ids is empty) and cuts their
	// established connections where the kernel allows it.
	Stop(ctx context.Context, rt Runtime, ids ...string) error

	Stats(ctx context.Context, rt Runtime) ([]Counter, error)
	Health(ctx context.Context, rt Runtime) Health
}

// RestartPolicy of a supervised process.
type RestartPolicy struct {
	Always     bool
	MinBackoff time.Duration // default 1s
	MaxBackoff time.Duration // default 30s
	// ResetAfter is how long a process must stay up before the backoff
	// resets (default 2 minutes).
	ResetAfter time.Duration
}

// ProcSpec describes one supervised child process. Args is an argv array;
// there is no shell.
type ProcSpec struct {
	ID          string // unique, e.g. "gost/main"
	Path        string
	Args        []string
	Env         []string // appended to a minimal base environment
	WorkDir     string
	LogFile     string // stdout+stderr, rotated by the supervisor
	Restart     RestartPolicy
	StopTimeout time.Duration // SIGTERM grace before SIGKILL (default 5s)
}

// ProcStatus is the supervisor's view of a process.
type ProcStatus struct {
	Running  bool
	PID      int
	Restarts int
	Since    time.Time
	LastExit string // human readable
}

// Supervisor runs child processes. Implemented by the agent core.
type Supervisor interface {
	// Start starts or, if the id already exists with an identical spec,
	// leaves the process running. A different spec replaces it (stop+start).
	Start(ctx context.Context, p ProcSpec) error
	Stop(ctx context.Context, id string) error
	Signal(id string, sig os.Signal) error
	Status(id string) ProcStatus
}
