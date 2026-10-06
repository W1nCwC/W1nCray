package bootstrap

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/panelclient"
	"github.com/W1nCwC/W1nCray/agent/reconcile"
	"github.com/W1nCwC/W1nCray/agent/spec"
)

// RemoteOptions configures StartRemote: the link between the agent and a panel
// (docs/PLAN-v7-panel-control.md).
type RemoteOptions struct {
	// URL is the panel origin; it must be https unless it is a loopback host or
	// AllowInsecureHTTP is set.
	URL string
	// MachineID and Token authenticate this machine on the panel.
	MachineID int
	Token     string
	// AllowInsecureHTTP permits plain http:// to a non-loopback host
	// (development only).
	AllowInsecureHTTP bool
	// PullInterval and ReportInterval default to 30s and are clamped to
	// [10s, 300s] by the runner.
	PullInterval   time.Duration
	ReportInterval time.Duration
	// AgentVersion is reported to the panel ("dev" when empty).
	AgentVersion string
	// Log receives the link's events; nil logs nothing. It never receives a
	// desired state, a secret or the token.
	Log driver.Logger

	// ManifestSync enables the signed kernel manifest sync loop: the link
	// fetches GET /manifest and the runtime's kernel Ensurer verifies it
	// locally before it is used.
	ManifestSync bool
	// ManifestPersistPath is where an accepted manifest is persisted
	// (see bootstrap.PersistedManifestPath). Empty disables persistence.
	ManifestPersistPath string
	// ManifestInterval is how often the manifest is re-fetched; the runner
	// defaults and clamps it.
	ManifestInterval time.Duration

	// HTTP replaces the HTTP client (tests).
	HTTP *http.Client
}

// remoteApplier adapts a Runtime to panelclient.Applier.
type remoteApplier struct{ rt *Runtime }

func (a remoteApplier) Apply(ctx context.Context, d spec.Desired) (reconcile.Report, error) {
	return a.rt.Apply(ctx, d)
}

func (a remoteApplier) Last() (reconcile.Report, bool) { return a.rt.Reconciler.Last() }

func (a remoteApplier) Health(ctx context.Context) reconcile.HealthReport {
	return a.rt.Reconciler.Health(ctx)
}

func (a remoteApplier) Stats(ctx context.Context) []driver.Counter {
	return a.rt.Reconciler.Stats(ctx)
}

// StartRemote connects the runtime to the panel: it pulls the desired state,
// applies it, acknowledges the outcome, reports the status and executes the
// whitelisted commands, until stop is called or ctx is cancelled.
//
// The link is best effort. An unreachable or misbehaving panel is logged and
// retried with backoff and never touches the instances that are running; the
// agent keeps serving its last good state. stop waits for the link to end and
// must be called before Shutdown so no apply races the teardown.
func (r *Runtime) StartRemote(ctx context.Context, o RemoteOptions) (stop func(), err error) {
	client, err := panelclient.New(panelclient.Options{
		BaseURL:           o.URL,
		MachineID:         o.MachineID,
		Token:             o.Token,
		AgentVersion:      o.AgentVersion,
		AllowInsecureHTTP: o.AllowInsecureHTTP,
		HTTP:              o.HTTP,
	})
	if err != nil {
		return nil, fmt.Errorf("bootstrap: panel link: %w", err)
	}
	log := o.Log
	if log == nil {
		log = r.log
	}
	ro := panelclient.RunnerOptions{
		AgentVersion:   o.AgentVersion,
		Engines:        r.engineNames(),
		Kernels:        r.externalKernels,
		PullInterval:   o.PullInterval,
		ReportInterval: o.ReportInterval,
		Log:            log,
	}
	// The kernel Ensurer is the local trust root of the manifest sync: the
	// panel's bytes are only accepted after its signature check.
	if o.ManifestSync && r.Kernels != nil {
		ro.Manifest = r.Kernels
		ro.ManifestPersistPath = o.ManifestPersistPath
		ro.ManifestInterval = o.ManifestInterval
	}
	runner, err := panelclient.NewRunner(client, remoteApplier{r}, ro)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: panel link: %w", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = runner.Run(runCtx)
	}()
	var once sync.Once
	return func() {
		once.Do(cancel)
		<-done
	}, nil
}

// engineNames lists the registered engines, sorted.
func (r *Runtime) engineNames() []string {
	names := make([]string, 0, len(r.Reconciler.Drivers))
	for name := range r.Reconciler.Drivers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// externalKernels returns the versions of the external kernels of the last
// apply. The builtin xray is an engine, not a kernel, and is left out.
func (r *Runtime) externalKernels() map[string]string {
	rep, ok := r.Reconciler.Last()
	if !ok {
		return nil
	}
	out := map[string]string{}
	for name, ver := range rep.Kernels {
		if ver != reconcile.BuiltinVersion {
			out[name] = ver
		}
	}
	return out
}
