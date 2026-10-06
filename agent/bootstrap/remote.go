package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/W1nCwC/W1nCray/agent/agentcfg"
	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/panelclient"
	"github.com/W1nCwC/W1nCray/agent/reconcile"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/agent/telemetry"
	"github.com/W1nCwC/W1nCray/agent/ws"
	"github.com/W1nCwC/W1nCray/agent/wsproto"
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

	// WS enables the persistent WebSocket channel next to the HTTP link. It is
	// only started once the HTTP options validated: without a machine id and a
	// token there is nothing to authenticate the upgrade with, and the agent
	// then behaves exactly as before the channel existed.
	WS bool
	// AgentConfig is the local agent policy the WebSocket channel reports
	// (hello.policy, capabilities) and enforces. nil means the defaults of a
	// zero Config.
	AgentConfig *agentcfg.Config
	// WSStreams overrides the telemetry source (tests). nil builds one from the
	// runtime and a Collector that also supplies the components probe.
	WSStreams ws.Streams
	// WSCommands overrides the shared command entry point (tests). nil uses the
	// Runner, so the HTTP and WS channels share one whitelist and one id space.
	WSCommands ws.Commands
	// WSNodes overrides the xray-nodes hint hook (tests). nil uses the local
	// module gate; batch 1 only pulls the desired state again.
	WSNodes ws.NodeToggle

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
// With WS set it also runs the persistent WebSocket channel (hello, telemetry,
// components, commands, hints). The HTTP link stays the fallback; while the
// socket is handshaken the HTTP report omits the host payload so the two
// channels never write the same numbers twice (design section 3.3).
//
// The link is best effort. An unreachable or misbehaving panel is logged and
// retried with backoff and never touches the instances that are running; the
// agent keeps serving its last good state. stop waits for the WebSocket to end
// first and then for the HTTP link, and must be called before Shutdown so no
// apply races the teardown.
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

	// The WebSocket endpoint is derived from the same validated base URL the
	// HTTP client uses, so the two channels can never point at different
	// panels (design R9). It is resolved before the runner so a bad URL fails
	// before anything starts.
	var (
		wsAgent   *ws.Agent
		wsClient  *ws.Client
		wsOpts    ws.Options
		streams   = o.WSStreams
		agentOpts ws.AgentOptions
	)
	if o.WS {
		base, err := panelclient.ValidateBaseURL(o.URL, o.AllowInsecureHTTP)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: panel link: %w", err)
		}
		endpoint, err := wsEndpoint(base)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: panel link: %w", err)
		}
		if streams == nil {
			collector := telemetry.New(telemetry.Options{
				Log:          log,
				AgentVersion: o.AgentVersion,
				Components:   r.ComponentProbe(),
			})
			streams = r.Streams(collector, o.AgentConfig)
		}
		wsOpts = ws.Options{
			URL:               endpoint,
			MachineID:         o.MachineID,
			Token:             o.Token,
			AgentVersion:      o.AgentVersion,
			AllowInsecureHTTP: o.AllowInsecureHTTP,
			HTTP:              o.HTTP,
			Log:               log,
		}
	}

	ro := panelclient.RunnerOptions{
		AgentVersion:   o.AgentVersion,
		Engines:        r.engineNames(),
		Kernels:        r.externalKernels,
		PullInterval:   o.PullInterval,
		ReportInterval: o.ReportInterval,
		Log:            log,
		// While the WebSocket is handshaken the socket carries the load; a
		// disconnect clears Connected() at once and the host comes back
		// (design section 3.3).
		SuppressHost: func() bool { return wsClient != nil && wsClient.Connected() },
	}
	// The declared capabilities travel in /config only when the WebSocket
	// channel (which is what declares them) is running.
	if o.WS && streams != nil {
		ro.Features = streams.Capabilities()
		// The instance id is generated once and handed to both channels, so the
		// panel sees one agent run and not two. Without the socket the Runner
		// keeps generating its own id exactly as before.
		ro.InstanceID = panelclient.NewInstanceID()
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

	if o.WS {
		// The command entry point is shared with the HTTP runner: one
		// whitelist, one id space, one answer per command (design 3.4).
		commands := o.WSCommands
		if commands == nil {
			commands = &wsCommands{runner: runner, log: log}
		}
		agentOpts.Streams = streams
		agentOpts.Log = log
		// The hello reports the id the HTTP link is using.
		agentOpts.InstanceID = runner.InstanceID()
		agentOpts.AgentVersion = o.AgentVersion
		agentOpts.Commands = commands
		// The nodes hint is always wired, so it is never silently ignored; the
		// local module gate lives inside the hook (ruling 6).
		agentOpts.Nodes = o.WSNodes
		if agentOpts.Nodes == nil {
			agentOpts.Nodes = xrayNodeHint{enabled: o.AgentConfig.XrayNodesEnabled(), refresh: runner.RequestRefresh, log: log}
		}
		wsAgent, err = ws.NewAgent(wsOpts, agentOpts)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: panel link: %w", err)
		}
		wsClient = wsAgent.Client()
		if c, ok := commands.(*wsCommands); ok {
			c.client = wsClient
		}
	}

	// The WebSocket and the HTTP link run on separate contexts so stop can end
	// them in the required order (design section 3.6).
	runCtx, cancelRun := context.WithCancel(ctx)
	httpCtx, cancelHTTP := context.WithCancel(runCtx)
	var (
		wsCtx    context.Context
		cancelWS context.CancelFunc
		wsDone   chan struct{}
	)
	if wsAgent != nil {
		wsCtx, cancelWS = context.WithCancel(runCtx)
	}

	runnerDone := make(chan struct{})
	go func() {
		defer close(runnerDone)
		_ = runner.Run(httpCtx)
	}()
	if wsAgent != nil {
		wsDone = make(chan struct{})
		go func() {
			// The order matters: the log line must be written before the
			// channel closes, so a close-order test (and an operator reading
			// the log) sees the WebSocket stop before the HTTP link.
			defer close(wsDone)
			defer log.Infof("agent: websocket channel stopped")
			_ = wsAgent.Run(wsCtx)
		}()
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			// The WebSocket goes first: its commands and hints run through the
			// same Runner the HTTP link owns, so the Runner must still be alive
			// while the socket stops.
			if cancelWS != nil {
				cancelWS()
				<-wsDone
			}
			cancelHTTP()
			<-runnerDone
			cancelRun()
		})
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

// wsEndpoint derives the agent WebSocket endpoint from a validated panel base
// URL: the same origin, the contract's fixed path, and never a token
// (docs/WS-PROTOCOL.md section 1).
func wsEndpoint(base string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("panel URL: %w", err)
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("panel URL has unsupported scheme %q", u.Scheme)
	}
	u.Path = ws.WSPath
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

// wsCommands is the single command entry point shared with the HTTP Runner: it
// de-duplicates by id across both channels and answers the panel over the
// WebSocket. A frame that cannot be delivered leaves the id unanswered (not
// remembered), so the HTTP fallback still gets a result (design section 3.4).
type wsCommands struct {
	runner *panelclient.Runner
	client *ws.Client // set once the Agent exists, before Run starts
	log    driver.Logger
}

var _ ws.Commands = (*wsCommands)(nil)

func (c *wsCommands) Execute(ctx context.Context, id string, cmd wsproto.Cmd, expiresAt int64) (string, any, error) {
	status, result, err := c.runner.ExecuteCommand(ctx, id, cmd.Type, cmd.Args, expiresAt)
	switch {
	case errors.Is(err, panelclient.ErrCommandAnswered):
		// The other channel already answered this id: a second answer would
		// give the panel two results for one command.
		return "", nil, ws.ErrAnswered
	case err != nil:
		return "", nil, err
	}
	env, encErr := ws.Encode(wsproto.TypeCmdResult, id, wsproto.CmdResult{Status: status, Result: json.RawMessage(result)})
	if encErr != nil {
		return "", nil, encErr
	}
	if sendErr := c.client.SendWait(ctx, env, ws.CommandQueueTimeout); sendErr != nil {
		c.log.Warnf("bootstrap: cmd.result for %q not delivered over the WebSocket: %v", id, sendErr)
		// Not remembered: a redelivery (over either channel) is answered.
		return "", nil, ws.ErrAnswered
	}
	c.runner.MarkAnswered(id)
	// The result is on the wire; the Agent must not send it a second time.
	return "", nil, ws.ErrAnswered
}

func (c *wsCommands) Refresh() { c.runner.RequestRefresh() }
