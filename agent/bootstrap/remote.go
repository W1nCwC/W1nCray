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
	"github.com/W1nCwC/W1nCray/agent/filesync"
	"github.com/W1nCwC/W1nCray/agent/opscmd"
	"github.com/W1nCwC/W1nCray/agent/panelclient"
	"github.com/W1nCwC/W1nCray/agent/reconcile"
	"github.com/W1nCwC/W1nCray/agent/selfupdate"
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

	// Reloader rebuilds the xray instance after the managed files changed. It
	// is the panel's ReloadForAgent (bootstrap must not import panel); nil
	// leaves the managed-file layer without a reload, so an apply that needs
	// one is refused instead of half-applied.
	Reloader filesync.Reloader
	// FilesValidator pre-checks a staged managed-file set. It is the panel's
	// validator (it owns the live core options); nil leaves the layer without a
	// validator, so every apply is refused.
	FilesValidator filesync.Validator

	// HTTP replaces the HTTP client (tests).
	HTTP *http.Client

	// OnRestart asks the process owner to exit so the binary that a committed
	// self_update put in place takes over. Without it the self_update command
	// is not registered and the upgrade capability is not declared.
	OnRestart func()
}

// filesSource adapts a Runtime to filesync.Source: the managed files of the
// desired state the reconciler last applied.
type filesSource struct{ rt *Runtime }

func (s filesSource) DesiredFiles() []spec.FileRef {
	if s.rt == nil || s.rt.Reconciler == nil {
		return nil
	}
	return s.rt.Reconciler.LastDesired().Files
}

// blobFetcher adapts the panel HTTP client to filesync.BlobFetcher. The client
// validates the sha256, sends If-None-Match and enforces the transport limit;
// the applier re-hashes what comes back before anything is written.
type blobFetcher struct{ api *panelclient.Client }

func (f blobFetcher) Fetch(ctx context.Context, sha string) ([]byte, bool, error) {
	res, err := f.api.Blob(ctx, panelclient.BlobRequest{SHA256: sha})
	if err != nil {
		return nil, false, err
	}
	if res.NotModified {
		return nil, true, nil
	}
	return res.Raw, false, nil
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

	// Self-update start-up: a process that came out of a committed update has
	// to prove itself. It confirms once the panel answered (OnConnected) and
	// reports self_update.stalled when that never happens; it never rolls
	// itself back, because a panel outage is not a broken binary (ruling 11).
	var startup *selfupdate.Startup
	if r.Updater != nil {
		startup = r.Updater.BeginStartup()
	}

	ro := panelclient.RunnerOptions{
		AgentVersion:   o.AgentVersion,
		Engines:        r.engineNames(),
		Kernels:        r.externalKernels,
		KernelsList:    r.KernelEntries,
		PullInterval:   o.PullInterval,
		ReportInterval: o.ReportInterval,
		Log:            log,
		// While the WebSocket is handshaken the socket carries the load; a
		// disconnect clears Connected() at once and the host comes back
		// (design section 3.3).
		SuppressHost: func() bool { return wsClient != nil && wsClient.Connected() },
		OnConnected: func() {
			if startup == nil {
				return
			}
			if err := startup.Confirm(); err != nil {
				log.Warnf("bootstrap: confirming the self-update: %v", err)
			}
		},
	}
	// The operations registry serves every command the Runner does not
	// implement itself, over both channels (design section 2.1).
	if r.Ops != nil {
		ro.Commands = r.Ops
	}
	// The managed-file layer (D4/D5) is completed now: its blob fetcher is this
	// link's HTTP client and its desired-state source is this runtime. It is
	// installed on the registry, so files_apply / files_validate /
	// files_rollback answer "not_supported" until this point and are served
	// from here on.
	if r.Files != nil && r.Files.Enabled() && r.Ops != nil {
		r.Files.applier.SetFetch(blobFetcher{api: client})
		r.Files.applier.SetSource(filesSource{rt: r})
		if o.Reloader != nil {
			r.Files.applier.SetReload(o.Reloader)
		}
		if o.FilesValidator != nil {
			r.Files.applier.SetValidator(o.FilesValidator)
		}
		r.Ops.SetFiles(r.Files)
	}
	// The declared capabilities travel in /config only when the WebSocket
	// channel (which is what declares them) is running.
	if o.WS && streams != nil {
		// Both are set: the list is recomputed on every pull (FeaturesFunc
		// wins), so a capability that appears later — the kernel installer
		// getting a signed manifest — is declared at the same time in hello
		// and in /config.features (ruling 1).
		ro.Features = streams.Capabilities()
		ro.FeaturesFunc = streams.Capabilities
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
	// self_update is registered here, not in Boot: it needs the restart hook
	// the process owner supplies, and a machine that cannot replace its own
	// executable must not declare the capability. A registration failure
	// leaves the command unregistered, which the panel sees as "unsupported".
	if r.Ops != nil && r.Updater != nil && r.upgradeReady && o.OnRestart != nil {
		if err := opscmd.RegisterSelfUpdate(r.Ops, r.Updater, o.OnRestart); err != nil {
			log.Warnf("bootstrap: self_update is not available: %v", err)
		}
	}
	runner, err := panelclient.NewRunner(client, remoteApplier{r}, ro)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: panel link: %w", err)
	}

	// Long commands (kernel_install today, self_update and files_apply later)
	// answer "accepted" and deliver their final result through this sink. It
	// exists for the HTTP link even without a WebSocket; the socket is adopted
	// below when it is running.
	late := &lateResult{runner: runner, log: log}
	if r.Ops != nil {
		r.Ops.SetSink(late)
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
		// The files hint applies the managed files; nil when the local policy
		// has no xray directory to manage (the hint then answers
		// not_supported, ruling 5).
		if r.Files != nil && r.Files.Enabled() {
			agentOpts.Files = r.Files
		}
		// The nodes hint is always wired, so it is never silently ignored; the
		// local module gate lives inside the hook (ruling 6).
		agentOpts.Nodes = o.WSNodes
		if agentOpts.Nodes == nil {
			agentOpts.Nodes = xrayNodeHint{enabled: o.AgentConfig.XrayNodesEnabled(), refresh: runner.RequestRefresh, log: log}
		}
		// The interactive terminal is wired only when this machine really has
		// one; a nil sink is what answers term.error{terminal_disabled}
		// (WP-G6 acceptance 3). The local switch was already applied at Boot,
		// so a remote frame can never turn it on (ruling 13).
		var termSink *wsTerminal
		if r.Terminal != nil {
			termSink = &wsTerminal{m: r.Terminal, log: log}
			agentOpts.Terminal = termSink
		}
		wsAgent, err = ws.NewAgent(wsOpts, agentOpts)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: panel link: %w", err)
		}
		if termSink != nil {
			// The pump's outlet is the agent's own send queue, so term.opened,
			// term.data and term.exit travel on the connection the term.open
			// arrived on. It is wired before Run starts, so no frame can race
			// an unwired adapter.
			termSink.setSend(wsAgent.SendFrame)
		}
		wsClient = wsAgent.Client()
		if c, ok := commands.(*wsCommands); ok {
			c.client = wsClient
		}
		late.ws = wsClient
		// kernel.installed / kernel.removed (protocol ruling 10). The event
		// frame is the WebSocket's; without a socket there is no event channel
		// in the HTTP contract, so nothing is sent.
		if r.Ops != nil {
			r.Ops.SetEvents(opscmd.EventFunc(wsAgent.SendEvent))
		}
		// Terminal session open/close: metadata only, as event frames. The
		// sink exists only with a socket, because the HTTP contract has no
		// event channel.
		if r.Terminal != nil {
			r.Terminal.SetAuditor(terminalAuditor{events: wsAgent, log: log})
		}
		// A rollback the self-update watchdog performed before this process
		// started is reported once, now that there is a channel (ruling 10).
		if startup != nil && r.Ops != nil {
			if rb, ok := startup.TakeRollback(); ok {
				msg := fmt.Sprintf("version %s was rolled back: %s", rb.Version, rb.Reason)
				log.Warnf("bootstrap: self_update.rolled_back: %s", msg)
				r.Ops.EmitEvent("self_update.rolled_back", "warn", msg)
			}
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
	// A pending update that never reaches the panel is reported, never rolled
	// back (protocol ruling 11).
	if startup != nil {
		go startup.WatchStalled(runCtx, func(kind, level, message string) {
			log.Warnf("bootstrap: %s: %s", kind, message)
			if r.Ops != nil {
				r.Ops.EmitEvent(kind, level, message)
			}
		})
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
	if status != panelclient.ResultAccepted {
		c.runner.MarkAnswered(id)
	}
	// A long command keeps its in-flight slot until its final result is
	// delivered (lateResult), so a redelivery in between is dropped instead of
	// running the command twice.
	return "", nil, ws.ErrAnswered
}

func (c *wsCommands) Refresh() { c.runner.RequestRefresh() }
