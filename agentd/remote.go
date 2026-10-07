package agentd

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/W1nCwC/W1nCray/agent/bootstrap"
)

// startRemoteLocked links the agent to the panel when it is configured. A
// problem with the link (unreadable token file, bad options) is logged and
// leaves the agent running on its local state. The caller must hold d.mu.
func (d *Daemon) startRemoteLocked(a *AgentConfig, rt *bootstrap.Runtime) {
	if a == nil || a.Panel == nil || !a.Panel.Enabled {
		return
	}
	pc := a.Panel
	token, err := pc.ResolveToken()
	if err != nil {
		log.Errorf("agent: panel link not started: %v", err)
		return
	}
	pull, report := pc.Intervals()
	o := bootstrap.RemoteOptions{
		URL:               pc.URL,
		MachineID:         pc.MachineID,
		Token:             token,
		AllowInsecureHTTP: pc.AllowInsecureHTTP,
		PullInterval:      pull,
		ReportInterval:    report,
		AgentVersion:      AgentVersion,
		Log:               log.StandardLogger(),
		// The persistent WebSocket channel rides on the same validated link:
		// it only exists once a token and a machine id did. Without them
		// startRemoteLocked returned above.
		WS:          true,
		AgentConfig: a,
		// A committed self_update swaps the executable and asks this process to
		// exit; the self-update watchdog (or the service manager) then brings
		// the new binary back up. Without the hook the command is not
		// registered.
		OnRestart: RequestRestart,
	}
	// The managed-file layer is validated by the Xray kernel when it is
	// installed: bootstrap installs the kernel validator from Options.Xray and
	// a nil-safe "Xray 内核未安装" refusal otherwise, so an apply is refused
	// with an explicit reason instead of a half-applied file set.
	if pc.ManifestSyncEnabled() {
		o.ManifestSync = true
		o.ManifestPersistPath = bootstrap.PersistedManifestPath(a.StateDir)
		o.ManifestInterval = pc.ManifestInterval()
	}
	stop, err := rt.StartRemote(context.Background(), o)
	if err != nil {
		log.Errorf("agent: panel link not started: %v", err)
		return
	}
	d.remote = stop
	log.Infof("agent: linked to the panel %s as machine %d", pc.URL, pc.MachineID)
	if o.ManifestSync {
		log.Infof("agent: kernel manifest sync enabled (every %s, persisted to %s)", o.ManifestInterval, o.ManifestPersistPath)
	}
}
