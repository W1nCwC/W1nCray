package agentd

import (
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/W1nCwC/W1nCray/agent/selfupdate"
)

// SelfUpdateStartup prepares the start-up side of a committed self_update for
// an agent with no panel link. It returns nil when there is nothing to do
// (agent disabled, no state directory, or a panel is configured: bootstrap
// then owns the watchdog).
func SelfUpdateStartup(cfg *Config) *selfupdate.Startup {
	a := cfg.Agent
	if a == nil || !a.Enabled || a.StateDir == "" {
		return nil
	}
	if a.Panel != nil && a.Panel.Enabled {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	up, err := selfupdate.New(selfupdate.Options{
		ExePath:      exe,
		StateDir:     a.StateDir,
		AgentVersion: AgentVersion,
		Log:          log.StandardLogger(),
	})
	if err != nil {
		log.Warnf("agent: self-update start-up check skipped: %v", err)
		return nil
	}
	st := up.BeginStartup()
	if _, pending := st.Pending(); pending {
		// The authoritative "the new version is running" signal the watchdog
		// reads (D-M7): this process's version and pid.
		if err := up.MarkReady(); err != nil {
			log.Warnf("agent: writing the self-update ready marker: %v", err)
		}
	}
	if rb, ok := st.TakeRollback(); ok {
		log.Warnf("agent: self_update.rolled_back: version %s: %s", rb.Version, rb.Reason)
	}
	// A local-only agent has no panel to wait for; a watchdog would report
	// self_update.stalled against a link that was never configured.
	return st
}
