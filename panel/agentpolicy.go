// This file translates the resolved local agent policy into the WP-G6 options:
// the interactive terminal (D8) and the confined file operations (D9). The
// translation lives in panel because that is where the config file paths are
// known; the behaviour lives in agent/terminal and agent/fileops.

package panel

import (
	"path/filepath"

	"github.com/W1nCwC/W1nCray/agent/agentcfg"
	"github.com/W1nCwC/W1nCray/agent/bootstrap"
	"github.com/W1nCwC/W1nCray/agent/fileops"
	"github.com/W1nCwC/W1nCray/agent/terminal"
)

// terminalOptions maps the local Terminal section onto terminal.Options.
// Enabled follows agentcfg.TerminalEnabled(): on unless the machine explicitly
// turned it off (RULINGS v9 ruling 17). The limits are the validated
// agentcfg values; agentcfg refuses more than two sessions, so the manager never
// has to clamp.
func terminalOptions(a *agentcfg.Config) terminal.Options {
	if a == nil {
		return terminal.Options{}
	}
	return terminal.Options{
		Enabled:     a.TerminalEnabled(),
		MaxSessions: a.Terminal.Sessions(),
		IdleTimeout: a.Terminal.IdleTimeout(),
		MaxLifetime: a.Terminal.MaxDuration(),
	}
}

// fileOptions maps the resolved Files section onto fileops.Options. The roots
// are the absolute directories ResolveLocalPolicy produced (the xray
// configuration directory and the agent state directory by default), and the
// excluded list is what keeps agent.yml, desired.json and last_good.json out of
// reach even though a root contains them (ruling 9/13). configPath is the
// config.yml the panel was started with; its directory is the xray root.
func fileOptions(configPath string, a *agentcfg.Config) fileops.Options {
	if a == nil || a.Files == nil {
		return fileops.Options{}
	}
	xrayDir := ""
	if configPath != "" {
		xrayDir = filepath.Dir(configPath)
	}
	return fileops.Options{
		Roots:        bootstrap.FileRoots(a.Files.Roots, xrayDir, a.StateDir),
		Unrestricted: a.Files.Unrestricted,
		AllowExec:    a.Files.AllowExec,
		Excluded:     a.ExcludedFiles(),
	}
}
