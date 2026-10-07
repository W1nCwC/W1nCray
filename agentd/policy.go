// This file translates the resolved local agent policy into the runtime
// options: the interactive terminal (D8), the confined file operations (D9)
// and the managed xray files (D4/D5). The translation lives here because that
// is where the config file paths are known; the behaviour lives in
// agent/terminal, agent/fileops and agent/filesync.

package agentd

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
// config.yml the agent was started with; its directory is the xray root.
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

// FilesOptionsFor translates the local Files policy into the managed-file
// layer's options (D4/D5). configPath is the live config.yml: the xray
// configuration directory is where the four JSON files and the two geo
// databases live, so that is the only place a managed file is written.
// config.yml is only manageable when the machine uses the agent.yml layout
// (ruling 2): otherwise that file is the agent's own configuration and a remote
// write would overwrite it.
//
// The command package (agent-apply) uses it too, so the offline run reports the
// same local policy as the running service.
func FilesOptionsFor(cfg *Config, configPath string) *bootstrap.FilesOptions {
	if cfg == nil || cfg.Agent == nil {
		return nil
	}
	a := cfg.Agent
	var maxBytes, maxGeo int64
	if a.Files != nil {
		maxBytes, maxGeo = a.Files.MaxBytes, a.Files.MaxGeoBytes
	}
	return &bootstrap.FilesOptions{
		ConfigDir:       filepath.Dir(configPath),
		ConfigPath:      configPath,
		StateDir:        filepath.Join(a.StateDir, "filesync"),
		MaxBytes:        maxBytes,
		MaxGeoBytes:     maxGeo,
		LayoutSeparated: a.SeparatedLayout(),
	}
}
