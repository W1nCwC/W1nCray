// Package agentd is the W1nCray agent daemon: it boots the agent runtime (the
// supervisor, the external kernels, the reconciler), links it to the panel,
// watches agent.yml and the desired-state file, and owns the terminal, the
// confined file operations and self-update.
//
// It must not link Xray-core: the Xray instance lives in the separate
// W1nCray-xray program (package xraynode), and this package reaches it only
// through the xrayapi.Service interface, which is nil on a machine where the
// kernel is not installed.
package agentd

import (
	"github.com/W1nCwC/W1nCray/agent/agentcfg"
	"github.com/W1nCwC/W1nCray/config"
)

// The configuration types are shared with the Xray kernel program (package
// config is free of any Xray-core dependency); the aliases keep the names this
// package used when it was part of package panel.
type (
	Config           = config.Config
	AgentConfig      = config.AgentConfig
	AgentPanelConfig = config.AgentPanelConfig
	AgentPolicy      = config.AgentPolicy
	TerminalConfig   = config.TerminalConfig
	FilesConfig      = config.FilesConfig
	ModuleConfig     = config.ModuleConfig
)

// LoadConfig reads only the agent's own configuration: the "Agent:" block of
// config.yml, or agent.yml when it exists next to it. The Xray section of
// config.yml is never parsed here, so a broken Nodes section cannot keep the
// agent from starting.
func LoadConfig(path string) (*Config, error) { return config.LoadAgent(path) }

// AgentSource returns the file kind the effective agent configuration came
// from.
func AgentSource(c *Config) agentcfg.Source { return c.AgentSource() }
