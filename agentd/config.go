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

// KernelAllowHTTP reports whether this machine's configuration permits plain
// http:// sources for the signed kernel manifest's assets
// (Kernels.AllowHTTP, default false). It is the one place the local switch is
// read, so the daemon, agent-apply and `W1nCray xray` cannot diverge: all
// three pass the result to bootstrap.Options.AllowHTTP.
//
// The switch is local by construction: the panel pushes a desired state, never
// agent configuration. Integrity does not depend on it (the manifest is signed
// and every asset is checked against its sha256); it exists so a self-hosted
// http-only mirror can be used.
func KernelAllowHTTP(cfg *Config) bool {
	if cfg == nil {
		return false
	}
	return cfg.Agent.KernelsAllowHTTP()
}

// NeedsXray reports whether the machine's configuration asks for the Xray
// kernel: config.yml configures at least one static node, or the panel owns the
// node list in machine mode. It is what gates the start-up migration
// (PLAN v11 §2.6).
func NeedsXray(path string, cfg *Config) bool {
	return config.HasNodes(path) || config.MachinePanel(cfg) != nil
}
