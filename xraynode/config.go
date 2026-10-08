// Package xraynode is the W1nCray Xray kernel service: it builds and rebuilds
// the Xray-core instance, runs one Xboard node controller per configured node
// (static Nodes or the machine's node list discovered from the panel), watches
// the Xray configuration files and exposes a local status interface.
//
// It is the only package that links Xray-core; the agent program must not.
package xraynode

import (
	"io/fs"

	"github.com/W1nCwC/W1nCray/agent/agentcfg"
	"github.com/W1nCwC/W1nCray/config"
	"github.com/W1nCwC/W1nCray/nodecfg"
)

// The configuration types are shared with the agent program (package config is
// free of any Xray-core dependency); the aliases keep the names this package
// used when it was part of package panel.
type (
	Config           = config.Config
	NodesConfig      = config.NodesConfig
	LogConfig        = config.LogConfig
	ConnectionConfig = config.ConnectionConfig
	AgentConfig      = agentcfg.Config
	AgentPanelConfig = agentcfg.PanelConfig
	AgentPolicy      = agentcfg.Policy
	TerminalConfig   = agentcfg.TerminalConfig
	FilesConfig      = agentcfg.FilesConfig
	ModuleConfig     = agentcfg.ModuleConfig
)

// LoadConfig reads and validates the whole config file (Xray side and agent
// side). The agent's own configuration comes from agent.yml when it exists and
// from the "Agent:" block otherwise.
func LoadConfig(path string) (*Config, error) { return config.Load(path) }

// machinePanel returns the panel section when machine mode is on: the panel
// then owns the node list, and each node gets NodeControllers[id] when it is
// set, otherwise the NodeController template.
func machinePanel(cfg *Config) *AgentPanelConfig { return config.MachinePanel(cfg) }

// controllerConfigWithDefaults returns a fresh ControllerConfig holding src's
// fields over the node defaults.
func controllerConfigWithDefaults(src *nodecfg.Config) *nodecfg.Config {
	return nodecfg.ControllerConfigWithDefaults(src)
}

// maxTokenFileBytes bounds what is read from a token file.
const maxTokenFileBytes = agentcfg.MaxTokenFileBytes

// readTokenFile reads a token file and returns the trimmed token.
func readTokenFile(path string) (string, error) { return agentcfg.ReadTokenFile(path) }

// checkTokenFileMode refuses a token file that group or other can access.
func checkTokenFileMode(path string, mode fs.FileMode, goos string) error {
	return agentcfg.CheckTokenFileMode(path, mode, goos)
}
