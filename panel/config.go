// Package panel loads the W1nCray config and runs the Xray instance with one
// controller per configured Xboard node.
package panel

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/W1nCwC/W1nCray/agent/agentcfg"
	"github.com/W1nCwC/W1nCray/node"
)

// The agent's own configuration lives in agent/agentcfg (D1, ruling 1). The
// panel aliases its types, so every existing caller keeps the same API while
// agent.yml and the config.yml "Agent:" block share one definition and cannot
// drift apart.
type (
	AgentConfig      = agentcfg.Config
	AgentPanelConfig = agentcfg.PanelConfig
	AgentPolicy      = agentcfg.Policy
	TerminalConfig   = agentcfg.TerminalConfig
	FilesConfig      = agentcfg.FilesConfig
	ModuleConfig     = agentcfg.ModuleConfig
)

// Config is the root of config.yml (XrayR compatible layout).
type Config struct {
	LogConfig          *LogConfig        `mapstructure:"Log"`
	DnsConfigPath      string            `mapstructure:"DnsConfigPath"`
	RouteConfigPath    string            `mapstructure:"RouteConfigPath"`
	InboundConfigPath  string            `mapstructure:"InboundConfigPath"`
	OutboundConfigPath string            `mapstructure:"OutboundConfigPath"`
	ConnectionConfig   *ConnectionConfig `mapstructure:"ConnectionConfig"`
	CertDir            string            `mapstructure:"CertDir"`
	NodesConfig        []*NodesConfig    `mapstructure:"Nodes"`
	Agent              *AgentConfig      `mapstructure:"Agent"`

	// agentSource and agentSourcePath record which file the effective agent
	// configuration came from (agent.yml or config.yml); "W1nCray check" and
	// the start-up log report them.
	agentSource     agentcfg.Source
	agentSourcePath string
}

// NodesConfig is one entry of Nodes.
type NodesConfig struct {
	PanelType        string          `mapstructure:"PanelType"`
	ApiConfig        *node.APIConfig `mapstructure:"ApiConfig"`
	ControllerConfig *node.Config    `mapstructure:"ControllerConfig"`
}

// LogConfig configures logging.
type LogConfig struct {
	Level      string `mapstructure:"Level"`
	AccessPath string `mapstructure:"AccessPath"`
	ErrorPath  string `mapstructure:"ErrorPath"`
}

// ConnectionConfig is the Xray level-0 policy (seconds / kB).
type ConnectionConfig struct {
	Handshake    uint32 `mapstructure:"Handshake"`
	ConnIdle     uint32 `mapstructure:"ConnIdle"`
	UplinkOnly   uint32 `mapstructure:"UplinkOnly"`
	DownlinkOnly uint32 `mapstructure:"DownlinkOnly"`
	BufferSize   int32  `mapstructure:"BufferSize"`
}

// AgentSource returns the file kind the effective agent configuration came
// from (agent.yml, config.yml or none).
func (c *Config) AgentSource() agentcfg.Source { return c.agentSource }

// AgentSourcePath returns the file the effective agent configuration came from
// ("" when the agent is not configured).
func (c *Config) AgentSourcePath() string { return c.agentSourcePath }

// loadConfigFile reads config.yml with the XrayR defaults and decodes it,
// without validating or resolving anything. LoadConfig finishes the job once
// the agent.yml precedence is known.
func loadConfigFile(path string) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(path)
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yml", ".yaml", ".json", ".toml":
	default:
		v.SetConfigType("yaml")
	}
	// XrayR defaults.
	v.SetDefault("Log.Level", "warning")
	v.SetDefault("ConnectionConfig.Handshake", 4)
	v.SetDefault("ConnectionConfig.ConnIdle", 30)
	v.SetDefault("ConnectionConfig.UplinkOnly", 2)
	v.SetDefault("ConnectionConfig.DownlinkOnly", 4)
	v.SetDefault("ConnectionConfig.BufferSize", 64)
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	cfg := new(Config)
	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return cfg, nil
}

// LoadConfig reads and validates a config file. The agent's own configuration
// comes from agent.yml next to it when that file exists and from the "Agent:"
// block otherwise; a broken agent.yml fails the load (D1, design R5).
func LoadConfig(path string) (*Config, error) {
	cfg, err := loadConfigFile(path)
	if err != nil {
		return nil, err
	}
	fromConfig := cfg.Agent
	agent, src, base, err := agentcfg.Resolve(path, fromConfig)
	if err != nil {
		return nil, err
	}
	cfg.Agent = agent
	cfg.agentSource = src
	cfg.Agent.SetSource(src)
	switch src {
	case agentcfg.SourceAgentYML:
		cfg.agentSourcePath = filepath.Join(filepath.Dir(path), agentcfg.FileName)
	case agentcfg.SourceConfig:
		cfg.agentSourcePath = path
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if err := cfg.resolvePaths(path, base); err != nil {
		return nil, err
	}
	// Both files describe the agent: agent.yml wins as a whole, but the
	// operator has to be told that the block they edited is ignored.
	if shadowed, agentPath := agentcfg.WarnIfShadowed(path, fromConfig); shadowed {
		log.Warnf("agent: %s wins over the Agent block in %s; the block is ignored", agentPath, path)
	}
	return cfg, nil
}

// resolvePaths fills the agent's path defaults relative to the file that won
// (config.yml, or agent.yml when it is in charge) and materialises the local
// policy defaults. It runs after validate so it never hides a config error.
func (c *Config) resolvePaths(configPath, agentBase string) error {
	if c.Agent == nil {
		return nil
	}
	base := agentBase
	if base == "" {
		base = filepath.Dir(configPath)
	}
	if c.Agent.StateDir == "" {
		c.Agent.StateDir = filepath.Join(base, "state")
	} else if !filepath.IsAbs(c.Agent.StateDir) {
		// Rule 5 of the D1 design: relative paths follow the file that won, so
		// "config in A, state directory in B" can never happen by accident.
		c.Agent.StateDir = filepath.Join(base, c.Agent.StateDir)
	}
	if c.Agent.KernelsDir == "" {
		c.Agent.KernelsDir = filepath.Join(c.Agent.StateDir, "kernels")
	} else if !filepath.IsAbs(c.Agent.KernelsDir) {
		c.Agent.KernelsDir = filepath.Join(base, c.Agent.KernelsDir)
	}
	if pc := c.Agent.Panel; pc != nil && pc.TokenFile != "" && !filepath.IsAbs(pc.TokenFile) {
		pc.TokenFile = filepath.Join(base, pc.TokenFile)
	}
	// The local gates (D3/D8/D9): xray's own directory is the managed-file
	// root, and the agent's configuration and state files are never inside it
	// (ruling 13).
	return c.Agent.ResolveLocalPolicy(base, filepath.Dir(configPath),
		agentcfg.ExcludedPaths(configPath, c.Agent.StateDir))
}

func (c *Config) validate() error {
	if c.LogConfig == nil {
		c.LogConfig = &LogConfig{Level: "warning"}
	}
	if c.ConnectionConfig == nil {
		c.ConnectionConfig = &ConnectionConfig{Handshake: 4, ConnIdle: 30, UplinkOnly: 2, DownlinkOnly: 4, BufferSize: 64}
	}
	// D-F: a machine may run the agent without any Xboard node, so an empty
	// Nodes list is only an error when neither Nodes nor the agent is enabled.
	// Machine mode (Agent.Panel.MachineNodes) needs the agent, so it is covered
	// by the same rule.
	if len(c.NodesConfig) == 0 && (c.Agent == nil || !c.Agent.Enabled) {
		return fmt.Errorf("config: no Nodes configured and Agent.Enabled is not set (configure Nodes, or an Agent)")
	}
	if c.Agent != nil {
		if err := c.Agent.Validate(); err != nil {
			return err
		}
	}
	seen := make(map[string]bool)
	for i, n := range c.NodesConfig {
		if n == nil || n.ApiConfig == nil {
			return fmt.Errorf("config: Nodes[%d]: missing ApiConfig", i)
		}
		switch strings.ToLower(n.PanelType) {
		case "", "xboard", "newv2board", "v2board":
		default:
			return fmt.Errorf("config: Nodes[%d]: unsupported PanelType %q (W1nCray supports Xboard)", i, n.PanelType)
		}
		a := n.ApiConfig
		if a.APIHost == "" || a.Key == "" || a.NodeID <= 0 {
			return fmt.Errorf("config: Nodes[%d]: ApiHost, ApiKey and NodeID are required", i)
		}
		key := fmt.Sprintf("%s#%d", strings.TrimRight(a.APIHost, "/"), a.NodeID)
		if seen[key] {
			return fmt.Errorf("config: Nodes[%d]: node %d of %s is configured twice", i, a.NodeID, a.APIHost)
		}
		seen[key] = true

		n.ControllerConfig = controllerConfigWithDefaults(n.ControllerConfig)
	}
	return nil
}

// controllerConfigWithDefaults returns a fresh ControllerConfig holding src's
// fields over the node defaults. It forwards to agentcfg, which owns the rule,
// so Nodes, the machine template and the per-node overrides all get the same
// treatment.
func controllerConfigWithDefaults(src *node.Config) *node.Config {
	return agentcfg.ControllerConfigWithDefaults(src)
}

// machinePanel returns the panel section when machine mode is on: the panel
// then owns the node list, and each node gets NodeControllers[id] when it is
// set, otherwise the NodeController template.
func machinePanel(cfg *Config) *AgentPanelConfig {
	if cfg.Agent == nil || !cfg.Agent.Enabled || cfg.Agent.Panel == nil {
		return nil
	}
	pc := cfg.Agent.Panel
	if !pc.Enabled || !pc.MachineNodes {
		return nil
	}
	return pc
}

// maxTokenFileBytes bounds what is read from a token file.
const maxTokenFileBytes = agentcfg.MaxTokenFileBytes

// readTokenFile reads a token file and returns the trimmed token. It forwards
// to agentcfg, which owns the rule; the panel keeps the name for its callers.
func readTokenFile(path string) (string, error) { return agentcfg.ReadTokenFile(path) }

// checkTokenFileMode refuses a token file that group or other can access. It
// forwards to agentcfg, which owns the rule.
func checkTokenFileMode(path string, mode fs.FileMode, goos string) error {
	return agentcfg.CheckTokenFileMode(path, mode, goos)
}
