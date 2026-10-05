// Package panel loads the W1nCray config and runs the Xray instance with one
// controller per configured Xboard node.
package panel

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"

	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/node"
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
}

// AgentConfig configures the in-process agent: a declarative kernel manager
// that applies a desired state (from Agent.DesiredPath) to the configured
// engines. It is independent of the Xboard Nodes; either may be configured.
type AgentConfig struct {
	Enabled bool `mapstructure:"Enabled"`
	// StateDir holds the agent's state files and per-driver directories.
	// Default: a "state" directory next to the config file.
	StateDir string `mapstructure:"StateDir"`
	// ManifestPath is the signed kernel manifest. Empty: only the builtin xray
	// engine is available (no external kernel can be installed).
	ManifestPath string `mapstructure:"ManifestPath"`
	// ManifestKeysPath is an optional file of extra trusted ed25519 public
	// keys (hex, one per line), added to the keys compiled into the binary.
	// For local/self-hosted use; production should inject keys with ldflags.
	ManifestKeysPath string `mapstructure:"ManifestKeysPath"`
	// KernelsDir is where external kernels are installed.
	// Default: StateDir/kernels.
	KernelsDir string `mapstructure:"KernelsDir"`
	// DesiredPath is a JSON file holding a spec.Desired. When set, the agent
	// applies it at start-up and re-applies it (debounced) on every change.
	DesiredPath string `mapstructure:"DesiredPath"`
	// Policy is the local root-of-trust policy; remote desired state can never
	// relax it.
	Policy *AgentPolicy `mapstructure:"Policy"`
}

// AgentPolicy maps agent/spec.Policy fields onto the config file. A zero value
// keeps the agent defaults (loopback-only listeners, ports >= 1024, ...).
type AgentPolicy struct {
	MaxInstances             int      `mapstructure:"MaxInstances"`
	MaxPortsPerInstance      int      `mapstructure:"MaxPortsPerInstance"`
	AllowListen              []string `mapstructure:"AllowListen"`
	PrivilegedPorts          bool     `mapstructure:"PrivilegedPorts"`
	PortRange                []int    `mapstructure:"PortRange"` // [lo, hi]
	DenyPorts                []int    `mapstructure:"DenyPorts"`
	DenyCIDRs                []string `mapstructure:"DenyCIDRs"`
	AllowPrivate             bool     `mapstructure:"AllowPrivate"`
	AllowAnyTarget           bool     `mapstructure:"AllowAnyTarget"`
	AllowAcceptProxyOnPublic bool     `mapstructure:"AllowAcceptProxyOnPublic"`
	AllowEngines             []string `mapstructure:"AllowEngines"`
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

// LoadConfig reads and validates a config file.
func LoadConfig(path string) (*Config, error) {
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
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cfg.resolvePaths(path)
	return cfg, nil
}

// resolvePaths fills the agent's path defaults relative to the config file.
// It runs after validate so it never hides a config error.
func (c *Config) resolvePaths(configPath string) {
	if c.Agent == nil {
		return
	}
	base := filepath.Dir(configPath)
	if c.Agent.StateDir == "" {
		c.Agent.StateDir = filepath.Join(base, "state")
	}
	if c.Agent.KernelsDir == "" {
		c.Agent.KernelsDir = filepath.Join(c.Agent.StateDir, "kernels")
	}
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
	if len(c.NodesConfig) == 0 && (c.Agent == nil || !c.Agent.Enabled) {
		return fmt.Errorf("config: no Nodes configured and Agent.Enabled is not set (configure Nodes, or an Agent)")
	}
	if c.Agent != nil {
		if err := c.Agent.validate(); err != nil {
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

		cc := node.DefaultConfig()
		if n.ControllerConfig != nil {
			merge(cc, n.ControllerConfig)
		}
		n.ControllerConfig = cc
	}
	return nil
}

// merge copies the set fields of src over the defaults in dst.
func merge(dst, src *node.Config) {
	defaults := *dst
	*dst = *src
	if dst.ListenIP == "" {
		dst.ListenIP = defaults.ListenIP
	}
	if dst.SendIP == "" {
		dst.SendIP = defaults.SendIP
	}
	if dst.DNSType == "" {
		dst.DNSType = defaults.DNSType
	}
}

// validate checks the agent section. It is deliberately shallow: the policy is
// parsed in full by the agent core when a desired state is applied.
func (a *AgentConfig) validate() error {
	if !a.Enabled {
		return nil
	}
	if a.Policy != nil {
		if n := len(a.Policy.PortRange); n != 0 && n != 2 {
			return fmt.Errorf("config: Agent.Policy.PortRange must have two elements [lo, hi], got %d", n)
		}
		for _, e := range a.Policy.AllowEngines {
			switch e {
			case spec.EngineAuto, spec.EngineXray, spec.EngineGost, spec.EngineFrp, spec.EngineRealm:
			default:
				return fmt.Errorf("config: Agent.Policy.AllowEngines: unknown engine %q", e)
			}
		}
	}
	return nil
}

// PolicySpec maps the config policy onto the agent core's policy. A nil policy
// yields the zero spec.Policy, which the core normalises to safe defaults.
func (a *AgentConfig) PolicySpec() spec.Policy {
	if a == nil || a.Policy == nil {
		return spec.Policy{}
	}
	p := a.Policy
	out := spec.Policy{
		MaxInstances:             p.MaxInstances,
		MaxPortsPerInstance:      p.MaxPortsPerInstance,
		AllowListen:              append([]string(nil), p.AllowListen...),
		PrivilegedPorts:          p.PrivilegedPorts,
		DenyPorts:                append([]int(nil), p.DenyPorts...),
		DenyCIDRs:                append([]string(nil), p.DenyCIDRs...),
		AllowPrivate:             p.AllowPrivate,
		AllowAnyTarget:           p.AllowAnyTarget,
		AllowAcceptProxyOnPublic: p.AllowAcceptProxyOnPublic,
		AllowEngines:             append([]string(nil), p.AllowEngines...),
	}
	if len(p.PortRange) == 2 {
		out.PortRange = [2]int{p.PortRange[0], p.PortRange[1]}
	}
	return out
}
