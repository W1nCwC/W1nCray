// Package panel loads the W1nCray config and runs the Xray instance with one
// controller per configured Xboard node.
package panel

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"

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
	return cfg, nil
}

func (c *Config) validate() error {
	if c.LogConfig == nil {
		c.LogConfig = &LogConfig{Level: "warning"}
	}
	if c.ConnectionConfig == nil {
		c.ConnectionConfig = &ConnectionConfig{Handshake: 4, ConnIdle: 30, UplinkOnly: 2, DownlinkOnly: 4, BufferSize: 64}
	}
	if len(c.NodesConfig) == 0 {
		return fmt.Errorf("config: no Nodes configured")
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
