// Package nodecfg holds the Xboard node configuration types (the
// "ControllerConfig" and "ApiConfig" sections, XrayR compatible) without any
// dependency on the Xray kernel.
//
// The types live in their own package so that the agent's configuration loader
// can read a machine's node settings without linking Xray-core: package node
// aliases them and owns the behaviour, this package owns the file format only.
package nodecfg

import (
	"github.com/W1nCwC/W1nCray/common/certcfg"
)

// APIConfig is the "ApiConfig" section of a node (XrayR compatible).
type APIConfig struct {
	APIHost      string  `mapstructure:"ApiHost"`
	Key          string  `mapstructure:"ApiKey"`
	NodeID       int     `mapstructure:"NodeID"`
	NodeType     string  `mapstructure:"NodeType"`
	Timeout      int     `mapstructure:"Timeout"`
	SpeedLimit   float64 `mapstructure:"SpeedLimit"`  // Mbps, overrides the panel when > 0
	DeviceLimit  int     `mapstructure:"DeviceLimit"` // overrides the panel when > 0
	RuleListPath string  `mapstructure:"RuleListPath"`

	// Deprecated XrayR options, accepted so old configs still load.
	EnableVless         bool   `mapstructure:"EnableVless"`
	VlessFlow           string `mapstructure:"VlessFlow"`
	DisableCustomConfig bool   `mapstructure:"DisableCustomConfig"`

	// Machine mode, set by the panel (Agent.Panel) and never by the node's
	// YAML: the machine token identifies this host and the panel decides which
	// nodes it runs. Both fields must be set.
	MachineID    int    `mapstructure:"-"`
	MachineToken string `mapstructure:"-"`
}

// Config is the "ControllerConfig" section of a node (XrayR compatible).
type Config struct {
	ListenIP             string                `mapstructure:"ListenIP"`
	SendIP               string                `mapstructure:"SendIP"`
	UpdatePeriodic       int                   `mapstructure:"UpdatePeriodic"`
	EnableDNS            bool                  `mapstructure:"EnableDNS"`
	DNSType              string                `mapstructure:"DNSType"`
	DisableUploadTraffic bool                  `mapstructure:"DisableUploadTraffic"`
	DisableGetRule       bool                  `mapstructure:"DisableGetRule"`
	EnableProxyProtocol  bool                  `mapstructure:"EnableProxyProtocol"`
	DisableSniffing      bool                  `mapstructure:"DisableSniffing"`
	DisableWebSocket     bool                  `mapstructure:"DisableWebSocket"`
	BlockPrivateIP       *bool                 `mapstructure:"BlockPrivateIP"`
	AutoSpeedLimitConfig *AutoSpeedLimitConfig `mapstructure:"AutoSpeedLimitConfig"`
	EnableFallback       bool                  `mapstructure:"EnableFallback"`
	FallBackConfigs      []*FallBackConfig     `mapstructure:"FallBackConfigs"`
	EnableREALITY        bool                  `mapstructure:"EnableREALITY"`
	REALITYConfigs       *REALITYConfig        `mapstructure:"REALITYConfigs"`
	CertConfig           *certcfg.Config       `mapstructure:"CertConfig"`

	// Deprecated XrayR options, accepted so old configs still load.
	DisableIVCheck            bool           `mapstructure:"DisableIVCheck"`
	DisableLocalREALITYConfig bool           `mapstructure:"DisableLocalREALITYConfig"`
	GlobalDeviceLimitConfig   map[string]any `mapstructure:"GlobalDeviceLimitConfig"`
}

// AutoSpeedLimitConfig limits users that exceed a speed for a while.
type AutoSpeedLimitConfig struct {
	Limit         int `mapstructure:"Limit"`         // Mbps
	WarnTimes     int `mapstructure:"WarnTimes"`     // consecutive warnings before limiting
	LimitSpeed    int `mapstructure:"LimitSpeed"`    // Mbps
	LimitDuration int `mapstructure:"LimitDuration"` // minutes
}

// FallBackConfig is a VLESS/Trojan fallback.
type FallBackConfig struct {
	SNI              string `mapstructure:"SNI"`
	Alpn             string `mapstructure:"Alpn"`
	Path             string `mapstructure:"Path"`
	Dest             string `mapstructure:"Dest"`
	ProxyProtocolVer uint64 `mapstructure:"ProxyProtocolVer"`
}

// REALITYConfig is a local REALITY config that overrides the panel's.
type REALITYConfig struct {
	Show             bool     `mapstructure:"Show"`
	Dest             string   `mapstructure:"Dest"`
	ProxyProtocolVer uint64   `mapstructure:"ProxyProtocolVer"`
	ServerNames      []string `mapstructure:"ServerNames"`
	PrivateKey       string   `mapstructure:"PrivateKey"`
	MinClientVer     string   `mapstructure:"MinClientVer"`
	MaxClientVer     string   `mapstructure:"MaxClientVer"`
	MaxTimeDiff      uint64   `mapstructure:"MaxTimeDiff"`
	ShortIds         []string `mapstructure:"ShortIds"`
}

// DefaultConfig returns XrayR's controller defaults.
func DefaultConfig() *Config {
	return &Config{
		ListenIP: "0.0.0.0",
		SendIP:   "0.0.0.0",
		DNSType:  "AsIs",
	}
}

// BlocksPrivateIP reports whether private targets are blocked (the XrayR
// default when the option is not written).
func (c *Config) BlocksPrivateIP() bool {
	if c == nil || c.BlockPrivateIP == nil {
		return true
	}
	return *c.BlockPrivateIP
}

// AutoSpeedLimit returns the auto speed limit config, or nil when it is off.
func (c *Config) AutoSpeedLimit() *AutoSpeedLimitConfig {
	if c == nil || c.AutoSpeedLimitConfig == nil || c.AutoSpeedLimitConfig.Limit <= 0 {
		return nil
	}
	return c.AutoSpeedLimitConfig
}

// ControllerConfigWithDefaults returns a fresh ControllerConfig holding src's
// fields over the node defaults. It is the one place that completes a
// ControllerConfig, so Nodes, the machine template and the per-node overrides
// all get the same treatment.
func ControllerConfigWithDefaults(src *Config) *Config {
	cc := DefaultConfig()
	if src != nil {
		merge(cc, src)
	}
	return cc
}

// merge copies the set fields of src over the defaults in dst.
func merge(dst, src *Config) {
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
