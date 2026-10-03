// Package node runs one Xboard node: it turns the panel config into Xray
// inbounds, keeps users in sync and reports traffic, online IPs and load.
package node

import (
	"time"

	"w1ncray/common/cert"
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
	BlockPrivateIP       *bool                 `mapstructure:"BlockPrivateIP"`
	AutoSpeedLimitConfig *AutoSpeedLimitConfig `mapstructure:"AutoSpeedLimitConfig"`
	EnableFallback       bool                  `mapstructure:"EnableFallback"`
	FallBackConfigs      []*FallBackConfig     `mapstructure:"FallBackConfigs"`
	EnableREALITY        bool                  `mapstructure:"EnableREALITY"`
	REALITYConfigs       *REALITYConfig        `mapstructure:"REALITYConfigs"`
	CertConfig           *cert.Config          `mapstructure:"CertConfig"`

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

func (c *Config) blockPrivateIP() bool {
	return c.BlockPrivateIP == nil || *c.BlockPrivateIP
}

func (c *Config) autoSpeedLimit() *AutoSpeedLimitConfig {
	if c.AutoSpeedLimitConfig == nil || c.AutoSpeedLimitConfig.Limit <= 0 {
		return nil
	}
	return c.AutoSpeedLimitConfig
}

const (
	defaultInterval = 60 * time.Second
	minInterval     = 10 * time.Second
)
