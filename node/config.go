// Package node runs one Xboard node: it turns the panel config into Xray
// inbounds, keeps users in sync and reports traffic, online IPs and load.
package node

import (
	"time"

	"github.com/W1nCwC/W1nCray/nodecfg"
)

// The node configuration types live in nodecfg, which does not depend on the
// Xray kernel; the aliases keep every existing caller (and the panel's config
// loader) working with the same names.
type (
	APIConfig            = nodecfg.APIConfig
	Config               = nodecfg.Config
	AutoSpeedLimitConfig = nodecfg.AutoSpeedLimitConfig
	FallBackConfig       = nodecfg.FallBackConfig
	REALITYConfig        = nodecfg.REALITYConfig
)

// DefaultConfig returns XrayR's controller defaults.
func DefaultConfig() *Config { return nodecfg.DefaultConfig() }

// ControllerConfigWithDefaults returns a fresh ControllerConfig holding src's
// fields over the node defaults.
func ControllerConfigWithDefaults(src *Config) *Config {
	return nodecfg.ControllerConfigWithDefaults(src)
}

const (
	defaultInterval = 60 * time.Second
	minInterval     = 10 * time.Second
)
