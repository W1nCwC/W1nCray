//go:build linux

package bootstrap

import "os"

// portHopPlatform reports whether port hopping may be offered here: Linux, not
// OpenWrt (the first release leaves OpenWrt's fw4 alone) and root, which the
// firewall tools need.
func portHopPlatform(openWrt bool) bool {
	return !openWrt && os.Geteuid() == 0
}
