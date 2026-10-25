//go:build !linux

package bootstrap

// portHopPlatform is false everywhere but Linux: there is no netfilter, so the
// port_hop capability is never declared and no firewall command is run.
func portHopPlatform(openWrt bool) bool { return false }
