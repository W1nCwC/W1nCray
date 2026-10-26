//go:build linux

package bootstrap

import "os"

// portHopPlatform reports whether port hopping may be offered here: Linux and
// root, which the firewall tools need. OpenWrt is included: the redirect lives
// in a table (nft) or chain (iptables) of its own, which a fw4 (nftables)
// reload leaves alone. On fw3 (iptables, OpenWrt before 22) a firewall reload
// can drop the jump into our chain from PREROUTING; the controller's 60 second
// self-heal pass puts it back. Whether a firewall tool exists at all is decided
// by the probe in startPortHop, not here.
func portHopPlatform(openWrt bool) bool {
	return os.Geteuid() == 0
}
