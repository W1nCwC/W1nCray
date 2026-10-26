// Package porthop implements the agent side of Hysteria port hopping: a local
// firewall redirect (DNAT) from a range of UDP ports to the single port the
// proxy kernel really listens on (Hysteria over UDP, mieru over UDP or TCP).
//
// Background. The panel's subscription tells clients to hop over a port range
// (for example 20000-30000), but the kernel only listens on one server_port, so
// without a redirect most client packets land on ports nobody listens on. The
// panel therefore also hands the agent the range; the agent installs a redirect
// in the nat/prerouting hook of its own, isolated firewall namespace:
//
//   - nftables (preferred): one table "w1ncray_porthop" per family (ip, ip6),
//     committed atomically with "nft -f <StateDir>/porthop/rules.nft".
//   - iptables (fallback): one own chain W1NCRAY-PORTHOP in the nat table,
//     refilled with "iptables-restore --noflush" and jumped to from the first
//     slot of PREROUTING.
//
// The package never edits /etc/nftables.conf, never runs iptables-save, never
// touches the OUTPUT chain and never installs software. The rules live until
// reboot; the agent restores them from <StateDir>/porthop/state.json at start
// (Restore) and repairs them when somebody flushes the firewall (Heal).
//
// Safety. The panel is not trusted blindly. Every rule goes through gates that
// are enforced here: range start >= 1024, bounded span, target port 1-65535
// and outside the range, tcp only when Config.AllowTCP (the agent turns it on
// by default), no overlap between
// rules (lower node_id wins), no local forward claiming a port of the range and
// no local listening socket in /proc/net inside the range (for tcp only
// sockets in the LISTEN state count). The only
// panel-controlled text that reaches a rule is integers: the comment carries
// the node id and nothing else, and the range string must parse as strict
// "lo-hi" digits.
//
// OpenWrt. The agent offers port hopping there too when a firewall tool is
// found. OpenWrt 22 and later use fw4 (nftables): "w1ncray_porthop" is a table
// of its own, so a fw4 reload does not remove it. Older releases use fw3
// (iptables): a firewall reload rebuilds PREROUTING and can drop the jump to
// our own chain W1NCRAY-PORTHOP; the 60 second Heal pass puts it back, so
// hopping may be interrupted for up to a minute after such a reload.
//
// Wiring points for the caller (not done in this package):
//   - Declare the capability "port_hop" only when Manager.Available() is true
//     after Probe.
//   - Fetch GET /api/v2/server/machine/agent/porthop (ETag / If-None-Match,
//     see ParseResponse), call Restore once at start, Apply on every changed
//     response, and Heal about every 60 seconds.
//   - Re-fetch when a WebSocket "nodes" hint arrives.
//   - Config.ForwardPorts should return the ports of the reconcile ledger.
package porthop

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/W1nCwC/W1nCray/agent/portledger"
)

const (
	// MinRangeStart is the lowest port a hop range may start at.
	MinRangeStart = 1024
	// DefaultMaxSpan is the default maximum number of ports in one range.
	DefaultMaxSpan = 30001

	ProtoUDP = "udp"
	ProtoTCP = "tcp"
)

// Rule is one hop rule as sent by the panel.
type Rule struct {
	NodeID int    `json:"node_id"`
	Proto  string `json:"proto"`
	Ports  string `json:"ports"`
	To     int    `json:"to"`
}

// Response is the body of GET /api/v2/server/machine/agent/porthop.
type Response struct {
	Version string `json:"version"`
	Rules   []Rule `json:"rules"`
}

// ParseResponse decodes the panel body. Unknown fields are ignored so the panel
// can grow the contract; rules may be empty or null.
func ParseResponse(b []byte) (Response, error) {
	var r Response
	if err := json.Unmarshal(b, &r); err != nil {
		return Response{}, fmt.Errorf("porthop: decode response: %w", err)
	}
	return r, nil
}

// ParseRange parses a hop range. Only the strict form "lo-hi" is accepted (a
// plain single port is not a range); the digit rules come from
// portledger.ParsePorts, which rejects spaces, signs, separators and leading
// zeros.
func ParseRange(s string) (lo, hi int, err error) {
	if !strings.Contains(s, "-") {
		return 0, 0, fmt.Errorf("ports %q: want a range lo-hi", s)
	}
	return portledger.ParsePorts(s)
}

// key identifies a rule for change detection.
func (r Rule) key() string {
	return strconv.Itoa(r.NodeID) + "|" + r.Proto + "|" + r.Ports + "|" + strconv.Itoa(r.To)
}

// validate applies the static gates and returns the parsed range.
func (c *Config) validate(r Rule) (lo, hi int, err error) {
	if r.NodeID <= 0 {
		return 0, 0, errors.New("node_id must be positive")
	}
	switch r.Proto {
	case ProtoUDP:
	case ProtoTCP:
		if !c.AllowTCP {
			return 0, 0, errors.New("tcp port hopping is not allowed by local policy")
		}
	default:
		return 0, 0, fmt.Errorf("unsupported proto %q", r.Proto)
	}
	lo, hi, err = ParseRange(r.Ports)
	if err != nil {
		return 0, 0, err
	}
	if lo < MinRangeStart {
		return 0, 0, fmt.Errorf("range starts below %d", MinRangeStart)
	}
	if span := hi - lo + 1; span > c.maxSpan() {
		return 0, 0, fmt.Errorf("range spans %d ports, limit is %d", span, c.maxSpan())
	}
	if r.To < 1 || r.To > 65535 {
		return 0, 0, fmt.Errorf("target port %d out of range 1-65535", r.To)
	}
	// A target inside the range is a panel misconfiguration: the real port must
	// not be one of the hop ports. (A nat redirect is only evaluated for the
	// first packet of a flow, so this is not a literal packet loop, but it is
	// meaningless and would make direct clients of the real port take the hop
	// path; refusing it keeps the rule set unambiguous.)
	if r.To >= lo && r.To <= hi {
		return 0, 0, errors.New("target port lies inside the hop range (misconfiguration)")
	}
	return lo, hi, nil
}
