// Package portledger tracks which local listeners the agent has claimed, detects
// conflicts between claims (including wildcard-versus-specific address
// overlaps, tcp and udp kept apart, and externally reserved ports such as the
// node ports), and verifies claims against the real system with bind probes.
// It is pure Go and needs no privileges.
package portledger

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// MaxPort is the largest valid port number.
const MaxPort = 65535

// ParsePorts parses a single port ("8443") or an inclusive range
// ("20000-20009"). The syntax is strict: ASCII digits only, no sign, spaces or
// leading zeros, 1..65535, and a range must have lo < hi (a one-port range is
// written as the plain port so every value has one canonical spelling).
func ParsePorts(s string) (lo, hi int, err error) {
	if s == "" {
		return 0, 0, errors.New("empty port")
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		lo, err = parsePort(s[:i])
		if err != nil {
			return 0, 0, err
		}
		hi, err = parsePort(s[i+1:])
		if err != nil {
			return 0, 0, err
		}
		if lo >= hi {
			return 0, 0, fmt.Errorf("invalid range %q: start must be below end", s)
		}
		return lo, hi, nil
	}
	lo, err = parsePort(s)
	return lo, lo, err
}

func parsePort(s string) (int, error) {
	if s == "" || len(s) > 5 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("invalid port %q: digits only", s)
		}
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, fmt.Errorf("invalid port %q: leading zero", s)
	}
	n, _ := strconv.Atoi(s)
	if n < 1 || n > MaxPort {
		return 0, fmt.Errorf("port %d out of range 1-%d", n, MaxPort)
	}
	return n, nil
}

// Expand turns a listen specification into one claim per port.
func Expand(proto, addr, ports, owner string) ([]driver.PortClaim, error) {
	lo, hi, err := ParsePorts(ports)
	if err != nil {
		return nil, err
	}
	out := make([]driver.PortClaim, 0, hi-lo+1)
	for p := lo; p <= hi; p++ {
		out = append(out, driver.PortClaim{Proto: proto, Addr: addr, Port: p, Owner: owner})
	}
	return out, nil
}

// normAddr parses a claim address. "" and "*" mean every address and are
// treated like "::" (Go's default listener is dual-stack).
func normAddr(s string) (netip.Addr, bool) {
	if s == "" || s == "*" {
		return netip.IPv6Unspecified(), true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.WithZone("").Unmap(), true
}

// AddrOverlap reports whether two listen addresses can collide on the same
// port. Equal addresses collide; 0.0.0.0 collides with every IPv4 address;
// "::" (and "" / "*") collides with everything because a dual-stack wildcard
// socket also owns the IPv4 space. Unparseable addresses collide only if
// textually equal.
func AddrOverlap(a, b string) bool {
	x, okx := normAddr(a)
	y, oky := normAddr(b)
	if !okx || !oky {
		return strings.EqualFold(a, b)
	}
	if x == y {
		return true
	}
	if x.IsUnspecified() && x.Is6() || y.IsUnspecified() && y.Is6() {
		return true
	}
	if x.IsUnspecified() && x.Is4() && y.Is4() {
		return true
	}
	if y.IsUnspecified() && y.Is4() && x.Is4() {
		return true
	}
	return false
}

func lowerProto(p string) string { return strings.ToLower(p) }

// ClaimsOverlap reports whether two claims compete for the same socket.
func ClaimsOverlap(a, b driver.PortClaim) bool {
	return lowerProto(a.Proto) == lowerProto(b.Proto) && a.Port == b.Port && AddrOverlap(a.Addr, b.Addr)
}

// ValidateClaim checks the shape of one claim.
func ValidateClaim(c driver.PortClaim) error {
	switch lowerProto(c.Proto) {
	case "tcp", "udp":
	default:
		return fmt.Errorf("invalid protocol %q", c.Proto)
	}
	if c.Port < 1 || c.Port > MaxPort {
		return fmt.Errorf("port %d out of range", c.Port)
	}
	if _, ok := normAddr(c.Addr); !ok {
		return fmt.Errorf("invalid address %q", c.Addr)
	}
	return nil
}

// Conflict is one problem found for a claim.
type Conflict struct {
	A      driver.PortClaim `json:"a"`
	B      driver.PortClaim `json:"b,omitempty"` // zero when the conflict is with the system
	Reason string           `json:"reason"`
}

func (c Conflict) String() string {
	if c.B == (driver.PortClaim{}) {
		return fmt.Sprintf("%s: %s", claimString(c.A), c.Reason)
	}
	return fmt.Sprintf("%s vs %s: %s", claimString(c.A), claimString(c.B), c.Reason)
}

func claimString(c driver.PortClaim) string {
	addr := c.Addr
	if addr == "" {
		addr = "*"
	}
	return fmt.Sprintf("%s %s:%d (%s)", lowerProto(c.Proto), addr, c.Port, c.Owner)
}

func sortClaims(cs []driver.PortClaim) {
	sort.Slice(cs, func(i, j int) bool { return claimLess(cs[i], cs[j]) })
}

func claimLess(a, b driver.PortClaim) bool {
	if pa, pb := lowerProto(a.Proto), lowerProto(b.Proto); pa != pb {
		return pa < pb
	}
	if a.Port != b.Port {
		return a.Port < b.Port
	}
	if a.Addr != b.Addr {
		return a.Addr < b.Addr
	}
	return a.Owner < b.Owner
}

// Detect finds every pair of overlapping claims in the set. Claims of the
// same owner count too: an instance claiming the same socket twice is a bug in
// its renderer. The result is deterministic.
func Detect(claims []driver.PortClaim) []Conflict {
	type key struct {
		proto string
		port  int
	}
	groups := map[key][]driver.PortClaim{}
	var out []Conflict
	for _, c := range claims {
		if err := ValidateClaim(c); err != nil {
			out = append(out, Conflict{A: c, Reason: "invalid claim: " + err.Error()})
			continue
		}
		k := key{lowerProto(c.Proto), c.Port}
		groups[k] = append(groups[k], c)
	}
	for _, g := range groups {
		if len(g) < 2 {
			continue
		}
		sortClaims(g)
		for i := 0; i < len(g); i++ {
			for j := i + 1; j < len(g); j++ {
				if !AddrOverlap(g[i].Addr, g[j].Addr) {
					continue
				}
				reason := "port claimed by two instances"
				if g[i].Owner == g[j].Owner {
					reason = "port claimed twice by the same instance"
				}
				out = append(out, Conflict{A: g[i], B: g[j], Reason: reason})
			}
		}
	}
	sortConflicts(out)
	return out
}

func sortConflicts(cs []Conflict) {
	sort.SliceStable(cs, func(i, j int) bool {
		if claimLess(cs[i].A, cs[j].A) {
			return true
		}
		if claimLess(cs[j].A, cs[i].A) {
			return false
		}
		if claimLess(cs[i].B, cs[j].B) {
			return true
		}
		if claimLess(cs[j].B, cs[i].B) {
			return false
		}
		return cs[i].Reason < cs[j].Reason
	})
}
