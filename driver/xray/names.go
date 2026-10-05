// Package xray is the driver of the embedded Xray kernel. It compiles the
// declarative spec.Instance values of the agent into Xray inbounds, outbounds,
// routing rules and balancers (Compile, a pure function), and applies them to
// a running Xray instance through the small Host interface (Apply).
//
// Safety model: Xray configuration is only ever produced by json.Marshal over
// typed structures, never by string concatenation, and every spec string that
// reaches a configuration value first passes a strict whitelist (validate.go).
// The shared Secret is only used to derive credentials; it is never written to
// logs or error messages.
package xray

import "strconv"

// Tag namespace. Tags contain "/" so they can never match the XrayR legacy tag
// pattern "<Type>_<IP>_<Port>" that core/legacytag.go rewrites, and the
// trailing "/" of the balancer selector makes id prefixes unambiguous
// ("w1n-fwd/o/a/" does not select "w1n-fwd/o/a-b/0").
const tagRoot = "w1n-fwd/"

// RulesTag is the key under which the driver registers all of its routing
// rules and balancers with the host (one node entry for the whole driver).
const RulesTag = "w1n-fwd"

func tagIn(id string) string        { return tagRoot + "i/" + id } // user facing inbound
func tagTunnelIn(id string) string  { return tagRoot + "x/" + id } // tunnel entrance (exit/portal side)
func tagTunnelOut(id string) string { return tagRoot + "t/" + id } // tunnel client outbound
func tagBalancer(id string) string  { return tagRoot + "b/" + id }
func tagBlock(id string) string     { return tagRoot + "k/" + id }
func tagReverse(id string) string   { return tagRoot + "r/" + id }

// tagOut is the outbound of target n of an instance. A single-target
// instance uses "w1n-fwd/o/<id>"; several targets use "w1n-fwd/o/<id>/<n>"
// and the selector "w1n-fwd/o/<id>/".
func tagOut(id string) string { return tagRoot + "o/" + id }
func tagOutN(id string, n int) string {
	return tagRoot + "o/" + id + "/" + strconv.Itoa(n)
}
func outSelector(id string) string { return tagRoot + "o/" + id + "/" }

// clientEmail is the Xray user of the tunnel client of an instance.
func clientEmail(id string) string { return tagRoot + id }

// Idle profile levels. They must stay equal to the policy levels the core
// pre-defines (core exports the same numbers); the values are part of the
// shared plan: 100 tcp_long, 101 udp_short, 102 udp_long, 103 tcp_default.
const (
	LevelTCPLong    uint32 = 100
	LevelUDPShort   uint32 = 101
	LevelUDPLong    uint32 = 102
	LevelTCPDefault uint32 = 103
)

// Levels maps idle profiles to Xray policy levels.
type Levels struct {
	TCPLong, UDPShort, UDPLong, TCPDefault uint32
}

// DefaultLevels are the levels the core is expected to define.
func DefaultLevels() Levels {
	return Levels{TCPLong: LevelTCPLong, UDPShort: LevelUDPShort, UDPLong: LevelUDPLong, TCPDefault: LevelTCPDefault}
}
