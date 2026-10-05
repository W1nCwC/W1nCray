package core

// Policy levels reserved for forwarding instances. Xray policies are looked
// up by user level, and a forwarding instance sets that level on its
// dokodemo-door inbound and freedom outbound ("userLevel"), so each idle
// profile of agent/spec.Instance.IdleProfile maps to one fixed level. Level 0
// stays the node policy (ConnectionPolicy).
const (
	// LevelTCPLong: long-lived TCP such as SSH or database sessions.
	// connIdle 3600 s, uplinkOnly/downlinkOnly 30 s.
	LevelTCPLong uint32 = 100
	// LevelUDPShort: short-lived UDP flows (DNS, games), connIdle 60 s.
	LevelUDPShort uint32 = 101
	// LevelUDPLong: longer UDP flows (QUIC, VPN), connIdle 120 s.
	LevelUDPLong uint32 = 102
	// LevelTCPDefault: the node ConnectionPolicy, for forwarding that should
	// behave like the nodes.
	LevelTCPDefault uint32 = 103
)

// DefaultForwardBufferKB is the per-direction buffer (kB) of the forward
// policy levels when ForwardOptions.BufferKB is 0. Xray's own default for a
// level without bufferSize is 512 kB per connection on amd64.
const DefaultForwardBufferKB = 64

// ForwardOptions configures the forwarding support of the instance.
type ForwardOptions struct {
	// BufferKB is the bufferSize (kB) of the levels LevelTCPLong,
	// LevelUDPShort and LevelUDPLong; 0 means DefaultForwardBufferKB.
	// LevelTCPDefault always takes the node ConnectionPolicy.
	BufferKB int32
}

// LevelForIdleProfile returns the policy level of an idle profile (the
// IdleProfile values "tcp_long", "tcp_default", "udp_short", "udp_long" of
// agent/spec.Instance). An empty profile selects "tcp_default" for TCP and
// "udp_short" for UDP, according to udp. ok is false for an unknown profile.
func LevelForIdleProfile(profile string, udp bool) (level uint32, ok bool) {
	switch profile {
	case "":
		if udp {
			return LevelUDPShort, true
		}
		return LevelTCPDefault, true
	case "tcp_long":
		return LevelTCPLong, true
	case "tcp_default":
		return LevelTCPDefault, true
	case "udp_short":
		return LevelUDPShort, true
	case "udp_long":
		return LevelUDPLong, true
	}
	return 0, false
}

// addForwardPolicy adds the forward levels and the system stats flags to the
// policy section of the generated config.
func addForwardPolicy(policy, levels map[string]any, cp ConnectionPolicy, f *ForwardOptions) {
	buf := f.BufferKB
	if buf <= 0 {
		buf = DefaultForwardBufferKB
	}
	levels["100"] = map[string]any{
		"handshake":    cp.Handshake,
		"connIdle":     3600,
		"uplinkOnly":   30,
		"downlinkOnly": 30,
		"bufferSize":   buf,
	}
	levels["101"] = map[string]any{
		"handshake":  cp.Handshake,
		"connIdle":   60,
		"bufferSize": buf,
	}
	levels["102"] = map[string]any{
		"handshake":  cp.Handshake,
		"connIdle":   120,
		"bufferSize": buf,
	}
	levels["103"] = map[string]any{
		"handshake":    cp.Handshake,
		"connIdle":     cp.ConnIdle,
		"uplinkOnly":   cp.UplinkOnly,
		"downlinkOnly": cp.DownlinkOnly,
		"bufferSize":   cp.BufferSize,
	}
	policy["system"] = map[string]any{
		"statsInboundUplink":    true,
		"statsInboundDownlink":  true,
		"statsOutboundUplink":   true,
		"statsOutboundDownlink": true,
	}
}
