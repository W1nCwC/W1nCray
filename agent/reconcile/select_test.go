package reconcile

import (
	"errors"
	"strings"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/spec"
)

// Capability sets copied from the real drivers (driver/gost, driver/frp,
// driver/realm Caps()), reduced to what capsReason looks at.
func realGostCaps() driver.Caps {
	return driver.Caps{
		Name:        spec.EngineGost,
		Kinds:       []spec.Kind{spec.KindForward, spec.KindTunnelEntry, spec.KindTunnelExit, spec.KindReversePortal, spec.KindReverseBridge},
		Network:     []string{"tcp", "udp"},
		TunnelTypes: []string{"tcp", "tls", "ws", "wss", "grpc"},
		Reverse:     true, ProxyIn: true, ProxyOut: true,
		Balance: []string{"round_robin", "random", "iphash", "failover"}, HealthCheck: "passive", Stats: "api",
	}
}

func realFrpCaps() driver.Caps {
	return driver.Caps{
		Name:        spec.EngineFrp,
		Kinds:       []spec.Kind{spec.KindReversePortal, spec.KindReverseBridge},
		Network:     []string{"tcp", "udp"},
		TunnelTypes: []string{"tcp", "tls", "ws", "wss"},
		Reverse:     true, ProxyOut: true,
		Balance: []string{"failover"}, HealthCheck: "active", Stats: "api",
	}
}

func realRealmCaps() driver.Caps {
	return driver.Caps{
		Name:        spec.EngineRealm,
		Kinds:       []spec.Kind{spec.KindForward, spec.KindTunnelEntry, spec.KindTunnelExit},
		Network:     []string{"tcp", "udp"},
		TunnelTypes: []string{"tcp", "tls", "ws", "wss"},
		ProxyIn:     true, ProxyOut: true,
		Balance: []string{"round_robin", "iphash"}, HealthCheck: "none", Stats: "none",
	}
}

func healthFwd(strategy string) spec.Instance {
	return spec.Instance{
		Kind: spec.KindForward, Network: []string{"tcp"},
		Balance: &spec.Balance{Strategy: strategy, Health: &spec.Health{Type: "tcp"}},
	}
}

func healthBridge(strategy string) spec.Instance {
	return spec.Instance{
		Kind: spec.KindReverseBridge, Network: []string{"tcp"},
		Tunnel:  &spec.Tunnel{Type: "tcp", Security: "tls"},
		Balance: &spec.Balance{Strategy: strategy, Health: &spec.Health{Type: "tcp"}},
	}
}

func TestCapsReasonHealth(t *testing.T) {
	cases := []struct {
		name string
		caps driver.Caps
		in   spec.Instance
		want string // "" = accepted, otherwise a substring of the reason
	}{
		{"gost passive accepts health", realGostCaps(), healthFwd("round_robin"), ""},
		{"gost passive accepts failover health", realGostCaps(), healthFwd("failover"), ""},
		{"frp bridge failover+health", realFrpCaps(), healthBridge("failover"), ""},
		{"frp refuses other strategies", realFrpCaps(), healthBridge("round_robin"), `balance strategy "round_robin" is not supported`},
		{"realm has no health checks", realRealmCaps(), healthFwd("round_robin"), "health checks are not supported"},
		{"realm without health still fine", realRealmCaps(), spec.Instance{Kind: spec.KindForward, Balance: &spec.Balance{Strategy: "round_robin"}}, ""},
		{"unset health capability is none", func() driver.Caps { c := realGostCaps(); c.HealthCheck = ""; return c }(), healthFwd("round_robin"), "health checks are not supported"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := capsReason(c.caps, c.in, false)
			if c.want == "" && got != "" {
				t.Fatalf("want accepted, got %q", got)
			}
			if c.want != "" && !strings.Contains(got, c.want) {
				t.Fatalf("want reason containing %q, got %q", c.want, got)
			}
		})
	}
}

func healthEnv(t *testing.T, xray, gost, realm string) *env {
	e := newEnv(t)
	e.xray.CapsV.HealthCheck = xray
	e.gost.CapsV.HealthCheck = gost
	e.realm.CapsV.HealthCheck = realm
	return e
}

func healthInst(t *testing.T, engine string) spec.Instance {
	in := fwd(t, "h", engine)
	in.Targets = append(in.Targets, spec.Target{Host: "198.51.100.11", Ports: "443"})
	in.Balance = &spec.Balance{Strategy: "round_robin", Health: &spec.Health{Type: "tcp"}}
	return in
}

func TestAutoWithHealthPrefersActiveThenPassive(t *testing.T) {
	// An active engine wins even when a passive one comes first in order.
	e := healthEnv(t, "passive", "active", "none")
	ir := inst(e.mustApply(desired(1, healthInst(t, "auto"))), "h")
	if ir.Engine != "gost" {
		t.Fatalf("want the active engine, got %+v", ir)
	}
	if ir.Considered["xray"] == "" || !strings.Contains(ir.Considered["xray"], "passive") {
		t.Fatalf("the passive engine skipped in favour of an active one must be explained: %v", ir.Considered)
	}

	// Only passive and none: the passive engine is selected and says so.
	e = healthEnv(t, "none", "passive", "none")
	ir = inst(e.mustApply(desired(1, healthInst(t, "auto"))), "h")
	if ir.Engine != "gost" {
		t.Fatalf("got %+v", ir)
	}
	if !strings.Contains(ir.Considered["gost"], "passive") {
		t.Fatalf("a passive-only selection must be explained: %v", ir.Considered)
	}
	if !strings.Contains(ir.Considered["xray"], "health checks are not supported") {
		t.Fatalf("considered %v", ir.Considered)
	}

	// Nothing supports health: refused, with every reason, never degraded.
	e = healthEnv(t, "none", "none", "none")
	rep, err := e.apply(desired(1, healthInst(t, "auto")))
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("err %v\n%s", err, dumpReport(rep))
	}
	msg := inst(rep, "h").Error
	for _, n := range []string{"gost", "realm", "xray"} {
		if !strings.Contains(msg, n+": health checks are not supported") {
			t.Fatalf("missing reason for %s: %s", n, msg)
		}
	}

	// Without health the order is unchanged: xray first.
	e = healthEnv(t, "passive", "active", "none")
	in := healthInst(t, "auto")
	in.Balance.Health = nil
	if got := inst(e.mustApply(desired(1, in)), "h").Engine; got != "xray" {
		t.Fatalf("got %s", got)
	}
}

func TestExplicitPassiveEngineAcceptsHealth(t *testing.T) {
	e := healthEnv(t, "active", "passive", "none")
	ir := inst(e.mustApply(desired(1, healthInst(t, "gost"))), "h")
	if ir.Engine != "gost" {
		t.Fatalf("%+v", ir)
	}
}

// TestCapsReasonTLSSelf covers the engine rule for security tls_self: realm
// verifies against the public CA roots only, so it can never accept a derived
// self-signed certificate. Saying so in capsReason is what keeps "auto" from
// selecting it (the realm driver's own Validate refuses it too).
func TestCapsReasonTLSSelf(t *testing.T) {
	in := spec.Instance{
		Kind: spec.KindTunnelEntry, Network: []string{"tcp"},
		Tunnel: &spec.Tunnel{Type: "tls", Security: "tls_self", SNI: "tun.example.com"},
	}
	if got := capsReason(realRealmCaps(), in, false); !strings.Contains(got, "tls_self") {
		t.Fatalf("realm must refuse tls_self, got %q", got)
	}
	if got := capsReason(realGostCaps(), in, false); got != "" {
		t.Fatalf("gost accepts tls_self on a TLS carrier, got %q", got)
	}
	// capsReason only owns what a Caps set can express: the pin rules belong
	// to each driver's Validate (gost refuses tls_pin there, xray accepts it),
	// so a tls_pin instance is not judged here.
	pin := in
	pin.Tunnel = &spec.Tunnel{Type: "tls", Security: "tls_pin", PinSHA256: strings.Repeat("a", 64)}
	if got := capsReason(realGostCaps(), pin, false); got != "" {
		t.Fatalf("capsReason must not invent a pin rule: %q", got)
	}
}

// TestAutoNeverSelectsRealmForTLSSelf is the selection half: with realm as the
// only engine, an "auto" instance with tls_self is refused with the reason
// instead of being handed to an engine that cannot verify the certificate.
func TestAutoNeverSelectsRealmForTLSSelf(t *testing.T) {
	e := newEnv(t)
	e.r.Drivers = map[string]driver.Driver{"realm": e.realm}
	in := entry(t, "a", "auto", "0123456789abcdef-secret")
	in.Tunnel.Type, in.Tunnel.Security, in.Tunnel.SNI = "tls", "tls_self", "tun.example.com"
	rep, err := e.apply(desired(1, in))
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("err = %v\n%s", err, dumpReport(rep))
	}
	if got := inst(rep, "a").Error; !strings.Contains(got, "tls_self") {
		t.Fatalf("the refusal must name tls_self: %q", got)
	}
	// With xray present, "auto" picks it (the embedded engine comes first) and
	// the instance applies.
	e2 := newEnv(t)
	in2 := entry(t, "a", "auto", "0123456789abcdef-secret")
	in2.Tunnel.Type, in2.Tunnel.Security, in2.Tunnel.SNI = "tls", "tls_self", "tun.example.com"
	if got := inst(e2.mustApply(desired(1, in2)), "a").Engine; got != "xray" {
		t.Fatalf("auto selected %q, want xray", got)
	}
}
