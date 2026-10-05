package xray

// Compile-level tests of the reverse proxy semantics shared with the gost and
// frp drivers: the bridge's targets decide the destinations, a portal has no
// targets and its users cannot choose where the bridge connects.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/spec"
)

// outboundOf returns the outbound part with the given tag.
func outboundOf(t *testing.T, c Compiled, tag string) jOutbound {
	t.Helper()
	for _, p := range c.Outbounds {
		if p.Tag == tag {
			var o jOutbound
			if err := json.Unmarshal(p.Config, &o); err != nil {
				t.Fatal(err)
			}
			return o
		}
	}
	t.Fatalf("no outbound %q in %v", tag, partTags(c.Outbounds))
	return jOutbound{}
}

// freedomOf decodes the settings of a freedom outbound.
func freedomOf(t *testing.T, c Compiled, tag string) jFreedom {
	t.Helper()
	o := outboundOf(t, c, tag)
	if o.Protocol != "freedom" {
		t.Fatalf("outbound %s is %s, not freedom", tag, o.Protocol)
	}
	b, _ := json.Marshal(o.Settings)
	var f jFreedom
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// userInboundOf returns the user facing (dokodemo) inbound of a compiled portal.
func userInboundOf(t *testing.T, c Compiled) jDokodemo {
	t.Helper()
	for _, p := range c.Inbounds {
		if strings.HasPrefix(p.Tag, "w1n-fwd/i/") {
			var ib jInbound
			_ = json.Unmarshal(p.Config, &ib)
			b, _ := json.Marshal(ib.Settings)
			var d jDokodemo
			_ = json.Unmarshal(b, &d)
			return d
		}
	}
	t.Fatal("no user inbound")
	return jDokodemo{}
}

// assertBridgeOnlyRedirects is the safety invariant of the bridge: apart from
// the tunnel client and the block, every outbound is a freedom WITH a
// redirect, and every rule on the relay inbound leads to the tunnel (the
// rendezvous request only), a redirect outbound, a balancer over redirect
// outbounds, or the block. So there is no route on which a portal-chosen
// destination is dialled.
func assertBridgeOnlyRedirects(t *testing.T, c Compiled, id string) {
	t.Helper()
	redirect := map[string]bool{}
	for _, p := range c.Outbounds {
		var o jOutbound
		_ = json.Unmarshal(p.Config, &o)
		switch o.Protocol {
		case "blackhole", "vless":
		case "freedom":
			b, _ := json.Marshal(o.Settings)
			var f jFreedom
			_ = json.Unmarshal(b, &f)
			if f.Redirect == "" {
				t.Fatalf("%s: bridge outbound %s is a freedom without redirect", id, p.Tag)
			}
			redirect[p.Tag] = true
		default:
			t.Fatalf("%s: unexpected outbound protocol %s", id, o.Protocol)
		}
	}
	if len(redirect) == 0 {
		t.Fatalf("%s: no redirect outbound", id)
	}
	rev := "w1n-fwd/r/" + id
	rs := rulesOf(t, c)
	for i, r := range rs {
		if len(r.InboundTag) != 1 || r.InboundTag[0] != rev {
			t.Fatalf("%s: rule %d is not scoped to the relay inbound: %+v", id, i, r)
		}
		switch {
		case r.BalancerTag != "":
			var found bool
			for _, raw := range c.Balancers {
				var b jBalancer
				_ = json.Unmarshal(raw, &b)
				if b.Tag != r.BalancerTag {
					continue
				}
				found = true
				for _, p := range c.Outbounds {
					for _, sel := range b.Selector {
						if strings.HasPrefix(p.Tag, sel) && !redirect[p.Tag] {
							t.Fatalf("%s: balancer %s selects non-redirect outbound %s", id, b.Tag, p.Tag)
						}
					}
				}
			}
			if !found {
				t.Fatalf("%s: rule uses unknown balancer %s", id, r.BalancerTag)
			}
		case r.OutboundTag == "w1n-fwd/t/"+id:
			// only the rendezvous request may reach the tunnel
			if len(r.Domain) != 1 || r.Domain[0] != "full:"+testDomain {
				t.Fatalf("%s: tunnel rule is not the rendezvous: %+v", id, r)
			}
		case r.OutboundTag == "w1n-fwd/k/"+id:
		case redirect[r.OutboundTag]:
		default:
			t.Fatalf("%s: rule %d routes to %q, which is neither redirect, tunnel nor block", id, i, r.OutboundTag)
		}
	}
	if last := rs[len(rs)-1]; last.OutboundTag != "w1n-fwd/k/"+id || len(last.IP)+len(last.Domain) != 0 || last.Port != "" {
		t.Fatalf("%s: relay inbound does not end in an unconditional block: %+v", id, last)
	}
}

func TestReversePortalPlaceholderDestination(t *testing.T) {
	c := mustCompile(t, portalInst("p1"), testOpts())
	d := userInboundOf(t, c)
	if d.Address != placeholderHost || d.Port != 1 || len(d.PortMap) != 0 || d.Network != "tcp,udp" {
		t.Fatalf("%+v", d)
	}
	if strings.Contains(raw(c), "192.168.1.10") {
		t.Fatal("portal output names a target")
	}
	// A port range: slot n for the n-th public port.
	in := portalInst("p2")
	in.Listen.Ports = "20001-20003"
	d = userInboundOf(t, mustCompile(t, in, testOpts()))
	want := map[string]string{"20001": placeholderHost + ":1", "20002": placeholderHost + ":2", "20003": placeholderHost + ":3"}
	if len(d.PortMap) != 3 {
		t.Fatalf("%+v", d)
	}
	for k, v := range want {
		if d.PortMap[k] != v {
			t.Fatalf("port map %v", d.PortMap)
		}
	}
	// The xray config loader accepts it.
	cc := mustCompile(t, in, testOpts())
	if _, err := buildHandlers(&cc); err != nil {
		t.Fatal(err)
	}
}

func TestReversePortalRejectsDestinations(t *testing.T) {
	in := portalInst("p1")
	in.Targets = []spec.Target{{Host: "192.168.1.10", Ports: "3389"}}
	if _, err := Compile(in, testOpts()); err == nil || !strings.Contains(err.Error(), "targets") {
		t.Fatalf("portal with targets: %v", err)
	}
	in = portalInst("p2")
	in.Listen.PortMap = map[string]string{"20001": "192.168.1.10:3389"}
	if _, err := Compile(in, testOpts()); err == nil || !strings.Contains(err.Error(), "port_map") {
		t.Fatalf("portal with port_map: %v", err)
	}
	in = portalInst("p3")
	in.Reverse.BridgeAllow = []spec.Allow{{Host: "10.5.5.5", Ports: "22"}}
	if _, err := Compile(in, testOpts()); err == nil || !strings.Contains(err.Error(), "bridge_allow") {
		t.Fatalf("portal with bridge_allow: %v", err)
	}
	in = portalInst("p4")
	in.AllowAnyTarget = true
	o := testOpts()
	o.Policy.AllowAnyTarget = true
	if _, err := Compile(in, o); err == nil {
		t.Fatal("allow_any_target accepted on a portal")
	}
}

func TestReverseBridgeRejects(t *testing.T) {
	cases := map[string]func(in *spec.Instance){
		"bridge_allow": func(in *spec.Instance) {
			in.Reverse.BridgeAllow = []spec.Allow{{Host: "192.168.1.10", Ports: "3389"}}
		},
		"no targets":           func(in *spec.Instance) { in.Targets = nil },
		"range without listen": func(in *spec.Instance) { in.Targets[0].Ports = "3389-3390" },
		"range length mismatch": func(in *spec.Instance) {
			in.Targets[0].Ports = "3389-3390"
			in.Listen = &spec.Listen{Ports: "20001-20003"}
		},
		"several targets with ranges": func(in *spec.Instance) {
			in.Targets = []spec.Target{{Host: "10.0.0.1", Ports: "80-81"}, {Host: "10.0.0.2", Ports: "80-81"}}
		},
		"several targets and listen range": func(in *spec.Instance) {
			in.Targets = []spec.Target{{Host: "10.0.0.1", Ports: "80"}, {Host: "10.0.0.2", Ports: "80"}}
			in.Listen = &spec.Listen{Ports: "20001-20002"}
		},
		"port_map": func(in *spec.Instance) {
			in.Listen = &spec.Listen{Ports: "20001", PortMap: map[string]string{"20001": "10.0.0.1:80"}}
		},
		"failover without health": func(in *spec.Instance) {
			in.Targets = []spec.Target{{Host: "10.0.0.1", Ports: "80"}, {Host: "10.0.0.2", Ports: "80"}}
			in.Balance = &spec.Balance{Strategy: "failover"}
		},
		"allow_any_target": func(in *spec.Instance) { in.AllowAnyTarget = true },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			in := bridgeInst("b1")
			mut(&in)
			o := testOpts()
			o.Policy.AllowAnyTarget = true // so the kind check is what refuses it
			if _, err := Compile(in, o); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	// the error of bridge_allow tells what to do
	in := bridgeInst("b2")
	in.Reverse.BridgeAllow = []spec.Allow{{Host: "192.168.1.10", Ports: "3389"}}
	_, err := Compile(in, testOpts())
	if err == nil || !strings.Contains(err.Error(), "list the permitted destinations in targets") {
		t.Fatalf("%v", err)
	}
}

func TestReverseBridgeOnlyRedirects(t *testing.T) {
	multi := bridgeInst("b")
	multi.Targets = []spec.Target{{Host: "10.0.0.1", Ports: "80"}, {Host: "10.0.0.2", Ports: "81", Weight: 3}}
	multi.Network = []string{"tcp"}

	random := multi
	random.Balance = &spec.Balance{Strategy: "random"}

	failover := multi
	failover.Balance = &spec.Balance{Strategy: "failover", Health: &spec.Health{Type: "tcp"}}

	rng := bridgeInst("b")
	rng.Targets = []spec.Target{{Host: "192.168.1.20", Ports: "8080-8082"}}
	rng.Listen = &spec.Listen{Ports: "20001-20003"}

	dom := bridgeInst("b")
	dom.Targets = []spec.Target{{Host: "nas.lan.example", Ports: "445"}}

	v6 := bridgeInst("b")
	v6.Targets = []spec.Target{{Host: "2001:db8::5", Ports: "443"}}

	pp := bridgeInst("b")
	pp.Network = []string{"tcp"}
	pp.ProxyProtocolOut = 2

	for name, in := range map[string]spec.Instance{
		"single": bridgeInst("b"), "multi": multi, "random": random, "failover": failover,
		"range": rng, "domain": dom, "ipv6": v6, "proxy-protocol": pp,
	} {
		t.Run(name, func(t *testing.T) {
			c := mustCompile(t, in, testOpts())
			assertBridgeOnlyRedirects(t, c, "b")
			if _, err := buildHandlers(&c); err != nil {
				t.Fatalf("Xray rejected the output: %v\n%s", err, raw(c))
			}
		})
	}
}

func TestReverseBridgeRedirects(t *testing.T) {
	// range: public port n -> target port n, selected by the slot
	in := bridgeInst("b")
	in.Targets = []spec.Target{{Host: "192.168.1.20", Ports: "8080-8082"}}
	in.Listen = &spec.Listen{Ports: "20001-20003"}
	c := mustCompile(t, in, testOpts())
	rs := rulesOf(t, c)
	if len(rs) != 5 { // rendezvous + 3 slots + block
		t.Fatalf("%+v", rs)
	}
	for k := 0; k < 3; k++ {
		r := rs[1+k]
		tag := tagOutN("b", k)
		if r.Port != string(rune('1'+k)) || r.OutboundTag != tag {
			t.Fatalf("slot %d: %+v", k, r)
		}
		want := []string{"192.168.1.20:8080", "192.168.1.20:8081", "192.168.1.20:8082"}[k]
		if f := freedomOf(t, c, tag); f.Redirect != want {
			t.Fatalf("slot %d redirect %q, want %q", k, f.Redirect, want)
		}
	}
	// the portal of the same link numbers its public ports with the slots
	p := portalInst("b")
	p.Listen.Ports = "20001-20003"
	if d := userInboundOf(t, mustCompile(t, p, testOpts())); d.PortMap["20002"] != placeholderHost+":2" {
		t.Fatalf("%v", d.PortMap)
	}

	// single target port with a listen range: every slot goes to that port
	in = bridgeInst("b")
	in.Listen = &spec.Listen{Ports: "20001-20003"}
	c = mustCompile(t, in, testOpts())
	if rs := rulesOf(t, c); len(rs) != 3 || rs[1].Port != "" {
		t.Fatalf("%+v", rs)
	}

	// several targets: redirect per target (repeated by weight) and a balancer
	in = bridgeInst("b")
	in.Network = []string{"tcp"}
	in.Targets = []spec.Target{{Host: "10.0.0.1", Ports: "80"}, {Host: "10.0.0.2", Ports: "81", Weight: 3}}
	in.Balance = &spec.Balance{Strategy: "random"}
	c = mustCompile(t, in, testOpts())
	got := map[string]int{}
	for _, p := range c.Outbounds {
		if strings.HasPrefix(p.Tag, "w1n-fwd/o/b/") {
			got[freedomOf(t, c, p.Tag).Redirect]++
		}
	}
	if len(got) != 2 || got["10.0.0.1:80"] != 1 || got["10.0.0.2:81"] != 3 {
		t.Fatalf("%v", got)
	}
	var bal jBalancer
	if len(c.Balancers) != 1 {
		t.Fatal("no balancer")
	}
	_ = json.Unmarshal(c.Balancers[0], &bal)
	if bal.Strategy.Type != "random" || bal.Selector[0] != "w1n-fwd/o/b/" {
		t.Fatalf("%+v", bal)
	}
	rs = rulesOf(t, c)
	if rs[1].BalancerTag != bal.Tag || rs[1].Network != "tcp" {
		t.Fatalf("%+v", rs[1])
	}

	// failover with health: probes run from the bridge towards its targets
	in.Balance = &spec.Balance{Strategy: "failover", Health: &spec.Health{Type: "tcp"}}
	c = mustCompile(t, in, testOpts())
	if c.Health == nil || len(c.Health.Targets) != 2 || c.Health.Targets[0].Addr != "10.0.0.1:80" || c.Health.Strategy != "failover" {
		t.Fatalf("%+v", c.Health)
	}
}

// A bridge relays only the networks the instance declares.
func TestReverseNetworkRestriction(t *testing.T) {
	in := bridgeInst("b")
	in.Network = []string{"tcp"}
	rs := rulesOf(t, mustCompile(t, in, testOpts()))
	if rs[1].Network != "tcp" {
		t.Fatalf("tcp-only bridge must restrict the network: %+v", rs[1])
	}
	in.Network = []string{"tcp", "udp"}
	rs = rulesOf(t, mustCompile(t, in, testOpts()))
	if rs[1].Network != "" {
		t.Fatalf("%+v", rs[1])
	}
	in.Network = []string{"udp"}
	rs = rulesOf(t, mustCompile(t, in, testOpts()))
	if rs[1].Network != "udp" {
		t.Fatalf("%+v", rs[1])
	}
}

// With no idle_profile every kind that carries TCP uses level 100 (tcp_long)
// on every place that sets a level; the node's 103 (30 s ConnectionConfig
// idle by default) appears only when asked for explicitly.
func TestDefaultIdleLevelEveryKind(t *testing.T) {
	udpOnly := fwd("u")
	udpOnly.Network = []string{"udp"}
	for name, in := range map[string]spec.Instance{
		"forward": fwd("f"), "entry": entry("e"), "exit": exitInst("x"),
		"portal": portalInst("p"), "bridge": bridgeInst("b"),
	} {
		s := raw(mustCompile(t, in, testOpts()))
		if strings.Contains(s, `"userLevel":103`) || strings.Contains(s, `"level":103`) || strings.Contains(s, `"level":101`) {
			t.Fatalf("%s: a default level other than tcp_long: %s", name, s)
		}
		if !strings.Contains(s, `"userLevel":100`) && !strings.Contains(s, `"level":100`) {
			t.Fatalf("%s: tcp_long (100) not applied: %s", name, s)
		}
		in.IdleProfile = "tcp_default"
		if s := raw(mustCompile(t, in, testOpts())); !strings.Contains(s, `103`) || strings.Contains(s, `"userLevel":100`) {
			t.Fatalf("%s: explicit tcp_default must give 103: %s", name, s)
		}
	}
	if s := raw(mustCompile(t, udpOnly, testOpts())); !strings.Contains(s, `"userLevel":101`) {
		t.Fatalf("udp-only default must be udp_short (101): %s", s)
	}
}
