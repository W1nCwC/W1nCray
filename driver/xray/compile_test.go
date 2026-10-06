package xray

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/spec"
)

const testSecret = "s3cret-for-tests-0123456789abcdef"
const testDomain = "k7q2m9x4v8n1c5b3z6w0r2t4y8" // 26 chars

// openPolicy lets loopback targets through; everything else stays default.
func openPolicy() *spec.Policy {
	return &spec.Policy{
		AllowListen:     []string{"127.0.0.1", "10.0.0.0/8", "0.0.0.0"},
		PrivilegedPorts: true,
		AllowPrivate:    true,
		DenyCIDRs:       []string{"169.254.0.0/16"},
	}
}

func testOpts() Options { return Options{Policy: openPolicy()} }

func fwd(id string) spec.Instance {
	return spec.Instance{
		ID: id, Enabled: true, Engine: spec.EngineXray, Kind: spec.KindForward,
		Listen:  &spec.Listen{Addr: "127.0.0.1", Ports: "20000"},
		Network: []string{"tcp"},
		Targets: []spec.Target{{Host: "10.1.2.3", Ports: "80"}},
	}
}

func entry(id string) spec.Instance {
	in := fwd(id)
	in.Kind = spec.KindTunnelEntry
	in.Secret = testSecret
	in.Tunnel = &spec.Tunnel{Type: "tcp", Server: "198.51.100.7:4443"}
	return in
}

func exitInst(id string) spec.Instance {
	return spec.Instance{
		ID: id, Enabled: true, Engine: spec.EngineXray, Kind: spec.KindTunnelExit,
		Network: []string{"tcp"},
		Targets: []spec.Target{{Host: "10.1.2.3", Ports: "80"}},
		Secret:  testSecret,
		Tunnel:  &spec.Tunnel{Type: "tcp", Listen: "0.0.0.0:4443"},
	}
}

func portalInst(id string) spec.Instance {
	return spec.Instance{
		ID: id, Enabled: true, Engine: spec.EngineXray, Kind: spec.KindReversePortal,
		Listen:  &spec.Listen{Addr: "127.0.0.1", Ports: "20001"},
		Network: []string{"tcp", "udp"},
		Secret:  testSecret,
		Tunnel:  &spec.Tunnel{Type: "tcp", Listen: "0.0.0.0:4444"},
		Reverse: &spec.Reverse{Domain: testDomain},
	}
}

func bridgeInst(id string) spec.Instance {
	return spec.Instance{
		ID: id, Enabled: true, Engine: spec.EngineXray, Kind: spec.KindReverseBridge,
		Network: []string{"tcp", "udp"},
		Targets: []spec.Target{{Host: "192.168.1.10", Ports: "3389"}},
		Secret:  testSecret,
		Tunnel:  &spec.Tunnel{Type: "tcp", Server: "198.51.100.7:4444"},
		Reverse: &spec.Reverse{Domain: testDomain},
	}
}

func mustCompile(t *testing.T, in spec.Instance, o Options) Compiled {
	t.Helper()
	c, err := Compile(in, o)
	if err != nil {
		t.Fatalf("Compile(%s): %v", in.ID, err)
	}
	return c
}

func rulesOf(t *testing.T, c Compiled) []jRule {
	t.Helper()
	var out []jRule
	for _, r := range c.Rules {
		var jr jRule
		if err := json.Unmarshal(r, &jr); err != nil {
			t.Fatal(err)
		}
		out = append(out, jr)
	}
	return out
}

func partTags(ps []Part) []string {
	var out []string
	for _, p := range ps {
		out = append(out, p.Tag)
	}
	return out
}

func hasTag(ps []Part, tag string) bool {
	for _, p := range ps {
		if p.Tag == tag {
			return true
		}
	}
	return false
}

func raw(c Compiled) string {
	b, _ := MarshalCompiled(c)
	return string(b)
}

// Every kind compiles and Xray's own config loader accepts the result.
func TestCompileAllKindsBuildInXray(t *testing.T) {
	cases := map[string]spec.Instance{
		"forward": fwd("f1"),
		"entry":   entry("e1"),
		"exit":    exitInst("x1"),
		"portal":  portalInst("p1"),
		"bridge":  bridgeInst("b1"),
	}
	// tunnel carrier matrix
	for _, ty := range []string{"tcp", "ws", "grpc", "xhttp"} {
		in := exitInst("xc-" + ty)
		in.Tunnel.Type = ty
		in.Tunnel.Security = "vless_enc"
		if ty != "tcp" {
			in.Tunnel.Path = "/tun"
		}
		cases["exit-enc-"+ty] = in
		en := entry("ec-" + ty)
		en.Tunnel.Type = ty
		en.Tunnel.Security = "vless_enc"
		if ty != "tcp" {
			en.Tunnel.Path = "/tun"
		}
		cases["entry-enc-"+ty] = en
	}
	for _, ty := range []string{"tls", "wss", "grpc", "xhttp"} {
		in := exitInst("xt-" + ty)
		in.Tunnel.Type = ty
		in.Tunnel.Security = "tls_pin"
		in.Tunnel.PinSHA256 = strings.Repeat("ab", 32)
		in.Tunnel.Cert = &spec.Cert{Mode: "self"}
		in.Tunnel.SNI = "tun.example.net"
		cases["exit-pin-"+ty] = in
		en := entry("et-" + ty)
		en.Tunnel.Type = ty
		en.Tunnel.Security = "tls_pin"
		en.Tunnel.PinSHA256 = strings.Repeat("ab", 32)
		en.Tunnel.SNI = "tun.example.net"
		cases["entry-pin-"+ty] = en
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			c := mustCompile(t, in, testOpts())
			if len(c.Inbounds) == 0 && in.Kind != spec.KindReverseBridge {
				t.Fatal("no inbounds")
			}
			if _, err := buildHandlers(&c); err != nil {
				t.Fatalf("Xray rejected the output: %v\n%s", err, raw(c))
			}
		})
	}
}

func TestCompileDeterministicAndHash(t *testing.T) {
	d := New(nil, testOpts())
	for _, in := range []spec.Instance{fwd("f1"), entry("e1"), exitInst("x1"), portalInst("p1"), bridgeInst("b1")} {
		a1, err := d.Render(in)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 5; i++ {
			a2, _ := d.Render(in)
			if a1.Hash != a2.Hash || !bytes.Equal(a1.Files[CompiledFile], a2.Files[CompiledFile]) {
				t.Fatalf("%s: render is not deterministic", in.ID)
			}
		}
		in2 := in
		in2.Secret = in.Secret + "x"
		if in.Secret != "" {
			a3, _ := d.Render(in2)
			if a3.Hash == a1.Hash {
				t.Fatalf("%s: hash does not depend on the secret", in.ID)
			}
		}
		in3 := in
		in3.ID = in.ID + "z"
		a4, _ := d.Render(in3)
		if a4.Hash == a1.Hash {
			t.Fatalf("%s: hash does not depend on the id", in.ID)
		}
	}
}

// The secret must never appear in the compiled output; credentials derived
// from it may (they have to reach Xray).
func TestSecretNotInOutput(t *testing.T) {
	for _, in := range []spec.Instance{entry("e1"), exitInst("x1"), portalInst("p1"), bridgeInst("b1")} {
		c := mustCompile(t, in, testOpts())
		if strings.Contains(raw(c), testSecret) {
			t.Fatalf("%s: secret leaked into compiled output", in.ID)
		}
	}
}

func TestSecretNotInErrors(t *testing.T) {
	in := entry("e1")
	in.Tunnel.Type = "bogus"
	_, err := Compile(in, testOpts())
	if err == nil || strings.Contains(err.Error(), testSecret) {
		t.Fatalf("unexpected error %v", err)
	}
	in = entry("e1")
	in.Secret = "short"
	_, err = Compile(in, testOpts())
	if err == nil || strings.Contains(err.Error(), "short") && strings.Contains(err.Error(), `"short"`) {
		t.Fatalf("secret echoed: %v", err)
	}
}

// Tags must not match the XrayR legacy pattern core/legacytag.go rewrites
// ("<Type>_<IP>_<Port>"), even for ids that contain underscores.
func TestTagsAvoidLegacyPattern(t *testing.T) {
	legacy := regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*_(.+)_([0-9]{1,5})$`) // copy of core.legacyTagRe
	for _, id := range []string{"a", "a_1_2", "x_0-0-0-0_65534", "my-fwd"} {
		for _, in := range []spec.Instance{fwd(id), entry(id), exitInst(id), portalInst(id), bridgeInst(id)} {
			c := mustCompile(t, in, testOpts())
			tags := append(partTags(c.Inbounds), partTags(c.Outbounds)...)
			if c.Reverse != nil {
				tags = append(tags, c.Reverse.Tag)
			}
			for _, r := range c.Balancers {
				var b jBalancer
				_ = json.Unmarshal(r, &b)
				tags = append(tags, b.Tag)
			}
			for _, tg := range tags {
				if !strings.HasPrefix(tg, "w1n-fwd/") {
					t.Fatalf("tag %q outside the namespace", tg)
				}
				if legacy.MatchString(tg) {
					t.Fatalf("tag %q matches the legacy XrayR pattern", tg)
				}
			}
		}
	}
}

func TestNoRuleTag(t *testing.T) {
	for _, in := range []spec.Instance{fwd("f"), entry("e"), exitInst("x"), portalInst("p"), bridgeInst("b")} {
		c := mustCompile(t, in, testOpts())
		if strings.Contains(raw(c), "ruleTag") {
			t.Fatalf("%s uses ruleTag", in.ID)
		}
	}
}

// Every rule is confined to the inbound(s) of its own instance.
func TestRulesAreInboundScoped(t *testing.T) {
	for _, in := range []spec.Instance{fwd("f"), entry("e"), exitInst("x"), portalInst("p"), bridgeInst("b")} {
		c := mustCompile(t, in, testOpts())
		for _, r := range rulesOf(t, c) {
			if len(r.InboundTag) == 0 {
				t.Fatalf("%s: rule without inboundTag: %+v", in.ID, r)
			}
			for _, tg := range r.InboundTag {
				if !strings.HasSuffix(tg, "/"+in.ID) {
					t.Fatalf("%s: rule scoped to foreign inbound %q", in.ID, tg)
				}
			}
			if r.OutboundTag != "" && !strings.HasSuffix(r.OutboundTag, "/"+in.ID) && !strings.Contains(r.OutboundTag, "/"+in.ID+"/") {
				t.Fatalf("%s: rule routes to foreign outbound %q", in.ID, r.OutboundTag)
			}
		}
		// the last rule of every inbound is a block
		last := map[string]jRule{}
		for _, r := range rulesOf(t, c) {
			last[r.InboundTag[0]] = r
		}
		for tg, r := range last {
			if !strings.Contains(r.OutboundTag, "/k/") {
				t.Fatalf("%s: inbound %s does not end in a block rule: %+v", in.ID, tg, r)
			}
		}
	}
}

func TestForwardSinglePortAndRange(t *testing.T) {
	in := fwd("f1")
	c := mustCompile(t, in, testOpts())
	var ib jInbound
	_ = json.Unmarshal(c.Inbounds[0].Config, &ib)
	if ib.Tag != "w1n-fwd/i/f1" || ib.Port != "20000" || ib.Listen != "127.0.0.1" || ib.Protocol != "dokodemo-door" {
		t.Fatalf("%+v", ib)
	}
	var dk jDokodemo
	b, _ := json.Marshal(ib.Settings)
	_ = json.Unmarshal(b, &dk)
	if dk.Address != "10.1.2.3" || dk.Port != 80 || dk.Network != "tcp" {
		t.Fatalf("%+v", dk)
	}

	// range one-to-one
	in = fwd("f2")
	in.Listen.Ports = "20010-20012"
	in.Targets = []spec.Target{{Host: "10.1.2.3", Ports: "30000-30002"}}
	in.Network = []string{"tcp", "udp"}
	c = mustCompile(t, in, testOpts())
	_ = json.Unmarshal(c.Inbounds[0].Config, &ib)
	b, _ = json.Marshal(ib.Settings)
	dk = jDokodemo{}
	_ = json.Unmarshal(b, &dk)
	want := map[string]string{"20010": "10.1.2.3:30000", "20011": "10.1.2.3:30001", "20012": "10.1.2.3:30002"}
	if ib.Port != "20010-20012" || dk.Port != 0 || len(dk.PortMap) != 3 || dk.Network != "tcp,udp" {
		t.Fatalf("%+v %+v", ib, dk)
	}
	for k, v := range want {
		if dk.PortMap[k] != v {
			t.Fatalf("portMap %v", dk.PortMap)
		}
	}
	if len(c.Claims) != 6 {
		t.Fatalf("claims %v", c.Claims)
	}
	pc := c.PortClaims()
	if pc[0].Owner != "f2" || pc[0].Proto != "tcp" || pc[0].Addr != "127.0.0.1" || pc[0].Port != 20010 {
		t.Fatalf("%+v", pc[0])
	}
}

func TestForwardPortMapOnly(t *testing.T) {
	in := fwd("f1")
	in.Listen = &spec.Listen{Addr: "127.0.0.1", Ports: "20020-20021", PortMap: map[string]string{
		"20020": "10.0.0.5:81", "20021": "[2001:db8::1]:82",
	}}
	in.Targets = nil
	c := mustCompile(t, in, testOpts())
	var ib jInbound
	_ = json.Unmarshal(c.Inbounds[0].Config, &ib)
	b, _ := json.Marshal(ib.Settings)
	var dk jDokodemo
	_ = json.Unmarshal(b, &dk)
	if dk.PortMap["20020"] != "10.0.0.5:81" || dk.PortMap["20021"] != "[2001:db8::1]:82" {
		t.Fatalf("%+v", dk)
	}
	if dk.Address == "" {
		t.Fatal("dokodemo default address must not be empty (it would fall back to localhost)")
	}
	// uncovered port rejected
	in.Listen.Ports = "20020-20022"
	if _, err := Compile(in, testOpts()); err == nil {
		t.Fatal("uncovered listen port accepted")
	}
}

func TestForwardMultiTargetBalancer(t *testing.T) {
	in := fwd("lb")
	in.Targets = []spec.Target{{Host: "10.0.0.1", Ports: "80"}, {Host: "10.0.0.2", Ports: "80", Weight: 3}}
	in.Balance = &spec.Balance{Strategy: "round_robin"}
	c := mustCompile(t, in, testOpts())
	// weight 1 + 3 -> 4 outbounds (+ block)
	var outs []string
	for _, p := range c.Outbounds {
		if strings.HasPrefix(p.Tag, "w1n-fwd/o/lb/") {
			outs = append(outs, p.Tag)
		}
	}
	if len(outs) != 4 {
		t.Fatalf("outbounds %v", outs)
	}
	if len(c.Balancers) != 1 {
		t.Fatal("balancer missing")
	}
	var bal jBalancer
	_ = json.Unmarshal(c.Balancers[0], &bal)
	if bal.Tag != "w1n-fwd/b/lb" || bal.Selector[0] != "w1n-fwd/o/lb/" || bal.Strategy.Type != "roundRobin" {
		t.Fatalf("%+v", bal)
	}
	rs := rulesOf(t, c)
	found := false
	for _, r := range rs {
		if r.BalancerTag == "w1n-fwd/b/lb" {
			found = true
		}
	}
	if !found {
		t.Fatal("no rule uses the balancer")
	}
	// the selector of id "lb" must not match the outbounds of id "lb-2"
	other := mustCompile(t, func() spec.Instance { i := in; i.ID = "lb-2"; return i }(), testOpts())
	for _, p := range other.Outbounds {
		if strings.HasPrefix(p.Tag, "w1n-fwd/o/lb/") {
			t.Fatalf("selector prefix collision with %s", p.Tag)
		}
	}
	// random
	in.Balance.Strategy = "random"
	c = mustCompile(t, in, testOpts())
	_ = json.Unmarshal(c.Balancers[0], &bal)
	if bal.Strategy.Type != "random" {
		t.Fatalf("%+v", bal)
	}
	// failover needs health; with health only the first target's tag set is used per target
	in.Balance = &spec.Balance{Strategy: "failover"}
	if _, err := Compile(in, testOpts()); err == nil {
		t.Fatal("failover without health accepted")
	}
	in.Balance.Health = &spec.Health{Type: "tcp"}
	c = mustCompile(t, in, testOpts())
	if c.Health == nil || len(c.Health.Targets) != 2 || len(c.Health.Targets[1].Tags) != 1 || c.Health.IntervalS != 5 || c.Health.MaxFails != 3 {
		t.Fatalf("%+v", c.Health)
	}
}

func TestProxyProtocol(t *testing.T) {
	// send
	in := fwd("f1")
	in.ProxyProtocolOut = 2
	c := mustCompile(t, in, testOpts())
	var ob jOutbound
	for _, p := range c.Outbounds {
		if p.Tag == "w1n-fwd/o/f1" {
			_ = json.Unmarshal(p.Config, &ob)
		}
	}
	b, _ := json.Marshal(ob.Settings)
	var fr jFreedom
	_ = json.Unmarshal(b, &fr)
	if fr.ProxyProtocol != 2 {
		t.Fatalf("%+v", fr)
	}
	// udp + proxy out rejected
	in.Network = []string{"tcp", "udp"}
	if _, err := Compile(in, testOpts()); err == nil || !strings.Contains(err.Error(), "TCP only") {
		t.Fatalf("udp+proxy_out: %v", err)
	}
	in.Network = []string{"udp"}
	if _, err := Compile(in, testOpts()); err == nil {
		t.Fatal("udp-only with proxy_out accepted")
	}
	// accept
	in = fwd("f2")
	in.AcceptProxyProtocol = true
	c = mustCompile(t, in, testOpts())
	var ib jInbound
	_ = json.Unmarshal(c.Inbounds[0].Config, &ib)
	if ib.Stream == nil || ib.Stream.Sockopt == nil || !ib.Stream.Sockopt.AcceptProxyProtocol {
		t.Fatalf("%+v", ib)
	}
	// accept on a public listen address is refused unless the policy allows it
	in.Listen.Addr = "0.0.0.0"
	if _, err := Compile(in, testOpts()); err == nil || !strings.Contains(err.Error(), "forgeable") {
		t.Fatalf("public accept_proxy: %v", err)
	}
	in.Listen.Addr = "203.0.113.9"
	o := testOpts()
	o.Policy = openPolicy()
	o.Policy.AllowListen = append(o.Policy.AllowListen, "203.0.113.9")
	if _, err := Compile(in, o); err == nil {
		t.Fatal("public accept_proxy accepted without AllowAcceptProxyOnPublic")
	}
	o.Policy.AllowAcceptProxyOnPublic = true
	if _, err := Compile(in, o); err != nil {
		t.Fatalf("policy-allowed accept_proxy: %v", err)
	}
	// private/loopback listeners are fine
	in.Listen.Addr = "10.9.9.9"
	if _, err := Compile(in, testOpts()); err != nil {
		t.Fatal(err)
	}
	// accept with udp rejected
	in.Network = []string{"tcp", "udp"}
	if _, err := Compile(in, testOpts()); err == nil {
		t.Fatal("accept_proxy with udp accepted")
	}
	// nil policy: public listener still refused (fail closed)
	in = fwd("f3")
	in.AcceptProxyProtocol = true
	in.Listen.Addr = "0.0.0.0"
	if _, err := Compile(in, Options{}); err == nil {
		t.Fatal("nil policy must not allow public accept_proxy")
	}
}

// PROXY header carrying on the forward tunnel: entry freedom{proxyProtocol}
// dials the target through the tunnel outbound (dialerProxy).
func TestEntryProxyCarry(t *testing.T) {
	in := entry("e1")
	in.ProxyProtocolOut = 2
	c := mustCompile(t, in, testOpts())
	var fr *jOutbound
	for _, p := range c.Outbounds {
		if p.Tag == "w1n-fwd/o/e1" {
			var ob jOutbound
			_ = json.Unmarshal(p.Config, &ob)
			fr = &ob
		}
	}
	if fr == nil {
		t.Fatal("no freedom outbound")
	}
	if fr.Stream == nil || fr.Stream.Sockopt == nil || fr.Stream.Sockopt.DialerProxy != "w1n-fwd/t/e1" {
		t.Fatalf("dialerProxy missing: %+v", fr.Stream)
	}
	b, _ := json.Marshal(fr.Settings)
	var f jFreedom
	_ = json.Unmarshal(b, &f)
	if f.ProxyProtocol != 2 {
		t.Fatal("proxyProtocol missing")
	}
	if !hasTag(c.Outbounds, "w1n-fwd/t/e1") {
		t.Fatal("tunnel outbound missing")
	}
	// plain entry routes straight into the tunnel outbound
	c = mustCompile(t, entry("e2"), testOpts())
	routed := false
	for _, r := range rulesOf(t, c) {
		if r.OutboundTag == "w1n-fwd/t/e2" {
			routed = true
		}
	}
	if !routed {
		t.Fatal("plain entry does not route into the tunnel")
	}
	// udp with carrying rejected
	in.Network = []string{"tcp", "udp"}
	if _, err := Compile(in, testOpts()); err == nil {
		t.Fatal("udp + proxy carry accepted")
	}
}

// The exit relays only declared destinations, only for its own client.
func TestExitWhitelist(t *testing.T) {
	in := exitInst("x1")
	in.Targets = []spec.Target{
		{Host: "10.1.2.3", Ports: "80"},
		{Host: "db.internal.example", Ports: "5432-5433"},
		{Host: "2001:db8::5", Ports: "443"},
	}
	c := mustCompile(t, in, testOpts())
	rs := rulesOf(t, c)
	if len(rs) != 4 { // 3 allows + final block
		t.Fatalf("%d rules: %+v", len(rs), rs)
	}
	for _, r := range rs[:3] {
		if r.InboundTag[0] != "w1n-fwd/x/x1" || len(r.User) != 1 || r.User[0] != "w1n-fwd/x1" || r.OutboundTag != "w1n-fwd/o/x1" || r.Port == "" {
			t.Fatalf("%+v", r)
		}
		if (len(r.IP) == 0) == (len(r.Domain) == 0) {
			t.Fatalf("exactly one of ip/domain expected: %+v", r)
		}
	}
	if rs[1].Domain[0] != "full:db.internal.example" || rs[1].Port != "5432-5433" || rs[2].IP[0] != "2001:db8::5" {
		t.Fatalf("%+v", rs)
	}
	if rs[3].OutboundTag != "w1n-fwd/k/x1" || len(rs[3].User) != 0 || len(rs[3].IP) != 0 {
		t.Fatalf("final rule %+v", rs[3])
	}
	// the tunnel inbound has exactly one client, with the per-instance email
	var ib jInbound
	_ = json.Unmarshal(c.Inbounds[0].Config, &ib)
	b, _ := json.Marshal(ib.Settings)
	var vi jVlessIn
	_ = json.Unmarshal(b, &vi)
	if len(vi.Clients) != 1 || vi.Clients[0].Email != "w1n-fwd/x1" {
		t.Fatalf("%+v", vi)
	}
	// without fixed targets the exit is refused unless policy and instance allow any
	in.Targets = nil
	if _, err := Compile(in, testOpts()); err == nil {
		t.Fatal("exit without targets accepted")
	}
	in.AllowAnyTarget = true
	if _, err := Compile(in, testOpts()); err == nil || !strings.Contains(err.Error(), "local policy") {
		t.Fatalf("allow_any_target without policy: %v", err)
	}
	o := testOpts()
	o.Policy.AllowAnyTarget = true
	c = mustCompile(t, in, o)
	rs = rulesOf(t, c)
	if len(rs) != 2 || len(rs[0].User) != 1 || rs[0].OutboundTag != "w1n-fwd/o/x1" || rs[1].OutboundTag != "w1n-fwd/k/x1" {
		t.Fatalf("%+v", rs)
	}
	// nil policy never allows it
	if _, err := Compile(in, Options{}); err == nil {
		t.Fatal("nil policy allowed allow_any_target")
	}
}

func TestExitNetworkRestriction(t *testing.T) {
	in := exitInst("x1")
	rs := rulesOf(t, mustCompile(t, in, testOpts()))
	if rs[0].Network != "tcp" {
		t.Fatalf("tcp-only exit must restrict the network: %+v", rs[0])
	}
	in.Network = []string{"tcp", "udp"}
	rs = rulesOf(t, mustCompile(t, in, testOpts()))
	if rs[0].Network != "" {
		t.Fatalf("%+v", rs[0])
	}
}

func TestPortalBridgeRules(t *testing.T) {
	p := mustCompile(t, portalInst("r1"), testOpts())
	if p.Reverse == nil || p.Reverse.Role != "portal" || p.Reverse.Tag != "w1n-fwd/r/r1" || p.Reverse.Domain != testDomain {
		t.Fatalf("%+v", p.Reverse)
	}
	rs := rulesOf(t, p)
	// tunnel inbound: rendezvous only, then block
	if rs[0].InboundTag[0] != "w1n-fwd/x/r1" || rs[0].Domain[0] != "full:"+testDomain || rs[0].OutboundTag != "w1n-fwd/r/r1" || len(rs[0].User) != 1 {
		t.Fatalf("%+v", rs[0])
	}
	if rs[1].InboundTag[0] != "w1n-fwd/x/r1" || rs[1].OutboundTag != "w1n-fwd/k/r1" {
		t.Fatalf("%+v", rs[1])
	}
	if rs[2].InboundTag[0] != "w1n-fwd/i/r1" || rs[2].OutboundTag != "w1n-fwd/r/r1" {
		t.Fatalf("%+v", rs[2])
	}
	// claims: user listener tcp+udp, tunnel listener tcp
	if len(p.Claims) != 3 {
		t.Fatalf("%v", p.Claims)
	}

	b := mustCompile(t, bridgeInst("r1"), testOpts())
	if b.Reverse == nil || b.Reverse.Role != "bridge" || len(b.Inbounds) != 0 {
		t.Fatalf("%+v", b.Reverse)
	}
	rs = rulesOf(t, b)
	if rs[0].InboundTag[0] != "w1n-fwd/r/r1" || rs[0].Domain[0] != "full:"+testDomain || rs[0].OutboundTag != "w1n-fwd/t/r1" {
		t.Fatalf("%+v", rs[0])
	}
	// the destination is fixed by the bridge's target: the relayed connection
	// goes to a freedom outbound that redirects to it (no ip/port matching on
	// what the portal asked for)
	if len(rs[1].IP) != 0 || len(rs[1].Domain) != 0 || rs[1].Port != "" || rs[1].OutboundTag != "w1n-fwd/o/r1" {
		t.Fatalf("%+v", rs[1])
	}
	if rs[len(rs)-1].OutboundTag != "w1n-fwd/k/r1" {
		t.Fatalf("%+v", rs)
	}
	if fr := freedomOf(t, b, "w1n-fwd/o/r1"); fr.Redirect != "192.168.1.10:3389" {
		t.Fatalf("redirect %q", fr.Redirect)
	}
	// BridgeAllow is refused (the targets are the allow list now)
	in := bridgeInst("r2")
	in.Reverse.BridgeAllow = []spec.Allow{{Host: "10.5.5.5", Ports: "22"}}
	if _, err := Compile(in, testOpts()); err == nil || !strings.Contains(err.Error(), "bridge_allow") || !strings.Contains(err.Error(), "targets") {
		t.Fatalf("bridge_allow on the bridge: %v", err)
	}
	// a bridge without any destination is refused
	in = bridgeInst("r3")
	in.Targets = nil
	if _, err := Compile(in, testOpts()); err == nil {
		t.Fatal("open bridge accepted")
	}
	// domain entropy / length
	in = bridgeInst("r4")
	in.Reverse.Domain = "short"
	if _, err := Compile(in, testOpts()); err == nil {
		t.Fatal("short reverse domain accepted")
	}
	in.Reverse.Domain = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := Compile(in, testOpts()); err == nil {
		t.Fatal("low-entropy reverse domain accepted")
	}
}

func TestACL(t *testing.T) {
	in := fwd("f1")
	in.ACL = &spec.ACL{Allow: []string{"10.0.0.0/8", "192.0.2.1"}, Deny: []string{"10.9.0.0/16"}}
	rs := rulesOf(t, mustCompile(t, in, testOpts()))
	if len(rs) != 3 {
		t.Fatalf("%+v", rs)
	}
	if rs[0].Source[0] != "10.9.0.0/16" || rs[0].OutboundTag != "w1n-fwd/k/f1" {
		t.Fatalf("%+v", rs[0])
	}
	if len(rs[1].Source) != 2 || rs[1].Source[1] != "192.0.2.1" || rs[1].OutboundTag != "w1n-fwd/o/f1" {
		t.Fatalf("%+v", rs[1])
	}
	in.ACL = &spec.ACL{Allow: []string{"not-an-ip"}}
	if _, err := Compile(in, testOpts()); err == nil {
		t.Fatal("bad acl accepted")
	}
}

func TestIdleProfileLevels(t *testing.T) {
	level := func(in spec.Instance) uint32 {
		c := mustCompile(t, in, testOpts())
		var ib jInbound
		_ = json.Unmarshal(c.Inbounds[0].Config, &ib)
		b, _ := json.Marshal(ib.Settings)
		var dk jDokodemo
		_ = json.Unmarshal(b, &dk)
		return dk.UserLevel
	}
	in := fwd("f1")
	// No idle_profile: TCP instances get tcp_long (an idle SSH session must
	// survive), not the node's 30 s ConnectionConfig default.
	if level(in) != 100 {
		t.Fatal("default tcp level must be tcp_long (100)")
	}
	in.IdleProfile = "tcp_long"
	if level(in) != 100 {
		t.Fatal("tcp_long")
	}
	// An explicit tcp_default still selects the node policy.
	in.IdleProfile = "tcp_default"
	if level(in) != 103 {
		t.Fatal("explicit tcp_default must stay 103")
	}
	// tcp+udp without a profile: the instance carries TCP, so tcp_long; an
	// explicit udp profile is not overridden.
	in.IdleProfile = ""
	in.Network = []string{"tcp", "udp"}
	if level(in) != 100 {
		t.Fatal("default tcp+udp level must be tcp_long (100)")
	}
	in.IdleProfile = "udp_short"
	if level(in) != 101 {
		t.Fatal("explicit udp_short on tcp+udp must stay 101")
	}
	in.IdleProfile = "udp_long"
	if level(in) != 102 {
		t.Fatal("explicit udp_long on tcp+udp must stay 102")
	}
	in.Network = []string{"udp"}
	in.IdleProfile = ""
	if level(in) != 101 {
		t.Fatal("udp default")
	}
	in.IdleProfile = "udp_long"
	if level(in) != 102 {
		t.Fatal("udp_long")
	}
	in.IdleProfile = "tcp_long"
	if _, err := Compile(in, testOpts()); err == nil {
		t.Fatal("tcp profile on udp-only instance accepted")
	}
	in.IdleProfile = "forever"
	if _, err := Compile(in, testOpts()); err == nil {
		t.Fatal("unknown profile accepted")
	}
}

func TestLimitsRejected(t *testing.T) {
	for _, l := range []spec.Limits{{MaxConns: 1}, {RateUpBps: 1}, {RateDownBps: 1}} {
		in := fwd("f1")
		l := l
		in.Limits = &l
		if _, err := Compile(in, testOpts()); err == nil || !strings.Contains(err.Error(), "limits") {
			t.Fatalf("%+v: %v", l, err)
		}
	}
	in := fwd("f1")
	in.Limits = &spec.Limits{}
	mustCompile(t, in, testOpts())
}

func TestDisabledInstance(t *testing.T) {
	in := fwd("f1")
	in.Enabled = false
	c := mustCompile(t, in, testOpts())
	if !c.Disabled || len(c.Inbounds) != 0 || len(c.Rules) != 0 {
		t.Fatalf("%+v", c)
	}
}

func TestTunnelSecurityMatrix(t *testing.T) {
	type tc struct {
		ty, sec string
		ok      bool
		note    string
	}
	cases := []tc{
		{"tcp", "", true, "default vless_enc"},
		{"tcp", "vless_enc", true, ""},
		{"tcp", "none", false, "plaintext raw"},
		{"tcp", "tls", true, "tcp+tls (needs cert)"},
		{"ws", "", true, "default vless_enc"},
		{"ws", "none", true, "behind a TLS terminator"},
		{"ws", "vless_enc", true, ""},
		{"tls", "none", false, ""},
		{"tls", "vless_enc", false, ""},
		{"wss", "vless_enc", false, ""},
		{"kcp", "", false, "unsupported carrier"},
		{"quic", "", false, "unsupported carrier"},
		{"nope", "", false, ""},
	}
	for _, c := range cases {
		in := exitInst("x1")
		in.Tunnel.Type, in.Tunnel.Security = c.ty, c.sec
		if c.ty == "ws" {
			in.Tunnel.Path = "/w"
		}
		if c.ty == "tls" || c.sec == "tls" {
			in.Tunnel.Cert = &spec.Cert{Mode: "panel"}
		}
		o := testOpts()
		o.PanelCert = func(string) (string, string, error) { cp, kp, _, _ := SelfCert("x", ""); return cp, kp, nil }
		_, err := Compile(in, o)
		if (err == nil) != c.ok {
			t.Errorf("%s/%s (%s): err=%v want ok=%v", c.ty, c.sec, c.note, err, c.ok)
		}
	}
	// tls_pin needs a valid pin
	in := entry("e1")
	in.Tunnel.Type, in.Tunnel.Security = "tls", "tls_pin"
	if _, err := Compile(in, testOpts()); err == nil {
		t.Fatal("tls_pin without pin accepted")
	}
	in.Tunnel.PinSHA256 = "zz"
	if _, err := Compile(in, testOpts()); err == nil {
		t.Fatal("malformed pin accepted")
	}
	in.Tunnel.PinSHA256 = strings.Repeat("AB", 32)
	c := mustCompile(t, in, testOpts())
	if !strings.Contains(raw(c), strings.Repeat("ab", 32)) {
		t.Fatal("pin must be normalised to lower case")
	}
	if strings.Contains(raw(c), "allowInsecure") {
		t.Fatal("allowInsecure must never be emitted")
	}
	// a self-signed certificate is only acceptable with a pin
	ex := exitInst("x2")
	ex.Tunnel.Type, ex.Tunnel.Security = "tls", "tls"
	ex.Tunnel.Cert = &spec.Cert{Mode: "self"}
	if _, err := Compile(ex, testOpts()); err == nil {
		t.Fatal("self-signed without pin accepted")
	}
}

func TestCertModes(t *testing.T) {
	ex := exitInst("x1")
	ex.Tunnel.Type, ex.Tunnel.Security = "tls", "tls"
	// file: needs a root
	ex.Tunnel.Cert = &spec.Cert{Mode: "file", CertFile: "/etc/w1n/cert.pem", KeyFile: "/etc/w1n/key.pem"}
	if _, err := Compile(ex, testOpts()); err == nil {
		t.Fatal("file mode accepted without cert roots")
	}
	o := testOpts()
	o.CertRoots = []string{"/etc/w1n"}
	c := mustCompile(t, ex, o)
	if len(c.CertFiles) != 2 || !strings.Contains(raw(c), `"oneTimeLoading":true`) {
		t.Fatalf("%+v", c.CertFiles)
	}
	for _, bad := range []string{"/etc/passwd", "/etc/w1n/../shadow", "/etc/w1nx/cert.pem", "etc/w1n/cert.pem", "/etc/w1n/a b.pem", "/etc/w1n//cert.pem"} {
		x := ex
		x.Tunnel = &spec.Tunnel{Type: "tls", Security: "tls", Listen: "0.0.0.0:4443", Cert: &spec.Cert{Mode: "file", CertFile: bad, KeyFile: "/etc/w1n/key.pem"}}
		if _, err := Compile(x, o); err == nil {
			t.Fatalf("path %q accepted", bad)
		}
	}
	// panel
	ex.Tunnel.Cert = &spec.Cert{Mode: "panel"}
	if _, err := Compile(ex, testOpts()); err == nil {
		t.Fatal("panel mode accepted without provider")
	}
	o.PanelCert = func(id string) (string, string, error) {
		cp, kp, _, err := SelfCert("panel-"+id, "")
		return cp, kp, err
	}
	c = mustCompile(t, ex, o)
	if !strings.Contains(raw(c), "BEGIN CERTIFICATE") {
		t.Fatal("panel certificate not inlined")
	}
}

// The self-signed certificate (and therefore its pin) is a pure function of
// secret and server name.
func TestSelfCertDeterministic(t *testing.T) {
	c1, k1, p1, err := SelfCert(testSecret, "a.example")
	if err != nil {
		t.Fatal(err)
	}
	c2, k2, p2, _ := SelfCert(testSecret, "a.example")
	if c1 != c2 || k1 != k2 || p1 != p2 {
		t.Fatal("not deterministic")
	}
	_, _, p3, _ := SelfCert(testSecret, "b.example")
	_, _, p4, _ := SelfCert(testSecret+"x", "a.example")
	if p1 == p3 || p1 == p4 {
		t.Fatal("pin must depend on secret and name")
	}
	if len(p1) != 64 {
		t.Fatalf("pin %q", p1)
	}
}

func TestCredentialsDerived(t *testing.T) {
	a, _ := deriveCreds(testSecret)
	b, _ := deriveCreds(testSecret)
	c, _ := deriveCreds(testSecret + "x")
	if *a != *b || *a == *c {
		t.Fatal("derivation is not a pure function of the secret")
	}
	if !strings.HasPrefix(a.Decryption, "mlkem768x25519plus.native.0s.") || !strings.HasPrefix(a.Encryption, "mlkem768x25519plus.native.1rtt.") {
		t.Fatalf("%s %s", a.Decryption, a.Encryption)
	}
	if strings.Contains(a.UUID, testSecret) || len(a.UUID) != 36 {
		t.Fatal(a.UUID)
	}
}

func TestValidationWhitelists(t *testing.T) {
	bad := map[string]func(*spec.Instance){
		"id upper":          func(i *spec.Instance) { i.ID = "Fwd" },
		"id slash":          func(i *spec.Instance) { i.ID = "a/b" },
		"id empty":          func(i *spec.Instance) { i.ID = "" },
		"id long":           func(i *spec.Instance) { i.ID = strings.Repeat("a", 41) },
		"unknown kind":      func(i *spec.Instance) { i.Kind = "shell" },
		"other engine":      func(i *spec.Instance) { i.Engine = "gost" },
		"bad network":       func(i *spec.Instance) { i.Network = []string{"sctp"} },
		"listen domain":     func(i *spec.Instance) { i.Listen.Addr = "example.com" },
		"listen empty":      func(i *spec.Instance) { i.Listen.Addr = "" },
		"listen zone":       func(i *spec.Instance) { i.Listen.Addr = "fe80::1%eth0" },
		"port 0":            func(i *spec.Instance) { i.Listen.Ports = "0" },
		"port big":          func(i *spec.Instance) { i.Listen.Ports = "70000" },
		"range reversed":    func(i *spec.Instance) { i.Listen.Ports = "20005-20001" },
		"port junk":         func(i *spec.Instance) { i.Listen.Ports = "80;rm" },
		"host junk":         func(i *spec.Instance) { i.Targets[0].Host = "a b" },
		"host injection":    func(i *spec.Instance) { i.Targets[0].Host = `x","protocol":"` },
		"host newline":      func(i *spec.Instance) { i.Targets[0].Host = "a.com\n" },
		"host underscore":   func(i *spec.Instance) { i.Targets[0].Host = "a_b.com" },
		"host numeric tld":  func(i *spec.Instance) { i.Targets[0].Host = "1.2.3.999" },
		"target port range": func(i *spec.Instance) { i.Targets[0].Ports = "80-90" },
		"weight huge":       func(i *spec.Instance) { i.Targets[0].Weight = 65 },
		"no targets":        func(i *spec.Instance) { i.Targets = nil },
		"tunnel on fwd":     func(i *spec.Instance) { i.Tunnel = &spec.Tunnel{Type: "tcp"} },
		"reverse on fwd":    func(i *spec.Instance) { i.Reverse = &spec.Reverse{Domain: testDomain} },
		"secret on fwd":     func(i *spec.Instance) { i.Secret = testSecret },
		"iphash":            func(i *spec.Instance) { i.Balance = &spec.Balance{Strategy: "iphash"} },
		"least_ping":        func(i *spec.Instance) { i.Balance = &spec.Balance{Strategy: "least_ping"} },
		"proxy 3":           func(i *spec.Instance) { i.ProxyProtocolOut = 3 },
		"port_map outside":  func(i *spec.Instance) { i.Listen.PortMap = map[string]string{"1": "1.1.1.1:1"} },
		"port_map host":     func(i *spec.Instance) { i.Listen.PortMap = map[string]string{"20000": "bad host:1"} },
	}
	for name, mut := range bad {
		in := fwd("f1")
		mut(&in)
		if _, err := Compile(in, testOpts()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// tunnel fields
	tbad := map[string]func(*spec.Instance){
		"path query":    func(i *spec.Instance) { i.Tunnel.Type = "ws"; i.Tunnel.Path = "/a?x=1" },
		"path space":    func(i *spec.Instance) { i.Tunnel.Type = "ws"; i.Tunnel.Path = "/a b" },
		"path no slash": func(i *spec.Instance) { i.Tunnel.Type = "ws"; i.Tunnel.Path = "a" },
		"path raw":      func(i *spec.Instance) { i.Tunnel.Path = "/a" },
		"grpc name":     func(i *spec.Instance) { i.Tunnel.Type = "grpc"; i.Tunnel.Path = "/a b" },
		"host header":   func(i *spec.Instance) { i.Tunnel.Type = "ws"; i.Tunnel.Host = "a b" },
		"sni on plain":  func(i *spec.Instance) { i.Tunnel.SNI = "a.example.com" },
		"alpn junk": func(i *spec.Instance) {
			i.Tunnel.Type = "tls"
			i.Tunnel.Security = "tls"
			i.Tunnel.ALPN = []string{"h2\n"}
		},
		"server no port":  func(i *spec.Instance) { i.Tunnel.Server = "example.com" },
		"server junk":     func(i *spec.Instance) { i.Tunnel.Server = "a b:1" },
		"listen on entry": func(i *spec.Instance) { i.Tunnel.Listen = "0.0.0.0:1" },
		"no secret":       func(i *spec.Instance) { i.Secret = "" },
		"weak secret":     func(i *spec.Instance) { i.Secret = "abc" },
		"secret chars":    func(i *spec.Instance) { i.Secret = "0123456789abcdef\"\n" },
		"pin w/o tls_pin": func(i *spec.Instance) { i.Tunnel.PinSHA256 = strings.Repeat("a", 64) },
	}
	for name, mut := range tbad {
		in := entry("e1")
		mut(&in)
		if _, err := Compile(in, testOpts()); err == nil {
			t.Errorf("tunnel %s: accepted", name)
		}
	}
}

// Policy checks done by the driver as defence in depth.
func TestPolicyEnforcement(t *testing.T) {
	o := Options{Policy: &spec.Policy{AllowListen: []string{"127.0.0.1"}, PortRange: [2]int{20000, 20100}, DenyPorts: []int{20050}}}
	ok := fwd("f1")
	ok.Targets = []spec.Target{{Host: "93.184.216.34", Ports: "80"}}
	if _, err := Compile(ok, o); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*spec.Instance){
		"loopback target":    func(i *spec.Instance) { i.Targets[0].Host = "127.0.0.1" },
		"metadata target":    func(i *spec.Instance) { i.Targets[0].Host = "169.254.169.254" },
		"private target":     func(i *spec.Instance) { i.Targets[0].Host = "10.0.0.1" },
		"v6 loopback":        func(i *spec.Instance) { i.Targets[0].Host = "::1" },
		"v4-mapped loopback": func(i *spec.Instance) { i.Targets[0].Host = "::ffff:127.0.0.1" },
		"localhost":          func(i *spec.Instance) { i.Targets[0].Host = "localhost" },
		"foo.localhost":      func(i *spec.Instance) { i.Targets[0].Host = "foo.localhost" },
		"port_map loopback":  func(i *spec.Instance) { i.Listen.PortMap = map[string]string{"20000": "127.0.0.1:22"} },
		"public listen":      func(i *spec.Instance) { i.Listen.Addr = "0.0.0.0" },
		"port out of range":  func(i *spec.Instance) { i.Listen.Ports = "19999" },
		"denied port":        func(i *spec.Instance) { i.Listen.Ports = "20049-20051" },
		"privileged":         func(i *spec.Instance) { i.Listen.Ports = "80" },
	}
	for name, mut := range cases {
		in := ok
		in.Listen = &spec.Listen{Addr: "127.0.0.1", Ports: "20000"}
		in.Targets = append([]spec.Target(nil), ok.Targets...)
		mut(&in)
		if _, err := Compile(in, o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// nil policy: no listen/target enforcement (the core does it)
	in := fwd("f1")
	in.Targets[0].Host = "127.0.0.1"
	if _, err := Compile(in, Options{}); err != nil {
		t.Fatal(err)
	}
}

func TestCaps(t *testing.T) {
	c := New(nil, Options{}).Caps()
	if c.Name != "xray" || !c.Reverse || !c.ProxyIn || !c.ProxyOut || c.ProxyOutUDP || c.External || c.DisruptsOnChange {
		t.Fatalf("%+v", c)
	}
	if len(c.Kinds) != 5 || c.Stats != "counters" || c.Reload != "hot" {
		t.Fatalf("%+v", c)
	}
}
