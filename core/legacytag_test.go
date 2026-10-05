package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseLegacyTag(t *testing.T) {
	cases := []struct {
		tag  string
		port int
		ok   bool
	}{
		{"V2ray_0.0.0.0_65534", 65534, true},
		{"Shadowsocks_0.0.0.0_65533", 65533, true},
		{"Vless_127.0.0.1_2083", 2083, true},
		{"Trojan_::_443", 443, true},
		{"Shadowsocks-Plugin_0.0.0.0_8388", 8388, true},
		{"node173@subscribe.example.com", 0, false},
		{"direct4", 0, false},
		{"my_custom_inbound", 0, false},   // middle part is not an IP
		{"V2ray_0.0.0.0_0", 0, false},     // port 0
		{"V2ray_0.0.0.0_65536", 0, false}, // port out of range
		{"_0.0.0.0_80", 0, false},         // no type
		{"V2ray_0.0.0.0_", 0, false},
	}
	for _, c := range cases {
		port, ok := ParseLegacyTag(c.tag)
		if port != c.port || ok != c.ok {
			t.Errorf("ParseLegacyTag(%q) = %d, %v; want %d, %v", c.tag, port, ok, c.port, c.ok)
		}
	}
}

func rule(t *testing.T, s string) json.RawMessage {
	t.Helper()
	if !json.Valid([]byte(s)) {
		t.Fatalf("invalid test rule %s", s)
	}
	return json.RawMessage(s)
}

func TestRewriteLegacyTags(t *testing.T) {
	ports := map[int]string{65534: "node214@h", 2083: "node138@h"}
	reserved := map[string]bool{"V2ray_0.0.0.0_2083": true} // the user's own inbound
	var seen []string
	note := func(r LegacyRef, node string) { seen = append(seen, r.Tag+">"+node) }

	in := rule(t, `{"type":"field","inboundTag":["V2ray_0.0.0.0_65534","other"],"outboundTag":"ca-socks","domain":["geosite:netflix"]}`)
	out := rewriteLegacyTags(in, ports, reserved, note)
	var got struct {
		InboundTag  []string `json:"inboundTag"`
		OutboundTag string   `json:"outboundTag"`
		Domain      []string `json:"domain"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got.InboundTag, ",") != "node214@h,other" || got.OutboundTag != "ca-socks" || got.Domain[0] != "geosite:netflix" {
		t.Fatalf("rewritten rule: %s", out)
	}

	// Single-string form stays a string.
	out = rewriteLegacyTags(rule(t, `{"inboundTag":"V2ray_0.0.0.0_65534","outboundTag":"x"}`), ports, reserved, note)
	if !strings.Contains(string(out), `"inboundTag":"node214@h"`) {
		t.Fatalf("single-string inboundTag: %s", out)
	}

	// Reserved (custom inbound) tags, unknown ports and plain rules are untouched, byte for byte.
	for _, s := range []string{
		`{"inboundTag":["V2ray_0.0.0.0_2083"],"outboundTag":"x"}`,
		`{"inboundTag":["V2ray_0.0.0.0_9999"],"outboundTag":"x"}`,
		`{"inboundTag":["node1@h"],"outboundTag":"x"}`,
		`{"outboundTag":"block","protocol":["bittorrent"]}`,
		`{"type":"field",  "domain":[]}`,
	} {
		if got := rewriteLegacyTags(rule(t, s), ports, reserved, note); string(got) != s {
			t.Errorf("rule changed: %s -> %s", s, got)
		}
	}
	if len(seen) != 2 {
		t.Fatalf("notifications: %v", seen)
	}
}

func TestRuleManagerMapsLegacyTagsByPort(t *testing.T) {
	dir := t.TempDir()
	route := filepath.Join(dir, "route.json")
	os.WriteFile(route, []byte(`{"rules":[
		{"type":"field","inboundTag":["V2ray_0.0.0.0_65534"],"outboundTag":"direct"},
		{"type":"field","outboundTag":"direct","protocol":["bittorrent"]}]}`), 0o600)
	inbound := filepath.Join(dir, "in.json")
	os.WriteFile(inbound, []byte(`[{"tag":"V2ray_0.0.0.0_1234","listen":"127.0.0.1","port":1234,"protocol":"socks","settings":{}}]`), 0o600)

	opts := exampleOptions()
	opts.RouteConfigPath = route
	opts.InboundConfigPath = inbound
	c, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	dump := func() string {
		var all []string
		for _, r := range c.Rules.Rules() {
			all = append(all, string(r))
		}
		return strings.Join(all, "\n")
	}
	if err := c.Rules.SetNode("node1@h", &NodeRules{Port: 65534}); err != nil {
		t.Fatal(err)
	}
	if d := dump(); !strings.Contains(d, `"inboundTag":["node1@h"]`) || strings.Contains(d, "V2ray_0.0.0.0_65534") {
		t.Fatalf("legacy tag not mapped:\n%s", d)
	}
	// Following a port change made in the panel.
	if err := c.Rules.SetNode("node1@h", &NodeRules{Port: 40000}); err != nil {
		t.Fatal(err)
	}
	if d := dump(); !strings.Contains(d, "V2ray_0.0.0.0_65534") {
		t.Fatalf("legacy tag must stay as written when no node listens on its port:\n%s", d)
	}

	refs, err := LegacyTagsInRoute(route, inbound)
	if err != nil || len(refs) != 1 || refs[0].Port != 65534 {
		t.Fatalf("LegacyTagsInRoute = %v, %v", refs, err)
	}
	refs, _ = LegacyTagsInRoute(route, "")
	if len(refs) != 1 {
		t.Fatal(refs)
	}
}
