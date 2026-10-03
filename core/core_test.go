package core

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func exampleOptions() Options {
	dir := filepath.Join("..", "release", "config")
	return Options{
		LogLevel:           "warning",
		DNSConfigPath:      filepath.Join(dir, "dns.json"),
		RouteConfigPath:    filepath.Join(dir, "route.json"),
		InboundConfigPath:  filepath.Join(dir, "custom_inbound.json"),
		OutboundConfigPath: filepath.Join(dir, "custom_outbound.json"),
		Connection:         ConnectionPolicy{Handshake: 4, ConnIdle: 30, UplinkOnly: 2, DownlinkOnly: 4, BufferSize: 64},
		NameServers:        []NameServer{{Address: "1.1.1.1", Domains: []string{"domain:example.org"}}},
	}
}

func TestNewWithExampleFiles(t *testing.T) {
	c, err := New(exampleOptions())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !c.HasOutbound("direct") || !c.HasOutbound(BlockTag) {
		t.Fatal("default outbounds missing")
	}
}

func TestRuleOrder(t *testing.T) {
	c, err := New(exampleOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	mk := func(tag, out string) json.RawMessage {
		return json.RawMessage(`{"inboundTag":["` + tag + `"],"outboundTag":"` + out + `"}`)
	}
	if err := c.Rules.SetNode("a", &NodeRules{Head: []json.RawMessage{mk("a", BlockTag)}, Tail: []json.RawMessage{mk("a", "direct")}}); err != nil {
		t.Fatal(err)
	}
	if err := c.Rules.SetNode("b", &NodeRules{Head: []json.RawMessage{mk("b", BlockTag)}, Tail: []json.RawMessage{mk("b", "direct")}}); err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, r := range c.Rules.Rules() {
		s := string(r)
		switch {
		case strings.Contains(s, "bittorrent"):
			order = append(order, "global")
		case strings.Contains(s, `["a"]`) && strings.Contains(s, BlockTag):
			order = append(order, "a-head")
		case strings.Contains(s, `["b"]`) && strings.Contains(s, BlockTag):
			order = append(order, "b-head")
		case strings.Contains(s, `["a"]`):
			order = append(order, "a-tail")
		case strings.Contains(s, `["b"]`):
			order = append(order, "b-tail")
		}
	}
	if got, want := strings.Join(order, ","), "a-head,b-head,global,a-tail,b-tail"; got != want {
		t.Fatalf("order %s, want %s", got, want)
	}

	// An invalid rule is rejected and the previous rules stay in place.
	if err := c.Rules.SetNode("a", &NodeRules{Head: []json.RawMessage{json.RawMessage(`{"inboundTag":["a"],"domain":["geosite:nope-missing-file"],"outboundTag":"x"}`)}}); err == nil {
		t.Fatal("invalid rule accepted")
	}
	if n := len(c.Rules.Rules()); n != 5 {
		t.Fatalf("rules after failed update: %d", n)
	}
	if err := c.Rules.RemoveNode("a"); err != nil {
		t.Fatal(err)
	}
	if n := len(c.Rules.Rules()); n != 3 {
		t.Fatalf("rules after remove: %d", n)
	}
}
