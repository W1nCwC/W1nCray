package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	routingsession "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/infra/conf"
)

// pickOut asks the live router which outbound a TCP connection from inbound
// tag in to ip:80 would use. proto, when set, is the sniffed protocol.
func pickOut(t *testing.T, c *Core, in, ip, proto string) (string, error) {
	t.Helper()
	rctx := &routingsession.Context{
		Inbound:  &session.Inbound{Tag: in},
		Outbound: &session.Outbound{Target: net.TCPDestination(net.ParseAddress(ip), 80)},
		Content:  &session.Content{Protocol: proto},
	}
	r, err := c.Rules.router.PickRoute(rctx)
	if err != nil {
		return "", err
	}
	return r.GetOutboundTag(), nil
}

func mustPick(t *testing.T, c *Core, in, ip, proto, want string) {
	t.Helper()
	got, err := pickOut(t, c, in, ip, proto)
	if err != nil {
		t.Fatalf("pick(%s -> %s %s): %v (router table empty?)", in, ip, proto, err)
	}
	if got != want {
		t.Fatalf("pick(%s -> %s %s) = %s, want %s", in, ip, proto, got, want)
	}
}

func addFreedom(t *testing.T, c *Core, tag string) {
	t.Helper()
	var oc conf.OutboundDetourConfig
	if err := json.Unmarshal([]byte(`{"protocol":"freedom","tag":"`+tag+`"}`), &oc); err != nil {
		t.Fatal(err)
	}
	hc, err := oc.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddOutbound(hc); err != nil {
		t.Fatal(err)
	}
}

// nodeA is a node with the usual security head rule (private ranges blocked)
// and a tail rule to its outbound.
func nodeA() *NodeRules {
	return &NodeRules{
		Head: []json.RawMessage{json.RawMessage(`{"inboundTag":["a"],"ip":["10.0.0.0/8"],"outboundTag":"` + BlockTag + `"}`)},
		Tail: []json.RawMessage{json.RawMessage(`{"inboundTag":["a"],"outboundTag":"direct"}`)},
	}
}

// D-B: RuleManager.apply used to hand the router a rule list that failed
// inside Router.ReloadRules after the router had already dropped its old
// table, so one bad update left every node without its security rules.
func TestFailedUpdateKeepsRules(t *testing.T) {
	c := newTestCore(t)
	if err := c.Rules.SetNode("a", nodeA()); err != nil {
		t.Fatal(err)
	}
	mustPick(t, c, "a", "10.1.2.3", "", BlockTag)
	mustPick(t, c, "a", "8.8.8.8", "", "direct")
	mustPick(t, c, "z", "8.8.8.8", "bittorrent", BlockTag) // global route.json rule

	bad := map[string]*NodeRules{
		// Build succeeds, Router.ReloadRules fails: unknown balancer.
		"unknown balancer": {Head: []json.RawMessage{json.RawMessage(`{"inboundTag":["b"],"balancerTag":"nope"}`)}},
		// Build succeeds, Router.ReloadRules fails: same ruleTag twice.
		"duplicate ruleTag": {Head: []json.RawMessage{
			json.RawMessage(`{"ruleTag":"dup","inboundTag":["b"],"outboundTag":"direct"}`),
			json.RawMessage(`{"ruleTag":"dup","inboundTag":["b"],"outboundTag":"direct"}`),
		}},
	}
	for name, nr := range bad {
		t.Run(name, func(t *testing.T) {
			if err := c.Rules.SetNode("b", nr); err == nil {
				t.Fatal("bad rules accepted")
			}
			mustPick(t, c, "a", "10.1.2.3", "", BlockTag)
			mustPick(t, c, "a", "8.8.8.8", "", "direct")
			mustPick(t, c, "z", "8.8.8.8", "bittorrent", BlockTag)
			if n := len(c.Rules.Rules()); n != 3 {
				t.Fatalf("rule list changed by a failed update: %d rules", n)
			}
		})
	}

	// A failed replacement of an existing node keeps that node's old rules.
	if err := c.Rules.SetNode("a", &NodeRules{Head: bad["unknown balancer"].Head}); err == nil {
		t.Fatal("bad rules accepted")
	}
	mustPick(t, c, "a", "10.1.2.3", "", BlockTag)
	mustPick(t, c, "a", "8.8.8.8", "", "direct")

	// The manager is still usable afterwards.
	if err := c.Rules.SetNode("b", &NodeRules{Head: []json.RawMessage{json.RawMessage(`{"inboundTag":["b"],"ip":["10.0.0.0/8"],"outboundTag":"` + BlockTag + `"}`)}}); err != nil {
		t.Fatal(err)
	}
	mustPick(t, c, "b", "10.9.9.9", "", BlockTag)
	mustPick(t, c, "a", "10.1.2.3", "", BlockTag)
}

// A rejected first update must leave the global route.json rules in place
// instead of an empty table.
func TestFirstFailedUpdateKeepsGlobalRules(t *testing.T) {
	c := newTestCore(t)
	mustPick(t, c, "z", "8.8.8.8", "bittorrent", BlockTag)
	err := c.Rules.SetNode("b", &NodeRules{Head: []json.RawMessage{json.RawMessage(`{"inboundTag":["b"],"balancerTag":"nope"}`)}})
	if err == nil {
		t.Fatal("bad rules accepted")
	}
	mustPick(t, c, "z", "8.8.8.8", "bittorrent", BlockTag)
	if n := len(c.Rules.Rules()); n != 1 {
		t.Fatalf("rules = %d, want only the global one", n)
	}
}

// Duplicate ruleTags are refused before the router is touched.
func TestDuplicateRuleTagRejectedBeforeRouter(t *testing.T) {
	fr := &fakeRouter{}
	m := &RuleManager{router: fr, nodes: make(map[string]*NodeRules)}
	if err := m.SetNode("a", nodeA()); err != nil {
		t.Fatal(err)
	}
	calls := fr.calls
	err := m.SetNode("b", &NodeRules{
		Head: []json.RawMessage{json.RawMessage(`{"ruleTag":"x","inboundTag":["b"],"outboundTag":"direct"}`)},
		Tail: []json.RawMessage{json.RawMessage(`{"ruleTag":"x","inboundTag":["b"],"outboundTag":"direct"}`)},
	})
	if err == nil || !strings.Contains(err.Error(), `duplicate ruleTag "x"`) {
		t.Fatalf("err = %v, want duplicate ruleTag error", err)
	}
	if fr.calls != calls {
		t.Fatal("router was called for a rule list that is invalid by itself")
	}
}

// fakeRouter models Router.ReloadRules: a failed call leaves an empty table.
type fakeRouter struct {
	routing.Router
	mu    sync.Mutex
	calls int
	fail  int // fail the next n calls
	table []byte
}

func (f *fakeRouter) AddRule(cfg *serial.TypedMessage, _ bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.fail > 0 {
		f.fail--
		f.table = nil
		return errors.New("injected failure")
	}
	f.table = bytes.Clone(cfg.Value)
	return nil
}

// RemoveNode that fails must put the node back, in its old position, and
// leave the router with the previous rules.
func TestRemoveNodeFailureRollsBack(t *testing.T) {
	fr := &fakeRouter{}
	m := &RuleManager{router: fr, nodes: make(map[string]*NodeRules)}
	for _, tag := range []string{"a", "b", "c"} {
		r := nodeA()
		r.Head = []json.RawMessage{json.RawMessage(`{"inboundTag":["` + tag + `"],"outboundTag":"direct"}`)}
		r.Tail = nil
		if err := m.SetNode(tag, r); err != nil {
			t.Fatal(err)
		}
	}
	before := bytes.Clone(fr.table)
	order := strings.Join(m.order, ",")

	fr.fail = 1
	if err := m.RemoveNode("b"); err == nil {
		t.Fatal("injected failure not reported")
	}
	if got := strings.Join(m.order, ","); got != order {
		t.Fatalf("order after failed remove = %s, want %s", got, order)
	}
	if _, ok := m.nodes["b"]; !ok {
		t.Fatal("node b not restored")
	}
	if !bytes.Equal(fr.table, before) {
		t.Fatal("router does not hold the previous rules after a failed remove")
	}

	// A failed SetNode of a new node is rolled back the same way.
	fr.fail = 1
	if err := m.SetNode("d", nodeA()); err == nil {
		t.Fatal("injected failure not reported")
	}
	if _, ok := m.nodes["d"]; ok {
		t.Fatal("node d kept after failed SetNode")
	}
	if got := strings.Join(m.order, ","); got != order {
		t.Fatalf("order after failed SetNode = %s, want %s", got, order)
	}
	if !bytes.Equal(fr.table, before) {
		t.Fatal("router does not hold the previous rules after a failed SetNode")
	}
}

func lbNode(tag string) *NodeRules {
	return &NodeRules{
		Balancers: json.RawMessage(`[{"tag":"` + tag + `-lb","selector":["o1","o2"],"strategy":{"type":"roundRobin"}}]`),
		Head:      []json.RawMessage{json.RawMessage(`{"inboundTag":["` + tag + `"],"balancerTag":"` + tag + `-lb"}`)},
	}
}

// Node balancers are merged into the router and used by the node's rules.
// This also pins down a property of Xray the callers must live with: every
// reload rebuilds all balancers, so a roundRobin position restarts from zero
// whenever any node changes.
func TestNodeBalancers(t *testing.T) {
	c := newTestCore(t)
	addFreedom(t, c, "o1")
	addFreedom(t, c, "o2")
	if err := c.Rules.SetNode("a", lbNode("a")); err != nil {
		t.Fatal(err)
	}
	first, err := pickOut(t, c, "a", "8.8.8.8", "")
	if err != nil {
		t.Fatal(err)
	}
	if first != "o1" && first != "o2" {
		t.Fatalf("balancer picked %q", first)
	}
	second, _ := pickOut(t, c, "a", "8.8.8.8", "")
	if second == first {
		t.Fatalf("roundRobin picked %s twice in a row", first)
	}

	// Another node's update reloads the router: the position restarts.
	if err := c.Rules.SetNode("b", lbNode("b")); err != nil {
		t.Fatal(err)
	}
	if got, _ := pickOut(t, c, "a", "8.8.8.8", ""); got != first {
		t.Fatalf("after reload balancer picked %s, want %s (position restarts)", got, first)
	}
	if got, err := pickOut(t, c, "b", "8.8.8.8", ""); err != nil || (got != "o1" && got != "o2") {
		t.Fatalf("node b balancer: %q, %v", got, err)
	}

	// Removing a node drops its balancer; the other node keeps working.
	if err := c.Rules.RemoveNode("b"); err != nil {
		t.Fatal(err)
	}
	if got, err := pickOut(t, c, "a", "8.8.8.8", ""); err != nil || (got != "o1" && got != "o2") {
		t.Fatalf("node a balancer after removing b: %q, %v", got, err)
	}
}

func TestNodeBalancerConflicts(t *testing.T) {
	c := newTestCore(t)
	addFreedom(t, c, "o1")
	addFreedom(t, c, "o2")
	if err := c.Rules.SetNode("a", lbNode("a")); err != nil {
		t.Fatal(err)
	}
	mustPick(t, c, "z", "8.8.8.8", "bittorrent", BlockTag)

	// Same tag in two nodes.
	clash := lbNode("b")
	clash.Balancers = lbNode("a").Balancers
	err := c.Rules.SetNode("b", clash)
	if err == nil || !strings.Contains(err.Error(), `balancer tag "a-lb"`) {
		t.Fatalf("err = %v, want balancer tag conflict", err)
	}

	// Same tag as a global balancer.
	c.Rules.mu.Lock()
	c.Rules.balancers = json.RawMessage(`[{"tag":"g-lb","selector":["o1"]}]`)
	c.Rules.mu.Unlock()
	global := lbNode("c")
	global.Balancers = json.RawMessage(`[{"tag":"g-lb","selector":["o2"]}]`)
	err = c.Rules.SetNode("c", global)
	if err == nil || !strings.Contains(err.Error(), `"g-lb"`) {
		t.Fatalf("err = %v, want balancer tag conflict with route.json", err)
	}

	// Malformed balancers.
	bad := lbNode("d")
	bad.Balancers = json.RawMessage(`{"tag":"d-lb"}`)
	if err := c.Rules.SetNode("d", bad); err == nil {
		t.Fatal("balancers that are not an array accepted")
	}

	// Nothing above disturbed the rules in effect.
	if _, err := pickOut(t, c, "a", "8.8.8.8", ""); err != nil {
		t.Fatal(err)
	}
	mustPick(t, c, "z", "8.8.8.8", "bittorrent", BlockTag)
	if n := len(c.Rules.Rules()); n != 2 {
		t.Fatalf("rules = %d, want 2", n)
	}
}
