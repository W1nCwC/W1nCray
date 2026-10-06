package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/W1nCwC/W1nCray/app/routeguard"
)

// NodeRules are the routing rules of one node. Every rule must be restricted
// to the node's inbound tag so that nodes cannot affect each other.
type NodeRules struct {
	// Port is the port the node listens on; XrayR-style inbound tags in the
	// global route.json that name this port are mapped to this node.
	Port int
	// Head rules are evaluated before the global route config (security
	// and panel rules).
	Head []json.RawMessage
	// Tail rules are evaluated after the global route config (fallback to
	// the node outbound).
	Tail []json.RawMessage
	// Balancers are balancers private to this node: a JSON array in the
	// format of the "balancers" of route.json. They are merged with the
	// global balancers and those of the other nodes; a tag that is used
	// twice makes the update fail. Name them after the node (for example
	// "<node>-lb") so tags cannot collide.
	//
	// Xray rebuilds every balancer whenever the rule list is reloaded, so any
	// balancer state (the position of a roundRobin balancer) restarts from
	// zero each time any node is added, changed or removed.
	Balancers json.RawMessage
}

// RuleManager owns the full router rule list:
//
//	[node heads...] + [global route.json rules] + [node tails...]
//
// and reloads it into the router whenever a node changes. Rebuilding the whole
// list keeps the order deterministic, which appending rules cannot.
//
// Xray's Router.ReloadRules drops the old table before it validates the new
// one, so a rule list that fails there leaves the router empty. The manager
// therefore validates what it can before the router is touched (duplicate
// ruleTags, balancer tags) and, when the router still refuses a list, replays
// the last list that was accepted.
type RuleManager struct {
	mu        sync.Mutex
	router    routing.Router
	global    []json.RawMessage
	balancers json.RawMessage
	nodes     map[string]*NodeRules
	order     []string
	reserved  map[string]bool // tags of the user's custom inbounds
	logged    map[string]bool
	lastGood  *serial.TypedMessage // last config the router accepted
}

// SetNode installs or replaces the rules of a node. On failure the rules
// that were in effect before stay in effect.
func (m *RuleManager) SetNode(tag string, rules *NodeRules) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	prev, existed := m.nodes[tag]
	m.nodes[tag] = rules
	if !existed {
		m.order = append(m.order, tag)
	}
	if err := m.apply(); err != nil {
		if existed {
			m.nodes[tag] = prev
		} else {
			m.remove(tag)
		}
		return err
	}
	return nil
}

// RemoveNode removes the rules of a node. On failure the node and its rules
// stay in place.
func (m *RuleManager) RemoveNode(tag string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	prev, ok := m.nodes[tag]
	if !ok {
		return nil
	}
	idx := m.indexOf(tag)
	m.remove(tag)
	if err := m.apply(); err != nil {
		m.nodes[tag] = prev
		m.order = append(m.order, "")
		copy(m.order[idx+1:], m.order[idx:])
		m.order[idx] = tag
		return err
	}
	return nil
}

func (m *RuleManager) indexOf(tag string) int {
	for i, t := range m.order {
		if t == tag {
			return i
		}
	}
	return len(m.order)
}

func (m *RuleManager) remove(tag string) {
	delete(m.nodes, tag)
	for i, t := range m.order {
		if t == tag {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
}

// Rules returns the rule list in evaluation order.
func (m *RuleManager) Rules() []json.RawMessage {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.compose()
}

func (m *RuleManager) compose() []json.RawMessage {
	var rules []json.RawMessage
	for _, tag := range m.order {
		rules = append(rules, m.nodes[tag].Head...)
	}
	rules = append(rules, m.globalRules()...)
	for _, tag := range m.order {
		rules = append(rules, m.nodes[tag].Tail...)
	}
	return rules
}

// globalRules returns the route.json rules with XrayR inbound tags mapped to
// the nodes that listen on the same port. Rules without such tags are
// returned as they are.
func (m *RuleManager) globalRules() []json.RawMessage {
	ports := make(map[int]string)
	for _, tag := range m.order {
		if p := m.nodes[tag].Port; p > 0 {
			if _, taken := ports[p]; !taken {
				ports[p] = tag
			}
		}
	}
	if len(ports) == 0 {
		return m.global
	}
	if m.logged == nil {
		m.logged = make(map[string]bool)
	}
	out := make([]json.RawMessage, len(m.global))
	for i, r := range m.global {
		out[i] = rewriteLegacyTags(r, ports, m.reserved, func(ref LegacyRef, node string) {
			logLegacyOnce(m.logged, ref, node)
		})
	}
	return out
}

// checkRuleTags rejects a rule list in which a ruleTag occurs twice, which
// Router.ReloadRules would refuse only after emptying the router.
func checkRuleTags(rules []json.RawMessage) error {
	seen := make(map[string]bool)
	for _, r := range rules {
		var h struct {
			RuleTag string `json:"ruleTag"`
		}
		if json.Unmarshal(r, &h) != nil || h.RuleTag == "" {
			continue // malformed rules are reported by Build
		}
		if seen[h.RuleTag] {
			return fmt.Errorf("duplicate ruleTag %q in the routing rules", h.RuleTag)
		}
		seen[h.RuleTag] = true
	}
	return nil
}

// balancerList returns the global balancers followed by those of the nodes,
// in node order. A tag defined twice is an error naming both owners.
func (m *RuleManager) balancerList() ([]json.RawMessage, error) {
	var out []json.RawMessage
	owner := make(map[string]string)
	add := func(who string, raw json.RawMessage) error {
		if len(bytes.TrimSpace(raw)) == 0 {
			return nil
		}
		var list []json.RawMessage
		if err := json.Unmarshal(raw, &list); err != nil {
			return fmt.Errorf("%s balancers: %w", who, err)
		}
		for _, b := range list {
			var h struct {
				Tag string `json:"tag"`
			}
			if err := json.Unmarshal(b, &h); err != nil {
				return fmt.Errorf("%s balancers: %w", who, err)
			}
			if h.Tag != "" {
				if prev, dup := owner[h.Tag]; dup {
					return fmt.Errorf("balancer tag %q of %s is already defined by %s", h.Tag, who, prev)
				}
				owner[h.Tag] = who
			}
			out = append(out, b)
		}
		return nil
	}
	if err := add("route.json", m.balancers); err != nil {
		return nil, fmt.Errorf("route balancers: %w", err)
	}
	for _, tag := range m.order {
		if err := add("node "+tag, m.nodes[tag].Balancers); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// buildRouterConfig compiles rules and balancers into the router config.
func buildRouterConfig(rules, balancers []json.RawMessage) (*serial.TypedMessage, error) {
	rc := &conf.RouterConfig{RuleList: rules}
	if len(balancers) > 0 {
		b, err := json.Marshal(balancers)
		if err == nil {
			err = json.Unmarshal(b, &rc.Balancers)
		}
		if err != nil {
			return nil, fmt.Errorf("route balancers: %w", err)
		}
	}
	cfg, err := rc.Build()
	if err != nil {
		return nil, fmt.Errorf("build routing rules: %w", err)
	}
	return serial.ToTypedMessage(cfg), nil
}

// apply compiles the current state and hands it to the router. When the
// router refuses it, the previously accepted config is loaded again, so a
// failed update never leaves the router without rules.
func (m *RuleManager) apply() error {
	if m.router == nil {
		return fmt.Errorf("router not available")
	}
	rules := m.compose()
	if err := checkRuleTags(rules); err != nil {
		return err
	}
	balancers, err := m.balancerList()
	if err != nil {
		return err
	}
	tm, err := buildRouterConfig(rules, balancers)
	if err != nil {
		return err
	}
	// One write section covers the reload and, if the router refuses it, the
	// restore: a refused reload leaves the router with an emptied or partial
	// table until the restore completes, and route selection must not see
	// that. m.router is the raw router (not routeguard.Router), because the
	// write lock is already held here and is not re-entrant. Nothing inside
	// the section selects a route or takes the guard again.
	if err := routeguard.Mutate(func() error {
		if err := m.router.AddRule(tm, false); err != nil {
			return m.restore(err)
		}
		return nil
	}); err != nil {
		return err
	}
	m.lastGood = tm
	return nil
}

// restore reloads the last accepted config after the router refused a new
// one. It runs inside apply's write section and must not take the guard.Before any config was accepted it falls back to the global rules, which
// is what the instance was started with.
func (m *RuleManager) restore(cause error) error {
	prev := m.lastGood
	if prev == nil {
		var bal []json.RawMessage
		if len(bytes.TrimSpace(m.balancers)) > 0 {
			_ = json.Unmarshal(m.balancers, &bal)
		}
		var err error
		if prev, err = buildRouterConfig(m.global, bal); err != nil {
			return fmt.Errorf("%w (restoring the global rules failed too: %v)", cause, err)
		}
	}
	if err := m.router.AddRule(prev, false); err != nil {
		return fmt.Errorf("%w (restoring the previous rules failed too: %v)", cause, err)
	}
	return cause
}
