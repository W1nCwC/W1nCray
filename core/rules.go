package core

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/infra/conf"
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
}

// RuleManager owns the full router rule list:
//
//	[node heads...] + [global route.json rules] + [node tails...]
//
// and reloads it into the router whenever a node changes. Rebuilding the whole
// list keeps the order deterministic, which appending rules cannot.
type RuleManager struct {
	mu        sync.Mutex
	router    routing.Router
	global    []json.RawMessage
	balancers json.RawMessage
	nodes     map[string]*NodeRules
	order     []string
	reserved  map[string]bool // tags of the user's custom inbounds
	logged    map[string]bool
}

// SetNode installs or replaces the rules of a node.
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

// RemoveNode removes the rules of a node.
func (m *RuleManager) RemoveNode(tag string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.nodes[tag]; !ok {
		return nil
	}
	m.remove(tag)
	return m.apply()
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

func (m *RuleManager) apply() error {
	rc := &conf.RouterConfig{RuleList: m.compose()}
	if len(m.balancers) > 0 {
		if err := json.Unmarshal(m.balancers, &rc.Balancers); err != nil {
			return fmt.Errorf("route balancers: %w", err)
		}
	}
	cfg, err := rc.Build()
	if err != nil {
		return fmt.Errorf("build routing rules: %w", err)
	}
	if m.router == nil {
		return fmt.Errorf("router not available")
	}
	return m.router.AddRule(serial.ToTypedMessage(cfg), false)
}
