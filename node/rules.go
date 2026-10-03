package node

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"w1ncray/api/xboard"
	"w1ncray/core"
)

// privateCIDRs are blocked by default so users cannot reach the node's own
// network (loopback services, cloud metadata, LAN).
var privateCIDRs = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
}

// domainPrefixes are Xray domain matcher prefixes accepted verbatim.
var domainPrefixes = []string{"domain:", "full:", "regexp:", "keyword:", "geosite:", "ext:", "dotless:"}

// classifyMatch turns one Xboard route match item into an Xray domain or IP
// matcher. Xboard's admin UI documents items as "example.com" and
// "*.example.com"; Xray prefixes are passed through, and items that look like
// regular expressions (XrayR treated every item as a regex) become regexp:.
func classifyMatch(item string) (domain, ip string) {
	item = strings.TrimSpace(item)
	if item == "" {
		return "", ""
	}
	lower := strings.ToLower(item)
	if strings.HasPrefix(lower, "geoip:") || strings.HasPrefix(lower, "ext-ip:") {
		return "", item
	}
	if _, _, err := net.ParseCIDR(item); err == nil {
		return "", item
	}
	if net.ParseIP(strings.Trim(item, "[]")) != nil {
		return "", strings.Trim(item, "[]")
	}
	for _, p := range domainPrefixes {
		if strings.HasPrefix(lower, p) {
			return item, ""
		}
	}
	if strings.HasPrefix(item, "*.") && !strings.ContainsAny(item[2:], "*()|^$\\[]+?{}") {
		return "domain:" + item[2:], ""
	}
	if strings.ContainsAny(item, "*()|^$\\[]+?{}") {
		return "regexp:" + item, ""
	}
	return "domain:" + item, ""
}

func splitMatch(items []string) (domains, ips []string) {
	for _, it := range items {
		d, ip := classifyMatch(it)
		if d != "" {
			domains = append(domains, d)
		}
		if ip != "" {
			ips = append(ips, ip)
		}
	}
	return domains, ips
}

func rule(m map[string]any) json.RawMessage {
	b, _ := json.Marshal(m)
	return b
}

// matchRules builds rules for the domain and IP parts of a match list.
func matchRules(inTag, outTag string, items []string) []json.RawMessage {
	domains, ips := splitMatch(items)
	var out []json.RawMessage
	if len(domains) > 0 {
		out = append(out, rule(map[string]any{"inboundTag": []string{inTag}, "domain": domains, "outboundTag": outTag}))
	}
	if len(ips) > 0 {
		out = append(out, rule(map[string]any{"inboundTag": []string{inTag}, "ip": ips, "outboundTag": outTag}))
	}
	return out
}

// customOutboundTag namespaces a panel custom outbound tag to its node.
func customOutboundTag(nodeTag, tag string) string {
	return nodeTag + "/" + tag
}

// ruleSet collects what a node needs to route its traffic.
type ruleSet struct {
	inTag        string
	outTag       string // node freedom outbound
	customTags   map[string]bool
	globalExists func(tag string) bool
	warn         func(format string, args ...any)
}

func (r *ruleSet) resolveOutbound(tag string) (string, bool) {
	switch tag {
	case "":
		return "", false
	case "direct", "freedom":
		if !r.customTags[tag] {
			return r.outTag, true
		}
	case "block", "blackhole", "reject":
		if !r.customTags[tag] {
			return core.BlockTag, true
		}
	}
	if r.customTags[tag] {
		return customOutboundTag(r.inTag, tag), true
	}
	if r.globalExists != nil && r.globalExists(tag) {
		return tag, true
	}
	return "", false
}

// build assembles the node rules (see core.RuleManager for ordering).
func (r *ruleSet) build(cfg *Config, routes []xboard.Route, customRoutes []json.RawMessage, localRules []string) *core.NodeRules {
	nr := &core.NodeRules{}
	if cfg.blockPrivateIP() {
		nr.Head = append(nr.Head, rule(map[string]any{"inboundTag": []string{r.inTag}, "ip": privateCIDRs, "outboundTag": core.BlockTag}))
	}

	if !cfg.DisableGetRule {
		for _, rt := range routes {
			switch strings.ToLower(string(rt.Action)) {
			case "block":
				nr.Head = append(nr.Head, matchRules(r.inTag, core.BlockTag, rt.Match)...)
			case "direct":
				nr.Head = append(nr.Head, matchRules(r.inTag, r.outTag, rt.Match)...)
			case "proxy":
				out, ok := r.resolveOutbound(string(rt.ActionValue))
				if !ok {
					r.warn("route %d: outbound %q not found, rule skipped", rt.ID, rt.ActionValue)
					continue
				}
				nr.Head = append(nr.Head, matchRules(r.inTag, out, rt.Match)...)
			case "dns":
				// Applied through the DNS app (see dnsServers).
			default:
				r.warn("route %d: unknown action %q, rule skipped", rt.ID, rt.Action)
			}
		}
	}

	for i, raw := range customRoutes {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			r.warn("custom route %d: %v, rule skipped", i, err)
			continue
		}
		m["inboundTag"] = []string{r.inTag}
		if ot, ok := m["outboundTag"].(string); ok {
			out, found := r.resolveOutbound(ot)
			if !found {
				r.warn("custom route %d: outbound %q not found, rule skipped", i, ot)
				continue
			}
			m["outboundTag"] = out
		}
		delete(m, "ruleTag")
		nr.Head = append(nr.Head, rule(m))
	}

	if len(localRules) > 0 {
		patterns := make([]string, 0, len(localRules))
		for _, p := range localRules {
			patterns = append(patterns, "regexp:"+p)
		}
		nr.Head = append(nr.Head, rule(map[string]any{"inboundTag": []string{r.inTag}, "domain": patterns, "outboundTag": core.BlockTag}))
	}

	nr.Tail = append(nr.Tail, rule(map[string]any{"inboundTag": []string{r.inTag}, "outboundTag": r.outTag}))
	return nr
}

// dnsServers returns the DNS servers requested by panel "dns" routes.
func dnsServers(routes []xboard.Route) []core.NameServer {
	var out []core.NameServer
	for _, rt := range routes {
		if !strings.EqualFold(string(rt.Action), "dns") || rt.ActionValue == "" {
			continue
		}
		domains, _ := splitMatch(rt.Match)
		if len(domains) == 0 {
			continue
		}
		out = append(out, core.NameServer{Address: string(rt.ActionValue), Domains: domains})
	}
	return out
}

// readRuleList reads XrayR's local rule list: one regular expression per line.
func readRuleList(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read rule list %s: %w", path, err)
	}
	return out, nil
}

// customOutbounds converts panel custom outbounds (Xray outbound JSON, also
// accepting Xboard-Node's {tag, protocol, settings, proxy_tag}) into Xray
// outbound JSON with node-scoped tags.
func customOutbounds(nodeTag string, raws []json.RawMessage, warn func(string, ...any)) (map[string]bool, []json.RawMessage) {
	tags := make(map[string]bool)
	var objs []map[string]any
	for i, raw := range raws {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			warn("custom outbound %d: %v, skipped", i, err)
			continue
		}
		tag, _ := m["tag"].(string)
		if tag == "" {
			warn("custom outbound %d: missing tag, skipped", i)
			continue
		}
		if tags[tag] {
			warn("custom outbound %d: duplicate tag %q, skipped", i, tag)
			continue
		}
		tags[tag] = true
		objs = append(objs, sanitizePHP(m))
	}
	var out []json.RawMessage
	for _, m := range objs {
		m["tag"] = customOutboundTag(nodeTag, m["tag"].(string))
		if pt, ok := m["proxy_tag"].(string); ok {
			delete(m, "proxy_tag")
			if pt != "" {
				m["proxySettings"] = map[string]any{"tag": pt}
			}
		}
		if ps, ok := m["proxySettings"].(map[string]any); ok {
			if t, ok := ps["tag"].(string); ok && tags[t] {
				ps["tag"] = customOutboundTag(nodeTag, t)
			}
		}
		if ss, ok := m["streamSettings"].(map[string]any); ok {
			if so, ok := ss["sockopt"].(map[string]any); ok {
				if t, ok := so["dialerProxy"].(string); ok && tags[t] {
					so["dialerProxy"] = customOutboundTag(nodeTag, t)
				}
			}
		}
		out = append(out, rule(m))
	}
	return tags, out
}
