package core

import (
	"encoding/json"
	"net"
	"regexp"
	"strconv"

	log "github.com/sirupsen/logrus"
)

// XrayR named its inbounds "<NodeType>_<ListenIP>_<Port>", e.g.
// "V2ray_0.0.0.0_65534", and route.json files written for it match on those
// names. W1nCray names inbounds after the node ("node173@panel.example"), so
// rules carried over from XrayR would silently stop matching. Legacy tags are
// therefore mapped to the node listening on the same port (a port can belong
// to one inbound only, and the mapping follows port changes made in the panel).
var legacyTagRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*_(.+)_([0-9]{1,5})$`)

// ParseLegacyTag returns the port of an XrayR inbound tag.
func ParseLegacyTag(tag string) (port int, ok bool) {
	m := legacyTagRe.FindStringSubmatch(tag)
	if m == nil || net.ParseIP(m[1]) == nil {
		return 0, false
	}
	p, err := strconv.Atoi(m[2])
	if err != nil || p < 1 || p > 65535 {
		return 0, false
	}
	return p, true
}

// LegacyRef is a legacy inbound tag found in a routing rule.
type LegacyRef struct {
	Tag  string
	Port int
}

// ruleInboundTags returns the inboundTag entries of a rule and whether the
// field was a single string (Xray accepts both forms).
func ruleInboundTags(fields map[string]json.RawMessage) (tags []string, single bool) {
	raw, ok := fields["inboundTag"]
	if !ok {
		return nil, false
	}
	if err := json.Unmarshal(raw, &tags); err == nil {
		return tags, false
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}, true
	}
	return nil, false
}

// rewriteLegacyTags replaces legacy inbound tags of a rule by the tag of the
// node listening on that port. Tags in reserved (custom inbounds of the user)
// are never touched. The rule is returned unchanged when nothing matches.
func rewriteLegacyTags(rule json.RawMessage, ports map[int]string, reserved map[string]bool, seen func(LegacyRef, string)) json.RawMessage {
	var fields map[string]json.RawMessage
	if json.Unmarshal(rule, &fields) != nil {
		return rule
	}
	tags, single := ruleInboundTags(fields)
	changed := false
	for i, t := range tags {
		if reserved[t] {
			continue
		}
		port, ok := ParseLegacyTag(t)
		if !ok {
			continue
		}
		if node, found := ports[port]; found {
			seen(LegacyRef{Tag: t, Port: port}, node)
			tags[i] = node
			changed = true
		}
	}
	if !changed {
		return rule
	}
	var b []byte
	if single {
		b, _ = json.Marshal(tags[0])
	} else {
		b, _ = json.Marshal(tags)
	}
	fields["inboundTag"] = b
	out, err := json.Marshal(fields)
	if err != nil {
		return rule
	}
	return out
}

// LegacyTagsInRoute lists the legacy inbound tags used by the rules of a
// route.json file, for `check`.
func LegacyTagsInRoute(routePath, inboundPath string) ([]LegacyRef, error) {
	if routePath == "" {
		return nil, nil
	}
	raw, err := readJSONFile(routePath)
	if err != nil {
		return nil, err
	}
	var rc struct {
		Rules []json.RawMessage `json:"rules"`
	}
	if err := json.Unmarshal(raw, &rc); err != nil {
		return nil, err
	}
	reserved := reservedInboundTags(inboundPath)
	var refs []LegacyRef
	have := map[string]bool{}
	for _, r := range rc.Rules {
		var fields map[string]json.RawMessage
		if json.Unmarshal(r, &fields) != nil {
			continue
		}
		tags, _ := ruleInboundTags(fields)
		for _, t := range tags {
			if reserved[t] || have[t] {
				continue
			}
			if port, ok := ParseLegacyTag(t); ok {
				have[t] = true
				refs = append(refs, LegacyRef{Tag: t, Port: port})
			}
		}
	}
	return refs, nil
}

// reservedInboundTags returns the tags of the user's custom inbounds.
func reservedInboundTags(path string) map[string]bool {
	out := map[string]bool{}
	if path == "" {
		return out
	}
	raw, err := readJSONFile(path)
	if err != nil {
		return out
	}
	var list []struct {
		Tag string `json:"tag"`
	}
	if json.Unmarshal(raw, &list) == nil {
		for _, in := range list {
			if in.Tag != "" {
				out[in.Tag] = true
			}
		}
	}
	return out
}

func logLegacyOnce(logged map[string]bool, ref LegacyRef, node string) {
	if logged[ref.Tag] {
		return
	}
	logged[ref.Tag] = true
	log.Infof("route.json: XrayR inbound tag %q is mapped to %q (port %d); the new tag can be used directly", ref.Tag, node, ref.Port)
}
