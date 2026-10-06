// Package filesync applies the panel's managed xray files (D4/D5): it fetches
// the blobs over HTTPS, stages them, validates them offline, replaces the
// configured files atomically, keeps the previous version as last_good, and
// asks the panel to reload the xray instance.
//
// The file set is a fixed whitelist of names inside one directory (the xray
// configuration directory). Nothing the panel sends can name a path: not a
// directory separator, not "..", not an absolute path, and never the agent's
// own configuration (agent.yml) or state files (docs/WS-PROTOCOL.md section 7
// rulings 9 and 13).
package filesync

import (
	"fmt"
	"path/filepath"
	"strings"
)

// The fixed managed-file names (D5). The order is the apply order.
const (
	NameConfig         = "config.yml"
	NameRoute          = "route.json"
	NameCustomInbound  = "custom_inbound.json"
	NameCustomOutbound = "custom_outbound.json"
	NameDNS            = "dns.json"
	NameGeoIP          = "geoip.dat"
	NameGeoSite        = "geosite.dat"
)

// ManagedNames is the whitelist of names the panel may manage, in apply order.
var ManagedNames = []string{
	NameConfig, NameRoute, NameCustomInbound, NameCustomOutbound, NameDNS, NameGeoIP, NameGeoSite,
}

// neverManaged are names that must be refused even though they look like
// ordinary files: the agent's own configuration and state are never managed
// (ruling 9/13). They are listed explicitly so the refusal names the reason.
var neverManaged = map[string]bool{
	"agent.yml":      true,
	"agent.yaml":     true,
	"desired.json":   true,
	"last_good.json": true,
	"blocked.json":   true,
	"manifest.json":  true,
}

// IsManaged reports whether name is a managed file name: a plain file name
// from the whitelist, with no directory part and no traversal.
func IsManaged(name string) bool {
	for _, n := range ManagedNames {
		if name == n {
			return true
		}
	}
	return false
}

// CheckName refuses every name that is not a whitelisted plain file name and
// says why. It is the single gate the apply path uses, so the rule cannot drift
// between staging, replacing and rollback.
func CheckName(name string) error {
	if name == "" {
		return fmt.Errorf("file name is required")
	}
	if neverManaged[strings.ToLower(name)] {
		return fmt.Errorf("file %q is never managed by the panel", name)
	}
	if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return fmt.Errorf("file name %q must be a plain name inside the xray directory", name)
	}
	if name != filepath.Base(name) {
		return fmt.Errorf("file name %q must not contain a directory part", name)
	}
	if !IsManaged(name) {
		return fmt.Errorf("file %q is not a managed file (allowed: %s)", name, strings.Join(ManagedNames, ", "))
	}
	return nil
}

// NeedsRebuild reports whether replacing name requires rebuilding the xray
// instance (design section 3.5). config.yml and the four JSON files are baked
// into the instance at construction time, so they need a reload; the two geo
// databases are read by xray on demand, so a change is picked up by the next
// connection and no reload is needed.
func NeedsRebuild(name string) bool {
	switch name {
	case NameGeoIP, NameGeoSite:
		return false
	default:
		return true
	}
}

// IsGeo reports whether name is one of the geo databases, whose local policy
// gate is Files.MaxBytes = 0 (a machine that deliberately keeps them off).
func IsGeo(name string) bool {
	return name == NameGeoIP || name == NameGeoSite
}

// NeedsRebuildAll reports whether replacing any of names requires a reload.
func NeedsRebuildAll(names []string) bool {
	for _, n := range names {
		if NeedsRebuild(n) {
			return true
		}
	}
	return false
}
