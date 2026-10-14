// Package certreload decides which running instances a changed managed file
// affects.
//
// The panel issues and renews certificates and delivers them to the machine
// through the managed-file channel (the same channel that carries the xray
// configuration files). The agent never does ACME and never parses a
// certificate: all it has to do is notice that the content of a managed file
// changed and restart the instances whose desired state references that file
// by path, so the new bytes are picked up immediately (ACME-1 design ruling).
//
// This package owns the association half of that: which paths an instance
// references (today the certificate pair of a tunnel), and which instances a
// set of changed files affects. Restarting is the reconciler's job; the
// managed-file applier only calls it with the result of Changed.
package certreload

import (
	"path/filepath"
	"sort"

	"github.com/W1nCwC/W1nCray/agent/spec"
)

// Paths returns every file path the instance's desired state references, in a
// stable order and without duplicates. It is the list Changed matches a
// changed managed file against.
//
// Today that is the tunnel certificate pair:
//
//   - Tunnel.Cert.CertFile is the certificate an exit/portal serves or the
//     trust anchor an entry/bridge verifies with (both are read from disk);
//   - Tunnel.Cert.KeyFile is the matching private key of an exit/portal.
//
// An instance without a tunnel (a plain forward), or with a certificate mode
// that has no files (self, panel), references nothing and is never restarted
// by a file change.
func Paths(in spec.Instance) []string {
	if in.Tunnel == nil || in.Tunnel.Cert == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range []string{in.Tunnel.Cert.CertFile, in.Tunnel.Cert.KeyFile} {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// Ref is one managed file that changed, named by its whitelisted name and the
// absolute path it was written to.
type Ref struct {
	Name string
	Path string
}

// Changed returns the ids of the enabled instances of d that reference any of
// the changed files, sorted and without duplicates.
//
// A reference matches when it names the file exactly. The panel stores only
// the whitelisted name of a managed file, so the path it lands on is built
// from the xray configuration directory; a spec that names the same file
// relatively (the plain file name, as an engine that runs with the directory
// as its working directory may) is therefore matched by its base name as
// well. A relative reference is only accepted when it really is a plain file
// name, so "certs/cert.pem" can never be mistaken for "<dir>/cert.pem".
//
// Disabled instances are ignored: they run nothing, and a later enable applies
// the desired state (and thus the new file) anyway.
func Changed(d spec.Desired, changed []Ref) []string {
	if len(changed) == 0 {
		return nil
	}
	affected := map[string]bool{}
	for _, in := range d.Instances {
		if !in.Enabled {
			continue
		}
		for _, ref := range Paths(in) {
			if matches(ref, changed) {
				affected[in.ID] = true
				break
			}
		}
	}
	return sortedIDs(affected)
}

// matches reports whether ref (a path an instance references) names one of the
// changed files.
func matches(ref string, changed []Ref) bool {
	for _, c := range changed {
		if ref == c.Path {
			return true
		}
		// A relative reference is the plain file name (the engine runs with
		// the directory as its working directory); anything with a directory
		// part has to be spelled out exactly.
		if filepath.Base(ref) == ref && ref == filepath.Base(c.Path) {
			return true
		}
	}
	return false
}

// sortedIDs returns the keys of set in a stable order.
func sortedIDs(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
