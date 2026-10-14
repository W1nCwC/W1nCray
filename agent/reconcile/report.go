package reconcile

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/agent/validate"
)

// Status is the overall outcome of an Apply.
type Status string

const (
	// StatusApplied: everything runs and passed the health check.
	StatusApplied Status = "applied"
	// StatusPartial: the apply failed, a rollback was attempted and restored
	// only some drivers; the machine is in a mixed state. Needs attention.
	StatusPartial Status = "partial"
	// StatusFailed: nothing could be applied for an environmental reason (for
	// example a kernel could not be installed, or the state directory is not
	// writable). The running configuration was not touched. May be retried.
	StatusFailed Status = "failed"
	// StatusRolledBack: applying failed and the last good configuration was
	// restored. The failed hash is blocked until the desired state changes.
	StatusRolledBack Status = "rolled_back"
	// StatusRejected: the desired state is invalid for this agent (schema,
	// local policy, no engine can run an instance, port conflict, render
	// error). Nothing was touched.
	StatusRejected Status = "rejected"
)

// Instance states reported per instance.
const (
	StateRunning    = "running"
	StateDisabled   = "disabled"
	StateRejected   = "rejected"
	StateFailed     = "failed"
	StateRolledBack = "rolled_back"
	StateNotApplied = "not_applied"
)

// Sentinel errors wrapped by Apply's returned error; the Report carries the
// details.
var (
	ErrRejected   = errors.New("desired state rejected")
	ErrFailed     = errors.New("apply failed")
	ErrRolledBack = errors.New("apply failed and was rolled back")
	ErrPartial    = errors.New("apply failed and the rollback was incomplete")
	// ErrBlocked is returned when the same desired state already failed;
	// change the desired state to try again.
	ErrBlocked = errors.New("desired state previously failed to apply (blocked until it changes)")
)

// InstanceReport is the outcome for one instance.
type InstanceReport struct {
	ID string `json:"id"`
	// State is one of the State* constants.
	State string `json:"state"`
	// Engine is the engine chosen for the instance (resolved from "auto").
	Engine string `json:"engine,omitempty"`
	// Requested is the engine named in the desired state ("auto" or explicit).
	Requested string `json:"requested_engine,omitempty"`
	// Considered explains, per engine, why it was not (or could not be) used.
	Considered map[string]string `json:"considered,omitempty"`
	ConfigHash string            `json:"config_hash,omitempty"`
	// Ports lists the listeners, compacted ("tcp 127.0.0.1:20000-20009").
	Ports []string `json:"ports,omitempty"`
	// FirewallOpen is true when the agent has opened this instance's public
	// ports in the machine's firewall (OpenWrt with Firewall.AutoOpen on, see
	// agent/fwopen). It stays false for an instance without a public listener
	// and on every machine where the agent does not manage the firewall;
	// hello.policy.firewall.auto_open tells the panel which case it is looking
	// at.
	FirewallOpen bool   `json:"firewall_open"`
	Error        string `json:"error,omitempty"`
}

// KernelEntry is one installed kernel version, mirroring the wire type
// wsproto.KernelEntry without making this core package import the wire
// package. agent/panelclient converts between the two.
type KernelEntry struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Current     bool   `json:"current"`
	Previous    bool   `json:"previous"`
	Path        string `json:"path,omitempty"`
	SizeBytes   int64  `json:"size_bytes,omitempty"`
	InstalledAt int64  `json:"installed_at,omitempty"`
	InUse       bool   `json:"in_use"`
}

// Report is the result of Apply, ready to be sent to the panel. It is JSON
// serialisable and never contains instance secrets.
type Report struct {
	Revision int64  `json:"revision"`
	Hash     string `json:"hash"`
	Status   Status `json:"status"`
	Message  string `json:"message,omitempty"`
	// Blocked is set when this hash had already failed and was not retried.
	Blocked          bool             `json:"blocked,omitempty"`
	ValidationErrors []validate.Error `json:"validation_errors,omitempty"`
	Instances        []InstanceReport `json:"instances"`
	// Kernels maps driver name to the kernel version in use ("builtin" for
	// the embedded xray).
	Kernels map[string]string `json:"kernels,omitempty"`
	// KernelEntries is the structured installed-kernel list. It is a separate
	// field on purpose: Kernels says which version this apply selected per
	// engine, KernelEntries says what is installed on the machine (design
	// section 6.6). It is filled by the caller that owns the kernel manager.
	KernelEntries []KernelEntry `json:"kernel_entries,omitempty"`
	At            time.Time     `json:"at"`
}

func (r Report) clone() Report {
	c := r
	c.ValidationErrors = append([]validate.Error(nil), r.ValidationErrors...)
	c.Instances = make([]InstanceReport, len(r.Instances))
	for i, in := range r.Instances {
		in.Ports = append([]string(nil), in.Ports...)
		if in.Considered != nil {
			m := make(map[string]string, len(in.Considered))
			for k, v := range in.Considered {
				m[k] = v
			}
			in.Considered = m
		}
		c.Instances[i] = in
	}
	if r.Kernels != nil {
		c.Kernels = make(map[string]string, len(r.Kernels))
		for k, v := range r.Kernels {
			c.Kernels[k] = v
		}
	}
	c.KernelEntries = append([]KernelEntry(nil), r.KernelEntries...)
	return c
}

// Diff is one difference between the desired and the actual state.
type Diff struct {
	Instance string `json:"instance"`
	// Kind: missing | not_running | hash_mismatch | not_listening |
	// port_not_bound | unexpected | driver_missing.
	Kind   string `json:"kind"`
	Detail string `json:"detail,omitempty"`
}

// HealthReport is the result of Health.
type HealthReport struct {
	At       time.Time `json:"at"`
	Revision int64     `json:"revision"`
	Hash     string    `json:"hash"`
	// OK is true when nothing differs. It is false (with Skipped set) when no
	// check could be made.
	OK      bool   `json:"ok"`
	Diffs   []Diff `json:"diffs,omitempty"`
	Skipped string `json:"skipped,omitempty"`
}

// ---- secret scrubbing ------------------------------------------------------

// minSecretScrub is the shortest secret that is searched for in text. Valid
// secrets are at least 16 characters; shorter strings would match too much.
const minSecretScrub = 8

func collectSecrets(d spec.Desired) []string {
	seen := map[string]bool{}
	var out []string
	for _, in := range d.Instances {
		if len(in.Secret) >= minSecretScrub && !seen[in.Secret] {
			seen[in.Secret] = true
			out = append(out, in.Secret)
		}
	}
	// longest first so a secret that contains another is removed whole
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

func scrub(s string, secrets []string) string {
	for _, sec := range secrets {
		if strings.Contains(s, sec) {
			s = strings.ReplaceAll(s, sec, "***")
		}
	}
	return s
}

func scrubReport(r *Report, secrets []string) {
	if len(secrets) == 0 {
		return
	}
	r.Message = scrub(r.Message, secrets)
	for i := range r.ValidationErrors {
		r.ValidationErrors[i].Message = scrub(r.ValidationErrors[i].Message, secrets)
	}
	for i := range r.Instances {
		in := &r.Instances[i]
		in.Error = scrub(in.Error, secrets)
		for k, v := range in.Considered {
			in.Considered[k] = scrub(v, secrets)
		}
	}
}

// ---- port compaction -------------------------------------------------------

// compactClaims renders claims as "proto addr:port[-port]" lines with
// consecutive ports merged, so a 1000-port range stays one entry.
func compactClaims(cs []driver.PortClaim) []string {
	if len(cs) == 0 {
		return nil
	}
	sorted := append([]driver.PortClaim(nil), cs...)
	sort.Slice(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.Proto != b.Proto {
			return a.Proto < b.Proto
		}
		if a.Addr != b.Addr {
			return a.Addr < b.Addr
		}
		return a.Port < b.Port
	})
	var out []string
	for i := 0; i < len(sorted); {
		j := i
		for j+1 < len(sorted) && sorted[j+1].Proto == sorted[i].Proto && sorted[j+1].Addr == sorted[i].Addr && sorted[j+1].Port == sorted[j].Port+1 {
			j++
		}
		addr := sorted[i].Addr
		if addr == "" {
			addr = "*"
		}
		if j == i {
			out = append(out, fmt.Sprintf("%s %s:%d", sorted[i].Proto, addr, sorted[i].Port))
		} else {
			out = append(out, fmt.Sprintf("%s %s:%d-%d", sorted[i].Proto, addr, sorted[i].Port, sorted[j].Port))
		}
		i = j + 1
	}
	return out
}
