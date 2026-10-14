// Package fwopen keeps the WAN side of an OpenWrt router reachable: it
// maintains one UCI firewall rule per forwarding instance that listens on a
// non-loopback address.
//
// It exists because the stock OpenWrt firewall rejects WAN input (PLAN v11
// §4.3): an instance that listens on 0.0.0.0 is reachable from the LAN but not
// from the internet until a rule opens the port. fwopen owns exactly one
// namespace: every section it writes is named "<SectionPrefix><instance>", and
// the reconcile removes every section with that prefix that no instance claims.
// The user's rules, zones and defaults are never touched.
//
// The rules are UCI firewall sections, so they survive a reboot and are visible
// in the same place as every other OpenWrt rule:
//
//	config rule 'w1ncray_fwd1'
//		option name 'W1nCray fwd1'
//		option src 'wan'
//		option proto 'tcp udp'
//		option dest_port '20000-20009'
//		option target 'ACCEPT'
//
// After a change the package commits the firewall configuration and reloads it
// ("fw4 reload" on OpenWrt >= 22.03, "/etc/init.d/firewall reload" on the fw3
// systems of 21.02 and older).
package fwopen

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/portledger"
	"github.com/W1nCwC/W1nCray/agent/spec"
)

// SectionPrefix names every firewall section the agent owns. It is the whole
// boundary of this package: only sections whose name starts with it are read,
// changed or deleted.
const SectionPrefix = "w1ncray_"

// fw3InitScript is the reload entry point of the iptables-based fw3 firewall
// (OpenWrt 21.02 and older). Newer releases ship the nftables-based fw4 binary.
const fw3InitScript = "/etc/init.d/firewall"

// commandTimeout bounds one uci/fw4 invocation. A hung uci must not hold the
// reconciler (and therefore every apply) forever.
const commandTimeout = 20 * time.Second

// Reload retry policy. The rules are committed before the reload runs, so a
// reload that fails transiently (fw4 reload is known to time out under load)
// leaves a persisted but inactive configuration. Retrying turns that window
// back into a normal apply; the wait doubles after every failure and the whole
// loop is bounded by reloadBudget.
const (
	// reloadAttempts is the total number of reload invocations after a commit
	// (the first try plus its retries).
	reloadAttempts = 3
	// reloadBackoff is the wait before the second attempt; it doubles after
	// every further failure.
	reloadBackoff = time.Second
	// reloadBudget caps the total time the reload loop may take, including the
	// time the reload commands themselves run.
	reloadBudget = 20 * time.Second
)

// Executor runs the external commands fwopen needs. It is an interface so the
// unit tests can pin the exact command sequence without a router.
type Executor interface {
	// Run executes name with args and returns its combined output.
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// Manager maintains the agent's firewall sections. The zero value is not
// usable; build one with New. It is safe for concurrent use.
type Manager struct {
	openWrt  bool
	autoOpen bool
	exec     Executor
	// reload is the argv of the firewall reload command (nil when neither fw4
	// nor the fw3 init script was found).
	reload []string
	// reloadTries, reloadWait and reloadCap are the retry policy of
	// reloadFirewall. New fills them with the package defaults; the unit tests
	// shrink them so a retry test does not sleep.
	reloadTries int
	reloadWait  time.Duration
	reloadCap   time.Duration
	log         driver.Logger

	mu sync.Mutex
}

// Options configures a Manager.
type Options struct {
	// OpenWrt is the detected platform: only OpenWrt has the UCI firewall this
	// package drives. Everywhere else Enabled is false and Sync is a no-op.
	OpenWrt bool
	// AutoOpen is the local switch (agent.yml Firewall.AutoOpen, defaulted per
	// platform). False keeps the agent's hands off the firewall.
	AutoOpen bool
	// Exec overrides the command runner (tests).
	Exec Executor
	// Reload overrides the firewall reload argv (tests). Empty means the
	// default: "fw4 reload" when fw4 exists, else the fw3 init script.
	Reload []string
	// Log receives one line per failed command; nil logs nothing.
	Log driver.Logger
}

// New builds a Manager. It never fails: a machine where neither reload command
// exists (for example a container with an OpenWrt release file) reports the
// error when it is first used.
func New(o Options) *Manager {
	m := &Manager{
		openWrt:     o.OpenWrt,
		autoOpen:    o.AutoOpen,
		exec:        o.Exec,
		reload:      append([]string(nil), o.Reload...),
		reloadTries: reloadAttempts,
		reloadWait:  reloadBackoff,
		reloadCap:   reloadBudget,
		log:         o.Log,
	}
	if m.exec == nil {
		m.exec = execExecutor{}
	}
	if m.log == nil {
		m.log = nopLog{}
	}
	if len(m.reload) == 0 {
		m.reload = defaultReload()
	}
	return m
}

// Enabled reports whether this machine manages its firewall at all: only on
// OpenWrt, and only when the local switch is on.
func (m *Manager) Enabled() bool { return m != nil && m.openWrt && m.autoOpen }

// rule is one desired firewall section.
type rule struct {
	instance string // instance id, for the report
	section  string // UCI section name ("w1ncray_<id>")
	name     string // UCI "name" option ("W1nCray <instance name>")
	proto    string // "tcp", "udp" or "tcp udp"
	destPort string // "8443" or "20000-20009"
}

// fields is the option set of a rule, in the order it is written. src and
// target are constant: the rule accepts WAN input for this instance only.
func (r rule) fields() [][2]string {
	return [][2]string{
		{"name", r.name},
		{"src", "wan"},
		{"proto", r.proto},
		{"dest_port", r.destPort},
		{"target", "ACCEPT"},
	}
}

// Sync makes the firewall sections match the public listeners of instances. It
// is a no-op on a machine where Enabled is false (open is then empty and
// skipped is nil).
//
// It returns:
//
//   - open: per instance id, whether that instance's public ports are open. The
//     section of an instance whose ports are open is reported true even when
//     nothing had to change. A failure leaves this map unusable (nil): the
//     caller must treat every instance as not opened.
//   - skipped: per instance id, why no rule could be derived for it, i.e. a
//     port declaration the agent could not parse. A warning is logged for every
//     entry; the caller can surface them in its own report. A skipped instance
//     is absent from open.
//   - err: a command failed. A *ReloadError means the configuration was
//     committed but the firewall was not reloaded: the rules are persisted yet
//     not active.
func (m *Manager) Sync(ctx context.Context, instances []spec.Instance) (map[string]bool, map[string]string, error) {
	open := map[string]bool{}
	if !m.Enabled() {
		return open, nil, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	want, skips := desiredRules(instances)
	skipped := make(map[string]string, len(skips))
	for _, s := range skips {
		skipped[s.instance] = s.reason
	}
	if len(skips) > 0 {
		// Sorted so the warning order of two identical applies is the same.
		ids := make([]string, 0, len(skips))
		for _, s := range skips {
			ids = append(ids, s.instance)
		}
		sort.Strings(ids)
		for _, id := range ids {
			m.log.Warnf("fwopen: instance %s has no firewall rule: %s", id, skipped[id])
		}
	}

	wantBySection := make(map[string]rule, len(want))
	for _, r := range want {
		wantBySection[r.section] = r
	}
	have, err := m.show(ctx)
	if err != nil {
		return nil, skipped, err
	}

	changed := false
	// Deterministic order: sorted by section, so the command sequence of a test
	// (and of two identical applies) never depends on map iteration.
	for _, r := range want {
		cur, exists := have[r.section]
		switch {
		case !exists || cur["__type"] != "rule":
			if exists {
				// A section of the wrong type cannot be turned into a rule;
				// remove it first so the recreate cannot fail halfway.
				if _, err := m.run(ctx, "uci", "delete", "firewall."+r.section); err != nil {
					return nil, skipped, err
				}
			}
			if _, err := m.run(ctx, "uci", "set", "firewall."+r.section+"=rule"); err != nil {
				return nil, skipped, err
			}
			for _, kv := range r.fields() {
				if _, err := m.run(ctx, "uci", "set", "firewall."+r.section+"."+kv[0]+"="+kv[1]); err != nil {
					return nil, skipped, err
				}
			}
			changed = true
		default:
			for _, kv := range r.fields() {
				if cur[kv[0]] == kv[1] {
					continue
				}
				if _, err := m.run(ctx, "uci", "set", "firewall."+r.section+"."+kv[0]+"="+kv[1]); err != nil {
					return nil, skipped, err
				}
				changed = true
			}
		}
		open[r.instance] = true
	}

	var stale []string
	for section := range have {
		if _, ok := wantBySection[section]; !ok {
			stale = append(stale, section)
		}
	}
	sort.Strings(stale)
	for _, section := range stale {
		if _, err := m.run(ctx, "uci", "delete", "firewall."+section); err != nil {
			return nil, skipped, err
		}
		changed = true
	}

	if !changed {
		return open, skipped, nil
	}
	if _, err := m.run(ctx, "uci", "commit", "firewall"); err != nil {
		return nil, skipped, err
	}
	if err := m.reloadFirewall(ctx); err != nil {
		return nil, skipped, err
	}
	m.log.Infof("fwopen: firewall updated (%d rule(s) open, %d removed)", len(want), len(stale))
	return open, skipped, nil
}

// show reads the firewall configuration and returns the agent-owned sections,
// keyed by section name. The special key "__type" carries the section type
// ("rule", "zone", ...). Only sections named with SectionPrefix are returned.
func (m *Manager) show(ctx context.Context) (map[string]map[string]string, error) {
	out, err := m.run(ctx, "uci", "show", "firewall")
	if err != nil {
		return nil, err
	}
	return parseShow(out), nil
}

// parseShow parses "uci show firewall" output. It keeps the lines whose section
// name carries SectionPrefix; everything else belongs to the user.
//
//	<sec>=<type>
//	<sec>.<option>=<value>
func parseShow(out string) map[string]map[string]string {
	sections := map[string]map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimPrefix(key, "firewall.")
		if key == line {
			continue // not a firewall section line
		}
		section, option, hasOption := strings.Cut(key, ".")
		if !strings.HasPrefix(section, SectionPrefix) {
			continue
		}
		if sections[section] == nil {
			sections[section] = map[string]string{}
		}
		if !hasOption {
			sections[section]["__type"] = value
			continue
		}
		sections[section][option] = unquote(value)
	}
	return sections
}

// unquote strips the single quotes "uci show" prints around a value. Values the
// agent writes never contain a quote (an instance name cannot), so a simple
// outer-quote strip is exact for them and best effort for a hand-written one.
func unquote(s string) string {
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return s[1 : len(s)-1]
	}
	return s
}

// skip is one instance that got no rule because its port declaration could not
// be parsed. It is reported in the Sync result instead of being dropped
// silently.
type skip struct {
	instance string // instance id, for the report
	reason   string // why no rule was derived ("listen ports ...: ...")
}

// desiredRules extracts the firewall rule of every instance that accepts user
// traffic on a non-loopback address, together with the instances it had to
// skip because their port declaration does not parse. Instances without such a
// listener produce no rule and no skip: a disabled instance, a loopback-only
// listener, and a reverse_bridge (it dials out; the public port belongs to the
// portal instance).
func desiredRules(instances []spec.Instance) ([]rule, []skip) {
	var out []rule
	var skips []skip
	seen := map[string]bool{}
	for _, in := range instances {
		if !in.Enabled {
			continue
		}
		_, ports, ok := publicListener(in)
		if !ok {
			continue
		}
		lo, hi, err := portledger.ParsePorts(ports)
		if err != nil {
			// The validator rejects this long before we run, so this branch is
			// defence in depth: never drop a rule without saying so.
			skips = append(skips, skip{
				instance: in.ID,
				reason:   fmt.Sprintf("listen ports %q: %v", ports, err),
			})
			continue
		}
		dest := strconv.Itoa(lo)
		if hi != lo {
			dest = strconv.Itoa(lo) + "-" + strconv.Itoa(hi)
		}
		section := SectionPrefix + sectionID(in.ID)
		if seen[section] {
			// Two instance ids cannot collide (sectionID is injective), but a
			// defensive skip keeps a future bug from writing one rule twice.
			continue
		}
		seen[section] = true
		out = append(out, rule{
			instance: in.ID,
			section:  section,
			name:     "W1nCray " + displayName(in),
			proto:    protos(in.Network),
			destPort: dest,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].section < out[j].section })
	return out, skips
}

// publicListener returns the address and port spec an instance listens on for
// user traffic, and false when it has none or it is loopback-only.
func publicListener(in spec.Instance) (addr, ports string, ok bool) {
	switch in.Kind {
	case spec.KindForward, spec.KindTunnelEntry, spec.KindReversePortal:
		if in.Listen == nil {
			return "", "", false
		}
		addr, ports = in.Listen.Addr, in.Listen.Ports
	case spec.KindTunnelExit:
		// A tunnel exit has no Listen; the tunnel accepts on Tunnel.Listen.
		if in.Tunnel == nil {
			return "", "", false
		}
		host, port, err := net.SplitHostPort(in.Tunnel.Listen)
		if err != nil {
			return "", "", false
		}
		addr, ports = host, port
	default:
		// reverse_bridge (and anything new): no local user-facing listener.
		return "", "", false
	}
	if addr == "" || isLoopback(addr) {
		return "", "", false
	}
	return addr, ports, true
}

// isLoopback reports whether addr is a loopback address. An address that does
// not parse is treated as loopback (never opened): the desired state is
// validated before this runs, so the conservative answer is the safe one.
func isLoopback(addr string) bool {
	a, err := netip.ParseAddr(strings.TrimSpace(addr))
	if err != nil {
		return true
	}
	return a.Unmap().IsLoopback()
}

// protos renders the instance's network list as the UCI proto value. An empty
// or unknown list falls back to TCP, which is the desired-state default.
func protos(network []string) string {
	seen := map[string]bool{}
	var out []string
	for _, n := range network {
		n = strings.ToLower(strings.TrimSpace(n))
		if n != "tcp" && n != "udp" {
			continue
		}
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	if len(out) == 0 {
		out = []string{"tcp"}
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

// displayName is the instance name shown in the rule ("W1nCray <name>"). An
// instance without a name falls back to its id.
func displayName(in spec.Instance) string {
	if in.Name != "" {
		return in.Name
	}
	return in.ID
}

// sectionID encodes an instance id into a UCI section name. UCI section names
// may only contain [A-Za-z0-9_] (a "-" is rejected with "uci: Invalid
// argument"), while an instance id may contain "-" and "_". The encoding is
// injective, so two different ids can never share a section:
//
//	"_" -> "__"   (a literal underscore)
//	"-" -> "_d"   (a dash)
//
// Every other byte of a valid id is already allowed and is copied as is.
func sectionID(id string) string {
	var b strings.Builder
	b.Grow(len(id) + 4)
	for i := 0; i < len(id); i++ {
		switch id[i] {
		case '_':
			b.WriteString("__")
		case '-':
			b.WriteString("_d")
		default:
			b.WriteByte(id[i])
		}
	}
	return b.String()
}

// ReloadError reports that the firewall configuration was committed but the
// firewall did not reload, so the new rules are persisted and not active. A
// later reload (the next apply, or a reboot) makes them effective.
type ReloadError struct {
	// Attempts is the number of reload invocations that failed.
	Attempts int
	// Err is the last failure.
	Err error
}

func (e *ReloadError) Error() string {
	return fmt.Sprintf("fwopen: firewall rules committed but not active: reload failed after %d attempt(s): %v", e.Attempts, e.Err)
}

// Unwrap exposes the last failure to errors.Is and errors.As.
func (e *ReloadError) Unwrap() error { return e.Err }

// RulesPersisted reports that the rules are saved and will take effect on the
// next successful reload. The reconciler matches this method structurally, so
// it can tell this state from a failure that changed nothing without importing
// this package.
func (e *ReloadError) RulesPersisted() bool { return true }

// reloadFirewall reloads the firewall after a commit. The rules are already
// persisted, so a transient failure (fw4 reload is known to time out under
// load) is retried with a doubling wait; the whole loop is bounded by
// reloadCap. When every attempt fails the returned error is a *ReloadError:
// the rules are saved but not active.
func (m *Manager) reloadFirewall(ctx context.Context) error {
	if len(m.reload) == 0 {
		return fmt.Errorf("fwopen: no firewall reload command found (%s or fw4)", fw3InitScript)
	}
	rctx, cancel := context.WithTimeout(ctx, m.reloadCap)
	defer cancel()
	var lastErr error
	attempts := 0
	for {
		attempts++
		_, err := m.run(rctx, m.reload[0], m.reload[1:]...)
		if err == nil {
			if attempts > 1 {
				m.log.Infof("fwopen: firewall reload succeeded on attempt %d", attempts)
			}
			return nil
		}
		lastErr = err
		if attempts >= m.reloadTries {
			break
		}
		m.log.Warnf("fwopen: firewall reload attempt %d/%d failed: %v", attempts, m.reloadTries, lastErr)
		wait := m.reloadWait << (attempts - 1)
		if wait <= 0 || wait > m.reloadCap {
			wait = m.reloadCap
		}
		if !sleepContext(rctx, wait) {
			break
		}
	}
	return &ReloadError{Attempts: attempts, Err: lastErr}
}

// sleepContext waits for d and reports false when ctx is done first. A
// non-positive wait returns immediately.
func sleepContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// defaultReload resolves the reload command of the running system.
func defaultReload() []string {
	_, fw4 := exec.LookPath("fw4")
	_, err := os.Stat(fw3InitScript)
	return resolveReload(fw4 == nil, err == nil)
}

// resolveReload is defaultReload with its two probes injected.
func resolveReload(hasFw4, hasFw3Init bool) []string {
	switch {
	case hasFw4:
		return []string{"fw4", "reload"}
	case hasFw3Init:
		return []string{fw3InitScript, "reload"}
	default:
		return nil
	}
}

// run executes one command through the executor.
func (m *Manager) run(ctx context.Context, name string, args ...string) (string, error) {
	return m.exec.Run(ctx, name, args...)
}

// execExecutor runs the real uci/fw4 binaries.
type execExecutor struct{}

func (execExecutor) Run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput() //nolint:noshell -- uci/fw4 with an argv array, never a shell
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, msg)
		}
		return string(out), fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return string(out), nil
}

// nopLog is the default logger.
type nopLog struct{}

func (nopLog) Debugf(string, ...any) {}
func (nopLog) Infof(string, ...any)  {}
func (nopLog) Warnf(string, ...any)  {}
func (nopLog) Errorf(string, ...any) {}
