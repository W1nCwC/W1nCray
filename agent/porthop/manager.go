package porthop

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// commandTimeout bounds one firewall command.
const commandTimeout = 20 * time.Second

// Config configures a Manager.
type Config struct {
	// Enabled is the local switch. False makes Apply equivalent to Clear and
	// Status report the feature as unavailable.
	Enabled bool
	// Backend forces "nft" or "iptables"; "" or "auto" probes (nft first).
	Backend string
	// StateDir holds <StateDir>/porthop/{rules.nft,state.json}.
	StateDir string
	// MaxSpan is the largest accepted range (ports); 0 means DefaultMaxSpan.
	MaxSpan int
	// AllowTCP admits rules with proto "tcp" (mieru can hop over a TCP
	// transport). The zero value refuses them; the agent sets it from
	// Firewall.PortHopAllowTCP, which is on unless the local configuration says
	// false. A tcp rule still passes every other gate: range start, span,
	// local forwards and listening sockets (LISTEN state only).
	AllowTCP bool
	// ProcRoot is the proc filesystem root; "" means /proc.
	ProcRoot string
	// SelfPID is the agent's pid, used to ignore its own sockets; 0 means
	// os.Getpid().
	SelfPID int
	// ForwardPorts returns the ports local forwards occupy (reconcile ledger).
	// Nil disables that check.
	ForwardPorts func() map[int]bool
	// ForwardPortsFor is ForwardPorts per protocol ("udp" or "tcp"): a TCP
	// forward must not block a UDP hop range or the other way round. When set
	// it replaces ForwardPorts.
	ForwardPortsFor func(proto string) map[int]bool
	// Checker replaces the default conflict checks (ledger + /proc/net).
	Checker ConflictChecker
	// Exec runs the firewall tools; nil means SystemExecutor.
	Exec Executor
	// Logf receives diagnostics; nil logs nothing.
	Logf func(format string, args ...any)
}

func (c *Config) maxSpan() int {
	if c.MaxSpan > 0 {
		return c.MaxSpan
	}
	return DefaultMaxSpan
}

// RuleStatus is the outcome for one panel rule.
type RuleStatus struct {
	NodeID int    `json:"node_id"`
	Proto  string `json:"proto"`
	Ports  string `json:"ports"`
	To     int    `json:"to"`
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

// Status is a snapshot for reporting to the panel.
type Status struct {
	Enabled   bool         `json:"enabled"`
	Available bool         `json:"available"`
	Backend   string       `json:"backend,omitempty"`
	Note      string       `json:"note,omitempty"`
	Rules     []RuleStatus `json:"rules"`
	LastError string       `json:"last_error,omitempty"`
}

type stateFile struct {
	Backend string `json:"backend"`
	Hash    string `json:"hash"`
	Rules   []Rule `json:"rules"`
}

// Manager owns the agent's port-hop firewall state. Safe for concurrent use.
type Manager struct {
	cfg Config
	e   env

	mu        sync.Mutex
	be        backend
	proven    bool // the backend completed a real commit
	cleaned   bool // a clear ran (or state was restored) in this process
	hash      string
	installed []accepted
	accepted  map[string]bool // rule keys that passed the conflict check
	statuses  []RuleStatus
	lastErr   string
}

// New builds a Manager. It does not touch the system.
func New(cfg Config) *Manager {
	if cfg.Exec == nil {
		cfg.Exec = SystemExecutor{}
	}
	if cfg.ProcRoot == "" {
		cfg.ProcRoot = "/proc"
	}
	if cfg.SelfPID == 0 {
		cfg.SelfPID = os.Getpid()
	}
	if cfg.Checker == nil {
		var cs chain
		switch {
		case cfg.ForwardPortsFor != nil:
			cs = append(cs, ledgerChecker{byProto: cfg.ForwardPortsFor})
		case cfg.ForwardPorts != nil:
			cs = append(cs, NewLedgerChecker(cfg.ForwardPorts))
		}
		cs = append(cs, NewProcChecker(cfg.ProcRoot, cfg.SelfPID))
		cfg.Checker = cs
	}
	m := &Manager{cfg: cfg, accepted: map[string]bool{}}
	m.e = env{run: m.run, runFile: m.runFile, writeTmp: m.writeFile}
	return m
}

func (m *Manager) logf(format string, args ...any) {
	if m.cfg.Logf != nil {
		m.cfg.Logf(format, args...)
	}
}

func (m *Manager) dir() string { return filepath.Join(m.cfg.StateDir, "porthop") }

func (m *Manager) run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	out, err := m.cfg.Exec.Run(ctx, name, args...)
	return out, wrapCmd(err, name, args, out)
}

func (m *Manager) runFile(ctx context.Context, stdinFile, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	out, err := m.cfg.Exec.RunWithStdinFile(ctx, stdinFile, name, args...)
	return out, wrapCmd(err, name, args, out)
}

func wrapCmd(err error, name string, args []string, out string) error {
	if err == nil {
		return nil
	}
	out = strings.TrimSpace(out)
	if len(out) > 300 {
		out = out[:300]
	}
	return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, out)
}

func (m *Manager) writeFile(name, content string) (string, error) {
	if err := os.MkdirAll(m.dir(), 0o700); err != nil {
		return "", err
	}
	p := filepath.Join(m.dir(), name)
	return p, writeAtomic(p, []byte(content))
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// ---- backend selection ----------------------------------------------------

var errNoBackend = errors.New("no usable firewall backend (nft or iptables)")

func (m *Manager) ensureBackend(ctx context.Context) error {
	if m.be != nil {
		return nil
	}
	var cands []backend
	switch m.cfg.Backend {
	case backendNft:
		cands = []backend{newNft(m.e)}
	case backendIptables:
		cands = []backend{newIpt(m.e)}
	default:
		cands = []backend{newNft(m.e), newIpt(m.e)}
	}
	var errs []error
	for _, b := range cands {
		if err := b.probe(ctx); err != nil {
			m.logf("porthop: backend %s unusable: %v", b.name(), err)
			errs = append(errs, fmt.Errorf("%s: %w", b.name(), err))
			continue
		}
		m.be = b
		m.proven = false
		return nil
	}
	return fmt.Errorf("%w: %v", errNoBackend, errors.Join(errs...))
}

// install commits rules; in auto mode a not yet proven nft backend that fails
// its first real commit falls back to iptables.
func (m *Manager) install(ctx context.Context, rules []accepted) error {
	err := m.be.install(ctx, rules)
	if err == nil {
		m.proven = true
		return nil
	}
	if m.cfg.Backend == "" || m.cfg.Backend == "auto" {
		if m.be.name() == backendNft && !m.proven {
			ipt := newIpt(m.e)
			if perr := ipt.probe(ctx); perr == nil {
				m.logf("porthop: nft commit failed (%v), falling back to iptables", err)
				if err2 := ipt.install(ctx, rules); err2 == nil {
					m.be = ipt
					m.proven = true
					return nil
				} else {
					return err2
				}
			}
		}
	}
	return err
}

// ---- evaluation -----------------------------------------------------------

func overlaps(a, b accepted) bool {
	return a.Proto == b.Proto && a.Lo <= b.Hi && b.Lo <= a.Hi
}

// evaluate runs every gate. Rules are processed in node_id order so that on an
// overlap the smaller node_id wins. The conflict check (ledger, /proc/net) is
// skipped for a rule that was accepted by the previous evaluation, so a socket
// appearing later cannot flip an installed rule off; a rejected rule is checked
// again every time, so it can only flip on.
func (m *Manager) evaluate(rules []Rule) ([]accepted, []RuleStatus) {
	sorted := append([]Rule(nil), rules...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].NodeID < sorted[j].NodeID })
	var acc []accepted
	var sts []RuleStatus
	next := map[string]bool{}
	for _, r := range sorted {
		st := RuleStatus{NodeID: r.NodeID, Proto: r.Proto, Ports: r.Ports, To: r.To}
		lo, hi, err := m.cfg.validate(r)
		if err != nil {
			st.Reason = err.Error()
			sts = append(sts, st)
			continue
		}
		a := accepted{Rule: r, Lo: lo, Hi: hi}
		clash := ""
		for _, o := range acc {
			if overlaps(a, o) {
				clash = fmt.Sprintf("range overlaps node %d (%s), the lower node_id wins", o.NodeID, o.Ports)
				break
			}
		}
		if clash != "" {
			st.Reason = clash
			sts = append(sts, st)
			continue
		}
		if !m.accepted[r.key()] {
			if err := m.cfg.Checker.Check(r.Proto, lo, hi, r.To); err != nil {
				st.Reason = "conflict: " + err.Error()
				sts = append(sts, st)
				continue
			}
		}
		next[r.key()] = true
		st.OK = true
		sts = append(sts, st)
		acc = append(acc, a)
	}
	m.accepted = next
	sort.SliceStable(acc, func(i, j int) bool {
		if acc[i].NodeID != acc[j].NodeID {
			return acc[i].NodeID < acc[j].NodeID
		}
		if acc[i].Proto != acc[j].Proto {
			return acc[i].Proto < acc[j].Proto
		}
		return acc[i].Lo < acc[j].Lo
	})
	return acc, sts
}

func (m *Manager) hashOf(acc []accepted) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n", m.be.name())
	for _, a := range acc {
		fmt.Fprintf(h, "%s\n", a.key())
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (m *Manager) failAll(reason string) {
	for i := range m.statuses {
		if m.statuses[i].OK {
			m.statuses[i].OK = false
			m.statuses[i].Reason = reason
		}
	}
}

// ---- public API -----------------------------------------------------------

// Probe selects the backend without changing the firewall. A nil error means
// port hopping can be offered (capability "port_hop").
func (m *Manager) Probe(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.cfg.Enabled {
		return errors.New("port hopping is disabled locally")
	}
	err := m.ensureBackend(ctx)
	if err != nil {
		m.lastErr = err.Error()
	}
	return err
}

// Available reports whether a backend was found and the local switch is on.
func (m *Manager) Available() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg.Enabled && m.be != nil
}

// Apply makes the firewall match rules. It is idempotent: when the accepted
// set is unchanged and still present nothing is written.
func (m *Manager) Apply(ctx context.Context, rules []Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.applyLocked(ctx, rules)
}

func (m *Manager) applyLocked(ctx context.Context, rules []Rule) error {
	if !m.cfg.Enabled {
		m.statuses = nil
		return m.clearLocked(ctx)
	}
	acc, sts := m.evaluate(rules)
	m.statuses = sts
	if err := m.ensureBackend(ctx); err != nil {
		m.lastErr = err.Error()
		m.failAll("no firewall backend")
		return err
	}
	if len(acc) == 0 {
		if m.hash != "" || !m.cleaned {
			if err := m.clearLocked(ctx); err != nil {
				return err
			}
		}
		m.lastErr = ""
		return nil
	}
	h := m.hashOf(acc)
	if h == m.hash {
		if err := m.be.verify(ctx, acc); err == nil {
			m.lastErr = ""
			return nil
		} else {
			m.logf("porthop: rules lost, reinstalling: %v", err)
		}
	}
	if err := m.install(ctx, acc); err != nil {
		m.lastErr = err.Error()
		m.failAll("commit failed")
		return err
	}
	m.hash, m.installed, m.cleaned, m.lastErr = h, acc, true, ""
	return m.saveState(acc, h)
}

func (m *Manager) saveState(acc []accepted, h string) error {
	st := stateFile{Backend: m.be.name(), Hash: h}
	for _, a := range acc {
		st.Rules = append(st.Rules, a.Rule)
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(m.dir(), 0o700); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(m.dir(), "state.json"), b)
}

// Verify checks that every installed rule is still present (for the 60 second
// self-heal poll). It changes nothing.
func (m *Manager) Verify(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.verifyLocked(ctx)
}

func (m *Manager) verifyLocked(ctx context.Context) error {
	if !m.cfg.Enabled || m.be == nil || len(m.installed) == 0 {
		return nil
	}
	return m.be.verify(ctx, m.installed)
}

// Heal is Verify plus repair: when rules are missing the whole set is
// committed again.
func (m *Manager) Heal(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.verifyLocked(ctx); err == nil {
		return nil
	} else {
		m.logf("porthop: self-heal: %v", err)
	}
	if err := m.install(ctx, m.installed); err != nil {
		m.lastErr = err.Error()
		return err
	}
	m.lastErr = ""
	return nil
}

// Restore re-applies <StateDir>/porthop/state.json at agent start, without
// waiting for the panel. A missing file is not an error. Rules in the file were
// accepted before, so the conflict check is not repeated.
func (m *Manager) Restore(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.cfg.Enabled {
		return m.clearLocked(ctx)
	}
	b, err := os.ReadFile(filepath.Join(m.dir(), "state.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var st stateFile
	if err := json.Unmarshal(b, &st); err != nil {
		return fmt.Errorf("porthop: state.json: %w", err)
	}
	for _, r := range st.Rules {
		m.accepted[r.key()] = true
	}
	m.cleaned = true
	return m.applyLocked(ctx, st.Rules)
}

// Clear removes every rule and the owned table/chain, and forgets the state.
func (m *Manager) Clear(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statuses = nil
	return m.clearLocked(ctx)
}

func (m *Manager) clearLocked(ctx context.Context) error {
	m.accepted = map[string]bool{}
	os.Remove(filepath.Join(m.dir(), "state.json"))
	if err := m.ensureBackend(ctx); err != nil {
		// Without a backend nothing of ours can exist.
		m.hash, m.installed, m.cleaned = "", nil, true
		return nil
	}
	if err := m.be.remove(ctx); err != nil {
		m.lastErr = err.Error()
		return err
	}
	m.hash, m.installed, m.cleaned, m.lastErr = "", nil, true, ""
	return nil
}

// Status returns a snapshot.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := Status{Enabled: m.cfg.Enabled, LastError: m.lastErr, Rules: append([]RuleStatus{}, m.statuses...)}
	if m.cfg.Enabled && m.be != nil {
		st.Available = true
		st.Backend = m.be.name()
		st.Note = m.be.note()
	}
	return st
}
