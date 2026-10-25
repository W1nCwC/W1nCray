package porthop

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
)

// Inspect reads what an earlier run recorded in <StateDir>/porthop/state.json
// and checks, without changing anything, whether those rules are present in
// the firewall now. It is for the `W1nCray porthop status` command, which runs
// in a fresh process that holds no in-memory state. Use it on a Manager that
// is discarded afterwards: an IPv4-only nftables setup is learned by turning
// the ip6 table off in the backend.
func (m *Manager) Inspect(ctx context.Context) Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := Status{Enabled: m.cfg.Enabled, Rules: []RuleStatus{}}
	if err := m.ensureBackend(ctx); err != nil {
		st.LastError = err.Error()
		return st
	}
	st.Available, st.Backend = true, m.be.name()
	b, err := os.ReadFile(filepath.Join(m.dir(), "state.json"))
	if err != nil {
		if os.IsNotExist(err) {
			st.Note = "no rules recorded"
		} else {
			st.LastError = err.Error()
		}
		return st
	}
	var sf stateFile
	if err := json.Unmarshal(b, &sf); err != nil {
		st.LastError = "state.json: " + err.Error()
		return st
	}
	var acc []accepted
	for _, r := range sf.Rules {
		lo, hi, err := ParseRange(r.Ports)
		if err != nil {
			st.Rules = append(st.Rules, RuleStatus{NodeID: r.NodeID, Proto: r.Proto, Ports: r.Ports, To: r.To, Reason: err.Error()})
			continue
		}
		acc = append(acc, accepted{Rule: r, Lo: lo, Hi: hi})
	}
	check := func(a accepted) error { return m.be.verify(ctx, []accepted{a}) }
	if nb, ok := m.be.(*nftBackend); ok && len(acc) > 0 && check(acc[0]) != nil {
		nb.v6 = false
		if check(acc[0]) == nil {
			nb.n = "ipv6 nat unavailable, only IPv4 is redirected"
		} else {
			nb.v6 = true
		}
	}
	st.Note = m.be.note()
	for _, a := range acc {
		rs := RuleStatus{NodeID: a.NodeID, Proto: a.Proto, Ports: a.Ports, To: a.To, OK: true}
		if err := check(a); err != nil {
			rs.OK, rs.Reason = false, "missing from the firewall"
		}
		st.Rules = append(st.Rules, rs)
	}
	return st
}
