package porthop

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fake is an in-memory firewall: it records every command and keeps the state
// the commands would have produced.
type fake struct {
	mu sync.Mutex

	calls []string

	nftCheckOK   bool // "nft -c" passes
	nft6OK       bool // ip6 nat accepted by the kernel
	nftCommitErr bool // "nft -f" fails after a passing check
	hasIpt       bool
	hasIpt6      bool

	nftInstalled map[string]string // family -> table body
	chains       map[string]string // iptables tool -> restore content
	jumps        map[string]bool
}

func newFake() *fake {
	return &fake{
		nftCheckOK: true, nft6OK: true, hasIpt: true, hasIpt6: true,
		nftInstalled: map[string]string{}, chains: map[string]string{}, jumps: map[string]bool{},
	}
}

func (f *fake) count(prefix string) int {
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func (f *fake) Run(_ context.Context, name string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	switch name {
	case "nft":
		switch args[0] {
		case "-c", "-f":
			b, err := os.ReadFile(args[len(args)-1])
			if err != nil {
				return "", err
			}
			c := string(b)
			if !f.nftCheckOK || (!f.nft6OK && strings.Contains(c, "table ip6")) {
				return "Error: bad ruleset", errors.New("exit 1")
			}
			if args[0] == "-f" {
				if f.nftCommitErr {
					return "Error: commit", errors.New("exit 1")
				}
				for _, fam := range []string{"ip", "ip6"} {
					if strings.Contains(c, "table "+fam+" "+NftTable+" {") {
						f.nftInstalled[fam] = c
					} else if strings.Contains(c, "delete table "+fam+" ") {
						delete(f.nftInstalled, fam)
					}
				}
			}
			return "", nil
		case "list":
			if c, ok := f.nftInstalled[args[2]]; ok {
				return c, nil
			}
			return "Error: No such file or directory", errors.New("exit 1")
		}
	case "iptables", "ip6tables":
		if name == "iptables" && !f.hasIpt || name == "ip6tables" && !f.hasIpt6 {
			return "", errors.New("not found")
		}
		switch {
		case args[2] == "-S" && args[3] == "PREROUTING":
			return "-P PREROUTING ACCEPT", nil
		case args[2] == "-S":
			if c, ok := f.chains[name]; ok {
				return c, nil
			}
			return "", errors.New("no chain")
		case args[2] == "-C":
			if f.jumps[name] {
				return "", nil
			}
			return "", errors.New("no rule")
		case args[2] == "-I":
			f.jumps[name] = true
			return "", nil
		case args[2] == "-D":
			if f.jumps[name] {
				f.jumps[name] = false
				return "", nil
			}
			return "", errors.New("no rule")
		case args[2] == "-F":
			return "", nil
		case args[2] == "-X":
			delete(f.chains, name)
			return "", nil
		}
	}
	return "", fmt.Errorf("fake: unexpected %s %v", name, args)
}

func (f *fake) RunWithStdinFile(_ context.Context, file, name string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name+" "+strings.Join(args, " ")+" < "+filepath.Base(file))
	tool := strings.TrimSuffix(name, "-restore")
	if tool == "iptables" && !f.hasIpt || tool == "ip6tables" && !f.hasIpt6 {
		return "", errors.New("not found")
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	f.chains[tool] = string(b)
	return "", nil
}

type okChecker struct{}

func (okChecker) Check(string, int, int, int) error { return nil }

func newMgr(t *testing.T, f *fake, mod func(*Config)) *Manager {
	t.Helper()
	cfg := Config{Enabled: true, StateDir: t.TempDir(), Exec: f, Checker: okChecker{}}
	if mod != nil {
		mod(&cfg)
	}
	return New(cfg)
}

var r12 = Rule{NodeID: 12, Proto: "udp", Ports: "20000-30000", To: 8443}

const wantNft = `table ip w1ncray_porthop
delete table ip w1ncray_porthop
table ip w1ncray_porthop {
	chain prerouting {
		type nat hook prerouting priority -100; policy accept;
		fib daddr type local udp dport 20000-30000 counter redirect to :8443 comment "w1ncray node 12"
	}
}
table ip6 w1ncray_porthop
delete table ip6 w1ncray_porthop
table ip6 w1ncray_porthop {
	chain prerouting {
		type nat hook prerouting priority -100; policy accept;
		fib daddr type local udp dport 20000-30000 counter redirect to :8443 comment "w1ncray node 12"
	}
}
`

const wantIpt = `*nat
:W1NCRAY-PORTHOP - [0:0]
-F W1NCRAY-PORTHOP
-A W1NCRAY-PORTHOP -p udp -m addrtype --dst-type LOCAL --dport 20000:30000 -m comment --comment "w1ncray node 12" -j REDIRECT --to-ports 8443
COMMIT
`

func TestGoldenNft(t *testing.T) {
	got := renderNft([]accepted{{Rule: r12, Lo: 20000, Hi: 30000}}, true)
	if got != wantNft {
		t.Fatalf("nft text mismatch:\n%s", got)
	}
	f := newFake()
	m := newMgr(t, f, nil)
	if err := m.Apply(context.Background(), []Rule{r12}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(m.dir(), "rules.nft"))
	if err != nil || string(b) != wantNft {
		t.Fatalf("rules.nft = %q, %v", b, err)
	}
	if st := m.Status(); st.Backend != "nft" || !st.Available || len(st.Rules) != 1 || !st.Rules[0].OK {
		t.Fatalf("status %+v", st)
	}
}

func TestGoldenIptables(t *testing.T) {
	if got := renderIptables([]accepted{{Rule: r12, Lo: 20000, Hi: 30000}}); got != wantIpt {
		t.Fatalf("iptables text mismatch:\n%s", got)
	}
	f := newFake()
	f.nftCheckOK = false
	m := newMgr(t, f, nil)
	if err := m.Apply(context.Background(), []Rule{r12}); err != nil {
		t.Fatal(err)
	}
	if f.chains["iptables"] != wantIpt || f.chains["ip6tables"] != wantIpt {
		t.Fatalf("restore contents: %v", f.chains)
	}
	if !f.jumps["iptables"] || !f.jumps["ip6tables"] {
		t.Fatalf("jump missing: %v", f.jumps)
	}
	if f.count("iptables-restore --noflush < rules.iptables") != 1 {
		t.Fatalf("calls: %v", f.calls)
	}
	// the jump is looked up first and inserted only when absent
	if f.count("iptables -t nat -C PREROUTING") != 1 || f.count("iptables -t nat -I PREROUTING 1 -j W1NCRAY-PORTHOP") != 1 {
		t.Fatalf("calls: %v", f.calls)
	}
}

func TestIdempotentSecondApply(t *testing.T) {
	f := newFake()
	m := newMgr(t, f, nil)
	ctx := context.Background()
	if err := m.Apply(ctx, []Rule{r12}); err != nil {
		t.Fatal(err)
	}
	commits := f.count("nft -f")
	if commits != 1 {
		t.Fatalf("first apply commits = %d", commits)
	}
	if err := m.Apply(ctx, []Rule{r12}); err != nil {
		t.Fatal(err)
	}
	if f.count("nft -f") != commits {
		t.Fatalf("second apply committed again: %v", f.calls)
	}
	if f.count("nft list table") == 0 {
		t.Fatal("second apply did not verify")
	}
}

func TestRulesLostAreReinstalled(t *testing.T) {
	f := newFake()
	m := newMgr(t, f, nil)
	ctx := context.Background()
	if err := m.Apply(ctx, []Rule{r12}); err != nil {
		t.Fatal(err)
	}
	f.nftInstalled = map[string]string{} // somebody flushed the firewall
	if err := m.Verify(ctx); err == nil {
		t.Fatal("Verify should notice the loss")
	}
	if err := m.Apply(ctx, []Rule{r12}); err != nil {
		t.Fatal(err)
	}
	if f.count("nft -f") != 2 || len(f.nftInstalled) != 2 {
		t.Fatalf("not reinstalled: %v %v", f.calls, f.nftInstalled)
	}
	f.nftInstalled = map[string]string{}
	if err := m.Heal(ctx); err != nil || len(f.nftInstalled) != 2 {
		t.Fatalf("Heal: %v %v", err, f.nftInstalled)
	}
	if err := m.Heal(ctx); err != nil || f.count("nft -f") != 3 {
		t.Fatalf("Heal on healthy system committed: %v", f.calls)
	}
}

func TestEmptyRulesDeleteTable(t *testing.T) {
	f := newFake()
	m := newMgr(t, f, nil)
	ctx := context.Background()
	if err := m.Apply(ctx, []Rule{r12}); err != nil {
		t.Fatal(err)
	}
	if err := m.Apply(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if len(f.nftInstalled) != 0 {
		t.Fatalf("tables remain: %v", f.nftInstalled)
	}
	b, _ := os.ReadFile(filepath.Join(m.dir(), "rules.nft"))
	if strings.Contains(string(b), "chain") || !strings.Contains(string(b), "delete table ip6 w1ncray_porthop") {
		t.Fatalf("clear file: %s", b)
	}
	if _, err := os.Stat(filepath.Join(m.dir(), "state.json")); !os.IsNotExist(err) {
		t.Fatalf("state.json remains: %v", err)
	}
	// a further empty apply does nothing
	n := len(f.calls)
	if err := m.Apply(ctx, nil); err != nil || len(f.calls) != n {
		t.Fatalf("empty re-apply ran commands: %v", f.calls[n:])
	}
}

func TestEmptyIptablesRemovesChain(t *testing.T) {
	f := newFake()
	f.nftCheckOK = false
	m := newMgr(t, f, nil)
	ctx := context.Background()
	if err := m.Apply(ctx, []Rule{r12}); err != nil {
		t.Fatal(err)
	}
	if err := m.Apply(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if len(f.chains) != 0 || f.jumps["iptables"] || f.jumps["ip6tables"] {
		t.Fatalf("leftovers: %v %v", f.chains, f.jumps)
	}
}

func TestFirstEmptyApplyCleansLeftovers(t *testing.T) {
	f := newFake()
	f.nftInstalled["ip"] = "old"
	m := newMgr(t, f, nil)
	if err := m.Apply(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if len(f.nftInstalled) != 0 {
		t.Fatalf("leftover table not removed: %v", f.nftInstalled)
	}
}

func TestProbeFallback(t *testing.T) {
	ctx := context.Background()
	// nft check fails -> iptables
	f := newFake()
	f.nftCheckOK = false
	m := newMgr(t, f, nil)
	if err := m.Probe(ctx); err != nil || m.Status().Backend != "iptables" {
		t.Fatalf("probe: %v %+v", err, m.Status())
	}
	// nft check passes but the real commit fails -> iptables
	f = newFake()
	f.nftCommitErr = true
	m = newMgr(t, f, nil)
	if err := m.Apply(ctx, []Rule{r12}); err != nil {
		t.Fatal(err)
	}
	if st := m.Status(); st.Backend != "iptables" || f.chains["iptables"] == "" {
		t.Fatalf("no fallback: %+v", st)
	}
	// neither -> unavailable
	f = newFake()
	f.nftCheckOK, f.hasIpt = false, false
	m = newMgr(t, f, nil)
	if err := m.Probe(ctx); !errors.Is(err, errNoBackend) {
		t.Fatalf("probe err = %v", err)
	}
	if m.Available() || m.Status().Available {
		t.Fatal("must be unavailable")
	}
	if err := m.Apply(ctx, []Rule{r12}); err == nil {
		t.Fatal("Apply without backend must fail")
	}
	if st := m.Status(); st.Rules[0].OK || st.LastError == "" {
		t.Fatalf("status %+v", st)
	}
	// forced backend does not fall back
	f = newFake()
	f.nftCheckOK = false
	m = newMgr(t, f, func(c *Config) { c.Backend = "nft" })
	if err := m.Probe(ctx); err == nil {
		t.Fatal("forced nft must not fall back")
	}
	f = newFake()
	m = newMgr(t, f, func(c *Config) { c.Backend = "iptables" })
	if err := m.Probe(ctx); err != nil || m.Status().Backend != "iptables" || f.count("nft") != 0 {
		t.Fatalf("forced iptables: %v %v", err, f.calls)
	}
}

func TestIPv6Degradation(t *testing.T) {
	f := newFake()
	f.nft6OK = false
	m := newMgr(t, f, nil)
	if err := m.Apply(context.Background(), []Rule{r12}); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.nftInstalled["ip"]; !ok || len(f.nftInstalled) != 1 {
		t.Fatalf("installed: %v", f.nftInstalled)
	}
	if st := m.Status(); st.Note == "" {
		t.Fatalf("no ipv6 note: %+v", st)
	}
	if err := m.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}

	f = newFake()
	f.nftCheckOK, f.hasIpt6 = false, false
	m = newMgr(t, f, nil)
	if err := m.Apply(context.Background(), []Rule{r12}); err != nil {
		t.Fatal(err)
	}
	if f.chains["iptables"] == "" || f.chains["ip6tables"] != "" || m.Status().Note == "" {
		t.Fatalf("ipt v4 only: %v %+v", f.chains, m.Status())
	}
}

func TestGates(t *testing.T) {
	cases := []struct {
		name string
		r    Rule
		mod  func(*Config)
		want string // "" = accepted, else substring of the reason
	}{
		{"ok", r12, nil, ""},
		{"low start", Rule{1, "udp", "1000-2000", 8443}, nil, "below 1024"},
		{"start 1024 ok", Rule{1, "udp", "1024-2000", 8443}, nil, ""},
		{"span too big", Rule{1, "udp", "2000-40000", 8443}, nil, "spans"},
		{"span 30001 ok", Rule{1, "udp", "2000-32000", 40000}, nil, ""},
		{"span custom limit", Rule{1, "udp", "2000-2100", 8443}, func(c *Config) { c.MaxSpan = 50 }, "spans"},
		{"port > 65535", Rule{1, "udp", "60000-70000", 8443}, nil, "out of range"},
		{"to zero", Rule{1, "udp", "20000-30000", 0}, nil, "target port"},
		{"to too big", Rule{1, "udp", "20000-30000", 65536}, nil, "target port"},
		{"to inside range", Rule{1, "udp", "20000-30000", 25000}, nil, "inside the hop range"},
		{"to at range edge", Rule{1, "udp", "20000-30000", 30000}, nil, "inside the hop range"},
		{"tcp rejected", Rule{1, "tcp", "20000-30000", 8443}, nil, "not allowed"},
		{"tcp allowed", Rule{1, "tcp", "20000-30000", 8443}, func(c *Config) { c.AllowTCP = true }, ""},
		{"other proto", Rule{1, "sctp", "20000-30000", 8443}, nil, "unsupported proto"},
		{"node id 0", Rule{0, "udp", "20000-30000", 8443}, nil, "node_id"},
		{"single port", Rule{1, "udp", "20000", 8443}, nil, "range"},
		{"reversed", Rule{1, "udp", "30000-20000", 8443}, nil, "start must be below"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := newMgr(t, newFake(), c.mod)
			_ = m.Apply(context.Background(), []Rule{c.r})
			st := m.Status().Rules
			if len(st) != 1 {
				t.Fatalf("statuses: %+v", st)
			}
			if c.want == "" {
				if !st[0].OK {
					t.Fatalf("rejected: %s", st[0].Reason)
				}
				return
			}
			if st[0].OK || !strings.Contains(st[0].Reason, c.want) {
				t.Fatalf("got ok=%v reason=%q, want %q", st[0].OK, st[0].Reason, c.want)
			}
		})
	}
}

func TestInjectionInPorts(t *testing.T) {
	bad := []string{
		"20000-30000;drop", "20000 -30000", "20000-30000 ", " 20000-30000", "20000-30000\n",
		"+20000-30000", "2e4-3e4", "20000-30000\"", "20000-30000 comment x", "020000-30000",
		"20000-30000-40000", "20000:30000", "", "-", "0x4e20-30000",
	}
	for _, p := range bad {
		f := newFake()
		m := newMgr(t, f, nil)
		_ = m.Apply(context.Background(), []Rule{{NodeID: 1, Proto: "udp", Ports: p, To: 8443}})
		if st := m.Status().Rules; len(st) != 1 || st[0].OK {
			t.Errorf("ports %q accepted: %+v", p, st)
		}
		if b, _ := os.ReadFile(filepath.Join(m.dir(), "rules.nft")); strings.Contains(string(b), "chain") || len(f.nftInstalled) != 0 {
			t.Errorf("ports %q reached the firewall", p)
		}
	}
	// the rendered comment is only the integer node id
	out := renderNft([]accepted{{Rule: Rule{NodeID: 7, Proto: "udp", Ports: "x", To: 1}, Lo: 2000, Hi: 3000}}, false)
	if !strings.Contains(out, `comment "w1ncray node 7"`) || strings.Count(out, "\"") != 2 {
		t.Fatalf("render: %s", out)
	}
}

func TestOverlapLowerNodeWins(t *testing.T) {
	f := newFake()
	m := newMgr(t, f, nil)
	rules := []Rule{
		{NodeID: 20, Proto: "udp", Ports: "25000-26000", To: 9000},
		{NodeID: 5, Proto: "udp", Ports: "20000-25500", To: 8000},
		{NodeID: 30, Proto: "udp", Ports: "40000-41000", To: 9001},
	}
	if err := m.Apply(context.Background(), rules); err != nil {
		t.Fatal(err)
	}
	st := m.Status().Rules
	if len(st) != 3 || st[0].NodeID != 5 || !st[0].OK || st[1].NodeID != 20 || st[1].OK || !st[2].OK {
		t.Fatalf("statuses: %+v", st)
	}
	if !strings.Contains(st[1].Reason, "node 5") {
		t.Fatalf("reason: %q", st[1].Reason)
	}
	body := f.nftInstalled["ip"]
	if strings.Contains(body, "node 20") || !strings.Contains(body, "node 5") || !strings.Contains(body, "node 30") {
		t.Fatalf("installed: %s", body)
	}
}

// ---- conflict checks ------------------------------------------------------

const procHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

func writeProc(t *testing.T, root, name string, lines ...string) {
	t.Helper()
	p := filepath.Join(root, "net", name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(procHeader+strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestProcConflict(t *testing.T) {
	root := t.TempDir()
	// 0x61A8 = 25000, 0x1F90 = 8080, 0x2243 = 8771
	writeProc(t, root, "udp",
		"   0: 00000000:61A8 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 11111 2 0000000000000000 0")
	writeProc(t, root, "udp6")
	writeProc(t, root, "tcp",
		"   0: 00000000:61A8 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22222 1 0000000000000000 100 0 0 10 0")
	writeProc(t, root, "tcp6")
	p := NewProcChecker(root, 1)
	p.ownInodes = func() map[uint64]bool { return nil }

	if err := p.Check("udp", 20000, 30000, 8443); err == nil || !strings.Contains(err.Error(), "25000") {
		t.Fatalf("udp conflict not found: %v", err)
	}
	if err := p.Check("udp", 20000, 24999, 8443); err != nil {
		t.Fatalf("outside the range: %v", err)
	}
	// the target port is never a conflict
	if err := p.Check("udp", 20000, 30000, 25000); err != nil {
		t.Fatalf("to excluded: %v", err)
	}
	// tcp is not looked at for udp rules and vice versa
	writeProc(t, root, "udp")
	if err := p.Check("udp", 20000, 30000, 8443); err != nil {
		t.Fatalf("tcp socket must not block udp: %v", err)
	}
	if err := p.Check("tcp", 20000, 30000, 8443); err == nil {
		t.Fatal("tcp listener must block tcp")
	}
	// an established tcp connection is not a listener
	writeProc(t, root, "tcp",
		"   0: 0100007F:61A8 0100007F:9999 01 00000000:00000000 00:00000000 00000000     0        0 33333 1 0000000000000000 100 0 0 10 0")
	if err := p.Check("tcp", 20000, 30000, 8443); err != nil {
		t.Fatalf("established: %v", err)
	}
}

func TestProcKernelSocketAndOwnProcess(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, "udp",
		"   0: 00000000:61A8 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 0 2 0000000000000000 0") // inode 0
	p := NewProcChecker(root, 1)
	p.ownInodes = func() map[uint64]bool { return map[uint64]bool{0: true} } // inode 0 can never be "own"
	if err := p.Check("udp", 20000, 30000, 8443); err == nil {
		t.Fatal("kernel socket (inode 0) must conflict")
	}
	writeProc(t, root, "udp",
		"   0: 00000000:61A8 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 555 2 0000000000000000 0")
	p.ownInodes = func() map[uint64]bool { return map[uint64]bool{555: true} }
	if err := p.Check("udp", 20000, 30000, 8443); err != nil {
		t.Fatalf("own socket must be ignored: %v", err)
	}
	p.ownInodes = func() map[uint64]bool { return map[uint64]bool{556: true} }
	if err := p.Check("udp", 20000, 30000, 8443); err == nil {
		t.Fatal("foreign socket must conflict")
	}
}

func TestProcOwnInodesFromFd(t *testing.T) {
	root := t.TempDir()
	fd := filepath.Join(root, "42", "fd")
	if err := os.MkdirAll(fd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[777]", filepath.Join(fd, "3")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	p := NewProcChecker(root, 42)
	if got := p.own(); !got[777] || len(got) != 1 {
		t.Fatalf("own = %v", got)
	}
	// unreadable fd directory: best effort, empty set
	if got := NewProcChecker(root, 43).own(); len(got) != 0 {
		t.Fatalf("own = %v", got)
	}
}

func TestProcMissingFilesAreSkipped(t *testing.T) {
	p := NewProcChecker(t.TempDir(), 1)
	if err := p.Check("udp", 20000, 30000, 8443); err != nil {
		t.Fatal(err)
	}
}

func TestManagerRejectsOnProcConflict(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, "udp",
		"   0: 00000000:61A8 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 11111 2 0000000000000000 0")
	f := newFake()
	m := newMgr(t, f, func(c *Config) { c.Checker = nil; c.ProcRoot = root; c.SelfPID = 1 })
	if err := m.Apply(context.Background(), []Rule{r12}); err != nil {
		t.Fatal(err)
	}
	st := m.Status().Rules
	if st[0].OK || !strings.Contains(st[0].Reason, "conflict") {
		t.Fatalf("status: %+v", st)
	}
	if len(f.nftInstalled) != 0 {
		t.Fatal("conflicting rule installed")
	}
}

func TestLedgerConflict(t *testing.T) {
	ports := map[int]bool{26000: true}
	f := newFake()
	m := newMgr(t, f, func(c *Config) {
		c.Checker = nil
		c.ProcRoot = t.TempDir()
		c.ForwardPorts = func() map[int]bool { return ports }
	})
	_ = m.Apply(context.Background(), []Rule{r12})
	st := m.Status().Rules
	if st[0].OK || !strings.Contains(st[0].Reason, "26000") {
		t.Fatalf("status: %+v", st)
	}
	// the forward goes away: the rejected rule is checked again and flips on
	delete(ports, 26000)
	if err := m.Apply(context.Background(), []Rule{r12}); err != nil {
		t.Fatal(err)
	}
	if !m.Status().Rules[0].OK {
		t.Fatalf("not recovered: %+v", m.Status())
	}
	// the forward comes back: the installed rule is not re-checked, no flip
	ports[26000] = true
	if err := m.Apply(context.Background(), []Rule{r12}); err != nil {
		t.Fatal(err)
	}
	if !m.Status().Rules[0].OK {
		t.Fatalf("accepted rule flipped: %+v", m.Status())
	}
	// ...but a changed rule is checked from scratch
	r := r12
	r.To = 8444
	_ = m.Apply(context.Background(), []Rule{r})
	if m.Status().Rules[0].OK {
		t.Fatal("changed rule skipped the conflict check")
	}
}

func TestLedgerCheckerExcludesTarget(t *testing.T) {
	c := NewLedgerChecker(func() map[int]bool { return map[int]bool{8443: true} })
	if err := c.Check("udp", 8000, 9000, 8443); err != nil {
		t.Fatal(err)
	}
	if err := c.Check("udp", 8000, 9000, 1); err == nil {
		t.Fatal("expected conflict")
	}
}

// ---- state and switches ---------------------------------------------------

func TestRestoreFromState(t *testing.T) {
	dir := t.TempDir()
	f1 := newFake()
	m1 := New(Config{Enabled: true, StateDir: dir, Exec: f1, Checker: okChecker{}})
	if err := m1.Apply(context.Background(), []Rule{r12}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "porthop", "state.json"))
	if err != nil || !strings.Contains(string(b), `"node_id": 12`) || !strings.Contains(string(b), `"nft"`) {
		t.Fatalf("state.json = %s, %v", b, err)
	}

	// "reboot": new process, empty firewall, a checker that would now refuse
	f2 := newFake()
	m2 := New(Config{Enabled: true, StateDir: dir, Exec: f2, Checker: failChecker{}})
	if err := m2.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f2.nftInstalled) != 2 || !m2.Status().Rules[0].OK {
		t.Fatalf("restore: %v %+v", f2.nftInstalled, m2.Status())
	}
	// no state file: Restore is a no-op
	m3 := New(Config{Enabled: true, StateDir: t.TempDir(), Exec: newFake(), Checker: okChecker{}})
	if err := m3.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
}

type failChecker struct{}

func (failChecker) Check(string, int, int, int) error { return errors.New("busy") }

func TestDisabledClears(t *testing.T) {
	dir := t.TempDir()
	f := newFake()
	m := New(Config{Enabled: true, StateDir: dir, Exec: f, Checker: okChecker{}})
	if err := m.Apply(context.Background(), []Rule{r12}); err != nil {
		t.Fatal(err)
	}
	// the operator turns the switch off; a fresh process starts disabled
	m2 := New(Config{Enabled: false, StateDir: dir, Exec: f, Checker: okChecker{}})
	if err := m2.Apply(context.Background(), []Rule{r12}); err != nil {
		t.Fatal(err)
	}
	if len(f.nftInstalled) != 0 {
		t.Fatalf("not cleared: %v", f.nftInstalled)
	}
	if st := m2.Status(); st.Enabled || st.Available || len(st.Rules) != 0 {
		t.Fatalf("status: %+v", st)
	}
	if _, err := os.Stat(filepath.Join(dir, "porthop", "state.json")); !os.IsNotExist(err) {
		t.Fatalf("state.json remains: %v", err)
	}
	if err := m2.Probe(context.Background()); err == nil {
		t.Fatal("disabled Probe must fail")
	}
}

func TestClear(t *testing.T) {
	f := newFake()
	m := newMgr(t, f, nil)
	ctx := context.Background()
	if err := m.Apply(ctx, []Rule{r12}); err != nil {
		t.Fatal(err)
	}
	if err := m.Clear(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.nftInstalled) != 0 || len(m.Status().Rules) != 0 {
		t.Fatalf("not cleared: %v", f.nftInstalled)
	}
}

func TestNoUserConfigTouched(t *testing.T) {
	f := newFake()
	m := newMgr(t, f, nil)
	_ = m.Apply(context.Background(), []Rule{r12})
	for _, c := range f.calls {
		for _, bad := range []string{"save", "OUTPUT", "flush", "nftables.conf"} {
			if strings.Contains(c, bad) {
				t.Errorf("command touches user config: %s", c)
			}
		}
	}
}

func TestParseResponse(t *testing.T) {
	r, err := ParseResponse([]byte(`{"version":"abc","rules":[{"node_id":12,"proto":"udp","ports":"20000-30000","to":8443}],"future":1}`))
	if err != nil || r.Version != "abc" || len(r.Rules) != 1 || r.Rules[0] != r12 {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = ParseResponse([]byte(`{"version":"x","rules":[]}`))
	if err != nil || len(r.Rules) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := ParseResponse([]byte(`{`)); err == nil {
		t.Fatal("want error")
	}
}
