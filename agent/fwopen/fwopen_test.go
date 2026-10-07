package fwopen

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/spec"
)

// fakeExec records every command and serves a canned "uci show firewall".
type fakeExec struct {
	show  string
	calls []string
	fail  map[string]error
	// failN fails the first N invocations of a command line; the following ones
	// succeed. It models a transient failure (a reload that times out once).
	failN map[string]int
}

func (f *fakeExec) Run(_ context.Context, name string, args ...string) (string, error) {
	line := name
	if len(args) > 0 {
		line += " " + strings.Join(args, " ")
	}
	f.calls = append(f.calls, line)
	if f.failN[line] > 0 {
		f.failN[line]--
		return "", errors.New("transient: " + line)
	}
	if err := f.fail[line]; err != nil {
		return "", err
	}
	if name == "uci" && len(args) == 2 && args[0] == "show" {
		return f.show, nil
	}
	return "", nil
}

func newManager(t *testing.T, show string) (*Manager, *fakeExec) {
	t.Helper()
	f := &fakeExec{show: show}
	m := New(Options{
		OpenWrt:  true,
		AutoOpen: true,
		Exec:     f,
		Reload:   []string{"fw4", "reload"},
	})
	return m, f
}

func fwd(id, addr, ports string, network ...string) spec.Instance {
	return spec.Instance{
		ID:      id,
		Name:    id,
		Enabled: true,
		Engine:  spec.EngineGost,
		Kind:    spec.KindForward,
		Listen:  &spec.Listen{Addr: addr, Ports: ports},
		Network: network,
		Targets: []spec.Target{{Host: "203.0.113.1", Ports: ports}},
	}
}

// TestSyncAddsRule pins the command sequence of a new rule: the section is
// created as a "rule", every field is set, then the configuration is committed
// and reloaded.
func TestSyncAddsRule(t *testing.T) {
	m, f := newManager(t, "")
	open, _, err := m.Sync(context.Background(), []spec.Instance{fwd("fwd1", "0.0.0.0", "8443")})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"uci show firewall",
		"uci set firewall.w1ncray_fwd1=rule",
		"uci set firewall.w1ncray_fwd1.name=W1nCray fwd1",
		"uci set firewall.w1ncray_fwd1.src=wan",
		"uci set firewall.w1ncray_fwd1.proto=tcp",
		"uci set firewall.w1ncray_fwd1.dest_port=8443",
		"uci set firewall.w1ncray_fwd1.target=ACCEPT",
		"uci commit firewall",
		"fw4 reload",
	}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls:\n got %v\nwant %v", f.calls, want)
	}
	if !open["fwd1"] {
		t.Fatalf("fwd1 not reported open: %v", open)
	}
}

// TestSyncUpdatesChangedField: an existing section is kept, only the field that
// differs is written, and the firewall is reloaded once.
func TestSyncUpdatesChangedField(t *testing.T) {
	show := "firewall.w1ncray_fwd1=rule\n" +
		"firewall.w1ncray_fwd1.name='W1nCray fwd1'\n" +
		"firewall.w1ncray_fwd1.src='wan'\n" +
		"firewall.w1ncray_fwd1.proto='tcp'\n" +
		"firewall.w1ncray_fwd1.dest_port='8443'\n" +
		"firewall.w1ncray_fwd1.target='ACCEPT'\n"
	m, f := newManager(t, show)
	open, _, err := m.Sync(context.Background(), []spec.Instance{fwd("fwd1", "0.0.0.0", "9443")})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"uci show firewall",
		"uci set firewall.w1ncray_fwd1.dest_port=9443",
		"uci commit firewall",
		"fw4 reload",
	}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls:\n got %v\nwant %v", f.calls, want)
	}
	if !open["fwd1"] {
		t.Fatalf("fwd1 not reported open: %v", open)
	}
}

// TestSyncUnchangedRunsNothing: a rule that already matches costs one read and
// no commit/reload at all.
func TestSyncUnchangedRunsNothing(t *testing.T) {
	show := "firewall.w1ncray_fwd1=rule\n" +
		"firewall.w1ncray_fwd1.name='W1nCray fwd1'\n" +
		"firewall.w1ncray_fwd1.src='wan'\n" +
		"firewall.w1ncray_fwd1.proto='tcp'\n" +
		"firewall.w1ncray_fwd1.dest_port='8443'\n" +
		"firewall.w1ncray_fwd1.target='ACCEPT'\n"
	m, f := newManager(t, show)
	open, _, err := m.Sync(context.Background(), []spec.Instance{fwd("fwd1", "0.0.0.0", "8443")})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.calls, []string{"uci show firewall"}) {
		t.Fatalf("calls = %v, want just the read", f.calls)
	}
	if !open["fwd1"] {
		t.Fatalf("fwd1 not reported open: %v", open)
	}
}

// TestSyncDeletesStaleRule: a w1ncray_* section no instance claims is removed,
// and nothing else in the firewall is touched.
func TestSyncDeletesStaleRule(t *testing.T) {
	show := "firewall.@defaults[0]=defaults\n" +
		"firewall.@defaults[0].input='REJECT'\n" +
		"firewall.w1ncray_old=rule\n" +
		"firewall.w1ncray_old.name='W1nCray old'\n" +
		"firewall.w1ncray_old.src='wan'\n" +
		"firewall.user_rule=rule\n" +
		"firewall.user_rule.name='keep me'\n"
	m, f := newManager(t, show)
	open, _, err := m.Sync(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"uci show firewall",
		"uci delete firewall.w1ncray_old",
		"uci commit firewall",
		"fw4 reload",
	}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls:\n got %v\nwant %v", f.calls, want)
	}
	if len(open) != 0 {
		t.Fatalf("open = %v, want empty", open)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "user_rule") {
			t.Fatalf("the user's rule was touched: %v", f.calls)
		}
	}
}

// TestSyncReconcilesAtStartup: matching sections are left alone and stale ones
// removed in one pass.
func TestSyncReconcilesAtStartup(t *testing.T) {
	show := "firewall.w1ncray_keep=rule\n" +
		"firewall.w1ncray_keep.name='W1nCray keep'\n" +
		"firewall.w1ncray_keep.src='wan'\n" +
		"firewall.w1ncray_keep.proto='tcp'\n" +
		"firewall.w1ncray_keep.dest_port='20000-20009'\n" +
		"firewall.w1ncray_keep.target='ACCEPT'\n" +
		"firewall.w1ncray_gone=rule\n" +
		"firewall.w1ncray_gone.name='W1nCray gone'\n"
	m, f := newManager(t, show)
	in := fwd("keep", "0.0.0.0", "20000-20009")
	open, _, err := m.Sync(context.Background(), []spec.Instance{in})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"uci show firewall",
		"uci delete firewall.w1ncray_gone",
		"uci commit firewall",
		"fw4 reload",
	}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls:\n got %v\nwant %v", f.calls, want)
	}
	if !open["keep"] {
		t.Fatalf("keep not reported open: %v", open)
	}
}

// TestSyncRangeAndBothProtocols: a port range is written as "lo-hi" and a
// tcp+udp instance as "tcp udp" on one rule.
func TestSyncRangeAndBothProtocols(t *testing.T) {
	m, f := newManager(t, "")
	_, _, err := m.Sync(context.Background(), []spec.Instance{
		fwd("range", "0.0.0.0", "20000-20009"),
		fwd("both", "0.0.0.0", "8443", "tcp", "udp"),
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(f.calls, "\n")
	for _, want := range []string{
		"uci set firewall.w1ncray_range.dest_port=20000-20009",
		"uci set firewall.w1ncray_both.proto=tcp udp",
		"uci set firewall.w1ncray_both.dest_port=8443",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
	}
}

// TestLoopbackIsNeverOpened: loopback-only listeners, disabled instances and
// instances without a local listener produce no rule and no command at all.
func TestLoopbackIsNeverOpened(t *testing.T) {
	off := fwd("off", "0.0.0.0", "9000")
	off.Enabled = false
	v6loop := fwd("v6", "::1", "9001")
	v4loop := fwd("v4", "127.0.0.5", "9002")
	bridge := spec.Instance{
		ID: "bridge", Enabled: true, Engine: spec.EngineFrp, Kind: spec.KindReverseBridge,
		Listen: &spec.Listen{Ports: "9003"},
	}
	m, f := newManager(t, "")
	open, _, err := m.Sync(context.Background(), []spec.Instance{off, v6loop, v4loop, bridge})
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 0 {
		t.Fatalf("open = %v, want none", open)
	}
	if !reflect.DeepEqual(f.calls, []string{"uci show firewall"}) {
		t.Fatalf("calls = %v, want just the read", f.calls)
	}
}

// TestTunnelExitOpensTunnelListen: a tunnel exit has no Listen; its public port
// is the tunnel's listen address.
func TestTunnelExitOpensTunnelListen(t *testing.T) {
	in := spec.Instance{
		ID: "exit", Name: "exit", Enabled: true, Engine: spec.EngineRealm,
		Kind:   spec.KindTunnelExit,
		Tunnel: &spec.Tunnel{Type: "tls", Listen: "0.0.0.0:9443"},
	}
	m, f := newManager(t, "")
	open, _, err := m.Sync(context.Background(), []spec.Instance{in})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(f.calls, "\n")
	if !strings.Contains(joined, "uci set firewall.w1ncray_exit.dest_port=9443") {
		t.Fatalf("tunnel exit port not opened:\n%s", joined)
	}
	if !open["exit"] {
		t.Fatalf("exit not reported open: %v", open)
	}

	// A loopback tunnel listen is never opened.
	loop := in
	loop.ID, loop.Name = "loopexit", "loopexit"
	loop.Tunnel = &spec.Tunnel{Type: "tls", Listen: "127.0.0.1:9444"}
	m2, f2 := newManager(t, "")
	if _, _, err := m2.Sync(context.Background(), []spec.Instance{loop}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f2.calls, []string{"uci show firewall"}) {
		t.Fatalf("loopback tunnel listen was opened: %v", f2.calls)
	}
}

// TestDisabledOrNotOpenWrtDoesNothing: the local switch and the platform gate
// are both hard gates.
func TestDisabledOrNotOpenWrtDoesNothing(t *testing.T) {
	for _, o := range []Options{
		{OpenWrt: false, AutoOpen: true, Exec: &fakeExec{}},
		{OpenWrt: true, AutoOpen: false, Exec: &fakeExec{}},
	} {
		m := New(o)
		if m.Enabled() {
			t.Fatalf("Enabled() = true for %+v", o)
		}
		open, _, err := m.Sync(context.Background(), []spec.Instance{fwd("fwd1", "0.0.0.0", "8443")})
		if err != nil {
			t.Fatal(err)
		}
		if len(open) != 0 {
			t.Fatalf("open = %v, want none", open)
		}
		if len(o.Exec.(*fakeExec).calls) != 0 {
			t.Fatalf("commands ran on a disabled manager: %v", o.Exec.(*fakeExec).calls)
		}
	}
}

// TestWrongSectionTypeIsRecreated: a w1ncray_* section that is not a rule
// cannot be updated in place, so it is deleted and recreated.
func TestWrongSectionTypeIsRecreated(t *testing.T) {
	show := "firewall.w1ncray_fwd1=zone\nfirewall.w1ncray_fwd1.name='W1nCray fwd1'\n"
	m, f := newManager(t, show)
	if _, _, err := m.Sync(context.Background(), []spec.Instance{fwd("fwd1", "0.0.0.0", "8443")}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"uci show firewall",
		"uci delete firewall.w1ncray_fwd1",
		"uci set firewall.w1ncray_fwd1=rule",
		"uci set firewall.w1ncray_fwd1.name=W1nCray fwd1",
		"uci set firewall.w1ncray_fwd1.src=wan",
		"uci set firewall.w1ncray_fwd1.proto=tcp",
		"uci set firewall.w1ncray_fwd1.dest_port=8443",
		"uci set firewall.w1ncray_fwd1.target=ACCEPT",
		"uci commit firewall",
		"fw4 reload",
	}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls:\n got %v\nwant %v", f.calls, want)
	}
}

// TestCommandFailureStopsTheSync: a failing command is reported, not swallowed.
func TestCommandFailureStopsTheSync(t *testing.T) {
	m, f := newManager(t, "")
	f.fail = map[string]error{"uci commit firewall": errors.New("boom")}
	open, _, err := m.Sync(context.Background(), []spec.Instance{fwd("fwd1", "0.0.0.0", "8443")})
	if err == nil {
		t.Fatal("Sync succeeded despite a failing commit")
	}
	if open != nil {
		t.Fatalf("open = %v, want nil on error", open)
	}
}

// countCalls counts how often a command line was executed.
func countCalls(calls []string, line string) int {
	n := 0
	for _, c := range calls {
		if c == line {
			n++
		}
	}
	return n
}

// captureLog records the warning lines the manager emits.
type captureLog struct{ warns []string }

func (*captureLog) Debugf(string, ...any) {}
func (*captureLog) Infof(string, ...any)  {}
func (l *captureLog) Warnf(format string, args ...any) {
	l.warns = append(l.warns, fmt.Sprintf(format, args...))
}
func (*captureLog) Errorf(string, ...any) {}

// TestReloadTransientFailureIsRetried: a reload that fails once is retried and
// the apply succeeds, so a single fw4 hiccup does not leave the ports closed
// until the next apply.
func TestReloadTransientFailureIsRetried(t *testing.T) {
	m, f := newManager(t, "")
	f.failN = map[string]int{"fw4 reload": 1}
	m.reloadWait = time.Millisecond
	m.reloadCap = time.Second

	open, skipped, err := m.Sync(context.Background(), []spec.Instance{fwd("fwd1", "0.0.0.0", "8443")})
	if err != nil {
		t.Fatalf("Sync after a transient reload failure: %v", err)
	}
	if !open["fwd1"] {
		t.Fatalf("fwd1 not reported open after a successful retry: %v", open)
	}
	if len(skipped) != 0 {
		t.Fatalf("skipped = %v, want none", skipped)
	}
	if got := countCalls(f.calls, "fw4 reload"); got != 2 {
		t.Fatalf("reload ran %d time(s), want 2 (one failure + one retry): %v", got, f.calls)
	}
}

// TestReloadFailureIsReportedAsPersisted: when every reload attempt fails the
// rules are already committed, and Sync says so with a *ReloadError instead of
// a generic failure. The open map is unusable, so the caller reports the ports
// closed.
func TestReloadFailureIsReportedAsPersisted(t *testing.T) {
	m, f := newManager(t, "")
	f.fail = map[string]error{"fw4 reload": errors.New("timeout")}
	m.reloadWait = time.Millisecond
	m.reloadCap = time.Second

	open, _, err := m.Sync(context.Background(), []spec.Instance{fwd("fwd1", "0.0.0.0", "8443")})
	if err == nil {
		t.Fatal("Sync succeeded despite a permanently failing reload")
	}
	var re *ReloadError
	if !errors.As(err, &re) {
		t.Fatalf("err = %T (%v), want *ReloadError", err, err)
	}
	if !re.RulesPersisted() {
		t.Fatal("ReloadError does not report the rules as persisted")
	}
	if re.Attempts != 3 {
		t.Fatalf("attempts = %d, want 3", re.Attempts)
	}
	if open != nil {
		t.Fatalf("open = %v, want nil: the ports are not open", open)
	}
	if got := countCalls(f.calls, "uci commit firewall"); got != 1 {
		t.Fatalf("commit ran %d time(s), want 1", got)
	}
	if got := countCalls(f.calls, "fw4 reload"); got != 3 {
		t.Fatalf("reload ran %d time(s), want 3: %v", got, f.calls)
	}
}

// TestReloadBudgetBoundsTheRetries: the whole retry loop is capped, so a hung
// reload cannot hold the apply for the sum of every attempt.
func TestReloadBudgetBoundsTheRetries(t *testing.T) {
	m, f := newManager(t, "")
	f.fail = map[string]error{"fw4 reload": errors.New("timeout")}
	m.reloadTries = 1000
	m.reloadWait = time.Hour
	m.reloadCap = 20 * time.Millisecond

	start := time.Now()
	_, _, err := m.Sync(context.Background(), []spec.Instance{fwd("fwd1", "0.0.0.0", "8443")})
	if err == nil {
		t.Fatal("Sync succeeded despite a permanently failing reload")
	}
	var re *ReloadError
	if !errors.As(err, &re) {
		t.Fatalf("err = %T (%v), want *ReloadError", err, err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("reload loop ran for %s, want it bounded by the budget", elapsed)
	}
	if got := countCalls(f.calls, "fw4 reload"); got > 2 {
		t.Fatalf("reload ran %d time(s): the budget must stop the retries", got)
	}
}

// TestUnparseablePortsAreReportedNotSilentlyDropped: an instance whose port
// declaration does not parse gets no rule, and Sync returns why instead of
// dropping it without a trace.
func TestUnparseablePortsAreReportedNotSilentlyDropped(t *testing.T) {
	log := &captureLog{}
	f := &fakeExec{}
	m := New(Options{
		OpenWrt:  true,
		AutoOpen: true,
		Exec:     f,
		Reload:   []string{"fw4", "reload"},
		Log:      log,
	})

	open, skipped, err := m.Sync(context.Background(), []spec.Instance{fwd("bad", "0.0.0.0", "0")})
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 0 {
		t.Fatalf("open = %v, want none: no rule can be derived", open)
	}
	reason, ok := skipped["bad"]
	if !ok {
		t.Fatalf("skipped = %v, want an entry for bad", skipped)
	}
	if !strings.Contains(reason, `listen ports "0"`) {
		t.Fatalf("reason = %q, want it to name the port declaration", reason)
	}
	if len(log.warns) == 0 || !strings.Contains(strings.Join(log.warns, "\n"), "bad") {
		t.Fatalf("warnings = %v, want one naming the instance", log.warns)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "w1ncray_bad") {
			t.Fatalf("a rule was written for an unparseable port: %v", f.calls)
		}
	}
}

func TestSectionIDIsInjective(t *testing.T) {
	ids := []string{"a", "a-b", "a_b", "a__b", "a--b", "a-_b", "fwd1", "x_d", "x-d", "x__d"}
	seen := map[string]string{}
	for _, id := range ids {
		s := sectionID(id)
		if !isUCIName(s) {
			t.Errorf("sectionID(%q) = %q is not a valid UCI name", id, s)
		}
		if prev, dup := seen[s]; dup {
			t.Errorf("sectionID collision: %q and %q both map to %q", prev, id, s)
		}
		seen[s] = id
	}
	if got := sectionID("fwd-1"); got != "fwd_d1" {
		t.Errorf("sectionID(\"fwd-1\") = %q, want fwd_d1", got)
	}
	if got := sectionID("fwd_1"); got != "fwd__1" {
		t.Errorf("sectionID(\"fwd_1\") = %q, want fwd__1", got)
	}
}

func isUCIName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' {
			continue
		}
		return false
	}
	return true
}

func TestParseShowKeepsOnlyAgentSections(t *testing.T) {
	out := "firewall.@defaults[0]=defaults\n" +
		"firewall.@defaults[0].input='REJECT'\n" +
		"firewall.w1ncray_a=rule\n" +
		"firewall.w1ncray_a.dest_port='80 443'\n" +
		"firewall.user=rule\n"
	got := parseShow(out)
	if len(got) != 1 {
		t.Fatalf("parseShow kept %d sections: %v", len(got), got)
	}
	if got["w1ncray_a"]["__type"] != "rule" || got["w1ncray_a"]["dest_port"] != "80 443" {
		t.Fatalf("parseShow = %v", got)
	}
}

func TestResolveReload(t *testing.T) {
	if got := resolveReload(true, true); !reflect.DeepEqual(got, []string{"fw4", "reload"}) {
		t.Errorf("fw4 present: %v", got)
	}
	if got := resolveReload(false, true); !reflect.DeepEqual(got, []string{"/etc/init.d/firewall", "reload"}) {
		t.Errorf("fw3 only: %v", got)
	}
	if got := resolveReload(false, false); got != nil {
		t.Errorf("neither present: %v", got)
	}
}

// TestNoReloadCommandFailsReadably: a machine with neither fw4 nor the fw3
// init script reports why instead of silently committing nothing.
func TestNoReloadCommandFailsReadably(t *testing.T) {
	f := &fakeExec{}
	m := New(Options{OpenWrt: true, AutoOpen: true, Exec: f, Reload: nil})
	m.reload = nil
	_, _, err := m.Sync(context.Background(), []spec.Instance{fwd("fwd1", "0.0.0.0", "8443")})
	if err == nil || !strings.Contains(err.Error(), "reload") {
		t.Fatalf("err = %v", err)
	}
}
