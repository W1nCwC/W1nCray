package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/portledger"
	"github.com/W1nCwC/W1nCray/agent/reconcile/internal/testdriver"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/agent/state"
	"github.com/W1nCwC/W1nCray/agent/validate"
)

const secretA = "SECRET-AAAAAAAAAAAAAAAA-1"
const secretB = "SECRET-BBBBBBBBBBBBBBBB-2"

// ---- fakes ---------------------------------------------------------------

type testLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *testLog) add(level, f string, a ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, level+" "+fmt.Sprintf(f, a...))
	l.mu.Unlock()
}
func (l *testLog) Debugf(f string, a ...any) { l.add("D", f, a...) }
func (l *testLog) Infof(f string, a ...any)  { l.add("I", f, a...) }
func (l *testLog) Warnf(f string, a ...any)  { l.add("W", f, a...) }
func (l *testLog) Errorf(f string, a ...any) { l.add("E", f, a...) }
func (l *testLog) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

type fakeKernels struct {
	mu        sync.Mutex
	unavail   map[string]string // name -> reason
	installed map[string]bool
	ensureErr map[string]error
	ensured   []spec.KernelPin
}

func (k *fakeKernels) Ensure(ctx context.Context, pin spec.KernelPin) (driver.Installed, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.ensured = append(k.ensured, pin)
	if err := k.ensureErr[pin.Name]; err != nil {
		return driver.Installed{}, err
	}
	v := pin.Version
	if v == "" {
		v = "default"
	}
	return driver.Installed{Path: "/opt/kernels/" + pin.Name + "/" + v + "/" + pin.Name, Version: v}, nil
}

func (k *fakeKernels) Available(name string) (bool, string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if why, bad := k.unavail[name]; bad {
		return false, why
	}
	return true, ""
}

func (k *fakeKernels) Installed(name string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.installed[name]
}

func (k *fakeKernels) pins() []spec.KernelPin {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]spec.KernelPin(nil), k.ensured...)
}

type noDNS struct{}

func (noDNS) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return nil, errors.New("no dns in tests")
}

// ---- environment ---------------------------------------------------------

type env struct {
	t     *testing.T
	r     *Reconciler
	xray  *testdriver.Fake
	gost  *testdriver.Fake
	realm *testdriver.Fake
	k     *fakeKernels
	st    *state.Store
	ports *portledger.Ledger
	log   *testLog
}

func xrayCaps() driver.Caps {
	c := testdriver.FullCaps()
	c.TunnelTypes = []string{"tcp", "ws", "tls", "wss", "grpc", "xhttp"}
	c.Stats = "counters"
	return c
}

func gostCaps() driver.Caps {
	c := testdriver.FullCaps()
	c.External = true
	c.InstalledSize = 50 << 20
	c.Stats = "prometheus"
	c.Balance = []string{"round_robin", "random", "iphash", "failover"}
	return c
}

func realmCaps() driver.Caps {
	return driver.Caps{
		Kinds:   []spec.Kind{spec.KindForward, spec.KindTunnelEntry, spec.KindTunnelExit},
		Network: []string{"tcp", "udp"}, TunnelTypes: []string{"ws", "tls", "wss"},
		ProxyIn: true, ProxyOut: true, Balance: []string{"round_robin"}, HealthCheck: "none",
		Stats: "none", Reload: "none", DisruptsOnChange: true, External: true, InstalledSize: 5 << 20,
	}
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, st: st, ports: portledger.New(), log: &testLog{}, k: &fakeKernels{unavail: map[string]string{}, installed: map[string]bool{}, ensureErr: map[string]error{}}}
	e.xray = testdriver.New("xray", xrayCaps())
	e.gost = testdriver.New("gost", gostCaps())
	e.realm = testdriver.New("realm", realmCaps())
	t.Cleanup(func() { e.xray.Close(); e.gost.Close(); e.realm.Close() })
	e.r = e.newReconciler()
	return e
}

func (e *env) newReconciler() *Reconciler {
	return &Reconciler{
		Drivers:         map[string]driver.Driver{"xray": e.xray, "gost": e.gost, "realm": e.realm},
		Kernels:         e.k,
		Policy:          spec.Policy{AllowListen: []string{"127.0.0.1"}, PortRange: [2]int{1024, 65535}},
		State:           e.st,
		Ports:           e.ports,
		Log:             e.log,
		ValidateOpts:    validate.Options{Resolver: noDNS{}},
		HealthWindow:    300 * time.Millisecond,
		HealthInterval:  10 * time.Millisecond,
		RollbackTimeout: 5 * time.Second,
	}
}

func port(t *testing.T) string { return strconv.Itoa(testdriver.FreePort(t)) }

func fwd(t *testing.T, id, engine string) spec.Instance {
	return spec.Instance{
		ID: id, Enabled: true, Engine: engine, Kind: spec.KindForward,
		Listen:  &spec.Listen{Addr: "127.0.0.1", Ports: port(t)},
		Targets: []spec.Target{{Host: "198.51.100.10", Ports: "443"}},
	}
}

func entry(t *testing.T, id, engine, secret string) spec.Instance {
	return spec.Instance{
		ID: id, Enabled: true, Engine: engine, Kind: spec.KindTunnelEntry,
		Listen: &spec.Listen{Addr: "127.0.0.1", Ports: port(t)},
		Tunnel: &spec.Tunnel{Type: "ws", Server: "198.51.100.20:443", Security: "tls"},
		Secret: secret,
	}
}

func desired(rev int64, ins ...spec.Instance) spec.Desired {
	return spec.Desired{Version: spec.Version, Revision: rev, Instances: ins}
}

func (e *env) apply(d spec.Desired) (Report, error) {
	e.t.Helper()
	return e.r.Apply(context.Background(), d)
}

func (e *env) mustApply(d spec.Desired) Report {
	e.t.Helper()
	rep, err := e.apply(d)
	if err != nil || rep.Status != StatusApplied {
		e.t.Fatalf("apply: status=%s err=%v\nreport=%s", rep.Status, err, dumpReport(rep))
	}
	return rep
}

func dumpReport(r Report) string {
	b, _ := json.MarshalIndent(r, "", " ")
	return string(b)
}

func inst(r Report, id string) InstanceReport {
	for _, i := range r.Instances {
		if i.ID == id {
			return i
		}
	}
	return InstanceReport{}
}

func eq(t *testing.T, what string, got, want []string) {
	t.Helper()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%s = %v, want %v", what, got, want)
	}
}

// ---- engine selection ----------------------------------------------------

func TestAutoPrefersBuiltinEngine(t *testing.T) {
	e := newEnv(t)
	rep := e.mustApply(desired(1, fwd(t, "a", "auto")))
	ir := inst(rep, "a")
	if ir.Engine != "xray" || ir.State != StateRunning || ir.Requested != "auto" || ir.ConfigHash == "" {
		t.Fatalf("%+v", ir)
	}
	if rep.Kernels["xray"] != BuiltinVersion || len(rep.Kernels) != 1 {
		t.Fatalf("kernels %v", rep.Kernels)
	}
	if pins := e.k.pins(); len(pins) != 0 {
		t.Fatalf("builtin engine must not trigger a kernel install: %v", pins)
	}
	eq(t, "xray running", e.xray.Running(), []string{"a"})
	eq(t, "gost running", e.gost.Running(), nil)
	if len(ir.Ports) != 1 || !strings.HasPrefix(ir.Ports[0], "tcp 127.0.0.1:") {
		t.Fatalf("ports %v", ir.Ports)
	}
}

func TestAutoFallsBackWithExplainedReasons(t *testing.T) {
	e := newEnv(t)
	e.xray.CapsV.ProxyIn = false // xray cannot accept PROXY here
	e.realm.CapsV.ProxyIn = false
	in := fwd(t, "a", "auto")
	in.AcceptProxyProtocol = true
	d := desired(1, in)
	d.Kernels = []spec.KernelPin{{Name: "gost", Version: "3.3.0"}}
	rep := e.mustApply(d)
	ir := inst(rep, "a")
	if ir.Engine != "gost" {
		t.Fatalf("selected %q: %+v", ir.Engine, ir)
	}
	if why := ir.Considered["xray"]; !strings.Contains(why, "accepting PROXY protocol is not supported") {
		t.Fatalf("considered = %v", ir.Considered)
	}
	if rep.Kernels["gost"] != "3.3.0" {
		t.Fatalf("kernels %v", rep.Kernels)
	}
	pins := e.k.pins()
	if len(pins) != 1 || pins[0] != (spec.KernelPin{Name: "gost", Version: "3.3.0"}) {
		t.Fatalf("ensure calls: %v", pins)
	}
	eq(t, "gost running", e.gost.Running(), []string{"a"})
}

func TestAutoRefusesInsteadOfDegrading(t *testing.T) {
	e := newEnv(t)
	// Only realm is available; it cannot do reverse proxying.
	e.r.Drivers = map[string]driver.Driver{"realm": e.realm}
	in := spec.Instance{
		ID: "rp", Enabled: true, Engine: "auto", Kind: spec.KindReversePortal,
		Listen: &spec.Listen{Addr: "127.0.0.1", Ports: port(t)},
		Tunnel: &spec.Tunnel{Type: "ws", Listen: "127.0.0.1:" + port(t), Security: "tls"},
		Secret: secretA,
	}
	rep, err := e.apply(desired(1, in))
	if !errors.Is(err, ErrRejected) || rep.Status != StatusRejected {
		t.Fatalf("status %s err %v", rep.Status, err)
	}
	ir := inst(rep, "rp")
	if ir.State != StateRejected || !strings.Contains(ir.Error, "no engine can run this instance") || !strings.Contains(ir.Error, "realm: kind \"reverse_portal\" is not supported") {
		t.Fatalf("%+v", ir)
	}
	if n := e.realm.CountCalls("apply"); n != 0 {
		t.Fatalf("driver touched: %v", e.realm.Calls())
	}
	if len(e.k.pins()) != 0 {
		t.Fatal("kernel installed for a rejected desired state")
	}
}

func TestExplicitEngineCapabilityRefusals(t *testing.T) {
	realmFwd := func(t *testing.T) spec.Instance { return fwd(t, "x", "realm") }
	cases := []struct {
		name string
		mk   func(t *testing.T) spec.Instance
		pre  func(e *env)
		want string
	}{
		{"reverse", func(t *testing.T) spec.Instance {
			return spec.Instance{ID: "x", Enabled: true, Engine: "realm", Kind: spec.KindReverseBridge,
				Listen:  &spec.Listen{Ports: "9100"},
				Tunnel:  &spec.Tunnel{Type: "ws", Server: "198.51.100.1:443", Security: "tls"},
				Targets: []spec.Target{{Host: "198.51.100.2", Ports: "22"}}, Secret: secretA}
		}, nil, "kind \"reverse_bridge\" is not supported"},
		{"health check", func(t *testing.T) spec.Instance {
			in := realmFwd(t)
			in.Targets = append(in.Targets, spec.Target{Host: "198.51.100.11", Ports: "443"})
			in.Balance = &spec.Balance{Strategy: "round_robin", Health: &spec.Health{Type: "tcp"}}
			return in
		}, nil, "health checks are not supported"},
		{"strategy", func(t *testing.T) spec.Instance {
			in := realmFwd(t)
			in.Balance = &spec.Balance{Strategy: "failover"}
			return in
		}, nil, "balance strategy \"failover\" is not supported"},
		{"metering", realmFwd, func(e *env) { e.r.RequireStats = true }, "traffic counters are not supported"},
		{"tunnel type", func(t *testing.T) spec.Instance {
			in := entry(t, "x", "realm", secretA)
			in.Tunnel.Type = "grpc"
			return in
		}, nil, "tunnel type \"grpc\" is not supported"},
		{"vless_enc on gost", func(t *testing.T) spec.Instance {
			in := entry(t, "x", "gost", secretA)
			in.Tunnel.Security = "vless_enc"
			return in
		}, nil, "only supported by the xray engine"}, // caught by validation before engines are considered
		{"unknown driver", func(t *testing.T) spec.Instance { return fwd(t, "x", "frp") }, nil, "no driver for this engine"},
		{"proxy out unsupported", func(t *testing.T) spec.Instance {
			in := realmFwd(t)
			in.ProxyProtocolOut = 2
			return in
		}, func(e *env) { e.realm.CapsV.ProxyOut = false }, "sending PROXY protocol is not supported"},
		{"udp unsupported", func(t *testing.T) spec.Instance {
			in := realmFwd(t)
			in.Network = []string{"tcp", "udp"}
			return in
		}, func(e *env) { e.realm.CapsV.Network = []string{"tcp"} }, "network \"udp\" is not supported"},
		{"driver validate", realmFwd, func(e *env) {
			e.realm.ValidateErr = func(spec.Instance) error { return errors.New("realm cannot express this") }
		}, "driver validation: realm cannot express this"},
		{"kernel unavailable", realmFwd, func(e *env) { e.k.unavail["realm"] = "no build for linux/mipsle" }, "no build for linux/mipsle"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			if c.pre != nil {
				c.pre(e)
			}
			rep, err := e.apply(desired(1, c.mk(t)))
			if rep.Status != StatusRejected || !errors.Is(err, ErrRejected) {
				t.Fatalf("status %s err %v\n%s", rep.Status, err, dumpReport(rep))
			}
			msgs := []string{rep.Message}
			for _, ir := range rep.Instances {
				msgs = append(msgs, ir.Error)
			}
			for _, v := range rep.ValidationErrors {
				msgs = append(msgs, v.Message)
			}
			if !strings.Contains(strings.Join(msgs, " | "), c.want) {
				t.Fatalf("want %q in %v", c.want, msgs)
			}
			if e.realm.CountCalls("apply") != 0 {
				t.Fatal("driver touched")
			}
		})
	}
}

func TestVlessEncAutoSelectsOnlyXray(t *testing.T) {
	e := newEnv(t)
	in := entry(t, "v", "auto", secretA)
	in.Tunnel.Type = "tcp"
	in.Tunnel.Security = "vless_enc"
	rep := e.mustApply(desired(1, in))
	if got := inst(rep, "v"); got.Engine != "xray" {
		t.Fatalf("%+v", got)
	}
	// without xray there is no engine, and the reason says why
	e2 := newEnv(t)
	e2.r.Drivers = map[string]driver.Driver{"gost": e2.gost}
	rep, err := e2.apply(desired(1, in))
	if !errors.Is(err, ErrRejected) || !strings.Contains(inst(rep, "v").Error, "gost: vless_enc security requires the xray engine") {
		t.Fatalf("%v\n%s", err, dumpReport(rep))
	}
}

func TestPolicyAllowEnginesConstrainsAuto(t *testing.T) {
	e := newEnv(t)
	e.r.Policy.AllowEngines = []string{"gost"}
	rep := e.mustApply(desired(1, fwd(t, "a", "auto")))
	ir := inst(rep, "a")
	if ir.Engine != "gost" || ir.Considered["xray"] != "not allowed by the local policy" {
		t.Fatalf("%+v", ir)
	}
	// explicit xray is refused by validation
	e2 := newEnv(t)
	e2.r.Policy.AllowEngines = []string{"gost"}
	rep, err := e2.apply(desired(1, fwd(t, "a", "xray")))
	if !errors.Is(err, ErrRejected) || len(rep.ValidationErrors) == 0 {
		t.Fatalf("%v %s", err, dumpReport(rep))
	}
}

func TestKernelAvailabilityAndSpaceInSelection(t *testing.T) {
	e := newEnv(t)
	// xray cannot do this (no PROXY in), gost kernel has no build, realm kernel unavailable too
	e.xray.CapsV.ProxyIn = false
	e.k.unavail["gost"] = "no linux/mipsle build in the manifest"
	e.realm.CapsV.ProxyIn = false
	in := fwd(t, "a", "auto")
	in.AcceptProxyProtocol = true
	rep, err := e.apply(desired(1, in))
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("%v", err)
	}
	if msg := inst(rep, "a").Error; !strings.Contains(msg, "gost: no linux/mipsle build in the manifest") {
		t.Fatalf("%s", msg)
	}

	// space: gost needs 50 MiB
	e = newEnv(t)
	e.xray.CapsV.ProxyIn = false
	e.realm.CapsV.ProxyIn = false
	e.r.FreeSpace = func() (int64, error) { return 10 << 20, nil }
	rep, err = e.apply(desired(1, in))
	if !errors.Is(err, ErrRejected) || !strings.Contains(inst(rep, "a").Error, "gost: not enough free disk space (50 MiB needed, 10 MiB free)") {
		t.Fatalf("%v\n%s", err, dumpReport(rep))
	}
	// already installed: the space check does not apply
	e.k.installed["gost"] = true
	in2 := in
	in2.Listen = &spec.Listen{Addr: "127.0.0.1", Ports: port(t)}
	if rep, err = e.apply(desired(2, in2)); err != nil || inst(rep, "a").Engine != "gost" {
		t.Fatalf("%v\n%s", err, dumpReport(rep))
	}
	// unknown free space is an explicit refusal, not a guess
	e = newEnv(t)
	e.xray.CapsV.ProxyIn = false
	e.realm.CapsV.ProxyIn = false
	e.r.FreeSpace = func() (int64, error) { return 0, errors.New("statfs failed") }
	rep, err = e.apply(desired(1, in))
	if !errors.Is(err, ErrRejected) || !strings.Contains(inst(rep, "a").Error, "cannot determine free disk space") {
		t.Fatalf("%v\n%s", err, dumpReport(rep))
	}
}

func TestRequireStatsAutoSkipsMeterlessEngine(t *testing.T) {
	e := newEnv(t)
	e.r.Drivers = map[string]driver.Driver{"realm": e.realm, "gost": e.gost}
	e.r.RequireStats = true
	rep := e.mustApply(desired(1, fwd(t, "a", "auto")))
	ir := inst(rep, "a")
	// realm is smaller and would win without the metering requirement
	if ir.Engine != "gost" || !strings.Contains(ir.Considered["realm"], "traffic counters") {
		t.Fatalf("%+v", ir)
	}
	e2 := newEnv(t)
	e2.r.Drivers = map[string]driver.Driver{"realm": e2.realm, "gost": e2.gost}
	rep = e2.mustApply(desired(1, fwd(t, "a", "auto")))
	if got := inst(rep, "a").Engine; got != "realm" {
		t.Fatalf("without metering requirement the smaller engine wins, got %q", got)
	}
}

// ---- preflight -----------------------------------------------------------

func TestPortReservedByNodeIsRejected(t *testing.T) {
	e := newEnv(t)
	in := fwd(t, "a", "auto")
	p, _ := strconv.Atoi(in.Listen.Ports)
	e.ports.Reserve("node:main", driver.PortClaim{Proto: "tcp", Addr: "0.0.0.0", Port: p})
	rep, err := e.apply(desired(1, in))
	if !errors.Is(err, ErrRejected) || rep.Status != StatusRejected {
		t.Fatalf("%v %s", err, rep.Status)
	}
	ir := inst(rep, "a")
	if ir.State != StateRejected || !strings.Contains(ir.Error, "port reserved for another component") {
		t.Fatalf("%+v", ir)
	}
	if len(e.xray.Calls()) != 0 && e.xray.CountCalls("apply") != 0 {
		t.Fatal("driver applied despite the conflict")
	}
}

func TestPortInUseByStrangerIsRejected(t *testing.T) {
	e := newEnv(t)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	in := fwd(t, "a", "auto")
	in.Listen.Ports = strconv.Itoa(busy.Addr().(*net.TCPAddr).Port)
	rep, err := e.apply(desired(1, in))
	if !errors.Is(err, ErrRejected) || !strings.Contains(inst(rep, "a").Error, "already in use by another process") {
		t.Fatalf("%v\n%s", err, dumpReport(rep))
	}
	if e.xray.CountCalls("apply") != 0 {
		t.Fatal("driver applied despite the busy port")
	}
	// not blocked: freeing the port and re-sending the same state works
	busy.Close()
	rep, err = e.apply(desired(1, in))
	if err != nil || rep.Status != StatusApplied {
		t.Fatalf("%v\n%s", err, dumpReport(rep))
	}
}

func TestOwnPortsAreNotConflictsOnReapply(t *testing.T) {
	e := newEnv(t)
	a := fwd(t, "a", "auto")
	e.mustApply(desired(1, a))
	// change something else; the listener on a's port is ours and must not be
	// reported as "in use by another process"
	a2 := a
	a2.Targets = []spec.Target{{Host: "198.51.100.77", Ports: "443"}}
	rep := e.mustApply(desired(2, a2))
	if inst(rep, "a").State != StateRunning {
		t.Fatalf("%s", dumpReport(rep))
	}
}

func TestValidationRejectsWithoutTouchingAnything(t *testing.T) {
	e := newEnv(t)
	bad := fwd(t, "a", "auto")
	bad.Targets[0].Host = "127.0.0.1" // loopback target
	good := fwd(t, "b", "auto")
	rep, err := e.apply(desired(1, bad, good))
	if !errors.Is(err, ErrRejected) || rep.Status != StatusRejected {
		t.Fatalf("%v %s", err, rep.Status)
	}
	if len(rep.ValidationErrors) == 0 || rep.ValidationErrors[0].Instance != "a" {
		t.Fatalf("%+v", rep.ValidationErrors)
	}
	if inst(rep, "a").State != StateRejected || inst(rep, "b").State != StateNotApplied {
		t.Fatalf("%s", dumpReport(rep))
	}
	if len(e.xray.Calls()) != 0 {
		t.Fatalf("driver called: %v", e.xray.Calls())
	}
	if _, ok, _ := e.st.LoadDesired(); ok {
		t.Fatal("a rejected desired state must not be persisted")
	}
	raw, err := json.Marshal(rep)
	if err != nil || !strings.Contains(string(raw), `"validation_errors"`) {
		t.Fatalf("%v %s", err, raw)
	}
}

func TestDisabledInstancesAreIgnored(t *testing.T) {
	e := newEnv(t)
	off := fwd(t, "off", "auto")
	off.Enabled = false
	on := fwd(t, "on", "auto")
	rep := e.mustApply(desired(1, off, on))
	if inst(rep, "off").State != StateDisabled || inst(rep, "on").State != StateRunning {
		t.Fatalf("%s", dumpReport(rep))
	}
	eq(t, "running", e.xray.Running(), []string{"on"})
	if e.xray.CountCalls("render:off") != 0 {
		t.Fatal("disabled instance rendered")
	}
}

// ---- apply, idempotence, last_good ---------------------------------------

func TestApplyIsIdempotentAndPersistsLastGood(t *testing.T) {
	e := newEnv(t)
	a := fwd(t, "a", "auto")
	d := desired(5, a)
	rep := e.mustApply(d)
	if rep.Revision != 5 || rep.Hash != state.Hash(d) {
		t.Fatalf("%+v", rep)
	}
	sn, ok, err := e.st.LoadLastGood()
	if err != nil || !ok || sn.Hash != rep.Hash || sn.Engines["a"] != "xray" {
		t.Fatalf("last good: %+v %v %v", sn, ok, err)
	}
	if h, _, _ := e.st.LoadBlocked(); h != "" {
		t.Fatalf("blocked %q", h)
	}
	n := e.xray.CountCalls("apply")

	// identical content, new revision: no-op, revision follows
	rep2, err := e.apply(desired(6, a))
	if err != nil || rep2.Status != StatusApplied || rep2.Revision != 6 || !strings.Contains(rep2.Message, "unchanged") {
		t.Fatalf("%v %s", err, dumpReport(rep2))
	}
	if e.xray.CountCalls("apply") != n || e.xray.CountCalls("render") != 1 {
		t.Fatalf("no-op touched the driver: %v", e.xray.Calls())
	}
	if inst(rep2, "a").ConfigHash != inst(rep, "a").ConfigHash {
		t.Fatal("hash changed")
	}
	// a real change applies again
	a.Targets[0].Host = "198.51.100.99"
	rep3 := e.mustApply(desired(7, a))
	if rep3.Hash == rep.Hash || e.xray.CountCalls("apply") != n+1 {
		t.Fatalf("change not applied: %v", e.xray.Calls())
	}
	if last, ok := e.r.Last(); !ok || last.Revision != 7 {
		t.Fatalf("Last: %+v", last)
	}
}

func TestRemovedInstancesAndDriversAreStopped(t *testing.T) {
	e := newEnv(t)
	g := fwd(t, "g", "gost")
	x := fwd(t, "x", "xray")
	e.mustApply(desired(1, g, x))
	eq(t, "gost", e.gost.Running(), []string{"g"})
	eq(t, "xray", e.xray.Running(), []string{"x"})
	// desired now only has the xray instance: gost must be told to run nothing
	e.mustApply(desired(2, x))
	if e.gost.CountCalls("apply:") != 2 || e.gost.Calls()[len(e.gost.Calls())-1] != "apply:" {
		t.Fatalf("gost calls: %v", e.gost.Calls())
	}
	eq(t, "gost", e.gost.Running(), nil)
	eq(t, "xray", e.xray.Running(), []string{"x"})
	// and the kernel is not re-ensured just to empty it
	if n := len(e.k.pins()); n != 1 {
		t.Fatalf("ensure calls: %v", e.k.pins())
	}
	// an empty desired state removes everything
	e.mustApply(desired(3))
	eq(t, "xray", e.xray.Running(), nil)
}

// ---- failure, rollback, blocked ------------------------------------------

func TestDriverApplyFailureRollsBackAndBlocks(t *testing.T) {
	e := newEnv(t)
	a := fwd(t, "a", "xray")
	good := desired(1, a)
	first := e.mustApply(good)
	claimsBefore := e.ports.Claims()

	b := fwd(t, "b", "xray")
	e.xray.FailApply = map[string]string{"b": "boom: cannot start b"}
	bad := desired(2, a, b)
	rep, err := e.apply(bad)
	if !errors.Is(err, ErrRolledBack) || rep.Status != StatusRolledBack {
		t.Fatalf("%v\n%s", err, dumpReport(rep))
	}
	if !strings.Contains(rep.Message, "boom: cannot start b") {
		t.Fatalf("message %q", rep.Message)
	}
	if got := inst(rep, "b"); got.State != StateFailed || !strings.Contains(got.Error, "boom") {
		t.Fatalf("%+v", got)
	}
	if got := inst(rep, "a"); got.State != StateRolledBack {
		t.Fatalf("%+v", got)
	}
	// the failing driver restored itself (driver contract); no second undo
	if e.xray.CountCalls("rollback") != 0 {
		t.Fatalf("calls %v", e.xray.Calls())
	}
	eq(t, "xray running", e.xray.Running(), []string{"a"})
	// last_good is still the good one, the ledger is unchanged, the hash is blocked
	sn, _, _ := e.st.LoadLastGood()
	if sn.Hash != first.Hash {
		t.Fatalf("last_good moved to %s", sn.Hash)
	}
	if got := e.ports.Claims(); fmt.Sprint(got) != fmt.Sprint(claimsBefore) {
		t.Fatalf("ledger changed: %v vs %v", got, claimsBefore)
	}
	if h, why, _ := e.st.LoadBlocked(); h != rep.Hash || !strings.Contains(why, "boom") {
		t.Fatalf("blocked %q %q", h, why)
	}

	// Same state again: not retried.
	calls := len(e.xray.Calls())
	rep2, err := e.apply(bad)
	if !errors.Is(err, ErrBlocked) || !rep2.Blocked || rep2.Status != StatusRolledBack {
		t.Fatalf("%v\n%s", err, dumpReport(rep2))
	}
	if len(e.xray.Calls()) != calls {
		t.Fatalf("blocked hash was retried: %v", e.xray.Calls()[calls:])
	}
	// A changed desired state is tried again (and succeeds once the fault is gone).
	e.xray.FailApply = nil
	b2 := b
	b2.Targets = []spec.Target{{Host: "198.51.100.88", Ports: "443"}}
	rep3 := e.mustApply(desired(3, a, b2))
	if inst(rep3, "b").State != StateRunning {
		t.Fatal("recovery failed")
	}
	if h, _, _ := e.st.LoadBlocked(); h != "" {
		t.Fatalf("blocked not cleared: %q", h)
	}
	// ... and the old failing content is retried after the block was lifted
	e.xray.FailApply = map[string]string{"zzz": "x"}
	if _, err := e.apply(bad); errors.Is(err, ErrBlocked) {
		t.Fatal("block must clear after a success")
	}
}

func TestBlockedHashSurvivesRestart(t *testing.T) {
	e := newEnv(t)
	a := fwd(t, "a", "xray")
	e.mustApply(desired(1, a))
	e.xray.FailApply = map[string]string{"b": "boom"}
	bad := desired(2, a, fwd(t, "b", "xray"))
	if _, err := e.apply(bad); !errors.Is(err, ErrRolledBack) {
		t.Fatal(err)
	}
	// a new Reconciler on the same state directory ("agent restarted")
	r2 := e.newReconciler()
	calls := len(e.xray.Calls())
	rep, err := r2.Apply(context.Background(), bad)
	if !errors.Is(err, ErrBlocked) || !rep.Blocked || !strings.Contains(rep.Message, "boom") {
		t.Fatalf("%v\n%s", err, dumpReport(rep))
	}
	if len(e.xray.Calls()) != calls {
		t.Fatal("driver called")
	}
}

func TestInstanceLevelFailureRollsBack(t *testing.T) {
	e := newEnv(t)
	a := fwd(t, "a", "xray")
	e.mustApply(desired(1, a))
	b := fwd(t, "b", "xray")
	e.xray.FailInstance = map[string]string{"b": "bind: address already in use"}
	rep, err := e.apply(desired(2, a, b))
	if !errors.Is(err, ErrRolledBack) || inst(rep, "b").State != StateFailed || !strings.Contains(inst(rep, "b").Error, "address already in use") {
		t.Fatalf("%v\n%s", err, dumpReport(rep))
	}
	eq(t, "running", e.xray.Running(), []string{"a"})
}

func TestHealthFailureRollsBack(t *testing.T) {
	cases := map[string]func(e *env){
		"hash mismatch": func(e *env) { e.xray.WrongHashFor = map[string]bool{"b": true} },
		"never ready":   func(e *env) { e.xray.NotRunning = map[string]bool{"b": true} },
		"lying driver":  func(e *env) { e.xray.NoBind = map[string]bool{"b": true} },
	}
	for name, fault := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			a := fwd(t, "a", "xray")
			e.mustApply(desired(1, a))
			fault(e)
			rep, err := e.apply(desired(2, a, fwd(t, "b", "xray")))
			if !errors.Is(err, ErrRolledBack) || !strings.Contains(rep.Message, "health check failed") {
				t.Fatalf("%v\n%s", err, dumpReport(rep))
			}
			if e.xray.CountCalls("rollback") != 1 {
				t.Fatalf("calls %v", e.xray.Calls())
			}
		})
	}
}

func TestHealthWindowWaitsForSlowStart(t *testing.T) {
	e := newEnv(t)
	e.xray.NotReadyCalls = 3 // not running for the first three polls
	e.r.HealthWindow = 2 * time.Second
	rep := e.mustApply(desired(1, fwd(t, "a", "xray")))
	if rep.Status != StatusApplied {
		t.Fatal(rep.Status)
	}
}

func TestFirstApplyFailureLeavesNothingRunning(t *testing.T) {
	e := newEnv(t)
	e.xray.FailApply = map[string]string{"b": "boom"}
	rep, err := e.apply(desired(1, fwd(t, "a", "xray"), fwd(t, "b", "xray")))
	if !errors.Is(err, ErrRolledBack) {
		t.Fatalf("%v", err)
	}
	// no last good: the driver is stopped rather than rolled back
	if e.xray.CountCalls("rollback") != 0 || e.xray.CountCalls("stop:") != 1 {
		t.Fatalf("calls %v", e.xray.Calls())
	}
	eq(t, "running", e.xray.Running(), nil)
	if _, ok, _ := e.st.LoadLastGood(); ok {
		t.Fatal("last_good written for a failed apply")
	}
	// nothing was running before, so every instance of the failed engine failed
	if got := inst(rep, "a"); got.State != StateFailed {
		t.Fatalf("%+v", got)
	}
}

func TestMultiDriverPartialFailureRollsBackEverything(t *testing.T) {
	e := newEnv(t)
	g := fwd(t, "g", "gost")
	first := e.mustApply(desired(1, g))

	g2 := g
	g2.Targets = []spec.Target{{Host: "198.51.100.55", Ports: "443"}} // gost applies this fine
	x := fwd(t, "x", "xray")                                          // xray fails afterwards (alphabetical order)
	e.xray.FailApply = map[string]string{"x": "xray exploded"}
	rep, err := e.apply(desired(2, g2, x))
	if !errors.Is(err, ErrRolledBack) || rep.Status != StatusRolledBack {
		t.Fatalf("%v\n%s", err, dumpReport(rep))
	}
	// gost had been changed and was rolled back; xray (no last good) was stopped
	if e.gost.CountCalls("rollback") != 1 {
		t.Fatalf("gost calls %v", e.gost.Calls())
	}
	if e.xray.CountCalls("stop:") != 1 {
		t.Fatalf("xray calls %v", e.xray.Calls())
	}
	eq(t, "gost running", e.gost.Running(), []string{"g"})
	eq(t, "xray running", e.xray.Running(), nil)
	if got := inst(rep, "g"); got.State != StateRolledBack {
		t.Fatalf("%+v", got)
	}
	if got := inst(rep, "x"); got.State != StateFailed || !strings.Contains(got.Error, "xray exploded") {
		t.Fatalf("%+v", got)
	}
	// the surviving gost instance runs the ORIGINAL configuration
	if h := e.r.Health(context.Background()); !h.OK || h.Hash != first.Hash {
		t.Fatalf("health after rollback: %+v", h)
	}
	if got := e.gost.Calls(); got[len(got)-1] != "rollback" {
		t.Fatalf("gost calls %v", got)
	}
}

func TestIncompleteRollbackIsPartial(t *testing.T) {
	e := newEnv(t)
	g := fwd(t, "g", "gost")
	e.mustApply(desired(1, g))
	e.gost.RollbackErr = errors.New("cannot restore")
	g2 := g
	g2.Targets = []spec.Target{{Host: "198.51.100.55", Ports: "443"}}
	e.xray.FailApply = map[string]string{"x": "boom"}
	rep, err := e.apply(desired(2, g2, fwd(t, "x", "xray")))
	if !errors.Is(err, ErrPartial) || rep.Status != StatusPartial {
		t.Fatalf("%v\n%s", err, dumpReport(rep))
	}
	if !strings.Contains(rep.Message, "gost: cannot restore") {
		t.Fatalf("%s", rep.Message)
	}
}

func TestDriverPanicIsContained(t *testing.T) {
	e := newEnv(t)
	e.xray.PanicApply = true
	rep, err := e.apply(desired(1, fwd(t, "a", "xray")))
	if !errors.Is(err, ErrRolledBack) || !strings.Contains(rep.Message, "driver panic") {
		t.Fatalf("%v\n%s", err, dumpReport(rep))
	}
}

func TestRollbackRunsEvenIfContextIsCancelled(t *testing.T) {
	e := newEnv(t)
	a := fwd(t, "a", "xray")
	e.mustApply(desired(1, a))
	e.xray.NotRunning = map[string]bool{"b": true}
	e.r.HealthWindow = 5 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	b := fwd(t, "b", "xray")
	start := time.Now()
	rep, err := e.r.Apply(ctx, desired(2, a, b))
	if !errors.Is(err, ErrRolledBack) {
		t.Fatalf("%v\n%s", err, dumpReport(rep))
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("cancelled context did not end the health wait: %v", time.Since(start))
	}
	if e.xray.CountCalls("rollback") != 1 || e.xray.RollbackCtxErr != nil {
		t.Fatalf("rollback must run with a live context: calls=%v ctxErr=%v", e.xray.Calls(), e.xray.RollbackCtxErr)
	}
}

func TestKernelInstallFailureTouchesNothing(t *testing.T) {
	e := newEnv(t)
	x := fwd(t, "x", "xray")
	e.mustApply(desired(1, x))
	e.k.ensureErr["gost"] = errors.New("download failed: checksum mismatch")
	nx := e.xray.CountCalls("apply")
	d := desired(2, x, fwd(t, "g", "gost"))
	rep, err := e.apply(d)
	if !errors.Is(err, ErrFailed) || rep.Status != StatusFailed {
		t.Fatalf("%v\n%s", err, dumpReport(rep))
	}
	if !strings.Contains(rep.Message, "checksum mismatch") || inst(rep, "g").State != StateFailed {
		t.Fatalf("%s", dumpReport(rep))
	}
	if e.xray.CountCalls("apply") != nx || e.gost.CountCalls("apply") != 0 {
		t.Fatalf("a driver was touched: %v %v", e.xray.Calls(), e.gost.Calls())
	}
	eq(t, "xray still running", e.xray.Running(), []string{"x"})
	// environmental failure is not blocked: the same state succeeds after a fix
	delete(e.k.ensureErr, "gost")
	rep = e.mustApply(d)
	if inst(rep, "g").State != StateRunning {
		t.Fatal("not recovered")
	}
}

func TestResumeAppliesLastGood(t *testing.T) {
	e := newEnv(t)
	g := fwd(t, "g", "gost")
	x := fwd(t, "x", "xray")
	first := e.mustApply(desired(4, g, x))

	// "restart": new drivers (nothing running), new reconciler, same state dir
	e2 := &env{t: t, st: e.st, ports: portledger.New(), log: &testLog{}, k: &fakeKernels{unavail: map[string]string{}, installed: map[string]bool{}, ensureErr: map[string]error{}}}
	e2.xray = testdriver.New("xray", xrayCaps())
	e2.gost = testdriver.New("gost", gostCaps())
	e2.realm = testdriver.New("realm", realmCaps())
	t.Cleanup(func() { e2.xray.Close(); e2.gost.Close() })
	e.xray.Close()
	e.gost.Close()
	e2.r = e2.newReconciler()
	rep, err := e2.r.Resume(context.Background())
	if err != nil || rep.Status != StatusApplied || rep.Hash != first.Hash {
		t.Fatalf("%v\n%s", err, dumpReport(rep))
	}
	eq(t, "gost", e2.gost.Running(), []string{"g"})
	eq(t, "xray", e2.xray.Running(), []string{"x"})

	// nothing persisted: Resume is a no-op
	e3 := newEnv(t)
	if rep, err := e3.r.Resume(context.Background()); err != nil || rep.Hash != "" {
		t.Fatalf("%v %+v", err, rep)
	}
}

func TestResumeSeedsRemovalOfVanishedDriver(t *testing.T) {
	e := newEnv(t)
	e.mustApply(desired(1, fwd(t, "g", "gost")))
	// new process; the next desired state no longer uses gost
	e2 := &env{t: t, st: e.st, ports: portledger.New(), log: &testLog{}, k: e.k}
	e2.xray = testdriver.New("xray", xrayCaps())
	e2.gost = testdriver.New("gost", gostCaps())
	e2.realm = testdriver.New("realm", realmCaps())
	t.Cleanup(func() { e2.xray.Close(); e2.gost.Close() })
	e.gost.Close()
	e2.r = e2.newReconciler()
	if _, err := e2.r.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	e2.mustApply(desired(2, fwd(t, "x", "xray")))
	if got := e2.gost.Calls(); got[len(got)-1] != "apply:" {
		t.Fatalf("gost was not emptied: %v", got)
	}
}

// ---- secrets -------------------------------------------------------------

func TestReportAndLogsNeverContainSecrets(t *testing.T) {
	e := newEnv(t)
	a := entry(t, "a", "xray", secretA)
	b := entry(t, "b", "xray", secretB)
	good := e.mustApply(desired(1, a))
	check := func(what string, v any) {
		raw, _ := json.Marshal(v)
		for _, s := range []string{secretA, secretB} {
			if strings.Contains(string(raw), s) {
				t.Errorf("%s contains a secret: %s", what, raw)
			}
		}
	}
	check("applied report", good)

	// a driver that echoes the secret in its error text
	e.xray.FailApply = map[string]string{"b": "cannot start b with key " + secretB}
	rep, err := e.apply(desired(2, a, b))
	if !errors.Is(err, ErrRolledBack) {
		t.Fatal(err)
	}
	check("rolled back report", rep)
	for _, s := range []string{secretA, secretB} {
		if strings.Contains(err.Error(), s) {
			t.Errorf("returned error leaks a secret: %v", err)
		}
	}
	if !strings.Contains(rep.Message, "***") {
		t.Errorf("redaction marker missing: %q", rep.Message)
	}
	// driver Validate error echoing the secret
	e.realm.ValidateErr = func(in spec.Instance) error { return fmt.Errorf("bad config for %s secret=%s", in.ID, in.Secret) }
	rin := entry(t, "r", "realm", secretA)
	rep, err = e.apply(desired(3, rin))
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("%v", err)
	}
	check("rejected report", rep)
	if !strings.Contains(inst(rep, "r").Error, "driver validation") {
		t.Fatalf("%+v", inst(rep, "r"))
	}
	// validation errors never carry the secret either
	bad := entry(t, "v", "xray", secretA)
	bad.Tunnel.Path = "no-slash"
	rep, _ = e.apply(desired(4, bad))
	check("validation report", rep)
	if text := e.log.text(); strings.Contains(text, secretA) || strings.Contains(text, secretB) {
		t.Errorf("logs contain a secret:\n%s", text)
	}
	// the secret must still reach the driver (rendering saw it) and the 0600 state
	if !strings.Contains(string(mustRender(t, e.xray, a).Files["a.json"]), secretA) {
		t.Fatal("test driver lost the secret; the test is meaningless")
	}
	sn, _, _ := e.st.LoadLastGood()
	if sn.Desired.Instances[0].Secret != secretA {
		t.Fatal("secret missing from the 0600 last_good file")
	}
	check("redacted snapshot", sn.Redacted())
}

func mustRender(t *testing.T, d driver.Driver, in spec.Instance) driver.Artifact {
	t.Helper()
	art, err := d.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	return art
}

// ---- health --------------------------------------------------------------

func TestHealthDiffs(t *testing.T) {
	e := newEnv(t)
	if h := e.r.Health(context.Background()); h.OK || h.Skipped == "" {
		t.Fatalf("nothing applied: %+v", h)
	}
	a, b := fwd(t, "a", "xray"), fwd(t, "b", "xray")
	e.mustApply(desired(9, a, b))
	h := e.r.Health(context.Background())
	if !h.OK || len(h.Diffs) != 0 || h.Revision != 9 || h.Hash == "" {
		t.Fatalf("%+v", h)
	}

	// a crashed listener the driver does not notice: only the ledger probe sees it
	e.xray.Kill("a")
	h = e.r.Health(context.Background())
	if h.OK || len(h.Diffs) != 1 || h.Diffs[0] != (Diff{Instance: "a", Kind: "port_not_bound", Detail: h.Diffs[0].Detail}) {
		t.Fatalf("%+v", h)
	}
	if !strings.HasPrefix(h.Diffs[0].Detail, "tcp 127.0.0.1:") {
		t.Fatalf("detail %q", h.Diffs[0].Detail)
	}

	// the engine forgot an instance
	e.xray.Drop("b")
	h = e.r.Health(context.Background())
	kinds := map[string]string{}
	for _, d := range h.Diffs {
		kinds[d.Instance] = d.Kind
	}
	if kinds["b"] != "missing" || kinds["a"] != "port_not_bound" {
		t.Fatalf("%+v", h)
	}

	// extra instance, wrong hash
	e.xray.Extra = []string{"ghost"}
	e.xray.WrongHash = true
	h = e.r.Health(context.Background())
	kinds = map[string]string{}
	for _, d := range h.Diffs {
		kinds[d.Instance] = d.Kind
	}
	if kinds["ghost"] != "unexpected" || kinds["a"] != "hash_mismatch" {
		t.Fatalf("%+v", h)
	}
	raw, err := json.Marshal(h)
	if err != nil || !strings.Contains(string(raw), `"kind":"unexpected"`) {
		t.Fatalf("%v %s", err, raw)
	}
}

func TestHealthIsSkippedWhileApplying(t *testing.T) {
	e := newEnv(t)
	e.mustApply(desired(1, fwd(t, "a", "xray")))
	e.r.applying.Store(true)
	h := e.r.Health(context.Background())
	e.r.applying.Store(false)
	if h.OK || h.Skipped != "an apply is in progress" {
		t.Fatalf("%+v", h)
	}
}

func TestHealthDetectsMissingDriver(t *testing.T) {
	e := newEnv(t)
	e.mustApply(desired(1, fwd(t, "a", "xray")))
	delete(e.r.Drivers, "xray")
	h := e.r.Health(context.Background())
	if h.OK || len(h.Diffs) == 0 || h.Diffs[0].Kind != "driver_missing" {
		t.Fatalf("%+v", h)
	}
}

func TestStatsAggregates(t *testing.T) {
	e := newEnv(t)
	if len(e.r.Stats(context.Background())) != 0 {
		t.Fatal("stats before apply")
	}
	e.mustApply(desired(1, fwd(t, "b", "xray"), fwd(t, "a", "gost")))
	cs := e.r.Stats(context.Background())
	if len(cs) != 2 || cs[0].InstanceID != "a" || cs[1].InstanceID != "b" {
		t.Fatalf("%+v", cs)
	}
}

// ---- concurrency ---------------------------------------------------------

func TestApplyIsSerialised(t *testing.T) {
	e := newEnv(t)
	e.xray.ApplyDelay = 30 * time.Millisecond
	a := fwd(t, "a", "xray")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			x := a
			x.Targets = []spec.Target{{Host: fmt.Sprintf("198.51.100.%d", 20+i), Ports: "443"}}
			if _, err := e.apply(desired(int64(i), x)); err != nil {
				t.Errorf("apply %d: %v", i, err)
			}
			_ = e.r.Health(context.Background())
			_, _ = e.r.Last()
		}(i)
	}
	wg.Wait()
	if m := e.xray.MaxConcurrentApply(); m != 1 {
		t.Fatalf("driver saw %d concurrent applies", m)
	}
}

// ---- misc ----------------------------------------------------------------

func TestStateStoreIsRequired(t *testing.T) {
	r := &Reconciler{Drivers: map[string]driver.Driver{}}
	rep, err := r.Apply(context.Background(), desired(1))
	if err == nil || rep.Status != StatusFailed {
		t.Fatalf("%v %s", err, rep.Status)
	}
}

func TestPortCompaction(t *testing.T) {
	var cs []driver.PortClaim
	for p := 20000; p <= 20009; p++ {
		cs = append(cs, driver.PortClaim{Proto: "tcp", Addr: "127.0.0.1", Port: p, Owner: "a"})
		cs = append(cs, driver.PortClaim{Proto: "udp", Addr: "127.0.0.1", Port: p, Owner: "a"})
	}
	cs = append(cs, driver.PortClaim{Proto: "tcp", Addr: "127.0.0.1", Port: 9000, Owner: "a"})
	cs = append(cs, driver.PortClaim{Proto: "tcp", Addr: "", Port: 9001, Owner: "a"})
	got := compactClaims(cs)
	want := []string{"tcp *:9001", "tcp 127.0.0.1:9000", "tcp 127.0.0.1:20000-20009", "udp 127.0.0.1:20000-20009"}
	eq(t, "compaction", got, want)
	if compactClaims(nil) != nil {
		t.Fatal("nil in, nil out")
	}
}

func TestReportIsDeepCopied(t *testing.T) {
	e := newEnv(t)
	rep := e.mustApply(desired(1, fwd(t, "a", "xray")))
	rep.Instances[0].Ports[0] = "mutated"
	rep.Kernels["xray"] = "mutated"
	again, _ := e.apply(desired(2, fwd(t, "a", "xray")))
	_ = again
	last, _ := e.r.Last()
	if last.Instances[0].Ports[0] == "mutated" || last.Kernels["xray"] == "mutated" {
		t.Fatal("caller mutation leaked into the reconciler")
	}
}

func TestEngineOrderIsDeterministic(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 20; i++ {
		got := e.r.engineOrder()
		eq(t, "order", got, []string{"xray", "realm", "gost"})
	}
}
