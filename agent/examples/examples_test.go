package examples

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/portledger"
	"github.com/W1nCwC/W1nCray/agent/reconcile"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/agent/state"
	"github.com/W1nCwC/W1nCray/agent/validate"
	"github.com/W1nCwC/W1nCray/driver/frp"
	"github.com/W1nCwC/W1nCray/driver/gost"
	"github.com/W1nCwC/W1nCray/driver/realm"
)

// placeholderSecret is the secret every sample uses. The tests insist on it so
// that a real secret can never be committed by accident, and so that the
// "secret never reaches a report" checks have something to search for.
const placeholderSecret = "CHANGE-ME-32-chars-minimum-secret"

// testPolicy is deliberately looser than the agent default so that the samples
// (which listen on 0.0.0.0 and use LAN targets in the reverse proxy samples)
// are judged on their own merits. It is NOT a recommendation; docs/AGENT.md
// tells operators which samples need which local policy.
func testPolicy() spec.Policy {
	return spec.Policy{
		AllowListen:    []string{"127.0.0.1", "0.0.0.0"},
		PortRange:      [2]int{1024, 65535},
		AllowPrivate:   true,
		AllowAnyTarget: false,
	}
}

// fakeResolver resolves every host name to one public documentation address
// (TEST-NET-3), so no test touches the network.
type fakeResolver struct{}

func (fakeResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("203.0.113.250")}, nil
}

// validateOpts returns the production validator options plus the offline
// resolver. No engine override is set: the samples must validate exactly like
// production does (PLAN v11 §2.5 removed the embedded xray engine, so
// engine=xray is refused by the default validator).
func validateOpts() validate.Options {
	return validate.Options{Resolver: fakeResolver{}}
}

// realDrivers builds the same engine set as bootstrap.buildDrivers, with zero
// options: the samples are validated and rendered, never applied to a kernel.
// The policy is part of the signature because callers share one helper.
func realDrivers(_ spec.Policy) map[string]driver.Driver {
	return map[string]driver.Driver{
		spec.EngineGost:  gost.New(gost.Options{}),
		spec.EngineFrp:   frp.New(frp.Options{}),
		spec.EngineRealm: realm.New(realm.Options{}),
	}
}

func TestList(t *testing.T) {
	list := List()
	if len(list) < 12 {
		t.Fatalf("only %d samples, want at least 12", len(list))
	}
	seen := map[string]bool{}
	names := make([]string, 0, len(list))
	for _, ex := range list {
		if seen[ex.Name] {
			t.Errorf("duplicate sample name %q", ex.Name)
		}
		seen[ex.Name] = true
		names = append(names, ex.Name)
		if ex.File != ex.Name+".json" {
			t.Errorf("%s: File = %q", ex.Name, ex.File)
		}
	}
	if !sort.StringsAreSorted(names) {
		t.Errorf("List is not sorted: %v", names)
	}
	// Every file on disk is listed (embed globbing cannot silently skip one).
	onDisk, err := filepath.Glob(filepath.Join("testdata", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(onDisk) != len(list) {
		t.Errorf("testdata has %d json files, List returned %d", len(onDisk), len(list))
	}
}

// TestCoverage pins the scenarios the manual promises, so removing a sample
// that docs/AGENT.md links to fails here.
func TestCoverage(t *testing.T) {
	have := map[string]bool{}
	for _, ex := range List() {
		have[ex.Name] = true
	}
	for _, want := range []string{
		"forward-tcp", "forward-udp", "forward-tcp-udp", "forward-port-range", "forward-port-map",
		"forward-balance", "forward-acl", "forward-gost-limits",
		"proxy-send", "proxy-accept", "proxy-passthrough",
		"tunnel-tls-self-entry", "tunnel-tls-self-exit",
		"reverse-frp-portal", "reverse-frp-bridge", "reverse-gost-portal", "reverse-gost-bridge",
		"realm-relay", "realm-wss-entry", "realm-wss-exit", "gost-wss-entry", "gost-wss-exit",
		"engine-auto",
	} {
		if !have[want] {
			t.Errorf("sample %q is missing", want)
		}
	}
}

// TestExamples runs the per-sample checks. Sub-test names:
//
//	<sample>/decode, <sample>/validate, <sample>/driver/<instance>,
//	<sample>/hygiene.
func TestExamples(t *testing.T) {
	pol := testPolicy()
	drivers := realDrivers(pol)
	for _, ex := range List() {
		ex := ex
		t.Run(ex.Name, func(t *testing.T) {
			raw, err := Raw(ex.File)
			if err != nil {
				t.Fatal(err)
			}

			t.Run("decode", func(t *testing.T) {
				// List() already decoded it; decode again here so a failure
				// is attributed to the right sub-test, and check the
				// round-trip loses nothing (a typo'd field would have been
				// rejected by DisallowUnknownFields, a dropped one would not).
				d, err := Decode(raw)
				if err != nil {
					t.Fatalf("strict decode: %v", err)
				}
				if d.Version != spec.Version {
					t.Errorf("version = %d, want %d", d.Version, spec.Version)
				}
				if len(d.Instances) == 0 {
					t.Error("no instances")
				}
				again, err := json.Marshal(d)
				if err != nil {
					t.Fatal(err)
				}
				d2, err := Decode(again)
				if err != nil {
					t.Fatalf("re-decode: %v", err)
				}
				a, _ := json.Marshal(d2)
				if string(a) != string(again) {
					t.Error("JSON round trip is not stable")
				}
			})

			t.Run("validate", func(t *testing.T) {
				if errs := validate.Desired(ex.Desired, pol, validateOpts()); len(errs) > 0 {
					for _, e := range errs {
						t.Errorf("%v", e)
					}
				}
			})

			for _, in := range ex.Desired.Instances {
				in := in
				t.Run("driver/"+in.ID, func(t *testing.T) {
					if in.Engine == spec.EngineAuto {
						t.Skip("engine auto: the engine is chosen at apply time; see TestPipeline")
					}
					drv := drivers[in.Engine]
					if drv == nil {
						t.Fatalf("no driver for engine %q", in.Engine)
					}
					if err := drv.Validate(in); err != nil {
						t.Fatalf("%s Validate: %v", in.Engine, err)
					}
					a1, err := drv.Render(in)
					if err != nil {
						t.Fatalf("%s Render: %v", in.Engine, err)
					}
					if a1.Hash == "" {
						t.Error("artifact hash is empty")
					}
					if len(a1.Files) == 0 {
						t.Error("artifact has no files")
					}
					a2, err := drv.Render(in)
					if err != nil {
						t.Fatalf("second Render: %v", err)
					}
					if a1.Hash != a2.Hash {
						t.Errorf("Render is not deterministic: %s != %s", a1.Hash, a2.Hash)
					}
					for _, c := range a1.PortClaims {
						if c.Owner != in.ID {
							t.Errorf("port claim owned by %q, want %q", c.Owner, in.ID)
						}
					}
				})
			}

			t.Run("hygiene", func(t *testing.T) {
				low := strings.ToLower(string(raw))
				for _, bad := range []string{"allowinsecure", "insecure", "//", "/*"} {
					// "//" would also match URLs; the samples contain none.
					if strings.Contains(low, bad) {
						t.Errorf("sample contains %q", bad)
					}
				}
				for _, in := range ex.Desired.Instances {
					if in.Name == "" {
						t.Errorf("instance %s has no name (one-line Chinese description)", in.ID)
					}
					if !in.Enabled {
						t.Errorf("instance %s is disabled: a disabled instance proves nothing", in.ID)
					}
					if in.Secret != "" && in.Secret != placeholderSecret {
						t.Errorf("instance %s: secret is not the placeholder", in.ID)
					}
					if in.Tunnel != nil && in.Tunnel.Security == "none" {
						t.Errorf("instance %s: samples must not use an unauthenticated tunnel", in.ID)
					}
				}
			})
		})
	}
}

// pairSuffixes name the two halves of a pair of samples: the side that dials
// first, the side that accepts second.
var pairSuffixes = [][2]string{{"-entry", "-exit"}, {"-bridge", "-portal"}}

// TestPairs checks that the halves of every pair of samples actually fit
// together: same engine and secret, the dialling side points at the port the
// accepting side listens on, and a pinned certificate matches the one the
// exit presents.
func TestPairs(t *testing.T) {
	by := map[string]Example{}
	for _, ex := range List() {
		by[ex.Name] = ex
	}
	pairs := 0
	for _, ex := range List() {
		for _, sfx := range pairSuffixes {
			if !strings.HasSuffix(ex.Name, sfx[0]) {
				continue
			}
			base := strings.TrimSuffix(ex.Name, sfx[0])
			peer, ok := by[base+sfx[1]]
			if !ok {
				t.Errorf("%s has no %s%s", ex.Name, base, sfx[1])
				continue
			}
			pairs++
			t.Run(base, func(t *testing.T) {
				checkPair(t, ex.Desired, peer.Desired)
			})
		}
	}
	for _, ex := range List() {
		for _, sfx := range pairSuffixes {
			if strings.HasSuffix(ex.Name, sfx[1]) {
				if _, ok := by[strings.TrimSuffix(ex.Name, sfx[1])+sfx[0]]; !ok {
					t.Errorf("%s has no matching %s half", ex.Name, sfx[0])
				}
			}
		}
	}
	if pairs < 5 {
		t.Errorf("only %d pairs of samples, want at least 5", pairs)
	}
}

// TestReverseSemantics pins the reverse proxy contract shared by gost and frp:
// the portal has no targets, the bridge's targets decide the destinations, and
// the old "portal decides" settings are refused by the layer that owns them.
func TestReverseSemantics(t *testing.T) {
	portal := sample(t, "reverse-gost-portal").Instances[0]
	bridge := sample(t, "reverse-gost-bridge").Instances[0]
	if len(portal.Targets) != 0 || len(portal.Listen.PortMap) != 0 {
		t.Errorf("the portal sample must not name destinations: %+v", portal.Targets)
	}
	if len(bridge.Targets) == 0 {
		t.Error("the bridge sample must name its destinations")
	}

	pol := testPolicy()

	// The layer above refuses a portal with targets: the destinations are the
	// bridge's decision, never the portal's.
	withTargets := portal
	withTargets.Targets = bridge.Targets
	one := spec.Desired{Version: spec.Version, Revision: 1, Instances: []spec.Instance{withTargets}}
	refused := false
	for _, e := range validate.Desired(one, pol, validateOpts()) {
		if e.Field == "targets" && strings.Contains(e.Message, "not used by reverse_portal") {
			refused = true
		}
	}
	if !refused {
		t.Error("validate no longer refuses targets on a reverse_portal")
	}
}

func port(t *testing.T, hostport string) string {
	t.Helper()
	i := strings.LastIndexByte(hostport, ':')
	if i < 0 {
		t.Fatalf("not host:port: %q", hostport)
	}
	return hostport[i+1:]
}

func checkPair(t *testing.T, dial, accept spec.Desired) {
	t.Helper()
	if len(dial.Instances) != 1 || len(accept.Instances) != 1 {
		t.Fatalf("pair files must hold exactly one instance each")
	}
	d, a := dial.Instances[0], accept.Instances[0]
	if d.ID != a.ID {
		t.Errorf("ids differ: %q vs %q", d.ID, a.ID)
	}
	if d.Engine != a.Engine {
		t.Errorf("engines differ: %q vs %q", d.Engine, a.Engine)
	}
	if d.Secret == "" || d.Secret != a.Secret {
		t.Errorf("the two halves must share one secret")
	}
	if d.Tunnel == nil || a.Tunnel == nil {
		t.Fatalf("both halves need a tunnel")
	}
	dt, at := d.Tunnel, a.Tunnel
	if dt.Type != at.Type || dt.Security != at.Security || dt.Path != at.Path || dt.Host != at.Host {
		t.Errorf("tunnel type/security/path/host differ: %+v vs %+v", dt, at)
	}
	if port(t, dt.Server) != port(t, at.Listen) {
		t.Errorf("dialling side connects to port %s but the accepting side listens on %s", port(t, dt.Server), port(t, at.Listen))
	}
	if dt.PinSHA256 != at.PinSHA256 {
		t.Errorf("pins differ")
	}
	switch a.Kind {
	case spec.KindTunnelExit:
		// Nothing to check here: gost and realm leave the destination to the
		// exit, which relays only to what it declares.
	case spec.KindReversePortal:
		if d.Reverse == nil || a.Reverse == nil || d.Reverse.Link != a.Reverse.Link || d.Reverse.Domain != a.Reverse.Domain {
			t.Errorf("reverse link/domain differ")
		}
		if d.Listen == nil || a.Listen == nil || d.Listen.Ports != a.Listen.Ports {
			t.Errorf("the bridge must name the portal's public ports in listen.ports")
		}
	}
}

// ---- end-to-end through the reconciler (no kernel, no network) ----------------

// dryDriver wraps a real driver: Validate and Render are the real ones, Apply
// and Health pretend the kernel runs the rendered set. That drives the real
// reconciler (validation, engine selection, rendering, port preflight, health
// comparison, report building) without a kernel binary.
type dryDriver struct {
	driver.Driver
	bound *atomic.Bool
	set   []driver.Rendered
}

func (d *dryDriver) Apply(_ context.Context, _ driver.Runtime, set []driver.Rendered) (driver.ApplyResult, error) {
	d.set = set
	d.bound.Store(true)
	var res driver.ApplyResult
	for _, r := range set {
		res.Running = append(res.Running, r.Instance.ID)
	}
	return res, nil
}

func (d *dryDriver) Health(context.Context, driver.Runtime) driver.Health {
	h := driver.Health{Instances: map[string]driver.InstanceHealth{}}
	for _, r := range d.set {
		h.Instances[r.Instance.ID] = driver.InstanceHealth{Running: true, Listening: true, ConfigHash: r.Artifact.Hash}
	}
	return h
}

func (d *dryDriver) Rollback(context.Context, driver.Runtime) error        { return nil }
func (d *dryDriver) Stop(context.Context, driver.Runtime, ...string) error { return nil }

type fakeKernels struct{}

func (fakeKernels) Ensure(_ context.Context, pin spec.KernelPin) (driver.Installed, error) {
	return driver.Installed{Path: "/opt/w1ncray-test/" + pin.Name, Version: "0.0.0-test"}, nil
}
func (fakeKernels) Available(string) (bool, string) { return true, "" }

func newReconciler(t *testing.T, pol spec.Policy, engines ...string) *reconcile.Reconciler {
	t.Helper()
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bound := new(atomic.Bool)
	real := realDrivers(pol)
	drivers := map[string]driver.Driver{}
	for _, e := range engines {
		drivers[e] = &dryDriver{Driver: real[e], bound: bound}
	}
	ledger := portledger.New()
	// Nothing is really bound: report "free" until Apply ran, then "in use".
	ledger.Prober = func(string, string, int) error {
		if bound.Load() {
			return portledger.ErrInUse
		}
		return nil
	}
	return &reconcile.Reconciler{
		Drivers:      drivers,
		Kernels:      fakeKernels{},
		Policy:       pol,
		State:        st,
		Ports:        ledger,
		ValidateOpts: validateOpts(),
		HealthWindow: -1,
	}
}

// autoWant is the engine each "auto" instance resolves to when every external
// engine is registered, and what docs/AGENT.md says about it: no builtin engine
// exists any more, so the smallest capable external kernel wins.
var autoWant = map[string]string{
	"auto-simple": spec.EngineRealm, // smallest capable kernel (realm)
	"auto-iphash": spec.EngineRealm, // realm supports iphash
}

// TestPipeline applies every sample through the real reconciler and checks the
// report: applied, every instance running, no secret anywhere in it.
func TestPipeline(t *testing.T) {
	pol := testPolicy()
	all := []string{spec.EngineGost, spec.EngineFrp, spec.EngineRealm}
	for _, ex := range List() {
		ex := ex
		t.Run(ex.Name, func(t *testing.T) {
			r := newReconciler(t, pol, all...)
			rep, err := r.Apply(context.Background(), ex.Desired)
			if err != nil {
				raw, _ := json.MarshalIndent(rep, "", "  ")
				t.Fatalf("Apply: %v\n%s", err, raw)
			}
			if rep.Status != reconcile.StatusApplied {
				t.Fatalf("status = %s (%s)", rep.Status, rep.Message)
			}
			for i, ir := range rep.Instances {
				in := ex.Desired.Instances[i]
				if ir.State != reconcile.StateRunning {
					t.Errorf("%s: state %s (%s)", ir.ID, ir.State, ir.Error)
				}
				if in.Engine != spec.EngineAuto {
					if ir.Engine != in.Engine {
						t.Errorf("%s: ran on %q, sample says %q", ir.ID, ir.Engine, in.Engine)
					}
					continue
				}
				if want := autoWant[in.ID]; want == "" {
					t.Errorf("%s: engine auto sample without an expectation in autoWant", in.ID)
				} else if ir.Engine != want {
					t.Errorf("%s: auto resolved to %q, want %q", in.ID, ir.Engine, want)
				}
			}
			raw, err := json.Marshal(rep)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), placeholderSecret) {
				t.Errorf("the report contains the secret:\n%s", raw)
			}
			if last, ok := r.Last(); ok {
				lraw, _ := json.Marshal(last)
				if strings.Contains(string(lraw), placeholderSecret) {
					t.Errorf("Last() report contains the secret")
				}
			}
		})
	}
}

// TestRejectedReportHasNoSecret applies every sample under the agent's
// built-in default policy (loopback listeners only): most are refused, and the
// refusal report must not leak the secret either.
func TestRejectedReportHasNoSecret(t *testing.T) {
	all := []string{spec.EngineGost, spec.EngineFrp, spec.EngineRealm}
	rejected := 0
	for _, ex := range List() {
		ex := ex
		t.Run(ex.Name, func(t *testing.T) {
			r := newReconciler(t, spec.Policy{}, all...)
			rep, err := r.Apply(context.Background(), ex.Desired)
			if err != nil {
				rejected++
			}
			raw, _ := json.Marshal(rep)
			text := string(raw)
			if err != nil {
				text += "\n" + err.Error()
			}
			if strings.Contains(text, placeholderSecret) {
				t.Errorf("rejected report leaks the secret:\n%s", text)
			}
		})
	}
	if rejected == 0 {
		t.Error("expected the default policy to reject at least one sample")
	}
}

// TestAutoNeedsExternalEngines documents what engine auto does when only some
// engines exist: every engine is external now (PLAN v11 §2.5 removed the
// builtin one), so auto-simple lands on the smallest capable kernel, and with
// no engine able to run the instance the apply is rejected with every engine's
// reason (no silent degrade).
func TestAutoNeedsExternalEngines(t *testing.T) {
	var auto spec.Desired
	for _, ex := range List() {
		if ex.Name == "engine-auto" {
			auto = ex.Desired
		}
	}
	if len(auto.Instances) == 0 {
		t.Fatal("engine-auto sample missing")
	}
	t.Run("all-external", func(t *testing.T) {
		r := newReconciler(t, testPolicy(), spec.EngineGost, spec.EngineFrp, spec.EngineRealm)
		rep, err := r.Apply(context.Background(), auto)
		if err != nil {
			t.Fatalf("Apply: %v (%s)", err, rep.Message)
		}
		got := map[string]string{}
		for _, ir := range rep.Instances {
			got[ir.ID] = ir.Engine
		}
		if got["auto-simple"] != spec.EngineRealm || got["auto-iphash"] != spec.EngineRealm {
			t.Errorf("both instances should land on the smallest capable kernel (realm), got %v", got)
		}
	})
	t.Run("only-frp", func(t *testing.T) {
		r := newReconciler(t, testPolicy(), spec.EngineFrp)
		rep, err := r.Apply(context.Background(), auto)
		if err == nil {
			t.Fatal("expected a rejection: frp cannot run a plain forward")
		}
		t.Logf("message: %s", rep.Message)
		for _, ir := range rep.Instances {
			if ir.State != reconcile.StateRejected || ir.Error == "" {
				t.Errorf("%s: state %s error %q, want rejected with a reason", ir.ID, ir.State, ir.Error)
			}
			t.Logf("%s: %s", ir.ID, ir.Error)
		}
	})
}

// TestLocalPolicyNeeds records, per sample, the smallest local policy change
// the agent needs to accept it. The shipped default (no Policy section) allows
// listeners on 127.0.0.1 only, ports >= 1024 and no private targets.
// docs/AGENT.md repeats this table; this test keeps it true.
//
//	default        accepted as is
//	listen         needs Policy.AllowListen to include the listen address (0.0.0.0)
//	private        needs Policy.AllowPrivate (LAN targets)
//	listen+private both of the above
func TestLocalPolicyNeeds(t *testing.T) {
	combos := []struct {
		name    string
		listen  bool
		private bool
	}{
		{"default", false, false},
		{"listen", true, false},
		{"private", false, true},
		{"listen+private", true, true},
	}
	for _, ex := range List() {
		ex := ex
		t.Run(ex.Name, func(t *testing.T) {
			var minimal []string
			ok := map[string]bool{}
			for _, c := range combos {
				p := spec.Policy{AllowPrivate: c.private}
				if c.listen {
					p.AllowListen = []string{"127.0.0.1", "0.0.0.0"}
				}
				ok[c.name] = len(validate.Desired(ex.Desired, p, validateOpts())) == 0
			}
			// accepted sets must be upward closed: more permission never
			// rejects what less permission accepted
			if ok["default"] && !(ok["listen"] && ok["private"] && ok["listen+private"]) ||
				ok["listen"] && !ok["listen+private"] || ok["private"] && !ok["listen+private"] {
				t.Fatalf("policy results are not monotonic: %v", ok)
			}
			for _, c := range combos {
				if ok[c.name] {
					minimal = append(minimal, c.name)
					break
				}
			}
			if len(minimal) == 0 {
				t.Fatalf("not accepted even with listen+private: %v", validate.Desired(ex.Desired, testPolicy(), validateOpts()))
			}
			if want := policyNeeds[ex.Name]; minimal[0] != want {
				t.Errorf("needs %q, table says %q (results %v)", minimal[0], want, ok)
			}
		})
	}
}

// policyNeeds is the table docs/AGENT.md prints.
var policyNeeds = map[string]string{
	"engine-auto":           "listen",
	"forward-acl":           "listen",
	"forward-balance":       "listen",
	"forward-gost-limits":   "listen",
	"forward-port-map":      "listen",
	"forward-port-range":    "listen",
	"forward-tcp":           "listen",
	"forward-tcp-udp":       "listen",
	"forward-udp":           "listen",
	"gost-wss-entry":        "listen",
	"gost-wss-exit":         "listen",
	"proxy-accept":          "default",
	"proxy-passthrough":     "default",
	"proxy-send":            "listen",
	"realm-relay":           "listen",
	"realm-wss-entry":       "listen",
	"realm-wss-exit":        "listen",
	"reverse-frp-bridge":    "private",
	"reverse-frp-portal":    "listen",
	"reverse-gost-bridge":   "private",
	"reverse-gost-portal":   "listen",
	"tunnel-tls-self-entry": "listen",
	"tunnel-tls-self-exit":  "listen",
}

// TestHealthSamples: the two samples that carry a balance.health section run
// through the real pipeline, each on the engine that implements it (gost:
// passive ejection, frp: active frpc healthCheck).
func TestHealthSamples(t *testing.T) {
	for name, engine := range map[string]string{"forward-gost-limits": spec.EngineGost, "reverse-frp-bridge": spec.EngineFrp} {
		name, engine := name, engine
		t.Run(name, func(t *testing.T) {
			d := sample(t, name)
			in := d.Instances[0]
			if in.Balance == nil || in.Balance.Health == nil || in.Balance.Strategy != "failover" {
				t.Fatalf("sample must carry failover + health: %+v", in.Balance)
			}
			r := newReconciler(t, testPolicy(), spec.EngineGost, spec.EngineFrp, spec.EngineRealm)
			rep, err := r.Apply(context.Background(), d)
			if err != nil {
				raw, _ := json.MarshalIndent(rep, "", "  ")
				t.Fatalf("Apply: %v\n%s", err, raw)
			}
			if got := rep.Instances[0].Engine; got != engine {
				t.Fatalf("ran on %q, want %q", got, engine)
			}
		})
	}
}

// TestClientTrustAnchor: a private CA given as tunnel.cert.cert_file (mode
// file, no key_file) on the dialling side passes the validator and the engines
// that honour it (gost: CA file, frp: trustedCaFile), and reaches the rendered
// configuration.
func TestClientTrustAnchor(t *testing.T) {
	pol := testPolicy()
	drivers := realDrivers(pol)
	for name, ca := range map[string]string{"gost-wss-entry": "/etc/w1ncray/relay-ca.pem", "reverse-frp-bridge": "/etc/w1ncray/portal-ca.pem"} {
		name, ca := name, ca
		t.Run(name, func(t *testing.T) {
			d := sample(t, name)
			in := &d.Instances[0]
			in.Tunnel.Cert = &spec.Cert{Mode: "file", CertFile: ca}
			if errs := validate.Desired(d, pol, validateOpts()); len(errs) > 0 {
				t.Fatalf("validate: %v", errs)
			}
			drv := drivers[in.Engine]
			if err := drv.Validate(*in); err != nil {
				t.Fatalf("%s Validate: %v", in.Engine, err)
			}
			art, err := drv.Render(*in)
			if err != nil {
				t.Fatalf("%s Render: %v", in.Engine, err)
			}
			found := false
			for _, f := range art.Files {
				found = found || strings.Contains(string(f), ca)
			}
			if !found {
				t.Errorf("the rendered configuration does not reference the trust anchor %s", ca)
			}
		})
	}
}

func TestMain(m *testing.M) {
	// The tests only read embedded data and the testdata directory; make sure
	// the working directory is the package directory (go test does that).
	if _, err := os.Stat("testdata"); err != nil {
		panic("run the tests from the package directory: " + err.Error())
	}
	os.Exit(m.Run())
}
