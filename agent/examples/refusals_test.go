package examples

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/kernelx"
	"github.com/W1nCwC/W1nCray/agent/portledger"
	"github.com/W1nCwC/W1nCray/agent/reconcile"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/agent/state"
	"github.com/W1nCwC/W1nCray/agent/validate"
)

// This file keeps the "common refusals" table of docs/AGENT.md true: each case
// takes a sample, breaks it in one way and checks that the real pipeline
// (validator, engine selection, driver validation) refuses it with the
// message the manual quotes.

// resolverFunc adapts a function to validate.Resolver.
type resolverFunc func(host string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return f(host)
}

type refusal struct {
	name   string
	sample string
	mutate func(d *spec.Desired)
	policy spec.Policy
	// resolver replaces the default fake resolver when set.
	resolver validate.Resolver
	// noManifest uses the real kernel manager without a manifest.
	noManifest bool
	// engines registered in the reconciler (default: all four).
	engines []string
	want    string
}

func sample(t *testing.T, name string) spec.Desired {
	t.Helper()
	for _, ex := range List() {
		if ex.Name == name {
			raw, err := Raw(ex.File)
			if err != nil {
				t.Fatal(err)
			}
			d, err := Decode(raw) // a fresh copy: cases mutate it
			if err != nil {
				t.Fatal(err)
			}
			return d
		}
	}
	t.Fatalf("no sample %q", name)
	return spec.Desired{}
}

func allText(rep reconcile.Report, err error) string {
	var sb strings.Builder
	if err != nil {
		sb.WriteString(err.Error() + "\n")
	}
	sb.WriteString(rep.Message + "\n")
	for _, e := range rep.ValidationErrors {
		sb.WriteString(e.Error() + "\n")
	}
	for _, ir := range rep.Instances {
		sb.WriteString(ir.Error + "\n")
		for _, why := range ir.Considered {
			sb.WriteString(why + "\n")
		}
	}
	return sb.String()
}

func fullPolicy() spec.Policy { return testPolicy() }

func TestRefusals(t *testing.T) {
	inst := func(d *spec.Desired) *spec.Instance { return &d.Instances[0] }
	listenOnly := spec.Policy{AllowListen: []string{"127.0.0.1", "0.0.0.0"}}
	failing := resolverFunc(func(string) ([]netip.Addr, error) { return nil, fmt.Errorf("no such host") })
	toPrivate := resolverFunc(func(string) ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil })

	cases := []refusal{
		{name: "listen-not-allowed", sample: "forward-tcp", policy: spec.Policy{},
			want: "listen address 0.0.0.0 is not allowed by the local policy"},
		{name: "privileged-port", sample: "forward-tcp", policy: listenOnly,
			mutate: func(d *spec.Desired) { inst(d).Listen.Ports = "80" },
			want:   "privileged ports (below 1024) are not allowed by the local policy"},
		{name: "port-outside-range", sample: "forward-tcp",
			policy: spec.Policy{AllowListen: []string{"0.0.0.0"}, PortRange: [2]int{30000, 40000}},
			want:   "ports 20080-20080 are outside the permitted range 30000-40000"},
		{name: "private-target", sample: "forward-tcp", policy: listenOnly,
			mutate: func(d *spec.Desired) { inst(d).Targets[0].Host = "192.168.1.10" },
			want:   "private address (policy.allow_private is off)"},
		{name: "loopback-target", sample: "forward-tcp", policy: fullPolicy(),
			mutate: func(d *spec.Desired) { inst(d).Targets[0].Host = "127.0.0.1" },
			want:   "destination 127.0.0.1 refused: loopback address"},
		{name: "localhost-name", sample: "forward-tcp", policy: fullPolicy(),
			mutate: func(d *spec.Desired) { inst(d).Targets[0].Host = "localhost" },
			want:   "refers to the local host"},
		{name: "unresolvable-name", sample: "forward-tcp", policy: fullPolicy(), resolver: failing,
			mutate: func(d *spec.Desired) { inst(d).Targets[0].Host = "backend.example.com" },
			want:   "cannot be resolved"},
		{name: "name-resolves-private", sample: "forward-tcp", resolver: toPrivate, policy: listenOnly,
			mutate: func(d *spec.Desired) { inst(d).Targets[0].Host = "backend.example.com" },
			want:   "resolves to 10.0.0.5: private address (policy.allow_private is off)"},
		{name: "any-target", sample: "tunnel-tls-self-exit", policy: fullPolicy(),
			mutate: func(d *spec.Desired) { inst(d).Targets, inst(d).AllowAnyTarget = nil, true },
			want:   "allow_any_target: not allowed by the local policy"},
		{name: "exit-without-target", sample: "tunnel-tls-self-exit", policy: fullPolicy(),
			mutate: func(d *spec.Desired) { inst(d).Targets = nil },
			want:   "tunnel_exit needs fixed targets or allow_any_target"},
		{name: "accept-proxy-public", sample: "proxy-accept", policy: fullPolicy(),
			mutate: func(d *spec.Desired) { inst(d).Listen.Addr = "0.0.0.0" },
			want:   "PROXY headers are forgeable there and the local policy does not allow it"},
		{name: "proxy-out-with-udp", sample: "forward-tcp", policy: fullPolicy(),
			mutate: func(d *spec.Desired) { inst(d).Network, inst(d).ProxyProtocolOut = []string{"tcp", "udp"}, 2 },
			want:   "PROXY protocol is TCP only and cannot be combined with network udp"},
		{name: "secret-charset", sample: "tunnel-tls-self-entry", policy: fullPolicy(),
			mutate: func(d *spec.Desired) { inst(d).Secret = placeholderSecret + "!" },
			want:   "secret: must be 16-256 characters of [A-Za-z0-9_.+/=-]"},
		// '~' is outside the accepted set; ':' and '@' are refused by frp. None
		// of them gets past the validator.
		{name: "secret-tilde", sample: "reverse-frp-bridge", policy: fullPolicy(),
			mutate: func(d *spec.Desired) { inst(d).Secret = placeholderSecret + "~" },
			want:   "secret: must be 16-256 characters of [A-Za-z0-9_.+/=-]"},
		{name: "secret-colon", sample: "tunnel-tls-self-entry", policy: fullPolicy(),
			mutate: func(d *spec.Desired) { inst(d).Secret = placeholderSecret + ":@" },
			want:   "secret: must be 16-256 characters of [A-Za-z0-9_.+/=-]"},
		{name: "secret-missing", sample: "tunnel-tls-self-entry", policy: fullPolicy(),
			mutate: func(d *spec.Desired) { inst(d).Secret = "" },
			want:   `required for kind "tunnel_entry" (at least 16 characters)`},
		{name: "range-length", sample: "forward-port-range", policy: fullPolicy(),
			mutate: func(d *spec.Desired) { inst(d).Targets[0].Ports = "30100-30102" },
			want:   "has 3 port(s) but listen.ports has 10; ranges must be the same length"},
		{name: "port-collision", sample: "forward-tcp", policy: fullPolicy(),
			mutate: func(d *spec.Desired) {
				second := d.Instances[0]
				second.ID = "web-80-copy"
				d.Instances = append(d.Instances, second)
			},
			want: "collide with instances[0]"},
		{name: "duplicate-id", sample: "forward-tcp", policy: fullPolicy(),
			mutate: func(d *spec.Desired) {
				second := d.Instances[0]
				second.Listen = &spec.Listen{Addr: "0.0.0.0", Ports: "20081"}
				d.Instances = append(d.Instances, second)
			},
			want: "duplicate id (also used by instances[0])"},
		{name: "engine-not-allowed", sample: "forward-tcp", policy: spec.Policy{AllowListen: []string{"0.0.0.0"}, AllowEngines: []string{"realm"}},
			want: `engine "gost" is not allowed by the local policy`},
		{name: "kind-unsupported-by-engine", sample: "reverse-frp-portal", policy: fullPolicy(),
			mutate: func(d *spec.Desired) { inst(d).Engine = spec.EngineRealm },
			want:   `engine "realm" cannot run this instance: kind "reverse_portal" is not supported`},
		{name: "strategy-unsupported-by-engine", sample: "forward-balance", policy: fullPolicy(),
			mutate: func(d *spec.Desired) { inst(d).Engine, inst(d).Balance.Strategy = spec.EngineRealm, "random" },
			want:   `balance strategy "random" is not supported`},
		{name: "realm-health", sample: "forward-gost-limits", policy: fullPolicy(),
			mutate: func(d *spec.Desired) {
				inst(d).Engine, inst(d).Limits = spec.EngineRealm, nil
				inst(d).Balance = &spec.Balance{Strategy: "round_robin", Health: &spec.Health{Type: "tcp"}}
			},
			want: `engine "realm" cannot run this instance: health checks are not supported`},
		{name: "gost-http-health", sample: "forward-gost-limits", policy: fullPolicy(),
			mutate: func(d *spec.Desired) { inst(d).Balance.Health = &spec.Health{Type: "http", ProbeURL: "/healthz"} },
			want:   "gost removes failing targets passively; active health checks are not implemented"},
		{name: "frp-bridge-strategy", sample: "reverse-frp-bridge", policy: fullPolicy(),
			mutate: func(d *spec.Desired) { inst(d).Balance.Strategy = "round_robin" },
			want:   `balance strategy "round_robin" is not supported`},
		{name: "client-cert-key-file", sample: "reverse-frp-bridge", policy: fullPolicy(),
			mutate: func(d *spec.Desired) {
				inst(d).Tunnel.Cert = &spec.Cert{Mode: "file", CertFile: "/etc/w1ncray/portal-ca.pem", KeyFile: "/etc/w1ncray/client.key"}
			},
			want: "tunnel.cert.key_file: not used by kind"},
		{name: "client-cert-self", sample: "gost-wss-entry", policy: fullPolicy(),
			mutate: func(d *spec.Desired) { inst(d).Tunnel.Cert = &spec.Cert{Mode: "self"} },
			want:   `only supports mode "file"`},
		{name: "realm-acl", sample: "forward-tcp", policy: fullPolicy(),
			mutate: func(d *spec.Desired) {
				inst(d).Engine = spec.EngineRealm
				inst(d).ACL = &spec.ACL{Allow: []string{"198.51.100.0/24"}}
			},
			want: "realm has no access control"},
		// PLAN v11 §2.5: vless_enc was the embedded xray engine's tunnel
		// security and is refused by validation now.
		{name: "vless-enc-removed", sample: "tunnel-tls-self-entry", policy: fullPolicy(),
			mutate: func(d *spec.Desired) { inst(d).Tunnel.Security = "vless_enc" },
			want:   "vless_enc 已随 xray 转发引擎移除"},
		{name: "realm-self-cert", sample: "realm-wss-exit", policy: fullPolicy(),
			mutate: func(d *spec.Desired) { inst(d).Tunnel.Cert = &spec.Cert{Mode: "self"} },
			want:   "a self-signed certificate cannot be verified by a realm entry"},
		{name: "realm-udp-tunnel", sample: "realm-wss-entry", policy: fullPolicy(),
			mutate: func(d *spec.Desired) { inst(d).Network = []string{"tcp", "udp"} },
			want:   "realm tunnels carry TCP only"},
		// `W1nCray agent-apply` registers no builtin xray engine, and the
		// production validator refuses engine=xray before engine selection
		// (PLAN v11 §2.5 removed the forwarding engine entirely).
		{name: "xray-engine-removed", sample: "forward-tcp", policy: fullPolicy(),
			mutate:  func(d *spec.Desired) { inst(d).Engine = spec.EngineXray },
			engines: []string{spec.EngineGost, spec.EngineFrp, spec.EngineRealm},
			want:    "xray 转发引擎已移除，请使用 gost 或 realm"},
		{name: "no-manifest", sample: "forward-gost-limits", policy: fullPolicy(), noManifest: true,
			want: "no signed kernel manifest loaded (set Agent.ManifestPath)"},
	}

	all := []string{spec.EngineGost, spec.EngineFrp, spec.EngineRealm}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			d := sample(t, c.sample)
			if c.mutate != nil {
				c.mutate(&d)
			}
			engines := c.engines
			if len(engines) == 0 {
				engines = all
			}
			st, err := state.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			bound := new(atomic.Bool)
			real := realDrivers(c.policy)
			drivers := map[string]driver.Driver{}
			for _, e := range engines {
				drivers[e] = &dryDriver{Driver: real[e], bound: bound}
			}
			ledger := portledger.New()
			ledger.Prober = func(string, string, int) error { return nil }
			var kern reconcile.KernelEnsurer = fakeKernels{}
			if c.noManifest {
				kern, err = kernelx.New(kernelx.Options{Dir: t.TempDir()})
				if err != nil {
					t.Fatal(err)
				}
			}
			opts := validateOpts()
			if c.resolver != nil {
				opts.Resolver = c.resolver
			}
			r := &reconcile.Reconciler{
				Drivers: drivers, Kernels: kern, Policy: c.policy, State: st,
				Ports: ledger, ValidateOpts: opts, HealthWindow: -1,
			}
			rep, err := r.Apply(context.Background(), d)
			if err == nil {
				raw, _ := json.MarshalIndent(rep, "", "  ")
				t.Fatalf("expected a refusal containing %q, but the apply succeeded:\n%s", c.want, raw)
			}
			text := allText(rep, err)
			t.Logf("refused: %s", strings.TrimSpace(strings.SplitN(text, "\n", 2)[0]))
			if !strings.Contains(text, c.want) {
				t.Errorf("refusal text does not contain %q:\n%s", c.want, text)
			}
			if strings.Contains(text, placeholderSecret) {
				t.Errorf("refusal text leaks the secret:\n%s", text)
			}
		})
	}
}

// TestUnknownFieldRefused: a typo in a field name is an error, never silently
// ignored, because the desired state is decoded strictly.
func TestUnknownFieldRefused(t *testing.T) {
	_, err := Decode([]byte(`{"version":1,"instances":[{"id":"a","enabled":true,"engine":"xray","kind":"forward","listn":{"addr":"0.0.0.0","ports":"20080"}}]}`))
	if err == nil || !strings.Contains(err.Error(), `unknown field "listn"`) {
		t.Fatalf("err = %v, want unknown field \"listn\"", err)
	}
	t.Logf("refused: %v", err)
}
