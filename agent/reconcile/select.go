package reconcile

import (
	"fmt"
	"sort"
	"strings"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/spec"
)

func hasString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func hasKind(list []spec.Kind, k spec.Kind) bool {
	for _, x := range list {
		if x == k {
			return true
		}
	}
	return false
}

// capsReason returns why a driver's capabilities cannot run the instance, or
// "" if they can. It is the single place where "greyed out" features are
// decided; the same text is shown to the panel.
func capsReason(c driver.Caps, in spec.Instance, requireStats bool) string {
	if !hasKind(c.Kinds, in.Kind) {
		return fmt.Sprintf("kind %q is not supported", in.Kind)
	}
	nets := in.Network
	if len(nets) == 0 {
		nets = []string{"tcp"}
	}
	for _, n := range nets {
		if !hasString(c.Network, n) {
			return fmt.Sprintf("network %q is not supported", n)
		}
	}
	reverse := in.Kind == spec.KindReversePortal || in.Kind == spec.KindReverseBridge
	if reverse && !c.Reverse {
		return "reverse proxy is not supported"
	}
	if in.Tunnel != nil {
		if !hasString(c.TunnelTypes, in.Tunnel.Type) {
			return fmt.Sprintf("tunnel type %q is not supported", in.Tunnel.Type)
		}
		if in.Tunnel.Security == "vless_enc" && c.Name != spec.EngineXray {
			return "vless_enc security requires the xray engine"
		}
	}
	if in.ProxyProtocolOut > 0 && !c.ProxyOut {
		return "sending PROXY protocol is not supported"
	}
	if in.AcceptProxyProtocol && !c.ProxyIn {
		return "accepting PROXY protocol is not supported"
	}
	if b := in.Balance; b != nil {
		if !hasString(c.Balance, b.Strategy) {
			return fmt.Sprintf("balance strategy %q is not supported", b.Strategy)
		}
		// An engine with passive ejection (gost) honours a health section
		// in its own way and its driver accepts it, so it is not refused
		// here; selectEngine prefers an active engine in "auto" mode and
		// reports when it had to settle for a passive one. Only an engine
		// without any failure detection refuses.
		if b.Health != nil && c.HealthCheck != "active" && c.HealthCheck != "passive" {
			return "health checks are not supported (the engine has no failure detection)"
		}
	}
	if requireStats && (c.Stats == "" || c.Stats == "none") {
		return "traffic counters are not supported (metering required)"
	}
	return ""
}

// engineOrder is the auto-selection preference: the embedded kernel first
// (nothing to install, no extra process), then the smaller install, then name.
func (r *Reconciler) engineOrder() []string {
	names := make([]string, 0, len(r.Drivers))
	for n := range r.Drivers {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		a, b := r.Drivers[names[i]].Caps(), r.Drivers[names[j]].Caps()
		if a.External != b.External {
			return !a.External
		}
		if a.InstalledSize != b.InstalledSize {
			return a.InstalledSize < b.InstalledSize
		}
		return names[i] < names[j]
	})
	return names
}

// evaluate decides whether one engine can run an instance. It returns "" if
// so, otherwise the reason.
func (r *Reconciler) evaluate(engine string, in spec.Instance, pol spec.Policy) string {
	drv := r.Drivers[engine]
	if drv == nil {
		return "no driver for this engine"
	}
	if len(pol.AllowEngines) > 0 && !hasString(pol.AllowEngines, engine) {
		return "not allowed by the local policy"
	}
	caps := drv.Caps()
	if why := capsReason(caps, in, r.RequireStats); why != "" {
		return why
	}
	if caps.External {
		if r.Kernels == nil {
			return "no kernel manager available"
		}
		if ok, why := r.Kernels.Available(engine); !ok {
			if why == "" {
				why = "kernel not available for this platform"
			}
			return why
		}
		if r.needsSpaceCheck(engine) && caps.InstalledSize > 0 && r.FreeSpace != nil {
			free, err := r.FreeSpace()
			switch {
			case err != nil:
				return "cannot determine free disk space: " + err.Error()
			case free < caps.InstalledSize:
				return fmt.Sprintf("not enough free disk space (%d MiB needed, %d MiB free)", caps.InstalledSize>>20, free>>20)
			}
		}
	}
	probe := in
	probe.Engine = engine
	if err := drv.Validate(probe); err != nil {
		return "driver validation: " + err.Error()
	}
	return ""
}

// needsSpaceCheck is true unless the kernel manager says the kernel is
// already installed (the optional Installed interface).
func (r *Reconciler) needsSpaceCheck(engine string) bool {
	if ins, ok := r.Kernels.(interface{ Installed(name string) bool }); ok && ins.Installed(engine) {
		return false
	}
	return true
}

// selection is the engine decision for one instance.
type selection struct {
	engine     string
	considered map[string]string
}

// selectEngine picks the engine for an instance. An explicit engine must be
// able to run it; "auto" takes the first capable engine in preference order.
// It never degrades silently: when nothing fits, the error lists every
// engine's reason.
func (r *Reconciler) selectEngine(in spec.Instance, pol spec.Policy) (selection, error) {
	sel := selection{considered: map[string]string{}}
	if in.Engine != spec.EngineAuto {
		if why := r.evaluate(in.Engine, in, pol); why != "" {
			sel.considered[in.Engine] = why
			return sel, fmt.Errorf("engine %q cannot run this instance: %s", in.Engine, why)
		}
		sel.engine = in.Engine
		sel.considered = nil
		return sel, nil
	}
	wantHealth := in.Balance != nil && in.Balance.Health != nil
	passive := "" // first engine that could run it with passive health only
	for _, name := range r.engineOrder() {
		why := r.evaluate(name, in, pol)
		if why != "" {
			sel.considered[name] = why
			continue
		}
		if wantHealth && r.Drivers[name].Caps().HealthCheck != "active" {
			// Capable, but it only ejects failing targets from the traffic
			// it sees. Keep looking for active probing; settle for this
			// engine (loudly) only if nothing better exists.
			sel.considered[name] = "only passive health checks (no active probing); an engine with active checks is preferred"
			if passive == "" {
				passive = name
			}
			continue
		}
		sel.engine = name
		if len(sel.considered) == 0 {
			sel.considered = nil
		}
		return sel, nil
	}
	if passive != "" {
		sel.engine = passive
		sel.considered[passive] = "selected with passive health checks only: failing targets are ejected by observed traffic errors, no engine with active probing can run this instance"
		return sel, nil
	}
	if len(sel.considered) == 0 {
		return sel, fmt.Errorf("no engine is available to run this instance")
	}
	names := make([]string, 0, len(sel.considered))
	for n := range sel.considered {
		names = append(names, n)
	}
	sort.Strings(names)
	parts := make([]string, len(names))
	for i, n := range names {
		parts[i] = n + ": " + sel.considered[n]
	}
	return sel, fmt.Errorf("no engine can run this instance (%s)", strings.Join(parts, "; "))
}
