package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/porthop"
	"github.com/W1nCwC/W1nCray/agent/wsproto"
	"github.com/W1nCwC/W1nCray/api/xboard"
)

// portHopInterval is the poll and self-heal cadence of the port-hop controller.
const portHopInterval = 60 * time.Second

// maxPortHopErrorBytes caps last_error on the wire.
const maxPortHopErrorBytes = 256

// portHopPanel is the panel surface the controller needs (the machine-mode
// client implements it through xboardPortHop).
type portHopPanel interface {
	PortHop(ctx context.Context, etag string) (*xboard.PortHop, error)
}

type xboardPortHop struct{ client *xboard.Client }

func (p xboardPortHop) PortHop(ctx context.Context, etag string) (*xboard.PortHop, error) {
	return p.client.GetMachinePortHop(ctx, etag)
}

// portHopCtl keeps the Hysteria port-hop firewall redirect of this machine in
// line with the panel's rule set. The rules are not tied to the agent process:
// stopping the controller (or the agent) leaves them installed, so forwarding
// keeps working across an agent restart; only an empty rule set, the local
// switch or `W1nCray porthop clear` removes them.
type portHopCtl struct {
	mgr      *porthop.Manager
	panel    portHopPanel
	log      driver.Logger
	interval time.Duration
	hints    chan struct{}

	// Touched only by the run goroutine.
	etag    string
	rules   []porthop.Rule
	have    bool // rules is the result of a successful fetch + apply
	lastErr string

	// snap is the last Manager status; telemetry reads it without waiting for
	// a firewall command that may be running.
	snap atomic.Pointer[porthop.Status]
}

func (c *portHopCtl) snapshot() {
	st := c.mgr.Status()
	c.snap.Store(&st)
}

// Hint asks for an immediate re-fetch (a panel "nodes" hint). It never blocks.
func (c *portHopCtl) Hint() {
	select {
	case c.hints <- struct{}{}:
	default:
	}
}

// Status returns the last snapshot.
func (c *portHopCtl) Status() porthop.Status {
	if st := c.snap.Load(); st != nil {
		return *st
	}
	return porthop.Status{}
}

func convertPortHopRules(doc *xboard.PortHop) []porthop.Rule {
	rules := make([]porthop.Rule, 0, len(doc.Rules))
	for _, r := range doc.Rules {
		rules = append(rules, porthop.Rule{NodeID: r.NodeID, Proto: r.Proto, Ports: r.Ports, To: r.To})
	}
	return rules
}

// sync fetches once and reconciles. A network error keeps the installed state
// (and still self-heals it); a 304 re-asserts the last applied set, which
// verifies the rules, reinstalls them when they vanished and gives a rule that
// was refused for a conflict the chance to flip on.
func (c *portHopCtl) sync(ctx context.Context) {
	fw := context.WithoutCancel(ctx) // a firewall commit is atomic; do not abort it half way
	doc, err := c.panel.PortHop(ctx, c.etag)
	switch {
	case err == nil:
		rules := convertPortHopRules(doc)
		if aerr := c.mgr.Apply(fw, rules); aerr != nil {
			c.warn("apply failed: %v", aerr)
		} else {
			c.etag, c.rules, c.have = doc.Version, rules, true
			c.lastErr = ""
		}
	case errors.Is(err, xboard.ErrNotModified):
		c.lastErr = ""
		c.reassert(fw)
	default:
		if ctx.Err() == nil {
			c.warn("fetch failed, keeping the installed rules: %v", err)
		}
		c.reassert(fw)
	}
	c.snapshot()
}

func (c *portHopCtl) reassert(fw context.Context) {
	var err error
	if c.have {
		err = c.mgr.Apply(fw, c.rules)
	} else {
		err = c.mgr.Heal(fw)
	}
	if err != nil {
		c.warn("self-heal failed: %v", err)
	}
}

// warn logs a message only when it differs from the previous one, so a panel
// that is down for an hour does not fill the log once a minute.
func (c *portHopCtl) warn(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if msg == c.lastErr {
		return
	}
	c.lastErr = msg
	c.log.Warnf("porthop: %s", msg)
}

func (c *portHopCtl) run(ctx context.Context) {
	c.sync(ctx)
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-c.hints:
		}
		c.sync(ctx)
	}
}

// startPortHop wires Hysteria port hopping: the local firewall redirect from
// the panel's port range to the node's real port. It declares the port_hop
// capability only when the platform allows it (Linux, root; OpenWrt included), the
// local switch Firewall.PortHop is on and a firewall backend probed usable. It
// returns a stop function; stopping never removes the installed rules.
func (r *Runtime) startPortHop(ctx context.Context, o RemoteOptions, log driver.Logger) func() {
	noop := func() {}
	if r == nil || !o.AgentConfig.MachineNodesEnabled() {
		return noop
	}
	platformOK := portHopPlatform
	if r.portHopPlatform != nil {
		platformOK = r.portHopPlatform
	}
	if !platformOK(r.openWrt) {
		return noop
	}
	if r.stateDir == "" {
		log.Warnf("porthop: no state directory configured; port hopping is not offered")
		return noop
	}
	rec := r.Reconciler
	mgr := porthop.New(porthop.Config{
		Enabled: o.AgentConfig.PortHopEnabled(),
		// tcp (mieru's TCP transport) is admitted unless the local
		// configuration turns it off; the other gates still apply.
		AllowTCP: o.AgentConfig.PortHopAllowTCPEnabled(),
		Backend:  o.AgentConfig.PortHopBackendName(),
		StateDir: r.stateDir,
		Exec:     r.portHopExec,
		Logf:     log.Infof,
		ForwardPortsFor: func(proto string) map[int]bool {
			out := map[int]bool{}
			if rec == nil || rec.Ports == nil {
				return out
			}
			for _, cl := range rec.Ports.Claims() {
				if strings.EqualFold(cl.Proto, proto) {
					out[cl.Port] = true
				}
			}
			return out
		},
	})
	if !o.AgentConfig.PortHopEnabled() {
		// Local switch off: remove what an earlier run may have left, declare
		// nothing.
		if err := mgr.Clear(ctx); err != nil {
			log.Warnf("porthop: removing the port-hop rules failed: %v", err)
		}
		return noop
	}
	// Bring back the rules of the previous run first, before the panel is
	// asked: a restart must not interrupt forwarding and works with the panel
	// unreachable.
	if err := mgr.Restore(ctx); err != nil {
		log.Warnf("porthop: restoring the previous rules failed: %v", err)
	}
	if err := mgr.Probe(ctx); err != nil {
		log.Warnf("porthop: no usable firewall backend, port hopping is not offered: %v", err)
		return noop
	}
	panel := r.portHopPanel
	if panel == nil {
		panel = xboardPortHop{client: xboard.New(xboard.Config{
			APIHost: o.URL, MachineID: o.MachineID, MachineToken: o.Token,
		})}
	}
	interval := r.portHopEvery
	if interval <= 0 {
		interval = portHopInterval
	}
	ctl := &portHopCtl{mgr: mgr, panel: panel, log: log, interval: interval, hints: make(chan struct{}, 1)}
	ctl.snapshot()
	r.PortHop = ctl
	r.portHopOn.Store(true)

	pctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ctl.run(pctx)
	}()
	var once sync.Once

	return func() {
		once.Do(func() {
			r.portHopOn.Store(false)
			cancel()
			<-done
		})
	}
}

// hintPortHop makes the controller re-fetch now (the panel pushed a nodes
// hint). It is a no-op without a controller.
func (r *Runtime) hintPortHop() {
	if r != nil && r.PortHop != nil {
		r.PortHop.Hint()
	}
}

// portHopComponent is the components entry of the port-hop firewall; nil when
// port hopping is not offered on this machine.
func (r *Runtime) portHopComponent() *wsproto.Component {
	if r == nil || r.PortHop == nil || !r.portHopOn.Load() {
		return nil
	}
	st := r.PortHop.Status()
	comp := wsproto.Component{
		Name:      "porthop",
		Kind:      "firewall",
		Instances: []wsproto.ComponentInstance{},
		State:     wsproto.StateRunning,
	}
	switch st.Backend {
	case "nft":
		comp.RuntimeVersion = "nftables"
	default:
		comp.RuntimeVersion = st.Backend
	}
	failed := ""
	byNode := map[int]string{}
	for _, rs := range st.Rules {
		state := wsproto.StateRunning
		if !rs.OK {
			state = wsproto.StateFailed
			if failed == "" {
				failed = "node " + strconv.Itoa(rs.NodeID) + ": " + rs.Reason
			}
		}
		if prev, ok := byNode[rs.NodeID]; !ok || prev == wsproto.StateRunning {
			byNode[rs.NodeID] = state
		}
	}
	ids := make([]int, 0, len(byNode))
	for id := range byNode {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		comp.Instances = append(comp.Instances, wsproto.ComponentInstance{ID: "node" + strconv.Itoa(id), State: byNode[id]})
	}
	lastErr := st.LastError
	if lastErr == "" {
		lastErr = failed
	}
	if st.LastError != "" || !st.Available {
		comp.State = wsproto.StateFailed
	}
	comp.LastError = truncateUTF8(lastErr, maxPortHopErrorBytes)
	return &comp
}
