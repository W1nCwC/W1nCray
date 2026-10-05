package xray

import (
	"context"
	"net"
	"sync"
	"time"

	xcore "github.com/xtls/xray-core/core"
)

// healthRunner probes the targets of a balanced forward instance with TCP
// connects and keeps only live targets in the balancer's candidate set. The
// balancer selects outbounds by tag prefix at pick time, so adding and
// removing the per-target outbound handlers changes the candidates without
// touching the routing table (and without Xray's observatory, which is an
// instance level feature and probes through HTTP).
type healthRunner struct {
	host  Host
	spec  HealthSpec
	cfgs  map[string]*xcore.OutboundHandlerConfig
	probe func(addr string, timeout time.Duration) error
	logf  func(format string, args ...any)

	cancel context.CancelFunc
	done   chan struct{}

	mu      sync.Mutex
	alive   map[string]bool
	fails   map[string]int
	present map[string]bool
}

func tcpProbe(addr string, timeout time.Duration) error {
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	return c.Close()
}

// initialAbsent returns the outbound tags that must not be added when the
// instance starts: with failover only the first target serves until a probe
// says otherwise.
func initialAbsent(hs *HealthSpec) map[string]bool {
	out := map[string]bool{}
	if hs == nil || hs.Strategy != "failover" {
		return out
	}
	for i, t := range hs.Targets {
		if i == 0 {
			continue
		}
		for _, tag := range t.Tags {
			out[tag] = true
		}
	}
	return out
}

func newHealthRunner(host Host, hs HealthSpec, cfgs map[string]*xcore.OutboundHandlerConfig, absent map[string]bool, logf func(string, ...any)) *healthRunner {
	h := &healthRunner{
		host: host, spec: hs, cfgs: cfgs, probe: tcpProbe, logf: logf,
		alive: map[string]bool{}, fails: map[string]int{}, present: map[string]bool{},
	}
	for _, t := range hs.Targets {
		h.alive[t.Addr] = true
		for _, tag := range t.Tags {
			h.present[tag] = !absent[tag]
		}
	}
	return h
}

func (h *healthRunner) start() {
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	h.done = make(chan struct{})
	go h.run(ctx)
}

// stop ends the probe loop and waits for it.
func (h *healthRunner) stop() {
	if h.cancel == nil {
		return
	}
	h.cancel()
	<-h.done
}

// targetStates returns the liveness of every target.
func (h *healthRunner) targetStates() map[string]bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]bool, len(h.alive))
	for k, v := range h.alive {
		out[k] = v
	}
	return out
}

func (h *healthRunner) run(ctx context.Context) {
	defer close(h.done)
	interval := time.Duration(h.spec.IntervalS) * time.Second
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		h.round(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (h *healthRunner) round(ctx context.Context) {
	timeout := time.Duration(h.spec.TimeoutS) * time.Second
	results := make([]error, len(h.spec.Targets))
	var wg sync.WaitGroup
	for i, t := range h.spec.Targets {
		wg.Add(1)
		go func(i int, addr string) {
			defer wg.Done()
			results[i] = h.probe(addr, timeout)
		}(i, t.Addr)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}
	h.mu.Lock()
	for i, t := range h.spec.Targets {
		if results[i] == nil {
			h.fails[t.Addr] = 0
			h.alive[t.Addr] = true
			continue
		}
		h.fails[t.Addr]++
		if h.fails[t.Addr] >= h.spec.MaxFails {
			h.alive[t.Addr] = false
		}
	}
	want := h.desired()
	h.mu.Unlock()
	h.converge(want)
}

// desired returns the set of outbound tags that should be present. The caller
// holds h.mu.
func (h *healthRunner) desired() map[string]bool {
	want := map[string]bool{}
	pick := func(t HealthTarget) {
		for _, tag := range t.Tags {
			want[tag] = true
		}
	}
	switch h.spec.Strategy {
	case "failover":
		for _, t := range h.spec.Targets {
			if h.alive[t.Addr] {
				pick(t)
				return want
			}
		}
		pick(h.spec.Targets[0])
	default:
		for _, t := range h.spec.Targets {
			if h.alive[t.Addr] {
				pick(t)
			}
		}
		if len(want) == 0 { // everything is down: keep trying all of them
			for _, t := range h.spec.Targets {
				pick(t)
			}
		}
	}
	return want
}

func (h *healthRunner) converge(want map[string]bool) {
	for _, t := range h.spec.Targets {
		for _, tag := range t.Tags {
			h.mu.Lock()
			have := h.present[tag]
			h.mu.Unlock()
			switch {
			case want[tag] && !have:
				if err := h.host.AddOutbound(h.cfgs[tag]); err != nil {
					h.log("health: cannot re-add %s: %v", tag, err)
					continue
				}
				h.setPresent(tag, true)
			case !want[tag] && have:
				if err := h.host.RemoveOutbound(tag); err != nil {
					h.log("health: cannot remove %s: %v", tag, err)
					continue
				}
				h.setPresent(tag, false)
			}
		}
	}
}

func (h *healthRunner) setPresent(tag string, v bool) {
	h.mu.Lock()
	h.present[tag] = v
	h.mu.Unlock()
}

func (h *healthRunner) log(format string, args ...any) {
	if h.logf != nil {
		h.logf(format, args...)
	}
}
