package gost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// rawStats are cumulative counters as gost reports them for one service.
type rawStats struct {
	up    uint64 // bytes read from clients (client -> target)
	down  uint64 // bytes written to clients (target -> client)
	total uint64 // connections accepted
}

func (r *rawStats) add(o rawStats) {
	r.up += o.up
	r.down += o.down
	r.total += o.total
}

func (r rawStats) less(o rawStats) bool { return r.up < o.up || r.down < o.down || r.total < o.total }

// svcAcc keeps the counters of one service monotonic. gost starts from zero
// whenever a service object is created: after a replace (the driver retires
// the old value first) or when the process restarts (detected through the
// service's createTime and through a value that went backwards).
type svcAcc struct {
	createTime int64
	last, base rawStats
	active     uint64
}

func (a *svcAcc) observe(createTime int64, raw rawStats, active uint64) {
	if a.createTime != 0 && (createTime != a.createTime || raw.less(a.last)) {
		a.base.add(a.last)
	}
	a.createTime, a.last, a.active = createTime, raw, active
}

func (a *svcAcc) total() rawStats {
	t := a.base
	t.add(a.last)
	return t
}

// observeAll folds a /config/services snapshot into the accumulators.
func (d *Driver) observeAll(snap map[string]svcInfo) {
	for name, s := range snap {
		if s.Status == nil || s.Status.Stats == nil {
			continue
		}
		a := d.rt.acc[name]
		if a == nil {
			a = &svcAcc{}
			d.rt.acc[name] = a
		}
		st := s.Status.Stats
		a.observe(s.Status.CreateTime, rawStats{up: st.InputBytes, down: st.OutputBytes, total: st.TotalConns}, st.CurrentConns)
	}
}

// retireService is called right before a service object is replaced: its
// counters so far become the base for the next incarnation.
func (d *Driver) retireService(name string) {
	if a := d.rt.acc[name]; a != nil {
		a.base.add(a.last)
		a.last = rawStats{}
		a.createTime = 0
		a.active = 0
	}
}

// dropServiceStats removes a service for good (its port was removed from the
// instance) but keeps what it transferred in the instance's total.
func (d *Driver) dropServiceStats(id, name string) {
	a := d.rt.acc[name]
	if a == nil {
		return
	}
	r := d.rt.retired[id]
	r.add(a.total())
	d.rt.retired[id] = r
	delete(d.rt.acc, name)
}

func (d *Driver) dropInstanceStats(id string) {
	delete(d.rt.retired, id)
	for name := range d.rt.acc {
		if instanceOfService(name) == id {
			delete(d.rt.acc, name)
		}
	}
}

// Stats implements driver.Driver. Without EnableMetrics the numbers come from
// gost's per-service API statistics. The byte counters of an entry, forward
// or bridge service count the user's payload exactly; those of a tunnel
// exit or portal also include the relay protocol's framing (a few dozen
// bytes per connection), because gost counts at the tunnel connection.
func (d *Driver) Stats(ctx context.Context, rt driver.Runtime) ([]driver.Counter, error) {
	d.rt.mu.Lock()
	defer d.rt.mu.Unlock()
	if err := checkRuntime(rt); err != nil {
		return nil, err
	}
	if !rt.Sup.Status(procID).Running {
		return nil, errors.New("gost: process is not running")
	}
	ep, err := loadEndpoint(rt.StateDir)
	if err != nil {
		return nil, fmt.Errorf("gost: read endpoint: %w", err)
	}
	api := newAPIClient(ep, d.opts.APITimeout)
	snap, err := api.services(ctx)
	if err != nil {
		return nil, fmt.Errorf("gost: stats: %w", err)
	}
	d.observeAll(snap)
	var prom map[string]promService
	if d.opts.EnableMetrics {
		prom, err = d.scrapeMetrics(ctx, ep)
		if err != nil {
			return nil, err
		}
	}
	st, err := loadApplied(rt.StateDir, appliedFile)
	if err != nil {
		return nil, err
	}
	var out []driver.Counter
	for _, id := range st.ids() {
		var tot rawStats
		var active uint64
		r := d.rt.retired[id]
		tot.add(r)
		for _, name := range st.Instances[id].Fragment.serviceNames() {
			if prom != nil {
				if ps, ok := prom[name]; ok {
					tot.add(rawStats{up: ps.up, down: ps.down, total: ps.total})
					active += ps.active
				}
				continue
			}
			if a := d.rt.acc[name]; a != nil {
				tot.add(a.total())
				active += a.active
			}
		}
		out = append(out, driver.Counter{InstanceID: id, BytesUp: tot.up, BytesDown: tot.down, ConnsActive: active, ConnsTotal: tot.total})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].InstanceID < out[j].InstanceID })
	return out, nil
}

// promService is the aggregate of one service's Prometheus series over all
// client labels.
type promService struct {
	up, down, total, active uint64
}

// scrapeMetrics reads the metrics endpoint and sums gost's per-client series
// per service. The client label is high cardinality (one series per source
// address, never freed); summing here keeps the driver's output bounded but
// cannot reduce gost's own memory use, which is why EnableMetrics is off by
// default.
func (d *Driver) scrapeMetrics(ctx context.Context, ep endpoint) (map[string]promService, error) {
	if ep.MetricsAddr == "" {
		return nil, errors.New("gost: metrics endpoint is not enabled")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+ep.MetricsAddr+"/metrics", nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(ep.User, ep.Pass)
	hc := &http.Client{Timeout: d.opts.APITimeout, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gost: scrape metrics: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gost: scrape metrics: http %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	samples, err := parseProm(b)
	if err != nil {
		return nil, err
	}
	out := map[string]promService{}
	for _, s := range samples {
		svc := s.labels["service"]
		if svc == "" {
			continue
		}
		ps := out[svc]
		v := uint64(s.value)
		switch s.name {
		case "gost_service_transfer_input_bytes_total":
			ps.up += v
		case "gost_service_transfer_output_bytes_total":
			ps.down += v
		case "gost_service_requests_total":
			ps.total += v
		case "gost_service_requests_in_flight":
			ps.active += v
		default:
			continue
		}
		out[svc] = ps
	}
	return out, nil
}
