package xray

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/W1nCwC/W1nCray/agent/driver"
	xcore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

// want is one instance of the set to apply.
type want struct {
	id   string
	c    *Compiled
	raw  []byte // compiled.json as rendered
	hash string // artifact hash, extended by the content of certificate files
}

// live is an applied instance.
type live struct {
	want
	rev    reverseHandle
	health *healthRunner
	built  *built
}

// built holds the Xray objects of an instance, built (and thereby validated
// by Xray's own config loader) before anything is changed.
type built struct {
	ins  []namedIn
	outs []namedOut
	cfgs map[string]*xcore.OutboundHandlerConfig
}

type namedIn struct {
	tag string
	cfg *xcore.InboundHandlerConfig
}

type namedOut struct {
	tag string
	cfg *xcore.OutboundHandlerConfig
}

type state struct {
	inst map[string]*live
	head []json.RawMessage
	bal  json.RawMessage
}

func newState() *state { return &state{inst: map[string]*live{}} }

func (d *Driver) logf(rt driver.Runtime) func(string, ...any) {
	return func(format string, args ...any) {
		if rt.Log != nil {
			rt.Log.Warnf("xray driver: "+format, args...)
		}
	}
}

// ------------------------------------------------------------------ parsing

func (d *Driver) parseSet(set []driver.Rendered) (map[string]*want, string, error) {
	out := make(map[string]*want, len(set))
	for _, r := range set {
		id := r.Instance.ID
		if _, dup := out[id]; dup {
			return nil, id, fmt.Errorf("duplicate instance id %q", id)
		}
		raw, ok := r.Artifact.Files[CompiledFile]
		if !ok {
			return nil, id, fmt.Errorf("artifact has no %s", CompiledFile)
		}
		// The policy may have changed since Render.
		if err := Validate(r.Instance, d.opts); err != nil {
			return nil, id, err
		}
		w, err := wantFromRaw(id, raw, r.Artifact.Hash)
		if err != nil {
			return nil, id, err
		}
		if w == nil {
			continue // disabled
		}
		out[id] = w
	}
	return out, "", nil
}

func wantFromRaw(id string, raw []byte, artifactHash string) (*want, error) {
	var c Compiled
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("invalid compiled artifact: %w", err)
	}
	if c.ID != id || c.V != CompileVersion {
		return nil, errors.New("compiled artifact does not match the instance or the driver version")
	}
	if c.Disabled {
		return nil, nil
	}
	h := artifactHash
	if h == "" {
		h = ArtifactHash(map[string][]byte{CompiledFile: raw})
	}
	if len(c.CertFiles) > 0 {
		// A renewed certificate must restart the inbound that serves it.
		sum := sha256.New()
		sum.Write([]byte(h))
		for _, f := range c.CertFiles {
			b, err := os.ReadFile(f)
			if err != nil {
				return nil, errors.New("cannot read a certificate file")
			}
			sum.Write(b)
		}
		h = hex.EncodeToString(sum.Sum(nil))
	}
	return &want{id: id, c: &c, raw: raw, hash: h}, nil
}

// buildHandlers turns the Xray JSON of an instance into handler configs.
func buildHandlers(c *Compiled) (*built, error) {
	b := &built{cfgs: map[string]*xcore.OutboundHandlerConfig{}}
	for _, p := range c.Outbounds {
		var oc conf.OutboundDetourConfig
		if err := json.Unmarshal(p.Config, &oc); err != nil {
			return nil, fmt.Errorf("outbound %s: %w", p.Tag, err)
		}
		cfg, err := oc.Build()
		if err != nil {
			return nil, fmt.Errorf("outbound %s: %w", p.Tag, err)
		}
		b.outs = append(b.outs, namedOut{p.Tag, cfg})
		b.cfgs[p.Tag] = cfg
	}
	for _, p := range c.Inbounds {
		var ic conf.InboundDetourConfig
		if err := json.Unmarshal(p.Config, &ic); err != nil {
			return nil, fmt.Errorf("inbound %s: %w", p.Tag, err)
		}
		cfg, err := ic.Build()
		if err != nil {
			return nil, fmt.Errorf("inbound %s: %w", p.Tag, err)
		}
		b.ins = append(b.ins, namedIn{p.Tag, cfg})
	}
	return b, nil
}

// ------------------------------------------------------------------ apply

// Apply makes Xray run exactly the given set.
//
// Algorithm: instances are compared by content hash. Unchanged ones are not
// touched. A changed instance is replaced (old torn down, new built; they
// share tags and ports so both cannot exist at once, and only that instance
// is interrupted). New instances are added outbounds first, then reverse
// portals, then inbounds; the whole routing table is switched once with
// SetRules; reverse bridges and health checks start after the switch;
// finally removed instances are torn down (inbound removed, established
// connections killed, outbounds removed, counters dropped). Any failure
// before the final step undoes the steps already taken, in reverse order,
// and re-installs the previous rules, so a failed Apply leaves the previous
// configuration running. The result of a successful Apply is written to the
// state directory.
func (d *Driver) Apply(ctx context.Context, rt driver.Runtime, set []driver.Rendered) (driver.ApplyResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	wants, badID, err := d.parseSet(set)
	if err != nil {
		res := driver.ApplyResult{Running: d.runningIDs(), Failed: map[string]string{}}
		res.Failed[badID] = err.Error()
		return res, fmt.Errorf("xray apply: %w", err)
	}
	res, err := d.reconcile(ctx, rt, wants)
	if err == nil {
		d.persist(rt, wants, false)
	}
	return res, err
}

func (d *Driver) runningIDs() []string {
	ids := make([]string, 0, len(d.state.inst))
	for id := range d.state.inst {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func sortedWantIDs(m map[string]*want) []string {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// composeRules builds the routing table of a set of instances.
func composeRules(wants map[string]*want) (head []json.RawMessage, bal json.RawMessage, err error) {
	var bals []json.RawMessage
	for _, id := range sortedWantIDs(wants) {
		head = append(head, wants[id].c.Rules...)
		bals = append(bals, wants[id].c.Balancers...)
	}
	if len(bals) > 0 {
		if bal, err = json.Marshal(bals); err != nil {
			return nil, nil, err
		}
	}
	return head, bal, nil
}

func (d *Driver) reconcile(ctx context.Context, rt driver.Runtime, wants map[string]*want) (driver.ApplyResult, error) {
	res := driver.ApplyResult{Failed: map[string]string{}}
	logf := d.logf(rt)
	old := d.state

	var added, changed, removed, same []string
	for _, id := range sortedWantIDs(wants) {
		o, ok := old.inst[id]
		switch {
		case !ok:
			added = append(added, id)
		case o.hash != wants[id].hash:
			changed = append(changed, id)
		default:
			same = append(same, id)
		}
	}
	for id := range old.inst {
		if _, ok := wants[id]; !ok {
			removed = append(removed, id)
		}
	}
	sort.Strings(removed)
	if len(added)+len(changed)+len(removed) == 0 {
		res.Running = d.runningIDs()
		return res, nil
	}

	// Build everything first: Xray's loader validates the configuration, and
	// nothing has been touched yet if it fails.
	builds := map[string]*built{}
	for _, id := range append(append([]string(nil), added...), changed...) {
		b, err := buildHandlers(wants[id].c)
		if err != nil {
			res.Failed[id] = err.Error()
			res.Running = d.runningIDs()
			return res, fmt.Errorf("xray apply: instance %s: %w", id, err)
		}
		builds[id] = b
	}
	head, bal, err := composeRules(wants)
	if err != nil {
		return res, fmt.Errorf("xray apply: %w", err)
	}
	if err := ctxErr(ctx); err != nil {
		res.Running = d.runningIDs()
		return res, err
	}

	var undo []func()
	rollback := func(id string, cause error) (driver.ApplyResult, error) {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
		res.Failed[id] = cause.Error()
		res.Running = d.runningIDs()
		res.Restarted, res.Disrupted = nil, nil
		return res, fmt.Errorf("xray apply: instance %s: %w (previous configuration restored)", id, cause)
	}

	// 1. Changed instances: tear the old one down (same tags and ports).
	for _, id := range changed {
		o := old.inst[id]
		d.teardown(o)
		undo = append(undo, func() {
			// Re-create the old instance; failures are logged only.
			if err := d.bringUp(rt, o); err != nil {
				logf("restoring instance %s: %v", o.id, err)
			}
		})
	}
	newLive := map[string]*live{}
	for _, id := range same {
		newLive[id] = old.inst[id]
	}
	// 2. New and changed instances: outbounds, portals, inbounds.
	for _, id := range append(append([]string(nil), added...), changed...) {
		l := &live{want: *wants[id], built: builds[id]}
		newLive[id] = l
		if err := d.setup(l); err != nil {
			d.teardown(l)
			return rollback(id, err)
		}
		undo = append(undo, func() { d.teardown(l) })
	}
	// 3. One routing switch.
	if err := d.host.SetRules(RulesTag, head, bal); err != nil {
		return rollback(firstOf(added, changed), fmt.Errorf("set rules: %w", err))
	}
	oldHead, oldBal := old.head, old.bal
	undo = append(undo, func() {
		if err := d.host.SetRules(RulesTag, oldHead, oldBal); err != nil {
			logf("restoring rules: %v", err)
		}
	})
	// 4. Post-switch start of bridges and health checks.
	for _, id := range append(append([]string(nil), added...), changed...) {
		l := newLive[id]
		if err := d.startAux(rt, l); err != nil {
			return rollback(id, err)
		}
		undo = append(undo, func() { d.stopAux(l) })
	}
	// 5. Removed instances: past the point of no return.
	for _, id := range removed {
		d.teardown(old.inst[id])
	}
	d.state = &state{inst: newLive, head: head, bal: bal}
	for id := range newLive {
		res.Running = append(res.Running, id)
	}
	sort.Strings(res.Running)
	res.Restarted = append([]string(nil), changed...)
	res.Disrupted = append([]string(nil), changed...)
	return res, nil
}

func firstOf(lists ...[]string) string {
	for _, l := range lists {
		if len(l) > 0 {
			return l[0]
		}
	}
	return ""
}

// setup registers the handlers of an instance: outbounds, then the portal
// outbound, then inbounds.
func (d *Driver) setup(l *live) error {
	absent := initialAbsent(l.c.Health)
	for _, o := range l.built.outs {
		if absent[o.tag] {
			continue
		}
		if err := d.host.AddOutbound(o.cfg); err != nil {
			return fmt.Errorf("add outbound %s: %w", o.tag, err)
		}
	}
	if rs := l.c.Reverse; rs != nil && rs.Role == "portal" {
		p, err := startPortal(d.host.OutboundManager(), rs.Tag, rs.Domain)
		if err != nil {
			return fmt.Errorf("start reverse portal: %w", err)
		}
		l.rev = p
	}
	for _, in := range l.built.ins {
		if err := d.host.AddInbound(in.cfg); err != nil {
			return fmt.Errorf("add inbound %s: %w", in.tag, err)
		}
	}
	return nil
}

// startAux starts what needs the routing table: the reverse bridge and the
// health checks.
func (d *Driver) startAux(rt driver.Runtime, l *live) error {
	if rs := l.c.Reverse; rs != nil && rs.Role == "bridge" {
		b, err := startBridge(d.host.Dispatcher(), rs.Tag, rs.Domain, d.logf(rt))
		if err != nil {
			return fmt.Errorf("start reverse bridge: %w", err)
		}
		l.rev = b
	}
	if hs := l.c.Health; hs != nil {
		l.health = newHealthRunner(d.host, *hs, l.built.cfgs, initialAbsent(hs), d.logf(rt))
		l.health.start()
	}
	return nil
}

func (d *Driver) stopAux(l *live) {
	if l.health != nil {
		l.health.stop()
		l.health = nil
	}
	if _, isBridge := l.rev.(*bridge); isBridge {
		l.rev.Close()
		l.rev = nil
	}
}

// bringUp re-creates an instance that was torn down (rollback path); the
// rules are already restored when it runs.
func (d *Driver) bringUp(rt driver.Runtime, l *live) error {
	b, err := buildHandlers(l.c)
	if err != nil {
		return err
	}
	l.built = b
	if err := d.setup(l); err != nil {
		d.teardown(l)
		return err
	}
	return d.startAux(rt, l)
}

// teardown removes an instance: stop health checks and reverse links, remove
// the inbounds (no new connections), kill the established ones, remove the
// outbounds (which closes them) and drop the counters, keeping their value
// so the cumulative counts never go backwards.
func (d *Driver) teardown(l *live) {
	if l.health != nil {
		l.health.stop()
		l.health = nil
	}
	if l.rev != nil {
		// A portal is registered as an outbound handler, not through
		// AddOutbound, so it is removed from the manager here. This must
		// happen outside portal.Close: the outbound manager holds its lock
		// while closing handlers during shutdown, and RemoveHandler would
		// deadlock against it (see portal.Close).
		if rs := l.c.Reverse; rs != nil && rs.Role == "portal" {
			_ = d.host.OutboundManager().RemoveHandler(context.Background(), rs.Tag)
		}
		l.rev.Close()
		l.rev = nil
	}
	var inTags []string
	for _, p := range l.c.Inbounds {
		inTags = append(inTags, p.Tag)
		_ = d.host.RemoveInbound(p.Tag)
	}
	if rs := l.c.Reverse; rs != nil && rs.Role == "bridge" {
		inTags = append(inTags, rs.Tag) // sessions relayed by the bridge enter under this tag
	}
	for _, t := range inTags {
		d.host.Kill(t)
	}
	for _, p := range l.c.Outbounds {
		_ = d.host.RemoveOutbound(p.Tag)
	}
	for _, t := range inTags {
		d.host.Kill(t) // anything accepted while the inbound was closing
	}
	d.harvestCounters(l)
}

func counterNames(kind, tag string) (up, down string) {
	return kind + ">>>" + tag + ">>>traffic>>>uplink", kind + ">>>" + tag + ">>>traffic>>>downlink"
}

func (d *Driver) harvestCounters(l *live) {
	drop := func(kind, tag string, keep bool) {
		up, down := counterNames(kind, tag)
		for _, n := range []string{up, down} {
			if keep {
				if v, ok := d.host.Counter(n); ok {
					d.base[n] += v
				}
			}
			d.host.DropCounter(n)
		}
	}
	for _, p := range l.c.Inbounds {
		drop("inbound", p.Tag, p.Tag == l.c.Stats.InboundTag)
	}
	for _, p := range l.c.Outbounds {
		keep := false
		for _, t := range l.c.Stats.OutboundTags {
			if t == p.Tag {
				keep = true
			}
		}
		drop("outbound", p.Tag, keep)
	}
}

// ------------------------------------------------------------------ persistence

type persisted struct {
	Instances []persistedInst `json:"instances"`
}

type persistedInst struct {
	ID       string          `json:"id"`
	Hash     string          `json:"hash"`
	Compiled json.RawMessage `json:"compiled"`
}

const (
	currentFile  = "xray-current.json"
	previousFile = "xray-previous.json"
)

func marshalSet(wants map[string]*want) []byte {
	var p persisted
	for _, id := range sortedWantIDs(wants) {
		w := wants[id]
		p.Instances = append(p.Instances, persistedInst{ID: id, Hash: w.hash, Compiled: w.raw})
	}
	b, _ := json.Marshal(p)
	return b
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// persist records the applied set. The set that was running before becomes
// the rollback target; re-applying an identical set keeps it.
func (d *Driver) persist(rt driver.Runtime, wants map[string]*want, isRollback bool) {
	if rt.StateDir == "" {
		return
	}
	if err := os.MkdirAll(rt.StateDir, 0o700); err != nil {
		d.logf(rt)("state dir: %v", err)
		return
	}
	cur := filepath.Join(rt.StateDir, currentFile)
	prev := filepath.Join(rt.StateDir, previousFile)
	data := marshalSet(wants)
	if isRollback {
		_ = os.Remove(prev)
	} else if old, err := os.ReadFile(cur); err == nil && !bytes.Equal(old, data) {
		if err := writeAtomic(prev, old); err != nil {
			d.logf(rt)("write %s: %v", previousFile, err)
		}
	}
	if err := writeAtomic(cur, data); err != nil {
		d.logf(rt)("write %s: %v", currentFile, err)
	}
}

func loadSet(path string) (map[string]*want, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p persisted
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	out := map[string]*want{}
	for _, pi := range p.Instances {
		w, err := wantFromRaw(pi.ID, pi.Compiled, pi.Hash)
		if err != nil {
			return nil, fmt.Errorf("instance %s: %w", pi.ID, err)
		}
		if w != nil {
			out[pi.ID] = w
		}
	}
	return out, nil
}

// Rollback re-applies the configuration that was running before the most
// recent successful Apply (xray-previous.json in the state directory). With
// nothing to go back to it is a no-op.
func (d *Driver) Rollback(ctx context.Context, rt driver.Runtime) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if rt.StateDir == "" {
		return errors.New("xray rollback: no state directory")
	}
	wants, err := loadSet(filepath.Join(rt.StateDir, previousFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("xray rollback: %w", err)
	}
	if _, err := d.reconcile(ctx, rt, wants); err != nil {
		return err
	}
	d.persist(rt, wants, true)
	return nil
}

// ------------------------------------------------------------------ stop, stats, health

// Stop removes the given instances (all when ids is empty).
func (d *Driver) Stop(ctx context.Context, rt driver.Runtime, ids ...string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	keep := map[string]*want{}
	drop := map[string]bool{}
	for _, id := range ids {
		drop[id] = true
	}
	for id, l := range d.state.inst {
		if len(ids) == 0 || drop[id] {
			continue
		}
		w := l.want
		keep[id] = &w
	}
	_, err := d.reconcile(ctx, rt, keep)
	return err
}

// Stats returns cumulative counters per instance. Inbound counters are used
// when the instance has a user facing or tunnel inbound; a reverse bridge has
// none and reports its outbound (to the targets) instead.
func (d *Driver) Stats(ctx context.Context, rt driver.Runtime) ([]driver.Counter, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	read := func(name string) uint64 {
		v, _ := d.host.Counter(name)
		return v + d.base[name]
	}
	var out []driver.Counter
	for _, id := range d.runningIDs() {
		l := d.state.inst[id]
		c := driver.Counter{InstanceID: id}
		st := l.c.Stats
		hasInbound := false
		for _, p := range l.c.Inbounds {
			if p.Tag == st.InboundTag {
				hasInbound = true
			}
		}
		if hasInbound {
			up, down := counterNames("inbound", st.InboundTag)
			c.BytesUp, c.BytesDown = read(up), read(down)
		} else {
			for _, t := range st.OutboundTags {
				up, down := counterNames("outbound", t)
				c.BytesUp += read(up)
				c.BytesDown += read(down)
			}
		}
		if st.InboundTag != "" {
			c.ConnsActive, c.ConnsTotal = d.host.Conns(st.InboundTag)
		}
		out = append(out, c)
	}
	return out, nil
}

// Health reports what is running. Listening is checked by trying to bind
// every claimed port: an "address in use" answer means the kernel's listener
// is there (a connect probe would make the forward open a real connection
// to its target).
func (d *Driver) Health(ctx context.Context, rt driver.Runtime) driver.Health {
	d.mu.Lock()
	defer d.mu.Unlock()
	h := driver.Health{Instances: map[string]driver.InstanceHealth{}}
	for id, l := range d.state.inst {
		ih := driver.InstanceHealth{Running: true, ConfigHash: l.hash, Listening: true}
		for _, cl := range l.c.Claims {
			if !portBusy(cl) {
				ih.Listening = false
				ih.Err = fmt.Sprintf("%s %s:%d is not listening", cl.Proto, cl.Addr, cl.Port)
				break
			}
		}
		if l.health != nil {
			ih.Targets = l.health.targetStates()
		}
		h.Instances[id] = ih
	}
	return h
}

func portBusy(cl Claim) bool {
	addr := net.JoinHostPort(cl.Addr, fmt.Sprint(cl.Port))
	var err error
	switch cl.Proto {
	case "udp":
		var pc net.PacketConn
		if pc, err = net.ListenPacket("udp", addr); err == nil {
			pc.Close()
			return false
		}
	default:
		var ln net.Listener
		if ln, err = net.Listen("tcp", addr); err == nil {
			ln.Close()
			return false
		}
	}
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "in use") || strings.Contains(m, "only one usage")
}
