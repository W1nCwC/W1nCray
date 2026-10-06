// Package testdriver provides Fake, a configurable in-process driver for
// testing the reconciler without any kernel. It binds real listeners for the
// claimed ports, so the port ledger's bind probes see what a real engine would
// produce.
package testdriver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/portledger"
	"github.com/W1nCwC/W1nCray/agent/spec"
)

// Fake implements driver.Driver.
type Fake struct {
	CapsV driver.Caps

	mu sync.Mutex

	// ValidateErr, if set, is consulted by Validate.
	ValidateErr func(spec.Instance) error
	// FailApply maps instance id -> error text; Apply returns an error (and
	// changes nothing) if the set contains such an instance.
	FailApply map[string]string
	// FailInstance maps instance id -> text reported in ApplyResult.Failed.
	FailInstance map[string]string
	// PanicApply makes Apply panic.
	PanicApply bool
	// RollbackErr is returned by Rollback.
	RollbackErr error
	// NoBind makes Apply skip binding listeners while Health still claims
	// Listening (a lying driver).
	NoBind map[string]bool
	// NotReadyCalls: the first N Health calls report instances as not running.
	NotReadyCalls int
	// WrongHash makes Health report a different config hash for every
	// instance; WrongHashFor does it for the named ones only.
	WrongHash    bool
	WrongHashFor map[string]bool
	// NotRunning keeps the named instances permanently "not running".
	NotRunning map[string]bool
	// Extra instances reported by Health that are not in the applied set.
	Extra []string
	// ApplyDelay makes Apply sleep (to test serialisation).
	ApplyDelay time.Duration
	// RollbackCtxErr records ctx.Err() as seen by the last Rollback call.
	RollbackCtxErr error

	current map[string]*running        // instance id -> state
	good    map[string]driver.Rendered // set before the last successful Apply
	calls   []string
	health  int

	inApply, maxApply int32
}

type running struct {
	r         driver.Rendered
	listeners []io.Closer
}

// New returns a fake driver with the given capabilities.
func New(name string, caps driver.Caps) *Fake {
	caps.Name = name
	return &Fake{CapsV: caps, current: map[string]*running{}, good: map[string]driver.Rendered{}}
}

// FullCaps is a capability set that supports everything except what a test
// removes afterwards.
func FullCaps() driver.Caps {
	return driver.Caps{
		Kinds:   []spec.Kind{spec.KindForward, spec.KindTunnelEntry, spec.KindTunnelExit, spec.KindReversePortal, spec.KindReverseBridge},
		Network: []string{"tcp", "udp"}, TunnelTypes: []string{"tcp", "tls", "ws", "wss"},
		Reverse: true, ProxyIn: true, ProxyOut: true,
		Balance: []string{"round_robin", "random"}, HealthCheck: "active", Stats: "counters", Reload: "hot",
	}
}

func (f *Fake) Caps() driver.Caps { return f.CapsV }

func (f *Fake) record(s string) {
	f.mu.Lock()
	f.calls = append(f.calls, s)
	f.mu.Unlock()
}

// Calls returns the recorded calls ("apply:a,b", "rollback", "stop:", ...).
func (f *Fake) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// CountCalls counts recorded calls with the given prefix.
func (f *Fake) CountCalls(prefix string) int {
	n := 0
	for _, c := range f.Calls() {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

// MaxConcurrentApply is the highest number of simultaneous Apply calls seen.
func (f *Fake) MaxConcurrentApply() int { return int(atomic.LoadInt32(&f.maxApply)) }

// Running returns the ids currently running, sorted.
func (f *Fake) Running() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return sortedIDs(f.current)
}

func sortedIDs(m map[string]*running) []string {
	out := make([]string, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Validate implements driver.Driver.
func (f *Fake) Validate(in spec.Instance) error {
	f.record("validate:" + in.ID)
	if f.ValidateErr != nil {
		return f.ValidateErr(in)
	}
	return nil
}

// Render implements driver.Driver. The "config file" is the instance JSON
// including its secret, which lets tests prove the reconciler never leaks it.
func (f *Fake) Render(in spec.Instance) (driver.Artifact, error) {
	f.record("render:" + in.ID)
	b, err := json.Marshal(in)
	if err != nil {
		return driver.Artifact{}, err
	}
	sum := sha256.Sum256(append([]byte(f.CapsV.Name+"\x00"), b...))
	art := driver.Artifact{Files: map[string][]byte{in.ID + ".json": b}, Hash: hex.EncodeToString(sum[:])}
	nets := in.Network
	if len(nets) == 0 {
		nets = []string{"tcp"}
	}
	add := func(proto, addr, ports string) error {
		cs, err := portledger.Expand(proto, addr, ports, in.ID)
		art.PortClaims = append(art.PortClaims, cs...)
		return err
	}
	if in.Kind != spec.KindReverseBridge && in.Listen != nil {
		for _, n := range nets {
			if err := add(n, in.Listen.Addr, in.Listen.Ports); err != nil {
				return driver.Artifact{}, err
			}
		}
	}
	if in.Tunnel != nil && in.Tunnel.Listen != "" {
		host, port, err := net.SplitHostPort(in.Tunnel.Listen)
		if err != nil {
			return driver.Artifact{}, err
		}
		if err := add("tcp", host, port); err != nil {
			return driver.Artifact{}, err
		}
	}
	return art, nil
}

// Apply implements driver.Driver.
func (f *Fake) Apply(ctx context.Context, rt driver.Runtime, set []driver.Rendered) (driver.ApplyResult, error) {
	ids := make([]string, len(set))
	for i, r := range set {
		ids[i] = r.Instance.ID
	}
	sort.Strings(ids)
	f.record("apply:" + strings.Join(ids, ","))
	n := atomic.AddInt32(&f.inApply, 1)
	defer atomic.AddInt32(&f.inApply, -1)
	for {
		m := atomic.LoadInt32(&f.maxApply)
		if n <= m || atomic.CompareAndSwapInt32(&f.maxApply, m, n) {
			break
		}
	}
	if f.ApplyDelay > 0 {
		time.Sleep(f.ApplyDelay)
	}
	if f.PanicApply {
		panic("fake driver exploded")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, id := range ids {
		if msg, bad := f.FailApply[id]; bad {
			return driver.ApplyResult{}, errors.New(msg)
		}
	}
	prev := f.current
	prevData := map[string]driver.Rendered{}
	for id, r := range prev {
		prevData[id] = r.r
	}
	next := map[string]*running{}
	res := driver.ApplyResult{Failed: map[string]string{}}
	for _, r := range set {
		id := r.Instance.ID
		if old, ok := prev[id]; ok && old.r.Artifact.Hash == r.Artifact.Hash {
			next[id] = old // unchanged: keep running
			res.Running = append(res.Running, id)
			continue
		}
		if msg, bad := f.FailInstance[id]; bad {
			res.Failed[id] = msg
			if old, ok := prev[id]; ok {
				closeAll(old)
			}
			continue
		}
		if old, ok := prev[id]; ok {
			closeAll(old)
			res.Restarted = append(res.Restarted, id)
		}
		run, err := f.start(r)
		if err != nil {
			res.Failed[id] = err.Error()
			continue
		}
		next[id] = run
		res.Running = append(res.Running, id)
	}
	for id, old := range prev {
		if _, keep := next[id]; !keep {
			closeAll(old)
		}
	}
	f.good = prevData
	f.current = next
	sort.Strings(res.Running)
	return res, nil
}

func (f *Fake) start(r driver.Rendered) (*running, error) {
	run := &running{r: r}
	if f.NoBind[r.Instance.ID] {
		return run, nil
	}
	for _, c := range r.Artifact.PortClaims {
		hp := net.JoinHostPort(c.Addr, strconv.Itoa(c.Port))
		switch c.Proto {
		case "udp":
			pc, err := net.ListenPacket("udp", hp)
			if err != nil {
				closeAll(run)
				return nil, err
			}
			run.listeners = append(run.listeners, pc)
		default:
			l, err := net.Listen("tcp", hp)
			if err != nil {
				closeAll(run)
				return nil, err
			}
			run.listeners = append(run.listeners, l)
		}
	}
	return run, nil
}

func closeAll(r *running) {
	for _, l := range r.listeners {
		_ = l.Close()
	}
	r.listeners = nil
}

// Rollback implements driver.Driver: back to the set before the last Apply.
func (f *Fake) Rollback(ctx context.Context, rt driver.Runtime) error {
	f.record("rollback")
	f.mu.Lock()
	f.RollbackCtxErr = ctx.Err()
	f.mu.Unlock()
	if f.RollbackErr != nil {
		return f.RollbackErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.current {
		closeAll(r)
	}
	next := map[string]*running{}
	for id, g := range f.good {
		run, err := f.start(g)
		if err != nil {
			return err
		}
		next[id] = run
	}
	f.current = next
	return nil
}

// Stop implements driver.Driver.
func (f *Fake) Stop(ctx context.Context, rt driver.Runtime, ids ...string) error {
	f.record("stop:" + strings.Join(ids, ","))
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(ids) == 0 {
		for id, r := range f.current {
			closeAll(r)
			delete(f.current, id)
		}
		return nil
	}
	for _, id := range ids {
		if r, ok := f.current[id]; ok {
			closeAll(r)
			delete(f.current, id)
		}
	}
	return nil
}

// Stats implements driver.Driver.
func (f *Fake) Stats(ctx context.Context, rt driver.Runtime) ([]driver.Counter, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []driver.Counter
	for _, id := range sortedIDs(f.current) {
		out = append(out, driver.Counter{InstanceID: id, BytesUp: 1, BytesDown: 2})
	}
	return out, nil
}

// Health implements driver.Driver.
func (f *Fake) Health(ctx context.Context, rt driver.Runtime) driver.Health {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.health++
	h := driver.Health{Instances: map[string]driver.InstanceHealth{}}
	for id, r := range f.current {
		ih := driver.InstanceHealth{Running: f.health > f.NotReadyCalls, ConfigHash: r.r.Artifact.Hash, Listening: true}
		if f.WrongHash || f.WrongHashFor[id] {
			ih.ConfigHash = "deadbeef"
		}
		if f.NotRunning[id] {
			ih.Running, ih.Err = false, "crashed"
		}
		if !ih.Running {
			ih.Err = "starting"
		}
		h.Instances[id] = ih
	}
	for _, id := range f.Extra {
		h.Instances[id] = driver.InstanceHealth{Running: true}
	}
	return h
}

// Kill closes the listeners of one instance without telling anyone (a crash).
func (f *Fake) Kill(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.current[id]; ok {
		closeAll(r)
	}
}

// Drop forgets an instance entirely (the engine lost it).
func (f *Fake) Drop(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.current[id]; ok {
		closeAll(r)
		delete(f.current, id)
	}
}

// Close releases every listener.
func (f *Fake) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.current {
		closeAll(r)
	}
}

// FreePort returns a TCP/UDP port that was free a moment ago on 127.0.0.1.
func FreePort(t testing.TB) int {
	t.Helper()
	for i := 0; i < 50; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		l.Close()
		pc, err := net.ListenPacket("udp", "127.0.0.1:"+strconv.Itoa(port))
		if err != nil {
			continue
		}
		pc.Close()
		return port
	}
	t.Fatal("no free port")
	return 0
}

var _ driver.Driver = (*Fake)(nil)
