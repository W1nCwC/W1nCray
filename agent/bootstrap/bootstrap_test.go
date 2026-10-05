package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/portledger"
	"github.com/W1nCwC/W1nCray/agent/reconcile"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/core"
)

// ---- fake driver ---------------------------------------------------------
//
// fakeDriver is a minimal in-process driver: it binds a real listener for every
// claimed port, so the reconciler's bind probes and health checks see a real
// listener. It is defined here rather than reused from
// agent/reconcile/internal/testdriver because Go's internal-package rule makes
// that package unimportable from agent/bootstrap.

type fakeDriver struct {
	mu      sync.Mutex
	current map[string]*fakeRun
	good    map[string]driver.Artifact
}

type fakeRun struct {
	art driver.Artifact
	ls  []net.Listener
	pcs []net.PacketConn
}

func newFakeDriver() *fakeDriver {
	return &fakeDriver{current: map[string]*fakeRun{}, good: map[string]driver.Artifact{}}
}

func (f *fakeDriver) Caps() driver.Caps {
	return driver.Caps{
		Name:     spec.EngineGost,
		Kinds:    []spec.Kind{spec.KindForward},
		Network:  []string{"tcp", "udp"},
		Stats:    "counters",
		Reload:   "hot",
		External: false,
	}
}

func (f *fakeDriver) Validate(spec.Instance) error { return nil }

func (f *fakeDriver) Render(in spec.Instance) (driver.Artifact, error) {
	b, err := json.Marshal(in)
	if err != nil {
		return driver.Artifact{}, err
	}
	sum := sha256.Sum256(b)
	art := driver.Artifact{Files: map[string][]byte{in.ID + ".json": b}, Hash: hex.EncodeToString(sum[:])}
	if in.Listen != nil {
		claims, err := portledger.Expand("tcp", in.Listen.Addr, in.Listen.Ports, in.ID)
		if err != nil {
			return driver.Artifact{}, err
		}
		art.PortClaims = claims
	}
	return art, nil
}

func (f *fakeDriver) Apply(ctx context.Context, rt driver.Runtime, set []driver.Rendered) (driver.ApplyResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	prev := f.current
	prevData := map[string]driver.Artifact{}
	for id, r := range prev {
		prevData[id] = r.art
	}
	next := map[string]*fakeRun{}
	res := driver.ApplyResult{Failed: map[string]string{}}
	for _, r := range set {
		id := r.Instance.ID
		if old, ok := prev[id]; ok && old.art.Hash == r.Artifact.Hash {
			next[id] = old
			res.Running = append(res.Running, id)
			continue
		}
		if old, ok := prev[id]; ok {
			closeRun(old)
		}
		run, err := f.start(r.Artifact)
		if err != nil {
			res.Failed[id] = err.Error()
			continue
		}
		next[id] = run
		res.Running = append(res.Running, id)
	}
	for id, old := range prev {
		if _, keep := next[id]; !keep {
			closeRun(old)
		}
	}
	f.good = prevData
	f.current = next
	sort.Strings(res.Running)
	return res, nil
}

func (f *fakeDriver) start(art driver.Artifact) (*fakeRun, error) {
	run := &fakeRun{art: art}
	for _, c := range art.PortClaims {
		hp := net.JoinHostPort(c.Addr, strconv.Itoa(c.Port))
		if c.Proto == "udp" {
			pc, err := net.ListenPacket("udp", hp)
			if err != nil {
				closeRun(run)
				return nil, err
			}
			run.pcs = append(run.pcs, pc)
			continue
		}
		l, err := net.Listen("tcp", hp)
		if err != nil {
			closeRun(run)
			return nil, err
		}
		run.ls = append(run.ls, l)
	}
	return run, nil
}

func closeRun(r *fakeRun) {
	for _, l := range r.ls {
		_ = l.Close()
	}
	for _, pc := range r.pcs {
		_ = pc.Close()
	}
	r.ls, r.pcs = nil, nil
}

func (f *fakeDriver) Rollback(ctx context.Context, rt driver.Runtime) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.current {
		closeRun(r)
	}
	next := map[string]*fakeRun{}
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

func (f *fakeDriver) Stop(ctx context.Context, rt driver.Runtime, ids ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, id := range ids {
		if r, ok := f.current[id]; ok {
			closeRun(r)
			delete(f.current, id)
		}
	}
	return nil
}

func (f *fakeDriver) Stats(ctx context.Context, rt driver.Runtime) ([]driver.Counter, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []driver.Counter
	for id := range f.current {
		out = append(out, driver.Counter{InstanceID: id, BytesUp: 1, BytesDown: 2})
	}
	return out, nil
}

func (f *fakeDriver) Health(ctx context.Context, rt driver.Runtime) driver.Health {
	f.mu.Lock()
	defer f.mu.Unlock()
	h := driver.Health{Instances: map[string]driver.InstanceHealth{}}
	for id, r := range f.current {
		h.Instances[id] = driver.InstanceHealth{Running: true, Listening: true, ConfigHash: r.art.Hash}
	}
	return h
}

var _ driver.Driver = (*fakeDriver)(nil)

// ---- test helpers --------------------------------------------------------

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func writeDesired(t *testing.T, path string, instances string) {
	t.Helper()
	body := fmt.Sprintf(`{"version":%d,"revision":1,"instances":[%s]}`, spec.Version, instances)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func dialOK(addr string) bool {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// ---- tests ---------------------------------------------------------------

// TestBootApplyFileReportShutdown exercises the whole assembly with a fake
// engine: Boot, ApplyFile, the report, a second apply that removes the
// instance, and Shutdown.
func TestBootApplyFileReportShutdown(t *testing.T) {
	fd := newFakeDriver()
	orig := driverBuilder
	driverBuilder = func(c *core.Core, pol spec.Policy, log driver.Logger) (map[string]driver.Driver, error) {
		return map[string]driver.Driver{spec.EngineGost: fd}, nil
	}
	t.Cleanup(func() { driverBuilder = orig })

	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	kernelsDir := filepath.Join(dir, "kernels")
	desiredPath := filepath.Join(dir, "desired.json")

	rt, err := Boot(Options{StateDir: stateDir, KernelsDir: kernelsDir}, nil)
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}

	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	inst := fmt.Sprintf(`{"id":"fwd1","enabled":true,"engine":"gost","kind":"forward","listen":{"addr":"127.0.0.1","ports":"%d"},"targets":[{"host":"1.1.1.1","ports":"80"}]}`, port)
	writeDesired(t, desiredPath, inst)

	rep, err := rt.ApplyFile(desiredPath)
	if err != nil {
		t.Fatalf("ApplyFile: %v (report %+v)", err, rep)
	}
	if rep.Status != reconcile.StatusApplied {
		t.Fatalf("status = %s, want applied (%s)", rep.Status, rep.Message)
	}
	if len(rep.Instances) != 1 || rep.Instances[0].State != reconcile.StateRunning {
		t.Fatalf("instances = %+v", rep.Instances)
	}
	if !dialOK(addr) {
		t.Fatalf("listen port %s is not reachable after apply", addr)
	}

	// Second apply: remove the instance; the port must close.
	writeDesired(t, desiredPath, "")
	rep2, err := rt.ApplyFile(desiredPath)
	if err != nil {
		t.Fatalf("second ApplyFile: %v (report %+v)", err, rep2)
	}
	if rep2.Status != reconcile.StatusApplied {
		t.Fatalf("second status = %s, want applied (%s)", rep2.Status, rep2.Message)
	}
	if dialOK(addr) {
		t.Fatalf("listen port %s is still reachable after removal", addr)
	}

	if err := rt.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

// TestApplyFileStrict rejects a desired state with an unknown field.
func TestApplyFileStrict(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"revision":1,"instances":[],"bogus":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rt := &Runtime{}
	if _, err := rt.ApplyFile(path); err == nil {
		t.Fatal("expected an error for an unknown field")
	}
}
