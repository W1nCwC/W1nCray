package realm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/spec"
)

// fakeSup is an in-memory Supervisor that mimics what matters of realm: it
// reads the -c file when a process starts and "listens" on its endpoints,
// except on ports in unbindable (realm's endpoint task dies while the process
// lives on, as with a bad certificate path or a lost bind race). foreign
// ports are owned by some other process: always "in use", never bound by us.
type fakeSup struct {
	mu         sync.Mutex
	procs      map[string]*fakeProc
	events     []string
	foreign    map[int]bool
	unbindable map[int]bool
	failFor    map[string]error // Start error per process id
}

type fakeProc struct {
	spec      driver.ProcSpec
	listening map[string]bool // "host:port"
	cfgHash   string
}

func newFakeSup() *fakeSup {
	return &fakeSup{procs: map[string]*fakeProc{}, foreign: map[int]bool{}, unbindable: map[int]bool{}, failFor: map[string]error{}}
}

func (f *fakeSup) Start(ctx context.Context, p driver.ProcSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failFor[p.ID]; err != nil {
		delete(f.failFor, p.ID) // one-shot
		return err
	}
	if old, ok := f.procs[p.ID]; ok {
		if reflect.DeepEqual(old.spec, p) {
			f.events = append(f.events, "keep "+p.ID)
			return nil
		}
		f.events = append(f.events, "stop "+p.ID)
	}
	if len(p.Args) != 2 || p.Args[0] != "-c" {
		return fmt.Errorf("unexpected args %v", p.Args)
	}
	b, err := os.ReadFile(p.Args[1])
	if err != nil {
		return err
	}
	var cfg fileConf
	if err := json.Unmarshal(b, &cfg); err != nil {
		return err
	}
	pr := &fakeProc{spec: p, listening: map[string]bool{}}
	for _, ep := range cfg.Endpoints {
		port, _ := strconv.Atoi(ep.Listen[strings.LastIndex(ep.Listen, ":")+1:])
		if f.foreign[port] || f.unbindable[port] {
			continue
		}
		pr.listening[ep.Listen] = true
	}
	f.procs[p.ID] = pr
	f.events = append(f.events, "start "+p.ID)
	return nil
}

func (f *fakeSup) Stop(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.procs, id)
	f.events = append(f.events, "stop "+id)
	return nil
}

func (f *fakeSup) Signal(id string, sig os.Signal) error { return nil }

func (f *fakeSup) Status(id string) driver.ProcStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.procs[id]; ok {
		return driver.ProcStatus{Running: true, PID: 1}
	}
	return driver.ProcStatus{LastExit: "exit status 101"}
}

func (f *fakeSup) kill(id string) {
	f.mu.Lock()
	delete(f.procs, id)
	f.mu.Unlock()
}

func (f *fakeSup) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.events
	f.events = nil
	return e
}

// inUse is the fake's bind probe: something (ours or foreign) holds the port.
func (f *fakeSup) inUse(c driver.PortClaim) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.foreign[c.Port] {
		return true
	}
	key := net_JoinHostPort(c.Addr, c.Port)
	for _, p := range f.procs {
		if p.listening[key] {
			return true
		}
	}
	return false
}

func net_JoinHostPort(addr string, port int) string {
	if strings.Contains(addr, ":") {
		return "[" + addr + "]:" + strconv.Itoa(port)
	}
	return addr + ":" + strconv.Itoa(port)
}

type env struct {
	d   *Driver
	sup *fakeSup
	rt  driver.Runtime
}

func newEnv(t *testing.T) *env {
	t.Helper()
	sup := newFakeSup()
	d := New(Options{ReadyTimeout: 400 * time.Millisecond})
	d.opts.probeBinary = func(ctx context.Context, path string) (BinaryInfo, error) {
		return BinaryInfo{Version: "2.9.6", Features: []string{"brutal", "batched-udp", "proxy", "balance", "transport", "multi-thread"}}, nil
	}
	d.opts.portInUse = sup.inUse
	d.opts.noStartGrace = true
	return &env{d: d, sup: sup, rt: driver.Runtime{
		Kernel:   driver.Installed{Path: filepath.Join(t.TempDir(), "realm"), Version: "v2.9.6"},
		StateDir: filepath.Join(t.TempDir(), "state"),
		Sup:      sup,
	}}
}

func (e *env) render(t *testing.T, ins ...spec.Instance) []driver.Rendered {
	t.Helper()
	var out []driver.Rendered
	for _, in := range ins {
		a, err := e.d.Render(in)
		if err != nil {
			t.Fatalf("Render %s: %v", in.ID, err)
		}
		out = append(out, driver.Rendered{Instance: in, Artifact: a})
	}
	return out
}

func (e *env) apply(t *testing.T, ins ...spec.Instance) (driver.ApplyResult, error) {
	t.Helper()
	return e.d.Apply(context.Background(), e.rt, e.render(t, ins...))
}

func ids(s []string) string {
	c := append([]string(nil), s...)
	sort.Strings(c)
	return strings.Join(c, ",")
}

func TestApplyOneProcessPerInstance(t *testing.T) {
	e := newEnv(t)
	a := fwd("alpha", "127.0.0.1", "8001", tg("10.0.0.1", "80", 0))
	b := fwd("beta", "127.0.0.1", "8002-8003", tg("10.0.0.2", "80-81", 0))
	res, err := e.apply(t, a, b)
	if err != nil {
		t.Fatalf("Apply: %v (%+v)", err, res)
	}
	if ids(res.Running) != "alpha,beta" || len(res.Failed) != 0 || len(res.Restarted) != 0 || len(res.Disrupted) != 0 {
		t.Fatalf("result %+v", res)
	}
	if got := ids(e.sup.take()); got != "start realm/alpha,start realm/beta" {
		t.Fatalf("events %s", got)
	}
	for _, id := range []string{"alpha", "beta"} {
		p := e.sup.procs["realm/"+id].spec
		cfg := filepath.Join(e.rt.StateDir, "run", id, "realm.json")
		if p.Path != e.rt.Kernel.Path || !reflect.DeepEqual(p.Args, []string{"-c", cfg}) {
			t.Errorf("%s: path/args = %s %v", id, p.Path, p.Args)
		}
		if !p.Restart.Always || p.Restart.MinBackoff <= 0 || p.Restart.MaxBackoff <= 0 || p.StopTimeout <= 0 {
			t.Errorf("%s: restart policy %+v", id, p.Restart)
		}
		if p.LogFile != filepath.Join(e.rt.StateDir, "logs", id+".log") {
			t.Errorf("%s: logfile %s", id, p.LogFile)
		}
		for _, kv := range p.Env {
			if strings.HasPrefix(kv, "REALM_CONF") {
				t.Errorf("%s: REALM_CONF must never be set", id)
			}
		}
		// Hash in the env makes a changed config a changed spec.
		if len(p.Env) != 1 || !strings.HasPrefix(p.Env[0], "W1NCRAY_CONFIG_HASH=") {
			t.Errorf("%s: env %v", id, p.Env)
		}
		if runtime.GOOS != "windows" {
			for _, f := range []string{cfg, filepath.Join(e.rt.StateDir, "state.json"), filepath.Join(e.rt.StateDir, "good", id, "realm.json")} {
				st, err := os.Stat(f)
				if err != nil || st.Mode().Perm() != 0o600 {
					t.Errorf("%s: mode %v err %v", f, st.Mode(), err)
				}
			}
			for _, d := range []string{filepath.Dir(cfg), e.rt.StateDir} {
				if st, _ := os.Stat(d); st.Mode().Perm() != 0o700 {
					t.Errorf("%s: dir mode %v", d, st.Mode())
				}
			}
		}
	}
	h := e.d.Health(context.Background(), e.rt)
	if len(h.Instances) != 2 || !h.Instances["alpha"].Running || !h.Instances["alpha"].Listening || h.Instances["alpha"].Err != "" {
		t.Fatalf("health %+v", h)
	}
}

func TestApplyUnchangedIsUntouched(t *testing.T) {
	e := newEnv(t)
	a := fwd("alpha", "127.0.0.1", "8001", tg("10.0.0.1", "80", 0))
	b := fwd("beta", "127.0.0.1", "8002", tg("10.0.0.2", "80", 0))
	if _, err := e.apply(t, a, b); err != nil {
		t.Fatal(err)
	}
	e.sup.take()
	res, err := e.apply(t, a, b)
	if err != nil {
		t.Fatal(err)
	}
	if ev := e.sup.take(); len(ev) != 0 {
		t.Fatalf("an identical Apply touched the supervisor: %v", ev)
	}
	if ids(res.Running) != "alpha,beta" || len(res.Restarted) != 0 || len(res.Disrupted) != 0 {
		t.Fatalf("result %+v", res)
	}
}

func TestApplyChangeRestartsOnlyThatInstance(t *testing.T) {
	e := newEnv(t)
	a := fwd("alpha", "127.0.0.1", "8001", tg("10.0.0.1", "80", 0))
	b := fwd("beta", "127.0.0.1", "8002", tg("10.0.0.2", "80", 0))
	if _, err := e.apply(t, a, b); err != nil {
		t.Fatal(err)
	}
	e.sup.take()
	a2 := mut(a, func(i *spec.Instance) { i.Targets[0].Host = "10.0.0.99" })
	res, err := e.apply(t, a2, b)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(e.sup.take(), ","); got != "stop realm/alpha,start realm/alpha" {
		t.Fatalf("events %s (beta must not appear)", got)
	}
	if ids(res.Restarted) != "alpha" || ids(res.Disrupted) != "alpha" || ids(res.Running) != "alpha,beta" {
		t.Fatalf("result %+v", res)
	}
	h := e.d.Health(context.Background(), e.rt)
	if h.Instances["alpha"].ConfigHash == "" || h.Instances["alpha"].ConfigHash == h.Instances["beta"].ConfigHash {
		t.Fatalf("config hashes %+v", h)
	}
	art, _ := e.d.Render(a2)
	if h.Instances["alpha"].ConfigHash != art.Hash {
		t.Fatalf("health reports %s, rendered %s", h.Instances["alpha"].ConfigHash, art.Hash)
	}
}

func TestApplyRemovesAndDisables(t *testing.T) {
	e := newEnv(t)
	a := fwd("alpha", "127.0.0.1", "8001", tg("10.0.0.1", "80", 0))
	b := fwd("beta", "127.0.0.1", "8002", tg("10.0.0.2", "80", 0))
	c := fwd("gamma", "127.0.0.1", "8003", tg("10.0.0.3", "80", 0))
	if _, err := e.apply(t, a, b, c); err != nil {
		t.Fatal(err)
	}
	e.sup.take()
	bOff := mut(b, func(i *spec.Instance) { i.Enabled = false })
	res, err := e.apply(t, a, bOff) // gamma missing, beta disabled
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(e.sup.take()); got != "stop realm/beta,stop realm/gamma" {
		t.Fatalf("events %s", got)
	}
	if ids(res.Running) != "alpha" || ids(res.Disrupted) != "beta,gamma" || len(res.Restarted) != 0 {
		t.Fatalf("result %+v", res)
	}
	for _, id := range []string{"beta", "gamma"} {
		if _, err := os.Stat(filepath.Join(e.rt.StateDir, "run", id)); !os.IsNotExist(err) {
			t.Errorf("run dir of %s still exists (it holds the ws token)", id)
		}
	}
	if h := e.d.Health(context.Background(), e.rt); len(h.Instances) != 1 {
		t.Fatalf("health %+v", h)
	}
	// Empty set stops everything.
	if _, err := e.apply(t); err != nil {
		t.Fatal(err)
	}
	if len(e.sup.procs) != 0 {
		t.Fatalf("processes left: %v", e.sup.procs)
	}
}

func TestApplyFailureRestoresLastGood(t *testing.T) {
	e := newEnv(t)
	a := fwd("alpha", "127.0.0.1", "8001", tg("10.0.0.1", "80", 0))
	b := fwd("beta", "127.0.0.1", "8002", tg("10.0.0.2", "80", 0))
	if _, err := e.apply(t, a, b); err != nil {
		t.Fatal(err)
	}
	goodHash := e.d.Health(context.Background(), e.rt).Instances["alpha"].ConfigHash
	e.sup.take()

	// alpha moves to a port its realm process then fails to bind (the port
	// was free at preflight time).
	e.sup.unbindable[9999] = true
	a2 := mut(a, func(i *spec.Instance) { i.Listen.Ports = "9999" })
	res, err := e.apply(t, a2, b)
	if err == nil {
		t.Fatal("Apply must report the failure")
	}
	if !strings.Contains(res.Failed["alpha"], "not listening") || len(res.Failed) != 1 {
		t.Fatalf("failed = %+v", res.Failed)
	}
	if ids(res.Running) != "alpha,beta" {
		t.Fatalf("alpha must be running again on its last-good config: %+v", res)
	}
	if ev := strings.Join(e.sup.take(), ","); ev != "stop realm/alpha,start realm/alpha,stop realm/alpha,start realm/alpha" {
		t.Fatalf("events %s", ev)
	}
	h := e.d.Health(context.Background(), e.rt).Instances["alpha"]
	if !h.Running || !h.Listening || h.ConfigHash != goodHash {
		t.Fatalf("after rollback: %+v (want hash %s)", h, goodHash)
	}
	if !e.sup.inUse(driver.PortClaim{Addr: "127.0.0.1", Port: 8001}) {
		t.Fatal("old listener is gone")
	}
	// beta untouched by all of this.
	for _, ev := range e.sup.events {
		if strings.Contains(ev, "beta") {
			t.Fatalf("beta was touched: %v", e.sup.events)
		}
	}
}

// A port someone else already holds is refused up front: nothing is started
// or stopped, and the running instance keeps its old configuration.
func TestApplyRefusesPortHeldByAnotherProcess(t *testing.T) {
	e := newEnv(t)
	a := fwd("alpha", "127.0.0.1", "8001", tg("10.0.0.1", "80", 0))
	if _, err := e.apply(t, a); err != nil {
		t.Fatal(err)
	}
	e.sup.take()
	e.sup.foreign[9999] = true
	a2 := mut(a, func(i *spec.Instance) { i.Listen.Ports = "9999" })
	res, err := e.apply(t, a2)
	if err == nil || !strings.Contains(res.Failed["alpha"], "already in use") || !strings.Contains(res.Failed["alpha"], "9999") {
		t.Fatalf("err=%v res=%+v", err, res)
	}
	if ev := e.sup.take(); len(ev) != 0 {
		t.Fatalf("the supervisor was touched: %v", ev)
	}
	if len(res.Restarted) != 0 || len(res.Disrupted) != 0 {
		t.Fatalf("nothing may be disrupted: %+v", res)
	}
	if h := e.d.Health(context.Background(), e.rt).Instances["alpha"]; !h.Running || !h.Listening {
		t.Fatalf("alpha must keep running: %+v", h)
	}
	// Its own ports do not count as "in use by another process".
	a3 := mut(a, func(i *spec.Instance) { i.Targets[0].Host = "10.0.0.2" })
	if _, err := e.apply(t, a3); err != nil {
		t.Fatalf("own port refused: %v", err)
	}
	// A brand-new instance on a foreign port is refused as well.
	n := fwd("fresh", "127.0.0.1", "9999", tg("10.0.0.1", "80", 0))
	if res, err := e.apply(t, a3, n); err == nil || !strings.Contains(res.Failed["fresh"], "already in use") {
		t.Fatalf("err=%v res=%+v", err, res)
	}
}

func TestApplyNewInstanceFailureIsStopped(t *testing.T) {
	e := newEnv(t)
	e.sup.unbindable[9999] = true
	n := fwd("fresh", "127.0.0.1", "9999", tg("10.0.0.1", "80", 0))
	res, err := e.apply(t, n)
	if err == nil || res.Failed["fresh"] == "" {
		t.Fatalf("err=%v res=%+v", err, res)
	}
	if len(e.sup.procs) != 0 || len(res.Running) != 0 {
		t.Fatalf("a failed new instance must not keep running: %+v", res)
	}
	if h := e.d.Health(context.Background(), e.rt); len(h.Instances) != 0 {
		t.Fatalf("health %+v", h)
	}
	if _, err := os.Stat(filepath.Join(e.rt.StateDir, "run", "fresh")); !os.IsNotExist(err) {
		t.Fatal("run dir left behind")
	}
}

func TestApplyPartialBindFailureIsDetected(t *testing.T) {
	// realm keeps running when one endpoint fails to bind; the port probe
	// must still notice.
	e := newEnv(t)
	e.sup.unbindable[7002] = true
	in := fwd("rng", "127.0.0.1", "7001-7003", tg("10.0.0.1", "80-82", 0))
	res, err := e.apply(t, in)
	if err == nil || !strings.Contains(res.Failed["rng"], "7002") {
		t.Fatalf("err=%v failed=%v", err, res.Failed)
	}
}

func TestApplyStartErrorRestoresLastGood(t *testing.T) {
	e := newEnv(t)
	a := fwd("alpha", "127.0.0.1", "8001", tg("10.0.0.1", "80", 0))
	if _, err := e.apply(t, a); err != nil {
		t.Fatal(err)
	}
	a2 := mut(a, func(i *spec.Instance) { i.Targets[0].Host = "10.0.0.7" })
	// The supervisor refuses the new spec once, then works again.
	e.sup.failFor["realm/alpha"] = errors.New("spawn failed")
	res, err := e.apply(t, a2)
	if err == nil || !strings.Contains(res.Failed["alpha"], "spawn failed") || strings.Contains(res.Failed["alpha"], "restoring") {
		t.Fatalf("err=%v res=%+v", err, res)
	}
	if ids(res.Running) != "alpha" || !e.d.Health(context.Background(), e.rt).Instances["alpha"].Listening {
		t.Fatalf("last-good was not restored: %+v", res)
	}
}

func TestApplyRefusesSlimAndWrongVersion(t *testing.T) {
	e := newEnv(t)
	a := fwd("alpha", "127.0.0.1", "8001", tg("10.0.0.1", "80", 0))
	e.d.opts.probeBinary = func(ctx context.Context, path string) (BinaryInfo, error) {
		return ParseVersionOutput("Realm 2.9.6 [brutal][batched-udp][multi-thread]\n")
	}
	if _, err := e.apply(t, a); err == nil || !strings.Contains(err.Error(), "slim") {
		t.Fatalf("slim binary accepted: %v", err)
	}
	if len(e.sup.procs) != 0 || len(e.sup.events) != 0 {
		t.Fatal("a refused binary must not start anything")
	}
	if _, err := os.Stat(e.rt.StateDir); err == nil {
		if _, err := os.Stat(filepath.Join(e.rt.StateDir, "run")); err == nil {
			t.Fatal("nothing may be written for a refused binary")
		}
	}
	e.d.opts.probeBinary = func(ctx context.Context, path string) (BinaryInfo, error) {
		return ParseVersionOutput("Realm 2.9.5 [brutal][proxy][balance][transport]\n")
	}
	if _, err := e.apply(t, a); err == nil || !strings.Contains(err.Error(), "2.9.5") {
		t.Fatalf("version mismatch accepted: %v", err)
	}
	e.d.opts.probeBinary = func(ctx context.Context, path string) (BinaryInfo, error) {
		return BinaryInfo{}, errors.New("exec format error")
	}
	if _, err := e.apply(t, a); err == nil {
		t.Fatal("an unrunnable binary was accepted")
	}
	// Nothing to run: an empty set needs no binary at all.
	e.rt.Kernel.Path = ""
	if _, err := e.apply(t); err != nil {
		t.Fatalf("empty set must not need a kernel: %v", err)
	}
}

func TestApplyRejectsTamperedArtifact(t *testing.T) {
	e := newEnv(t)
	a := fwd("alpha", "127.0.0.1", "8001", tg("10.0.0.1", "80", 0))
	set := e.render(t, a)
	set[0].Artifact.Files[configName] = []byte(`{"endpoints":[{"listen":"0.0.0.0:22","remote":"10.0.0.1:22"}]}`)
	res, err := e.d.Apply(context.Background(), e.rt, set)
	if err == nil || res.Failed["alpha"] == "" || len(e.sup.procs) != 0 {
		t.Fatalf("tampered artifact ran: err=%v res=%+v", err, res)
	}
	// Stale artifact (rendered from another instance).
	set = e.render(t, a)
	other := e.render(t, mut(a, func(i *spec.Instance) { i.Targets[0].Host = "10.9.9.9" }))
	set[0].Artifact = other[0].Artifact
	res, err = e.d.Apply(context.Background(), e.rt, set)
	if err == nil || res.Failed["alpha"] == "" {
		t.Fatalf("stale artifact ran: err=%v res=%+v", err, res)
	}
	// Invalid instance ids can never reach a path.
	bad := e.render(t, a)
	bad[0].Instance.ID = "../evil"
	if _, err := e.d.Apply(context.Background(), e.rt, bad); err == nil {
		t.Fatal("path-traversal id accepted")
	}
	dup := e.render(t, a, a)
	if _, err := e.d.Apply(context.Background(), e.rt, dup); err == nil {
		t.Fatal("duplicate ids accepted")
	}
}

func TestApplyInvalidNewVersionKeepsOldRunning(t *testing.T) {
	e := newEnv(t)
	a := fwd("alpha", "127.0.0.1", "8001", tg("10.0.0.1", "80", 0))
	if _, err := e.apply(t, a); err != nil {
		t.Fatal(err)
	}
	e.sup.take()
	// The core hands in an artifact for a now-invalid instance.
	good := e.render(t, a)
	bad := good
	bad[0].Instance = mut(a, func(i *spec.Instance) { i.Targets[0].Host = "a;b" })
	res, err := e.d.Apply(context.Background(), e.rt, bad)
	if err == nil || res.Failed["alpha"] == "" {
		t.Fatalf("err=%v res=%+v", err, res)
	}
	if len(e.sup.take()) != 0 || len(e.sup.procs) != 1 {
		t.Fatal("the running instance must not be touched by an invalid update")
	}
}

func TestRollbackRestoresLastGood(t *testing.T) {
	e := newEnv(t)
	a := fwd("alpha", "127.0.0.1", "8001", tg("10.0.0.1", "80", 0))
	b := fwd("beta", "127.0.0.1", "8002", tg("10.0.0.2", "80", 0))
	if _, err := e.apply(t, a, b); err != nil {
		t.Fatal(err)
	}
	e.sup.take()
	// Both processes vanish (crash loop gave up / agent restarted) and the
	// live config of alpha is damaged.
	e.sup.kill("realm/alpha")
	e.sup.kill("realm/beta")
	cfg := filepath.Join(e.rt.StateDir, "run", "alpha", "realm.json")
	if err := os.WriteFile(cfg, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.d.Rollback(context.Background(), e.rt); err != nil {
		t.Fatal(err)
	}
	if len(e.sup.procs) != 2 {
		t.Fatalf("procs %v", e.sup.procs)
	}
	h := e.d.Health(context.Background(), e.rt)
	for _, id := range []string{"alpha", "beta"} {
		if ih := h.Instances[id]; !ih.Running || !ih.Listening || ih.Err != "" {
			t.Errorf("%s: %+v", id, ih)
		}
	}
	// A damaged last-good copy is refused instead of executed.
	e.sup.kill("realm/alpha")
	if err := os.WriteFile(filepath.Join(e.rt.StateDir, "good", "alpha", "realm.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.d.Rollback(context.Background(), e.rt); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("damaged last-good accepted: %v", err)
	}
}

func TestStop(t *testing.T) {
	e := newEnv(t)
	a := fwd("alpha", "127.0.0.1", "8001", tg("10.0.0.1", "80", 0))
	b := fwd("beta", "127.0.0.1", "8002", tg("10.0.0.2", "80", 0))
	if _, err := e.apply(t, a, b); err != nil {
		t.Fatal(err)
	}
	if err := e.d.Stop(context.Background(), e.rt, "alpha"); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.sup.procs["realm/alpha"]; ok || len(e.sup.procs) != 1 {
		t.Fatalf("procs %v", e.sup.procs)
	}
	if err := e.d.Stop(context.Background(), e.rt, "../x"); err == nil {
		t.Fatal("invalid id accepted")
	}
	if err := e.d.Stop(context.Background(), e.rt, "nope"); err != nil {
		t.Fatalf("stopping an unknown instance is a no-op: %v", err)
	}
	if err := e.d.Stop(context.Background(), e.rt); err != nil {
		t.Fatal(err)
	}
	if len(e.sup.procs) != 0 {
		t.Fatalf("procs %v", e.sup.procs)
	}
	if h := e.d.Health(context.Background(), e.rt); len(h.Instances) != 0 {
		t.Fatalf("health %+v", h)
	}
	// The last-good config survives a Stop; Rollback brings the instances back.
	if err := e.d.Rollback(context.Background(), e.rt); err != nil {
		t.Fatal(err)
	}
	if len(e.sup.procs) != 2 {
		t.Fatalf("rollback after stop: %v", e.sup.procs)
	}
}

func TestHealthReportsProblems(t *testing.T) {
	e := newEnv(t)
	a := fwd("alpha", "127.0.0.1", "8001-8002", tg("10.0.0.1", "80-81", 0))
	if _, err := e.apply(t, a); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if ih := e.d.Health(ctx, e.rt).Instances["alpha"]; !ih.Running || !ih.Listening || ih.Err != "" || ih.Targets != nil {
		t.Fatalf("healthy: %+v", ih)
	}
	// One listener disappears.
	e.sup.procs["realm/alpha"].listening["127.0.0.1:8002"] = false
	ih := e.d.Health(ctx, e.rt).Instances["alpha"]
	if !ih.Running || ih.Listening || !strings.Contains(ih.Err, "8002") {
		t.Fatalf("partial: %+v", ih)
	}
	e.sup.procs["realm/alpha"].listening["127.0.0.1:8002"] = true
	// Config file edited behind our back.
	if err := os.WriteFile(filepath.Join(e.rt.StateDir, "run", "alpha", "realm.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ih := e.d.Health(ctx, e.rt).Instances["alpha"]; !strings.Contains(ih.Err, "changed on disk") {
		t.Fatalf("tampered: %+v", ih)
	}
	// Process dies.
	e.sup.kill("realm/alpha")
	ih = e.d.Health(ctx, e.rt).Instances["alpha"]
	if ih.Running || ih.Listening || !strings.Contains(ih.Err, "not running") || !strings.Contains(ih.Err, "101") {
		t.Fatalf("dead: %+v", ih)
	}
	// Apply heals a dead instance without counting it as a disruption.
	res, err := e.apply(t, a)
	if err != nil {
		t.Fatal(err)
	}
	if ids(res.Running) != "alpha" || len(res.Restarted) != 0 || len(res.Disrupted) != 0 {
		t.Fatalf("heal: %+v", res)
	}
	if ih := e.d.Health(ctx, e.rt).Instances["alpha"]; !ih.Running || !ih.Listening || ih.Err != "" {
		t.Fatalf("healed: %+v", ih)
	}
}

func TestStatsIsEmptyAndNoError(t *testing.T) {
	e := newEnv(t)
	a := fwd("alpha", "127.0.0.1", "8001", tg("10.0.0.1", "80", 0))
	if _, err := e.apply(t, a); err != nil {
		t.Fatal(err)
	}
	c, err := e.d.Stats(context.Background(), e.rt)
	if err != nil || len(c) != 0 {
		t.Fatalf("Stats = %v, %v", c, err)
	}
	if e.d.Caps().Stats != "none" {
		t.Fatal("Caps.Stats must be none")
	}
}

func TestRuntimeMisuse(t *testing.T) {
	d := New(Options{})
	ctx := context.Background()
	if _, err := d.Apply(ctx, driver.Runtime{}, nil); err == nil {
		t.Error("Apply without StateDir/Sup")
	}
	if err := d.Rollback(ctx, driver.Runtime{}); err == nil {
		t.Error("Rollback without StateDir/Sup")
	}
	if err := d.Stop(ctx, driver.Runtime{}); err == nil {
		t.Error("Stop without StateDir/Sup")
	}
	if h := d.Health(ctx, driver.Runtime{}); len(h.Instances) != 0 {
		t.Error("Health without runtime")
	}
}

func TestParseVersionOutput(t *testing.T) {
	good := "Realm 2.9.6 [brutal][batched-udp][proxy][balance][transport][multi-thread]\n"
	bi, err := ParseVersionOutput(good)
	if err != nil || bi.Version != "2.9.6" || len(bi.Features) != 6 {
		t.Fatalf("%+v %v", bi, err)
	}
	if err := bi.Check("v2.9.6"); err != nil {
		t.Fatal(err)
	}
	if err := bi.Check("2.9.7"); err == nil {
		t.Fatal("version mismatch accepted")
	}
	slim, err := ParseVersionOutput("Realm 2.9.6 [brutal][batched-udp][multi-thread]\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if err := slim.Check(""); err == nil || !strings.Contains(err.Error(), "proxy, balance, transport") {
		t.Fatalf("slim accepted: %v", err)
	}
	for _, bad := range []string{"", "gost 3.3.0", "Realm", "Realm 2.9.6 garbage", "realm 2.9.6 [proxy]"} {
		if _, err := ParseVersionOutput(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}
