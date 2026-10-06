package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/reconcile"
	"github.com/W1nCwC/W1nCray/agent/spec"
)

const remoteToken = "tok-remote-0123456789"

// remotePanel is a loopback HTTP stand-in for the panel (a loopback http URL is
// accepted by the client, so no certificates are needed here; the TLS and
// header rules are covered in agent/panelclient).
type remotePanel struct {
	srv *httptest.Server

	mu       sync.Mutex
	desired  string // JSON of the "desired" member; "" answers unchanged
	revision int64
	counts   map[string]int
	acks     []map[string]any
	auth     []string
}

func newRemotePanel(t *testing.T) *remotePanel {
	p := &remotePanel{counts: map[string]int{}}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		ep := strings.TrimPrefix(r.URL.Path, "/api/v2/server/machine/agent/")
		p.mu.Lock()
		defer p.mu.Unlock()
		p.counts[ep]++
		p.auth = append(p.auth, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		switch ep {
		case "config":
			if p.desired == "" {
				io.WriteString(w, `{"schema":1,"unchanged":true,"revision":0}`)
				return
			}
			fmt.Fprintf(w, `{"schema":1,"revision":%d,"hash":"sha256:test","desired":%s}`, p.revision, p.desired)
		case "ack":
			var m map[string]any
			json.Unmarshal(raw, &m)
			p.acks = append(p.acks, m)
			io.WriteString(w, `{"ok":true}`)
		default:
			io.WriteString(w, `{"ok":true}`)
		}
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *remotePanel) count(ep string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.counts[ep]
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func remoteOptions(url string, log *recLog) RemoteOptions {
	o := RemoteOptions{URL: url, MachineID: 7, Token: remoteToken, AgentVersion: "1.2.3"}
	if log != nil {
		o.Log = log
	}
	return o
}

func TestStartRemoteAppliesThePanelStateAndAcknowledges(t *testing.T) {
	dir := t.TempDir()
	rt, _ := bootCycle(t, dir, false, nil)
	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	p := newRemotePanel(t)
	p.desired = fmt.Sprintf(`{"version":%d,"revision":3,"instances":[%s]}`, spec.Version, fwdInstance(port))
	p.revision = 3

	stop, err := rt.StartRemote(context.Background(), remoteOptions(p.srv.URL, nil))
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the ack", func() bool { return p.count("ack") >= 1 })
	if !dialOK(addr) {
		t.Fatalf("%s is not listening after the panel state was applied", addr)
	}
	p.mu.Lock()
	ack := p.acks[0]
	for _, a := range p.auth {
		if a != "Bearer "+remoteToken {
			t.Errorf("Authorization = %q", a)
		}
	}
	p.mu.Unlock()
	rep, _ := ack["report"].(map[string]any)
	if ack["revision"] != float64(3) || ack["hash"] != "sha256:test" || rep["status"] != "applied" {
		t.Errorf("ack = %v", ack)
	}
	// The Runtime's own report agrees.
	if last, ok := rt.Reconciler.Last(); !ok || last.Status != reconcile.StatusApplied || last.Revision != 3 {
		t.Errorf("Last = %+v ok=%v", last, ok)
	}

	// stop waits for the link: nothing reaches the panel afterwards.
	stop()
	stop() // idempotent
	n := p.count("config")
	time.Sleep(50 * time.Millisecond)
	if p.count("config") != n {
		t.Error("the link kept talking to the panel after stop")
	}
	// Stopping the link does not stop the forwarding; Shutdown does.
	if !dialOK(addr) {
		t.Error("stopping the panel link must not stop the instances")
	}
	if err := rt.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if dialOK(addr) {
		t.Error("Shutdown left the instance running")
	}
}

func TestUnreachablePanelLeavesTheResumedInstancesRunning(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	// lifetime 1 applies a state and shuts down; lifetime 2 resumes it.
	rt1, _ := bootCycle(t, dir, false, nil)
	desiredPath := filepath.Join(dir, "d.json")
	writeDesired(t, desiredPath, fwdInstance(port))
	if _, err := rt1.ApplyFile(desiredPath); err != nil {
		t.Fatal(err)
	}
	if err := rt1.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	rt2, _ := bootCycle(t, dir, true, nil)
	if !dialOK(addr) {
		t.Fatal("the last good state was not resumed")
	}

	// A panel that is gone: its port refuses connections.
	dead := httptest.NewServer(http.NotFoundHandler())
	url := dead.URL
	dead.Close()

	log := &recLog{}
	stop, err := rt2.StartRemote(context.Background(), remoteOptions(url, log))
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the failed pull to be logged", func() bool { return strings.Contains(log.warnText(), "pull failed") })
	if !dialOK(addr) {
		t.Error("an unreachable panel took the forwarding down")
	}
	if last, ok := rt2.Reconciler.Last(); !ok || last.Status != reconcile.StatusApplied {
		t.Errorf("the resumed state was disturbed: %+v ok=%v", last, ok)
	}
	if strings.Contains(log.warnText(), remoteToken) {
		t.Errorf("the token is in the log: %s", log.warnText())
	}
	stop()
	if !dialOK(addr) {
		t.Error("stopping the link took the forwarding down")
	}
}

func TestStartRemoteRejectsBadOptions(t *testing.T) {
	rt, _ := bootCycle(t, t.TempDir(), false, nil)
	for name, o := range map[string]RemoteOptions{
		"plain http to a remote host": {URL: "http://panel.example.com", MachineID: 1, Token: remoteToken},
		"no token":                    {URL: "https://panel.example.com", MachineID: 1},
		"no machine id":               {URL: "https://panel.example.com", Token: remoteToken},
		"user info in the URL":        {URL: "https://u:p@panel.example.com", MachineID: 1, Token: remoteToken},
	} {
		stop, err := rt.StartRemote(context.Background(), o)
		if err == nil {
			stop()
			t.Errorf("%s: accepted", name)
			continue
		}
		if stop != nil {
			t.Errorf("%s: stop must be nil on error", name)
		}
		if strings.Contains(err.Error(), remoteToken) || strings.Contains(err.Error(), ":p@") {
			t.Errorf("%s: error leaks a credential: %v", name, err)
		}
	}
}

func TestStartRemoteEndsWithItsContext(t *testing.T) {
	rt, _ := bootCycle(t, t.TempDir(), false, nil)
	p := newRemotePanel(t)
	ctx, cancel := context.WithCancel(context.Background())
	stop, err := rt.StartRemote(ctx, remoteOptions(p.srv.URL, nil))
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the first pull", func() bool { return p.count("config") >= 1 })
	cancel()
	done := make(chan struct{})
	go func() { stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("stop did not return after the context was cancelled")
	}
}

func TestRemoteApplierAdaptsTheRuntime(t *testing.T) {
	rt, _ := bootCycle(t, t.TempDir(), false, nil)
	a := remoteApplier{rt}
	if _, ok := a.Last(); ok {
		t.Fatal("Last before any apply")
	}
	if names := rt.engineNames(); len(names) != 1 || names[0] != spec.EngineGost {
		t.Errorf("engines = %v", names)
	}
	if k := rt.externalKernels(); k != nil {
		t.Errorf("kernels before any apply = %v", k)
	}

	port := freePort(t)
	var d spec.Desired
	if err := json.Unmarshal([]byte(fmt.Sprintf(`{"version":%d,"revision":9,"instances":[%s]}`, spec.Version, fwdInstance(port))), &d); err != nil {
		t.Fatal(err)
	}
	rep, err := a.Apply(context.Background(), d)
	if err != nil || rep.Status != reconcile.StatusApplied {
		t.Fatalf("Apply = %+v, %v", rep, err)
	}
	if last, ok := a.Last(); !ok || last.Revision != 9 {
		t.Errorf("Last = %+v ok=%v", last, ok)
	}
	if h := a.Health(context.Background()); !h.OK || h.Revision != 9 {
		t.Errorf("Health = %+v", h)
	}
	stats := a.Stats(context.Background())
	if len(stats) != 1 || stats[0].InstanceID != "fwd1" {
		t.Errorf("Stats = %+v", stats)
	}
	// The fake engine is not external, so it does not count as an installed kernel.
	for name, ver := range rt.externalKernels() {
		if ver == reconcile.BuiltinVersion {
			t.Errorf("builtin kernel %s listed as external", name)
		}
	}
}
