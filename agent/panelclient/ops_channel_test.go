package panelclient

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// fakeCommandRunner stands in for the operations registry: it records the
// types the Runner delegated and answers them from a programmable function.
type fakeCommandRunner struct {
	mu     sync.Mutex
	calls  []string
	answer func(c Command) (string, json.RawMessage)
}

func (f *fakeCommandRunner) Execute(ctx context.Context, c Command) (string, json.RawMessage) {
	f.mu.Lock()
	f.calls = append(f.calls, c.Type)
	f.mu.Unlock()
	if f.answer != nil {
		return f.answer(c)
	}
	return ResultDone, mustJSON(map[string]string{"type": c.Type})
}

func (f *fakeCommandRunner) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// TestCommandRunnerServesOnlyTheNonBuiltinTypes covers the delegation
// contract: refresh and dump_state stay in the Runner, everything else goes to
// the registry, and the registry's "unsupported command" answer is what the
// panel sees for a type nobody registered.
func TestCommandRunnerServesOnlyTheNonBuiltinTypes(t *testing.T) {
	p := newPanel(t)
	c := newClient(t, p.srv)
	fr := &fakeCommandRunner{answer: func(c Command) (string, json.RawMessage) {
		if c.Type == CmdKernelList {
			return ResultDone, mustJSON(map[string]int{"kernels": 0})
		}
		return ResultFailed, mustJSON(map[string]string{"error": "unsupported command"})
	}}
	r, err := NewRunner(c, &fakeApp{}, RunnerOptions{InstanceID: runnerID, Commands: fr})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	status, res, err := r.ExecuteCommand(ctx, "k1", CmdKernelList, nil, 0)
	if err != nil || status != ResultDone {
		t.Fatalf("kernel_list = (%q, %s, %v), want done", status, res, err)
	}
	status, res, err = r.ExecuteCommand(ctx, "x1", "bogus", nil, 0)
	if err != nil || status != ResultFailed {
		t.Fatalf("unknown type = (%q, %s, %v), want failed", status, res, err)
	}
	var body map[string]string
	if err := json.Unmarshal(res, &body); err != nil || body["error"] != "unsupported command" {
		t.Errorf("unknown type result = %s (%v)", res, err)
	}
	if _, _, err := r.ExecuteCommand(ctx, "b1", CmdRefresh, nil, 0); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if _, _, err := r.ExecuteCommand(ctx, "b2", CmdDumpState, nil, 0); err != nil {
		t.Fatalf("dump_state: %v", err)
	}
	if got := strings.Join(fr.called(), ","); got != CmdKernelList+",bogus" {
		t.Errorf("the registry saw %v, want only the non-builtin types", got)
	}
}

// TestLongCommandStaysInFlightUntilTheFinalResult covers design section 3.1
// point 5: the accepted answer and the final one share the id, so the id stays
// in flight until the final result is delivered, and only then is it
// remembered.
func TestLongCommandStaysInFlightUntilTheFinalResult(t *testing.T) {
	p := newPanel(t)
	c := newClient(t, p.srv)
	fr := &fakeCommandRunner{answer: func(c Command) (string, json.RawMessage) {
		return ResultAccepted, nil
	}}
	r, err := NewRunner(c, &fakeApp{}, RunnerOptions{InstanceID: runnerID, Commands: fr})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	status, _, err := r.ExecuteCommand(ctx, "L1", "kernel_install", nil, 0)
	if err != nil || status != ResultAccepted {
		t.Fatalf("first answer = (%q, %v), want accepted", status, err)
	}
	// A redelivery while the long command runs must not execute it again.
	if _, _, err := r.ExecuteCommand(ctx, "L1", "kernel_install", nil, 0); !errors.Is(err, ErrCommandAnswered) {
		t.Fatalf("redelivery while in flight = %v, want ErrCommandAnswered", err)
	}
	if n := len(fr.called()); n != 1 {
		t.Fatalf("the long command ran %d times, want 1", n)
	}

	// The final result goes over the HTTP link and remembers the id.
	if err := r.DeliverResult(ctx, "L1", ResultDone, mustJSON(map[string]string{"version": "3.3.0"})); err != nil {
		t.Fatalf("DeliverResult: %v", err)
	}
	p.waitCount("command-result", 1)
	res := p.resultReq(0)
	if res.ID != "L1" || res.Status != ResultDone || !strings.Contains(string(res.Result), "3.3.0") {
		t.Errorf("final result = %+v / %s", res, res.Result)
	}
	// After the final result the id is answered for good.
	if _, _, err := r.ExecuteCommand(ctx, "L1", "kernel_install", nil, 0); !errors.Is(err, ErrCommandAnswered) {
		t.Fatalf("after the final result = %v, want ErrCommandAnswered", err)
	}
	if n := len(fr.called()); n != 1 {
		t.Fatalf("the command ran %d times after its final result", n)
	}
}

// TestReleaseCommandLetsARedeliveryRunAgain covers the failure path: a long
// command whose final result could not be delivered must be runnable again,
// not stuck in flight forever.
func TestReleaseCommandLetsARedeliveryRunAgain(t *testing.T) {
	p := newPanel(t)
	c := newClient(t, p.srv)
	fr := &fakeCommandRunner{answer: func(c Command) (string, json.RawMessage) {
		return ResultAccepted, nil
	}}
	r, err := NewRunner(c, &fakeApp{}, RunnerOptions{InstanceID: runnerID, Commands: fr})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if status, _, err := r.ExecuteCommand(ctx, "L2", "kernel_install", nil, 0); err != nil || status != ResultAccepted {
		t.Fatalf("first answer = (%q, %v), want accepted", status, err)
	}
	r.ReleaseCommand("L2")
	if status, _, err := r.ExecuteCommand(ctx, "L2", "kernel_install", nil, 0); err != nil || status != ResultAccepted {
		t.Fatalf("redelivery after release = (%q, %v), want accepted", status, err)
	}
	if n := len(fr.called()); n != 2 {
		t.Fatalf("the command ran %d times, want 2", n)
	}

	// A final delivery that fails releases the id as well.
	if err := r.DeliverResult(ctx, "L2", ResultDone, nil); err != nil {
		t.Fatalf("DeliverResult: %v", err)
	}
	p.setCmdResult(func(req CommandResultRequest) int { return 500 })
	if err := r.DeliverResult(ctx, "L3", ResultDone, nil); err == nil {
		t.Error("a refused delivery must be reported")
	}
	if status, _, err := r.ExecuteCommand(ctx, "L3", "kernel_install", nil, 0); err != nil || status != ResultAccepted {
		t.Fatalf("redelivery after a failed final delivery = (%q, %v), want accepted", status, err)
	}
}

// TestKernelEntriesTravelInConfigReportAndAck covers design section 3.3: the
// structured list is added next to the legacy kernels map in /config, in
// /report and in the ack report, under the contract's "kernel_entries" name.
func TestKernelEntriesTravelInConfigReportAndAck(t *testing.T) {
	p := newPanel(t)
	c := newClient(t, p.srv)
	entries := []wsproto.KernelEntry{{
		Name: "gost", Version: "3.3.0", Current: true,
		Path: "/srv/kernels/gost/3.3.0/gost", SizeBytes: 4096, InstalledAt: 1700000000, InUse: true,
	}}
	r, err := NewRunner(c, &fakeApp{}, RunnerOptions{
		InstanceID:  runnerID,
		Kernels:     func() map[string]string { return map[string]string{"gost": "3.3.0"} },
		KernelsList: func() ([]wsproto.KernelEntry, error) { return entries, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	p.setConfig(func(n int, req ConfigRequest) (int, string) {
		if n == 1 {
			return 200, desiredBody(42, "sha256:cd34", instJSON("hk-ssh", "gost", ""), "")
		}
		return 200, unchangedBody(42, "")
	})

	if err := r.pullOnce(ctx); err != nil {
		t.Fatal(err)
	}
	p.waitCount("ack", 1)

	req := p.configReq(0)
	if len(req.KernelEntries) != 1 || req.KernelEntries[0].Name != "gost" || !req.KernelEntries[0].InUse {
		t.Errorf("config kernel_entries = %+v", req.KernelEntries)
	}
	if req.Kernels["gost"] != "3.3.0" {
		t.Errorf("the legacy kernels map disappeared: %+v", req.Kernels)
	}
	if body := string(p.bodies("config")[0]); !strings.Contains(body, `"kernel_entries"`) {
		t.Errorf("config body has no kernel_entries key: %s", body)
	}

	ack := p.ackReq(0)
	if len(ack.Report.KernelEntries) != 1 || ack.Report.KernelEntries[0].Version != "3.3.0" {
		t.Errorf("ack report kernel_entries = %+v", ack.Report.KernelEntries)
	}

	if err := r.reportOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var rep ReportRequest
	if err := json.Unmarshal(p.bodies("report")[0], &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.KernelEntries) != 1 || rep.KernelEntries[0].Path == "" {
		t.Errorf("report kernel_entries = %+v", rep.KernelEntries)
	}
	if !strings.Contains(string(p.bodies("report")[0]), `"kernel_entries"`) {
		t.Errorf("report body has no kernel_entries key: %s", p.bodies("report")[0])
	}
}

// TestKernelEntryFailureIsOmittedNotFatal keeps the collection best effort: a
// failing kernel listing omits the field and never fails the pull.
func TestKernelEntryFailureIsOmittedNotFatal(t *testing.T) {
	p := newPanel(t)
	c := newClient(t, p.srv)
	r, err := NewRunner(c, &fakeApp{}, RunnerOptions{
		InstanceID:  runnerID,
		KernelsList: func() ([]wsproto.KernelEntry, error) { return nil, errors.New("boom") },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.pullOnce(context.Background()); err != nil {
		t.Fatalf("pullOnce: %v", err)
	}
	if body := string(p.bodies("config")[0]); strings.Contains(body, "kernel_entries") {
		t.Errorf("a failed collection must omit the field: %s", body)
	}
}
