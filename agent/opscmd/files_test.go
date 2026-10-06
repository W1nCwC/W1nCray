package opscmd

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/filesync"
	"github.com/W1nCwC/W1nCray/agent/panelclient"
)

// fakeFiles records the file commands and answers with programmed results.
type fakeFiles struct {
	mu        sync.Mutex
	applies   int
	validates int
	rollbacks int
	applyRes  filesync.Result
	applyErr  error
	valRes    filesync.Result
	valErr    error
	rollRes   filesync.Result
	rollErr   error
	applyFn   func(context.Context) (filesync.Result, error)
}

func (f *fakeFiles) Apply(ctx context.Context) (filesync.Result, error) {
	f.mu.Lock()
	f.applies++
	fn, res, err := f.applyFn, f.applyRes, f.applyErr
	f.mu.Unlock()
	if fn != nil {
		return fn(ctx)
	}
	return res, err
}

func (f *fakeFiles) Validate(context.Context) (filesync.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.validates++
	return f.valRes, f.valErr
}

func (f *fakeFiles) Rollback(context.Context) (filesync.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rollbacks++
	return f.rollRes, f.rollErr
}

func (f *fakeFiles) counts() (int, int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applies, f.validates, f.rollbacks
}

// recordingSink captures the late results a long command delivers.
type recordingSink struct {
	mu      sync.Mutex
	results []delivered
}

type delivered struct {
	id, status string
	data       json.RawMessage
}

func (s *recordingSink) Deliver(id, status string, data json.RawMessage) {
	s.mu.Lock()
	s.results = append(s.results, delivered{id: id, status: status, data: data})
	s.mu.Unlock()
}

func (s *recordingSink) wait(t *testing.T, n int) []delivered {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		got := append([]delivered(nil), s.results...)
		s.mu.Unlock()
		if len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d late result(s), got %v", n, got)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestFilesCommandsAreRegisteredAndUnwiredAnswers covers ruling 5: the three
// commands exist, and without a file applier they answer an explicit
// not_supported instead of pretending the type is unknown.
func TestFilesCommandsAreRegisteredAndUnwiredAnswers(t *testing.T) {
	reg := mustRegistry(t, Deps{})
	for _, typ := range []string{panelclient.CmdFilesApply, panelclient.CmdFilesValidate, panelclient.CmdFilesRollback} {
		if !reg.Has(typ) {
			t.Errorf("command %q is not registered", typ)
		}
		status, res := reg.Execute(context.Background(), panelclient.Command{ID: "x-" + typ, Type: typ})
		if status != panelclient.ResultFailed {
			t.Errorf("%s status = %q, want failed", typ, status)
		}
		f := decodeFailure(t, res)
		if f.Code != "not_supported" {
			t.Errorf("%s code = %q, want not_supported", typ, f.Code)
		}
		if f.Error == "unsupported command" {
			t.Errorf("%s answered the historical unsupported command", typ)
		}
	}
}

// TestFilesApplyIsAcceptedThenDelivered covers ruling 7 and 9: files_apply
// answers "accepted" at once, and the final done carries applied_pending when
// the reload was initiated.
func TestFilesApplyIsAcceptedThenDelivered(t *testing.T) {
	files := &fakeFiles{applyRes: filesync.Result{
		Status: filesync.StatusDone,
		Reload: filesync.ReloadReloaded,
		Files:  []filesync.FileResult{{Name: filesync.NameRoute, SHA256: strings.Repeat("a", 64), Size: 10, Bytes: 10}},
	}}
	sink := &recordingSink{}
	reg := mustRegistry(t, Deps{Files: files})
	reg.SetSink(sink)

	status, res := reg.Execute(context.Background(), panelclient.Command{ID: "c1", Type: panelclient.CmdFilesApply})
	if status != panelclient.ResultAccepted {
		t.Fatalf("status = %q, want accepted", status)
	}
	if len(res) != 0 {
		t.Errorf("the accepted answer carries a body: %s", res)
	}
	got := sink.wait(t, 1)
	if got[0].id != "c1" || got[0].status != panelclient.ResultDone {
		t.Fatalf("late result = %+v", got[0])
	}
	var body map[string]any
	if err := json.Unmarshal(got[0].data, &body); err != nil {
		t.Fatalf("late result body %s: %v", got[0].data, err)
	}
	if body["applied_pending"] != true {
		t.Errorf("applied_pending = %v, want true (%s)", body["applied_pending"], got[0].data)
	}
	if body["status"] != filesync.StatusDone || body["reload"] != filesync.ReloadReloaded {
		t.Errorf("body = %s", got[0].data)
	}
	if n, _, _ := files.counts(); n != 1 {
		t.Errorf("applies = %d, want 1", n)
	}
}

// TestFilesApplyDoesNotPromiseHealthForGeoOnly: a geo-only change never asks
// for a reload, so applied_pending must be absent.
func TestFilesApplyDoesNotPromiseHealthForGeoOnly(t *testing.T) {
	files := &fakeFiles{applyRes: filesync.Result{Status: filesync.StatusDone, Reload: filesync.ReloadNotNeeded}}
	sink := &recordingSink{}
	reg := mustRegistry(t, Deps{Files: files})
	reg.SetSink(sink)

	if status, _ := reg.Execute(context.Background(), panelclient.Command{ID: "c2", Type: panelclient.CmdFilesApply}); status != panelclient.ResultAccepted {
		t.Fatalf("status = %q", status)
	}
	got := sink.wait(t, 1)
	var body map[string]any
	if err := json.Unmarshal(got[0].data, &body); err != nil {
		t.Fatal(err)
	}
	if _, ok := body["applied_pending"]; ok {
		t.Errorf("applied_pending present for a geo-only change: %s", got[0].data)
	}
}

// TestFilesApplyReportsARefusal: an invalid file set is delivered as a done
// result with the status and the errors, never as a transport failure.
func TestFilesApplyReportsARefusal(t *testing.T) {
	files := &fakeFiles{applyRes: filesync.Result{
		Status: filesync.StatusInvalid,
		Errors: []string{"route.json: rules[0] unknown field"},
	}}
	sink := &recordingSink{}
	reg := mustRegistry(t, Deps{Files: files})
	reg.SetSink(sink)

	reg.Execute(context.Background(), panelclient.Command{ID: "c3", Type: panelclient.CmdFilesApply})
	got := sink.wait(t, 1)
	var body struct {
		Status string   `json:"status"`
		Errors []string `json:"errors"`
	}
	if err := json.Unmarshal(got[0].data, &body); err != nil {
		t.Fatal(err)
	}
	if body.Status != filesync.StatusInvalid || len(body.Errors) != 1 {
		t.Errorf("body = %s", got[0].data)
	}
}

// TestFilesApplyReportsAProtocolFailureAsFailed: when the apply cannot even
// start (no desired state), the late result is a failed one with the error.
func TestFilesApplyReportsAProtocolFailureAsFailed(t *testing.T) {
	files := &fakeFiles{applyErr: errors.New("filesync: no managed files in the desired state")}
	sink := &recordingSink{}
	reg := mustRegistry(t, Deps{Files: files})
	reg.SetSink(sink)

	if status, _ := reg.Execute(context.Background(), panelclient.Command{ID: "c4", Type: panelclient.CmdFilesApply}); status != panelclient.ResultAccepted {
		t.Fatalf("status = %q", status)
	}
	got := sink.wait(t, 1)
	if got[0].status != panelclient.ResultFailed {
		t.Fatalf("late status = %q, want failed", got[0].status)
	}
	if !strings.Contains(string(got[0].data), "no managed files") {
		t.Errorf("body = %s", got[0].data)
	}
}

// TestFilesValidateAndRollbackFinishInline: neither is a long command.
func TestFilesValidateAndRollbackFinishInline(t *testing.T) {
	files := &fakeFiles{
		valRes:  filesync.Result{Status: filesync.StatusDone, Reload: filesync.ReloadNotNeeded},
		rollRes: filesync.Result{Status: filesync.StatusRolledBack, RolledBack: true, Reload: filesync.ReloadReloaded},
	}
	sink := &recordingSink{}
	reg := mustRegistry(t, Deps{Files: files})
	reg.SetSink(sink)

	status, res := reg.Execute(context.Background(), panelclient.Command{ID: "v1", Type: panelclient.CmdFilesValidate})
	if status != panelclient.ResultDone {
		t.Fatalf("files_validate status = %q, want done", status)
	}
	var vbody struct {
		Status string `json:"status"`
		Reload string `json:"reload"`
	}
	if err := json.Unmarshal(res, &vbody); err != nil {
		t.Fatal(err)
	}
	if vbody.Status != filesync.StatusDone || vbody.Reload != filesync.ReloadNotNeeded {
		t.Errorf("files_validate body = %s", res)
	}

	status, res = reg.Execute(context.Background(), panelclient.Command{ID: "r1", Type: panelclient.CmdFilesRollback})
	if status != panelclient.ResultDone {
		t.Fatalf("files_rollback status = %q, want done", status)
	}
	var rbody struct {
		Status     string `json:"status"`
		RolledBack bool   `json:"rolled_back"`
	}
	if err := json.Unmarshal(res, &rbody); err != nil {
		t.Fatal(err)
	}
	if rbody.Status != filesync.StatusRolledBack || !rbody.RolledBack {
		t.Errorf("files_rollback body = %s", res)
	}
	if len(sink.results) != 0 {
		t.Errorf("an inline command delivered a late result: %+v", sink.results)
	}
	if _, v, r := files.counts(); v != 1 || r != 1 {
		t.Errorf("validates=%d rollbacks=%d, want 1 and 1", v, r)
	}
}

// TestFilesRollbackRefusalIsAFailure: a rollback with no snapshot fails with
// the error, not with a fake done.
func TestFilesRollbackRefusalIsAFailure(t *testing.T) {
	files := &fakeFiles{rollErr: errors.New("filesync: no last_good snapshot to roll back to")}
	reg := mustRegistry(t, Deps{Files: files})
	status, res := reg.Execute(context.Background(), panelclient.Command{ID: "r2", Type: panelclient.CmdFilesRollback})
	if status != panelclient.ResultFailed {
		t.Fatalf("status = %q, want failed", status)
	}
	if !strings.Contains(string(res), "no last_good") {
		t.Errorf("body = %s", res)
	}
}

// TestFilesEventsAreEmitted covers ruling 10: files.applied and
// files.rolled_back are reported through the event sink.
func TestFilesEventsAreEmitted(t *testing.T) {
	files := &fakeFiles{
		applyRes: filesync.Result{Status: filesync.StatusDone, Reload: filesync.ReloadReloaded},
		rollRes:  filesync.Result{Status: filesync.StatusRolledBack, RolledBack: true},
	}
	var mu sync.Mutex
	var kinds []string
	reg := mustRegistry(t, Deps{Files: files})
	reg.SetSink(&recordingSink{})
	reg.SetEvents(EventFunc(func(kind, _, _ string) {
		mu.Lock()
		kinds = append(kinds, kind)
		mu.Unlock()
	}))

	reg.Execute(context.Background(), panelclient.Command{ID: "e1", Type: panelclient.CmdFilesApply})
	// Wait for the goroutine's event before the rollback, so the order is
	// deterministic.
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(kinds)
		mu.Unlock()
		if n >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("files.applied was never emitted")
		}
		time.Sleep(5 * time.Millisecond)
	}
	reg.Execute(context.Background(), panelclient.Command{ID: "e2", Type: panelclient.CmdFilesRollback})
	mu.Lock()
	defer mu.Unlock()
	if len(kinds) != 2 || kinds[0] != "files.applied" || kinds[1] != "files.rolled_back" {
		t.Errorf("events = %v, want files.applied then files.rolled_back", kinds)
	}
}
