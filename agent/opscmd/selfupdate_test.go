package opscmd

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/panelclient"
	"github.com/W1nCwC/W1nCray/agent/selfupdate"
)

// fakeUpdater is the SelfUpdateOps surface with no disk or manifest behind it.
type fakeUpdater struct {
	staged     selfupdate.Staged
	stageErr   error
	commitErr  error
	respawnErr error
	readyErr   error
	pending    selfupdate.Pending
	hasPending bool
}

func (f *fakeUpdater) Stage(context.Context, string) (selfupdate.Staged, error) {
	return f.staged, f.stageErr
}
func (f *fakeUpdater) Commit(selfupdate.Staged) error      { return f.commitErr }
func (f *fakeUpdater) RespawnHelper() error                { return f.respawnErr }
func (f *fakeUpdater) Ready() error                        { return f.readyErr }
func (f *fakeUpdater) Pending() (selfupdate.Pending, bool) { return f.pending, f.hasPending }

// selfUpdateRegistry builds a registry with the self_update command registered
// and a channel that collects the late results.
func selfUpdateRegistry(t *testing.T, up SelfUpdateOps, restart func()) (*Registry, chan sinkCall) {
	t.Helper()
	calls := make(chan sinkCall, 4)
	reg := mustRegistry(t, Deps{Sink: SinkFunc(func(id, status string, data json.RawMessage) {
		calls <- sinkCall{id: id, status: status, data: data}
	})})
	if err := RegisterSelfUpdate(reg, up, restart); err != nil {
		t.Fatalf("RegisterSelfUpdate: %v", err)
	}
	return reg, calls
}

// TestSelfUpdateAnswersAcceptedThenDone covers protocol ruling 7 for the
// command: the panel gets "accepted" inside the ttl and the final done result
// later, and only then does the process restart.
func TestSelfUpdateAnswersAcceptedThenDone(t *testing.T) {
	restarted := make(chan struct{}, 1)
	up := &fakeUpdater{staged: selfupdate.Staged{Version: "0.5.0", Path: "/state/update/staged/0.5.0/W1nCray", SHA256: "ab", Size: 12}}
	reg, calls := selfUpdateRegistry(t, up, func() { restarted <- struct{}{} })

	status, res := reg.Execute(context.Background(), panelclient.Command{
		ID: "s1", Type: panelclient.CmdSelfUpdate, Args: json.RawMessage(`{"version":"v0.5.0"}`),
	})
	if status != panelclient.ResultAccepted || len(res) != 0 {
		t.Fatalf("first answer = (%q, %s), want accepted with no body", status, res)
	}
	select {
	case c := <-calls:
		if c.id != "s1" || c.status != panelclient.ResultDone {
			t.Fatalf("final call = %+v, want id s1 done", c)
		}
		var body selfUpdateResult
		if err := json.Unmarshal(c.data, &body); err != nil {
			t.Fatalf("result %s: %v", c.data, err)
		}
		if body.Version != "0.5.0" || !body.Restart {
			t.Errorf("result = %+v", body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the final result never arrived")
	}
	select {
	case <-restarted:
	case <-time.After(2 * time.Second):
		t.Fatal("the process was never asked to restart")
	}
}

// TestSelfUpdateRefusalsAreImmediate covers the synchronous refusals: a bad
// argument list, a machine that cannot self-update and an update that is
// already pending are all answered without starting any work.
func TestSelfUpdateRefusalsAreImmediate(t *testing.T) {
	cases := []struct {
		name string
		args string
		up   *fakeUpdater
		code string
	}{
		{"missing version", `{}`, &fakeUpdater{}, "invalid_args"},
		{"unknown field", `{"version":"1.0.0","force":true}`, &fakeUpdater{}, "invalid_args"},
		{"platform unsupported", `{"version":"1.0.0"}`, &fakeUpdater{readyErr: selfupdate.ErrNotSupported}, "not_supported"},
		{"already pending", `{"version":"1.0.0"}`, &fakeUpdater{hasPending: true, pending: selfupdate.Pending{Version: "0.4.0"}}, "pending"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			restarts := 0
			reg, calls := selfUpdateRegistry(t, tc.up, func() { restarts++ })
			status, res := reg.Execute(context.Background(), panelclient.Command{
				ID: "x", Type: panelclient.CmdSelfUpdate, Args: json.RawMessage(tc.args),
			})
			if status != panelclient.ResultFailed {
				t.Fatalf("status = %q, want failed", status)
			}
			if f := decodeFailure(t, res); f.Code != tc.code {
				t.Errorf("failure = %+v, want code %q", f, tc.code)
			}
			select {
			case c := <-calls:
				t.Fatalf("a refusal must not deliver a late result: %+v", c)
			case <-time.After(50 * time.Millisecond):
			}
			if restarts != 0 {
				t.Error("a refusal must not restart the process")
			}
		})
	}
}

// TestSelfUpdateLateFailuresKeepTheProcessRunning covers the failure paths of
// the background work: none of them may restart the process, and each is
// reported as a failed final result with a stable code.
func TestSelfUpdateLateFailuresKeepTheProcessRunning(t *testing.T) {
	cases := []struct {
		name string
		up   *fakeUpdater
	}{
		{"stage fails", &fakeUpdater{stageErr: errors.New("version not in the manifest")}},
		{"commit fails", &fakeUpdater{staged: selfupdate.Staged{Version: "0.5.0", Path: "/tmp/new"}, commitErr: errors.New("rename failed")}},
		{"helper fails", &fakeUpdater{staged: selfupdate.Staged{Version: "0.5.0", Path: "/tmp/new"}, respawnErr: errors.New("no helper")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			restarted := make(chan struct{}, 1)
			reg, calls := selfUpdateRegistry(t, tc.up, func() { restarted <- struct{}{} })
			if status, _ := reg.Execute(context.Background(), panelclient.Command{
				ID: "f", Type: panelclient.CmdSelfUpdate, Args: json.RawMessage(`{"version":"0.5.0"}`),
			}); status != panelclient.ResultAccepted {
				t.Fatalf("status = %q, want accepted", status)
			}
			select {
			case c := <-calls:
				if c.status != panelclient.ResultFailed {
					t.Fatalf("final call = %+v, want failed", c)
				}
				if f := decodeFailure(t, c.data); f.Error == "" {
					t.Errorf("failure body = %s", c.data)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("the final result never arrived")
			}
			select {
			case <-restarted:
				t.Error("a failed update must not restart the process")
			case <-time.After(50 * time.Millisecond):
			}
		})
	}
}

// TestSelfUpdateRegistrationNeedsBothHalves keeps the capability honest: the
// command is only served when an updater and a restart hook exist.
func TestSelfUpdateRegistrationNeedsBothHalves(t *testing.T) {
	reg := mustRegistry(t, Deps{})
	if err := RegisterSelfUpdate(reg, nil, func() {}); err == nil {
		t.Error("a nil updater must be refused")
	}
	if err := RegisterSelfUpdate(reg, &fakeUpdater{}, nil); err == nil {
		t.Error("a nil restart hook must be refused")
	}
	if reg.Has(panelclient.CmdSelfUpdate) {
		t.Error("a refused registration must leave the command unregistered")
	}
	if err := RegisterSelfUpdate(reg, &fakeUpdater{}, func() {}); err != nil {
		t.Fatalf("RegisterSelfUpdate: %v", err)
	}
	if !reg.Has(panelclient.CmdSelfUpdate) {
		t.Error("self_update must be registered after a successful call")
	}
	// The reserved name is never a kernel command: kernel_install refuses it.
	status, res := reg.Execute(context.Background(), panelclient.Command{
		ID: "k", Type: panelclient.CmdKernelInstall, Args: json.RawMessage(`{"name":"agent","version":"1.0.0"}`),
	})
	if status != panelclient.ResultFailed {
		t.Fatalf("kernel_install agent = %q, want failed", status)
	}
	if f := decodeFailure(t, res); f.Code != "reserved_name" {
		t.Errorf("failure = %+v, want reserved_name", f)
	}
}

// TestEmitEventReachesTheEventSink covers the rollback event the bootstrap
// layer reports outside of any command.
func TestEmitEventReachesTheEventSink(t *testing.T) {
	events := make(chan string, 2)
	reg := mustRegistry(t, Deps{Events: EventFunc(func(kind, level, message string) {
		events <- kind + ":" + level
	})})
	reg.EmitEvent("self_update.rolled_back", "warn", "version 0.5.0 was rolled back")
	select {
	case got := <-events:
		if got != "self_update.rolled_back:warn" {
			t.Errorf("event = %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("the event never reached the sink")
	}
}
