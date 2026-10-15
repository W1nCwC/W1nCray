package opscmd

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/panelclient"
)

// fakeAudit is the AuditControl surface the audit_ctl command drives. The test
// controls both the kernel's support bit and the state the command left behind.
type fakeAudit struct {
	supported bool
	enabled   bool
	// calls counts SetAuditEnabled, and setErr fails it (the command still
	// reports the state it asked for: the switch is applied by the agent loop).
	calls int
}

func (f *fakeAudit) AuditSupported() bool { return f.supported }

func (f *fakeAudit) AuditEnabled() bool { return f.enabled }

func (f *fakeAudit) SetAuditEnabled(enabled bool) bool {
	f.calls++
	f.enabled = enabled
	return enabled
}

// decodeAuditResult reads the {"enabled":bool} body of a successful audit_ctl.
func decodeAuditResult(t *testing.T, res json.RawMessage) auditCtlResult {
	t.Helper()
	var out auditCtlResult
	if err := json.Unmarshal(res, &out); err != nil {
		t.Fatalf("audit_ctl result %s: %v", res, err)
	}
	return out
}

// TestAuditCtlTurnsTheStreamOnAndOff covers the command's happy path: the args
// are strict, the switch is driven, and the result repeats the state in force.
func TestAuditCtlTurnsTheStreamOnAndOff(t *testing.T) {
	ctl := &fakeAudit{supported: true}
	reg := mustRegistry(t, Deps{})
	reg.SetAudit(ctl)

	status, res := reg.Execute(context.Background(), panelclient.Command{
		ID:   "a1",
		Type: panelclient.CmdAuditCtl,
		Args: json.RawMessage(`{"enabled":true}`),
	})
	if status != panelclient.ResultDone {
		t.Fatalf("status = %q, want done (%s)", status, res)
	}
	if got := decodeAuditResult(t, res); !got.Enabled {
		t.Errorf("result = %+v, want enabled", got)
	}
	if !ctl.enabled || ctl.calls != 1 {
		t.Errorf("switch: enabled=%v calls=%d, want true/1", ctl.enabled, ctl.calls)
	}

	status, res = reg.Execute(context.Background(), panelclient.Command{
		ID:   "a2",
		Type: panelclient.CmdAuditCtl,
		Args: json.RawMessage(`{"enabled":false}`),
	})
	if status != panelclient.ResultDone {
		t.Fatalf("status = %q, want done (%s)", status, res)
	}
	if got := decodeAuditResult(t, res); got.Enabled {
		t.Errorf("result = %+v, want disabled", got)
	}
	if ctl.enabled || ctl.calls != 2 {
		t.Errorf("switch: enabled=%v calls=%d, want false/2", ctl.enabled, ctl.calls)
	}
}

// TestAuditCtlRefusesWithoutAWiredStream covers the "never pretend" rule: the
// command is registered, but a registry without a stream answers not_supported
// instead of reporting a switch that does not exist.
func TestAuditCtlRefusesWithoutAWiredStream(t *testing.T) {
	reg := mustRegistry(t, Deps{})
	status, res := reg.Execute(context.Background(), panelclient.Command{
		ID:   "a1",
		Type: panelclient.CmdAuditCtl,
		Args: json.RawMessage(`{"enabled":true}`),
	})
	if status != panelclient.ResultFailed {
		t.Fatalf("status = %q, want failed", status)
	}
	if f := decodeFailure(t, res); f.Code != "not_supported" {
		t.Errorf("code = %q, want not_supported (%s)", f.Code, res)
	}
}

// TestAuditCtlRefusesAKernelWithoutTheCollector covers the capability rule on
// the command path: a kernel that does not serve /audit cannot be switched on.
func TestAuditCtlRefusesAKernelWithoutTheCollector(t *testing.T) {
	ctl := &fakeAudit{supported: false}
	reg := mustRegistry(t, Deps{})
	reg.SetAudit(ctl)

	status, res := reg.Execute(context.Background(), panelclient.Command{
		ID:   "a1",
		Type: panelclient.CmdAuditCtl,
		Args: json.RawMessage(`{"enabled":true}`),
	})
	if status != panelclient.ResultFailed {
		t.Fatalf("status = %q, want failed", status)
	}
	if f := decodeFailure(t, res); f.Code != "not_supported" {
		t.Errorf("code = %q, want not_supported (%s)", f.Code, res)
	}
	if ctl.calls != 0 {
		t.Errorf("the switch was driven %d times for an unsupported kernel", ctl.calls)
	}
}

// TestAuditCtlDecodesArgsStrictly covers the strict decoding rule: an unknown
// field is refused instead of being half-applied, and a missing body means
// "off" (the zero value of the contract's only field).
func TestAuditCtlDecodesArgsStrictly(t *testing.T) {
	ctl := &fakeAudit{supported: true}
	reg := mustRegistry(t, Deps{})
	reg.SetAudit(ctl)

	status, res := reg.Execute(context.Background(), panelclient.Command{
		ID:   "a1",
		Type: panelclient.CmdAuditCtl,
		Args: json.RawMessage(`{"enabled":true,"path":"/etc/shadow"}`),
	})
	if status != panelclient.ResultFailed {
		t.Fatalf("status = %q, want failed (%s)", status, res)
	}
	if f := decodeFailure(t, res); f.Code != "invalid_args" {
		t.Errorf("code = %q, want invalid_args (%s)", f.Code, res)
	}
	if ctl.calls != 0 {
		t.Error("an invalid args body reached the switch")
	}

	// An empty body is the contract's zero value: audit off.
	status, res = reg.Execute(context.Background(), panelclient.Command{
		ID:   "a2",
		Type: panelclient.CmdAuditCtl,
	})
	if status != panelclient.ResultDone {
		t.Fatalf("status = %q, want done (%s)", status, res)
	}
	if got := decodeAuditResult(t, res); got.Enabled {
		t.Errorf("result = %+v, want disabled for an empty body", got)
	}
}
