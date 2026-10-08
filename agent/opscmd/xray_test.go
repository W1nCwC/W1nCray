package opscmd

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/panelclient"
	"github.com/W1nCwC/W1nCray/agent/xraysvc"
	"github.com/W1nCwC/W1nCray/kernel"
	"github.com/W1nCwC/W1nCray/kernel/install"
)

// TestKernelInstallXrayRoutesToTheServiceManager covers PLAN v11 WP-X2: the
// Xray kernel runs as a service of its own, so its kernel_install goes through
// the service manager (install when nothing is installed, upgrade when a
// version already is) instead of the plain file installer.
func TestKernelInstallXrayRoutesToTheServiceManager(t *testing.T) {
	for _, tc := range []struct {
		name string
		list []install.Entry
		want string
	}{
		{"fresh install", nil, "install 2.0.0"},
		{"already installed upgrades", []install.Entry{{Name: "xray", Version: "1.0.0", Current: true}}, "upgrade 2.0.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := &fakeXray{}
			late := make(chan string, 1)
			reg := mustRegistry(t, Deps{
				Kernels: fakeKernels{list: tc.list},
				Xray:    x,
				Sink: SinkFunc(func(id, status string, data json.RawMessage) {
					late <- status
				}),
			})
			status, res := reg.Execute(context.Background(), panelclient.Command{
				ID: "x1", Type: panelclient.CmdKernelInstall,
				Args: json.RawMessage(`{"name":"xray","version":"2.0.0"}`),
			})
			if status != panelclient.ResultAccepted {
				t.Fatalf("kernel_install status = %q (%s), want accepted", status, res)
			}
			select {
			case got := <-late:
				if got != panelclient.ResultDone {
					t.Fatalf("late status = %q, want done", got)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("kernel_install delivered no late result")
			}
			if len(x.calls) != 1 || x.calls[0] != tc.want {
				t.Fatalf("service calls = %v, want [%s]", x.calls, tc.want)
			}
		})
	}
}

func TestKernelRemoveXrayRemovesTheService(t *testing.T) {
	x := &fakeXray{removed: true}
	reg := mustRegistry(t, Deps{Xray: x})
	status, res := reg.Execute(context.Background(), panelclient.Command{
		ID: "x2", Type: panelclient.CmdKernelRemove,
		Args: json.RawMessage(`{"name":"xray"}`),
	})
	if status != panelclient.ResultDone {
		t.Fatalf("kernel_remove = (%q, %s), want done", status, res)
	}
	if len(x.calls) != 1 || x.calls[0] != "remove" {
		t.Fatalf("service calls = %v, want [remove]", x.calls)
	}
	var out panelclient.KernelRemoveResult
	if err := json.Unmarshal(res, &out); err != nil {
		t.Fatalf("result %s: %v", res, err)
	}
	if out.AlreadyAbsent {
		t.Errorf("a real service removal reported already_absent: %+v", out)
	}
}

// TestKernelRemoveXrayReportsTheFreedBytes covers REG2 observation 1: removing
// the Xray kernel through the service manager answered freed_bytes=0 while the
// supervised kernels reported the declared installed size. The service manager
// deletes every installed version at once, so the freed bytes are the sum over
// them, read before the removal exactly like the gost/realm/frp branch does.
// Before the fix this command returned {"freed_bytes":0}.
func TestKernelRemoveXrayReportsTheFreedBytes(t *testing.T) {
	x := &fakeXray{removed: true}
	reg := mustRegistry(t, Deps{
		Kernels: fakeKernels{list: []install.Entry{
			{Name: "xray", Version: "0.6.3", Current: true, Size: 41_000_000},
			{Name: "xray", Version: "0.6.2", Size: 40_000_000},
			// Another kernel on the machine must never leak into the sum.
			{Name: "gost", Version: "3.3.0", Size: 7_000_000},
		}},
		Xray: x,
	})
	status, res := reg.Execute(context.Background(), panelclient.Command{
		ID: "x8", Type: panelclient.CmdKernelRemove,
		Args: json.RawMessage(`{"name":"xray"}`),
	})
	if status != panelclient.ResultDone {
		t.Fatalf("kernel_remove xray = (%q, %s), want done", status, res)
	}
	var out panelclient.KernelRemoveResult
	if err := json.Unmarshal(res, &out); err != nil {
		t.Fatalf("result %s: %v", res, err)
	}
	if out.AlreadyAbsent {
		t.Errorf("a real removal reported already_absent: %s", res)
	}
	if out.FreedBytes != 81_000_000 {
		t.Errorf("freed_bytes = %d, want 81000000 (every installed xray version, gost excluded)", out.FreedBytes)
	}
}

// TestKernelRemoveXrayAbsentReportsNoFreedBytes pins the idempotent half: with
// nothing installed the command still answers already_absent and must not
// invent freed bytes.
func TestKernelRemoveXrayAbsentReportsNoFreedBytes(t *testing.T) {
	x := &fakeXray{} // removed=false: there was nothing to remove
	reg := mustRegistry(t, Deps{Xray: x})
	status, res := reg.Execute(context.Background(), panelclient.Command{
		ID: "x9", Type: panelclient.CmdKernelRemove,
		Args: json.RawMessage(`{"name":"xray"}`),
	})
	if status != panelclient.ResultDone {
		t.Fatalf("kernel_remove xray = (%q, %s), want done", status, res)
	}
	var out panelclient.KernelRemoveResult
	if err := json.Unmarshal(res, &out); err != nil {
		t.Fatalf("result %s: %v", res, err)
	}
	if !out.AlreadyAbsent || out.FreedBytes != 0 {
		t.Errorf("kernel_remove on an absent service = %s, want already_absent with freed_bytes 0", res)
	}
}

// TestKernelRemoveXrayIsIdempotent covers D-M2's xray half: when the service
// manager has nothing to remove (never installed, or already removed), the
// command answers done with already_absent instead of the "Unit not loaded"
// failure the matrix reported.
func TestKernelRemoveXrayIsIdempotent(t *testing.T) {
	x := &fakeXray{} // removed=false: there was nothing to remove
	reg := mustRegistry(t, Deps{Xray: x})
	status, res := reg.Execute(context.Background(), panelclient.Command{
		ID: "x6", Type: panelclient.CmdKernelRemove,
		Args: json.RawMessage(`{"name":"xray"}`),
	})
	if status != panelclient.ResultDone {
		t.Fatalf("kernel_remove xray = (%q, %s), want done", status, res)
	}
	if len(x.calls) != 1 || x.calls[0] != "remove" {
		t.Fatalf("service calls = %v, want [remove]", x.calls)
	}
	var out panelclient.KernelRemoveResult
	if err := json.Unmarshal(res, &out); err != nil {
		t.Fatalf("result %s: %v", res, err)
	}
	if !out.AlreadyAbsent {
		t.Errorf("kernel_remove on an absent service = %s, want already_absent", res)
	}
}

// TestKernelRemoveXrayReportsInUseWhileTheProcessLives is the wire half of
// R1-8: the service manager refuses to delete the kernel files while the kernel
// process is still alive, and the panel must see the stable in_use code instead
// of a generic error.
func TestKernelRemoveXrayReportsInUseWhileTheProcessLives(t *testing.T) {
	x := &fakeXray{err: kernel.Newf(kernel.ErrInUse, "xray", "", "内核进程尚未退出")}
	reg := mustRegistry(t, Deps{Xray: x})
	status, res := reg.Execute(context.Background(), panelclient.Command{
		ID: "x7", Type: panelclient.CmdKernelRemove,
		Args: json.RawMessage(`{"name":"xray"}`),
	})
	if status != panelclient.ResultFailed {
		t.Fatalf("kernel_remove = (%q, %s), want failed", status, res)
	}
	if f := decodeFailure(t, res); f.Code != "in_use" {
		t.Fatalf("failure = %+v, want code in_use", f)
	}
	if len(x.calls) != 1 || x.calls[0] != "remove" {
		t.Fatalf("service calls = %v, want [remove]", x.calls)
	}
}

func TestKernelRollbackXrayUsesTheServiceManager(t *testing.T) {
	x := &fakeXray{}
	reg := mustRegistry(t, Deps{
		Kernels: fakeKernels{list: []install.Entry{{Name: "xray", Version: "1.0.0", Current: true, Path: "/x"}}},
		Xray:    x,
	})
	status, res := reg.Execute(context.Background(), panelclient.Command{
		ID: "x3", Type: panelclient.CmdKernelRollback,
		Args: json.RawMessage(`{"name":"xray"}`),
	})
	if status != panelclient.ResultDone {
		t.Fatalf("kernel_rollback = (%q, %s), want done", status, res)
	}
	if len(x.calls) != 1 || x.calls[0] != "rollback" {
		t.Fatalf("service calls = %v, want [rollback]", x.calls)
	}
	var out installedResult
	if err := json.Unmarshal(res, &out); err != nil || out.Name != "xray" || out.Version != "1.0.0" {
		t.Fatalf("result = %s (%v)", res, err)
	}
}

func TestComponentRestartXrayUsesTheServiceManager(t *testing.T) {
	comp := &fakeComp{}
	x := &fakeXray{}
	reg := mustRegistry(t, Deps{Comp: comp, Xray: x})
	status, res := reg.Execute(context.Background(), panelclient.Command{
		ID: "x4", Type: panelclient.CmdComponentRestart, Args: json.RawMessage(`{"name":"xray"}`),
	})
	if status != panelclient.ResultDone {
		t.Fatalf("component_restart xray = (%q, %s), want done", status, res)
	}
	var out restartedResult
	if err := json.Unmarshal(res, &out); err != nil || out.Name != "xray" || out.Restarted != 1 {
		t.Fatalf("result = %s (%v)", res, err)
	}
	if len(x.calls) != 1 || x.calls[0] != "restart" {
		t.Fatalf("service calls = %v, want [restart]", x.calls)
	}
	if len(comp.calls) != 0 {
		t.Fatalf("the supervisor was used for a service kernel: %v", comp.calls)
	}
}

// TestKernelListCarriesTheXrayService covers the wire shape: kernel_list lists
// xray like every other kernel and adds the service backend and state.
func TestKernelListCarriesTheXrayService(t *testing.T) {
	reg := mustRegistry(t, Deps{
		Kernels: fakeKernels{list: []install.Entry{{Name: "xray", Version: "0.6.0", Current: true}}},
		Xray: &fakeXray{status: xraysvc.Status{
			Backend: xraysvc.BackendSystemd, State: xraysvc.StateRunning, ManagedBy: "service",
		}},
	})
	status, res := reg.Execute(context.Background(), panelclient.Command{ID: "x5", Type: panelclient.CmdKernelList})
	if status != panelclient.ResultDone {
		t.Fatalf("kernel_list = (%q, %s)", status, res)
	}
	var out panelclient.KernelListResult
	if err := json.Unmarshal(res, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Kernels) != 1 {
		t.Fatalf("kernels = %+v", out.Kernels)
	}
	svc := out.Kernels[0].Service
	if svc == nil || svc.Backend != xraysvc.BackendSystemd || svc.State != xraysvc.StateRunning || svc.ManagedBy != "service" {
		t.Fatalf("service = %+v", svc)
	}
}
