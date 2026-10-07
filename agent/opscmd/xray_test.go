package opscmd

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/panelclient"
	"github.com/W1nCwC/W1nCray/agent/xraysvc"
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
	x := &fakeXray{}
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
