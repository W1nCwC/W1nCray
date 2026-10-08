package opscmd

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/panelclient"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/agent/xrayapi"
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

// rigXrayService drives the real kernel installer the way agent/xraysvc does:
// Install/Upgrade make a version current through the installer, Rollback swaps
// the pointers, and Remove deletes the whole kernel. Every service call is
// recorded, so the test can prove that removing one non-current version never
// touches the service.
type rigXrayService struct {
	rig   *kernelRig
	calls []string
}

func (s *rigXrayService) Install(ctx context.Context, version string) error {
	s.calls = append(s.calls, "install "+version)
	_, err := s.rig.ensurePinForce(ctx, spec.KernelPin{Name: xrayapi.KernelName, Version: version})
	return err
}

func (s *rigXrayService) Upgrade(ctx context.Context, version string) error {
	s.calls = append(s.calls, "upgrade "+version)
	_, err := s.rig.ensurePinForce(ctx, spec.KernelPin{Name: xrayapi.KernelName, Version: version})
	return err
}

func (s *rigXrayService) Rollback(context.Context) error {
	s.calls = append(s.calls, "rollback")
	_, err := s.rig.in.Rollback(xrayapi.KernelName)
	return err
}

func (s *rigXrayService) Restart(context.Context) error {
	s.calls = append(s.calls, "restart")
	return nil
}

func (s *rigXrayService) Remove(context.Context) (bool, error) {
	s.calls = append(s.calls, "remove")
	removed := false
	list, err := s.rig.in.List()
	if err != nil {
		return false, err
	}
	for _, e := range list {
		if e.Name == xrayapi.KernelName {
			removed = true
			break
		}
	}
	rerr := s.rig.in.Remove(xrayapi.KernelName, "")
	if errors.Is(rerr, kernel.ErrNotInstalled) {
		rerr = nil
	}
	return removed, rerr
}

func (s *rigXrayService) Status(context.Context) (xraysvc.Status, error) {
	return xraysvc.Status{Backend: xraysvc.BackendSystemd, State: xraysvc.StateRunning, ManagedBy: "service"}, nil
}

// TestKernelRemoveXrayHonoursTheVersion reproduces FIN1-1 end to end against
// the real installer: install 0.6.7, install 0.6.8, roll back (current 0.6.7,
// previous 0.6.8), then kernel_remove xray 0.6.8. Before the fix the xray
// branch short-circuited before the version: it uninstalled the whole kernel
// (freed_bytes was the sum of both versions) and the following kernel_list was
// empty, even though the panel named a stale version only. After the fix only
// 0.6.8 is deleted, the service is untouched and 0.6.7 stays current. Removing
// the current version is the uninstall: it stops the service, deletes every
// version and reports uninstalled=true.
func TestKernelRemoveXrayHonoursTheVersion(t *testing.T) {
	rig := newKernelRig(t)
	rig.addKernelVersion("xray", "0.6.7")
	rig.addKernelVersion("xray", "0.6.8")
	svc := &rigXrayService{rig: rig}
	late := make(chan string, 4)
	reg := mustRegistry(t, Deps{
		Kernels: rig.ops("", false),
		Xray:    svc,
		Sink: SinkFunc(func(id, status string, data json.RawMessage) {
			late <- status
		}),
	})
	ctx := context.Background()

	install := func(id, version string) {
		t.Helper()
		status, res := reg.Execute(ctx, panelclient.Command{
			ID: id, Type: panelclient.CmdKernelInstall,
			Args: json.RawMessage(`{"name":"xray","version":"` + version + `"}`),
		})
		if status != panelclient.ResultAccepted {
			t.Fatalf("kernel_install xray %s = (%q, %s), want accepted", version, status, res)
		}
		select {
		case got := <-late:
			if got != panelclient.ResultDone {
				t.Fatalf("kernel_install xray %s late status = %q, want done", version, got)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("kernel_install xray %s delivered no late result", version)
		}
	}
	remove := func(id, version string) (string, json.RawMessage, panelclient.KernelRemoveResult) {
		t.Helper()
		status, res := reg.Execute(ctx, panelclient.Command{
			ID: id, Type: panelclient.CmdKernelRemove,
			Args: json.RawMessage(`{"name":"xray","version":"` + version + `"}`),
		})
		var out panelclient.KernelRemoveResult
		if status == panelclient.ResultDone {
			if err := json.Unmarshal(res, &out); err != nil {
				t.Fatalf("kernel_remove xray %s result %s: %v", version, res, err)
			}
		}
		return status, res, out
	}

	install("f1", "0.6.7")
	install("f2", "0.6.8")

	// Roll back: current 0.6.7, previous 0.6.8, exactly the FIN1-1 state.
	status, res := reg.Execute(ctx, panelclient.Command{
		ID: "f3", Type: panelclient.CmdKernelRollback, Args: json.RawMessage(`{"name":"xray"}`),
	})
	if status != panelclient.ResultDone {
		t.Fatalf("kernel_rollback xray = (%q, %s), want done", status, res)
	}
	if e, ok := rig.entry("0.6.7"); !ok || !e.Current {
		t.Fatalf("after rollback 0.6.7 = %+v (present=%v), want current", e, ok)
	}
	size067, _ := rig.entry("0.6.7")
	size068, _ := rig.entry("0.6.8")
	svc.calls = nil // the install/upgrade/rollback calls are not what this test checks

	// FIN1-1: removing the previous version must delete only that version.
	status, res, out := remove("f4", "0.6.8")
	if status != panelclient.ResultDone {
		t.Fatalf("kernel_remove xray 0.6.8 = (%q, %s), want done", status, res)
	}
	if out.AlreadyAbsent || out.Uninstalled {
		t.Errorf("removing the previous version = %s, want a plain version removal", res)
	}
	if out.FreedBytes != size068.Size {
		t.Errorf("freed_bytes = %d, want %d (only 0.6.8)", out.FreedBytes, size068.Size)
	}
	if out.FreedBytes == size067.Size+size068.Size {
		t.Errorf("freed_bytes = %d is the whole kernel: the version was ignored", out.FreedBytes)
	}
	if len(svc.calls) != 0 {
		t.Errorf("service calls = %v, want none: removing a non-current version must not stop Xray", svc.calls)
	}
	if _, ok := rig.entry("0.6.8"); ok {
		t.Error("0.6.8 is still installed")
	}
	if e, ok := rig.entry("0.6.7"); !ok || !e.Current {
		t.Fatalf("after removing 0.6.8, 0.6.7 = %+v (present=%v), want current", e, ok)
	}

	// The panel-visible list must still carry the current version.
	status, res = reg.Execute(ctx, panelclient.Command{ID: "f5", Type: panelclient.CmdKernelList})
	if status != panelclient.ResultDone {
		t.Fatalf("kernel_list = (%q, %s), want done", status, res)
	}
	var listed panelclient.KernelListResult
	if err := json.Unmarshal(res, &listed); err != nil {
		t.Fatalf("kernel_list result %s: %v", res, err)
	}
	if len(listed.Kernels) != 1 || listed.Kernels[0].Version != "0.6.7" || !listed.Kernels[0].Current {
		t.Fatalf("kernel_list after removing 0.6.8 = %s, want exactly 0.6.7 current", res)
	}

	// Removing the current version is the uninstall of the whole service.
	status, res, out = remove("f6", "0.6.7")
	if status != panelclient.ResultDone {
		t.Fatalf("kernel_remove xray 0.6.7 (current) = (%q, %s), want done", status, res)
	}
	if !out.Uninstalled {
		t.Errorf("removing the current version = %s, want uninstalled=true", res)
	}
	if out.FreedBytes != size067.Size {
		t.Errorf("freed_bytes = %d, want %d (the last version)", out.FreedBytes, size067.Size)
	}
	if len(svc.calls) != 1 || svc.calls[0] != "remove" {
		t.Fatalf("service calls = %v, want [remove]", svc.calls)
	}
	if got := rig.list(); len(got) != 0 {
		t.Errorf("installed kernels after the uninstall = %+v, want none", got)
	}

	// A version that is not installed stays the idempotent already_absent.
	status, res, out = remove("f7", "0.6.9")
	if status != panelclient.ResultDone {
		t.Fatalf("kernel_remove xray 0.6.9 = (%q, %s), want done", status, res)
	}
	if !out.AlreadyAbsent || out.FreedBytes != 0 || out.Uninstalled {
		t.Errorf("removing a never-installed version = %s, want already_absent with freed_bytes 0", res)
	}
	if len(svc.calls) != 1 {
		t.Errorf("service calls after already_absent = %v, want the uninstall only", svc.calls)
	}
}

// TestKernelRemoveXrayRefusesAnOlderVersionThatIsStillRunning keeps the safety
// check of the supervised kernels on the new per-version xray path: a rollback
// can leave an older version executing, and deleting its directory would unlink
// a live binary (FIN1-1 impact 3).
func TestKernelRemoveXrayRefusesAnOlderVersionThatIsStillRunning(t *testing.T) {
	x := &fakeXray{}
	reg := mustRegistry(t, Deps{
		Kernels: fakeKernels{
			list: []install.Entry{
				{Name: "xray", Version: "0.6.7", Current: true, Size: 100},
				{Name: "xray", Version: "0.6.8", Previous: true, Size: 200},
			},
			running: "0.6.8", exact: true,
		},
		Xray: x,
	})
	status, res := reg.Execute(context.Background(), panelclient.Command{
		ID: "xr1", Type: panelclient.CmdKernelRemove,
		Args: json.RawMessage(`{"name":"xray","version":"0.6.8"}`),
	})
	if status != panelclient.ResultFailed || decodeFailure(t, res).Code != "in_use" {
		t.Fatalf("removing an executing older xray version = (%q, %s), want failed/in_use", status, res)
	}
	if len(x.calls) != 0 {
		t.Errorf("service calls = %v, want none: a refused removal must not touch the service", x.calls)
	}
}
