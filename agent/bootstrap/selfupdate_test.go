package bootstrap

import (
	"context"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/opscmd"
	"github.com/W1nCwC/W1nCray/agent/panelclient"
	"github.com/W1nCwC/W1nCray/agent/selfupdate"
	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// fakeSelfUpdate is the SelfUpdateOps surface with nothing behind it.
type fakeSelfUpdate struct{}

func (fakeSelfUpdate) Stage(context.Context, string) (selfupdate.Staged, error) {
	return selfupdate.Staged{Version: "0.5.0"}, nil
}
func (fakeSelfUpdate) Commit(selfupdate.Staged) error      { return nil }
func (fakeSelfUpdate) RespawnHelper() error                { return nil }
func (fakeSelfUpdate) Ready() error                        { return nil }
func (fakeSelfUpdate) Pending() (selfupdate.Pending, bool) { return selfupdate.Pending{}, false }

// TestUpgradeCapabilityFollowsTheRegistration covers protocol ruling 11: the
// "upgrade" capability is a promise that self_update is served here, so it is
// declared exactly when the command is registered — not merely when the binary
// was built for a platform that could support it.
func TestUpgradeCapabilityFollowsTheRegistration(t *testing.T) {
	rt, _ := bootCycle(t, t.TempDir(), false, nil)
	if rt.Updater == nil {
		t.Fatal("Boot did not build a self-update updater")
	}
	if rt.upgradeCapable() {
		t.Error("self_update is registered by StartRemote, not Boot; the capability must not be declared yet")
	}
	if got := rt.Streams(nil, nil).Capabilities(); hasCapability(got, wsproto.CapUpgrade) {
		t.Errorf("capabilities = %v, want no upgrade before registration", got)
	}

	reg, err := opscmd.New(opscmd.Deps{Kernels: rt.Kernels})
	if err != nil {
		t.Fatal(err)
	}
	rt.Ops = reg
	if err := opscmd.RegisterSelfUpdate(reg, fakeSelfUpdate{}, func() {}); err != nil {
		t.Fatalf("RegisterSelfUpdate: %v", err)
	}
	if !rt.upgradeCapable() {
		t.Fatal("a registered self_update must make the runtime upgrade-capable")
	}
	if got := rt.Streams(nil, nil).Capabilities(); !hasCapability(got, wsproto.CapUpgrade) {
		t.Errorf("capabilities = %v, want upgrade", got)
	}
	// The list must stay a copy the caller cannot mutate.
	got := rt.Streams(nil, nil).Capabilities()
	if len(got) == 0 {
		t.Fatal("empty capabilities")
	}
	got[0] = "mutated"
	if again := rt.Streams(nil, nil).Capabilities(); again[0] == "mutated" {
		t.Error("Capabilities() returned a shared slice")
	}
}

// TestUpgradeCapabilityIsWithheldWhenReadyFails keeps the capability honest on
// a machine that cannot replace its own executable: the updater exists, the
// command could be registered, but Ready refuses.
func TestUpgradeCapabilityIsWithheldWhenReadyFails(t *testing.T) {
	rt, _ := bootCycle(t, t.TempDir(), false, nil)
	if rt.Updater == nil {
		t.Fatal("Boot did not build a self-update updater")
	}
	// Whatever the host says, upgradeReady must be exactly Ready()'s verdict.
	if want := rt.Updater.Ready() == nil; rt.upgradeReady != want {
		t.Fatalf("upgradeReady = %v, Ready() == nil is %v", rt.upgradeReady, want)
	}
}

// TestSelfUpdateIsNeverAKernelCommand covers the reserved name end to end: the
// kernel commands refuse "agent" so nothing but self_update can touch it.
func TestSelfUpdateIsNeverAKernelCommand(t *testing.T) {
	rt, _ := bootCycle(t, t.TempDir(), false, nil)
	status, res := rt.Ops.Execute(context.Background(), panelclient.Command{
		ID: "k1", Type: panelclient.CmdKernelInstall, Args: []byte(`{"name":"agent","version":"0.5.0"}`),
	})
	if status != panelclient.ResultFailed {
		t.Fatalf("kernel_install agent = %q (%s), want failed", status, res)
	}
	status, res = rt.Ops.Execute(context.Background(), panelclient.Command{
		ID: "k2", Type: panelclient.CmdKernelRemove, Args: []byte(`{"name":"agent","version":"0.5.0"}`),
	})
	if status != panelclient.ResultFailed {
		t.Fatalf("kernel_remove agent = %q (%s), want failed", status, res)
	}
	status, res = rt.Ops.Execute(context.Background(), panelclient.Command{
		ID: "k3", Type: panelclient.CmdKernelRollback, Args: []byte(`{"name":"agent"}`),
	})
	if status != panelclient.ResultFailed {
		t.Fatalf("kernel_rollback agent = %q (%s), want failed", status, res)
	}
}
