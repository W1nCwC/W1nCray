package bootstrap

import (
	"context"
	"errors"
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

// TestResolveUpdaterExeFallsBackToTheInstalledPath is the D-M7 self-heal: when
// the running image no longer resolves ("<path> (deleted)" after a rollback
// raced this start), the self-update must target the installed path from the
// service unit instead of giving up on the upgrade capability. It failed before
// the fix (the deleted path was kept and Ready refused it).
func TestResolveUpdaterExeFallsBackToTheInstalledPath(t *testing.T) {
	ok := func(string) (string, error) { return "/usr/local/W1nCray/W1nCray", nil }
	gone := func(string) (string, error) {
		return "", errors.New("lstat /usr/local/W1nCray/W1nCray (deleted): no such file")
	}

	// The running executable resolves: it wins, no fallback.
	got, healed := resolveUpdaterExe("/proc/self/exe", ok, func() string { return "/install/W1nCray" })
	if got != "/usr/local/W1nCray/W1nCray" || healed {
		t.Errorf("resolving path = (%q, %v), want the resolved path and no fallback", got, healed)
	}

	// It does not resolve and a service unit names the installed path.
	got, healed = resolveUpdaterExe("/usr/local/W1nCray/W1nCray (deleted)", gone, func() string { return "/install/W1nCray" })
	if got != "/install/W1nCray" || !healed {
		t.Errorf("fallback = (%q, %v), want the installed path and healed=true", got, healed)
	}

	// It does not resolve and there is no installed path: keep the running one
	// and let Ready report the readable diagnostic.
	got, healed = resolveUpdaterExe("/x/W1nCray (deleted)", gone, func() string { return "" })
	if got != "/x/W1nCray (deleted)" || healed {
		t.Errorf("no-installed path = (%q, %v), want the running path and healed=false", got, healed)
	}
}

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
