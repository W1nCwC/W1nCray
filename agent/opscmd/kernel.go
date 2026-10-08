// This file registers the kernel_* commands and component_restart. The heavy
// lifting (downloading, verifying, switching, refusing the current version,
// swapping the pointers) lives in kernel/install; this file only decodes the
// arguments, enforces the reserved name, decides which commands are long, and
// maps the outcome onto the wire.

package opscmd

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/panelclient"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/agent/wsproto"
	"github.com/W1nCwC/W1nCray/agent/xrayapi"
	"github.com/W1nCwC/W1nCray/kernel"
	"github.com/W1nCwC/W1nCray/kernel/install"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
)

// ReservedAgentName is the manifest kernel name reserved for self_update
// (protocol ruling 11). Every kernel_* command that names a kernel refuses it,
// and component_restart refuses it too: the agent is not a kernel.
const ReservedAgentName = "agent"

// reKernelName mirrors the manifest's kernel-name rule so an invalid name is
// rejected before it reaches the installer (which would only report it as a
// missing kernel).
var reKernelName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// installedResult is the result of a successful kernel_install or
// kernel_rollback.
type installedResult struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Path    string `json:"path,omitempty"`
}

// restartedResult is the result of component_restart.
type restartedResult struct {
	Name      string `json:"name"`
	Restarted int    `json:"restarted"`
}

// kernelCmds holds the dependencies of the kernel handlers. It reads the
// registry for the sinks so they can be installed after construction.
type kernelCmds struct {
	reg  *Registry
	deps Deps
}

// registerKernel adds the operation commands of this work package. Later
// packages add their own registrations the same way.
func registerKernel(r *Registry, d Deps) error {
	k := &kernelCmds{reg: r, deps: d}
	for _, c := range []struct {
		typ string
		h   Handler
	}{
		{panelclient.CmdKernelList, k.kernelList},
		{panelclient.CmdKernelInstall, k.kernelInstall},
		{panelclient.CmdKernelRemove, k.kernelRemove},
		{panelclient.CmdKernelRollback, k.kernelRollback},
		{panelclient.CmdComponentRestart, k.componentRestart},
	} {
		if err := r.Register(c.typ, c.h); err != nil {
			return err
		}
	}
	return nil
}

// checkKernelName rejects an empty, reserved or malformed kernel name.
func checkKernelName(name string) error {
	if name == "" {
		return coded("invalid_args", errors.New("name is required"))
	}
	if name == ReservedAgentName {
		return coded("reserved_name", fmt.Errorf("kernel name %q is reserved for self_update", name))
	}
	if !reKernelName.MatchString(name) {
		return coded("invalid_args", fmt.Errorf("invalid kernel name %q", name))
	}
	return nil
}

// InUse reports whether an installed kernel entry is the version that is
// really running. exact is the second value of KernelOps.RunningVersion: when
// the platform cannot verify which binary a process executes, the current
// pointer is the best available answer and is used instead (never a guess).
//
// It lives here because the kernel commands and the hello/report collector
// must agree: one rule, one place.
func InUse(entry install.Entry, running string, exact bool) bool {
	if exact {
		return entry.Version == running
	}
	return entry.Current
}

// kernelList answers kernel_list: what is installed and what the signed
// manifest offers. The installed versions are a fact and are always returned;
// a missing manifest only empties the catalog (design section 3.2).
func (k *kernelCmds) kernelList(ctx context.Context, req Request, complete Completion) (Result, error) {
	list, err := k.deps.Kernels.List()
	if err != nil {
		return Result{}, fmt.Errorf("listing the installed kernels: %w", err)
	}
	entries := make([]wsproto.KernelEntry, 0, len(list))
	running := map[string]string{}
	exact := map[string]bool{}
	for _, e := range list {
		if _, seen := exact[e.Name]; !seen {
			v, ex := k.deps.Kernels.RunningVersion(e.Name)
			running[e.Name], exact[e.Name] = v, ex
		}
		entry := wsproto.KernelEntry{
			Name:      e.Name,
			Version:   e.Version,
			Current:   e.Current,
			Previous:  e.Previous,
			Path:      e.Path,
			SizeBytes: e.Size,
			InUse:     InUse(e, running[e.Name], exact[e.Name]),
		}
		if e.Name == xrayapi.KernelName && k.deps.Xray != nil {
			entry.Service = k.xrayServiceInfo(ctx)
		}
		if !e.InstalledAt.IsZero() {
			entry.InstalledAt = e.InstalledAt.Unix()
		}
		entries = append(entries, entry)
	}
	cat, catErr := k.deps.Kernels.Catalog()
	if catErr != nil {
		k.reg.logf().Warnf("opscmd: kernel_list has no catalog: %v", catErr)
	}
	return done(panelclient.KernelListResult{Kernels: entries, Catalog: catalogOf(cat)}), nil
}

// catalogOf groups the available manifest entries by name. Unavailable
// versions (no target for this platform, revoked, agent too old) are left out:
// the panel must not offer an install that cannot work.
func catalogOf(entries []install.CatalogEntry) []panelclient.KernelCatalogEntry {
	byName := map[string][]string{}
	for _, e := range entries {
		if !e.Available {
			continue
		}
		byName[e.Name] = append(byName[e.Name], e.Version)
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]panelclient.KernelCatalogEntry, 0, len(names))
	for _, n := range names {
		out = append(out, panelclient.KernelCatalogEntry{Name: n, Versions: byName[n]})
	}
	return out
}

// xrayServiceInfo reports the service state of the Xray kernel for
// kernel_list, hello and /report. A failure is reported as an entry with an
// empty state, never by dropping the kernel from the list.
func (k *kernelCmds) xrayServiceInfo(ctx context.Context) *wsproto.KernelService {
	if k.deps.Xray == nil {
		return nil
	}
	st, err := k.deps.Xray.Status(ctx)
	if err != nil {
		return &wsproto.KernelService{}
	}
	return &wsproto.KernelService{Backend: st.Backend, State: st.State, ManagedBy: st.ManagedBy}
}

// kernelInstall answers kernel_install. Downloading, verifying and switching
// can take minutes, so it answers "accepted" immediately and reports the
// outcome through the registry's sink (ruling 7).
func (k *kernelCmds) kernelInstall(ctx context.Context, req Request, complete Completion) (Result, error) {
	var a panelclient.KernelInstallArgs
	if err := decodeArgs(req.Args, &a); err != nil {
		return Result{}, err
	}
	if err := checkKernelName(a.Name); err != nil {
		return Result{}, err
	}
	version := manifest.NormalizeVersion(a.Version)
	if a.Name == xrayapi.KernelName && k.deps.Xray != nil {
		return k.xrayInstall(ctx, version, complete)
	}
	pin := spec.KernelPin{Name: a.Name, Version: version}
	wanted := version
	if wanted == "" {
		wanted = "newest"
	}
	k.reg.logf().Infof("opscmd: kernel_install %s@%s accepted", a.Name, wanted)
	go func() {
		// EnsureForce, not Ensure: an administrator explicitly asked for this
		// version, so the automatic retry back-off (which a rollback arms) must
		// not refuse it (D-M3).
		inst, err := k.deps.Kernels.EnsureForce(ctx, pin)
		if err != nil {
			k.reg.logf().Warnf("opscmd: kernel_install %s@%s failed: %v", a.Name, wanted, err)
			complete(StatusFailed, nil, err)
			return
		}
		k.reg.logf().Infof("opscmd: kernel_install %s@%s done", a.Name, inst.Version)
		k.reg.event("kernel.installed", "info", fmt.Sprintf("kernel %s@%s installed", a.Name, inst.Version))
		complete(StatusDone, mustJSON(installedResult{Name: a.Name, Version: inst.Version, Path: inst.Path}), nil)
	}()
	return accepted(), nil
}

// xrayInstall answers kernel_install for the Xray kernel through the service
// manager: the kernel runs as a service of its own, so installing means
// installing the service too. A version that is already installed is upgraded
// (with automatic rollback on a failed health check) instead of reinstalled.
func (k *kernelCmds) xrayInstall(ctx context.Context, version string, complete Completion) (Result, error) {
	wanted := version
	if wanted == "" {
		wanted = "newest"
	}
	k.reg.logf().Infof("opscmd: kernel_install xray@%s accepted (service)", wanted)
	go func() {
		var err error
		if k.anyInstalled(xrayapi.KernelName) {
			err = k.deps.Xray.Upgrade(ctx, version)
		} else {
			err = k.deps.Xray.Install(ctx, version)
		}
		if err != nil {
			k.reg.logf().Warnf("opscmd: kernel_install xray@%s failed: %v", wanted, err)
			complete(StatusFailed, nil, err)
			return
		}
		inst := k.currentOf(xrayapi.KernelName)
		k.reg.logf().Infof("opscmd: kernel_install xray@%s done (service)", inst.Version)
		k.reg.event("kernel.installed", "info", fmt.Sprintf("kernel xray@%s installed and running as a service", inst.Version))
		complete(StatusDone, mustJSON(installedResult{Name: xrayapi.KernelName, Version: inst.Version, Path: inst.Path}), nil)
	}()
	return accepted(), nil
}

// currentOf returns the installed current version of a kernel from the kernel
// list (KernelOps deliberately has no Current: the pointer is a detail of the
// installer).
func (k *kernelCmds) currentOf(name string) driver.Installed {
	list, err := k.deps.Kernels.List()
	if err != nil {
		return driver.Installed{}
	}
	for _, e := range list {
		if e.Name == name && e.Current {
			return driver.Installed{Path: e.Path, Version: e.Version}
		}
	}
	return driver.Installed{}
}

// anyInstalled reports whether any version of a kernel is installed.
func (k *kernelCmds) anyInstalled(name string) bool {
	list, err := k.deps.Kernels.List()
	if err != nil {
		return false
	}
	for _, e := range list {
		if e.Name == name {
			return true
		}
	}
	return false
}

// kernelRemove answers kernel_remove. It is quick (no network), so it finishes
// inline. A version that is executing right now is refused even when the
// current pointer already moved on, which a rollback can leave behind.
//
// It is a version-level command: one installed version is deleted and the
// others stay. The Xray kernel is the single exception to the "the current
// version is refused" rule, because it is a service: naming its current version
// means uninstalling the kernel. xrayRemove below spells that out.
func (k *kernelCmds) kernelRemove(ctx context.Context, req Request, complete Completion) (Result, error) {
	var a panelclient.KernelRemoveArgs
	if err := decodeArgs(req.Args, &a); err != nil {
		return Result{}, err
	}
	if err := checkKernelName(a.Name); err != nil {
		return Result{}, err
	}
	// The Xray kernel is a service, so kernel_remove has two meanings that the
	// requested version decides (FIN1-1: the version used to be ignored and
	// every installed version was deleted):
	//
	//   - the version is not the current one: delete just that version
	//     directory through the plain kernel installer, exactly like
	//     gost/realm/frp. The service is not stopped or rewritten; a version
	//     that is really executing right now is still refused (in_use), and the
	//     installer clears the rollback pointer when the version was the
	//     previous one.
	//   - the version is the current one: that is an uninstall. Stop and
	//     disable the service, delete its unit file and remove every installed
	//     version, while config.yml and the managed files stay.
	//
	// The panel always sends a version (W1nCBoard: kernel_remove's version is
	// required) and refuses the command with 409 xray_in_use while nodes are
	// still bound to the machine. An empty version is not part of the protocol:
	// it keeps the historical whole-service uninstall for backward
	// compatibility and is logged as a warning.
	//
	// It is idempotent (D-M2): a machine where the service was never installed
	// answers done with already_absent, never a "Unit not loaded" failure.
	if a.Name == xrayapi.KernelName && k.deps.Xray != nil {
		return k.xrayRemove(ctx, a)
	}
	if a.Version == "" {
		return Result{}, coded("invalid_args", errors.New("version is required"))
	}
	version := manifest.NormalizeVersion(a.Version)
	if running, exact := k.deps.Kernels.RunningVersion(a.Name); exact && running == version {
		return Result{}, coded("in_use", fmt.Errorf("kernel %s@%s is running; ensure or roll back to another version first", a.Name, version))
	}
	// The declared installed size is what the version occupied; it is read
	// before the removal because afterwards the entry is gone.
	freed := k.installedSizeOf(a.Name, version)
	if err := k.deps.Kernels.Remove(a.Name, version); err != nil {
		// An already removed version is the desired state of kernel_remove:
		// report success with already_absent instead of failing the command
		// (D-M2). This makes gost/realm/frp removal idempotent too.
		if errors.Is(err, kernel.ErrNotInstalled) {
			k.reg.logf().Infof("opscmd: kernel_remove %s@%s: not installed (already absent)", a.Name, version)
			return done(panelclient.KernelRemoveResult{AlreadyAbsent: true}), nil
		}
		return Result{}, err
	}
	k.reg.logf().Infof("opscmd: kernel_remove %s@%s done (%d bytes freed)", a.Name, version, freed)
	k.reg.event("kernel.removed", "info", fmt.Sprintf("kernel %s@%s removed", a.Name, version))
	return done(panelclient.KernelRemoveResult{FreedBytes: freed}), nil
}

// xrayRemove answers kernel_remove for the Xray kernel service. The requested
// version decides what the command means; kernelRemove documents the two cases.
func (k *kernelCmds) xrayRemove(ctx context.Context, a panelclient.KernelRemoveArgs) (Result, error) {
	version := manifest.NormalizeVersion(a.Version)
	if version == "" {
		// The protocol requires a version (W1nCBoard always sends one). An
		// older or hand-made panel that omits it still gets the historical
		// whole-service uninstall, and the omission is visible in the log.
		k.reg.logf().Warnf("opscmd: kernel_remove xray without a version: uninstalling the whole service (the protocol requires a version)")
		return k.xrayUninstall(ctx)
	}
	list, err := k.deps.Kernels.List()
	if err != nil {
		return Result{}, fmt.Errorf("listing the installed kernels: %w", err)
	}
	installed, current := false, false
	for _, e := range list {
		if e.Name != xrayapi.KernelName || e.Version != version {
			continue
		}
		installed, current = true, e.Current
		break
	}
	if !installed {
		k.reg.logf().Infof("opscmd: kernel_remove xray@%s: not installed (already absent)", version)
		return done(panelclient.KernelRemoveResult{AlreadyAbsent: true}), nil
	}
	if current {
		// Xray is the single kernel whose current version can be removed: it is
		// a service, so this is the uninstall of the kernel.
		return k.xrayUninstall(ctx)
	}
	// A non-current version is a plain version removal: the same in_use guard
	// as gost/realm/frp (a rollback can leave an older version executing) and
	// the same kernel/install per-version deletion, which also clears the
	// rollback pointer when this was the previous version. The service manager
	// is deliberately not involved, so a running Xray is never stopped.
	if running, exact := k.deps.Kernels.RunningVersion(xrayapi.KernelName); exact && running == version {
		return Result{}, coded("in_use", fmt.Errorf("kernel %s@%s is running; ensure or roll back to another version first", a.Name, version))
	}
	freed := k.installedSizeOf(xrayapi.KernelName, version)
	if err := k.deps.Kernels.Remove(xrayapi.KernelName, version); err != nil {
		if errors.Is(err, kernel.ErrNotInstalled) {
			k.reg.logf().Infof("opscmd: kernel_remove xray@%s: not installed (already absent)", version)
			return done(panelclient.KernelRemoveResult{AlreadyAbsent: true}), nil
		}
		return Result{}, err
	}
	k.reg.logf().Infof("opscmd: kernel_remove xray@%s done (%d bytes freed; the running service was not touched)", version, freed)
	k.reg.event("kernel.removed", "info", fmt.Sprintf("kernel xray@%s removed", version))
	return done(panelclient.KernelRemoveResult{FreedBytes: freed}), nil
}

// xrayUninstall stops and deletes the Xray kernel service and every installed
// version, keeping config.yml and the managed files: reinstalling restores the
// service. It is what kernel_remove means when the requested version is the
// current one (and, defensively, when no version is sent), and it is idempotent
// (D-M2): a machine where the service was never installed answers success with
// already_absent.
func (k *kernelCmds) xrayUninstall(ctx context.Context) (Result, error) {
	// The service manager removes every installed version at once, so the freed
	// bytes are the sum over them. Like the supervised kernels below the
	// declared installed size is read *before* the removal, because afterwards
	// the entries are gone (REG2 observation 1: this branch used to answer
	// freed_bytes=0).
	freed := k.installedSizeOf(xrayapi.KernelName, "")
	removed, err := k.deps.Xray.Remove(ctx)
	if err != nil {
		return Result{}, err
	}
	if !removed {
		k.reg.logf().Infof("opscmd: kernel_remove xray: nothing installed (already absent)")
		return done(panelclient.KernelRemoveResult{AlreadyAbsent: true}), nil
	}
	k.reg.logf().Infof("opscmd: kernel_remove xray done (%d bytes freed; service and files removed; configuration kept)", freed)
	k.reg.event("kernel.removed", "info", "kernel xray removed (service and files; configuration kept)")
	// uninstalled tells the panel/operator that the running service was removed
	// with the kernel, as opposed to one stale version being deleted.
	return done(panelclient.KernelRemoveResult{FreedBytes: freed, Uninstalled: true}), nil
}

// installedSizeOf returns the declared installed size of one kernel version, or
// of every installed version of the kernel when version is empty (the Xray
// service is removed as a whole). It is read *before* a removal because
// afterwards the entries are gone: this is what kernel_remove reports as
// freed_bytes, the manifest-declared size and not a du measurement (the same
// number for gost, realm, frp and xray).
func (k *kernelCmds) installedSizeOf(name, version string) int64 {
	list, err := k.deps.Kernels.List()
	if err != nil {
		return 0
	}
	var freed int64
	for _, e := range list {
		if e.Name != name {
			continue
		}
		if version == "" || e.Version == version {
			freed += e.Size
		}
	}
	return freed
}

// kernelRollback answers kernel_rollback: current and previous swap.
func (k *kernelCmds) kernelRollback(ctx context.Context, req Request, complete Completion) (Result, error) {
	var a panelclient.KernelRollbackArgs
	if err := decodeArgs(req.Args, &a); err != nil {
		return Result{}, err
	}
	if err := checkKernelName(a.Name); err != nil {
		return Result{}, err
	}
	if a.Name == xrayapi.KernelName && k.deps.Xray != nil {
		if err := k.deps.Xray.Rollback(ctx); err != nil {
			return Result{}, err
		}
		inst := k.currentOf(xrayapi.KernelName)
		k.reg.logf().Infof("opscmd: kernel_rollback xray -> %s (service)", inst.Version)
		return done(installedResult{Name: xrayapi.KernelName, Version: inst.Version, Path: inst.Path}), nil
	}
	inst, err := k.deps.Kernels.Rollback(a.Name)
	if err != nil {
		return Result{}, err
	}
	k.reg.logf().Infof("opscmd: kernel_rollback %s -> %s", a.Name, inst.Version)
	return done(installedResult{Name: a.Name, Version: inst.Version, Path: inst.Path}), nil
}

// componentRestart answers component_restart. Only a kernel process can be
// restarted: the agent is not supervised (and restarting it would drop the
// panel link). The Xray kernel is a service of its own and is restarted through
// its service manager; the supervised kernels go through the supervisor.
func (k *kernelCmds) componentRestart(ctx context.Context, req Request, complete Completion) (Result, error) {
	var a panelclient.ComponentRestartArgs
	if err := decodeArgs(req.Args, &a); err != nil {
		return Result{}, err
	}
	if a.Name == "" {
		return Result{}, coded("invalid_args", errors.New("name is required"))
	}
	if a.Name == ReservedAgentName {
		return Result{}, coded("reserved_name", errors.New("component_restart never restarts the agent itself"))
	}
	if a.Name == xrayapi.KernelName {
		if k.deps.Xray == nil {
			return Result{}, coded("not_supported", errors.New("the Xray kernel service is not managed by this agent"))
		}
		if err := k.deps.Xray.Restart(ctx); err != nil {
			return Result{}, err
		}
		k.reg.logf().Infof("opscmd: component_restart xray restarted the service")
		return done(restartedResult{Name: a.Name, Restarted: 1}), nil
	}
	if k.deps.Comp == nil {
		return Result{}, coded("not_supported", errors.New("component restart is not wired on this agent"))
	}
	n, err := k.deps.Comp.Restart(ctx, a.Name)
	if err != nil {
		return Result{}, err
	}
	k.reg.logf().Infof("opscmd: component_restart %s restarted %d process(es)", a.Name, n)
	return done(restartedResult{Name: a.Name, Restarted: n}), nil
}
