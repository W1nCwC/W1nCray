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

	"github.com/W1nCwC/W1nCray/agent/panelclient"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/agent/wsproto"
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
	pin := spec.KernelPin{Name: a.Name, Version: version}
	wanted := version
	if wanted == "" {
		wanted = "newest"
	}
	k.reg.logf().Infof("opscmd: kernel_install %s@%s accepted", a.Name, wanted)
	go func() {
		inst, err := k.deps.Kernels.Ensure(ctx, pin)
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

// kernelRemove answers kernel_remove. It is quick (no network), so it finishes
// inline. A version that is executing right now is refused even when the
// current pointer already moved on, which a rollback can leave behind.
func (k *kernelCmds) kernelRemove(ctx context.Context, req Request, complete Completion) (Result, error) {
	var a panelclient.KernelRemoveArgs
	if err := decodeArgs(req.Args, &a); err != nil {
		return Result{}, err
	}
	if err := checkKernelName(a.Name); err != nil {
		return Result{}, err
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
	var freed int64
	if list, err := k.deps.Kernels.List(); err == nil {
		for _, e := range list {
			if e.Name == a.Name && e.Version == version {
				freed = e.Size
				break
			}
		}
	}
	if err := k.deps.Kernels.Remove(a.Name, version); err != nil {
		return Result{}, err
	}
	k.reg.logf().Infof("opscmd: kernel_remove %s@%s done (%d bytes freed)", a.Name, version, freed)
	k.reg.event("kernel.removed", "info", fmt.Sprintf("kernel %s@%s removed", a.Name, version))
	return done(panelclient.KernelRemoveResult{FreedBytes: freed}), nil
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
	inst, err := k.deps.Kernels.Rollback(a.Name)
	if err != nil {
		return Result{}, err
	}
	k.reg.logf().Infof("opscmd: kernel_rollback %s -> %s", a.Name, inst.Version)
	return done(installedResult{Name: a.Name, Version: inst.Version, Path: inst.Path}), nil
}

// componentRestart answers component_restart. Only a kernel process can be
// restarted: the agent is not supervised (and restarting it would drop the
// panel link), and the embedded xray engine shares the agent process, so it
// cannot be restarted on its own.
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
	if a.Name == spec.EngineXray {
		return Result{}, coded("embedded", errors.New("xray is embedded in the agent process; restart the agent service to restart it"))
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
