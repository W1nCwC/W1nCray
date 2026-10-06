// This file adds the kernel *operations* the panel drives (kernel_list,
// kernel_install, kernel_remove, kernel_rollback) on top of the install
// library the agent already uses for reconciliation.
//
// It deliberately keeps *install.Installer private: the reconciler, the
// commands and the panel all go through one Ensurer, so the on-disk kernel
// directory has exactly one owner. Every method is a thin delegation; the
// behaviour (refusing the current version, clearing the previous pointer,
// swapping current/previous) lives in kernel/install and is not re-implemented
// here.

package kernelx

import (
	"context"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/kernel/install"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
)

// List returns every installed kernel version, sorted by name then version
// descending. It reads the kernel directory and needs no manifest.
func (e *Ensurer) List() ([]install.Entry, error) { return e.in.List() }

// Catalog lists every kernel version of the signed manifest with its
// availability on this machine. Without a loaded manifest it returns
// kernel.ErrNoManifest; the caller decides whether that is fatal.
func (e *Ensurer) Catalog() ([]install.CatalogEntry, error) { return e.in.Catalog() }

// Remove deletes one installed version. The version the installer made current
// is refused with kernel.ErrInUse; removing the previous version clears the
// previous pointer.
func (e *Ensurer) Remove(name, version string) error { return e.in.Remove(name, version) }

// Rollback makes the previous version current again and marks the version that
// was current as bad (with back-off), so a later Ensure of the same pin does
// not immediately switch back. It returns the now-current kernel.
func (e *Ensurer) Rollback(name string) (driver.Installed, error) { return e.in.Rollback(name) }

// Current returns the version the installer last made current, from the
// pointer alone (no process check).
func (e *Ensurer) Current(name string) (driver.Installed, error) { return e.in.Current(name) }

// DownloadFor resolves name@version in the loaded manifest and downloads its
// verified archive into dir. It is the exported staging path of the install
// library, used by agent/selfupdate; the Installer itself stays private so the
// kernel directory still has exactly one owner.
func (e *Ensurer) DownloadFor(ctx context.Context, name, version, dir string) (manifest.Target, string, error) {
	return e.in.DownloadFor(ctx, name, version, dir)
}

// VerifyArchiveFor verifies a downloaded archive against the manifest,
// extracts it into dest and runs the version self-check. See
// install.Installer.VerifyArchiveFor.
func (e *Ensurer) VerifyArchiveFor(ctx context.Context, name, version, archivePath, dest string) (manifest.Target, string, error) {
	return e.in.VerifyArchiveFor(ctx, name, version, archivePath, dest)
}
