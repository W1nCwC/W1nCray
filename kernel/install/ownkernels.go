// This file adds the built-in W1nCray release table (v0.8.7): gost, realm and
// frp are our own mirrors of upstream releases, and the agent installs them
// from the table instead of from a signed manifest.
//
// Why: those three kernels are rebuilt and re-signed by us on every release,
// so a signed manifest entry added nothing but a second thing to publish, and
// a manifest that listed a version we do not mirror turned into an install
// that downloaded from upstream. With Config.OwnKernels the agent resolves
// name@version, the platform row and the bytes from ownkernels_gen.go, which
// release/build-kernels.sh generates from the mirrored assets. A version or
// platform the table does not hold is refused; the signed manifest is never
// consulted as a fallback. Everything else (xray, and any other name) keeps
// the manifest path byte for byte.
//
// The data lives in ownkernels_gen.go and is generated, never edited: this
// file holds the row type, the lookups and the install step.

package install

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/kernel"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
	"github.com/W1nCwC/W1nCray/kernel/platform"
)

// ownKernel is one W1nCray release asset the agent installs without a manifest.
type ownKernel struct {
	Name, Version, Platform, Variant string // Platform is a manifest-style key such as "linux/armv7"
	URL, SHA256                      string
	Size                             int64
	Archive                          string
	Members                          []DirectMember
}

// ownFrpMembers is the member list of the frp asset: one tar.gz holding frpc
// and frps, installed side by side (release/build-kernels.sh packs both).
var ownFrpMembers = []DirectMember{{From: "frpc", To: "frpc"}, {From: "frps", To: "frps"}}

// isOwnKernel reports whether the built-in table serves name.
func isOwnKernel(name string) bool {
	switch name {
	case "gost", "realm", "frp":
		return true
	}
	return false
}

// OwnKernelLatest returns the newest version of name the built-in table holds
// for plat, and whether there is one at all. "Newest" is the semantic order
// (3.10.0 > 3.9.0), never the lexical one; a row counts only when its variant
// runs on this machine, and the platform's own preference order decides a tie
// (an armv7 machine keeps the armv7 row over the armv5 fallback).
func OwnKernelLatest(name string, plat platform.Info) (string, bool) {
	best := ""
	for _, key := range plat.Keys() {
		for _, e := range ownKernelTable {
			if e.Name != name || e.Platform != key {
				continue
			}
			if plat.Compatible(e.Variant) != nil {
				continue
			}
			if best == "" || manifest.CompareVersions(e.Version, best) > 0 {
				best = e.Version
			}
		}
	}
	return best, best != ""
}

// ownEntry picks the table row of name@version that runs here: the platform's
// keys in preference order (so ARM falls back armv7 -> armv6 -> armv5) and, at
// each key, the first row whose variant is compatible. Nothing here reads the
// manifest.
func (in *Installer) ownEntry(name, version string) (ownKernel, error) {
	var notes []string
	for _, key := range in.plat.Keys() {
		for _, e := range ownKernelTable {
			if e.Name != name || e.Version != version || e.Platform != key {
				continue
			}
			if err := in.plat.Compatible(e.Variant); err != nil {
				notes = append(notes, key+": "+err.Error())
				continue
			}
			return e, nil
		}
	}
	msg := fmt.Sprintf("%s %s is not in the W1nCray release table for %s", name, version, in.plat.Key())
	if len(notes) > 0 {
		msg += " (" + strings.Join(notes, "; ") + ")"
	}
	e := kernel.Newf(kernel.ErrUnknownKernel, name, version, "%s", msg)
	e.Target = in.plat.Key()
	return ownKernel{}, e
}

// ownFilesIntact is the fast-path check of the built-in table: the marker of a
// previous install of this exact archive lists the files it wrote, and each
// must still be a regular file of the recorded size. It is filesIntact for the
// table path, where the manifest's per-file sizes do not exist (the marker
// holds them).
func (in *Installer) ownFilesIntact(name, version string, mk *marker) bool {
	if len(mk.Files) == 0 {
		return false
	}
	for _, f := range mk.Files {
		fi, err := os.Stat(filepath.Join(in.verDir(name, version), f.To))
		if err != nil || !fi.Mode().IsRegular() || fi.Size() != f.Size {
			return false
		}
	}
	return true
}

// ensureOwn installs name@version from the built-in table. The caller holds
// in.mu. It never consults the signed manifest: an unknown version, a platform
// without a row and an incompatible variant are all refused, and the only
// network access is the release asset of the selected row.
func (in *Installer) ensureOwn(ctx context.Context, pin spec.KernelPin, force bool) (driver.Installed, error) {
	name := pin.Name
	version := manifest.NormalizeVersion(pin.Version)
	if version == "" {
		v, ok := OwnKernelLatest(name, in.plat)
		if !ok {
			return driver.Installed{}, kernel.Newf(kernel.ErrUnknownKernel, name, "",
				"no W1nCray release build of %s for %s", name, in.plat.Key())
		}
		version = v
	}
	entry, err := in.ownEntry(name, version)
	if err != nil {
		return driver.Installed{}, err
	}
	if force {
		// Same contract as the manifest path: the operator's explicit request
		// wins over the automatic retry back-off (D-M3).
		in.clearFailure(name, version)
	}
	// Already installed from this very archive: activate it, no network at all.
	if mk := in.readMarker(name, version); mk != nil && mk.ArchiveSHA256 == entry.SHA256 && in.ownFilesIntact(name, version, mk) {
		if err := in.activate(name, version); err != nil {
			return driver.Installed{}, err
		}
		return in.installedOf(name, version, mk), nil
	}
	if err := in.checkBackoff(name, version); err != nil {
		return driver.Installed{}, err
	}
	in.logf("kernel: installing %s %s from own-release (%s)", name, version, entry.Platform)
	inst, err := in.installDirectLocked(ctx, DirectInstall{
		Name: name, Version: version, URL: entry.URL, SHA256: entry.SHA256,
		Size: entry.Size, Archive: entry.Archive, Members: entry.Members,
	})
	if err != nil {
		if ctx.Err() == nil {
			in.recordFailure(name, version, err)
		}
		return driver.Installed{}, err
	}
	in.logf("kernel: installed %s %s from own-release (%s)", name, version, entry.Platform)
	return inst, nil
}
