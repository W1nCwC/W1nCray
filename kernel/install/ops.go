package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/kernel"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
)

// Entry is one installed kernel version.
type Entry struct {
	Name          string
	Version       string
	Path          string // main binary
	Current       bool
	Previous      bool
	Target        string
	Variant       string
	ArchiveSHA256 string
	InstalledAt   time.Time
	Size          int64    // bytes of the extracted files
	Bad           *BadInfo // non-nil while the version is in retry back-off
}

// BadInfo describes a failed version.
type BadInfo struct {
	Fails     int
	Until     time.Time
	LastError string
	Code      string
}

// Current returns the kernel that Ensure/Rollback last made current. It does
// no network I/O and needs no manifest (driver.Detect uses it).
func (in *Installer) Current(name string) (driver.Installed, error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if err := validName(name); err != nil {
		return driver.Installed{}, err
	}
	cur, err := readPointer(in.curPath(name))
	if err != nil {
		return driver.Installed{}, kernel.Newf(kernel.ErrNotInstalled, name, "", "no current version")
	}
	mk := in.readMarker(name, cur)
	if mk == nil {
		return driver.Installed{}, kernel.Newf(kernel.ErrNotInstalled, name, cur, "installation record missing or damaged")
	}
	return in.installedOf(name, cur, mk), nil
}

// Files returns the files of the current version of name, keyed by their
// manifest "to" name, as absolute paths. It lets a driver find siblings of
// the main binary (frp: frpc is driver.Installed.Path, frps is Files["frps"]).
func (in *Installer) Files(name string) (map[string]string, error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if err := validName(name); err != nil {
		return nil, err
	}
	cur, err := readPointer(in.curPath(name))
	if err != nil {
		return nil, kernel.Newf(kernel.ErrNotInstalled, name, "", "no current version")
	}
	mk := in.readMarker(name, cur)
	if mk == nil {
		return nil, kernel.Newf(kernel.ErrNotInstalled, name, cur, "installation record missing or damaged")
	}
	out := make(map[string]string, len(mk.Files))
	for _, f := range mk.Files {
		out[f.To] = filepath.Join(in.verDir(name, cur), f.To)
	}
	return out, nil
}

// List returns all installed versions, sorted by name then version
// descending.
func (in *Installer) List() ([]Entry, error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	names, err := os.ReadDir(in.root)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, n := range names {
		if !n.IsDir() || validName(n.Name()) != nil {
			continue
		}
		name := n.Name()
		cur, _ := readPointer(in.curPath(name))
		prev, _ := readPointer(in.prevPath(name))
		vers, err := os.ReadDir(in.nameDir(name))
		if err != nil {
			continue
		}
		var entries []Entry
		for _, v := range vers {
			if !v.IsDir() || !reVersionDir.MatchString(v.Name()) {
				continue
			}
			mk := in.readMarker(name, v.Name())
			if mk == nil {
				continue
			}
			e := Entry{
				Name: name, Version: v.Name(), Path: filepath.Join(in.verDir(name, v.Name()), mk.Binary),
				Current: v.Name() == cur, Previous: v.Name() == prev,
				Target: mk.Target, Variant: mk.Variant, ArchiveSHA256: mk.ArchiveSHA256, InstalledAt: mk.InstalledAt,
			}
			for _, f := range mk.Files {
				e.Size += f.Size
			}
			if b := in.st.Bad[badKey(name, v.Name())]; b != nil {
				e.Bad = &BadInfo{Fails: b.Fails, Until: b.Until, LastError: b.LastError, Code: b.Code}
			}
			entries = append(entries, e)
		}
		sort.Slice(entries, func(i, j int) bool { return manifest.CompareVersions(entries[i].Version, entries[j].Version) > 0 })
		out = append(out, entries...)
	}
	return out, nil
}

// Remove deletes one installed version. The current version is refused
// (kernel.ErrInUse); an empty version removes the whole kernel, including
// current, and forgets its failure records.
func (in *Installer) Remove(name, version string) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	if err := validName(name); err != nil {
		return err
	}
	if version == "" {
		if _, err := os.Stat(in.nameDir(name)); err != nil {
			return kernel.Newf(kernel.ErrNotInstalled, name, "", "not installed")
		}
		for k := range in.st.Bad {
			if len(k) > len(name) && k[:len(name)+1] == name+"@" {
				delete(in.st.Bad, k)
			}
		}
		_ = in.saveState()
		return os.RemoveAll(in.nameDir(name))
	}
	version = manifest.NormalizeVersion(version)
	if !reVersionDir.MatchString(version) {
		return kernel.Newf(kernel.ErrNotInstalled, name, version, "invalid version")
	}
	if cur, _ := readPointer(in.curPath(name)); cur == version {
		return kernel.Newf(kernel.ErrInUse, name, version, "it is the current version; ensure/roll back to another one first")
	}
	if _, err := os.Stat(in.verDir(name, version)); err != nil {
		return kernel.Newf(kernel.ErrNotInstalled, name, version, "not installed")
	}
	if prev, _ := readPointer(in.prevPath(name)); prev == version {
		removePointer(in.prevPath(name))
	}
	return os.RemoveAll(in.verDir(name, version))
}

// Rollback makes the previous version current again and marks the version
// that was current as bad (with back-off) so a later Ensure of the same pin
// does not immediately switch back. It returns the now-current kernel.
func (in *Installer) Rollback(name string) (driver.Installed, error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if err := validName(name); err != nil {
		return driver.Installed{}, err
	}
	cur, _ := readPointer(in.curPath(name))
	prev, perr := readPointer(in.prevPath(name))
	if perr != nil || prev == "" {
		return driver.Installed{}, kernel.Newf(kernel.ErrNotInstalled, name, "", "no previous version to roll back to")
	}
	mk := in.readMarker(name, prev)
	if mk == nil {
		return driver.Installed{}, kernel.Newf(kernel.ErrNotInstalled, name, prev, "previous version damaged or removed")
	}
	if cur != "" {
		if err := writePointer(in.prevPath(name), cur); err != nil {
			return driver.Installed{}, err
		}
	} else {
		removePointer(in.prevPath(name))
	}
	if err := writePointer(in.curPath(name), prev); err != nil {
		return driver.Installed{}, err
	}
	if cur != "" {
		in.recordFailure(name, cur, errors.New("rolled back by operator or driver"))
	}
	return in.installedOf(name, prev, mk), nil
}

// VerifyInstalled re-hashes the files of an installed version against the
// manifest (the Ensure fast path only checks sizes).
func (in *Installer) VerifyInstalled(name, version string) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	k, key, t, err := in.resolve(name, version)
	if err != nil {
		return err
	}
	mk := in.readMarker(name, k.Version)
	if mk == nil {
		return kernel.Newf(kernel.ErrNotInstalled, name, k.Version, "not installed")
	}
	for _, e := range t.Extract {
		h, n, err := hashFile(filepath.Join(in.verDir(name, k.Version), e.To))
		if err != nil {
			return kernel.Wrap(kernel.ErrVerify, name, k.Version, err, "reading %s", e.To)
		}
		if n != e.Size || h != e.SHA256 {
			e := kernel.Newf(kernel.ErrVerify, name, k.Version, "%s no longer matches the manifest", e.To)
			e.Target = key
			return e
		}
	}
	return nil
}

// Import installs a kernel from a local archive without network access, for
// offline devices. The archive must be byte-identical to a build the loaded
// manifest lists for this platform (matched by sha256), and goes through the
// same extraction, hashing, self-check and switch as a download. The
// manifest must have been loaded first (LoadManifest).
func (in *Installer) Import(ctx context.Context, archivePath string) (driver.Installed, error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.man == nil {
		return driver.Installed{}, kernel.Newf(kernel.ErrNoManifest, "", "", "load a signed manifest before importing")
	}
	if err := in.man.CheckFresh(in.now()); err != nil {
		return driver.Installed{}, err
	}
	sum, size, err := hashFile(archivePath)
	if err != nil {
		return driver.Installed{}, err
	}
	var (
		best *manifest.Kernel
		bt   *manifest.Target
		bkey string
	)
	for i := range in.man.Kernels {
		k := &in.man.Kernels[i]
		key, t, err := in.selectTarget(k)
		if err != nil || t.ArchiveSHA256 != sum {
			continue
		}
		if best == nil || manifest.CompareVersions(k.Version, best.Version) > 0 {
			best, bt, bkey = k, t, key
		}
	}
	if best == nil {
		return driver.Installed{}, kernel.Newf(kernel.ErrVerify, "", "", "archive sha256 %s matches no build in manifest sequence %d for %s", sum[:16], in.man.Sequence, in.plat.Key())
	}
	name, version := best.Name, best.Version
	if size != bt.ArchiveSize {
		return driver.Installed{}, kernel.Newf(kernel.ErrVerify, name, version, "archive is %d bytes, manifest says %d", size, bt.ArchiveSize)
	}
	if err := best.CheckAgent(in.cfg.AgentVersion); err != nil {
		return driver.Installed{}, err
	}
	if why, bad := in.man.RevokedReason(name, version, bt.Hashes()...); bad {
		return driver.Installed{}, kernel.Newf(kernel.ErrRevoked, name, version, "%s", why)
	}
	if err := os.MkdirAll(in.partialDir(name), privDir); err != nil {
		return driver.Installed{}, err
	}
	if err := in.checkSpace(name, version, bkey, bt, "", false); err != nil {
		return driver.Installed{}, err
	}
	if err := in.installArchive(ctx, best, bkey, bt, archivePath); err != nil {
		return driver.Installed{}, err
	}
	in.clearFailure(name, version)
	return in.installedOf(name, version, in.readMarker(name, version)), nil
}

// CatalogEntry says whether a manifest kernel can be installed here.
type CatalogEntry struct {
	Name          string
	Version       string
	Channel       string
	Available     bool
	Code          string // kernel.Code of the reason when unavailable
	Reason        string
	ArchiveSize   int64
	InstalledSize int64
	Variant       string
	Capabilities  map[string]any
	Installed     bool
}

// Catalog lists every kernel version of the manifest with its availability
// on this platform (target null/absent/incompatible, revoked, agent too
// old, expired manifest), for reporting to the panel. No network.
func (in *Installer) Catalog() ([]CatalogEntry, error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.man == nil {
		return nil, kernel.Newf(kernel.ErrNoManifest, "", "", "load a signed manifest first")
	}
	var out []CatalogEntry
	for i := range in.man.Kernels {
		k := &in.man.Kernels[i]
		ce := CatalogEntry{Name: k.Name, Version: k.Version, Channel: k.Channel, Capabilities: k.Capabilities}
		_, _, t, err := in.resolve(k.Name, k.Version)
		if err != nil {
			ce.Code, ce.Reason = kernel.Code(err), err.Error()
		} else {
			ce.Available = true
			ce.ArchiveSize, ce.InstalledSize, ce.Variant = t.ArchiveSize, installedSizeOf(t), t.Variant
			ce.Installed = in.readMarker(k.Name, k.Version) != nil
		}
		out = append(out, ce)
	}
	return out, nil
}

func installedSizeOf(t *manifest.Target) int64 {
	if t.InstalledSize > 0 {
		return t.InstalledSize
	}
	return sumExtract(t)
}
