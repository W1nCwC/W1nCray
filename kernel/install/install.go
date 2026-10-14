// Package install downloads, verifies, installs, switches and rolls back
// external kernel binaries according to a signed manifest. See package
// kernel for the trust model and on-disk layout.
//
// Concurrency: an Installer serialises its public methods with a mutex. Two
// agent processes sharing one Dir are not supported.
package install

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/kernel"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
	"github.com/W1nCwC/W1nCray/kernel/netutil"
	"github.com/W1nCwC/W1nCray/kernel/platform"
)

// spaceMargin is added to every free-space requirement.
const spaceMargin = 8 << 20

// Config configures an Installer. Only Dir is required.
type Config struct {
	// Dir is the base directory; kernels live under <Dir>/kernels. On
	// OpenWrt choose a directory on persistent, large storage (extroot/USB);
	// never /tmp, which is RAM.
	Dir string
	// Keys are the trusted manifest keys; nil means manifest.DefaultKeys().
	Keys []manifest.Key
	// AgentVersion is compared with a kernel's min_agent ("" or "dev" skips).
	AgentVersion string
	// Platform overrides detection (tests, cross-installs).
	Platform *platform.Info

	HTTPClient *http.Client // nil: netutil.NewClient() (proxy env incl. socks5)
	AllowHTTP  bool         // permit http:// sources (tests only; hashes still apply)

	// Check overrides the version self-check (default: run version_cmd).
	Check CheckFunc
	// FreeSpace overrides the free-space probe; ok=false means "unknown"
	// and skips the check.
	FreeSpace func(dir string) (free uint64, ok bool)

	Keep int // versions retained per kernel including current (default 2)

	Timeout      time.Duration // whole download phase (default 30m)
	StallTimeout time.Duration // abort a transfer idle this long (default 60s)
	Retries      int           // attempts per source, resuming each time (default 3)
	RetryDelay   time.Duration // base delay between attempts (default 2s)

	BackoffBase time.Duration // first retry delay after a failed install (default 1m)
	BackoffMax  time.Duration // cap of the exponential back-off (default 6h)

	MaxEntries      int   // archive members scanned (default 4096)
	MaxExtractBytes int64 // decompression budget; 0 = 2*listed size + 64 MiB

	Now func() time.Time
	Log driver.Logger
}

// Installer manages the kernels under one directory.
type Installer struct {
	cfg  Config
	mu   sync.Mutex
	root string // <Dir>/kernels
	st   state
	man  *manifest.Manifest
	plat platform.Info
	keys []manifest.Key
}

// New prepares the directory, loads persisted state and, if present, the
// previously accepted manifest.
func New(cfg Config) (*Installer, error) {
	if cfg.Dir == "" {
		return nil, errors.New("install: Dir is required")
	}
	abs, err := filepath.Abs(cfg.Dir)
	if err != nil {
		return nil, err
	}
	cfg.Dir = abs
	if cfg.Keep < 1 {
		cfg.Keep = 2
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = netutil.NewClient()
	}
	if cfg.FreeSpace == nil {
		cfg.FreeSpace = statfsFree
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Minute
	}
	if cfg.StallTimeout <= 0 {
		cfg.StallTimeout = 60 * time.Second
	}
	if cfg.Retries <= 0 {
		cfg.Retries = 3
	}
	if cfg.RetryDelay <= 0 {
		cfg.RetryDelay = 2 * time.Second
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = time.Minute
	}
	if cfg.BackoffMax <= 0 {
		cfg.BackoffMax = 6 * time.Hour
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 4096
	}
	if runtime.GOOS == "linux" && (abs == "/tmp" || strings.HasPrefix(abs, "/tmp/") || strings.HasPrefix(abs, "/var/run/")) && cfg.Log != nil {
		cfg.Log.Warnf("kernel: Dir %s is on a RAM disk on most routers (OpenWrt /tmp): kernels would vanish on reboot and downloads may not fit; use persistent storage (--prefix)", abs)
	}
	in := &Installer{cfg: cfg, root: filepath.Join(abs, "kernels"), keys: cfg.Keys}
	if in.keys == nil {
		in.keys, err = manifest.DefaultKeys()
		if err != nil {
			// Not fatal: List/Current/Remove/Rollback still work offline.
			in.keys = nil
			in.logf("kernel: %v (manifests will be rejected)", err)
		}
	}
	if cfg.Platform != nil {
		in.plat = *cfg.Platform
	} else {
		in.plat = platform.Detect()
	}
	if err := os.MkdirAll(in.root, dirMode); err != nil {
		return nil, err
	}
	if err := in.loadState(); err != nil {
		return nil, err
	}
	if raw, err := os.ReadFile(in.manifestPath()); err == nil {
		m, err := manifest.Verify(raw, manifest.VerifyOptions{Keys: in.keys, Now: in.now(), MinSequence: in.st.MaxSequence, AllowExpired: true})
		if err != nil {
			in.logf("kernel: stored manifest rejected: %v", err)
		} else {
			in.man = m
			in.logIgnoredTargets(m)
		}
	}
	return in, nil
}

func (in *Installer) now() time.Time { return in.cfg.Now() }

func (in *Installer) logf(format string, args ...any) {
	if in.cfg.Log != nil {
		in.cfg.Log.Infof(format, args...)
	}
}

// logIgnoredTargets surfaces the forward-compatible target keys Validate
// accepted but never selects (a "os/arch+<unknown suffix>" key from a newer
// manifest). They are not an error, but an operator should see them: a kernel
// whose only build is such a key is unavailable here.
func (in *Installer) logIgnoredTargets(m *manifest.Manifest) {
	rep, err := m.ValidateReport()
	if err != nil {
		return
	}
	for _, n := range rep.IgnoredTargets {
		in.logf("kernel: manifest sequence %d: ignoring target %s %s: %s", m.Sequence, n.Kernel, n.Key, n.Reason)
	}
}

func (in *Installer) statePath() string    { return filepath.Join(in.root, "state.json") }
func (in *Installer) manifestPath() string { return filepath.Join(in.root, "manifest.json") }
func (in *Installer) nameDir(n string) string {
	return filepath.Join(in.root, n)
}
func (in *Installer) verDir(n, v string) string { return filepath.Join(in.root, n, v) }
func (in *Installer) partialDir(n string) string {
	return filepath.Join(in.root, n, ".partial")
}

// Platform reports the platform the installer selects builds for.
func (in *Installer) Platform() platform.Info { return in.plat }

// Manifest returns the accepted manifest (nil before LoadManifest).
func (in *Installer) Manifest() *manifest.Manifest {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.man
}

// LoadManifest verifies raw against the trusted keys (signature, expiry,
// sequence >= the highest ever accepted), then persists it and raises the
// accepted sequence. On any error the previously accepted manifest stays in
// force.
func (in *Installer) LoadManifest(raw []byte) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	m, err := manifest.Verify(raw, manifest.VerifyOptions{Keys: in.keys, Now: in.now(), MinSequence: in.st.MaxSequence})
	if err != nil {
		return err
	}
	if err := writeFileAtomic(in.manifestPath(), raw, stateMode); err != nil {
		return err
	}
	if m.Sequence > in.st.MaxSequence {
		in.st.MaxSequence = m.Sequence
		if err := in.saveState(); err != nil {
			return err
		}
	}
	in.man = m
	in.logIgnoredTargets(m)
	return nil
}

func validName(n string) error {
	if !manifestNameRe(n) {
		return kernel.Newf(kernel.ErrUnknownKernel, n, "", "invalid kernel name")
	}
	return nil
}

func manifestNameRe(n string) bool {
	if n == "" || len(n) > 32 || n[0] == '-' || n[0] == '_' {
		return false
	}
	for _, c := range n {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// selectTarget picks the first usable build among the platform's candidate
// (field, key) pairs. On OpenWrt that is openwrt_targets[os/arch], then the
// legacy targets[os/arch+openwrt], then targets[os/arch]; elsewhere only
// targets[os/arch] is ever read. The returned key is the plain platform key.
// The error distinguishes explicit null, absent and incompatible.
func (in *Installer) selectTarget(k *manifest.Kernel) (string, *manifest.Target, error) {
	var notes []string
	for _, c := range in.plat.Candidates() {
		var (
			t     *manifest.Target
			st    manifest.TargetState
			where = c.Key
		)
		if c.Source == platform.OpenWrtTargetsField {
			t, st = k.LookupOpenWrt(c.Key)
			where = "openwrt_targets[" + c.Key + "]"
		} else {
			t, st = k.Lookup(c.Key)
		}
		switch st {
		case manifest.TargetPresent:
			if err := in.plat.Compatible(t.Variant); err != nil {
				notes = append(notes, where+": "+err.Error())
				continue
			}
			return c.Base, t, nil
		case manifest.TargetNull:
			notes = append(notes, where+": no build exists (null)")
		default:
			notes = append(notes, where+": not listed")
		}
	}
	e := kernel.Newf(kernel.ErrUnavailable, k.Name, k.Version, "%v", notes)
	e.Target = in.plat.Key()
	return "", nil, e
}

// resolve performs every manifest-level check for name@version.
func (in *Installer) resolve(name, version string) (*manifest.Kernel, string, *manifest.Target, error) {
	if err := validName(name); err != nil {
		return nil, "", nil, err
	}
	version = manifest.NormalizeVersion(version)
	if version == "" {
		return nil, "", nil, kernel.Newf(kernel.ErrUnknownKernel, name, "", "a version is required")
	}
	if in.man == nil {
		return nil, "", nil, kernel.Newf(kernel.ErrNoManifest, name, version, "load a signed manifest first")
	}
	if err := in.man.CheckFresh(in.now()); err != nil {
		return nil, "", nil, err
	}
	k, err := in.man.Find(name, version)
	if err != nil {
		return nil, "", nil, err
	}
	if err := k.CheckAgent(in.cfg.AgentVersion); err != nil {
		return nil, "", nil, err
	}
	if why, bad := in.man.RevokedReason(name, version); bad {
		return nil, "", nil, kernel.Newf(kernel.ErrRevoked, name, version, "%s", why)
	}
	key, t, err := in.selectTarget(k)
	if err != nil {
		return nil, "", nil, err
	}
	if why, bad := in.man.RevokedReason(name, version, t.Hashes()...); bad {
		e := kernel.Newf(kernel.ErrRevoked, name, version, "%s", why)
		e.Target = key
		return nil, "", nil, e
	}
	return k, key, t, nil
}

// Ensure makes the pinned kernel version installed and current, and returns
// its location. It is idempotent and cheap when the version is already
// installed from the same archive (no network, no hashing). Otherwise it
// downloads to <name>/.partial, verifies, extracts only the listed files,
// self-checks the binary and switches atomically; the previous version is
// kept. Any failure leaves the previously current version untouched and is
// remembered with exponential back-off. Errors wrap the kinds in package
// kernel (ErrUnavailable, ErrNoSpace, ErrVerify, ErrRevoked, ...). An
// operator-initiated install uses EnsureForce instead: the back-off constrains
// the automatic retries only (D-M3).
func (in *Installer) Ensure(ctx context.Context, pin spec.KernelPin) (driver.Installed, error) {
	return in.ensure(ctx, pin, false)
}

// EnsureForce is Ensure for an operator-initiated install: it bypasses the
// retry back-off and clears the failure record first, so an administrator who
// explicitly asks for a version after a rollback (or a failed automatic
// attempt) is never refused by a timer meant for automatic retries (D-M3). A
// failure of the forced attempt starts a fresh back-off, so the automatic path
// still backs off.
func (in *Installer) EnsureForce(ctx context.Context, pin spec.KernelPin) (driver.Installed, error) {
	return in.ensure(ctx, pin, true)
}

func (in *Installer) ensure(ctx context.Context, pin spec.KernelPin, force bool) (driver.Installed, error) {
	in.mu.Lock()
	defer in.mu.Unlock()

	name, version := pin.Name, manifest.NormalizeVersion(pin.Version)
	k, key, t, err := in.resolve(name, version)
	if err != nil {
		return driver.Installed{}, err
	}
	if force {
		// The operator's explicit request wins over the automatic back-off:
		// the record is dropped so the attempt runs, and a fresh failure
		// records a fresh count (recordFailure below).
		in.clearFailure(name, version)
	}
	if mk := in.readMarker(name, version); mk != nil && mk.ArchiveSHA256 == t.ArchiveSHA256 && in.filesIntact(name, version, t) {
		if err := in.activate(name, version); err != nil {
			return driver.Installed{}, err
		}
		return in.installedOf(name, version, mk), nil
	}
	if err := in.checkBackoff(name, version); err != nil {
		return driver.Installed{}, err
	}

	part := filepath.Join(in.partialDir(name), t.ArchiveSHA256+".part")
	if err := os.MkdirAll(in.partialDir(name), privDir); err != nil {
		return driver.Installed{}, err
	}
	in.cleanPartial(name, t.ArchiveSHA256+".part")
	if err := in.checkSpace(name, version, key, t, part, true); err != nil {
		return driver.Installed{}, err // not recorded as a failure: nothing was tried
	}

	dctx, cancel := context.WithTimeout(ctx, in.cfg.Timeout)
	err = in.download(dctx, name, version, t, part)
	cancel()
	if err == nil {
		err = in.installArchive(ctx, k, key, t, part)
	}
	if err != nil {
		if ctx.Err() == nil {
			in.recordFailure(name, version, err)
		}
		return driver.Installed{}, err
	}
	_ = os.Remove(part)
	in.clearFailure(name, version)
	mk := in.readMarker(name, version)
	return in.installedOf(name, version, mk), nil
}

func (in *Installer) installedOf(name, version string, mk *marker) driver.Installed {
	bin := ""
	if mk != nil {
		bin = filepath.Join(in.verDir(name, version), mk.Binary)
	}
	return driver.Installed{Path: bin, Version: version}
}

// cleanPartial removes stale staging directories and partial downloads of
// other archives (keep is the file name that may be resumed).
func (in *Installer) cleanPartial(name, keep string) {
	ents, err := os.ReadDir(in.partialDir(name))
	if err != nil {
		return
	}
	for _, e := range ents {
		if e.Name() == keep {
			continue
		}
		_ = os.RemoveAll(filepath.Join(in.partialDir(name), e.Name()))
	}
}

// checkSpace refuses when the filesystem cannot hold the new version next to
// the old ones. Nothing is deleted to make room.
func (in *Installer) checkSpace(name, version, key string, t *manifest.Target, part string, needArchive bool) error {
	free, ok := in.cfg.FreeSpace(in.root)
	if !ok {
		return nil
	}
	need := t.InstalledSize
	if sum := sumExtract(t); sum > need {
		need = sum
	}
	if needArchive {
		have := int64(0)
		if fi, err := os.Stat(part); err == nil {
			have = fi.Size()
		}
		if rest := t.ArchiveSize - have; rest > 0 {
			need += rest
		}
	}
	need += spaceMargin
	if free < uint64(need) {
		e := kernel.Newf(kernel.ErrNoSpace, name, version,
			"need %d MiB free in %s, only %d MiB available; existing versions were kept. Use a directory on larger storage (--prefix, extroot or USB) or free space",
			(need+(1<<20)-1)>>20, in.root, free>>20)
		e.Target = key
		return e
	}
	return nil
}

func sumExtract(t *manifest.Target) int64 {
	var s int64
	for _, e := range t.Extract {
		s += e.Size
	}
	return s
}

// installArchive extracts, verifies, self-checks and switches. archivePath
// has already been matched against t.ArchiveSHA256.
func (in *Installer) installArchive(ctx context.Context, k *manifest.Kernel, key string, t *manifest.Target, archivePath string) (err error) {
	name, version := k.Name, k.Version
	stage, err := in.newStage(name, version)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(stage)
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := extractArchive(archivePath, t.Archive, t.Extract, stage, in.limitsFor(t.Extract), name, version); err != nil {
		return err
	}
	check := in.cfg.Check
	if check == nil {
		check = DefaultCheck(k.Run)
	}
	if err := in.selfCheck(check, filepath.Join(stage, k.Run.Binary), k); err != nil {
		return err
	}
	return in.commit(stage, k, key, t)
}

// newStage creates an empty staging directory for name@version under the
// kernel's .partial area. The caller removes it on failure.
func (in *Installer) newStage(name, version string) (string, error) {
	if err := os.MkdirAll(in.partialDir(name), privDir); err != nil {
		return "", err
	}
	stage := filepath.Join(in.partialDir(name), "stage-"+version)
	_ = os.RemoveAll(stage)
	if err := os.MkdirAll(stage, dirMode); err != nil {
		return "", err
	}
	return stage, nil
}

// commit writes the installation marker into stage and atomically switches
// <name>/<version> to it, keeping the version that was current as previous.
// It is the shared tail of a manifest install and a local install: the two
// produce byte-for-byte the same on-disk layout, so list/upgrade/rollback/
// remove treat them identically.
func (in *Installer) commit(stage string, k *manifest.Kernel, key string, t *manifest.Target) (err error) {
	name, version := k.Name, k.Version
	mk := marker{
		Name: name, Version: version, Target: key, Variant: t.Variant, Binary: k.Run.Binary,
		ArchiveSHA256: t.ArchiveSHA256, InstalledAt: in.now().UTC(),
	}
	for _, e := range t.Extract {
		mk.Files = append(mk.Files, markerFile{To: e.To, Size: e.Size, Mode: e.Mode})
	}
	mb, _ := json.MarshalIndent(&mk, "", "  ")
	if err := os.WriteFile(filepath.Join(stage, ".installed.json"), append(mb, '\n'), stateMode); err != nil {
		return err
	}

	// ---- switch ----
	final := in.verDir(name, version)
	aside := filepath.Join(in.partialDir(name), "old-"+version)
	_ = os.RemoveAll(aside)
	hadFinal := false
	if _, statErr := os.Lstat(final); statErr == nil {
		if err := os.Rename(final, aside); err != nil {
			return fmt.Errorf("moving aside existing %s: %w", final, err)
		}
		hadFinal = true
	}
	restoreFinal := func() {
		_ = os.RemoveAll(final)
		if hadFinal {
			_ = os.Rename(aside, final)
		}
	}
	if err := os.Rename(stage, final); err != nil {
		restoreFinal()
		return err
	}
	prevCur, _ := readPointer(in.curPath(name))
	prevPrev, _ := readPointer(in.prevPath(name))
	revert := func() {
		if prevCur == "" {
			removePointer(in.curPath(name))
		} else {
			_ = writePointer(in.curPath(name), prevCur)
		}
		if prevPrev == "" {
			removePointer(in.prevPath(name))
		} else {
			_ = writePointer(in.prevPath(name), prevPrev)
		}
		restoreFinal()
	}
	if prevCur != "" && prevCur != version {
		if err := writePointer(in.prevPath(name), prevCur); err != nil {
			revert()
			return err
		}
	}
	if err := writePointer(in.curPath(name), version); err != nil {
		revert()
		return err
	}
	// Re-check from the final location: catches noexec mounts and anything
	// that differs between staging and the real path.
	check := in.cfg.Check
	if check == nil {
		check = DefaultCheck(k.Run)
	}
	if err := in.selfCheck(check, filepath.Join(final, k.Run.Binary), k); err != nil {
		revert()
		return err
	}
	_ = os.RemoveAll(aside)
	in.prune(name)
	return nil
}

func (in *Installer) curPath(name string) string  { return filepath.Join(in.nameDir(name), "current") }
func (in *Installer) prevPath(name string) string { return filepath.Join(in.nameDir(name), "previous") }

func (in *Installer) selfCheck(check CheckFunc, bin string, k *manifest.Kernel) error {
	got, err := check(bin)
	if err != nil {
		return kernel.Wrap(kernel.ErrCheck, k.Name, k.Version, err, "running version check")
	}
	if manifest.NormalizeVersion(got) != k.Version {
		return kernel.Newf(kernel.ErrCheck, k.Name, k.Version, "binary reports version %q", got)
	}
	return nil
}

func (in *Installer) readMarker(name, version string) *marker {
	b, err := os.ReadFile(filepath.Join(in.verDir(name, version), ".installed.json"))
	if err != nil {
		return nil
	}
	var m marker
	if json.Unmarshal(b, &m) != nil || m.Name != name || m.Version != version || m.Binary == "" {
		return nil
	}
	return &m
}

// filesIntact is the cheap fast-path check (existence, size, exec bit); the
// full re-hash is VerifyInstalled.
func (in *Installer) filesIntact(name, version string, t *manifest.Target) bool {
	for _, e := range t.Extract {
		fi, err := os.Stat(filepath.Join(in.verDir(name, version), e.To))
		if err != nil || !fi.Mode().IsRegular() || fi.Size() != e.Size {
			return false
		}
	}
	return true
}

// activate points current at an already installed version.
func (in *Installer) activate(name, version string) error {
	cur, _ := readPointer(in.curPath(name))
	if cur == version {
		return nil
	}
	if cur != "" {
		if err := writePointer(in.prevPath(name), cur); err != nil {
			return err
		}
	}
	if err := writePointer(in.curPath(name), version); err != nil {
		return err
	}
	in.prune(name)
	return nil
}

// prune keeps current, previous (if Keep >= 2) and the newest others up to
// Keep versions in total, and deletes the rest.
func (in *Installer) prune(name string) {
	cur, _ := readPointer(in.curPath(name))
	prev, _ := readPointer(in.prevPath(name))
	ents, err := os.ReadDir(in.nameDir(name))
	if err != nil {
		return
	}
	retain := map[string]bool{}
	if cur != "" {
		retain[cur] = true
	}
	if in.cfg.Keep >= 2 && prev != "" {
		retain[prev] = true
	} else if prev != "" {
		removePointer(in.prevPath(name))
	}
	type cand struct {
		v string
		t time.Time
	}
	var others []cand
	for _, e := range ents {
		if !e.IsDir() || !reVersionDir.MatchString(e.Name()) || retain[e.Name()] {
			continue
		}
		t := time.Time{}
		if mk := in.readMarker(name, e.Name()); mk != nil {
			t = mk.InstalledAt
		}
		others = append(others, cand{e.Name(), t})
	}
	sort.Slice(others, func(i, j int) bool { return others[i].t.After(others[j].t) })
	for _, c := range others {
		if len(retain) < in.cfg.Keep {
			retain[c.v] = true
			continue
		}
		in.logf("kernel %s: removing old version %s", name, c.v)
		_ = os.RemoveAll(in.verDir(name, c.v))
	}
}

// --- failure back-off ------------------------------------------------------

func (in *Installer) checkBackoff(name, version string) error {
	b := in.st.Bad[badKey(name, version)]
	if b == nil || !in.now().Before(b.Until) {
		return nil
	}
	return kernel.Newf(kernel.ErrBackoff, name, version, "failed %d time(s), retry after %s; last error: %s",
		b.Fails, b.Until.UTC().Format(time.RFC3339), b.LastError)
}

// recordFailure marks name@version bad with exponential back-off. Free-space
// refusals and manifest-level refusals are not recorded: they cost nothing
// to re-evaluate and can be fixed by the operator at once.
func (in *Installer) recordFailure(name, version string, err error) {
	switch {
	case errors.Is(err, kernel.ErrNoSpace), errors.Is(err, kernel.ErrBackoff), errors.Is(err, kernel.ErrUnavailable),
		errors.Is(err, kernel.ErrRevoked), errors.Is(err, kernel.ErrUnknownKernel):
		return
	}
	if in.st.Bad == nil {
		in.st.Bad = map[string]*badEntry{}
	}
	b := in.st.Bad[badKey(name, version)]
	if b == nil {
		b = &badEntry{}
		in.st.Bad[badKey(name, version)] = b
	}
	b.Fails++
	d := in.cfg.BackoffBase
	for i := 1; i < b.Fails && d < in.cfg.BackoffMax; i++ {
		d *= 2
	}
	if d > in.cfg.BackoffMax {
		d = in.cfg.BackoffMax
	}
	b.LastAt = in.now().UTC()
	b.Until = b.LastAt.Add(d)
	b.LastError = trimForLog(err.Error())
	b.Code = kernel.Code(err)
	if serr := in.saveState(); serr != nil {
		in.logf("kernel: saving state: %v", serr)
	}
}

func (in *Installer) clearFailure(name, version string) {
	if _, ok := in.st.Bad[badKey(name, version)]; ok {
		delete(in.st.Bad, badKey(name, version))
		if err := in.saveState(); err != nil {
			in.logf("kernel: saving state: %v", err)
		}
	}
}
