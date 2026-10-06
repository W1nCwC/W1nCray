// Package selfupdate replaces the running agent binary with a version listed
// in the signed kernel manifest under the reserved name "agent", atomically and
// without bricking the machine (PLAN v9 D7, protocol ruling 11).
//
// The trust root is the manifest: the target version must be listed for this
// platform, not revoked, satisfy min_agent, pass the archive and member
// hashes and pass the manifest's own version self-check. Only then is anything
// swapped, and even then the old binary is renamed to exe.old, never deleted,
// so a manual "mv exe.old exe" is the last line of defence.
//
// The package owns four markers under <StateDir>/update:
//
//	pending.json   a commit happened and the new process has not confirmed yet
//	rollback.json  the watchdog rolled the swap back (reported on the next start)
//	staged/        verified next versions, waiting for Commit
//	archive/       downloaded archives, verified before use
//
// A commit also leaves a copy of the previous, known-good executable in
// update/watchdog/. That copy — never the new binary, which may be the thing
// that cannot run — is what the detached watchdog runs (see restart.go).
package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
)

// DefaultAgentName is the manifest kernel name reserved for self_update.
const DefaultAgentName = "agent"

// Defaults of the watchdog and the start-up watchdog.
const (
	DefaultAttempts = 3
	// DefaultAliveWindow is how long the watchdog tolerates "no agent alive"
	// after the update before it rolls back.
	DefaultAliveWindow = 10 * time.Second
	// DefaultDeadline bounds the whole observation. Past it, an agent that is
	// alive and stable but never confirmed is only reported as stalled.
	DefaultDeadline = 90 * time.Second
	// DefaultPollInterval is how often the watchdog probes the single-instance
	// lock.
	DefaultPollInterval  = 2 * time.Second
	DefaultConfirmWindow = 10 * time.Minute
	parentWaitTimeout    = 60 * time.Second
)

var (
	// ErrNotSupported is returned when this build or platform cannot replace
	// its own executable (Windows) or has no service manager that runs it.
	ErrNotSupported = errors.New("self-update is not supported on this platform")
	// ErrNoInstaller means no manifest installer is wired: nothing can be
	// staged.
	ErrNoInstaller = errors.New("self-update has no manifest installer wired")
	// ErrPending means a previous commit has not been confirmed or rolled back
	// yet; a second update would clobber its backup.
	ErrPending = errors.New("a self-update is already pending; confirm or roll it back first")
)

// Installer is the part of kernel/install the updater uses. It is the same
// resolve/download/verify/extract/self-check pipeline the kernel commands use,
// so a manifest-level refusal (unknown version, revoked, min_agent, expired,
// no target) or a hash/self-check failure is reported here unchanged.
type Installer interface {
	DownloadFor(ctx context.Context, name, version, dir string) (manifest.Target, string, error)
	VerifyArchiveFor(ctx context.Context, name, version, archivePath, dest string) (manifest.Target, string, error)
}

// Options configures an Updater.
type Options struct {
	// ExePath is the resolved absolute path of the running executable
	// (os.Executable + filepath.EvalSymlinks). Required.
	ExePath string
	// StateDir holds the update/ markers. Required.
	StateDir string
	// LockPath is the single-instance lock file (<config>.lock) whose content
	// is the pid of the running agent. The watchdog reads it to tell whether an
	// agent is alive and how often it restarted. Empty means the watchdog has
	// no liveness signal and never rolls back on its own.
	LockPath string
	// AgentVersion is the version of the binary that is running right now. It
	// names the known-good copy of it that Commit keeps for the watchdog
	// (update/watchdog/W1nCray-<version>). Empty falls back to "old".
	AgentVersion string
	// AgentName is the manifest kernel name; empty means DefaultAgentName.
	AgentName string
	// Installer stages a version. It may be nil for the start-up watchdog,
	// which only reads and clears the markers.
	Installer Installer
	Now       func() time.Time
	Log       driver.Logger

	// Attempts, AliveWindow, Deadline and PollInterval configure the watchdog.
	// Attempts is how many agent restarts it tolerates before rolling back;
	// AliveWindow is how long it tolerates no live agent; Deadline is the total
	// budget before it gives up (and only reports the update as stalled).
	Attempts     int
	AliveWindow  time.Duration
	Deadline     time.Duration
	PollInterval time.Duration
	// ConfirmWindow is how long a new process may run without reaching the
	// panel before self_update.stalled is reported. It never triggers a
	// rollback (protocol ruling 11).
	ConfirmWindow time.Duration

	// Ready overrides the platform/install-method gate (see Ready). It exists
	// for tests; production leaves it nil and gets the real check.
	Ready func(exePath string) error
}

// Updater stages, commits, confirms and rolls back one agent version.
type Updater struct {
	exe       string
	stateDir  string
	dir       string
	lockPath  string
	agentName string
	version   string
	installer Installer
	now       func() time.Time
	log       driver.Logger

	attempts      int
	aliveWindow   time.Duration
	deadline      time.Duration
	pollInterval  time.Duration
	confirmWindow time.Duration
	ready         func(exePath string) error
}

// CurrentVersion is the build version of the running agent ("" when the
// caller did not provide one). self_update reports it as `from`.
func (u *Updater) CurrentVersion() string { return u.version }

// Staged is a verified next version, ready for Commit.
type Staged struct {
	Version string `json:"version"`
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
}

// Pending is the on-disk record of a commit that has not been confirmed.
type Pending struct {
	Version  string    `json:"version"`
	OldPath  string    `json:"old_path"`
	ExePath  string    `json:"exe_path"`
	At       time.Time `json:"at"`
	Attempts int       `json:"attempts"`
}

// Rollback is the on-disk record of a rollback the helper performed; the next
// start reports it once (event self_update.rolled_back).
type Rollback struct {
	Version string    `json:"version,omitempty"`
	Reason  string    `json:"reason"`
	At      time.Time `json:"at"`
	ExePath string    `json:"exe_path"`
	OldPath string    `json:"old_path"`
}

type nopLog struct{}

func (nopLog) Debugf(string, ...any) {}
func (nopLog) Infof(string, ...any)  {}
func (nopLog) Warnf(string, ...any)  {}
func (nopLog) Errorf(string, ...any) {}

// New builds an Updater. ExePath and StateDir are required.
func New(o Options) (*Updater, error) {
	if o.ExePath == "" {
		return nil, errors.New("selfupdate: ExePath is required")
	}
	if o.StateDir == "" {
		return nil, errors.New("selfupdate: StateDir is required")
	}
	exe, err := filepath.Abs(o.ExePath)
	if err != nil {
		return nil, err
	}
	state, err := filepath.Abs(o.StateDir)
	if err != nil {
		return nil, err
	}
	u := &Updater{
		exe:       exe,
		stateDir:  state,
		dir:       filepath.Join(state, "update"),
		lockPath:  o.LockPath,
		agentName: o.AgentName,
		version:   o.AgentVersion,
		installer: o.Installer,
		now:       o.Now,
		log:       o.Log,
		// watchdog settings
		attempts:      o.Attempts,
		aliveWindow:   o.AliveWindow,
		deadline:      o.Deadline,
		pollInterval:  o.PollInterval,
		confirmWindow: o.ConfirmWindow,
		ready:         o.Ready,
	}
	if u.ready == nil {
		u.ready = Ready
	}
	if u.agentName == "" {
		u.agentName = DefaultAgentName
	}
	if u.now == nil {
		u.now = time.Now
	}
	if u.log == nil {
		u.log = nopLog{}
	}
	if u.attempts <= 0 {
		u.attempts = DefaultAttempts
	}
	if u.aliveWindow <= 0 {
		u.aliveWindow = DefaultAliveWindow
	}
	if u.deadline <= 0 {
		u.deadline = DefaultDeadline
	}
	if u.pollInterval <= 0 {
		u.pollInterval = DefaultPollInterval
	}
	if u.confirmWindow <= 0 {
		u.confirmWindow = DefaultConfirmWindow
	}
	return u, nil
}

// AgentName is the manifest kernel name this updater reads.
func (u *Updater) AgentName() string { return u.agentName }

// ExePath is the resolved executable this updater replaces.
func (u *Updater) ExePath() string { return u.exe }

// OldPath is where Commit keeps the previous executable.
func (u *Updater) OldPath() string { return u.exe + ".old" }

// LockPath is the single-instance lock the watchdog probes ("" when unknown).
func (u *Updater) LockPath() string { return u.lockPath }

// watchdogDir is <StateDir>/update/watchdog.
func (u *Updater) watchdogDir() string { return filepath.Join(u.dir, "watchdog") }

// WatchdogPath is the known-good copy of the previous executable that the
// watchdog runs. Commit creates it; RespawnHelper starts it.
func (u *Updater) WatchdogPath() string {
	tag := u.version
	if tag == "" {
		tag = "old"
	}
	return filepath.Join(u.watchdogDir(), "W1nCray-"+tag)
}

// CleanupWatchdog removes the watchdog copy. It is idempotent and is called
// once the update is confirmed, rolled back or no longer being watched.
func (u *Updater) CleanupWatchdog() error {
	if err := os.RemoveAll(u.watchdogDir()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// installWatchdogCopy copies the previous executable (already renamed aside)
// into the watchdog directory and verifies the copy byte for byte. The watchdog
// must be a known-good binary: the new one may be exactly the thing that cannot
// start, so it can never be its own watchdog.
func (u *Updater) installWatchdogCopy(old string) error {
	dir := u.watchdogDir()
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	dst := u.WatchdogPath()
	if err := copyFile(old, dst, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(dst, 0o755); err != nil && !isWindows() {
		return err
	}
	wantSum, wantSize, err := hashFile(old)
	if err != nil {
		return err
	}
	gotSum, gotSize, err := hashFile(dst)
	if err != nil {
		return err
	}
	if gotSum != wantSum || gotSize != wantSize {
		return fmt.Errorf("selfupdate: the watchdog copy does not match the backup (sha256 %s/%d, want %s/%d)",
			gotSum, gotSize, wantSum, wantSize)
	}
	u.log.Infof("selfupdate: watchdog copy of the previous binary at %s", dst)
	return nil
}

// ConfirmWindow is how long a new process may run without confirming.
func (u *Updater) ConfirmWindow() time.Duration { return u.confirmWindow }

// Ready reports whether this updater can replace the executable in place:
// the platform supports the swap and a service manager runs exactly this
// executable (see Ready). It is the honest input of the "upgrade" capability.
func (u *Updater) Ready() error { return u.ready(u.exe) }

// Stage downloads and verifies the manifest entry for the agent version and
// extracts it into <StateDir>/update/staged/<version>. Nothing outside the
// state directory (and the installer's own download directory) is touched: in
// particular the running executable is never written, so every manifest-level
// refusal, hash mismatch and failed self-check leaves the agent untouched.
func (u *Updater) Stage(ctx context.Context, version string) (Staged, error) {
	if err := u.Ready(); err != nil {
		return Staged{}, err
	}
	if u.installer == nil {
		return Staged{}, ErrNoInstaller
	}
	version = manifest.NormalizeVersion(version)
	if version == "" {
		return Staged{}, errors.New("selfupdate: a version is required")
	}
	if p, ok := u.Pending(); ok {
		return Staged{}, fmt.Errorf("%w (version %s committed at %s)", ErrPending, p.Version, p.At.UTC().Format(time.RFC3339))
	}
	stagedDir := filepath.Join(u.dir, "staged", version)
	if err := os.RemoveAll(stagedDir); err != nil {
		return Staged{}, err
	}
	if err := os.MkdirAll(stagedDir, 0o700); err != nil {
		return Staged{}, err
	}
	archiveDir := filepath.Join(u.dir, "archive")
	_, archivePath, err := u.installer.DownloadFor(ctx, u.agentName, version, archiveDir)
	if err != nil {
		return Staged{}, err
	}
	verified, binPath, err := u.installer.VerifyArchiveFor(ctx, u.agentName, version, archivePath, stagedDir)
	if err != nil {
		_ = os.RemoveAll(stagedDir)
		return Staged{}, err
	}
	if len(verified.Extract) == 0 {
		_ = os.RemoveAll(stagedDir)
		return Staged{}, errors.New("selfupdate: the manifest target lists no file")
	}
	// The staged binary is the extract entry the manifest's run.binary names;
	// for the agent's gz entry there is exactly one, but a tar.gz entry may
	// list a licence next to it.
	ex, ok := extractNamed(verified, filepath.Base(binPath))
	if !ok {
		_ = os.RemoveAll(stagedDir)
		return Staged{}, fmt.Errorf("selfupdate: %s is not one of the manifest's extract entries", filepath.Base(binPath))
	}
	sum, size, err := hashFile(binPath)
	if err != nil {
		_ = os.RemoveAll(stagedDir)
		return Staged{}, err
	}
	if sum != ex.SHA256 || size != ex.Size {
		_ = os.RemoveAll(stagedDir)
		return Staged{}, fmt.Errorf("selfupdate: the staged binary does not match the manifest (%s/%d, want %s/%d)",
			sum, size, ex.SHA256, ex.Size)
	}
	u.log.Infof("selfupdate: staged %s@%s at %s", u.agentName, version, binPath)
	return Staged{Version: version, Path: binPath, SHA256: sum, Size: size}, nil
}

// Commit swaps the executable: the running binary becomes exe.old, the staged
// binary becomes exe, and pending.json records that the new process still has
// to prove itself. Every failure restores the original executable.
func (u *Updater) Commit(s Staged) error {
	if s.Path == "" || s.Version == "" {
		return errors.New("selfupdate: nothing was staged")
	}
	if err := u.Ready(); err != nil {
		return err
	}
	if p, ok := u.Pending(); ok {
		return fmt.Errorf("%w (version %s committed at %s)", ErrPending, p.Version, p.At.UTC().Format(time.RFC3339))
	}
	if sum, _, err := hashFile(s.Path); err != nil {
		return err
	} else if s.SHA256 != "" && sum != s.SHA256 {
		return fmt.Errorf("selfupdate: the staged binary changed under us (sha256 %s, want %s)", sum, s.SHA256)
	}

	dir := filepath.Dir(u.exe)
	// The new binary is copied next to the executable first, so both renames
	// below stay on one filesystem and are atomic.
	next := filepath.Join(dir, "."+filepath.Base(u.exe)+".new")
	_ = os.Remove(next)
	if err := copyFile(s.Path, next, 0o700); err != nil {
		return err
	}
	defer func() { _ = os.Remove(next) }()
	if err := os.Chmod(next, 0o755); err != nil && !isWindows() {
		return err
	}
	if err := syncFile(next); err != nil {
		return err
	}

	old := u.OldPath()
	// A leftover .old from an earlier, confirmed update is stale: there is no
	// pending marker, so nothing points at it any more.
	if _, err := os.Lstat(old); err == nil {
		if err := os.Remove(old); err != nil {
			return fmt.Errorf("selfupdate: removing the stale backup %s: %w", old, err)
		}
	}
	if err := os.Rename(u.exe, old); err != nil {
		return fmt.Errorf("selfupdate: moving the running binary aside: %w", err)
	}
	if err := os.Rename(next, u.exe); err != nil {
		// Put the original back; the agent must never be left without a binary.
		_ = os.Rename(old, u.exe)
		return fmt.Errorf("selfupdate: installing the new binary: %w", err)
	}
	if err := os.Chmod(u.exe, 0o755); err != nil && !isWindows() {
		_ = os.Rename(u.exe, next)
		_ = os.Rename(old, u.exe)
		return err
	}
	_ = syncDir(dir)

	// The watchdog has to be run by a binary that is known to work. The new one
	// just took the executable's place and is unproven, so keep a verified copy
	// of the previous one before the pending marker makes the swap official.
	if err := u.installWatchdogCopy(old); err != nil {
		_ = os.Rename(u.exe, next)
		_ = os.Rename(old, u.exe)
		_ = u.CleanupWatchdog()
		return fmt.Errorf("selfupdate: preparing the watchdog: %w", err)
	}

	p := Pending{Version: s.Version, OldPath: old, ExePath: u.exe, At: u.now().UTC()}
	if err := writeJSONAtomic(u.pendingPath(), &p, 0o600); err != nil {
		// The swap happened; without the marker the watchdog cannot roll it
		// back, so restore immediately.
		_ = os.Rename(u.exe, next)
		_ = os.Rename(old, u.exe)
		_ = u.CleanupWatchdog()
		return fmt.Errorf("selfupdate: writing %s: %w", u.pendingPath(), err)
	}
	u.log.Infof("selfupdate: committed %s (previous binary kept at %s)", s.Version, old)
	return nil
}

// Rollback restores exe.old over the executable and records rollback.json. It
// is idempotent: with no backup and no pending marker there is nothing to do.
func (u *Updater) Rollback(reason string) error {
	p, hasPending := u.Pending()
	old := u.OldPath()
	if _, err := os.Lstat(old); err != nil {
		if hasPending {
			return fmt.Errorf("selfupdate: pending %s has no backup at %s", p.Version, old)
		}
		return nil // nothing was committed here: idempotent no-op
	}
	dir := filepath.Dir(u.exe)
	failed := u.exe + ".failed"
	_ = os.Remove(failed)
	hadExe := false
	if _, err := os.Lstat(u.exe); err == nil {
		if err := os.Rename(u.exe, failed); err != nil {
			return fmt.Errorf("selfupdate: moving the failed binary aside: %w", err)
		}
		hadExe = true
	}
	if err := os.Rename(old, u.exe); err != nil {
		if hadExe {
			_ = os.Rename(failed, u.exe)
		}
		return fmt.Errorf("selfupdate: restoring the previous binary: %w", err)
	}
	if err := os.Chmod(u.exe, 0o755); err != nil && !isWindows() {
		return err
	}
	_ = syncDir(dir)
	_ = os.Remove(failed)

	rb := Rollback{Reason: reason, At: u.now().UTC(), ExePath: u.exe, OldPath: old}
	if hasPending {
		rb.Version = p.Version
	}
	if err := writeJSONAtomic(u.rollbackPath(), &rb, 0o600); err != nil {
		return fmt.Errorf("selfupdate: writing %s: %w", u.rollbackPath(), err)
	}
	if err := os.Remove(u.pendingPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// The old binary is the executable again, so the watchdog copy of it is
	// redundant. Removing the file while the watchdog runs from it is safe on
	// every platform this supports. A failure here is logged, not returned:
	// the rollback itself already succeeded and must be reported as such.
	if err := u.CleanupWatchdog(); err != nil {
		u.log.Warnf("selfupdate: cleaning the watchdog copy: %v", err)
	}
	u.log.Warnf("selfupdate: rolled back to the previous binary (%s)", reason)
	return nil
}

// Confirm marks a committed update as proven: the new process reached the
// panel. It removes the backup and the pending marker. It is a no-op when
// there is nothing pending.
func (u *Updater) Confirm() error {
	old := u.OldPath()
	if err := os.Remove(old); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("selfupdate: removing the backup %s: %w", old, err)
	}
	if err := os.Remove(u.pendingPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// The watchdog sees the pending marker disappear and stops on its own; the
	// copy it runs from is cleaned here too so a watchdog that never started
	// (or was killed with the machine) leaves nothing behind.
	return u.CleanupWatchdog()
}

// Pending reports the committed update that has not been confirmed yet.
func (u *Updater) Pending() (Pending, bool) {
	var p Pending
	if err := readJSON(u.pendingPath(), &p); err != nil || p.Version == "" {
		return Pending{}, false
	}
	return p, true
}

// TakeRollback returns the rollback the helper recorded, if any, and removes
// the marker so the event is reported exactly once.
func (u *Updater) TakeRollback() (Rollback, bool) {
	var rb Rollback
	if err := readJSON(u.rollbackPath(), &rb); err != nil || rb.Reason == "" {
		return Rollback{}, false
	}
	_ = os.Remove(u.rollbackPath())
	return rb, true
}

// extractNamed returns the extract entry whose installed name is to.
func extractNamed(t manifest.Target, to string) (manifest.Extract, bool) {
	for _, e := range t.Extract {
		if e.To == to {
			return e, true
		}
	}
	return manifest.Extract{}, false
}

// pendingPath is <StateDir>/update/pending.json.
func (u *Updater) pendingPath() string { return filepath.Join(u.dir, "pending.json") }

// rollbackPath is <StateDir>/update/rollback.json.
func (u *Updater) rollbackPath() string { return filepath.Join(u.dir, "rollback.json") }

// ---- helpers ---------------------------------------------------------------

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		_ = os.Remove(dst)
		return err
	}
	return out.Close()
}

func syncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Sync(); err != nil && !isWindows() {
		return err
	}
	return nil
}

func writeJSONAtomic(path string, v any, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Chmod(name, mode); err != nil && !isWindows() {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
