// Package fileops is the agent's confined file manager (PLAN v9 D9 / WP-G6).
//
// Every file_* command goes through Ops.Resolve first: it is the only place
// that turns a (root, path) pair from the panel into a real path. The rules are
// deliberately strict, because the panel is a remote caller:
//
//   - a path must be relative, must not contain a ".." or "\" segment, and must
//     not be absolute;
//   - every path segment is checked with Lstat and opened with O_NOFOLLOW, so a
//     symlink anywhere along the way is refused instead of being followed;
//   - the target must be a regular file (or a directory, for file_list): FIFOs,
//     devices, sockets and symlinks are refused;
//   - the resolved path must sit inside the named root and must not be one of
//     the agent's own files (agent.yml, desired.json, last_good.json), which
//     are never reachable even when a root contains them;
//   - file_write never writes an executable bit unless the local policy sets
//     Files.AllowExec, and never a setuid/setgid/sticky bit;
//   - file_read and file_write are bounded by MaxRead/MaxWrite (128 KiB by
//     default: the contract's frame limit, docs/WS-PROTOCOL.md section 7
//     ruling 8).
//
// Known limitation (design section 3.9): the os package has no openat, so
// between the Lstat check and the open there is a small TOCTOU window. The
// deployment requirement that follows from it — no directory inside a root may
// be writable by a non-root user — is documented in docs/AGENT.md.
package fileops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// Size limits. The contract (docs/WS-PROTOCOL.md section 7 ruling 8) caps both
// a file_read limit and a file_write payload at 128 KiB raw, which fits the
// 256 KiB frame once base64 encoded. Anything larger belongs to the managed
// files blob path, not to these commands.
const (
	DefaultMaxRead  int64 = 128 << 10
	DefaultMaxWrite int64 = 128 << 10

	// maxListEntries bounds one file_list answer. A directory with more
	// entries would not fit the frame anyway.
	maxListEntries = 4096
)

// Errors the operations return. They are sentinel values so the command layer
// can map them onto stable wire codes.
var (
	ErrOutsideRoots = errors.New("path outside the configured roots")
	ErrNotRegular   = errors.New("not a regular file")
	ErrSymlink      = errors.New("symbolic links are refused")
	ErrTooLarge     = errors.New("size limit exceeded")
	ErrBadPath      = errors.New("invalid path")
	ErrNotDir       = errors.New("not a directory")
	ErrIsDir        = errors.New("is a directory")
	ErrExecBit      = errors.New("an executable bit requires Files.AllowExec")
	ErrSpecialMode  = errors.New("setuid, setgid and sticky bits are refused")
	ErrHashMismatch = errors.New("sha256 mismatch")
	ErrUnknownRoot  = errors.New("unknown file root")
	ErrNoRoots      = errors.New("no file root is configured")
)

// Root is one managed directory. Name is the short label the panel sends
// ("xray", "state", ...); Path is the absolute directory.
type Root struct {
	Name string
	Path string
}

// Options configures the file operations.
type Options struct {
	// Roots are the only directories the panel may reach. At least one is
	// required for the file_* commands to exist at all.
	Roots []Root
	// Unrestricted skips the root lookup: the panel may name an absolute path
	// or one with "..". It is a local-only switch (Files.Unrestricted) and the
	// symlink, regular-file and size rules still apply.
	Unrestricted bool
	// AllowExec permits writing the executable bit. Default false: a panel that
	// can drop an executable into a directory root runs is a remote code
	// execution path (design section 6.9).
	AllowExec bool
	// Excluded are absolute paths that are never readable or writable, even
	// when they sit inside a root: the agent's own agent.yml and its state
	// files (agentcfg.ExcludedPaths).
	Excluded []string
	// MaxRead and MaxWrite default to 128 KiB.
	MaxRead  int64
	MaxWrite int64
	// Log receives the operations' events; never file content.
	Log driver.Logger

	// testAllowSystemRoot relaxes the system-directory check of New. It exists
	// only so the package's own tests can use t.TempDir() on a platform whose
	// temp directory sits under /tmp or /var; production code never sets it.
	testAllowSystemRoot bool
}

// Ops performs the confined file operations.
type Ops struct {
	opts  Options
	roots map[string]Root
	log   driver.Logger
	excl  []string
}

// Entry is one file_list row.
type Entry struct {
	Name  string `json:"name"`
	Type  string `json:"type"` // file | dir | link | other
	Size  int64  `json:"size"`
	Mode  string `json:"mode"`
	MTime int64  `json:"mtime"`
}

// ReadResult is a file_read answer. Data is base64-encoded by the command
// layer, not here.
type ReadResult struct {
	Data []byte `json:"-"`
	Size int64  `json:"size"`
	EOF  bool   `json:"eof"`
}

// WriteResult is a file_write answer.
type WriteResult struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	Created bool   `json:"created"`
}

// New validates the roots and builds the operations. A root that is a system
// directory or too shallow is refused: the panel must never be handed a write
// path to one (design section 3.9).
func New(o Options) (*Ops, error) {
	if o.MaxRead <= 0 {
		o.MaxRead = DefaultMaxRead
	}
	if o.MaxWrite <= 0 {
		o.MaxWrite = DefaultMaxWrite
	}
	if o.Log == nil {
		o.Log = nopLog{}
	}
	roots := make(map[string]Root, len(o.Roots))
	for i, r := range o.Roots {
		if r.Name == "" {
			return nil, fmt.Errorf("fileops: Roots[%d] has no name", i)
		}
		if _, dup := roots[r.Name]; dup {
			return nil, fmt.Errorf("fileops: root %q is configured twice", r.Name)
		}
		abs, err := checkRoot(r.Path, o.testAllowSystemRoot)
		if err != nil {
			return nil, fmt.Errorf("fileops: root %q: %w", r.Name, err)
		}
		r.Path = abs
		roots[r.Name] = r
	}
	excl := make([]string, 0, len(o.Excluded))
	for _, e := range o.Excluded {
		if e == "" {
			continue
		}
		abs, err := filepath.Abs(e)
		if err != nil {
			return nil, fmt.Errorf("fileops: excluded path %s: %w", e, err)
		}
		excl = append(excl, filepath.Clean(abs))
	}
	return &Ops{opts: o, roots: roots, log: o.Log, excl: excl}, nil
}

// Roots returns the configured roots, sorted by name.
func (o *Ops) Roots() []Root {
	out := make([]Root, 0, len(o.roots))
	for _, r := range o.roots {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// RootNames returns the configured root names, sorted.
func (o *Ops) RootNames() []string {
	out := make([]string, 0, len(o.roots))
	for n := range o.roots {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Unrestricted reports the local Files.Unrestricted switch.
func (o *Ops) Unrestricted() bool { return o.opts.Unrestricted }

// AllowExec reports the local Files.AllowExec switch.
func (o *Ops) AllowExec() bool { return o.opts.AllowExec }

// MaxRead and MaxWrite expose the limits (the command layer checks them before
// it decodes a payload).
func (o *Ops) MaxRead() int64  { return o.opts.MaxRead }
func (o *Ops) MaxWrite() int64 { return o.opts.MaxWrite }

// List answers file_list: the entries of one directory inside a root.
func (o *Ops) List(ctx context.Context, root, rel string) ([]Entry, error) {
	dir, err := o.Resolve(root, rel)
	if err != nil {
		return nil, err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %s", ErrSymlink, dir)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%w: %s", ErrNotDir, dir)
	}
	f, err := openNoFollow(dir, true)
	if err != nil {
		if isSymlinkErr(err) {
			return nil, fmt.Errorf("%w: %s", ErrSymlink, dir)
		}
		return nil, err
	}
	defer f.Close()
	names, err := f.Readdirnames(maxListEntries)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	out := make([]Entry, 0, len(names))
	for _, name := range names {
		full := filepath.Join(dir, name)
		if o.isExcluded(full) {
			continue
		}
		fi, err := os.Lstat(full)
		if err != nil {
			// A file that vanished between readdir and lstat is reported as
			// "other" with no size rather than failing the whole listing.
			out = append(out, Entry{Name: name, Type: "other"})
			continue
		}
		out = append(out, Entry{
			Name:  name,
			Type:  entryType(fi.Mode()),
			Size:  fi.Size(),
			Mode:  fmt.Sprintf("%04o", fi.Mode().Perm()),
			MTime: fi.ModTime().Unix(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Read answers file_read. offset may exceed the file size; limit is clamped to
// MaxRead.
func (o *Ops) Read(ctx context.Context, root, rel string, offset, limit int64) (ReadResult, error) {
	if offset < 0 {
		return ReadResult{}, fmt.Errorf("%w: negative offset", ErrBadPath)
	}
	if limit <= 0 {
		limit = o.opts.MaxRead
	}
	if limit > o.opts.MaxRead {
		return ReadResult{}, fmt.Errorf("%w: limit %d exceeds %d", ErrTooLarge, limit, o.opts.MaxRead)
	}
	full, err := o.Resolve(root, rel)
	if err != nil {
		return ReadResult{}, err
	}
	f, err := openRegular(full)
	if err != nil {
		return ReadResult{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return ReadResult{}, err
	}
	if !fi.Mode().IsRegular() {
		return ReadResult{}, fmt.Errorf("%w: %s", ErrNotRegular, full)
	}
	size := fi.Size()
	if offset > size {
		offset = size
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return ReadResult{}, err
	}
	data, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return ReadResult{}, err
	}
	return ReadResult{Data: data, Size: int64(len(data)), EOF: offset+int64(len(data)) >= size}, nil
}

// Write answers file_write: the payload is verified, then written atomically
// (same-directory temp file, fsync, rename over the target).
func (o *Ops) Write(ctx context.Context, root, rel string, data []byte, mode os.FileMode, wantSHA string) (WriteResult, error) {
	if int64(len(data)) > o.opts.MaxWrite {
		return WriteResult{}, fmt.Errorf("%w: %d bytes exceeds %d", ErrTooLarge, len(data), o.opts.MaxWrite)
	}
	if mode == 0 {
		mode = 0o644
	}
	if err := o.checkMode(mode); err != nil {
		return WriteResult{}, err
	}
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if wantSHA != "" {
		if !strings.EqualFold(strings.TrimSpace(wantSHA), got) {
			return WriteResult{}, fmt.Errorf("%w: want %s, got %s", ErrHashMismatch, strings.TrimSpace(wantSHA), got)
		}
	}
	full, err := o.Resolve(root, rel)
	if err != nil {
		return WriteResult{}, err
	}
	if err := o.checkTargetForWrite(full); err != nil {
		return WriteResult{}, err
	}
	created, err := o.writeAtomic(full, data, mode.Perm())
	if err != nil {
		return WriteResult{}, err
	}
	o.logf().Infof("fileops: wrote %s (%d bytes, mode %04o)", full, len(data), mode.Perm())
	return WriteResult{Path: full, SHA256: got, Size: int64(len(data)), Created: created}, nil
}

// Delete answers file_delete. It removes one regular file and never recurses: a
// directory, a symlink or a special file is refused, so one command can never
// empty a configuration directory.
func (o *Ops) Delete(ctx context.Context, root, rel string) error {
	full, err := o.Resolve(root, rel)
	if err != nil {
		return err
	}
	fi, err := os.Lstat(full)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", ErrSymlink, full)
	}
	if fi.IsDir() {
		return fmt.Errorf("%w: %s (file_delete never removes a directory)", ErrIsDir, full)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s", ErrNotRegular, full)
	}
	if err := os.Remove(full); err != nil {
		return err
	}
	o.logf().Infof("fileops: deleted %s", full)
	return nil
}

// checkMode applies the local mode policy: only 0600, 0644 and 0755, no
// setuid/setgid/sticky, and an executable bit only with Files.AllowExec.
//
// The special bits are tested with the Unix octal masks (04000/02000/01000)
// rather than os.ModeSetuid and friends: the panel sends a Unix mode string
// like "4755", which parses into those low bits, not into Go's high-bit
// FileMode flags.
func (o *Ops) checkMode(mode os.FileMode) error {
	if mode&0o7000 != 0 {
		return fmt.Errorf("%w: %04o", ErrSpecialMode, mode)
	}
	if mode&0o111 != 0 && !o.opts.AllowExec {
		return fmt.Errorf("%w: %04o", ErrExecBit, mode)
	}
	switch mode.Perm() {
	case 0o600, 0o644, 0o755:
		return nil
	default:
		return fmt.Errorf("%w: mode %04o is not one of 0600, 0644, 0755", ErrBadPath, mode.Perm())
	}
}

// checkTargetForWrite refuses a target that exists as something other than a
// regular file. A symlink is refused rather than replaced, so a write can never
// be redirected to a file outside the root.
func (o *Ops) checkTargetForWrite(full string) error {
	fi, err := os.Lstat(full)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", ErrSymlink, full)
	}
	if fi.IsDir() {
		return fmt.Errorf("%w: %s", ErrIsDir, full)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s", ErrNotRegular, full)
	}
	return nil
}

// writeAtomic writes data to a temp file in the target's directory and renames
// it over the target (the state store's pattern). The temp file is created with
// the target's mode and never more permissive.
func (o *Ops) writeAtomic(full string, data []byte, mode os.FileMode) (bool, error) {
	dir := filepath.Dir(full)
	if err := o.checkSegment(dir, true); err != nil {
		return false, err
	}
	_, statErr := os.Lstat(full)
	created := errors.Is(statErr, os.ErrNotExist)

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(full)+".*.tmp")
	if err != nil {
		return false, err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		cleanup()
		return false, err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return false, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return false, err
	}
	if err := os.Rename(tmpName, full); err != nil {
		cleanup()
		return false, err
	}
	syncDir(dir)
	return created, nil
}

func (o *Ops) isExcluded(p string) bool {
	for _, e := range o.excl {
		if samePath(p, e) {
			return true
		}
	}
	return false
}

func (o *Ops) logf() driver.Logger {
	if o.log == nil {
		return nopLog{}
	}
	return o.log
}

type nopLog struct{}

func (nopLog) Debugf(string, ...any) {}
func (nopLog) Infof(string, ...any)  {}
func (nopLog) Warnf(string, ...any)  {}
func (nopLog) Errorf(string, ...any) {}
