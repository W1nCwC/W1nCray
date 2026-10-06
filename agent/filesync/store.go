package filesync

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Directory names under the filesync state directory.
const (
	blobDirName  = "blobs"
	stageDirName = "stage"
	goodDirName  = "last_good"
)

// Store is the on-disk side of the managed-file sync: the content-addressed
// blob cache, the staging directory, and the last_good snapshot of the files
// that were in place before the last replacement. It is safe for concurrent use
// through the Applier's mutex; it holds no lock of its own.
type Store struct {
	dir string
}

// Open creates the state directory (0700) if needed and returns a store on it.
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("filesync: empty state directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("filesync: %w", err)
	}
	return &Store{dir: dir}, nil
}

// Dir returns the store's root directory.
func (s *Store) Dir() string { return s.dir }

// blobPath is where the blob with this digest lives. The digest is validated
// before it is joined, so it can never contain a path.
func (s *Store) blobPath(sha string) (string, error) {
	if !ValidSHA256(sha) {
		return "", fmt.Errorf("filesync: %q is not a sha256 digest", sha)
	}
	return filepath.Join(s.dir, blobDirName, sha), nil
}

// Has reports whether the blob is already cached.
func (s *Store) Has(sha string) bool {
	p, err := s.blobPath(sha)
	if err != nil {
		return false
	}
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// Put stores b under its digest (which the caller has already verified) and
// returns the cache path. The write is atomic: a temporary file in the same
// directory is synced and renamed over the final name, so a crash can never
// leave a truncated blob behind. An existing blob is left alone.
func (s *Store) Put(sha string, b []byte) (string, error) {
	p, err := s.blobPath(sha)
	if err != nil {
		return "", err
	}
	if s.Has(sha) {
		return p, nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", fmt.Errorf("filesync: %w", err)
	}
	if err := writeFileAtomic(p, b, 0o600); err != nil {
		return "", err
	}
	return p, nil
}

// Get returns the cache path of a blob, if it is present.
func (s *Store) Get(sha string) (string, bool) {
	p, err := s.blobPath(sha)
	if err != nil {
		return "", false
	}
	fi, err := os.Stat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return "", false
	}
	return p, true
}

// NewStage creates a fresh staging directory and returns its path.
func (s *Store) NewStage() (string, error) {
	dir := filepath.Join(s.dir, stageDirName, fmt.Sprintf("stage-%d", time.Now().UnixNano()))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("filesync: %w", err)
	}
	return dir, nil
}

// DiscardStage removes a staging directory. A missing directory is not an
// error: the caller may discard twice.
func (s *Store) DiscardStage(dir string) error {
	if dir == "" {
		return nil
	}
	base := filepath.Base(dir)
	if !strings.HasPrefix(base, "stage-") {
		return fmt.Errorf("filesync: refusing to remove %q: not a staging directory", dir)
	}
	if err := os.RemoveAll(dir); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("filesync: %w", err)
	}
	return nil
}

// StageBlob copies a cached blob into the staging directory under its managed
// name. The name is validated first, so nothing but a whitelisted plain file
// name can ever be created there.
func (s *Store) StageBlob(stageDir, name, sha string) error {
	if err := CheckName(name); err != nil {
		return err
	}
	src, ok := s.Get(sha)
	if !ok {
		return fmt.Errorf("filesync: blob %s is not cached", sha)
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("filesync: reading the cached blob %s: %w", sha, err)
	}
	return writeFileAtomic(filepath.Join(stageDir, name), b, 0o644)
}

// FileState is the sha256, size and mode of one managed file on disk.
type FileState struct {
	Name   string
	SHA256 string
	Size   int64
	Mode   fs.FileMode
}

// StateOf hashes the managed file in dir. A missing file returns ok=false and
// no error: "not there" is a normal state for the first apply.
func StateOf(dir, name string) (FileState, bool, error) {
	if err := CheckName(name); err != nil {
		return FileState{}, false, err
	}
	p := filepath.Join(dir, name)
	f, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return FileState{}, false, nil
	}
	if err != nil {
		return FileState{}, false, fmt.Errorf("filesync: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return FileState{}, false, fmt.Errorf("filesync: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return FileState{}, false, fmt.Errorf("filesync: %s is not a regular file", p)
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return FileState{}, false, fmt.Errorf("filesync: hashing %s: %w", p, err)
	}
	return FileState{
		Name:   name,
		SHA256: hex.EncodeToString(h.Sum(nil)),
		Size:   n,
		Mode:   fi.Mode().Perm(),
	}, true, nil
}

// SnapshotLastGood copies the current content of every named file from dir into
// the last_good directory, replacing any previous snapshot. A file that is not
// there is recorded as absent, so a rollback removes it again instead of
// leaving a half-applied state behind.
func (s *Store) SnapshotLastGood(dir string, names []string) error {
	good := filepath.Join(s.dir, goodDirName)
	if err := os.RemoveAll(good); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("filesync: %w", err)
	}
	if err := os.MkdirAll(good, 0o700); err != nil {
		return fmt.Errorf("filesync: %w", err)
	}
	var absent []string
	for _, name := range names {
		if err := CheckName(name); err != nil {
			return err
		}
		src := filepath.Join(dir, name)
		b, err := os.ReadFile(src)
		if errors.Is(err, fs.ErrNotExist) {
			absent = append(absent, name)
			continue
		}
		if err != nil {
			return fmt.Errorf("filesync: snapshotting %s: %w", src, err)
		}
		mode := fs.FileMode(0o644)
		if fi, err := os.Stat(src); err == nil {
			mode = fi.Mode().Perm()
		}
		if err := writeFileAtomic(filepath.Join(good, name), b, mode); err != nil {
			return err
		}
	}
	if len(absent) > 0 {
		// One line per absent file, so a rollback knows to remove it.
		if err := os.WriteFile(filepath.Join(good, absentName), []byte(strings.Join(absent, "\n")+"\n"), 0o600); err != nil {
			return fmt.Errorf("filesync: %w", err)
		}
	}
	return nil
}

// absentName records the managed files that did not exist when the snapshot was
// taken (one name per line).
const absentName = "absent.txt"

// HasLastGood reports whether a last_good snapshot exists.
func (s *Store) HasLastGood() bool {
	fi, err := os.Stat(filepath.Join(s.dir, goodDirName))
	return err == nil && fi.IsDir()
}

// LastGoodNames returns the managed file names present in the last_good
// snapshot, sorted. It is used by files_rollback to know what to restore when
// the panel does not name the files.
func (s *Store) LastGoodNames() []string {
	entries, err := os.ReadDir(filepath.Join(s.dir, goodDirName))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || e.Name() == absentName {
			continue
		}
		if IsManaged(e.Name()) {
			out = append(out, e.Name())
		}
	}
	return out
}

// RestoreLastGood puts every snapshot file back into dir and removes the files
// the snapshot recorded as absent. It returns the restored names.
func (s *Store) RestoreLastGood(dir string) ([]string, error) {
	good := filepath.Join(s.dir, goodDirName)
	if !s.HasLastGood() {
		return nil, errors.New("filesync: no last_good snapshot to restore")
	}
	names := s.LastGoodNames()
	for _, name := range names {
		b, err := os.ReadFile(filepath.Join(good, name))
		if err != nil {
			return nil, fmt.Errorf("filesync: reading the last_good copy of %s: %w", name, err)
		}
		mode := fs.FileMode(0o644)
		if fi, err := os.Stat(filepath.Join(dir, name)); err == nil {
			mode = fi.Mode().Perm()
		} else if fi, err := os.Stat(filepath.Join(good, name)); err == nil {
			mode = fi.Mode().Perm()
		}
		if err := ReplaceFile(dir, name, b, mode); err != nil {
			return nil, err
		}
	}
	if raw, err := os.ReadFile(filepath.Join(good, absentName)); err == nil {
		for _, name := range strings.Fields(string(raw)) {
			if err := CheckName(name); err != nil {
				continue
			}
			if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return nil, fmt.Errorf("filesync: removing %s during the rollback: %w", name, err)
			}
		}
	}
	return names, nil
}

// DropLastGood forgets the snapshot: the files it holds are now the good ones.
func (s *Store) DropLastGood() error {
	if err := os.RemoveAll(filepath.Join(s.dir, goodDirName)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("filesync: %w", err)
	}
	return nil
}

// PruneStages removes every staging directory. It is called once per apply so a
// crash cannot leave staged files (and their bytes) around forever.
func (s *Store) PruneStages() {
	stages, err := os.ReadDir(filepath.Join(s.dir, stageDirName))
	if err != nil {
		return
	}
	for _, e := range stages {
		if e.IsDir() && strings.HasPrefix(e.Name(), "stage-") {
			_ = os.RemoveAll(filepath.Join(s.dir, stageDirName, e.Name()))
		}
	}
}

// ValidSHA256 reports whether s is a plain lowercase hex sha256 digest.
func ValidSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Digest returns the lowercase hex sha256 of b.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ReplaceFile replaces dir/name with content atomically: a temporary file in
// the target directory is written, synced and renamed over the destination, so
// a reader (or a crash) never sees a half-written file. The name is validated
// first. mode is the permission of the new file; when the destination already
// exists its mode is kept (a geo file an operator chmodded stays that way).
func ReplaceFile(dir, name string, content []byte, mode fs.FileMode) error {
	if err := CheckName(name); err != nil {
		return err
	}
	dst := filepath.Join(dir, name)
	if fi, err := os.Stat(dst); err == nil {
		mode = fi.Mode().Perm()
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("filesync: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("filesync: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+name+".*.tmp")
	if err != nil {
		return fmt.Errorf("filesync: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("filesync: writing %s: %w", dst, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("filesync: syncing %s: %w", dst, err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("filesync: %w", err)
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		cleanup()
		return fmt.Errorf("filesync: chmod %s: %w", dst, err)
	}
	if err := renameOver(tmpName, dst); err != nil {
		cleanup()
		return fmt.Errorf("filesync: replacing %s: %w", dst, err)
	}
	syncDir(dir)
	return nil
}

// writeFileAtomic writes b to path through a temporary file in the same
// directory, syncing before the rename.
func writeFileAtomic(path string, b []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("filesync: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("filesync: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("filesync: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("filesync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("filesync: %w", err)
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		cleanup()
		return fmt.Errorf("filesync: %w", err)
	}
	if err := renameOver(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("filesync: %w", err)
	}
	syncDir(dir)
	return nil
}

// syncDir flushes directory metadata so a rename survives a crash. Best effort:
// some platforms cannot fsync a directory.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}
