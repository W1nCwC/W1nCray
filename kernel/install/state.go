package install

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// File modes used on disk.
const (
	dirMode   os.FileMode = 0o755 // kernel directories (executables must be reachable)
	privDir   os.FileMode = 0o700 // .partial (download/staging area)
	stateMode os.FileMode = 0o600 // state.json, manifest.json, .installed.json
)

var reVersionDir = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$`)

// state is <dir>/kernels/state.json.
type state struct {
	Schema      int                  `json:"schema"`
	MaxSequence int64                `json:"max_sequence"` // highest manifest sequence ever accepted
	Bad         map[string]*badEntry `json:"bad,omitempty"`
}

// badEntry records a failed version; Ensure refuses it until Until.
type badEntry struct {
	Fails     int       `json:"fails"`
	LastError string    `json:"last_error"`
	Code      string    `json:"code"`
	LastAt    time.Time `json:"last_at"`
	Until     time.Time `json:"until"`
}

// marker is <dir>/kernels/<name>/<version>/.installed.json.
type marker struct {
	Name          string       `json:"name"`
	Version       string       `json:"version"`
	Target        string       `json:"target"`
	Variant       string       `json:"variant,omitempty"`
	Binary        string       `json:"binary"`
	ArchiveSHA256 string       `json:"archive_sha256"`
	InstalledAt   time.Time    `json:"installed_at"`
	Files         []markerFile `json:"files"`
}

type markerFile struct {
	To   string `json:"to"`
	Size int64  `json:"size"`
	Mode string `json:"mode"`
}

func badKey(name, version string) string { return name + "@" + version }

// writeFileAtomic writes via a temp file in the same directory and renames.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := func() { _ = os.Remove(name) }
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Chmod(name, mode); err != nil && runtime.GOOS != "windows" {
		cleanup()
		return err
	}
	if err := os.Rename(name, path); err != nil {
		cleanup()
		return err
	}
	return nil
}

func (in *Installer) loadState() error {
	b, err := os.ReadFile(in.statePath())
	switch {
	case errors.Is(err, os.ErrNotExist):
		in.st = state{Schema: 1}
		return nil
	case err != nil:
		return err
	}
	var s state
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("corrupt %s: %w", in.statePath(), err)
	}
	in.st = s
	return nil
}

func (in *Installer) saveState() error {
	in.st.Schema = 1
	b, err := json.MarshalIndent(&in.st, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(in.statePath(), append(b, '\n'), stateMode)
}

// --- current / previous pointers -----------------------------------------
//
// A pointer is a relative symlink "<name>/current -> <version>" on unix. On
// Windows, and wherever symlinks are not supported (vfat extroot), it is a
// small text file holding the version. Both forms are read on every OS.

func readPointer(path string) (string, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	var v string
	if fi.Mode()&os.ModeSymlink != 0 {
		t, err := os.Readlink(path)
		if err != nil {
			return "", err
		}
		v = filepath.Base(t)
	} else {
		if fi.Size() > 128 {
			return "", fmt.Errorf("pointer %s too large", path)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		v = strings.TrimSpace(string(b))
	}
	if !reVersionDir.MatchString(v) {
		return "", fmt.Errorf("pointer %s holds invalid version %q", path, v)
	}
	return v, nil
}

// writePointer atomically points path at version.
func writePointer(path, version string) error {
	dir := filepath.Dir(path)
	tmp := filepath.Join(dir, ".ptr-"+filepath.Base(path)+"-tmp")
	_ = os.Remove(tmp)
	if runtime.GOOS != "windows" {
		if err := os.Symlink(version, tmp); err == nil {
			if err := os.Rename(tmp, path); err == nil {
				return nil
			}
			_ = os.Remove(tmp)
		}
	}
	// Text fallback. If a symlink currently sits at path, rename replaces it.
	if err := os.WriteFile(tmp, []byte(version+"\n"), stateMode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func removePointer(path string) { _ = os.Remove(path) }
