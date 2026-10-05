// Package state persists the agent's desired state and its last known good
// state. Files are JSON, written atomically (temp file + rename) with mode
// 0600 inside a 0700 directory; they are the only place where instance
// secrets are ever stored. Use Redacted before logging or reporting a Desired.
package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/W1nCwC/W1nCray/agent/spec"
)

// SchemaVersion is the version of the on-disk files.
const SchemaVersion = 1

const (
	fileDesired  = "desired.json"
	fileLastGood = "last_good.json"
	fileBlocked  = "blocked.json"
)

// Snapshot is a persisted desired state.
type Snapshot struct {
	Schema  int          `json:"schema"`
	SavedAt time.Time    `json:"saved_at"`
	Hash    string       `json:"hash"`
	Desired spec.Desired `json:"desired"`
	// Engines records the engine each instance id was resolved to when the
	// snapshot was applied (only set for last_good).
	Engines map[string]string `json:"engines,omitempty"`
}

// Redacted returns a copy of the snapshot with every secret removed.
func (s Snapshot) Redacted() Snapshot {
	s.Desired = Redacted(s.Desired)
	return s
}

// Redacted returns a copy of d with all instance secrets cleared. The result
// shares no Instance elements with d, so it is safe to log or report.
func Redacted(d spec.Desired) spec.Desired {
	out := d
	out.Kernels = append([]spec.KernelPin(nil), d.Kernels...)
	out.Instances = make([]spec.Instance, len(d.Instances))
	for i, in := range d.Instances {
		in.Secret = ""
		out.Instances[i] = in
	}
	return out
}

// Hash is the content hash of a desired state: sha256 over its canonical JSON
// with the revision zeroed, so the same content under a new revision number
// hashes identically. Secrets are part of the content (changing a secret must
// re-apply) but only the digest leaves this function.
func Hash(d spec.Desired) string {
	d.Revision = 0
	b, err := json.Marshal(d)
	if err != nil { // spec.Desired always marshals; keep the function total
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Store is a directory of state files. It is safe for concurrent use.
type Store struct {
	dir string
	mu  sync.Mutex
}

// Open creates the directory (0700) if needed and returns a store on it.
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("state: empty directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	// MkdirAll leaves an existing directory's mode alone; tighten it.
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	return &Store{dir: dir}, nil
}

// Dir returns the store directory.
func (s *Store) Dir() string { return s.dir }

// DriverDir returns (creating it with mode 0700) the private directory of a
// driver, for its last-good configuration.
func (s *Store) DriverDir(name string) (string, error) {
	if !validName(name) {
		return "", fmt.Errorf("state: invalid driver name %q", name)
	}
	p := filepath.Join(s.dir, "drivers", name)
	if err := os.MkdirAll(p, 0o700); err != nil {
		return "", fmt.Errorf("state: %w", err)
	}
	return p, nil
}

func validName(n string) bool {
	if n == "" || len(n) > 40 {
		return false
	}
	for _, r := range n {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

// SaveDesired persists the most recently accepted desired state.
func (s *Store) SaveDesired(d spec.Desired) error {
	return s.save(fileDesired, snapshot(d, nil))
}

// LoadDesired returns the persisted desired state; ok is false if none exists.
func (s *Store) LoadDesired() (Snapshot, bool, error) { return s.load(fileDesired) }

// SaveLastGood persists the desired state that was applied and verified,
// together with the engine chosen for each instance.
func (s *Store) SaveLastGood(d spec.Desired, engines map[string]string) error {
	return s.save(fileLastGood, snapshot(d, engines))
}

// LoadLastGood returns the last good state; ok is false if none exists.
func (s *Store) LoadLastGood() (Snapshot, bool, error) { return s.load(fileLastGood) }

type blocked struct {
	Schema  int       `json:"schema"`
	SavedAt time.Time `json:"saved_at"`
	Hash    string    `json:"hash"`
	Reason  string    `json:"reason,omitempty"`
}

// SaveBlocked records a desired-state hash that failed to apply; the agent
// will not retry it until the desired state changes.
func (s *Store) SaveBlocked(hash, reason string) error {
	return s.save(fileBlocked, blocked{Schema: SchemaVersion, SavedAt: time.Now().UTC(), Hash: hash, Reason: reason})
}

// LoadBlocked returns the blocked hash ("" if none).
func (s *Store) LoadBlocked() (hash, reason string, err error) {
	var b blocked
	ok, err := s.read(fileBlocked, &b)
	if err != nil || !ok {
		return "", "", err
	}
	if b.Schema > SchemaVersion {
		return "", "", fmt.Errorf("state: %s has newer schema %d", fileBlocked, b.Schema)
	}
	return b.Hash, b.Reason, nil
}

// ClearBlocked forgets the blocked hash.
func (s *Store) ClearBlocked() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(filepath.Join(s.dir, fileBlocked)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("state: %w", err)
	}
	return nil
}

func snapshot(d spec.Desired, engines map[string]string) Snapshot {
	return Snapshot{Schema: SchemaVersion, SavedAt: time.Now().UTC(), Hash: Hash(d), Desired: d, Engines: engines}
}

func (s *Store) load(name string) (Snapshot, bool, error) {
	var sn Snapshot
	ok, err := s.read(name, &sn)
	if err != nil || !ok {
		return Snapshot{}, false, err
	}
	if sn.Schema > SchemaVersion {
		return Snapshot{}, false, fmt.Errorf("state: %s has newer schema %d (this agent understands %d)", name, sn.Schema, SchemaVersion)
	}
	if sn.Schema < 1 {
		return Snapshot{}, false, fmt.Errorf("state: %s has no schema version", name)
	}
	return sn, true, nil
}

func (s *Store) read(name string, v any) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(filepath.Join(s.dir, name))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("state: %w", err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		return false, fmt.Errorf("state: %s is corrupt: %w", name, err)
	}
	return true, nil
}

// save writes v atomically: temp file in the same directory (mode 0600),
// fsync, rename over the target, fsync of the directory where supported.
func (s *Store) save(name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("state: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tmp, err := os.CreateTemp(s.dir, "."+name+".*.tmp")
	if err != nil {
		return fmt.Errorf("state: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	// os.CreateTemp creates the file with mode 0600.
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("state: %w", err)
	}
	if err := os.Rename(tmpName, filepath.Join(s.dir, name)); err != nil {
		cleanup()
		return fmt.Errorf("state: %w", err)
	}
	syncDir(s.dir)
	return nil
}

// syncDir flushes directory metadata so the rename survives a crash. It is
// best effort: some platforms cannot fsync a directory.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}
