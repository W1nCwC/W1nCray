// This file answers "which kernel version is really running". The installer's
// current/previous pointers say what was *selected*, not what is executing: a
// process keeps the binary it started with until it is restarted, so after a
// rollback the running version can be the previous one. The answer comes from
// the supervisor's pid records, verified against the live process, and then
// mapped back to the version directory under <kernelsRoot>/<name>/<version>/.

package kernelx

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/W1nCwC/W1nCray/agent/supervisor"
)

// pidRecord mirrors the supervisor's on-disk record (<PIDDir>/<id>.pid,
// agent/supervisor/pidfile.go). It is duplicated on purpose: the supervisor
// owns the format, this package only reads it, and a decoding change there
// must not become an import cycle.
type pidRecord struct {
	ID      string    `json:"id"`
	PID     int       `json:"pid"`
	Path    string    `json:"path"`
	Exe     string    `json:"exe,omitempty"`
	Started time.Time `json:"started"`
}

// RunningBinary returns the executable paths of the live managed processes
// that belong to kernel name. A record belongs to name when its supervisor id
// is name itself or starts with "name/" (gost/main, realm/<instance>,
// frp/frps-<instance>).
//
// A record is only trusted when the pid is alive *and* the process still runs
// the recorded binary (/proc/<pid>/exe), which is what defeats pid reuse. On a
// platform where the executable cannot be read the record is skipped, so the
// caller sees "cannot tell" rather than a wrong answer.
func RunningBinary(pidDir, name string) ([]string, error) {
	if pidDir == "" || name == "" {
		return nil, nil
	}
	ents, err := os.ReadDir(pidDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ent := range ents {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".pid") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(pidDir, ent.Name()))
		if err != nil {
			continue
		}
		var rec pidRecord
		if err := json.Unmarshal(b, &rec); err != nil {
			continue
		}
		if !belongsTo(rec.ID, name) {
			continue
		}
		if rec.PID <= 1 || rec.PID == os.Getpid() || !supervisor.PIDAlive(rec.PID) {
			continue
		}
		exe, ok := supervisor.ProcExe(rec.PID)
		if !ok {
			continue
		}
		exe = filepath.Clean(exe)
		// The process must still be the recorded one; anything else means the
		// pid was reused by an unrelated program.
		if rec.Exe != "" && exe != filepath.Clean(rec.Exe) {
			continue
		}
		if rec.Exe == "" && rec.Path != "" && exe != filepath.Clean(rec.Path) {
			continue
		}
		out = append(out, exe)
	}
	return out, nil
}

// belongsTo reports whether a supervisor id names a process of kernel name.
func belongsTo(id, name string) bool {
	return id == name || strings.HasPrefix(id, name+"/")
}

// MatchVersion maps an executable path back to the version it was installed
// as: the path must sit under <kernelsRoot>/<name>/<version>/ and the version
// segment must be a plain name (no "..", no hidden staging directory). The
// relative path is checked explicitly so "../../evil" can never match.
func MatchVersion(kernelsRoot, name, binPath string) (string, bool) {
	if kernelsRoot == "" || name == "" || binPath == "" {
		return "", false
	}
	base := filepath.Join(filepath.Clean(kernelsRoot), name)
	rel, err := filepath.Rel(base, filepath.Clean(binPath))
	if err != nil || rel == "" || rel == "." {
		return "", false
	}
	if filepath.IsAbs(rel) {
		return "", false
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) < 2 {
		return "", false
	}
	version := parts[0]
	if version == "" || version == "." || version == ".." || strings.HasPrefix(version, ".") {
		return "", false
	}
	for _, p := range parts {
		if p == ".." {
			return "", false
		}
	}
	return version, true
}

// RunningVersion returns the version of kernel name a live managed process is
// executing. exact is false when the platform cannot verify process identity
// (or no pid directory is configured): version is then empty and the caller
// must fall back to the current pointer instead of pretending to know.
//
// exact is true with an empty version when the identity is verifiable and no
// process of that kernel is running: that is a real answer, not a missing one.
func (e *Ensurer) RunningVersion(name string) (version string, exact bool) {
	if e == nil || e.pidDir == "" || !identityVerifiable() {
		return "", false
	}
	exes, err := RunningBinary(e.pidDir, name)
	if err != nil {
		return "", false
	}
	for _, exe := range exes {
		if v, ok := MatchVersion(e.kernelsRoot, name, exe); ok {
			return v, true
		}
	}
	return "", true
}

// identityVerifiable reports whether /proc can tell what a pid executes. The
// probe runs on this process, so it needs no privileges.
func identityVerifiable() bool {
	_, ok := supervisor.ProcExe(os.Getpid())
	return ok
}
