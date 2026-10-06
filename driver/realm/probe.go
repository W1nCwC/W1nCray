package realm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// BinaryInfo is what "realm -v" reports ("Realm 2.9.6 [brutal][batched-udp]
// [proxy][balance][transport][multi-thread]", src/cmd/mod.rs and consts.rs).
type BinaryInfo struct {
	Version  string
	Features []string
}

var (
	verRe  = regexp.MustCompile(`^Realm\s+(\S+)((?:\s*\[[a-z0-9-]+\])*)\s*$`)
	featRe = regexp.MustCompile(`\[([a-z0-9-]+)\]`)
)

// requiredFeatures are the compile-time features this driver depends on. The
// "default-slim" build has none of them.
var requiredFeatures = []string{"proxy", "balance", "transport"}

// ParseVersionOutput parses the output of "realm -v".
func ParseVersionOutput(out string) (BinaryInfo, error) {
	line := strings.TrimSpace(out)
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	m := verRe.FindStringSubmatch(line)
	if m == nil {
		return BinaryInfo{}, fmt.Errorf("realm: unrecognised version output %s (not a realm binary?)", show(line))
	}
	bi := BinaryInfo{Version: m[1]}
	for _, f := range featRe.FindAllStringSubmatch(m[2], -1) {
		bi.Features = append(bi.Features, f[1])
	}
	return bi, nil
}

// Check verifies that the binary is the full build and, if wantVersion is not
// empty, that it is that version (a leading "v" is ignored).
func (bi BinaryInfo) Check(wantVersion string) error {
	have := map[string]bool{}
	for _, f := range bi.Features {
		have[f] = true
	}
	var missing []string
	for _, f := range requiredFeatures {
		if !have[f] {
			missing = append(missing, f)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("realm: binary %s lacks feature(s) %s: this is the slim build; the full (non-slim) build is required", bi.Version, strings.Join(missing, ", "))
	}
	if wantVersion != "" && strings.TrimPrefix(wantVersion, "v") != strings.TrimPrefix(bi.Version, "v") {
		return fmt.Errorf("realm: binary reports version %s, expected %s", bi.Version, wantVersion)
	}
	return nil
}

// CheckBinary runs "<path> -v" (argv, no shell, REALM_CONF removed from the
// environment because realm lets it override everything) and returns what the
// binary says it is. The kernel manager can use it as the Detect step.
func CheckBinary(ctx context.Context, path string) (BinaryInfo, error) {
	if path == "" {
		return BinaryInfo{}, errors.New("realm: kernel path is empty")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "-v")
	cmd.Env = cleanEnv()
	out, err := cmd.Output()
	if err != nil {
		return BinaryInfo{}, fmt.Errorf("realm: running %q -v: %w", path, err)
	}
	return ParseVersionOutput(string(out))
}

func cleanEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(strings.ToUpper(kv), "REALM_CONF=") {
			continue
		}
		env = append(env, kv)
	}
	return env
}

// binCache avoids spawning "realm -v" on every Apply for an unchanged file.
type binKey struct {
	path string
	size int64
	mod  time.Time
}

var (
	binMu    sync.Mutex
	binCache = map[binKey]BinaryInfo{}
)

func (d *Driver) checkKernel(ctx context.Context, path, wantVersion string) error {
	if path == "" {
		return errors.New("realm: Runtime.Kernel.Path is empty")
	}
	probe := d.opts.probeBinary
	if probe == nil {
		probe = CheckBinary
		st, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("realm: kernel binary: %w", err)
		}
		k := binKey{path, st.Size(), st.ModTime()}
		binMu.Lock()
		bi, ok := binCache[k]
		binMu.Unlock()
		if !ok {
			if bi, err = probe(ctx, path); err != nil {
				return err
			}
			binMu.Lock()
			binCache[k] = bi
			binMu.Unlock()
		}
		return bi.Check(wantVersion)
	}
	bi, err := probe(ctx, path)
	if err != nil {
		return err
	}
	return bi.Check(wantVersion)
}
