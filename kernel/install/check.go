package install

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/W1nCwC/W1nCray/kernel/manifest"
)

// CheckFunc runs a freshly installed binary and returns the version it
// reports. It exists so tests (and cross-platform tooling) can replace the
// real execution; the default is DefaultCheck for the kernel's Run block.
type CheckFunc func(path string) (version string, err error)

var defaultVersionRe = regexp.MustCompile(`[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z][0-9A-Za-z.+-]*)?`)

// DefaultCheck returns the CheckFunc that executes "<binary> <version_cmd...>"
// (argv array, no shell, 10 s timeout, minimal environment) and extracts the
// version from stdout+stderr with run.version_regex or, by default, the first
// dotted number sequence.
func DefaultCheck(run manifest.Run) CheckFunc {
	return func(bin string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, run.VersionCmd...)
		cmd.Dir = filepath.Dir(bin)
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "HOME=/nonexistent"}
		var out limitedBuffer
		out.max = 64 << 10
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		text := out.String()
		if ctx.Err() != nil {
			return "", fmt.Errorf("timed out running %s", filepath.Base(bin))
		}
		v := extractVersion(run, text)
		if v == "" {
			if err != nil {
				return "", fmt.Errorf("running %s: %w (output: %q)", filepath.Base(bin), err, trimForLog(text))
			}
			return "", fmt.Errorf("no version found in output %q", trimForLog(text))
		}
		// A non-zero exit with a parsable version is accepted: several
		// kernels print their banner and exit 1 on "-v".
		return v, nil
	}
}

func extractVersion(run manifest.Run, text string) string {
	re := defaultVersionRe
	if run.VersionRegex != "" {
		r, err := regexp.Compile(run.VersionRegex)
		if err != nil {
			return ""
		}
		m := r.FindStringSubmatch(text)
		if len(m) < 2 {
			return ""
		}
		return m[1]
	}
	return re.FindString(text)
}

func trimForLog(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

// limitedBuffer keeps at most max bytes and silently drops the rest.
type limitedBuffer struct {
	buf bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.max - l.buf.Len(); room > 0 {
		if len(p) > room {
			l.buf.Write(p[:room])
		} else {
			l.buf.Write(p)
		}
	}
	return len(p), nil
}

func (l *limitedBuffer) String() string { return l.buf.String() }
