//go:build linux

package selfupdate

import (
	"os"
	"strconv"
	"strings"
)

// processExecutable returns the executable pid runs from, with the kernel's
// " (deleted)" marker removed, and whether it could be determined at all.
//
// /proc/<pid>/exe is the authoritative source: it is the file the process was
// exec'd from, so a pid the kernel has recycled to an unrelated program can
// never be mistaken for the agent (unlike the process name, which any program
// can carry). When the link cannot be read — a race with the process exiting,
// or a /proc the caller cannot read — the process's own argv[0] is the
// fallback: it is the path the program was started with, which is enough to
// compare against the known agent paths. Anything that is not an absolute path
// is refused rather than guessed at.
func processExecutable(pid int) (string, bool) {
	if pid <= 0 {
		return "", false
	}
	base := "/proc/" + strconv.Itoa(pid)
	if p, err := os.Readlink(base + "/exe"); err == nil {
		return strings.TrimSuffix(p, deletedSuffix), true
	}
	b, err := os.ReadFile(base + "/cmdline")
	if err != nil {
		return "", false
	}
	arg0 := string(b)
	if i := strings.IndexByte(arg0, 0); i >= 0 {
		arg0 = arg0[:i]
	}
	if !strings.HasPrefix(arg0, "/") {
		return "", false
	}
	return arg0, true
}
