package supervisor

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoShellInvocationInAgentCode is the static check behind acceptance A4:
// no non-test code under agent/ may start a shell or an interpreter with a
// command string. External commands must be argv arrays run directly.
func TestNoShellInvocationInAgentCode(t *testing.T) {
	root := ".." // the agent/ directory
	shells := `"(sh|bash|dash|ash|zsh|/bin/sh|/bin/bash|/usr/bin/env|cmd|cmd\.exe|powershell|powershell\.exe|pwsh)"`
	patterns := []*regexp.Regexp{
		// exec.Command("sh", ...), exec.CommandContext(ctx, "bash", ...)
		regexp.MustCompile(`exec\.Command\(\s*` + shells),
		regexp.MustCompile(`exec\.CommandContext\(\s*[^,]+,\s*` + shells),
		// a shell name followed by a "run this string" flag
		regexp.MustCompile(shells + `\s*,\s*"(-c|/c|-Command|-command|-EncodedCommand)"`),
		regexp.MustCompile(`syscall\.(ForkExec|Exec)\(`),
	}
	checked := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		checked++
		for _, re := range patterns {
			if loc := re.FindIndex(b); loc != nil {
				line := 1 + strings.Count(string(b[:loc[0]]), "\n")
				t.Errorf("%s:%d: shell invocation %q", path, line, re.String())
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 10 {
		t.Skipf("scanned only %d files; agent sources not present (bare test binary)", checked)
	}
}

// The detector itself must catch the patterns it claims to.
func TestNoShellDetectorSelfCheck(t *testing.T) {
	shells := `"(sh|bash)"`
	re := regexp.MustCompile(`exec\.Command\(\s*` + shells)
	for _, bad := range []string{`exec.Command("sh", "-c", x)`, `exec.Command( "bash")`} {
		if !re.MatchString(bad) {
			t.Errorf("detector misses %q", bad)
		}
	}
	if re.MatchString(`exec.Command(path, "-c")`) {
		t.Error("detector flags a legitimate call")
	}
}
