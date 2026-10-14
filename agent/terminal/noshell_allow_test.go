// This file is the reverse assertion behind the noshell whitelist (design
// section 3.8 rule 4). It runs in the whitelisted package itself, so a change
// to agent/supervisor/noshell_test.go cannot quietly widen the exception:
//
//	(a) agent/terminal really does start a shell (the whitelist is not a dead
//	    entry that would let the constraint rot),
//	(b) every entry of the whitelist is recorded in the security-model section
//	    of docs/AGENT.md, with the package path written out (so "changed the
//	    code, forgot the document" fails the build), and
//	(c) the whitelist is exactly what this file expects: one package.

package terminal

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/supervisor"
)

// docSecurityModel is the section of docs/AGENT.md that records the intentional
// security-model change (D8). Every whitelisted package must be named there.
const docSecurityModel = "安全模型变更记录"

// shellInvocation matches the call that makes the whitelist necessary: the
// shell is started from a variable, which is exactly what the noshell detector
// refuses everywhere else.
var shellInvocation = regexp.MustCompile(`exec\.Command\(\s*shell\b`)

// ptyInvocation matches a PTY start, the other capability that must not spread.
var ptyInvocation = regexp.MustCompile(`\bpty\.(Start|StartWithSize|StartWithAttrs|Open)\(`)

// TestWhitelistIsNotDead asserts (a): this package starts a shell and a PTY,
// so the exception is real and reviewable.
func TestWhitelistIsNotDead(t *testing.T) {
	shell, pty := 0, 0
	files := nonTestFiles(t, ".")
	for _, path := range files {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		shell += len(shellInvocation.FindAll(b, -1))
		pty += len(ptyInvocation.FindAll(b, -1))
	}
	if shell == 0 {
		t.Errorf("no exec.Command(shell, ...) in agent/terminal: the whitelist entry is dead and must be removed")
	}
	if pty == 0 {
		t.Errorf("no pty.Start* in agent/terminal: the package does not actually create a terminal")
	}
	t.Logf("agent/terminal: %d shell invocation(s) and %d PTY start(s) across %d file(s)", shell, pty, len(files))
}

// TestNoPackageOutsideTheWhitelistStartsAShell asserts the other direction from
// inside the whitelisted package: a scan of agent/ finds a shell call in
// exactly the packages the supervisor whitelist names.
func TestNoPackageOutsideTheWhitelistStartsAShell(t *testing.T) {
	root := filepath.Join("..") // agent/
	found := map[string]int{}
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
		if !shellInvocation.Match(b) && !ptyInvocation.Match(b) {
			return nil
		}
		pkg := packageKey(root, path)
		found[pkg]++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) == 0 {
		t.Skip("agent sources not present (bare test binary)")
	}
	for pkg := range found {
		if _, ok := supervisor.AllowedShellPackages[pkg]; !ok {
			t.Errorf("package %s starts a shell or a PTY but is not on the whitelist", pkg)
		}
	}
	for pkg := range supervisor.AllowedShellPackages {
		if found[pkg] == 0 {
			t.Errorf("whitelisted package %s has no shell or PTY call: the entry is dead", pkg)
		}
	}
}

// TestWhitelistMatchesDocumentation asserts (b): every whitelisted package is
// named in the security-model section of docs/AGENT.md. The document is the
// deliberate record of the change; without it the exception is undocumented.
func TestWhitelistMatchesDocumentation(t *testing.T) {
	doc := filepath.Join("..", "..", "docs", "AGENT.md")
	b, err := os.ReadFile(doc)
	if err != nil {
		t.Skipf("%s is not readable (%v): the documentation check needs the repository", doc, err)
	}
	section := securityModelSection(t, string(b))
	if section == "" {
		t.Fatalf("docs/AGENT.md has no %q section: the intentional terminal capability must be recorded there", docSecurityModel)
	}
	if !strings.Contains(section, "Terminal.Enabled") || !strings.Contains(section, "--noterminal") {
		t.Errorf("the %q section must state that the terminal is a local switch (Terminal.Enabled, --noterminal)", docSecurityModel)
	}
	if !strings.Contains(section, "agent/terminal") {
		t.Errorf("the %q section must name agent/terminal", docSecurityModel)
	}
	for pkg := range supervisor.AllowedShellPackages {
		if !strings.Contains(section, pkg) {
			t.Errorf("whitelisted package %q is not named in the %q section of docs/AGENT.md", pkg, docSecurityModel)
		}
	}
}

// TestWhitelistIsExactlyOnePackage asserts (c): the exception is one package,
// so widening it is always a visible change to this test.
func TestWhitelistIsExactlyOnePackage(t *testing.T) {
	keys := make([]string, 0, len(supervisor.AllowedShellPackages))
	for k, reason := range supervisor.AllowedShellPackages {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("whitelist entry %q has no written reason", k)
		}
		if !strings.Contains(reason, "docs/AGENT.md") {
			t.Errorf("whitelist entry %q must point at docs/AGENT.md", k)
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := []string{"agent/terminal"}
	if len(keys) != len(want) || (len(keys) > 0 && keys[0] != want[0]) {
		t.Fatalf("AllowedShellPackages = %v, want %v: widening the exception requires updating this test and docs/AGENT.md", keys, want)
	}
}

// securityModelSection returns the text of the "## N 安全模型变更记录" section
// of AGENT.md (up to the next level-2 heading).
func securityModelSection(t *testing.T, doc string) string {
	t.Helper()
	lines := strings.Split(doc, "\n")
	start := -1
	for i, l := range lines {
		if strings.HasPrefix(l, "## ") && strings.Contains(l, docSecurityModel) {
			start = i
			break
		}
	}
	if start < 0 {
		return ""
	}
	var b strings.Builder
	for _, l := range lines[start:] {
		if b.Len() > 0 && strings.HasPrefix(l, "## ") {
			break
		}
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return b.String()
}

// nonTestFiles lists the non-test .go files directly under dir.
func nonTestFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	if len(out) == 0 {
		t.Fatal("no source files found")
	}
	return out
}

// packageKey turns a walked path into the "agent/<pkg>" whitelist key.
func packageKey(root, path string) string {
	rel := filepath.ToSlash(strings.TrimPrefix(filepath.Clean(path), filepath.Clean(root)+string(filepath.Separator)))
	dir := filepath.ToSlash(filepath.Dir(rel))
	if dir == "." {
		return "agent"
	}
	return "agent/" + dir
}
