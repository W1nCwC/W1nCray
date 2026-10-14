package supervisor

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestNoShellInvocationInAgentCode is the static check behind acceptance A4:
// no non-test code under agent/ may start a shell or an interpreter with a
// command string, except the packages named in AllowedShellPackages. External
// commands must be argv arrays run directly.
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
		// pty.Start / pty.Open must not spread beyond the whitelisted package:
		// a terminal is the one thing allowed to hold a PTY.
		regexp.MustCompile(`\bpty\.(Start|StartWithSize|StartWithAttrs|Open)\(`),
	}
	// The exec.Command argument rule: in a non-whitelisted package the first
	// argument must be a non-empty string literal or a known safe constant,
	// because exec.Command(shellVar, ...) would slip past the literal patterns
	// above. Anything the checker cannot decide statically is reported unless
	// the file carries an explicit //nolint:noshell exemption.
	safeConstArgs := map[string]bool{
		"os.Args[0]": true, // the test binary re-executing itself
	}
	exemptions := 0
	checked := 0
	hits := map[string]int{}

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
		pkg := packagePath(root, path)
		if reason, allowed := AllowedShellPackages[pkg]; allowed {
			if !strings.Contains(reason, "docs/AGENT.md") {
				t.Errorf("%s: the whitelist reason must point at docs/AGENT.md, got %q", pkg, reason)
			}
			hits[pkg]++
			return nil
		}
		src := string(b)
		for _, re := range patterns {
			if loc := re.FindIndex(b); loc != nil {
				line := 1 + strings.Count(src[:loc[0]], "\n")
				t.Errorf("%s:%d: shell invocation %q", path, line, re.String())
			}
		}
		// The first-argument rule, parsed rather than grepped so a call split
		// over several lines is still seen.
		if strings.Contains(src, "os/exec") {
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, b, parser.ParseComments)
			if perr != nil {
				return nil // a file that does not parse is the compiler's job
			}
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				name := calleeName(call)
				if name != "exec.Command" && name != "exec.CommandContext" {
					return true
				}
				argIdx := 0
				if name == "exec.CommandContext" {
					argIdx = 1
				}
				if len(call.Args) <= argIdx {
					return true
				}
				arg := call.Args[argIdx]
				pos := fset.Position(arg.Pos())
				if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if v, err := strconv.Unquote(lit.Value); err == nil && v != "" {
						return true
					}
					t.Errorf("%s:%d: exec.Command with an empty program name", path, pos.Line)
					return true
				}
				if safeConstArgs[exprString(arg)] {
					return true
				}
				if exemptionAt(fset, f, src, call, arg) {
					exemptions++
					return true
				}
				t.Errorf("%s:%d: exec.Command program name %s is not a string literal or a known safe constant; use a literal or add //nolint:noshell with a reason", path, pos.Line, exprString(arg))
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 10 {
		t.Skipf("scanned only %d files; agent sources not present (bare test binary)", checked)
	}
	if len(hits) != len(AllowedShellPackages) {
		t.Errorf("only %d of %d whitelisted packages contain a shell call: %v", len(hits), len(AllowedShellPackages), hits)
	}
	t.Logf("noshell: scanned %d files, %d whitelisted package(s) with shell calls, %d explicit //nolint:noshell exemption(s)", checked, len(hits), exemptions)
}

// packagePath turns a walked path into the "agent/<pkg>" key of the whitelist.
func packagePath(root, path string) string {
	rel := filepath.ToSlash(strings.TrimPrefix(filepath.Clean(path), filepath.Clean(root)+string(filepath.Separator)))
	dir := filepath.ToSlash(filepath.Dir(rel))
	if dir == "." {
		return "agent"
	}
	return "agent/" + dir
}

// calleeName renders "pkg.Func" for a package-qualified call.
func calleeName(call *ast.CallExpr) string {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	return ident.Name + "." + sel.Sel.Name
}

// exprString renders the small expression forms the checker recognises.
func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	case *ast.IndexExpr:
		return exprString(v.X) + "[]"
	default:
		return "?"
	}
}

// commentText is the raw text of a comment group. It uses the individual
// comments rather than CommentGroup.Text(), which strips the "//" markers and
// would hide the //nolint:noshell directive.
func commentText(cg *ast.CommentGroup) string {
	var b strings.Builder
	for _, c := range cg.List {
		b.WriteString(c.Text)
		b.WriteByte('\n')
	}
	return b.String()
}

// fileHasExemption reports whether the file carries a //nolint:noshell marker
// anywhere (a file-level exemption must still be visible in review).
func fileHasExemption(fset *token.FileSet, f *ast.File) bool {
	for _, cg := range f.Comments {
		if strings.Contains(commentText(cg), "nolint:noshell") {
			return true
		}
	}
	return false
}

// lineHasExemption reports whether the given 1-based line carries the marker.
func lineHasExemption(src string, line int) bool {
	lines := strings.Split(src, "\n")
	if line < 1 || line > len(lines) {
		return false
	}
	return strings.Contains(lines[line-1], "nolint:noshell")
}

// exemptionAt reports whether a //nolint:noshell marker covers this call: a
// file-level marker, a line marker anywhere between the call's start and its
// program argument (a comment written on the line above a multi-line call), or
// a comment node in that range.
func exemptionAt(fset *token.FileSet, f *ast.File, src string, call *ast.CallExpr, arg ast.Expr) bool {
	if fileHasExemption(fset, f) {
		return true
	}
	from := fset.Position(call.Pos()).Line
	to := fset.Position(arg.Pos()).Line
	lines := strings.Split(src, "\n")
	for i := from; i <= to && i <= len(lines); i++ {
		if i >= 1 && strings.Contains(lines[i-1], "nolint:noshell") {
			return true
		}
	}
	for _, cg := range f.Comments {
		cl := fset.Position(cg.Pos()).Line
		if cl >= from && cl <= to && strings.Contains(commentText(cg), "nolint:noshell") {
			return true
		}
	}
	return false
}

// The detector itself must catch the patterns it claims to, including the new
// first-argument rule.
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
	// The pty pattern must catch a PTY outside agent/terminal.
	ptyRe := regexp.MustCompile(`\bpty\.(Start|StartWithSize|StartWithAttrs|Open)\(`)
	for _, bad := range []string{`pty.Start(cmd)`, `pty.StartWithSize(cmd, ws)`, `pty.Open()`} {
		if !ptyRe.MatchString(bad) {
			t.Errorf("pty detector misses %q", bad)
		}
	}
	if ptyRe.MatchString("spty.Start(") {
		t.Error("pty detector matches a longer identifier")
	}
}

// TestFirstArgumentRuleCatchesAVariableProgram is the self-check for the new
// rule: a fake file that runs a shell through a variable is reported, and the
// same file with an explicit exemption is not.
func TestFirstArgumentRuleCatchesAVariableProgram(t *testing.T) {
	bad := `package fake

import "os/exec"

func run(shell string) *exec.Cmd {
	return exec.Command(shell, "-i")
}
`
	good := `package fake

import "os/exec"

func run(shell string) *exec.Cmd {
	return exec.Command(shell, "-i") //nolint:noshell: the caller guarantees a literal path
}
`
	goodAbove := `package fake

import "os/exec"

func run(shell string) *exec.Cmd {
	//nolint:noshell -- the caller guarantees a literal path.
	return exec.Command(shell, "-i")
}
`
	report := func(src string) []string {
		var out []string
		checkExecProgramArg(t, src, &out)
		return out
	}
	if got := report(bad); len(got) != 1 {
		t.Errorf("the variable-program rule reported %v, want one hit", got)
	}
	if got := report(good); len(got) != 0 {
		t.Errorf("a same-line //nolint:noshell exemption was not honoured: %v", got)
	}
	if got := report(goodAbove); len(got) != 0 {
		t.Errorf("a comment-above //nolint:noshell exemption was not honoured: %v", got)
		t.Logf("debug: comments=%v", debugComments(goodAbove))
	}
	literal := `package fake

import "os/exec"

func run() *exec.Cmd {
	return exec.Command("/bin/true")
}
`
	if got := report(literal); len(got) != 0 {
		t.Errorf("a literal program name was reported: %v", got)
	}
}

// checkExecProgramArg runs the first-argument rule over one source string and
// appends a message per hit. It is the shared core of the file scan and the
// self-check, so the self-check cannot drift from the real rule.
func checkExecProgramArg(t *testing.T, src string, out *[]string) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fake.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := calleeName(call)
		if name != "exec.Command" && name != "exec.CommandContext" {
			return true
		}
		argIdx := 0
		if name == "exec.CommandContext" {
			argIdx = 1
		}
		if len(call.Args) <= argIdx {
			return true
		}
		arg := call.Args[argIdx]
		if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if v, uerr := strconv.Unquote(lit.Value); uerr == nil && v != "" {
				return true
			}
		}
		if exemptionAt(fset, f, src, call, arg) {
			return true
		}
		*out = append(*out, exprString(arg))
		return true
	})
}

// debugComments lists the comment groups of a source string with their line
// numbers; it is only used by a failing self-check.
func debugComments(src string) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fake.go", src, parser.ParseComments)
	if err != nil {
		return []string{"parse: " + err.Error()}
	}
	var out []string
	for _, cg := range f.Comments {
		out = append(out, strconv.Itoa(fset.Position(cg.Pos()).Line)+":"+strconv.Quote(commentText(cg)))
	}
	return out
}

// TestWhitelistIsReviewedAndSorted keeps the whitelist readable: every reason
// is present and the keys are printed sorted for the log.
func TestWhitelistIsReviewedAndSorted(t *testing.T) {
	if len(AllowedShellPackages) == 0 {
		t.Fatal("the whitelist is empty: agent/terminal must be listed")
	}
	keys := make([]string, 0, len(AllowedShellPackages))
	for k, v := range AllowedShellPackages {
		if strings.TrimSpace(v) == "" {
			t.Errorf("whitelist entry %q has no reason", k)
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	t.Logf("packages allowed to start a shell: %v", keys)
}
