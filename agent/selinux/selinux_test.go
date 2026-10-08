package selinux

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeEnv is the machine surface with a scripted SELinux mode and tool set. It
// records every command so the tests can assert the exact sequence of each
// path (enabled with semanage, enabled without semanage, disabled, no tools).
type fakeEnv struct {
	mode  string
	tools map[string]bool
	fail  map[string]error
	calls []string
}

func newFakeEnv(mode string, tools ...string) *fakeEnv {
	f := &fakeEnv{mode: mode, tools: map[string]bool{}, fail: map[string]error{}}
	for _, t := range tools {
		f.tools[t] = true
	}
	return f
}

func (f *fakeEnv) SELinux() string { return f.mode }

func (f *fakeEnv) LookPath(file string) string {
	if f.tools[file] {
		return "/usr/sbin/" + file
	}
	return ""
}

func (f *fakeEnv) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	line := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, line)
	if err := f.fail[name]; err != nil {
		return []byte("boom"), err
	}
	return nil, nil
}

// recordingLog captures the messages a path logs.
type recordingLog struct {
	info  []string
	warn  []string
	error []string
}

func (l *recordingLog) Debugf(string, ...any)    {}
func (l *recordingLog) Infof(f string, a ...any) { l.info = append(l.info, fmt.Sprintf(f, a...)) }
func (l *recordingLog) Warnf(f string, a ...any) { l.warn = append(l.warn, fmt.Sprintf(f, a...)) }
func (l *recordingLog) Errorf(f string, a ...any) {
	l.error = append(l.error, fmt.Sprintf(f, a...))
}

// tree is a temporary directory with a file inside it, standing in for the
// kernel install tree.
func tree(t *testing.T) (dir, file string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "kernels")
	if err := os.MkdirAll(filepath.Join(dir, "xray", "0.6.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	file = filepath.Join(dir, "xray", "0.6.0", "W1nCray-xray")
	if err := os.WriteFile(file, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir, file
}

// TestDisabledRunsNothing: a machine with SELinux off needs no label and no
// tool, so the labeler must not run a single command.
func TestDisabledRunsNothing(t *testing.T) {
	dir, _ := tree(t)
	env := newFakeEnv("", "semanage", "restorecon", "chcon")
	log := &recordingLog{}
	l := New(Options{Env: env, Log: log})

	if l.Enabled() {
		t.Fatal("Enabled() = true on a machine with SELinux off")
	}
	if err := l.EnsureBinT(context.Background(), dir); err != nil {
		t.Fatalf("EnsureBinT: %v", err)
	}
	if len(env.calls) != 0 {
		t.Fatalf("commands = %v, want none", env.calls)
	}
	if len(log.warn) != 0 {
		t.Fatalf("warnings = %v, want none", log.warn)
	}
}

// TestPersistentLabelWithSemanage: with semanage present the label is made
// persistent (one fcontext rule for the whole tree) and applied with
// restorecon.
func TestPersistentLabelWithSemanage(t *testing.T) {
	dir, _ := tree(t)
	env := newFakeEnv(ModeEnforcing, "semanage", "restorecon")
	l := New(Options{Env: env, Log: &recordingLog{}})

	if !l.Enabled() {
		t.Fatal("Enabled() = false with SELinux enforcing")
	}
	if err := l.EnsureBinT(context.Background(), dir); err != nil {
		t.Fatalf("EnsureBinT: %v", err)
	}
	want := []string{
		"/usr/sbin/semanage fcontext -a -t bin_t " + dir + "(/.*)?",
		"/usr/sbin/restorecon -F -R " + dir,
	}
	if !equal(env.calls, want) {
		t.Fatalf("commands = %v, want %v", env.calls, want)
	}

	// A second call must be a no-op: the paths are remembered per process.
	if err := l.EnsureBinT(context.Background(), dir); err != nil {
		t.Fatalf("second EnsureBinT: %v", err)
	}
	if !equal(env.calls, want) {
		t.Fatalf("commands after the second call = %v, want %v", env.calls, want)
	}
}

// TestPersistentLabelOnAFile: the supervisor labels one binary, not a tree, so
// the fcontext rule and restorecon name that file exactly.
func TestPersistentLabelOnAFile(t *testing.T) {
	_, file := tree(t)
	env := newFakeEnv(ModePermissive, "semanage", "restorecon")
	l := New(Options{Env: env, Log: &recordingLog{}})
	if err := l.EnsureBinT(context.Background(), file); err != nil {
		t.Fatalf("EnsureBinT: %v", err)
	}
	want := []string{
		"/usr/sbin/semanage fcontext -a -t bin_t " + file,
		"/usr/sbin/restorecon -F " + file,
	}
	if !equal(env.calls, want) {
		t.Fatalf("commands = %v, want %v", env.calls, want)
	}
}

// TestChconFallback: a machine without semanage (policycoreutils-python-utils
// is not part of a minimal install) still gets the label, with chcon, on every
// install and start.
func TestChconFallback(t *testing.T) {
	dir, _ := tree(t)
	outside := filepath.Join(t.TempDir(), "W1nCray-xray")
	if err := os.WriteFile(outside, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	env := newFakeEnv(ModeEnforcing, "chcon")
	l := New(Options{Env: env, Log: &recordingLog{}})

	if err := l.EnsureBinT(context.Background(), dir); err != nil {
		t.Fatalf("EnsureBinT(dir): %v", err)
	}
	if err := l.EnsureBinT(context.Background(), outside); err != nil {
		t.Fatalf("EnsureBinT(file): %v", err)
	}
	want := []string{
		"/usr/sbin/chcon -R -t bin_t " + dir,
		"/usr/sbin/chcon -t bin_t " + outside,
	}
	if !equal(env.calls, want) {
		t.Fatalf("commands = %v, want %v", env.calls, want)
	}
}

// TestBinaryInsideALabelledTreeIsSkipped: the installer labels the whole kernel
// tree, so the supervisor must not add a second, per-version fcontext rule for
// every binary it starts (they would pile up across upgrades).
func TestBinaryInsideALabelledTreeIsSkipped(t *testing.T) {
	dir, file := tree(t)
	env := newFakeEnv(ModeEnforcing, "semanage", "restorecon")
	l := New(Options{Env: env, Log: &recordingLog{}})

	if err := l.EnsureBinT(context.Background(), dir); err != nil {
		t.Fatalf("EnsureBinT(dir): %v", err)
	}
	if err := l.EnsureBinT(context.Background(), file); err != nil {
		t.Fatalf("EnsureBinT(file): %v", err)
	}
	want := []string{
		"/usr/sbin/semanage fcontext -a -t bin_t " + dir + "(/.*)?",
		"/usr/sbin/restorecon -F -R " + dir,
	}
	if !equal(env.calls, want) {
		t.Fatalf("commands = %v, want %v", env.calls, want)
	}
}

// TestSemanageFailureFallsBackToChcon: a tool that is present but refuses must
// not fail the installation; chcon still applies the label.
func TestSemanageFailureFallsBackToChcon(t *testing.T) {
	dir, _ := tree(t)
	env := newFakeEnv(ModeEnforcing, "semanage", "restorecon", "chcon")
	env.fail["/usr/sbin/semanage"] = errors.New("exit status 1")
	log := &recordingLog{}
	l := New(Options{Env: env, Log: log})

	if err := l.EnsureBinT(context.Background(), dir); err != nil {
		t.Fatalf("EnsureBinT: %v", err)
	}
	want := []string{
		"/usr/sbin/semanage fcontext -a -t bin_t " + dir + "(/.*)?",
		"/usr/sbin/chcon -R -t bin_t " + dir,
	}
	if !equal(env.calls, want) {
		t.Fatalf("commands = %v, want %v", env.calls, want)
	}
	if len(log.warn) == 0 {
		t.Fatal("a failed persistent label must be reported")
	}
}

// TestMissingToolsWarnOnly: SELinux enforcing and neither semanage nor chcon
// available is a machine we cannot fix. It must not turn into a failed
// installation — the service health check reports the real problem.
func TestMissingToolsWarnOnly(t *testing.T) {
	dir, _ := tree(t)
	env := newFakeEnv(ModeEnforcing)
	log := &recordingLog{}
	l := New(Options{Env: env, Log: log})

	if err := l.EnsureBinT(context.Background(), dir); err != nil {
		t.Fatalf("EnsureBinT: %v", err)
	}
	if len(env.calls) != 0 {
		t.Fatalf("commands = %v, want none", env.calls)
	}
	if len(log.warn) != 1 || !strings.Contains(log.warn[0], "semanage") {
		t.Fatalf("warnings = %v, want one naming the missing tools", log.warn)
	}
}

// TestChconFailureIsReported: when a tool that exists fails and there is no
// fallback, the caller must see it instead of a silently unlabelled kernel.
func TestChconFailureIsReported(t *testing.T) {
	dir, _ := tree(t)
	env := newFakeEnv(ModeEnforcing, "chcon")
	env.fail["/usr/sbin/chcon"] = errors.New("exit status 1")
	l := New(Options{Env: env, Log: &recordingLog{}})

	err := l.EnsureBinT(context.Background(), dir)
	if err == nil || !strings.Contains(err.Error(), "chcon") {
		t.Fatalf("err = %v, want a chcon failure", err)
	}
	// A failed label must not be remembered as done.
	env.fail = map[string]error{}
	if err := l.EnsureBinT(context.Background(), dir); err != nil {
		t.Fatalf("retry after a failure: %v", err)
	}
}

// TestEmptyPathIsANoOp keeps a caller that has no binary yet from running a
// tool against "".
func TestEmptyPathIsANoOp(t *testing.T) {
	env := newFakeEnv(ModeEnforcing, "semanage", "restorecon", "chcon")
	l := New(Options{Env: env, Log: &recordingLog{}})
	if err := l.EnsureBinT(context.Background(), ""); err != nil {
		t.Fatalf("EnsureBinT(\"\"): %v", err)
	}
	if len(env.calls) != 0 {
		t.Fatalf("commands = %v, want none", env.calls)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
