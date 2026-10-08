package kernelx

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/selinux"
)

// fakeSelinuxEnv is a scripted SELinux machine: a mode and a tool set. It
// records every command the labeler runs.
type fakeSelinuxEnv struct {
	mode  string
	tools map[string]bool
	calls []string
}

func (f *fakeSelinuxEnv) SELinux() string { return f.mode }

func (f *fakeSelinuxEnv) LookPath(file string) string {
	if f.tools[file] {
		return "/usr/sbin/" + file
	}
	return ""
}

func (f *fakeSelinuxEnv) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	return nil, nil
}

// TestLabelKernelsLabelsTheKernelTree: the ensurer owns the kernel directory, so
// it is what turns the whole tree into bin_t — one persistent fcontext rule
// that survives every version install, upgrade and rollback.
func TestLabelKernelsLabelsTheKernelTree(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "kernels")
	env := &fakeSelinuxEnv{mode: selinux.ModeEnforcing, tools: map[string]bool{"semanage": true, "restorecon": true}}
	e, err := New(Options{Dir: base, Labeler: selinux.New(selinux.Options{Env: env})})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.LabelKernels(context.Background()); err != nil {
		t.Fatalf("LabelKernels: %v", err)
	}
	tree := filepath.Join(base, "kernels")
	want := []string{
		"/usr/sbin/semanage fcontext -a -t bin_t " + tree + "(/.*)?",
		"/usr/sbin/restorecon -F -R " + tree,
	}
	if len(env.calls) != len(want) {
		t.Fatalf("commands = %v, want %v", env.calls, want)
	}
	for i := range want {
		if env.calls[i] != want[i] {
			t.Fatalf("commands = %v, want %v", env.calls, want)
		}
	}
}

// TestLabelKernelsWithoutLabelerIsANoOp: an ensurer built without a labeler
// (tests, non-Linux) must not fail.
func TestLabelKernelsWithoutLabelerIsANoOp(t *testing.T) {
	e, err := New(Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.LabelKernels(context.Background()); err != nil {
		t.Fatalf("LabelKernels: %v", err)
	}
}
