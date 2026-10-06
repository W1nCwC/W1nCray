package kernelx

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/supervisor"
)

// TestMatchVersionMapsOnlyRealVersionDirectories covers the path mapping that
// decides "in use": anything outside <root>/<name>/<version>/ must not match,
// including traversal attempts.
func TestMatchVersionMapsOnlyRealVersionDirectories(t *testing.T) {
	root := filepath.Join(string(filepath.Separator)+"srv", "w1ncray", "kernels")
	cases := []struct {
		name string
		bin  string
		want string
		ok   bool
	}{
		{"main binary", filepath.Join(root, "gost", "1.0.0", "gost"), "1.0.0", true},
		{"nested file", filepath.Join(root, "gost", "2.0.0", "bin", "gost"), "2.0.0", true},
		{"version directory itself", filepath.Join(root, "gost", "1.0.0"), "", false},
		{"kernel directory", filepath.Join(root, "gost"), "", false},
		{"staging directory", filepath.Join(root, "gost", ".partial", "gost"), "", false},
		{"other kernel", filepath.Join(root, "realm", "1.0.0", "realm"), "", false},
		{"traversal inside", filepath.Join(root, "gost", "..", "evil"), "", false},
		{"traversal above", filepath.Join(root, "..", "evil"), "", false},
		{"outside the root", filepath.Join(string(filepath.Separator)+"etc", "passwd"), "", false},
		{"empty", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := MatchVersion(root, "gost", tc.bin)
			if ok != tc.ok || got != tc.want {
				t.Errorf("MatchVersion(%q) = (%q, %v), want (%q, %v)", tc.bin, got, ok, tc.want, tc.ok)
			}
		})
	}
}

// writePIDRecord writes one supervisor pid file. The file name is the escaped
// supervisor id; the id inside the record is what the reader trusts.
func writePIDRecord(t *testing.T, dir, file, id string, pid int, exe string) {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"id": id, "pid": pid, "path": exe, "exe": exe, "started": time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, file), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestRunningBinarySkipsRecordsItCannotTrust covers the pid-reuse defence with
// records that must never be reported: a dead pid, another kernel's process,
// the agent's own pid and an unreadable file.
func TestRunningBinarySkipsRecordsItCannotTrust(t *testing.T) {
	if got, err := RunningBinary(filepath.Join(t.TempDir(), "missing"), "gost"); err != nil || got != nil {
		t.Fatalf("missing pid dir = (%v, %v), want (nil, nil)", got, err)
	}

	dir := t.TempDir()
	const deadPID = 1 << 30 // above every realistic pid_max
	writePIDRecord(t, dir, "gost-main.pid", "gost/main", deadPID, "/srv/kernels/gost/1.0.0/gost")
	writePIDRecord(t, dir, "realm-x.pid", "realm/x", os.Getpid(), "/srv/kernels/realm/1.0.0/realm")
	writePIDRecord(t, dir, "gost-self.pid", "gost/main", os.Getpid(), "/srv/kernels/gost/2.0.0/gost")
	// A file that is not a record at all is skipped, never fatal.
	if err := os.WriteFile(filepath.Join(dir, "garbage.pid"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := RunningBinary(dir, "gost")
	if err != nil {
		t.Fatalf("RunningBinary: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("RunningBinary = %v, want nothing", got)
	}
}

// TestKernelxHelperProcess is not a test: it is the sleeping child the
// live-process check re-executes itself as.
func TestKernelxHelperProcess(t *testing.T) {
	if os.Getenv("W1NCRAY_KERNELX_HELPER") != "1" {
		return
	}
	time.Sleep(30 * time.Second)
	os.Exit(0)
}

// TestRunningBinaryVerifiesTheLiveProcess covers the positive path and the
// reuse defence: a live pid is only reported when it still runs the recorded
// binary.
func TestRunningBinaryVerifiesTheLiveProcess(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process identity is only verifiable where /proc exists")
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=TestKernelxHelperProcess")
	cmd.Env = append(os.Environ(), "W1NCRAY_KERNELX_HELPER=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	exe, ok := supervisor.ProcExe(cmd.Process.Pid)
	if !ok {
		t.Skip("cannot read /proc/<pid>/exe")
	}

	writePIDRecord(t, dir, "gost-main.pid", "gost/main", cmd.Process.Pid, exe)
	got, err := RunningBinary(dir, "gost")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != exe {
		t.Fatalf("RunningBinary = %v, want [%s]", got, exe)
	}

	// The pid is alive but runs something else: a reused pid, never trusted.
	writePIDRecord(t, dir, "gost-main.pid", "gost/main", cmd.Process.Pid, "/usr/bin/something-else")
	got, err = RunningBinary(dir, "gost")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("RunningBinary trusted a reused pid: %v", got)
	}
}

// TestRunningVersionExactnessFollowsThePlatform pins the "do not pretend"
// contract: exact is only true where process identity can be verified, and a
// pid directory is required at all.
func TestRunningVersionExactnessFollowsThePlatform(t *testing.T) {
	dir := t.TempDir()
	e, err := New(Options{Dir: dir, PIDDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	v, exact := e.RunningVersion("gost")
	if v != "" {
		t.Errorf("RunningVersion = %q, want empty (nothing is running)", v)
	}
	_, canVerify := supervisor.ProcExe(os.Getpid())
	if exact != canVerify {
		t.Errorf("exact = %v, want %v on %s", exact, canVerify, runtime.GOOS)
	}

	// No pid directory: the answer can never be exact.
	noPid, err := New(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if _, exact := noPid.RunningVersion("gost"); exact {
		t.Error("without a pid directory the answer must not claim to be exact")
	}
}

// TestNewKeepsTheKernelLayoutUsedForMatching guards the <Dir>/kernels layer:
// the version match must be computed against the directory the installer
// really uses.
func TestNewKeepsTheKernelLayoutUsedForMatching(t *testing.T) {
	dir := t.TempDir()
	e, err := New(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "kernels", "gost", "3.3.0", "gost")
	if v, ok := MatchVersion(e.kernelsRoot, "gost", bin); !ok || v != "3.3.0" {
		t.Errorf("MatchVersion under the installer layout = (%q, %v)", v, ok)
	}
}
