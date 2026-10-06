package supervisor

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// ---- helper process (re-entry of the test binary) -----------------------

// TestHelperProcess is not a test: when W1NC_HELPER is set the test binary
// acts as the supervised child, so the supervisor is exercised with a real
// process on every platform.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("W1NC_HELPER") == "" {
		return
	}
	helperMain()
}

// blockForever parks the helper. A pending timer keeps the runtime's deadlock
// detector quiet (a bare empty select in a test binary can abort with exit 2).
func blockForever() {
	for {
		time.Sleep(time.Hour)
	}
}

func helperMain() {
	fmt.Printf("START %d %d\n", time.Now().UnixNano(), os.Getpid())
	switch os.Getenv("W1NC_MODE") {
	case "sleep":
		blockForever()
	case "exit":
		ms, _ := strconv.Atoi(os.Getenv("W1NC_RUN_MS"))
		time.Sleep(time.Duration(ms) * time.Millisecond)
		code, _ := strconv.Atoi(os.Getenv("W1NC_CODE"))
		os.Exit(code)
	case "args":
		for i, a := range os.Args[1:] {
			fmt.Printf("ARG%d=%s\n", i, a)
		}
		blockForever()
	case "env":
		fmt.Printf("LEAK=%q\n", os.Getenv("LEAK_ME"))
		fmt.Printf("MINE=%q\n", os.Getenv("W1NC_MINE"))
		fmt.Printf("HASPATH=%v\n", os.Getenv("PATH") != "")
		blockForever()
	case "cwd":
		wd, _ := os.Getwd()
		fmt.Printf("CWD=%s\n", wd)
		blockForever()
	case "noisy":
		line := strings.Repeat("x", 99)
		n, _ := strconv.Atoi(os.Getenv("W1NC_LINES"))
		for i := 0; i < n; i++ {
			if i%2 == 0 {
				fmt.Fprintln(os.Stdout, line)
			} else {
				fmt.Fprintln(os.Stderr, line)
			}
		}
		blockForever()
	default:
		helperUnix()
	}
	os.Exit(0)
}

// ---- test plumbing -------------------------------------------------------

func exePath(t *testing.T) string {
	t.Helper()
	p, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

var testDirs sync.Map // *testing.T -> string

// testDir returns a per-test directory. newSup creates it before registering
// its Shutdown cleanup, so Shutdown runs first and the directory (which holds
// open log files on Windows) can then be removed.
func testDir(t *testing.T) string {
	if d, ok := testDirs.Load(t); ok {
		return d.(string)
	}
	d := t.TempDir()
	testDirs.Store(t, d)
	return d
}

func helperSpec(t *testing.T, id, mode string, env ...string) driver.ProcSpec {
	t.Helper()
	return driver.ProcSpec{
		ID:      id,
		Path:    exePath(t),
		Args:    []string{"-test.run=^TestHelperProcess$"},
		Env:     append([]string{"W1NC_HELPER=1", "W1NC_MODE=" + mode}, env...),
		LogFile: filepath.Join(testDir(t), "logs", id+".log"),
		Restart: driver.RestartPolicy{MinBackoff: 20 * time.Millisecond, MaxBackoff: 80 * time.Millisecond, ResetAfter: time.Hour},
		// Windows cannot signal gracefully; keep unix tests snappy too.
		StopTimeout: 2 * time.Second,
	}
}

func eventually(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func readFile(path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}

// starts returns the START records (unix nanos, pid) in a log file.
func starts(path string) (ts []int64, pids []int) {
	sc := bufio.NewScanner(strings.NewReader(readFile(path)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 3 && f[0] == "START" {
			n, _ := strconv.ParseInt(f[1], 10, 64)
			p, _ := strconv.Atoi(f[2])
			ts, pids = append(ts, n), append(pids, p)
		}
	}
	return
}

func newSup(t *testing.T, o Options) *Supervisor {
	t.Helper()
	testDir(t)
	s := New(o)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	return s
}

func bg() context.Context { return context.Background() }

func waitDead(t *testing.T, pid int) {
	t.Helper()
	eventually(t, 5*time.Second, fmt.Sprintf("pid %d to die", pid), func() bool { return !pidAlive(pid) })
}

// ---- tests ---------------------------------------------------------------

func TestStartStatusStop(t *testing.T) {
	s := newSup(t, Options{})
	p := helperSpec(t, "gost/main", "sleep")
	if err := s.Start(bg(), p); err != nil {
		t.Fatal(err)
	}
	st := s.Status("gost/main")
	if !st.Running || st.PID <= 0 || st.Since.IsZero() || st.Restarts != 0 {
		t.Fatalf("status %+v", st)
	}
	eventually(t, 5*time.Second, "child output", func() bool { _, pids := starts(p.LogFile); return len(pids) == 1 })
	if _, pids := starts(p.LogFile); pids[0] != st.PID {
		t.Fatalf("log pid %d != status pid %d", pids[0], st.PID)
	}
	if err := s.Stop(bg(), "gost/main"); err != nil {
		t.Fatal(err)
	}
	waitDead(t, st.PID)
	if err := s.Stop(bg(), "gost/main"); err != nil {
		t.Fatalf("second stop: %v", err)
	}
	if err := s.Stop(bg(), "never-started"); err != nil {
		t.Fatalf("unknown stop: %v", err)
	}
	if got := s.Status("gost/main"); got.Running {
		t.Fatalf("still running: %+v", got)
	}
	if got := s.Status("unknown"); got != (driver.ProcStatus{}) {
		t.Fatalf("unknown status %+v", got)
	}
}

func TestCrashRestartWithExponentialBackoff(t *testing.T) {
	var mu sync.Mutex
	var sleeps []time.Duration
	s := newSup(t, Options{})
	s.hookSleep = func(id string, d time.Duration) { mu.Lock(); sleeps = append(sleeps, d); mu.Unlock() }
	p := helperSpec(t, "crash", "exit", "W1NC_CODE=3", "W1NC_RUN_MS=0")
	p.Restart = driver.RestartPolicy{Always: true, MinBackoff: 30 * time.Millisecond, MaxBackoff: 120 * time.Millisecond, ResetAfter: time.Hour}
	if err := s.Start(bg(), p); err != nil {
		t.Fatal(err)
	}
	eventually(t, 20*time.Second, "5 starts", func() bool { ts, _ := starts(p.LogFile); return len(ts) >= 5 })

	mu.Lock()
	got := append([]time.Duration(nil), sleeps...)
	mu.Unlock()
	want := []time.Duration{30, 60, 120, 120}
	for i, w := range want {
		if i >= len(got) || got[i] != w*time.Millisecond {
			t.Fatalf("backoff sequence = %v, want prefix %v ms", got, want)
		}
	}
	// the observed gaps are at least the backoff (lower bound cannot flake)
	ts, pids := starts(p.LogFile)
	for i, w := range want {
		if gap := time.Duration(ts[i+1] - ts[i]); gap < w*time.Millisecond {
			t.Errorf("gap %d = %v < backoff %v ms", i, gap, w)
		}
	}
	// every restart is a new process
	seen := map[int]bool{}
	for _, pid := range pids {
		if seen[pid] {
			t.Fatalf("pid %d reused across restarts", pid)
		}
		seen[pid] = true
	}
	st := s.Status("crash")
	if st.Restarts < 4 {
		t.Fatalf("restarts = %d", st.Restarts)
	}
	if !strings.Contains(st.LastExit, "exit status 3") && !st.Running {
		t.Fatalf("LastExit = %q", st.LastExit)
	}
	if err := s.Stop(bg(), "crash"); err != nil {
		t.Fatal(err)
	}
}

func TestBackoffResetsAfterStableRun(t *testing.T) {
	// pure function: exact
	pol := driver.RestartPolicy{Always: true, MinBackoff: 10 * time.Millisecond, MaxBackoff: 80 * time.Millisecond, ResetAfter: 100 * time.Millisecond}
	cur := pol.MinBackoff
	var seq []time.Duration
	var sl time.Duration
	for _, ran := range []time.Duration{0, 0, 0, 0, 0, 150 * time.Millisecond, 0, 0} {
		sl, cur = nextBackoff(cur, ran, pol)
		seq = append(seq, sl)
	}
	want := []time.Duration{10, 20, 40, 80, 80, 10, 20, 40}
	for i := range want {
		if seq[i] != want[i]*time.Millisecond {
			t.Fatalf("seq = %v, want %v ms", seq, want)
		}
	}
	// integration: a process that runs longer than ResetAfter never grows its backoff
	var mu sync.Mutex
	var sleeps []time.Duration
	s := newSup(t, Options{})
	s.hookSleep = func(_ string, d time.Duration) { mu.Lock(); sleeps = append(sleeps, d); mu.Unlock() }
	p := helperSpec(t, "stable", "exit", "W1NC_CODE=1", "W1NC_RUN_MS=250")
	p.Restart = driver.RestartPolicy{Always: true, MinBackoff: 20 * time.Millisecond, MaxBackoff: 640 * time.Millisecond, ResetAfter: 100 * time.Millisecond}
	if err := s.Start(bg(), p); err != nil {
		t.Fatal(err)
	}
	eventually(t, 20*time.Second, "4 backoffs", func() bool { mu.Lock(); defer mu.Unlock(); return len(sleeps) >= 4 })
	mu.Lock()
	defer mu.Unlock()
	for i, d := range sleeps[:4] {
		if d != 20*time.Millisecond {
			t.Fatalf("sleep %d = %v, backoff must reset after a stable run: %v", i, d, sleeps)
		}
	}
}

func TestStartIdempotent(t *testing.T) {
	s := newSup(t, Options{})
	p := helperSpec(t, "idem", "sleep")
	if err := s.Start(bg(), p); err != nil {
		t.Fatal(err)
	}
	pid := s.Status("idem").PID
	for i := 0; i < 3; i++ {
		if err := s.Start(bg(), p); err != nil {
			t.Fatal(err)
		}
	}
	st := s.Status("idem")
	if st.PID != pid || st.Restarts != 0 || !st.Running {
		t.Fatalf("idempotent start disturbed the process: %+v (was pid %d)", st, pid)
	}
	eventually(t, 5*time.Second, "child output", func() bool { _, pids := starts(p.LogFile); return len(pids) >= 1 })
	time.Sleep(100 * time.Millisecond)
	if _, pids := starts(p.LogFile); len(pids) != 1 {
		t.Fatalf("process started %d times", len(pids))
	}
}

func TestStartReplacesOnSpecChange(t *testing.T) {
	s := newSup(t, Options{})
	p := helperSpec(t, "rep", "sleep", "W1NC_V=1")
	if err := s.Start(bg(), p); err != nil {
		t.Fatal(err)
	}
	old := s.Status("rep").PID
	p2 := p
	p2.Env = append(append([]string(nil), p.Env...), "W1NC_V=2")
	if err := s.Start(bg(), p2); err != nil {
		t.Fatal(err)
	}
	st := s.Status("rep")
	if !st.Running || st.PID == old {
		t.Fatalf("not replaced: old %d new %+v", old, st)
	}
	waitDead(t, old)
	// a changed arg also replaces
	p3 := p2
	p3.Args = append(append([]string(nil), p2.Args...), "-test.v=false")
	prev := s.Status("rep").PID
	if err := s.Start(bg(), p3); err != nil {
		t.Fatal(err)
	}
	if s.Status("rep").PID == prev {
		t.Fatal("arg change did not replace the process")
	}
	waitDead(t, prev)
}

func TestStartErrors(t *testing.T) {
	s := newSup(t, Options{})
	if err := s.Start(bg(), driver.ProcSpec{Path: "/x"}); err == nil {
		t.Error("empty id accepted")
	}
	if err := s.Start(bg(), driver.ProcSpec{ID: "x"}); err == nil {
		t.Error("empty path accepted")
	}
	p := helperSpec(t, "missing", "sleep")
	p.Path = filepath.Join(t.TempDir(), "does-not-exist")
	if err := s.Start(bg(), p); err == nil {
		t.Fatal("missing binary accepted")
	}
	if st := s.Status("missing"); st.Running {
		t.Fatalf("failed start left state: %+v", st)
	}
	if ids := s.IDs(); len(ids) != 0 {
		t.Fatalf("failed start registered: %v", ids)
	}
}

func TestExitWithoutRestartPolicyThenStartAgain(t *testing.T) {
	s := newSup(t, Options{})
	p := helperSpec(t, "once", "exit", "W1NC_CODE=0", "W1NC_RUN_MS=0")
	p.Restart = driver.RestartPolicy{}
	if err := s.Start(bg(), p); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "exit", func() bool { return !s.Status("once").Running })
	st := s.Status("once")
	if st.Restarts != 0 || st.LastExit != "exit status 0" {
		t.Fatalf("status %+v", st)
	}
	time.Sleep(100 * time.Millisecond)
	if ts, _ := starts(p.LogFile); len(ts) != 1 {
		t.Fatalf("restarted without policy: %d starts", len(ts))
	}
	// Start == ensure running: the same spec starts it again.
	if err := s.Start(bg(), p); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "second run", func() bool { ts, _ := starts(p.LogFile); return len(ts) == 2 })
}

func TestArgvIsNotInterpretedByAShell(t *testing.T) {
	s := newSup(t, Options{})
	p := helperSpec(t, "argv", "args")
	evil := []string{"; echo pwned > /tmp/pwned", "$(id)", "`id`", "a b  c", "*", "\"quoted\"", "|", "&&", ">out"}
	p.Args = append(p.Args, evil...)
	if err := s.Start(bg(), p); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "args printed", func() bool { return strings.Contains(readFile(p.LogFile), "ARG9=") })
	out := readFile(p.LogFile)
	// ARG0 is the -test.run flag; ours follow
	for i, a := range evil {
		line := fmt.Sprintf("ARG%d=%s", i+1, a)
		if !strings.Contains(out, line+"\n") && !strings.Contains(out, line+"\r\n") {
			t.Errorf("argument %q was altered; log:\n%s", a, out)
		}
	}
}

func TestMinimalEnvironmentPlusSpecEnv(t *testing.T) {
	t.Setenv("LEAK_ME", "secret-from-agent-env")
	s := newSup(t, Options{})
	p := helperSpec(t, "env", "env", "W1NC_MINE=yes")
	if err := s.Start(bg(), p); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "env printed", func() bool { return strings.Contains(readFile(p.LogFile), "HASPATH=") })
	out := readFile(p.LogFile)
	if !strings.Contains(out, `LEAK=""`) {
		t.Errorf("agent environment leaked into the child:\n%s", out)
	}
	if !strings.Contains(out, `MINE="yes"`) {
		t.Errorf("spec env missing:\n%s", out)
	}
	if !strings.Contains(out, "HASPATH=true") {
		t.Errorf("PATH missing:\n%s", out)
	}
}

func TestBaseEnvOverride(t *testing.T) {
	t.Setenv("LEAK_ME", "x")
	s := newSup(t, Options{BaseEnv: []string{"W1NC_MINE=from-base", "SYSTEMROOT=" + os.Getenv("SYSTEMROOT")}})
	p := helperSpec(t, "env2", "env")
	if err := s.Start(bg(), p); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "env printed", func() bool { return strings.Contains(readFile(p.LogFile), "HASPATH=") })
	if out := readFile(p.LogFile); !strings.Contains(out, `MINE="from-base"`) || !strings.Contains(out, "HASPATH=false") {
		t.Errorf("custom base env not honoured:\n%s", out)
	}
}

func TestWorkDir(t *testing.T) {
	dir := t.TempDir()
	s := newSup(t, Options{})
	p := helperSpec(t, "cwd", "cwd")
	p.WorkDir = dir
	if err := s.Start(bg(), p); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "cwd printed", func() bool { return strings.Contains(readFile(p.LogFile), "CWD=") })
	got := strings.TrimSpace(strings.SplitN(strings.SplitN(readFile(p.LogFile), "CWD=", 2)[1], "\n", 2)[0])
	a, _ := filepath.EvalSymlinks(got)
	b, _ := filepath.EvalSymlinks(dir)
	if a != b {
		t.Fatalf("cwd %q, want %q", got, dir)
	}
}

func TestLogRotationUnit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d", "x.log")
	l, err := openLog(path, 100, 2)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		line := fmt.Sprintf("%d%s\n", i, strings.Repeat("-", 48)) // 50 bytes: two per file
		if n, err := l.Write([]byte(line)); n != len(line) || err != nil {
			t.Fatalf("Write = %d, %v", n, err)
		}
	}
	l.Close()
	ents, _ := os.ReadDir(filepath.Dir(path))
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
		fi, _ := e.Info()
		if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", e.Name(), fi.Mode().Perm())
		}
		if fi.Size() > 100 {
			t.Errorf("%s is %d bytes, over the limit", e.Name(), fi.Size())
		}
	}
	if len(names) != 3 {
		t.Fatalf("files = %v, want x.log, x.log.1, x.log.2", names)
	}
	// newest data in x.log, older in .1, oldest kept in .2
	if !strings.HasPrefix(readFile(path), "8") || !strings.HasPrefix(readFile(path+".1"), "6") || !strings.HasPrefix(readFile(path+".2"), "4") {
		t.Fatalf("rotation order wrong: %q %q %q", readFile(path), readFile(path+".1"), readFile(path+".2"))
	}
	// writes after Close are swallowed, not errors
	if n, err := l.Write([]byte("late")); n != 4 || err != nil {
		t.Fatalf("write after close: %d %v", n, err)
	}
}

func TestLogRotationKeepNone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.log")
	l, _ := openLog(path, 10, -1)
	for i := 0; i < 5; i++ {
		l.Write([]byte("0123456789ab\n"))
	}
	l.Close()
	ents, _ := os.ReadDir(filepath.Dir(path))
	if len(ents) != 1 {
		t.Fatalf("keep<=0 must leave only the live file, got %d entries", len(ents))
	}
}

func TestLogPermissionsTightened(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	path := filepath.Join(t.TempDir(), "x.log")
	os.WriteFile(path, []byte("old\n"), 0o644)
	l, err := openLog(path, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("existing log not tightened: %v", fi.Mode().Perm())
	}
	if readFile(path) != "old\n" {
		t.Fatal("existing content must be appended to, not truncated")
	}
}

func TestLogRotationOfRealProcessOutput(t *testing.T) {
	s := newSup(t, Options{LogMaxBytes: 2000, LogKeep: 2})
	p := helperSpec(t, "noisy", "noisy", "W1NC_LINES=200")
	if err := s.Start(bg(), p); err != nil {
		t.Fatal(err)
	}
	// 200 lines of 100 bytes = 20 kB of stdout+stderr -> must have rotated
	eventually(t, 10*time.Second, "rotation", func() bool {
		_, err := os.Stat(p.LogFile + ".2")
		return err == nil
	})
	time.Sleep(200 * time.Millisecond)
	ents, _ := os.ReadDir(filepath.Dir(p.LogFile))
	if len(ents) > 3 {
		t.Errorf("more than live + 2 rotated files: %d", len(ents))
	}
	for _, e := range ents {
		fi, _ := e.Info()
		if fi.Size() > 2100 {
			t.Errorf("%s is %d bytes", e.Name(), fi.Size())
		}
		if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", e.Name(), fi.Mode().Perm())
		}
	}
	// the child kept running throughout (logging never kills it)
	if !s.Status("noisy").Running {
		t.Fatalf("child died: %+v", s.Status("noisy"))
	}
}

func TestLogWriteFailureNeverFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.log")
	l, err := openLog(path, 1000, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.Write([]byte("0123456789abcdef"))
	l.f.Close() // simulate a broken descriptor: every write now errors
	if n, err := l.Write([]byte("more")); n != 4 || err != nil {
		t.Fatalf("a failing log must still report success, got %d %v", n, err)
	}
	if l.dropped == 0 {
		t.Fatal("dropped bytes not accounted")
	}
}

func TestPIDFile(t *testing.T) {
	pidDir := filepath.Join(t.TempDir(), "run")
	s := newSup(t, Options{PIDDir: pidDir})
	p := helperSpec(t, "gost/main", "sleep")
	if err := s.Start(bg(), p); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(pidDir, "gost%2Fmain.pid")
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), fmt.Sprintf(`"pid":%d`, s.Status("gost/main").PID)) {
		t.Fatalf("pid file: %s", b)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(file)
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("pid file mode %v", fi.Mode().Perm())
		}
		di, _ := os.Stat(pidDir)
		if di.Mode().Perm() != 0o700 {
			t.Errorf("pid dir mode %v", di.Mode().Perm())
		}
	}
	if err := s.Stop(bg(), "gost/main"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("pid file left behind: %v", err)
	}
}

func TestStopContextExpiryKillsImmediately(t *testing.T) {
	s := newSup(t, Options{})
	p := helperSpec(t, "ctx", "sleep")
	p.StopTimeout = time.Minute
	if err := s.Start(bg(), p); err != nil {
		t.Fatal(err)
	}
	pid := s.Status("ctx").PID
	ctx, cancel := context.WithCancel(bg())
	cancel()
	start := time.Now()
	err := s.Stop(ctx, "ctx")
	if err == nil {
		t.Fatal("expected the context error")
	}
	if time.Since(start) > 10*time.Second {
		t.Fatalf("expired context did not force a kill: %v", time.Since(start))
	}
	waitDead(t, pid)
}

func TestShutdown(t *testing.T) {
	s := New(Options{})
	var pids []int
	for i := 0; i < 4; i++ {
		p := helperSpec(t, fmt.Sprintf("p%d", i), "sleep")
		if err := s.Start(bg(), p); err != nil {
			t.Fatal(err)
		}
		pids = append(pids, s.Status(p.ID).PID)
	}
	// one of them is crash-looping
	cp := helperSpec(t, "loop", "exit", "W1NC_CODE=1", "W1NC_RUN_MS=0")
	cp.Restart.Always = true
	if err := s.Start(bg(), cp); err != nil {
		t.Fatal(err)
	}
	if err := s.Shutdown(bg()); err != nil {
		t.Fatal(err)
	}
	for _, pid := range pids {
		waitDead(t, pid)
	}
	if ids := s.IDs(); len(ids) != 0 {
		t.Fatalf("still tracking %v", ids)
	}
	if err := s.Start(bg(), helperSpec(t, "late", "sleep")); err == nil {
		t.Fatal("Start after Shutdown must fail")
	}
	if err := s.Shutdown(bg()); err != nil {
		t.Fatalf("second shutdown: %v", err)
	}
}

func TestConcurrentStartStop(t *testing.T) {
	s := newSup(t, Options{})
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := helperSpec(t, fmt.Sprintf("c%d", i%3), "sleep", fmt.Sprintf("W1NC_V=%d", i))
			_ = s.Start(bg(), p)
			_ = s.Status(p.ID)
			if i%2 == 0 {
				_ = s.Stop(bg(), p.ID)
			}
		}(i)
	}
	wg.Wait()
}

func TestNoGoroutineLeak(t *testing.T) {
	base := settledGoroutines()
	for round := 0; round < 3; round++ {
		s := New(Options{LogMaxBytes: 1000})
		p := helperSpec(t, "leak", "exit", "W1NC_CODE=1", "W1NC_RUN_MS=0")
		p.Restart.Always = true
		if err := s.Start(bg(), p); err != nil {
			t.Fatal(err)
		}
		q := helperSpec(t, "leak2", "noisy", "W1NC_LINES=50")
		if err := s.Start(bg(), q); err != nil {
			t.Fatal(err)
		}
		eventually(t, 10*time.Second, "restarts", func() bool { return s.Status("leak").Restarts >= 2 })
		q.Env = append(q.Env, "W1NC_V=2") // replacement
		if err := s.Start(bg(), q); err != nil {
			t.Fatal(err)
		}
		if err := s.Stop(bg(), "leak"); err != nil {
			t.Fatal(err)
		}
		if err := s.Shutdown(bg()); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, 5*time.Second, "goroutines to settle", func() bool { return runtime.NumGoroutine() <= base })
	if n := runtime.NumGoroutine(); n > base {
		buf := make([]byte, 1<<16)
		buf = buf[:runtime.Stack(buf, true)]
		t.Fatalf("goroutine leak: %d > %d\n%s", n, base, buf)
	}
}

func settledGoroutines() int {
	time.Sleep(100 * time.Millisecond)
	return runtime.NumGoroutine()
}

func TestSignalErrors(t *testing.T) {
	s := newSup(t, Options{})
	if err := s.Signal("nope", os.Interrupt); err == nil {
		t.Error("signal to unknown id succeeded")
	}
	p := helperSpec(t, "gone", "exit", "W1NC_CODE=0", "W1NC_RUN_MS=0")
	p.Restart = driver.RestartPolicy{}
	if err := s.Start(bg(), p); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "exit", func() bool { return !s.Status("gone").Running })
	if err := s.Signal("gone", os.Interrupt); err == nil {
		t.Error("signal to an exited process succeeded")
	}
}

func TestRecoverOrphansStaleAndDisabled(t *testing.T) {
	// no PIDDir: nothing to do
	if o, err := New(Options{}).RecoverOrphans(bg()); o != nil || err != nil {
		t.Fatalf("%v %v", o, err)
	}
	pidDir := t.TempDir()
	s := newSup(t, Options{PIDDir: pidDir})
	// a record for a process that no longer exists, plus junk
	dead := helperSpec(t, "dead", "exit", "W1NC_CODE=0", "W1NC_RUN_MS=0")
	dead.Restart = driver.RestartPolicy{}
	s2 := New(Options{PIDDir: t.TempDir()})
	if err := s2.Start(bg(), dead); err != nil {
		t.Fatal(err)
	}
	pid := s2.Status("dead").PID
	eventually(t, 10*time.Second, "exit", func() bool { return !s2.Status("dead").Running })
	waitDead(t, pid)
	os.WriteFile(filepath.Join(pidDir, "dead.pid"), []byte(fmt.Sprintf(`{"id":"dead","pid":%d,"path":%q}`, pid, dead.Path)), 0o600)
	os.WriteFile(filepath.Join(pidDir, "junk.pid"), []byte("not json"), 0o600)
	os.WriteFile(filepath.Join(pidDir, "init.pid"), []byte(`{"id":"init","pid":1,"path":"/sbin/init"}`), 0o600)
	os.WriteFile(filepath.Join(pidDir, "ignored.txt"), []byte("x"), 0o600)
	got, err := s.RecoverOrphans(bg())
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range got {
		if o.Action != "stale" {
			t.Errorf("unexpected action %+v", o)
		}
	}
	if len(got) != 3 {
		t.Fatalf("got %+v", got)
	}
	left, _ := os.ReadDir(pidDir)
	if len(left) != 1 || left[0].Name() != "ignored.txt" {
		t.Fatalf("records not cleaned: %v", left)
	}
}

func TestRecoverOrphansSkipsManaged(t *testing.T) {
	pidDir := t.TempDir()
	s := newSup(t, Options{PIDDir: pidDir})
	p := helperSpec(t, "mine", "sleep")
	if err := s.Start(bg(), p); err != nil {
		t.Fatal(err)
	}
	got, err := s.RecoverOrphans(bg())
	if err != nil || len(got) != 0 {
		t.Fatalf("managed process touched: %v %v", got, err)
	}
	if !s.Status("mine").Running {
		t.Fatal("managed process was killed by RecoverOrphans")
	}
}

func TestEscapeID(t *testing.T) {
	for in, want := range map[string]string{"gost/main": "gost%2Fmain", "a.b": "a%2Eb", "../x": "%2E%2E%2Fx", "ok_1-x": "ok_1-x"} {
		if got := escapeID(in); got != want {
			t.Errorf("escapeID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNextBackoffBounds(t *testing.T) {
	pol := driver.RestartPolicy{MinBackoff: time.Second, MaxBackoff: 30 * time.Second, ResetAfter: 2 * time.Minute}
	cur := time.Duration(0) // below Min is clamped
	s, n := nextBackoff(cur, 0, pol)
	if s != time.Second || n != 2*time.Second {
		t.Fatalf("%v %v", s, n)
	}
	s, n = nextBackoff(20*time.Second, 0, pol)
	if s != 20*time.Second || n != 30*time.Second {
		t.Fatalf("%v %v", s, n)
	}
	s, n = nextBackoff(30*time.Second, 0, pol)
	if s != 30*time.Second || n != 30*time.Second {
		t.Fatalf("%v %v", s, n)
	}
	s, _ = nextBackoff(30*time.Second, 3*time.Minute, pol)
	if s != time.Second {
		t.Fatalf("stable run must reset: %v", s)
	}
}

func TestApplyDefaults(t *testing.T) {
	p := applyDefaults(driver.ProcSpec{})
	if p.Restart.MinBackoff != DefaultMinBackoff || p.Restart.MaxBackoff != DefaultMaxBackoff || p.Restart.ResetAfter != DefaultResetAfter || p.StopTimeout != DefaultStopTimeout {
		t.Fatalf("%+v", p)
	}
	p = applyDefaults(driver.ProcSpec{Restart: driver.RestartPolicy{MinBackoff: time.Minute, MaxBackoff: time.Second}})
	if p.Restart.MaxBackoff != time.Minute {
		t.Fatalf("max below min not fixed: %+v", p.Restart)
	}
}

var _ = exec.ErrNotFound
