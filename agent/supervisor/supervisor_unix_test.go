//go:build unix

package supervisor

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

func helperUnix() {
	switch os.Getenv("W1NC_MODE") {
	case "term_graceful":
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGTERM)
		fmt.Println("READY")
		<-c
		fmt.Println("got SIGTERM")
		os.Exit(0)
	case "term_ignore":
		signal.Ignore(syscall.SIGTERM)
		fmt.Println("READY")
		blockForever()
	case "hup":
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGHUP)
		fmt.Println("READY")
		for range c {
			fmt.Println("got SIGHUP")
		}
	case "spawn_child", "leave_child":
		cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
		cmd.Env = append(os.Environ(), "W1NC_MODE=sleep")
		cmd.Stdout = os.Stdout // the grandchild shares our output pipe on purpose
		if err := cmd.Start(); err != nil {
			fmt.Println("spawn failed:", err)
			os.Exit(2)
		}
		fmt.Printf("CHILD %d\n", cmd.Process.Pid)
		if os.Getenv("W1NC_MODE") == "leave_child" {
			os.Exit(0)
		}
		blockForever()
	}
}

func childPID(t *testing.T, logPath string) int {
	t.Helper()
	var pid int
	eventually(t, 10*time.Second, "child pid in log", func() bool {
		for _, ln := range strings.Split(readFile(logPath), "\n") {
			if strings.HasPrefix(ln, "CHILD ") {
				pid, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(ln, "CHILD ")))
				return pid > 0
			}
		}
		return false
	})
	return pid
}

func entryOf(s *Supervisor, id string) *entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.procs[id]
}

func TestGracefulStopUsesSIGTERM(t *testing.T) {
	s := newSup(t, Options{})
	p := helperSpec(t, "graceful", "term_graceful")
	if err := s.Start(bg(), p); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "READY", func() bool { return strings.Contains(readFile(p.LogFile), "READY") })
	e := entryOf(s, "graceful")
	start := time.Now()
	if err := s.Stop(bg(), "graceful"); err != nil {
		t.Fatal(err)
	}
	// The point is that the child exits on SIGTERM instead of being killed
	// after StopTimeout (5 s by default). Keep the bound well above 1 s: a
	// child built with -race sleeps for GORACE's atexit_sleep_ms (1 s) before
	// it exits, which made a 1 s bound fail on every -race run.
	if time.Since(start) > 3*time.Second {
		t.Fatalf("graceful stop took %v", time.Since(start))
	}
	if !strings.Contains(readFile(p.LogFile), "got SIGTERM") {
		t.Fatalf("child never saw SIGTERM:\n%s", readFile(p.LogFile))
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !strings.Contains(e.st.LastExit, "stopped by supervisor") || !strings.Contains(e.st.LastExit, "exit status 0") || e.st.Running {
		t.Fatalf("status %+v", e.st)
	}
}

func TestForceKillAfterStopTimeout(t *testing.T) {
	s := newSup(t, Options{})
	p := helperSpec(t, "stubborn", "term_ignore")
	p.StopTimeout = 300 * time.Millisecond
	if err := s.Start(bg(), p); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "READY", func() bool { return strings.Contains(readFile(p.LogFile), "READY") })
	pid := s.Status("stubborn").PID
	e := entryOf(s, "stubborn")
	start := time.Now()
	if err := s.Stop(bg(), "stubborn"); err != nil {
		t.Fatal(err)
	}
	el := time.Since(start)
	if el < 300*time.Millisecond || el > 5*time.Second {
		t.Fatalf("stop took %v, want >= StopTimeout and not much more", el)
	}
	waitDead(t, pid)
	e.mu.Lock()
	defer e.mu.Unlock()
	if !strings.Contains(e.st.LastExit, "killed") {
		t.Fatalf("LastExit = %q, want a kill", e.st.LastExit)
	}
}

func TestStopKillsTheWholeProcessGroup(t *testing.T) {
	s := newSup(t, Options{})
	p := helperSpec(t, "tree", "spawn_child")
	if err := s.Start(bg(), p); err != nil {
		t.Fatal(err)
	}
	child := childPID(t, p.LogFile)
	if !pidAlive(child) {
		t.Fatal("grandchild not running")
	}
	if err := s.Stop(bg(), "tree"); err != nil {
		t.Fatal(err)
	}
	waitDead(t, child)
}

func TestLeaderExitSweepsStragglers(t *testing.T) {
	s := newSup(t, Options{})
	p := helperSpec(t, "left", "leave_child")
	p.Restart = driver.RestartPolicy{}
	if err := s.Start(bg(), p); err != nil {
		t.Fatal(err)
	}
	child := childPID(t, p.LogFile)
	// The leader exits at once; the grandchild keeps the output pipe open, so
	// the exit is noticed after waitDelay at the latest, and the straggler is killed.
	eventually(t, 10*time.Second, "leader exit", func() bool { return !s.Status("left").Running })
	waitDead(t, child)
}

func TestSignalDeliversToProcess(t *testing.T) {
	s := newSup(t, Options{})
	p := helperSpec(t, "hup", "hup")
	if err := s.Start(bg(), p); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "READY", func() bool { return strings.Contains(readFile(p.LogFile), "READY") })
	if err := s.Signal("hup", syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "SIGHUP seen", func() bool { return strings.Contains(readFile(p.LogFile), "got SIGHUP") })
	if !s.Status("hup").Running {
		t.Fatal("SIGHUP killed the process")
	}
}

func TestRecoverOrphansTerminatesVerifiedLeftover(t *testing.T) {
	pidDir := t.TempDir()
	crashed := New(Options{PIDDir: pidDir}) // stands for the previous agent run
	p := helperSpec(t, "orph", "sleep")
	if err := crashed.Start(bg(), p); err != nil {
		t.Fatal(err)
	}
	pid := crashed.Status("orph").PID
	t.Cleanup(func() { _ = syscall.Kill(-pid, syscall.SIGKILL) })

	fresh := New(Options{PIDDir: pidDir})
	got, err := fresh.RecoverOrphans(bg())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].PID != pid || got[0].ID != "orph" {
		t.Fatalf("got %+v", got)
	}
	if runtime.GOOS == "linux" {
		if got[0].Action != "terminated" {
			t.Fatalf("action %q", got[0].Action)
		}
		waitDead(t, pid)
	} else if got[0].Action != "unverified" || !pidAlive(pid) {
		t.Fatalf("without /proc the process must be left alone: %+v", got[0])
	}
	if left, _ := os.ReadDir(pidDir); len(left) != 0 {
		t.Fatalf("records left: %v", left)
	}
}

func TestRecoverOrphansIgnoresReusedPid(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs /proc")
	}
	pidDir := t.TempDir()
	s := newSup(t, Options{})
	p := helperSpec(t, "innocent", "sleep")
	if err := s.Start(bg(), p); err != nil {
		t.Fatal(err)
	}
	pid := s.Status("innocent").PID
	// a record that claims this (unrelated) live pid belonged to another binary
	rec := fmt.Sprintf(`{"id":"stale","pid":%d,"path":"/usr/bin/gost","exe":"/usr/bin/gost"}`, pid)
	os.WriteFile(filepath.Join(pidDir, "stale.pid"), []byte(rec), 0o600)
	fresh := New(Options{PIDDir: pidDir})
	got, err := fresh.RecoverOrphans(bg())
	if err != nil || len(got) != 1 || got[0].Action != "reused" {
		t.Fatalf("%+v %v", got, err)
	}
	time.Sleep(200 * time.Millisecond)
	if !pidAlive(pid) || !s.Status("innocent").Running {
		t.Fatal("an unrelated process was killed because its pid matched a stale record")
	}
}
