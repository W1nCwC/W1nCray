//go:build linux || darwin || freebsd || openbsd || netbsd

package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// With W1NCRAY_LOCK_HELPER set the test binary acts as a second W1nCray
// process: it takes the lock and holds it until it is killed.
func TestMain(m *testing.M) {
	if path := os.Getenv("W1NCRAY_LOCK_HELPER"); path != "" {
		l, err := acquireInstanceLock(path)
		if err != nil {
			os.Stdout.WriteString("LOCK-FAILED " + err.Error() + "\n")
			os.Exit(3)
		}
		_ = l
		os.Stdout.WriteString("LOCKED\n")
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestInstanceLockExcludesSecondInstance(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.yml")
	first, err := acquireInstanceLock(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquireInstanceLock(cfg); err == nil {
		t.Fatal("second instance acquired the lock")
	} else if !strings.Contains(err.Error(), "已有 W1nCray 实例") || !strings.Contains(err.Error(), "PID "+strconv.Itoa(os.Getpid())) {
		t.Fatalf("unhelpful error: %v", err)
	}

	other := filepath.Join(t.TempDir(), "other.yml")
	second, err := acquireInstanceLock(other)
	if err != nil {
		t.Fatalf("a different config must not conflict: %v", err)
	}
	second.release()

	first.release()
	again, err := acquireInstanceLock(cfg)
	if err != nil {
		t.Fatalf("lock not free after release: %v", err)
	}
	again.release()
}

// A crashed (killed) instance must not leave the config locked.
func TestInstanceLockReleasedWhenHolderIsKilled(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.yml")
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "W1NCRAY_LOCK_HELPER="+cfg)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, _ := stdout.Read(buf)
	if !strings.HasPrefix(string(buf[:n]), "LOCKED") {
		t.Fatalf("helper did not take the lock: %q", buf[:n])
	}

	_, err = acquireInstanceLock(cfg)
	if err == nil {
		t.Fatal("lock was acquired while another process holds it")
	}
	if !strings.Contains(err.Error(), "PID "+strconv.Itoa(cmd.Process.Pid)) {
		t.Fatalf("error does not name the holder (pid %d): %v", cmd.Process.Pid, err)
	}

	cmd.Process.Kill() // SIGKILL: no chance to clean up
	cmd.Wait()
	deadline := time.Now().Add(3 * time.Second)
	for {
		l, err := acquireInstanceLock(cfg)
		if err == nil {
			l.release()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("lock still held after the holder was killed: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
