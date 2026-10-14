package selfupdate

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/kernel"
	"github.com/W1nCwC/W1nCray/kernel/install"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
	"github.com/W1nCwC/W1nCray/kernel/platform"
)

var fixedNow = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func gz(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// testServer serves the agent archives over HTTP, the way the release mirror
// does.
type testServer struct {
	*httptest.Server
	blobs map[string][]byte
}

func serve(t *testing.T, blobs map[string][]byte) *testServer {
	t.Helper()
	if blobs == nil {
		blobs = map[string][]byte{}
	}
	s := &testServer{blobs: blobs}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := s.blobs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(b))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *testServer) url(path string, b []byte) string {
	s.blobs[path] = b
	return s.URL + path
}

// fakeBin is a stand-in executable whose "version" fakeCheck reads.
func fakeBin(version string, pad int) []byte {
	return append([]byte("#!/bin/sh\n# FAKEKERNEL version="+version+"\n"), bytes.Repeat([]byte("x"), pad)...)
}

var reFake = regexp.MustCompile(`FAKEKERNEL version=(\S+)`)

func fakeCheck(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	m := reFake.FindSubmatch(b)
	if m == nil {
		return "", io.ErrUnexpectedEOF
	}
	return string(m[1]), nil
}

// fixture signs manifests with one key and serves archives over httptest.
type fixture struct {
	t    *testing.T
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{t: t, pub: pub, priv: priv}
}

// agentKernel describes the manifest entry for the reserved name "agent".
type agentKernel struct {
	Version  string
	Data     []byte // the binary inside the gz archive
	URL      string
	Revoked  []manifest.Revocation
	MinAgent string
	AgentVer string // install.Config.AgentVersion
}

// installer builds a real install.Installer with the signed agent entry loaded.
func (f *fixture) installer(k agentKernel) *install.Installer {
	f.t.Helper()
	archive := gz(f.t, k.Data)
	ex := manifest.Extract{From: "W1nCray-linux-amd64", To: "W1nCray", SHA256: sha(k.Data), Size: int64(len(k.Data)), Mode: "0755"}
	m := &manifest.Manifest{
		Schema: manifest.SchemaVersion, Sequence: 3,
		IssuedAt: fixedNow.Add(-time.Hour), ExpiresAt: fixedNow.Add(30 * 24 * time.Hour),
		Kernels: []manifest.Kernel{{
			Name: "agent", Version: k.Version, Channel: "stable", MinAgent: k.MinAgent,
			License: manifest.License{SPDX: "MIT", SourceURL: "https://example.com/agent"},
			Run:     manifest.Run{Binary: "W1nCray", VersionCmd: []string{"version"}},
			Targets: map[string]*manifest.Target{
				"linux/amd64": {
					URLs: []string{k.URL}, Archive: manifest.ArchiveGz,
					ArchiveSHA256: sha(archive), ArchiveSize: int64(len(archive)),
					Extract: []manifest.Extract{ex}, InstalledSize: ex.Size,
				},
			},
			Revoked: k.Revoked,
		}},
	}
	raw, err := manifest.Sign(m, f.priv)
	if err != nil {
		f.t.Fatal(err)
	}
	in, err := install.New(install.Config{
		Dir:          f.t.TempDir(),
		Keys:         []manifest.Key{manifest.NewKey(f.pub)},
		AgentVersion: k.AgentVer,
		Platform:     &platform.Info{GOOS: "linux", GOARCH: "amd64", Libc: "glibc"},
		AllowHTTP:    true,
		Check:        fakeCheck,
		FreeSpace:    func(string) (uint64, bool) { return 1 << 40, true },
		Now:          func() time.Time { return fixedNow },
		RetryDelay:   time.Millisecond,
		StallTimeout: 5 * time.Second,
	})
	if err != nil {
		f.t.Fatal(err)
	}
	if err := in.LoadManifest(raw); err != nil {
		f.t.Fatal(err)
	}
	return in
}

// updater builds an Updater with the platform gate stubbed open (the real gate
// needs a service manager and is exercised by Ready).
func (f *fixture) updater(exe, state string, inst Installer) *Updater {
	f.t.Helper()
	up, err := New(Options{
		ExePath: exe, StateDir: state, Installer: inst, Log: nopLog{},
		Ready: func(string) error { return nil },
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return up
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestStageFailsWithoutTouchingTheExecutable covers acceptance item 4: every
// manifest-level refusal, a revoked version, an unmet min_agent and a failed
// version self-check leave the running executable exactly as it was.
func TestStageFailsWithoutTouchingTheExecutable(t *testing.T) {
	cases := []struct {
		name string
		k    agentKernel
		want error
	}{
		{
			name: "version not in the manifest",
			k:    agentKernel{Version: "1.0.0", Data: fakeBin("1.0.0", 64), URL: "http://127.0.0.1:1/a.gz"},
			want: kernel.ErrUnknownKernel,
		},
		{
			name: "version revoked",
			k: agentKernel{Version: "1.0.0", Data: fakeBin("1.0.0", 64), URL: "http://127.0.0.1:1/a.gz",
				Revoked: []manifest.Revocation{{Version: "1.0.0", Reason: "bad build"}}},
			want: kernel.ErrRevoked,
		},
		{
			name: "min_agent not satisfied",
			k: agentKernel{Version: "1.0.0", Data: fakeBin("1.0.0", 64), URL: "http://127.0.0.1:1/a.gz",
				MinAgent: "9.9.9", AgentVer: "0.5.0"},
			want: kernel.ErrAgentTooOld,
		},
		{
			name: "self-check reports another version",
			k:    agentKernel{Version: "1.0.0", Data: fakeBin("2.0.0", 64), URL: "http://127.0.0.1:1/a.gz"},
			want: kernel.ErrCheck,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			srv := serve(t, nil)
			// Every case gets a real, served archive: the failures below must
			// come from the manifest/self-check, not from an unreachable URL.
			tc.k.URL = srv.url("/a.gz", gz(t, tc.k.Data))
			dir := t.TempDir()
			exe := filepath.Join(dir, "W1nCray")
			writeFile(t, exe, "OLD-BINARY")
			state := filepath.Join(dir, "state")
			in := f.installer(tc.k)
			up := f.updater(exe, state, in)

			version := tc.k.Version
			if tc.want == kernel.ErrUnknownKernel {
				version = "9.9.9"
			}
			if _, err := up.Stage(context.Background(), version); !errors.Is(err, tc.want) {
				t.Fatalf("Stage error = %v, want %v", err, tc.want)
			}
			if got := readFile(t, exe); got != "OLD-BINARY" {
				t.Errorf("the executable was modified: %q", got)
			}
			if _, err := os.Stat(exe + ".old"); !errors.Is(err, os.ErrNotExist) {
				t.Error("a refused stage must not create a backup")
			}
			if _, ok := up.Pending(); ok {
				t.Error("a refused stage must not write a pending marker")
			}
		})
	}
}

// TestStageCommitConfirm covers acceptance item 5: after Commit exe is the new
// binary, exe.old the old one and pending.json exists; Confirm removes both.
func TestStageCommitConfirm(t *testing.T) {
	f := newFixture(t)
	srv := serve(t, nil)
	data := fakeBin("1.0.0", 4096)
	url := srv.url("/W1nCray-linux-amd64.gz", gz(t, data))
	dir := t.TempDir()
	exe := filepath.Join(dir, "W1nCray")
	writeFile(t, exe, "OLD-BINARY")
	up := f.updater(exe, filepath.Join(dir, "state"), f.installer(agentKernel{Version: "1.0.0", Data: data, URL: url}))

	staged, err := up.Stage(context.Background(), "1.0.0")
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if got := readFile(t, exe); got != "OLD-BINARY" {
		t.Fatalf("Stage wrote the executable: %q", got)
	}
	if staged.Version != "1.0.0" || staged.SHA256 != sha(data) || staged.Size != int64(len(data)) {
		t.Fatalf("staged = %+v", staged)
	}

	if err := up.Commit(staged); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if got := readFile(t, exe); got != string(data) {
		t.Error("exe is not the new binary after Commit")
	}
	if got := readFile(t, exe+".old"); got != "OLD-BINARY" {
		t.Error("exe.old is not the previous binary after Commit")
	}
	if p, ok := up.Pending(); !ok || p.Version != "1.0.0" || p.ExePath != exe {
		t.Errorf("pending = %+v (ok=%v)", p, ok)
	}

	// A second commit while one is pending would clobber the backup.
	if _, err := up.Stage(context.Background(), "1.0.0"); !errors.Is(err, ErrPending) {
		t.Errorf("a second Stage = %v, want ErrPending", err)
	}

	if err := up.Confirm(); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if _, err := os.Stat(exe + ".old"); !errors.Is(err, os.ErrNotExist) {
		t.Error("Confirm must remove exe.old")
	}
	if _, ok := up.Pending(); ok {
		t.Error("Confirm must remove pending.json")
	}
	if got := readFile(t, exe); got != string(data) {
		t.Error("Confirm must keep the new binary")
	}
}

// TestRollbackRestoresTheOldBinaryAndIsIdempotent covers the rollback half of
// acceptance item 7.
func TestRollbackRestoresTheOldBinaryAndIsIdempotent(t *testing.T) {
	f := newFixture(t)
	srv := serve(t, nil)
	data := fakeBin("1.0.0", 256)
	url := srv.url("/a.gz", gz(t, data))
	dir := t.TempDir()
	exe := filepath.Join(dir, "W1nCray")
	writeFile(t, exe, "OLD-BINARY")
	up := f.updater(exe, filepath.Join(dir, "state"), f.installer(agentKernel{Version: "1.0.0", Data: data, URL: url}))

	staged, err := up.Stage(context.Background(), "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := up.Commit(staged); err != nil {
		t.Fatal(err)
	}
	if err := up.Rollback("the new version did not start"); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if got := readFile(t, exe); got != "OLD-BINARY" {
		t.Errorf("exe after rollback = %q", got)
	}
	if _, err := os.Stat(exe + ".old"); !errors.Is(err, os.ErrNotExist) {
		t.Error("rollback must consume the backup")
	}
	if _, ok := up.Pending(); ok {
		t.Error("rollback must clear the pending marker")
	}
	rb, ok := up.TakeRollback()
	if !ok || rb.Version != "1.0.0" || rb.Reason == "" {
		t.Fatalf("rollback marker = %+v (ok=%v)", rb, ok)
	}
	if _, again := up.TakeRollback(); again {
		t.Error("the rollback marker must be reported exactly once")
	}
	// Idempotent: nothing left to do.
	if err := up.Rollback("again"); err != nil {
		t.Errorf("a second Rollback = %v, want nil", err)
	}
}

// fakeClock is the injected clock of the watchdog tests: now is read and sleep
// advances it, so a 90 s budget is exercised in microseconds.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) sleep(d time.Duration)   { c.t = c.t.Add(d) }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// watchdogFixture commits an update over a distinct old binary and returns the
// updater: exe is the new, unproven binary, exe.old the known-good one and
// update/watchdog/ the verified copy of it the watchdog runs.
func watchdogFixture(t *testing.T) (*Updater, string, string) {
	t.Helper()
	dir := t.TempDir()
	exe := filepath.Join(dir, "W1nCray")
	writeFile(t, exe, "OLD-BINARY")
	staged := filepath.Join(dir, "staged")
	writeFile(t, staged, "NEW-BINARY")
	state := filepath.Join(dir, "state")
	up, err := New(Options{
		ExePath: exe, StateDir: state, Log: nopLog{}, Ready: func(string) error { return nil },
		AgentVersion: "0.5.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := up.Commit(Staged{Version: "0.6.0", Path: staged, SHA256: sha([]byte("NEW-BINARY"))}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return up, exe, state
}

// watchdogBudget is a HelperOptions with a small, explicit budget. The probe is
// injected, so the lock path is only a label here.
func watchdogBudget(exe, state string) HelperOptions {
	return HelperOptions{
		ExePath: exe, StateDir: state, LockPath: filepath.Join(state, "config.yml.lock"),
		Attempts: 3, AliveWindow: 10 * time.Second, Deadline: 90 * time.Second, PollInterval: 2 * time.Second,
	}
}

// TestWatchdogStopsWhenTheNewVersionConfirms covers the success rule: the
// pending marker disappears (the new process reached the panel), the watchdog
// exits, the new binary stays and the watchdog copy is cleaned up.
func TestWatchdogStopsWhenTheNewVersionConfirms(t *testing.T) {
	up, exe, state := watchdogFixture(t)
	confirmed := false
	probe := func() (int, bool) { return 4242, true }
	sleep := func(time.Duration) {
		if !confirmed {
			confirmed = true
			if err := up.Confirm(); err != nil {
				t.Errorf("Confirm: %v", err)
			}
		}
	}
	if err := runWatchdog(context.Background(), watchdogBudget(exe, state), probe, time.Now, sleep, nopLog{}); err != nil {
		t.Fatalf("runWatchdog: %v", err)
	}
	if _, ok := up.Pending(); ok {
		t.Error("a confirmed update must leave no pending marker")
	}
	if got := readFile(t, exe); got != "NEW-BINARY" {
		t.Errorf("exe = %q, want the new binary kept", got)
	}
	if _, err := os.Stat(up.watchdogDir()); !errors.Is(err, os.ErrNotExist) {
		t.Error("a confirmed update must clean the watchdog copy")
	}
	if _, err := os.Stat(up.OldPath()); !errors.Is(err, os.ErrNotExist) {
		t.Error("a confirmed update must clean the backup")
	}
}

// TestWatchdogRollsBackAfterRepeatedRestarts covers the first rollback rule:
// the new version keeps coming back with a new pid (the service manager is
// restarting it) and never confirms.
func TestWatchdogRollsBackAfterRepeatedRestarts(t *testing.T) {
	up, exe, state := watchdogFixture(t)
	clock := &fakeClock{t: time.Unix(1000, 0)}
	pids := []int{1001, 1002, 1003, 1004}
	i := 0
	probe := func() (int, bool) {
		p := pids[len(pids)-1]
		if i < len(pids) {
			p = pids[i]
			i++
		}
		return p, true
	}
	h := watchdogBudget(exe, state)
	if err := runWatchdog(context.Background(), h, probe, clock.now, clock.sleep, nopLog{}); err != nil {
		t.Fatalf("runWatchdog: %v", err)
	}
	if i < h.Attempts+1 {
		t.Errorf("the watchdog gave up after %d observation(s), want %d", i, h.Attempts+1)
	}
	if got := readFile(t, exe); got != "OLD-BINARY" {
		t.Errorf("exe after the rollback = %q, want the previous binary", got)
	}
	if _, ok := up.Pending(); ok {
		t.Error("a rollback must clear the pending marker")
	}
	rb, ok := up.TakeRollback()
	if !ok || rb.Version != "0.6.0" || !strings.Contains(rb.Reason, "restarted") {
		t.Fatalf("rollback marker = %+v (ok=%v)", rb, ok)
	}
	if _, err := os.Stat(up.watchdogDir()); !errors.Is(err, os.ErrNotExist) {
		t.Error("a rollback must clean the watchdog copy")
	}
}

// TestWatchdogRollsBackWhenNoAgentEverComesUp covers the second rollback rule:
// the service manager cannot get an agent running at all (the reported fault
// injection: the new binary exits 1 immediately and never takes the lock).
func TestWatchdogRollsBackWhenNoAgentEverComesUp(t *testing.T) {
	up, exe, state := watchdogFixture(t)
	clock := &fakeClock{t: time.Unix(1000, 0)}
	probe := func() (int, bool) { return 0, false }
	h := watchdogBudget(exe, state)
	if err := runWatchdog(context.Background(), h, probe, clock.now, clock.sleep, nopLog{}); err != nil {
		t.Fatalf("runWatchdog: %v", err)
	}
	if got := readFile(t, exe); got != "OLD-BINARY" {
		t.Errorf("exe after the rollback = %q, want the previous binary", got)
	}
	if _, ok := up.Pending(); ok {
		t.Error("a rollback must clear the pending marker")
	}
	rb, ok := up.TakeRollback()
	if !ok || !strings.Contains(rb.Reason, "alive") {
		t.Fatalf("rollback marker = %+v (ok=%v)", rb, ok)
	}
}

// TestWatchdogKeepsAStalledButAliveUpdate covers the "started but cannot reach
// the panel" rule (protocol ruling 11): the deadline passes with an agent that
// is alive and stable, so nothing is rolled back and the backup is kept.
func TestWatchdogKeepsAStalledButAliveUpdate(t *testing.T) {
	up, exe, state := watchdogFixture(t)
	clock := &fakeClock{t: time.Unix(1000, 0)}
	probe := func() (int, bool) { return 7, true } // one pid, never restarted
	h := watchdogBudget(exe, state)
	h.Deadline = 20 * time.Second
	if err := runWatchdog(context.Background(), h, probe, clock.now, clock.sleep, nopLog{}); err != nil {
		t.Fatalf("runWatchdog: %v", err)
	}
	if _, ok := up.Pending(); !ok {
		t.Error("a stalled but alive update must keep its pending marker")
	}
	if got := readFile(t, exe); got != "NEW-BINARY" {
		t.Errorf("exe = %q, want the new binary kept", got)
	}
	if _, err := os.Stat(up.OldPath()); err != nil {
		t.Error("a stalled update must keep the backup for a manual rollback")
	}
	if _, err := os.Stat(up.watchdogDir()); err != nil {
		t.Error("a stalled update must keep the watchdog copy")
	}
	if _, ok := up.TakeRollback(); ok {
		t.Error("a stalled update must not record a rollback")
	}
	if clock.now().Before(time.Unix(1000, 0).Add(20 * time.Second)) {
		t.Error("the watchdog stopped before its deadline")
	}
}

// TestWatchdogRollbackIsIdempotent keeps the second run honest: once the
// pending marker is gone, a watchdog (for example one restarted by the machine)
// does nothing at all.
func TestWatchdogRollbackIsIdempotent(t *testing.T) {
	up, exe, state := watchdogFixture(t)
	if err := up.Rollback("the first watchdog rolled it back"); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if _, ok := up.TakeRollback(); !ok {
		t.Fatal("the first rollback must be recorded")
	}
	probe := func() (int, bool) { return 0, false }
	if err := runWatchdog(context.Background(), watchdogBudget(exe, state), probe, time.Now, func(time.Duration) {}, nopLog{}); err != nil {
		t.Fatalf("a second watchdog = %v, want a no-op", err)
	}
	if got := readFile(t, exe); got != "OLD-BINARY" {
		t.Errorf("exe = %q", got)
	}
	if _, ok := up.TakeRollback(); ok {
		t.Error("a second watchdog must not record a second rollback")
	}
}

// TestLockPIDReadsTheSingleInstanceLock pins the contract with
// cmd/lock_flock.go: the file holds "<pid>\n", and anything else means "no
// agent" rather than a bogus rollback.
func TestLockPIDReadsTheSingleInstanceLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml.lock")
	writeFile(t, path, strconv.Itoa(4242)+"\n")
	if got := lockPID(path); got != 4242 {
		t.Errorf("lockPID = %d, want 4242", got)
	}
	for name, body := range map[string]string{"empty": "", "garbage": "not-a-pid\n"} {
		t.Run(name, func(t *testing.T) {
			writeFile(t, path, body)
			if got := lockPID(path); got != 0 {
				t.Errorf("lockPID(%q) = %d, want 0", body, got)
			}
		})
	}
	if got := lockPID(filepath.Join(dir, "missing.lock")); got != 0 {
		t.Errorf("lockPID(missing) = %d, want 0", got)
	}
	if got := lockPID(""); got != 0 {
		t.Errorf("lockPID(\"\") = %d, want 0", got)
	}
}

// TestWatchdogWithoutALockPathOnlyReportsStalled keeps the missing-probe path
// honest: with no single-instance lock the watchdog cannot tell a dead agent
// from a live one, so it must never roll a good update back.
func TestWatchdogWithoutALockPathOnlyReportsStalled(t *testing.T) {
	up, exe, state := watchdogFixture(t)
	clock := &fakeClock{t: time.Unix(1000, 0)}
	h := watchdogBudget(exe, state)
	h.LockPath = ""
	h.Deadline = 20 * time.Second
	if err := runWatchdog(context.Background(), h, nil, clock.now, clock.sleep, nopLog{}); err != nil {
		t.Fatalf("runWatchdog: %v", err)
	}
	if _, ok := up.Pending(); !ok {
		t.Error("a watchdog with no liveness signal must not roll back")
	}
	if _, err := os.Stat(up.OldPath()); err != nil {
		t.Error("the backup must be kept")
	}
}

// TestCommitCreatesAVerifiedWatchdogCopy covers the copy the watchdog runs
// from: it must exist after Commit, be executable, and match the backup byte
// for byte. Confirm and Rollback both clean it up.
func TestCommitCreatesAVerifiedWatchdogCopy(t *testing.T) {
	up, _, _ := watchdogFixture(t)
	copyPath := up.WatchdogPath()
	if filepath.Base(copyPath) != "W1nCray-0.5.0" {
		t.Errorf("watchdog copy = %s, want it named after the previous version", copyPath)
	}
	fi, err := os.Stat(copyPath)
	if err != nil {
		t.Fatalf("the watchdog copy is missing: %v", err)
	}
	if !isWindows() && fi.Mode().Perm()&0o111 == 0 {
		t.Errorf("the watchdog copy is not executable: %v", fi.Mode())
	}
	wantSum, wantSize, err := hashFile(up.OldPath())
	if err != nil {
		t.Fatal(err)
	}
	gotSum, gotSize, err := hashFile(copyPath)
	if err != nil {
		t.Fatal(err)
	}
	if gotSum != wantSum || gotSize != wantSize {
		t.Errorf("the watchdog copy is not the backup (sha256 %s/%d, want %s/%d)", gotSum, gotSize, wantSum, wantSize)
	}

	if err := up.Confirm(); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if _, err := os.Stat(up.watchdogDir()); !errors.Is(err, os.ErrNotExist) {
		t.Error("Confirm must clean the watchdog copy")
	}

	up2, _, _ := watchdogFixture(t)
	if err := up2.Rollback("test"); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if _, err := os.Stat(up2.watchdogDir()); !errors.Is(err, os.ErrNotExist) {
		t.Error("Rollback must clean the watchdog copy")
	}
}

// TestStartupWatchdogReportsStalledWithoutRollingBack covers "started but
// cannot reach the panel": only an event, never a rollback.
func TestStartupWatchdogReportsStalledWithoutRollingBack(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "W1nCray")
	writeFile(t, exe, "NEW-BINARY")
	state := filepath.Join(dir, "state")
	up, err := New(Options{
		ExePath: exe, StateDir: state, Log: nopLog{}, Ready: func(string) error { return nil },
		ConfirmWindow: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := up.Commit(Staged{Version: "1.0.0", Path: exe, SHA256: sha([]byte("NEW-BINARY"))}); err != nil {
		t.Fatal(err)
	}

	st := up.BeginStartup()
	if p, ok := st.Pending(); !ok || p.Version != "1.0.0" {
		t.Fatalf("startup pending = %+v (ok=%v)", p, ok)
	}
	var kind string
	st.WatchStalled(context.Background(), func(k, level, message string) { kind = k })
	if kind != "self_update.stalled" {
		t.Fatalf("event = %q, want self_update.stalled", kind)
	}
	if _, ok := up.Pending(); !ok {
		t.Error("a stalled update must NOT be rolled back or cleared")
	}
	if got := readFile(t, exe); got != "NEW-BINARY" {
		t.Errorf("exe = %q, want the new binary kept", got)
	}
	if _, err := os.Stat(exe + ".old"); err != nil {
		t.Error("the backup must be kept for a manual rollback")
	}

	// Confirm inside the window keeps the watchdog silent.
	st2 := up.BeginStartup()
	if err := st2.Confirm(); err != nil {
		t.Fatal(err)
	}
	reported := false
	st2.WatchStalled(context.Background(), func(string, string, string) { reported = true })
	if reported {
		t.Error("a confirmed update must not report stalled")
	}
	if _, ok := up.Pending(); ok {
		t.Error("Confirm must clear the pending marker")
	}
}

// TestHelperArgvRoundTrip keeps the watchdog's command line in sync with its
// parser: the values the agent passes are the values the watchdog reads.
func TestHelperArgvRoundTrip(t *testing.T) {
	h := HelperOptions{
		ParentPID: 4242, ExePath: "/usr/bin/W1nCray", StateDir: "/var/lib/W1nCray/state",
		LockPath: "/etc/W1nCray/config.yml.lock", Unit: "W1nCray.service",
		Attempts: 3, AliveWindow: 10 * time.Second, Deadline: 90 * time.Second, PollInterval: 2 * time.Second,
	}
	args := HelperArgv(h.ExePath, []string{"-c", "/etc/W1nCray/config.yml"}, h)
	got, err := ParseHelperArgs(args)
	if err != nil {
		t.Fatalf("ParseHelperArgs: %v", err)
	}
	if got.ParentPID != h.ParentPID || got.ExePath != h.ExePath || got.StateDir != h.StateDir {
		t.Fatalf("parsed = %+v", got)
	}
	if got.LockPath != h.LockPath || got.Unit != h.Unit {
		t.Fatalf("parsed watchdog settings = %+v", got)
	}
	if got.Attempts != 3 || got.AliveWindow != 10*time.Second || got.Deadline != 90*time.Second || got.PollInterval != 2*time.Second {
		t.Fatalf("parsed retry settings = %+v", got)
	}
	if len(got.Argv) != 2 || got.Argv[0] != "-c" || got.Argv[1] != "/etc/W1nCray/config.yml" {
		t.Fatalf("parsed argv = %v", got.Argv)
	}
	// The optional flags disappear when there is nothing to say.
	bare, err := ParseHelperArgs(HelperArgv("/usr/bin/W1nCray", nil, HelperOptions{StateDir: "/s"}))
	if err != nil {
		t.Fatalf("ParseHelperArgs (bare): %v", err)
	}
	if bare.LockPath != "" || bare.Unit != "" {
		t.Errorf("bare helper options = %+v", bare)
	}
	if _, err := ParseHelperArgs([]string{"-bogus", "1", "--"}); err == nil {
		t.Error("an unknown helper option must be refused")
	}
}

// TestWatchdogArgsIsAnArgvArray pins the watchdog's own command line: the
// hidden subcommand first, then the parsed options, and never a shell.
func TestWatchdogArgsIsAnArgvArray(t *testing.T) {
	h := HelperOptions{
		ParentPID: 7, ExePath: "/usr/bin/W1nCray", StateDir: "/s",
		LockPath: "/etc/config.yml.lock", Unit: "W1nCray.service",
		Attempts: 3, AliveWindow: 10 * time.Second, Deadline: 90 * time.Second, PollInterval: 2 * time.Second,
		Argv: []string{"-c", "/etc/W1nCray/config.yml"},
	}
	got := WatchdogArgs(h)
	if got[0] != HelperCommand {
		t.Fatalf("argv[0] = %q, want %q", got[0], HelperCommand)
	}
	if HelperCommand != "__watchdog" {
		t.Errorf("HelperCommand = %q, want __watchdog", HelperCommand)
	}
	// The parser must accept exactly what the builder produced.
	if _, err := ParseHelperArgs(got[1:]); err != nil {
		t.Fatalf("ParseHelperArgs(WatchdogArgs) = %v", err)
	}
	// Nothing is joined into one shell word: every flag and value is its own
	// element and no element carries a separator.
	for _, a := range got {
		if strings.ContainsAny(a, " \t\n;&|$`") {
			t.Errorf("argv element %q looks like a shell command string", a)
		}
	}
}

// TestSystemdRunArgv covers the systemd-run wrapper: the watchdog runs as its
// own transient unit, and the executable and its arguments stay separate argv
// elements (never a shell command string).
func TestSystemdRunArgv(t *testing.T) {
	h := HelperOptions{
		ParentPID: 7, ExePath: "/usr/bin/W1nCray", StateDir: "/var/lib/W1nCray",
		LockPath: "/etc/W1nCray/config.yml.lock", Unit: "W1nCray.service",
		Attempts: 3, AliveWindow: 10 * time.Second, Deadline: 90 * time.Second, PollInterval: 2 * time.Second,
	}
	watchdog := "/var/lib/W1nCray/update/watchdog/W1nCray-0.5.0"
	got := SystemdRunArgv("w1ncray-selfupdate-1700000000", watchdog, WatchdogArgs(h))
	want := []string{
		"systemd-run", "--quiet", "--collect", "--no-block",
		"--unit=w1ncray-selfupdate-1700000000", "--",
		watchdog, "__watchdog",
		"-parent", "7", "-state", "/var/lib/W1nCray", "-exe", "/usr/bin/W1nCray",
		"-attempts", "3", "-window", "10s", "-deadline", "1m30s", "-poll", "2s",
		"-lock", "/etc/W1nCray/config.yml.lock", "-unit", "W1nCray.service", "--",
	}
	if len(got) != len(want) {
		t.Fatalf("argv = %q\nwant %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("argv[%d] = %q, want %q\nfull: %q", i, got[i], want[i], got)
		}
	}
	if n := systemdUnitName(time.Unix(1700000000, 0)); n != "w1ncray-selfupdate-1700000000" {
		t.Errorf("systemdUnitName = %q", n)
	}
}

// TestUseSystemdRunDecision covers when the watchdog can be moved out of the
// service cgroup and when the caller has to fall back to setsid.
func TestUseSystemdRunDecision(t *testing.T) {
	found := func(string) (string, error) { return "/usr/bin/systemd-run", nil }
	missing := func(string) (string, error) { return "", exec.ErrNotFound }
	cases := []struct {
		name         string
		invocationID string
		systemdDir   bool
		look         func(string) (string, error)
		want         bool
	}{
		{"systemd invocation with systemd-run", "abc", false, found, true},
		{"systemd directory with systemd-run", "", true, found, true},
		{"not systemd at all", "", false, found, false},
		{"systemd but no systemd-run", "abc", false, missing, false},
		{"no lookPath", "abc", true, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := useSystemdRun(tc.invocationID, tc.systemdDir, tc.look); got != tc.want {
				t.Errorf("useSystemdRun(%q, %v) = %v, want %v", tc.invocationID, tc.systemdDir, got, tc.want)
			}
		})
	}
}

// TestUnsupportedPlatformIsRefused keeps the Windows path honest: the platform
// reports no support and Ready refuses instead of half-working.
func TestUnsupportedPlatformIsRefused(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the negative platform path is Windows-only")
	}
	if Supported() {
		t.Error("Supported() must be false on Windows")
	}
	if err := Ready("C:/W1nCray.exe"); !errors.Is(err, ErrNotSupported) {
		t.Errorf("Ready = %v, want ErrNotSupported", err)
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, "W1nCray.exe")
	writeFile(t, exe, "OLD")
	up, err := New(Options{ExePath: exe, StateDir: filepath.Join(dir, "state")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := up.Stage(context.Background(), "1.0.0"); !errors.Is(err, ErrNotSupported) {
		t.Errorf("Stage = %v, want ErrNotSupported", err)
	}
	if err := up.Commit(Staged{Version: "1.0.0", Path: exe}); !errors.Is(err, ErrNotSupported) {
		t.Errorf("Commit = %v, want ErrNotSupported", err)
	}
	if got := readFile(t, exe); got != "OLD" {
		t.Errorf("exe = %q, want it untouched", got)
	}
}

// TestSelfUpdateHelperProcess is not a test: it is the child process the
// fault-injection test starts as the new version. It exits 1 for the first N
// invocations (read from a counter file), then stays alive, which is exactly
// "the new binary cannot start, the restored one can". It stays alive for a
// moment before failing so the watchdog can really observe its pid in the
// single-instance lock.
func TestSelfUpdateHelperProcess(t *testing.T) {
	counter := os.Getenv("W1NCRAY_SELFUPDATE_COUNTER")
	if counter == "" {
		return
	}
	fails := 2
	if v := os.Getenv("W1NCRAY_SELFUPDATE_FAILS"); v != "" {
		_, _ = fmt.Sscanf(v, "%d", &fails)
	}
	n := 0
	if b, err := os.ReadFile(counter); err == nil {
		_, _ = fmt.Sscanf(string(b), "%d", &n)
	}
	n++
	_ = os.WriteFile(counter, []byte(strconv.Itoa(n)), 0o600)
	if n <= fails {
		time.Sleep(200 * time.Millisecond)
		os.Exit(1)
	}
	// Longer than the watchdog's poll interval, short enough to keep the test
	// quick.
	time.Sleep(1500 * time.Millisecond)
	os.Exit(0)
}

// TestWatchdogRollsBackARealCrashLoop is the end-to-end fault injection: a real
// subprocess really exits 1 as the new version, a stand-in service manager
// really restarts it and really writes the single-instance lock, and the
// watchdog really reads that lock, counts the restarts and restores exe.old.
func TestWatchdogRollsBackARealCrashLoop(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	name := "W1nCray"
	if runtime.GOOS == "windows" {
		name += ".exe" // os/exec needs the extension to run a copied binary
	}
	exe := filepath.Join(dir, name)
	if err := copyFile(self, exe, 0o755); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(dir, "staged")
	if err := copyFile(self, staged, 0o755); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state")
	lock := filepath.Join(dir, "config.yml.lock")
	counter := filepath.Join(dir, "counter")
	up, err := New(Options{
		ExePath: exe, StateDir: state, Log: nopLog{}, Ready: func(string) error { return nil },
		AgentVersion: "0.5.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := up.Commit(Staged{Version: "0.6.0", Path: staged, SHA256: sha(mustRead(t, staged))}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	t.Setenv("W1NCRAY_SELFUPDATE_COUNTER", counter)
	t.Setenv("W1NCRAY_SELFUPDATE_FAILS", "2")

	// The stand-in service manager: Restart=always. It starts the new binary,
	// records its pid in the single-instance lock (what the real agent does in
	// run()) and restarts it whenever it dies.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			//nolint:noshell -- exe is a copy of this test binary, run with an
			// argv array, never a shell.
			cmd := exec.Command(exe, "-test.run=TestSelfUpdateHelperProcess")
			cmd.Env = os.Environ()
			if err := cmd.Start(); err != nil {
				return
			}
			_ = os.WriteFile(lock, []byte(strconv.Itoa(cmd.Process.Pid)+"\n"), 0o600)
			_ = cmd.Wait()
			time.Sleep(20 * time.Millisecond)
		}
	}()

	h := HelperOptions{
		ExePath: exe, StateDir: state, LockPath: lock,
		Attempts: 2, AliveWindow: 2 * time.Second, Deadline: 30 * time.Second,
		PollInterval: 10 * time.Millisecond,
	}
	runErr := RunHelper(context.Background(), h, nopLog{})
	close(stop)
	wg.Wait()
	if runErr != nil {
		t.Fatalf("RunHelper: %v", runErr)
	}

	if got, want := sha(mustRead(t, exe)), sha(mustRead(t, self)); got != want {
		t.Errorf("exe after the rollback is not the previous binary (sha256 %s, want %s)", got, want)
	}
	if _, ok := up.Pending(); ok {
		t.Error("the rollback must clear the pending marker")
	}
	rb, ok := up.TakeRollback()
	if !ok || rb.Version != "0.6.0" {
		t.Fatalf("rollback marker = %+v (ok=%v)", rb, ok)
	}
	// A platform with a real liveness probe counts the crash loop's restarts;
	// Windows has none (self_update is refused there anyway), so the same real
	// crash loop is caught by the "no agent alive" rule.
	if runtime.GOOS == "windows" {
		if !strings.Contains(rb.Reason, "alive") {
			t.Errorf("rollback reason = %q, want the no-agent-alive rule", rb.Reason)
		}
	} else if !strings.Contains(rb.Reason, "restarted") {
		t.Errorf("rollback reason = %q, want the restart rule", rb.Reason)
	}
	if _, err := os.Stat(up.watchdogDir()); !errors.Is(err, os.ErrNotExist) {
		t.Error("the rollback must clean the watchdog copy")
	}
	if got := string(mustRead(t, counter)); got == "0" || got == "1" {
		t.Errorf("the new binary was started %s time(s); the crash loop did not run", got)
	}
	// The stand-in service manager may still be running the restored binary
	// for a moment; wait for it to exit so the temporary directory can be
	// removed (Windows keeps a running image locked).
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if err := os.Remove(exe); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
