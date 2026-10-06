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
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
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

// TestRunHelperRollsBackAfterRepeatedStartFailures is the fault injection of
// acceptance item 7: the new binary exits immediately, the helper retries three
// times, restores exe.old and starts it.
func TestRunHelperRollsBackAfterRepeatedStartFailures(t *testing.T) {
	f := newFixture(t)
	srv := serve(t, nil)
	data := fakeBin("1.0.0", 64)
	url := srv.url("/a.gz", gz(t, data))
	dir := t.TempDir()
	exe := filepath.Join(dir, "W1nCray")
	writeFile(t, exe, "OLD-BINARY")
	state := filepath.Join(dir, "state")
	up := f.updater(exe, state, f.installer(agentKernel{Version: "1.0.0", Data: data, URL: url}))

	staged, err := up.Stage(context.Background(), "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := up.Commit(staged); err != nil {
		t.Fatal(err)
	}

	var (
		calls  int
		sawOld bool
	)
	start := func(path string, argv []string, window time.Duration) error {
		calls++
		if calls == 1 {
			if got := readFile(t, path); got != string(data) {
				t.Errorf("the first attempt did not run the new binary")
			}
		}
		if got := readFile(t, path); got == "OLD-BINARY" {
			sawOld = true
			return nil // the restored binary comes up
		}
		return errors.New("exit status 1")
	}
	sleep := func(time.Duration) {}

	err = runHelper(context.Background(), HelperOptions{
		ExePath: exe, StateDir: state, Attempts: 3, RetryDelay: time.Millisecond, AliveWindow: time.Millisecond,
	}, start, sleep, nopLog{})
	if err != nil {
		t.Fatalf("runHelper: %v", err)
	}
	if calls != 4 {
		t.Errorf("start called %d times, want 3 attempts + 1 recovery", calls)
	}
	if !sawOld {
		t.Error("the helper never ran the restored binary")
	}
	if got := readFile(t, exe); got != "OLD-BINARY" {
		t.Errorf("exe after the rollback = %q", got)
	}
	if _, ok := up.Pending(); ok {
		t.Error("the rollback must clear the pending marker")
	}
	rb, ok := up.TakeRollback()
	if !ok || rb.Version != "1.0.0" {
		t.Fatalf("rollback marker = %+v (ok=%v)", rb, ok)
	}
	if rb.Reason == "" {
		t.Error("the rollback reason must be recorded")
	}
}

// TestRunHelperGivesUpWhenTheNewBinarySurvives covers the happy path: one start
// that stays alive ends the helper without a rollback.
func TestRunHelperGivesUpWhenTheNewBinarySurvives(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	exe := filepath.Join(dir, "W1nCray")
	writeFile(t, exe, "NEW-BINARY")
	state := filepath.Join(dir, "state")
	up := f.updater(exe, state, nil)
	if err := up.Commit(Staged{Version: "1.0.0", Path: exe, SHA256: sha([]byte("NEW-BINARY"))}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	calls := 0
	start := func(string, []string, time.Duration) error { calls++; return nil }
	if err := runHelper(context.Background(), HelperOptions{
		ExePath: exe, StateDir: state, Attempts: 3, AliveWindow: time.Millisecond,
	}, start, func(time.Duration) {}, nopLog{}); err != nil {
		t.Fatalf("runHelper: %v", err)
	}
	if calls != 1 {
		t.Errorf("start called %d times, want 1", calls)
	}
	if _, ok := up.Pending(); !ok {
		t.Error("a surviving start must leave the confirmation to the new process")
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

// TestHelperArgvRoundTrip keeps the helper's command line in sync with its
// parser: the values the agent passes are the values the helper reads.
func TestHelperArgvRoundTrip(t *testing.T) {
	h := HelperOptions{
		ParentPID: 4242, ExePath: "/usr/bin/W1nCray", StateDir: "/var/lib/W1nCray/state",
		Attempts: 3, RetryDelay: 5 * time.Second, AliveWindow: 10 * time.Second,
	}
	args := HelperArgv(h.ExePath, []string{"-c", "/etc/W1nCray/config.yml"}, h)
	got, err := ParseHelperArgs(args)
	if err != nil {
		t.Fatalf("ParseHelperArgs: %v", err)
	}
	if got.ParentPID != h.ParentPID || got.ExePath != h.ExePath || got.StateDir != h.StateDir {
		t.Fatalf("parsed = %+v", got)
	}
	if got.Attempts != 3 || got.RetryDelay != 5*time.Second || got.AliveWindow != 10*time.Second {
		t.Fatalf("parsed retry settings = %+v", got)
	}
	if len(got.Argv) != 2 || got.Argv[0] != "-c" || got.Argv[1] != "/etc/W1nCray/config.yml" {
		t.Fatalf("parsed argv = %v", got.Argv)
	}
	if _, err := ParseHelperArgs([]string{"-bogus", "1", "--"}); err == nil {
		t.Error("an unknown helper option must be refused")
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
// fault-injection test starts. It exits 1 for the first N invocations (read
// from a counter file), then stays alive, which is exactly "the new binary
// cannot start, the restored one can".
func TestSelfUpdateHelperProcess(t *testing.T) {
	counter := os.Getenv("W1NCRAY_SELFUPDATE_COUNTER")
	if counter == "" {
		return
	}
	n := 0
	if b, err := os.ReadFile(counter); err == nil {
		_, _ = fmt.Sscanf(string(b), "%d", &n)
	}
	n++
	_ = os.WriteFile(counter, []byte(strconv.Itoa(n)), 0o600)
	if n <= 2 {
		os.Exit(1)
	}
	time.Sleep(800 * time.Millisecond)
	os.Exit(0)
}

// TestRunHelperRecoversWithRealProcesses is the end-to-end fault injection of
// acceptance item 7: the staged binary really exits 1 (a child of this test
// binary), the helper really retries, really restores exe.old and really starts
// it. The counter file makes the third start survive.
func TestRunHelperRecoversWithRealProcesses(t *testing.T) {
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
	counter := filepath.Join(dir, "counter")
	up, err := New(Options{ExePath: exe, StateDir: state, Log: nopLog{}, Ready: func(string) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := up.Commit(Staged{Version: "1.0.0", Path: staged, SHA256: sha(mustRead(t, staged))}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	t.Setenv("W1NCRAY_SELFUPDATE_COUNTER", counter)

	h := HelperOptions{
		ExePath: exe, StateDir: state, Attempts: 2,
		RetryDelay: 10 * time.Millisecond, AliveWindow: 150 * time.Millisecond,
		Argv: []string{"-test.run=TestSelfUpdateHelperProcess"},
	}
	if err := RunHelper(context.Background(), h, nopLog{}); err != nil {
		t.Fatalf("RunHelper: %v", err)
	}
	if _, err := os.Stat(exe); err != nil {
		t.Fatalf("the executable is missing after the rollback: %v", err)
	}
	if _, ok := up.Pending(); ok {
		t.Error("the rollback must clear the pending marker")
	}
	if rb, ok := up.TakeRollback(); !ok || rb.Version != "1.0.0" || rb.Reason == "" {
		t.Fatalf("rollback marker = %+v (ok=%v)", rb, ok)
	}
	if got := string(mustRead(t, counter)); got == "1" || got == "0" {
		t.Errorf("the new binary was started %s time(s); the helper did not retry", got)
	}
	// The restored binary survived the window and keeps running for a moment;
	// wait for it to exit so the temporary directory can be removed (Windows
	// keeps a running image locked).
	deadline := time.Now().Add(5 * time.Second)
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
