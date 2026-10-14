package install

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/W1nCwC/W1nCray/kernel"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
	"github.com/W1nCwC/W1nCray/kernel/platform"
)

// directFixture is a manifest-less installer over a local HTTP server: the
type directFixture struct {
	t    *testing.T
	in   *Installer
	plat platform.Info
}

func newDirectFixture(t *testing.T, allowHTTP bool) *directFixture {
	t.Helper()
	plat := platform.Info{GOOS: "linux", GOARCH: "amd64", Libc: "glibc"}
	in, err := New(Config{
		Dir: t.TempDir(), Platform: &plat, AllowHTTP: allowHTTP, Check: fakeCheck,
		FreeSpace:  func(string) (uint64, bool) { return 1 << 40, true },
		RetryDelay: 0, StallTimeout: 5 * 1e9,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &directFixture{t: t, in: in, plat: plat}
}

func TestInstallDirectGzInstallsAndSwitches(t *testing.T) {
	f := newDirectFixture(t, true)
	bin := fakeBin("3.0.0", 512)
	archive := mkGz(t, bin)
	fs := newFileServer(t)
	url := fs.put("/gost-3.0.0.gz", archive)

	inst, err := f.in.InstallDirect(context.Background(), DirectInstall{
		Name: "gost", Version: "3.0.0", URL: url,
		SHA256: sum(archive), Size: int64(len(archive)),
	})
	if err != nil {
		t.Fatalf("InstallDirect: %v", err)
	}
	if inst.Version != "3.0.0" || inst.Path == "" {
		t.Errorf("installed = %+v", inst)
	}
	// The result is indistinguishable from a manifest install.
	entries, err := f.in.List()
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range entries {
		if e.Name == "gost" && e.Version == "3.0.0" && e.Current {
			found = true
		}
	}
	if !found {
		t.Errorf("gost@3.0.0 is not the current entry: %+v", entries)
	}
	if b, err := os.ReadFile(inst.Path); err != nil || string(b) != string(bin) {
		t.Errorf("installed binary differs (err %v)", err)
	}
}

// The archive-level hash is the anchor of the direct path: a wrong hash is
// refused before anything is extracted and nothing is installed.
func TestInstallDirectRefusesWrongHashAndScheme(t *testing.T) {
	f := newDirectFixture(t, true)
	bin := fakeBin("3.0.0", 512)
	archive := mkGz(t, bin)
	fs := newFileServer(t)
	url := fs.put("/gost-3.0.0.gz", archive)

	cases := []struct {
		name   string
		sha    string
		size   int64
		modURL string
		want   string
	}{
		{"wrong sha256", strings.Repeat("ab", 32), int64(len(archive)), "", "verify_failed"},
		{"wrong size", sum(archive), int64(len(archive)) + 1, "", "verify_failed"},
		{"http refused without AllowHTTP", sum(archive), 0, "", "verify_failed"},
	}
	for _, tc := range cases[:2] {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := f.in.InstallDirect(context.Background(), DirectInstall{
				Name: "gost", Version: "3.0.0", URL: url, SHA256: tc.sha, Size: tc.size,
			}); err == nil || kernel.Code(err) != tc.want {
				t.Fatalf("err = %v, want code %q", err, tc.want)
			}
			if l, _ := f.in.List(); len(l) != 0 {
				t.Errorf("a refused install must not touch the kernel directory: %+v", l)
			}
		})
	}
	t.Run("http refused without AllowHTTP", func(t *testing.T) {
		g := newDirectFixture(t, false)
		httpsURL := strings.Replace(url, "http://", "http://", 1)
		if _, err := g.in.InstallDirect(context.Background(), DirectInstall{
			Name: "gost", Version: "3.0.0", URL: httpsURL, SHA256: sum(archive),
		}); err == nil || kernel.Code(err) != "verify_failed" {
			t.Fatalf("err = %v, want code verify", err)
		}
	})
}

// A tar.gz direct install takes the named member (From) and installs it under
// the kernel's default binary name.
func TestInstallDirectTarGz(t *testing.T) {
	f := newDirectFixture(t, true)
	bin := fakeBin("4.1.0", 512)
	archive := mkTarGz(t, tarEntry{Name: "realm-x86_64", Data: bin}, tarEntry{Name: "README", Data: []byte("hi")})
	fs := newFileServer(t)
	url := fs.put("/realm.tar.gz", archive)

	inst, err := f.in.InstallDirect(context.Background(), DirectInstall{
		Name: "realm", Version: "4.1.0", URL: url,
		SHA256: sum(archive), Archive: manifest.ArchiveTarGz,
		From: "realm-x86_64", To: "realm",
	})
	if err != nil {
		t.Fatalf("InstallDirect: %v", err)
	}
	if inst.Version != "4.1.0" {
		t.Errorf("version = %q", inst.Version)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(inst.Path), "README")); err == nil {
		t.Error("an unlisted member must not be extracted")
	}
}

// An archive whose version self-check disagrees with the declared version is
// refused, exactly like a manifest install (VerifyArchiveFor).
func TestInstallDirectRefusesWrongVersion(t *testing.T) {
	f := newDirectFixture(t, true)
	archive := mkGz(t, fakeBin("9.9.9", 64))
	fs := newFileServer(t)
	url := fs.put("/gost-1.0.0.gz", archive)
	if _, err := f.in.InstallDirect(context.Background(), DirectInstall{
		Name: "gost", Version: "1.0.0", URL: url, SHA256: sum(archive),
	}); err == nil || kernel.Code(err) != "check_failed" {
		t.Fatalf("err = %v, want code check", err)
	}
}

// StageAgentDirect is the self-update staging path: download, extract, and
// self-check against the requested version.
func TestStageAgentDirect(t *testing.T) {
	f := newDirectFixture(t, true)
	bin := fakeBin("0.9.0", 512)
	archive := mkGz(t, bin)
	fs := newFileServer(t)
	url := fs.put("/w1ncray-v0.9.0-linux-amd64.gz", archive)

	dest := t.TempDir()
	archiveDir := t.TempDir()
	path, err := f.in.StageAgentDirect(context.Background(),
		AgentDirect{Version: "0.9.0", URL: url, SHA256: sum(archive)}, archiveDir, dest)
	if err != nil {
		t.Fatalf("StageAgentDirect: %v", err)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != string(bin) {
		t.Errorf("staged binary differs (err %v)", err)
	}

	t.Run("wrong sha256 is refused", func(t *testing.T) {
		if _, err := f.in.StageAgentDirect(context.Background(),
			AgentDirect{Version: "0.9.0", URL: url, SHA256: strings.Repeat("cd", 32)}, t.TempDir(), t.TempDir()); err == nil {
			t.Fatal("a wrong archive hash must be refused")
		}
	})
	t.Run("wrong version is refused", func(t *testing.T) {
		if _, err := f.in.StageAgentDirect(context.Background(),
			AgentDirect{Version: "1.0.0", URL: url, SHA256: sum(archive)}, t.TempDir(), t.TempDir()); err == nil || kernel.Code(err) != "check_failed" {
			t.Fatalf("err = %v, want code check", err)
		}
	})
}

// DefaultKernelRun is the built-in run block of the known kernels; an unknown
// kernel has none and must be named explicitly by the caller.
func TestDefaultKernelRun(t *testing.T) {
	if r := DefaultKernelRun("gost"); r.Binary != "gost" || len(r.VersionCmd) == 0 {
		t.Errorf("gost run = %+v", r)
	}
	if r := DefaultKernelRun("nosuch"); r.Binary != "" {
		t.Errorf("unknown kernel run = %+v", r)
	}
	if AgentRun.VersionRegex == "" || AgentRun.Binary == "" {
		t.Error("AgentRun must carry the agent's own self-check")
	}
}
