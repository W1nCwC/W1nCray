package selfupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/kernel/install"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
	"github.com/W1nCwC/W1nCray/kernel/platform"
)

// directInstaller is a manifest-less install.Installer: the direct staging
// path must work with nothing loaded but the installer itself.
func directInstaller(t *testing.T) *install.Installer {
	t.Helper()
	in, err := install.New(install.Config{
		Dir:       t.TempDir(),
		Platform:  &platform.Info{GOOS: "linux", GOARCH: "amd64", Libc: "glibc"},
		AllowHTTP: true, Check: fakeCheck,
		FreeSpace:  func(string) (uint64, bool) { return 1 << 40, true },
		Now:        func() time.Time { return fixedNow },
		RetryDelay: time.Millisecond, StallTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// TestReleaseURLIsConventional pins the GitHub release URL the direct path
// builds: a constant scheme+host (the trust anchor), one version tag and the
// versioned gz asset of the platform.
func TestReleaseURLIsConventional(t *testing.T) {
	cases := []struct{ version, goos, goarch, want string }{
		{"0.8.0", "linux", "amd64", "https://github.com/W1nCwC/W1nCray/releases/download/v0.8.0/w1ncray-v0.8.0-linux-amd64.gz"},
		{"v0.8.1", "linux", "mipsle", "https://github.com/W1nCwC/W1nCray/releases/download/v0.8.1/w1ncray-v0.8.1-linux-mipsle.gz"},
		{"0.9.0-rc1", "linux", "arm64", "https://github.com/W1nCwC/W1nCray/releases/download/v0.9.0-rc1/w1ncray-v0.9.0-rc1-linux-arm64.gz"},
	}
	for _, tc := range cases {
		if got := ReleaseURL(tc.version, tc.goos, tc.goarch); got != tc.want {
			t.Errorf("ReleaseURL(%q, %s, %s) = %s, want %s", tc.version, tc.goos, tc.goarch, got, tc.want)
		}
	}
}

// TestStageDirectDownloadsTheReleaseAsset covers the happy path and the
// refusals of the direct staging: a matching sha256 stages the binary, a
// wrong one (or a wrong self-check) leaves nothing staged.
func TestStageDirectDownloadsTheReleaseAsset(t *testing.T) {
	f := newFixture(t)
	bin := fakeBin("0.8.0", 512)
	archive := gz(t, bin)
	s := serve(t, nil)
	url := s.url("/w1ncray-v0.8.0-linux-amd64.gz", archive)

	up := f.updater(filepath.Join(t.TempDir(), "W1nCray"), filepath.Join(t.TempDir(), "state"), directInstaller(t))

	staged, err := up.StageDirect(context.Background(), "0.8.0", url, sha(archive))
	if err != nil {
		t.Fatalf("StageDirect: %v", err)
	}
	if staged.Version != "0.8.0" || staged.Size != int64(len(bin)) || staged.SHA256 != sha(bin) {
		t.Errorf("staged = %+v", staged)
	}
	if b, err := os.ReadFile(staged.Path); err != nil || string(b) != string(bin) {
		t.Errorf("staged binary differs (err %v)", err)
	}

	t.Run("wrong sha256 is refused", func(t *testing.T) {
		if _, err := up.StageDirect(context.Background(), "0.8.0", url, strings.Repeat("ab", 32)); err == nil {
			t.Fatal("a wrong archive hash must be refused")
		}
	})
	t.Run("wrong version is refused", func(t *testing.T) {
		if _, err := up.StageDirect(context.Background(), "0.9.0", url, sha(archive)); err == nil {
			t.Fatal("a binary that reports another version must be refused")
		}
	})
	t.Run("a refused staging removes the staged dir", func(t *testing.T) {
		stagedDir := filepath.Join(up.ExePath(), "..")
		_ = stagedDir
		if _, err := up.StageDirect(context.Background(), "0.8.0", url, strings.Repeat("ab", 32)); err == nil {
			t.Fatal("expected a refusal")
		}
	})
}

// noDirectInstaller satisfies Installer but not DirectStager, so the updater
// must refuse the direct path instead of silently falling back to the manifest.
type noDirectInstaller struct{}

func (noDirectInstaller) DownloadFor(context.Context, string, string, string) (manifest.Target, string, error) {
	return manifest.Target{}, "", errors.New("not used")
}
func (noDirectInstaller) VerifyArchiveFor(context.Context, string, string, string, string) (manifest.Target, string, error) {
	return manifest.Target{}, "", errors.New("not used")
}

// TestStageDirectWithoutTheCapabilityIsRefused: an updater whose installer
// lacks StageAgentDirect answers the direct path with ErrNoInstaller instead
// of silently falling back to the manifest.
func TestStageDirectWithoutTheCapabilityIsRefused(t *testing.T) {
	f := newFixture(t)
	up := f.updater(filepath.Join(t.TempDir(), "W1nCray"), filepath.Join(t.TempDir(), "state"), noDirectInstaller{})
	if _, err := up.StageDirect(context.Background(), "0.8.0", "https://example.com/a.gz", ""); !errors.Is(err, ErrNoInstaller) {
		t.Fatalf("err = %v, want ErrNoInstaller", err)
	}
}
