// The manifest-free self-update path (v0.8.0): the panel pins the release
// asset and the agent builds the conventional GitHub release URL itself,
// never consulting the signed manifest. The manifest path (Stage) stays the
// fallback for agents that predate this protocol and for the boot sequence a
// manifest still performs (plan 24).

package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/W1nCwC/W1nCray/kernel/install"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
)

// releaseURLBase is the GitHub release the conventional asset URL is built
// from. A constant, exactly like the panel's: the scheme+host is the trust
// anchor of the direct path, so it is not configurable.
const releaseURLBase = "https://github.com/W1nCwC/W1nCray/releases/download"

// ReleaseURL is the conventional release asset of one version for one
// platform: v<ver>/w1ncray-v<ver>-<goos>-<goarch>.gz. goos/goarch are passed
// in (not taken from runtime) so tests can pin them.
func ReleaseURL(version, goos, goarch string) string {
	v := manifest.NormalizeVersion(version)
	asset := fmt.Sprintf("w1ncray-v%s-%s-%s.gz", v, goos, goarch)
	return releaseURLBase + "/v" + v + "/" + asset
}

// ReleaseURLFor is ReleaseURL for the running process's platform.
func ReleaseURLFor(version string) string {
	return ReleaseURL(version, runtime.GOOS, runtime.GOARCH)
}

// DirectStager is the optional manifest-free staging capability of the
// installer (kernel/install.StageAgentDirect). The Updater uses it when the
// self_update command carries a sha256: the command then builds the
// conventional release URL and stages straight from it.
type DirectStager interface {
	// StageAgentDirect downloads ad.URL and extracts the single gzip member
	// into dest (which must be empty), self-checking that the binary reports
	// ad.Version. It returns the path of the staged binary.
	StageAgentDirect(ctx context.Context, ad install.AgentDirect, archiveDir, dest string) (string, error)
}

// StageDirect is the direct-path counterpart of Stage: the same guards (Ready,
// no pending update, fresh staging directory) and the same Staged result, but
// the archive comes from url and only the archive-level sha256 (when
// non-empty) pins the bytes. The member hash is computed from what was
// extracted, exactly as a manifest install records it in its marker.
func (u *Updater) StageDirect(ctx context.Context, version, url, sha256 string) (Staged, error) {
	if err := u.Ready(); err != nil {
		return Staged{}, err
	}
	ds, ok := u.installer.(DirectStager)
	if !ok {
		return Staged{}, ErrNoInstaller
	}
	version = manifest.NormalizeVersion(version)
	if version == "" {
		return Staged{}, errors.New("selfupdate: a version is required")
	}
	if p, ok := u.Pending(); ok {
		return Staged{}, fmt.Errorf("%w (version %s committed at %s)", ErrPending, p.Version, p.At.UTC().Format(time.RFC3339))
	}
	stagedDir := u.stagedVersionDir(version)
	if err := os.RemoveAll(stagedDir); err != nil {
		return Staged{}, err
	}
	if err := os.MkdirAll(stagedDir, 0o700); err != nil {
		return Staged{}, err
	}
	bin, err := ds.StageAgentDirect(ctx, install.AgentDirect{
		Version: version, URL: url, SHA256: strings.ToLower(strings.TrimSpace(sha256)),
	}, filepath.Join(u.dir, "archive"), stagedDir)
	if err != nil {
		_ = os.RemoveAll(stagedDir)
		return Staged{}, err
	}
	sum, size, err := hashFile(bin)
	if err != nil {
		_ = os.RemoveAll(stagedDir)
		return Staged{}, err
	}
	u.log.Infof("selfupdate: staged agent@%s (direct) at %s", version, bin)
	return Staged{Version: version, Path: bin, SHA256: sum, Size: size}, nil
}
