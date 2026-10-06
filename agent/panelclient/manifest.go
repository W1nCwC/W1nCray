// This file implements the signed kernel manifest sync loop: the Runner
// periodically fetches GET /manifest from the panel and hands the body to a
// ManifestSink, which verifies it locally before anything is written.
//
// Trust model: the transport (the panel) is not trusted. The panel may serve
// any bytes; only the sink's local verification decides whether a manifest is
// accepted. A rejected document is logged and dropped: it is never persisted,
// never replaces the manifest in force and never touches the running
// instances.

package panelclient

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// ErrNoManifest is returned by Client.Manifest when the panel has not published
// a manifest yet (404). It is a normal state, not a failure.
var ErrNoManifest = errors.New("panelclient: the panel has no kernel manifest")

// ManifestSink accepts a signed manifest document. The implementation must
// verify it (signature, expiry, sequence) and keep the previous manifest in
// force when the check fails; kernelx.Ensurer is the production sink.
type ManifestSink interface {
	LoadManifest(raw []byte) error
}

// manifestSequencer is the optional part of a ManifestSink that reports the
// sequence of the manifest now in force; the Runner logs it when available.
type manifestSequencer interface {
	ManifestSequence() (int64, bool)
}

// DefaultManifestInterval is the manifest poll interval when none is
// configured.
const DefaultManifestInterval = time.Hour

// MinManifestInterval and MaxManifestInterval clamp the configured interval.
const (
	MinManifestInterval = 5 * time.Minute
	MaxManifestInterval = 24 * time.Hour
)

// manifestJitterFraction is the +/- randomisation applied to the manifest wait.
// The task asks for 10%; the pull and report loops use 20%.
const manifestJitterFraction = 0.1

// ClampManifestInterval returns DefaultManifestInterval for d <= 0 and
// otherwise d limited to [MinManifestInterval, MaxManifestInterval].
func ClampManifestInterval(d time.Duration) time.Duration {
	switch {
	case d <= 0:
		return DefaultManifestInterval
	case d < MinManifestInterval:
		return MinManifestInterval
	case d > MaxManifestInterval:
		return MaxManifestInterval
	}
	return d
}

// manifestLoop fetches the manifest immediately, then every manifestEvery
// (jittered by +/-10%). A transport failure backs off; a document the sink
// rejects is logged and dropped, and the loop keeps its normal cadence. It
// returns when ctx ends.
func (r *Runner) manifestLoop(ctx context.Context) {
	var bo backoff
	var delay time.Duration // the first fetch happens immediately
	for first := true; ; first = false {
		if !first && !r.wait(ctx, delay, false) {
			return
		}
		if ctx.Err() != nil {
			return
		}
		err := r.safely("manifest", func() error { return r.manifestOnce(ctx) })
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			delay = r.jitterBy(bo.fail(), manifestJitterFraction)
			r.log.Warnf("panel: kernel manifest sync failed, retrying in %s: %v", delay.Round(time.Second), err)
		default:
			bo.reset()
			delay = r.jitterBy(r.manifestEvery, manifestJitterFraction)
		}
	}
}

// manifestOnce is one GET /manifest round: fetch, verify through the sink and,
// only on success, persist the accepted document and remember its ETag.
func (r *Runner) manifestOnce(ctx context.Context) error {
	res, err := r.api.Manifest(ctx, ManifestRequest{ETag: r.manifestTag()})
	if errors.Is(err, ErrNoManifest) {
		r.log.Debugf("panel: no kernel manifest published yet")
		return nil
	}
	if err != nil {
		return err
	}
	if res.NotModified {
		r.log.Debugf("panel: kernel manifest unchanged")
		return nil
	}

	// The sink verifies the document. A failure must not touch the manifest in
	// force, the persisted copy or the ETag; only the (content-free) error is
	// logged.
	if err := r.manifest.LoadManifest(res.Raw); err != nil {
		r.log.Warnf("panel: rejected the kernel manifest from the panel: %v", err)
		return nil
	}
	if r.manifestPath != "" {
		if err := writeManifestFile(r.manifestPath, res.Raw); err != nil {
			// The manifest is already in force; persisting it is for the next
			// start. Keep the old ETag so the round is retried.
			r.log.Warnf("panel: persisting the kernel manifest to %s: %v", r.manifestPath, err)
			return nil
		}
	}
	r.setManifestTag(res.ETag)
	if s, ok := r.manifest.(manifestSequencer); ok {
		if seq, ok := s.ManifestSequence(); ok {
			r.log.Infof("panel: kernel manifest sequence %d is in force", seq)
			return nil
		}
	}
	r.log.Infof("panel: the kernel manifest from the panel is in force")
	return nil
}

func (r *Runner) manifestTag() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.manifestETag
}

func (r *Runner) setManifestTag(tag string) {
	r.mu.Lock()
	r.manifestETag = tag
	r.mu.Unlock()
}

// writeManifestFile writes raw to path with mode 0600 through a temporary file
// in the same directory and a rename, so a crash never leaves a half-written
// manifest. It mirrors kernel/install's atomic writer.
func writeManifestFile(path string, raw []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".manifest-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := func() { _ = os.Remove(name) }
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	// os.CreateTemp already uses 0600; on Windows the permission bits carry no
	// meaning (access is by ACL), so a failing Chmod is tolerated there.
	if err := os.Chmod(name, 0o600); err != nil && runtime.GOOS != "windows" {
		cleanup()
		return err
	}
	if err := os.Rename(name, path); err != nil {
		cleanup()
		return err
	}
	return nil
}
