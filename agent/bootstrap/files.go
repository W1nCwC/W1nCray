// This file wires the managed-file sync (agent/filesync) into the booted
// runtime: the applier is built at Boot (the configuration and state
// directories are known then) and completed once the panel link exists (the
// blob fetcher is the panel HTTP client). It is what makes files_apply /
// files_validate / files_rollback servable, and what turns a "files" hint into
// the same apply.

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/W1nCwC/W1nCray/agent/agentcfg"
	"github.com/W1nCwC/W1nCray/agent/filesync"
	"github.com/W1nCwC/W1nCray/agent/spec"
)

// FilesOptions is the local policy of the managed-file layer, translated from
// agent.yml by the panel (bootstrap never reads the config file itself).
type FilesOptions struct {
	// ConfigDir is the xray configuration directory: the only place a managed
	// file is written.
	ConfigDir string
	// ConfigPath is the live config.yml (used to decide whether config.yml may
	// be managed at all).
	ConfigPath string
	// StateDir is where the blob cache, the staging directories and last_good
	// live. Default: <agent StateDir>/filesync.
	StateDir string
	// MaxBytes / MaxGeoBytes are the per-file blob limits (see
	// agentcfg.FilesConfig).
	MaxBytes    int64
	MaxGeoBytes int64
	// LayoutSeparated reports whether the machine uses the agent.yml layout
	// (ruling 2): config.yml is only managed then.
	LayoutSeparated bool
}

// FilesRuntime is the managed-file applier plus the policy decisions the rest
// of the agent needs (the "files" capability, the files hint).
type FilesRuntime struct {
	applier *filesync.Applier
	// cfg is the local agent configuration the policy gates are read from.
	cfg *agentcfg.Config
}

// newFilesRuntime builds the managed-file layer when the local policy allows
// it. It returns nil when no xray configuration directory is known, so a
// runtime built by hand (tests, agent-apply) simply has no file commands.
func newFilesRuntime(o Options) *FilesRuntime {
	f := o.Files
	if f == nil || f.ConfigDir == "" {
		return nil
	}
	stateDir := f.StateDir
	if stateDir == "" {
		stateDir = filepath.Join(o.StateDir, "filesync")
	}
	applier, err := filesync.New(filesync.Options{
		ConfigDir:       f.ConfigDir,
		StateDir:        stateDir,
		ConfigPath:      f.ConfigPath,
		LayoutSeparated: f.LayoutSeparated,
		MaxBytes:        f.MaxBytes,
		MaxGeoBytes:     f.MaxGeoBytes,
		// Fetch, Validate, Reload and Source are installed later: the fetcher
		// is the panel HTTP client and the validator/reloader belong to the
		// panel. The placeholders keep the applier constructible and make an
		// unwired call fail with a clear message instead of a nil panic.
		Fetch: filesync.BlobFetcherFunc(func(context.Context, string) ([]byte, bool, error) {
			return nil, false, errors.New("filesync: the panel link is not up yet")
		}),
		Validate: filesync.ValidatorFunc(func(context.Context, string, []filesync.FileRef) []error {
			return []error{errors.New("filesync: no validator is wired")}
		}),
		Source: filesync.SourceFunc(func() []spec.FileRef { return nil }),
		Log:    o.Log,
	})
	if err != nil {
		// A bad state directory is a configuration problem; the caller logs it
		// and the machine simply has no managed-file commands.
		if o.Log != nil {
			o.Log.Warnf("bootstrap: managed files are disabled: %v", err)
		}
		return nil
	}
	return &FilesRuntime{applier: applier, cfg: o.AgentConfig}
}

// applierOrNil returns the applier, or an error when the managed-file layer is
// not configured on this machine.
func (f *FilesRuntime) applierOrNil() (*filesync.Applier, error) {
	if f == nil || f.applier == nil {
		return nil, errors.New("filesync: managed files are not configured on this machine")
	}
	return f.applier, nil
}

// Enabled reports whether this machine serves the managed-file commands.
func (f *FilesRuntime) Enabled() bool { return f != nil && f.applier != nil }

// LayoutSeparated reports whether config.yml is a managed file on this machine.
func (f *FilesRuntime) LayoutSeparated() bool {
	return f != nil && f.applier != nil && f.applier.LayoutSeparated()
}

// Apply implements opscmd.FilesOps.
func (f *FilesRuntime) Apply(ctx context.Context) (filesync.Result, error) {
	a, err := f.applierOrNil()
	if err != nil {
		return filesync.Result{}, err
	}
	return a.Apply(ctx, a.Files())
}

// Validate implements opscmd.FilesOps.
func (f *FilesRuntime) Validate(ctx context.Context) (filesync.Result, error) {
	a, err := f.applierOrNil()
	if err != nil {
		return filesync.Result{}, err
	}
	return a.Validate(ctx)
}

// Rollback implements opscmd.FilesOps.
func (f *FilesRuntime) Rollback(ctx context.Context) (filesync.Result, error) {
	a, err := f.applierOrNil()
	if err != nil {
		return filesync.Result{}, err
	}
	return a.Rollback(ctx)
}

// SyncFiles is the "files" hint: it applies the managed files of the last
// desired state. It returns an error only when the apply could not run at all
// or was refused; a validation refusal is reported as an error too, so the
// panel sees an explicit answer instead of silence (ruling 5).
func (f *FilesRuntime) SyncFiles(ctx context.Context) error {
	res, err := f.Apply(ctx)
	if err != nil {
		return err
	}
	if res.Status != filesync.StatusDone && res.Status != filesync.StatusRolledBack {
		return fmt.Errorf("managed files: %s: %v", res.Status, res.Errors)
	}
	return nil
}
