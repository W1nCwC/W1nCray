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
	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/filesync"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/agent/xrayapi"
	"github.com/W1nCwC/W1nCray/config"
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
		// is the panel HTTP client. The validator is the Xray kernel when it
		// is installed (Options.Xray) and a nil-safe refusal otherwise, so an
		// unwired call fails with a clear message instead of a nil panic.
		Fetch: filesync.BlobFetcherFunc(func(context.Context, string) ([]byte, bool, error) {
			return nil, false, errors.New("filesync: the panel link is not up yet")
		}),
		Validate: filesValidator(o.Xray),
		// The reloader waits for the kernel to report the fingerprint of the
		// files just written (PLAN v11 §C). Without a kernel service there is
		// nothing to wait for and the layer refuses a reload that needs one.
		Reload: filesReloader(o.Xray, f.ConfigPath, o.Log),
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

// filesValidator returns the managed-file validator: the Xray kernel service
// when it is installed, and a nil-safe refusal otherwise. A machine without the
// kernel must answer with an explicit reason instead of half-applying a file
// set no running instance would pick up.
func filesValidator(svc xrayapi.Service) filesync.Validator {
	if svc == nil {
		return filesync.ValidatorFunc(func(context.Context, string, []filesync.FileRef) []error {
			return []error{errors.New("Xray 内核未安装")}
		})
	}
	return xrayValidator{svc: svc}
}

// xrayValidator adapts the Xray kernel service to the managed-file validator:
// the kernel pre-checks a staged file set with its own configuration loader.
type xrayValidator struct{ svc xrayapi.Service }

// ValidateStaged asks the kernel to check the staged files and flattens its
// JSON error list into the validator's []error.
func (v xrayValidator) ValidateStaged(ctx context.Context, dir string, files []filesync.FileRef) []error {
	names := make([]string, 0, len(files))
	for _, f := range files {
		names = append(names, f.Name)
	}
	res, err := v.svc.CheckStaged(ctx, dir, names)
	if err != nil {
		return []error{err}
	}
	if res.OK {
		return nil
	}
	errs := make([]error, 0, len(res.Errors))
	for _, e := range res.Errors {
		if e.File == "" {
			errs = append(errs, errors.New(e.Message))
			continue
		}
		errs = append(errs, fmt.Errorf("%s: %s", e.File, e.Message))
	}
	if len(errs) == 0 {
		errs = append(errs, errors.New("the Xray kernel refused the staged files"))
	}
	return errs
}

// filesReloader returns the managed-file reloader: the Xray kernel service
// when it is installed, and nil (a reload is then refused) otherwise.
func filesReloader(svc xrayapi.Service, configPath string, log driver.Logger) filesync.Reloader {
	if svc == nil || configPath == "" {
		return nil
	}
	return xrayReloader{svc: svc, configPath: configPath, log: log}
}

// xrayReloader waits for the kernel to pick up the managed files it just
// received. It computes the content fingerprint of the kernel's watched files
// with exactly the code the kernel uses (config.Fingerprint over
// config.WatchedFiles), so the two can never disagree, and waits (30s) for the
// kernel's status endpoint to report it.
type xrayReloader struct {
	svc        xrayapi.Service
	configPath string
	log        driver.Logger
}

// Reload implements filesync.Reloader.
func (r xrayReloader) Reload(ctx context.Context, reason string) error {
	cfg, err := config.LoadConfigFile(r.configPath)
	if err != nil {
		return fmt.Errorf("读取 %s 以计算配置指纹: %w", r.configPath, err)
	}
	fp := config.Fingerprint(cfg.WatchedFiles(r.configPath))
	if r.log != nil {
		r.log.Infof("filesync: 等待 Xray 内核重载配置（%s）", reason)
	}
	return r.svc.WaitReloaded(ctx, fp)
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
