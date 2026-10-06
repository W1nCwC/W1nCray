package filesync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/spec"
)

// Result statuses (the cmd.result body of files_apply / files_validate /
// files_rollback).
const (
	StatusDone       = "done"
	StatusFailed     = "failed"
	StatusInvalid    = "invalid"
	StatusRolledBack = "rolled_back"
)

// Reload outcomes.
const (
	ReloadReloaded  = "reloaded"
	ReloadNotNeeded = "not_needed"
	ReloadFailed    = "failed"
)

// Reload reasons reported to the reloader.
const (
	ReasonApply    = "managed files applied"
	ReasonRollback = "managed files rolled back"
)

// BlobFetcher fetches one managed file's content by its sha256. The production
// implementation is the panel HTTP client (GET /file/<sha256> with
// If-None-Match); tests substitute a fake or a real server.
type BlobFetcher interface {
	// Fetch returns the content of the blob with this sha256 and whether the
	// panel answered "not modified" (the cached copy is then current). When
	// notModified is true, content must be ignored.
	Fetch(ctx context.Context, sha string) (content []byte, notModified bool, err error)
}

// BlobFetcherFunc adapts a function to BlobFetcher.
type BlobFetcherFunc func(ctx context.Context, sha string) ([]byte, bool, error)

// Fetch implements BlobFetcher.
func (f BlobFetcherFunc) Fetch(ctx context.Context, sha string) ([]byte, bool, error) {
	return f(ctx, sha)
}

// Reloader asks the running instance to pick up the new files. The production
// implementation is the panel's ReloadForAgent, which validates the config and
// serialises the reload; a validation failure returns an error and never shuts
// the instance down (ruling 2).
type Reloader interface {
	Reload(ctx context.Context, reason string) error
}

// ReloaderFunc adapts a function to Reloader.
type ReloaderFunc func(ctx context.Context, reason string) error

// Reload implements Reloader.
func (f ReloaderFunc) Reload(ctx context.Context, reason string) error { return f(ctx, reason) }

// Source reports the managed files of the desired state the agent last
// accepted. The files_apply and files_validate commands carry no arguments: the
// panel first publishes the revision and then asks for it to be applied
// (docs/WS-PROTOCOL.md section 4).
type Source interface {
	DesiredFiles() []spec.FileRef
}

// SourceFunc adapts a function to Source.
type SourceFunc func() []spec.FileRef

// DesiredFiles implements Source.
func (f SourceFunc) DesiredFiles() []spec.FileRef { return f() }

// Options configures an Applier. ConfigDir, StateDir, Fetch and Validate are
// required.
type Options struct {
	// ConfigDir is the xray configuration directory: the only place a managed
	// file is ever written (D5).
	ConfigDir string
	// StateDir holds the blob cache, the staging directories and last_good.
	StateDir string
	// Fetch fetches one blob by its sha256.
	Fetch BlobFetcher
	// Validate pre-checks a staged file set (never nil in production).
	Validate Validator
	// Reload asks the running instance to rebuild. Nil means this agent cannot
	// reload (a file change is then refused rather than half-applied).
	Reload Reloader
	// Source reports the managed files of the last desired state.
	Source Source
	// ConfigPath is the live config.yml; it is only used for logging.
	ConfigPath string
	// LayoutSeparated reports whether the machine uses the agent.yml layout
	// (ruling 2): config.yml is only managed when the agent's own
	// configuration lives in agent.yml, because writing it otherwise would
	// overwrite the agent's own settings.
	LayoutSeparated bool
	// MaxBytes is the largest blob accepted for one file. 0 means the default
	// (DefaultMaxBytes); a negative value refuses geo files locally (the
	// OpenWrt default, design section 3.6), which is reported as "geo files
	// disabled by local policy" instead of being silently skipped.
	MaxBytes int64
	// MaxGeoBytes overrides MaxBytes for geoip.dat and geosite.dat. 0 means
	// MaxBytes.
	MaxGeoBytes int64
	// Now is the clock; nil uses time.Now.
	Now func() time.Time
	// Log receives the applier's events; never a file's content.
	Log driver.Logger
}

// DefaultMaxBytes is the per-file blob limit when Options.MaxBytes is 0.
const DefaultMaxBytes = 64 << 20 // 64 MiB

// Result is the outcome of an apply or a rollback, and the JSON body the panel
// receives as cmd.result.
type Result struct {
	// Status is "done" for an applied (or already-current) set, "invalid" when
	// validation refused the files, "rolled_back" when the previous files were
	// restored, "failed" otherwise.
	Status string `json:"status"`
	// Files lists every managed file the panel asked for with the sha256 now in
	// place. Bytes is what was actually transferred this time (0 = cache hit or
	// already current).
	Files []FileResult `json:"files,omitempty"`
	// Reload is "reloaded", "not_needed" (geo-only change) or "failed".
	Reload string `json:"reload,omitempty"`
	// RolledBack is true when the previous files were restored.
	RolledBack bool `json:"rolled_back,omitempty"`
	// Reason is the human-readable cause of a rollback or a failure.
	Reason string `json:"reason,omitempty"`
	// Errors lists the validation or replacement problems.
	Errors []string `json:"errors,omitempty"`
}

// FileResult is one managed file in a Result.
type FileResult struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Bytes  int64  `json:"bytes,omitempty"`
	// Skipped is true when the file was already exactly this content (same
	// sha256 on disk): nothing was downloaded, replaced or reloaded for it.
	Skipped bool `json:"skipped,omitempty"`
}

// appliedState is the persisted record of the last applied file set. It is what
// makes a repeated files_apply cheap: every file whose sha256 still matches is
// neither downloaded nor replaced.
type appliedState struct {
	Schema int               `json:"schema"`
	At     time.Time         `json:"at"`
	Files  map[string]string `json:"files"`
}

// appliedSchema is the version of applied.json.
const appliedSchema = 1

// appliedName is the state file inside the filesync state directory.
const appliedName = "applied.json"

// Applier is the managed-file sync: stage, validate, replace, reload. It is
// safe for concurrent use; one apply runs at a time.
type Applier struct {
	opts  Options
	store *Store
	log   driver.Logger

	// mu serialises the applies, so two files_apply calls can never interleave
	// their staging and replacement.
	mu sync.Mutex
	// wireMu guards the wiring (opts.Fetch, opts.Reload, opts.Validate,
	// opts.Source) that bootstrap installs once the panel link exists. It is a
	// lock of its own because an apply holds mu for its whole run.
	wireMu sync.Mutex
}

// New builds an Applier. It creates the state directory but touches no managed
// file.
func New(o Options) (*Applier, error) {
	if o.ConfigDir == "" {
		return nil, errors.New("filesync: ConfigDir is required")
	}
	if o.StateDir == "" {
		return nil, errors.New("filesync: StateDir is required")
	}
	if o.Fetch == nil {
		return nil, errors.New("filesync: a blob fetcher is required")
	}
	if o.Validate == nil {
		return nil, errors.New("filesync: a validator is required")
	}
	st, err := Open(o.StateDir)
	if err != nil {
		return nil, err
	}
	log := o.Log
	if log == nil {
		log = nopLog{}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Applier{opts: o, store: st, log: log}, nil
}

type nopLog struct{}

func (nopLog) Debugf(string, ...any) {}
func (nopLog) Infof(string, ...any)  {}
func (nopLog) Warnf(string, ...any)  {}
func (nopLog) Errorf(string, ...any) {}

// Files returns the managed files of the last desired state (nil when no source
// is wired).
func (a *Applier) Files() []spec.FileRef {
	if a == nil || a.opts.Source == nil {
		return nil
	}
	return a.opts.Source.DesiredFiles()
}

// SetFetch installs the blob fetcher. It exists because the fetcher is the
// panel HTTP client, which only exists once the panel link is built; before
// that a blob request fails with a clear error instead of panicking.
func (a *Applier) SetFetch(f BlobFetcher) {
	a.wireMu.Lock()
	a.opts.Fetch = f
	a.wireMu.Unlock()
}

// SetReload installs the reloader (the panel's ReloadForAgent).
func (a *Applier) SetReload(r Reloader) {
	a.wireMu.Lock()
	a.opts.Reload = r
	a.wireMu.Unlock()
}

// SetValidator installs the pre-check (the panel's core validator).
func (a *Applier) SetValidator(v Validator) {
	a.wireMu.Lock()
	a.opts.Validate = v
	a.wireMu.Unlock()
}

// SetSource installs the desired-state source the file commands read.
func (a *Applier) SetSource(s Source) {
	a.wireMu.Lock()
	a.opts.Source = s
	a.wireMu.Unlock()
}

// wiring returns the fetch, validate and reload functions under one lock, so an
// apply sees a consistent set.
func (a *Applier) wiring() (BlobFetcher, Validator, Reloader, Source) {
	a.wireMu.Lock()
	defer a.wireMu.Unlock()
	return a.opts.Fetch, a.opts.Validate, a.opts.Reload, a.opts.Source
}

// LayoutSeparated reports whether the agent.yml layout is in use on this
// machine (config.yml is only managed then).
func (a *Applier) LayoutSeparated() bool { return a.opts.LayoutSeparated }

// maxBytesFor returns the per-file limit for one name.
func (a *Applier) maxBytesFor(name string) int64 {
	limit := a.opts.MaxBytes
	if limit == 0 {
		limit = DefaultMaxBytes
	}
	if IsGeo(name) && a.opts.MaxGeoBytes != 0 {
		limit = a.opts.MaxGeoBytes
	}
	return limit
}

// plan is one requested file, checked and resolved.
type plan struct {
	ref spec.FileRef
	// needStage is false when the file on disk is already exactly this content.
	needStage bool
	// current is the sha256 on disk ("" when the file is not there).
	current string
}

// Apply stages, validates, replaces and reloads the given managed files.
//
// Nothing is written before every file has been fetched, hash-checked and
// validated; the previous content is snapshotted as last_good before the first
// replacement; and a reload failure restores the snapshot. A validation failure
// never replaces a file and never reloads (design section 3.4).
func (a *Applier) Apply(ctx context.Context, refs []spec.FileRef) (Result, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// The desired-state file set is a whole: the panel decides which files are
	// managed, so a request that names nothing is a protocol error, not "apply
	// nothing".
	if len(refs) == 0 {
		return Result{}, errors.New("filesync: no managed files in the desired state")
	}
	fetch, validate, reload, _ := a.wiring()
	if validate == nil {
		return Result{}, errors.New("filesync: no validator is wired")
	}

	plans, errs := a.plan(refs)
	if len(errs) > 0 {
		return Result{Status: StatusFailed, Errors: errs}, nil
	}

	// Files already exactly in place are neither downloaded nor replaced.
	var stage []plan
	result := make([]FileResult, 0, len(plans))
	for _, p := range plans {
		if !p.needStage {
			result = append(result, FileResult{Name: p.ref.Name, SHA256: p.ref.SHA256, Size: p.ref.Size, Skipped: true})
			continue
		}
		stage = append(stage, p)
	}

	if len(stage) == 0 {
		// Everything the panel asked for is already on disk. Record it, so the
		// next call short-circuits the same way, and answer without touching the
		// instance.
		a.remember(plans)
		a.log.Infof("filesync: %d managed file(s) already current; nothing to do", len(plans))
		return Result{Status: StatusDone, Files: result, Reload: ReloadNotNeeded}, nil
	}

	a.store.PruneStages()
	stageDir, err := a.store.NewStage()
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = a.store.DiscardStage(stageDir) }()

	downloaded := map[string]int64{}
	for _, p := range stage {
		_, n, err := a.content(ctx, fetch, p.ref)
		if err != nil {
			return Result{Status: StatusFailed, Errors: []string{err.Error()}}, nil
		}
		downloaded[p.ref.Name] = n
		if err := a.store.StageBlob(stageDir, p.ref.Name, p.ref.SHA256); err != nil {
			return Result{Status: StatusFailed, Errors: []string{err.Error()}}, nil
		}
	}

	// Validation runs on the staged copies, before a single managed file is
	// touched. The four JSON files are checked one by one and then as a whole
	// instance; a staged config.yml goes through the full LoadConfig.
	staged := make([]FileRef, 0, len(stage))
	for _, p := range stage {
		staged = append(staged, p.ref)
	}
	if verrs := validate.ValidateStaged(ctx, stageDir, staged); len(verrs) > 0 {
		for _, e := range verrs {
			errs = append(errs, e.Error())
		}
		a.log.Warnf("filesync: refusing %d staged file(s): %s", len(staged), strings.Join(errs, "; "))
		return Result{Status: StatusInvalid, Errors: errs}, nil
	}

	names := make([]string, 0, len(stage))
	for _, p := range stage {
		names = append(names, p.ref.Name)
	}
	if err := a.store.SnapshotLastGood(a.opts.ConfigDir, names); err != nil {
		return Result{}, err
	}

	replaced := make([]string, 0, len(stage))
	for _, p := range stage {
		content, err := os.ReadFile(filepath.Join(stageDir, p.ref.Name))
		if err != nil {
			a.restoreAfterFailure(replaced)
			return Result{Status: StatusFailed, Errors: []string{err.Error()}}, nil
		}
		if err := ReplaceFile(a.opts.ConfigDir, p.ref.Name, content, 0o644); err != nil {
			a.restoreAfterFailure(replaced)
			return Result{Status: StatusFailed, Errors: []string{err.Error()}}, nil
		}
		replaced = append(replaced, p.ref.Name)
		result = append(result, FileResult{Name: p.ref.Name, SHA256: p.ref.SHA256, Size: p.ref.Size, Bytes: downloaded[p.ref.Name]})
	}

	// Every file is in place. A geo-only change needs no reload: xray reads the
	// databases when it evaluates a rule, so the next connection picks them up
	// (design section 3.5).
	needsReload := NeedsRebuildAll(names)
	res := Result{Status: StatusDone, Files: result}
	if !needsReload {
		res.Reload = ReloadNotNeeded
		a.remember(plans)
		a.log.Infof("filesync: applied %d geo file(s); no reload needed", len(names))
		return res, nil
	}
	if reload == nil {
		a.restoreAfterFailure(replaced)
		return Result{
			Status:     StatusFailed,
			RolledBack: true,
			Reason:     "this agent cannot reload the instance",
			Errors:     []string{"filesync: no reloader is wired; the files were restored"},
		}, nil
	}
	if err := reload.Reload(ctx, ReasonApply); err != nil {
		a.log.Warnf("filesync: reload refused after the replacement: %v; restoring the previous files", err)
		restored, rerr := a.store.RestoreLastGood(a.opts.ConfigDir)
		if rerr != nil {
			return Result{
				Status: StatusFailed,
				Reload: ReloadFailed,
				Reason: err.Error(),
				Errors: []string{rerr.Error()},
			}, nil
		}
		a.log.Infof("filesync: restored %d managed file(s) from last_good", len(restored))
		// The reloader already refused this configuration; asking it again with
		// the restored files would be a guess. The restore is reported and the
		// panel decides (ruling 9: health is judged on the panel side).
		return Result{
			Status:     StatusRolledBack,
			RolledBack: true,
			Reload:     ReloadFailed,
			Reason:     err.Error(),
			Files:      result,
		}, nil
	}
	res.Reload = ReloadReloaded
	a.remember(plans)
	a.log.Infof("filesync: applied %d managed file(s) and initiated a reload", len(names))
	return res, nil
}

// Validate stages and validates the desired file set without writing or
// reloading anything (the files_validate command).
func (a *Applier) Validate(ctx context.Context) (Result, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	refs := a.Files()
	if len(refs) == 0 {
		return Result{}, errors.New("filesync: no managed files in the desired state")
	}
	fetch, validate, _, _ := a.wiring()
	if validate == nil {
		return Result{}, errors.New("filesync: no validator is wired")
	}
	plans, errs := a.plan(refs)
	if len(errs) > 0 {
		return Result{Status: StatusFailed, Errors: errs}, nil
	}
	a.store.PruneStages()
	stageDir, err := a.store.NewStage()
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = a.store.DiscardStage(stageDir) }()

	result := make([]FileResult, 0, len(plans))
	staged := make([]FileRef, 0, len(plans))
	for _, p := range plans {
		if !p.needStage {
			result = append(result, FileResult{Name: p.ref.Name, SHA256: p.ref.SHA256, Size: p.ref.Size, Skipped: true})
			continue
		}
		if _, _, err := a.content(ctx, fetch, p.ref); err != nil {
			return Result{Status: StatusFailed, Errors: []string{err.Error()}}, nil
		}
		if err := a.store.StageBlob(stageDir, p.ref.Name, p.ref.SHA256); err != nil {
			return Result{Status: StatusFailed, Errors: []string{err.Error()}}, nil
		}
		staged = append(staged, p.ref)
		result = append(result, FileResult{Name: p.ref.Name, SHA256: p.ref.SHA256, Size: p.ref.Size})
	}
	if len(staged) > 0 {
		if verrs := validate.ValidateStaged(ctx, stageDir, staged); len(verrs) > 0 {
			for _, e := range verrs {
				errs = append(errs, e.Error())
			}
			return Result{Status: StatusInvalid, Files: result, Errors: errs}, nil
		}
	}
	return Result{Status: StatusDone, Files: result, Reload: ReloadNotNeeded}, nil
}

// Rollback restores the last_good snapshot and reloads the instance. It is what
// the panel sends after a managed-file change left the machine unhealthy
// (protocol ruling 9).
func (a *Applier) Rollback(ctx context.Context) (Result, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.store.HasLastGood() {
		return Result{}, errors.New("filesync: no last_good snapshot to roll back to")
	}
	_, _, reload, _ := a.wiring()
	names, err := a.store.RestoreLastGood(a.opts.ConfigDir)
	if err != nil {
		return Result{}, err
	}
	res := Result{Status: StatusRolledBack, RolledBack: true}
	for _, n := range names {
		st, ok, err := StateOf(a.opts.ConfigDir, n)
		if err != nil || !ok {
			continue
		}
		res.Files = append(res.Files, FileResult{Name: n, SHA256: st.SHA256, Size: st.Size})
	}
	if NeedsRebuildAll(names) {
		if reload == nil {
			res.Reload = ReloadFailed
			res.Reason = "this agent cannot reload the instance"
			return res, nil
		}
		if err := reload.Reload(ctx, ReasonRollback); err != nil {
			res.Reload = ReloadFailed
			res.Reason = err.Error()
			return res, nil
		}
		res.Reload = ReloadReloaded
	} else {
		res.Reload = ReloadNotNeeded
	}
	// The restored files are the good ones now; a second rollback has nothing
	// left to restore.
	_ = a.store.DropLastGood()
	a.forget(names)
	a.log.Infof("filesync: rolled back %d managed file(s)", len(names))
	return res, nil
}

// content returns the content of one file: from the blob cache when the digest
// is already there, otherwise fetched, re-hashed and verified. The returned
// count is what was actually transferred (0 on a cache hit). A blob that fails
// its sha256 or size check is never cached and never staged (design section 3.4
// step 1).
func (a *Applier) content(ctx context.Context, fetch BlobFetcher, ref spec.FileRef) ([]byte, int64, error) {
	if fetch == nil {
		return nil, 0, errors.New("filesync: the panel link is not up yet, no blob can be fetched")
	}
	if p, ok := a.store.Get(ref.SHA256); ok {
		b, err := os.ReadFile(p)
		if err == nil && Digest(b) == ref.SHA256 {
			return b, 0, nil
		}
		// A corrupt cache entry is discarded and fetched again.
		a.log.Warnf("filesync: cached blob %s does not hash back; fetching it again", ref.SHA256)
		_ = os.Remove(p)
	}
	content, notModified, err := fetch.Fetch(ctx, ref.SHA256)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: fetching blob %s: %w", ref.Name, ref.SHA256, err)
	}
	if notModified {
		// The panel says the machine already has these bytes, but the cache does
		// not: the cache was pruned or lost. One retry without the validator
		// tag brings the body.
		content, notModified, err = fetch.Fetch(ctx, ref.SHA256)
		if err != nil {
			return nil, 0, fmt.Errorf("%s: fetching blob %s: %w", ref.Name, ref.SHA256, err)
		}
		if notModified {
			return nil, 0, fmt.Errorf("%s: the panel answered 304 but the blob is not cached", ref.Name)
		}
	}
	limit := a.maxBytesFor(ref.Name)
	if int64(len(content)) > limit {
		return nil, 0, fmt.Errorf("%s: the blob is %d bytes, over the %d byte limit for this file", ref.Name, len(content), limit)
	}
	if got := Digest(content); got != ref.SHA256 {
		return nil, 0, fmt.Errorf("%s: sha256 mismatch: the panel served %s, the desired state says %s", ref.Name, got, ref.SHA256)
	}
	if ref.Size > 0 && int64(len(content)) != ref.Size {
		return nil, 0, fmt.Errorf("%s: size mismatch: the panel served %d bytes, the desired state says %d", ref.Name, len(content), ref.Size)
	}
	if _, err := a.store.Put(ref.SHA256, content); err != nil {
		return nil, 0, err
	}
	return content, int64(len(content)), nil
}

// plan validates every requested file and decides which ones have to be staged.
func (a *Applier) plan(refs []spec.FileRef) ([]plan, []string) {
	var errs []string
	seen := map[string]bool{}
	out := make([]plan, 0, len(refs))
	for _, ref := range refs {
		if err := CheckName(ref.Name); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if seen[ref.Name] {
			errs = append(errs, fmt.Sprintf("%s: named twice in the desired state", ref.Name))
			continue
		}
		seen[ref.Name] = true
		if !ValidSHA256(ref.SHA256) {
			errs = append(errs, fmt.Sprintf("%s: %q is not a sha256 digest", ref.Name, ref.SHA256))
			continue
		}
		if ref.Size < 0 {
			errs = append(errs, fmt.Sprintf("%s: size must not be negative", ref.Name))
			continue
		}
		if IsGeo(ref.Name) && a.maxBytesFor(ref.Name) < 0 {
			errs = append(errs, fmt.Sprintf("%s: geo files disabled by local policy", ref.Name))
			continue
		}
		if ref.Size > 0 && ref.Size > a.maxBytesFor(ref.Name) {
			errs = append(errs, fmt.Sprintf("%s: the desired size %d is over the %d byte limit for this file", ref.Name, ref.Size, a.maxBytesFor(ref.Name)))
			continue
		}
		if ref.Name == NameConfig && !a.opts.LayoutSeparated {
			errs = append(errs, fmt.Sprintf("%s: refused: the agent's own configuration still lives in config.yml (no agent.yml next to it)", NameConfig))
			continue
		}
		st, ok, err := StateOf(a.opts.ConfigDir, ref.Name)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		p := plan{ref: ref, needStage: true}
		if ok {
			p.current = st.SHA256
			if st.SHA256 == ref.SHA256 && (ref.Size == 0 || st.Size == ref.Size) {
				p.needStage = false
			}
		}
		out = append(out, p)
	}
	return out, errs
}

// restoreAfterFailure puts the snapshot back after a replacement failed halfway
// through. It reports the outcome in the log: the caller returns a failure
// result either way.
func (a *Applier) restoreAfterFailure(replaced []string) {
	if len(replaced) == 0 || !a.store.HasLastGood() {
		return
	}
	if _, err := a.store.RestoreLastGood(a.opts.ConfigDir); err != nil {
		a.log.Errorf("filesync: restoring last_good after a failed replacement: %v", err)
	}
}

// remember persists the sha256 of every managed file of the last good set, so a
// repeated apply does not download or replace what is already there.
func (a *Applier) remember(plans []plan) {
	st := appliedState{Schema: appliedSchema, At: a.opts.Now(), Files: map[string]string{}}
	for _, p := range plans {
		st.Files[p.ref.Name] = p.ref.SHA256
	}
	if err := writeFileAtomic(filepath.Join(a.store.Dir(), appliedName), mustJSON(st), 0o600); err != nil {
		a.log.Warnf("filesync: recording the applied file set: %v", err)
	}
}

// forget drops one or more names from the applied record.
func (a *Applier) forget(names []string) {
	st, ok := a.loadApplied()
	if !ok {
		return
	}
	for _, n := range names {
		delete(st.Files, n)
	}
	st.At = a.opts.Now()
	if err := writeFileAtomic(filepath.Join(a.store.Dir(), appliedName), mustJSON(st), 0o600); err != nil {
		a.log.Warnf("filesync: recording the applied file set: %v", err)
	}
}

// loadApplied reads the applied record.
func (a *Applier) loadApplied() (appliedState, bool) {
	raw, err := os.ReadFile(filepath.Join(a.store.Dir(), appliedName))
	if err != nil {
		return appliedState{}, false
	}
	var st appliedState
	if err := json.Unmarshal(raw, &st); err != nil {
		return appliedState{}, false
	}
	if st.Schema > appliedSchema {
		return appliedState{}, false
	}
	return st, true
}

// mustJSON marshals v; a value that cannot be marshalled yields "{}".
func mustJSON(v any) []byte {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return []byte("{}")
	}
	return b
}
