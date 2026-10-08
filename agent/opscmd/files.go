// This file registers the managed-file commands: files_apply, files_validate
// and files_rollback (docs/WS-PROTOCOL.md section 7 ruling 9). The heavy
// lifting (blob download, staging, validation, atomic replacement, last_good
// rollback) lives in agent/filesync; this file only maps the commands onto it
// and shapes the results for the panel.
//
// files_apply is a long command: it answers "accepted" immediately and delivers
// its final result through the registry's sink, exactly like kernel_install.

package opscmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/W1nCwC/W1nCray/agent/filesync"
	"github.com/W1nCwC/W1nCray/agent/panelclient"
)

// FilesOps is the managed-file surface the commands need. It is declared here
// so this package does not depend on the panel link (which imports it back) and
// so tests can substitute a fake.
type FilesOps interface {
	// Apply stages, validates, replaces and reloads the managed files of the
	// last desired state. A returned error is a protocol-level failure (no
	// desired state, no applier); an invalid or refused file set comes back as
	// a Result with a non-done status and no error.
	Apply(ctx context.Context) (filesync.Result, error)
	// Validate stages and validates without writing or reloading.
	Validate(ctx context.Context) (filesync.Result, error)
	// Rollback restores the last good managed files and reloads.
	Rollback(ctx context.Context) (filesync.Result, error)
}

// filesCmds holds the managed-file handlers. The implementation is read from
// the registry on every call, because it is installed once the panel link (and
// with it the blob fetcher) exists.
type filesCmds struct {
	reg *Registry
}

// registerFiles adds the managed-file commands. A registry without a file
// applier still registers them: the answer is then an explicit "not_supported",
// never a silent no-op (protocol ruling 5).
func registerFiles(r *Registry, d Deps) error {
	f := &filesCmds{reg: r}
	for _, c := range []struct {
		typ string
		h   Handler
	}{
		{panelclient.CmdFilesApply, f.filesApply},
		{panelclient.CmdFilesValidate, f.filesValidate},
		{panelclient.CmdFilesRollback, f.filesRollback},
	} {
		if err := r.Register(c.typ, c.h); err != nil {
			return err
		}
	}
	return nil
}

// errNoFiles is the answer when the managed-file layer is not wired on this
// agent (no panel link, or a local policy that forbids it).
var errNoFiles = coded("not_supported", errors.New("managed files are not wired on this agent"))

// filesApply answers files_apply. It is a long command: the blob download (up
// to tens of megabytes), the validation and the reload all take time, so the
// panel gets "accepted" within its ttl and the outcome later (ruling 7).
func (f *filesCmds) filesApply(ctx context.Context, req Request, complete Completion) (Result, error) {
	ops := f.reg.filesOps()
	if ops == nil {
		return Result{}, errNoFiles
	}
	var args struct {
		// Revision is the desired revision the panel published the files in
		// (optional; older panels send no args).
		Revision int64 `json:"revision"`
	}
	if err := decodeArgs(req.Args, &args); err != nil {
		return Result{}, err
	}
	f.reg.logf().Infof("opscmd: files_apply accepted")
	go func() {
		if args.Revision > 0 {
			if err := f.waitDesired(ctx, args.Revision); err != nil {
				f.reg.logf().Warnf("opscmd: files_apply: %v", err)
				complete(StatusFailed, nil, err)
				return
			}
		}
		res, err := ops.Apply(ctx)
		if err != nil {
			f.reg.logf().Warnf("opscmd: files_apply failed: %v", err)
			complete(StatusFailed, nil, err)
			return
		}
		f.reg.logf().Infof("opscmd: files_apply %s (reload %s, %d file(s))", res.Status, res.Reload, len(res.Files))
		if res.Status == filesync.StatusDone {
			f.reg.event("files.applied", "info", fmt.Sprintf("applied %d managed file(s) (%s)", len(res.Files), res.Reload))
		}
		complete(StatusDone, filesApplyResult(res), nil)
	}()
	return accepted(), nil
}

// desiredWait bounds how long files_apply waits for its revision to arrive.
var desiredWait = 30 * time.Second

// waitDesired returns once the applied desired state is at least rev, pulling
// immediately instead of waiting for the next poll. Without a desired-state
// view it returns nil (the apply then uses what the agent has, as before).
func (f *filesCmds) waitDesired(ctx context.Context, rev int64) error {
	s := f.reg.desiredSync()
	if s == nil {
		return nil
	}
	deadline := time.Now().Add(desiredWait)
	for {
		have := s.DesiredRevision()
		if have >= rev {
			return nil
		}
		if time.Now().After(deadline) {
			return coded("stale_desired", fmt.Errorf("desired revision %d has not been applied on this machine (it has %d); the managed files were not applied", rev, have))
		}
		s.RequestRefresh()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
}

// filesApplyResult renders the apply outcome. applied_pending is the contract's
// signal that the reload was initiated and the panel now judges health itself:
// the agent never waits for it in-process (protocol ruling 9, design section
// 6.2).
func filesApplyResult(res filesync.Result) json.RawMessage {
	body := map[string]any{
		"status": res.Status,
		"reload": res.Reload,
	}
	if len(res.Files) > 0 {
		body["files"] = res.Files
	}
	if len(res.Errors) > 0 {
		body["errors"] = res.Errors
	}
	if res.RolledBack {
		body["rolled_back"] = true
	}
	if res.Reason != "" {
		body["reason"] = res.Reason
	}
	// The reload was asked for (successfully or not): from here on the panel
	// watches hello/telemetry and sends files_rollback when the machine does not
	// come back.
	if res.Status == filesync.StatusDone && res.Reload == filesync.ReloadReloaded {
		body["applied_pending"] = true
	}
	return mustJSON(body)
}

// filesValidate answers files_validate: stage and check only. Nothing is
// written and nothing is reloaded, so a panel can show the errors before it
// publishes a revision.
func (f *filesCmds) filesValidate(ctx context.Context, req Request, complete Completion) (Result, error) {
	ops := f.reg.filesOps()
	if ops == nil {
		return Result{}, errNoFiles
	}
	res, err := ops.Validate(ctx)
	if err != nil {
		return Result{}, err
	}
	f.reg.logf().Infof("opscmd: files_validate %s (%d error(s))", res.Status, len(res.Errors))
	return done(res), nil
}

// filesRollback answers files_rollback: restore the last good managed files and
// reload. The panel sends it when the machine did not recover after an apply.
func (f *filesCmds) filesRollback(ctx context.Context, req Request, complete Completion) (Result, error) {
	ops := f.reg.filesOps()
	if ops == nil {
		return Result{}, errNoFiles
	}
	res, err := ops.Rollback(ctx)
	if err != nil {
		return Result{}, err
	}
	f.reg.logf().Infof("opscmd: files_rollback %s (%d file(s) restored)", res.Status, len(res.Files))
	f.reg.event("files.rolled_back", "warn", fmt.Sprintf("restored %d managed file(s) from last_good", len(res.Files)))
	return done(res), nil
}
