// This file registers the self_update command. It is a separate entry point
// (not part of opscmd.Deps) because it needs the updater and a way to ask the
// process to exit, which only bootstrap has: bootstrap installs it once the
// updater and the restart hook exist.
//
// The command is long: it answers "accepted" immediately and delivers its
// final done/failed result through the registry's sink (protocol ruling 7).

package opscmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/W1nCwC/W1nCray/agent/panelclient"
	"github.com/W1nCwC/W1nCray/agent/selfupdate"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
)

// SelfUpdateOps is the surface the self_update command needs. It is an
// interface so the command is testable without a manifest installer.
type SelfUpdateOps interface {
	// Stage downloads and verifies the target version; it never writes the
	// running executable.
	Stage(ctx context.Context, version string) (selfupdate.Staged, error)
	// Commit swaps the executable and writes the pending marker.
	Commit(s selfupdate.Staged) error
	// Pending reports a commit that has not been confirmed yet.
	Pending() (selfupdate.Pending, bool)
	// Ready reports why an in-place update is impossible on this machine.
	Ready() error
	// RespawnHelper starts the detached watchdog: a copy of the previous
	// binary that restores it when the new one cannot run.
	RespawnHelper() error
}

// selfUpdateArgs is the args of self_update: the target version, which must be
// listed for the reserved manifest kernel name "agent".
type selfUpdateArgs struct {
	Version string `json:"version"`
}

// selfUpdateResult is the final result of a successful self_update.
type selfUpdateResult struct {
	// From is the version that was running when the update was committed.
	From    string `json:"from,omitempty"`
	Version string `json:"version"`
	Path    string `json:"path,omitempty"`
	Restart bool   `json:"restart"`
}

// RegisterSelfUpdate adds the self_update command to a registry. up serves the
// update; restart asks the process to exit so the helper (or the service
// manager) starts the new binary. Both are required: without a restart hook
// the swap would never take effect, so the command is not registered and the
// panel is answered "unsupported command" instead.
func RegisterSelfUpdate(r *Registry, up SelfUpdateOps, restart func()) error {
	if r == nil {
		return errors.New("opscmd: nil registry")
	}
	if up == nil {
		return errors.New("opscmd: self_update needs an updater")
	}
	if restart == nil {
		return errors.New("opscmd: self_update needs a restart hook")
	}
	c := &selfUpdateCmds{reg: r, up: up, restart: restart}
	return r.Register(panelclient.CmdSelfUpdate, c.selfUpdate)
}

type selfUpdateCmds struct {
	reg     *Registry
	up      SelfUpdateOps
	restart func()
}

// EmitEvent reports an event through the registry's event sink. It exists for
// events that are not tied to a command, such as a rollback the self-update
// watchdog performed before this process started (protocol ruling 10).
func (r *Registry) EmitEvent(kind, level, message string) { r.event(kind, level, message) }

// selfUpdate answers self_update. The whole update (download, verify, extract,
// self-check, swap) runs in the background: it can take minutes, and the panel
// must get its "accepted" answer within the command's ttl.
func (c *selfUpdateCmds) selfUpdate(ctx context.Context, req Request, complete Completion) (Result, error) {
	var a selfUpdateArgs
	if err := decodeArgs(req.Args, &a); err != nil {
		return Result{}, err
	}
	if a.Version == "" {
		return Result{}, coded("invalid_args", errors.New("version is required"))
	}
	if err := c.up.Ready(); err != nil {
		return Result{}, coded("not_supported", err)
	}
	if p, ok := c.up.Pending(); ok {
		return Result{}, coded("pending", fmt.Errorf("version %s is already committed and has not been confirmed yet", p.Version))
	}
	version := manifest.NormalizeVersion(a.Version)
	c.reg.logf().Infof("opscmd: self_update to %s accepted", version)
	c.reg.event("self_update.started", "info", "self_update to "+version+" started")

	go func() {
		staged, err := c.up.Stage(ctx, version)
		if err != nil {
			c.reg.logf().Warnf("opscmd: self_update to %s failed: %v", version, err)
			complete(StatusFailed, nil, err)
			return
		}
		if err := c.up.Commit(staged); err != nil {
			// Commit restores the original executable on every failure path.
			c.reg.logf().Warnf("opscmd: self_update commit of %s failed: %v", version, err)
			complete(StatusFailed, nil, err)
			return
		}
		if err := c.up.RespawnHelper(); err != nil {
			// The swap is committed but nothing will watch it. The service
			// manager still picks the new binary up on the next stop/start, so
			// this is reported as a failure without undoing it.
			complete(StatusFailed, nil, fmt.Errorf("committed %s but could not start the self-update watchdog: %w", staged.Version, err))
			return
		}
		c.reg.logf().Infof("opscmd: self_update to %s committed; restarting", staged.Version)
		from := ""
		if cv, ok := c.up.(interface{ CurrentVersion() string }); ok {
			from = cv.CurrentVersion()
		}
		complete(StatusDone, mustJSON(selfUpdateResult{From: from, Version: staged.Version, Path: staged.Path, Restart: true}), nil)
		// The result is delivered synchronously by the sink; only now is it
		// safe to hand over to the new binary.
		c.restart()
	}()
	return accepted(), nil
}
