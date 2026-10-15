// This file registers the audit_ctl command: the panel's switch for the Xray
// kernel's access-log stream (W1NCRAY-D2).
//
// The command carries one boolean and nothing else, so it can never name a
// path, a file or a host. It answers immediately (the kernel request is made by
// the WebSocket agent's own loop), which keeps it a short command like
// kernel_rollback rather than a long one.
//
// It is registered unconditionally: the command is part of this agent build,
// and a machine whose kernel predates the collector answers not_supported
// instead of looking like an agent that does not know the command at all.

package opscmd

import (
	"context"
	"errors"

	"github.com/W1nCwC/W1nCray/agent/panelclient"
)

// AuditControl is the agent side of the access-log stream. The WebSocket agent
// implements it (agent/ws.Agent); it is declared here so this package does not
// import the transport and so tests can substitute a fake.
type AuditControl interface {
	// AuditSupported reports whether the "audit" capability is declared right
	// now (a kernel that serves the collector is wired and reachable).
	AuditSupported() bool
	// AuditEnabled reports whether the stream is on right now.
	AuditEnabled() bool
	// SetAuditEnabled turns the stream on or off and reports the state that
	// will be in force.
	SetAuditEnabled(enabled bool) bool
}

// auditCtlArgs is the audit_ctl payload: {"enabled":bool}. It is decoded
// strictly, so a panel that invents a field is refused instead of half-applied.
type auditCtlArgs struct {
	Enabled bool `json:"enabled"`
}

// auditCtlResult is the audit_ctl answer. It repeats the state that is now in
// force, which is what the panel displays.
type auditCtlResult struct {
	Enabled bool `json:"enabled"`
}

// registerAudit adds the audit_ctl command. The switch is read from the
// registry on every call (SetAudit), so the command can be registered before
// the WebSocket channel that owns the stream exists.
func registerAudit(r *Registry, _ Deps) error {
	return r.Register(panelclient.CmdAuditCtl, auditCtl(r))
}

// auditCtl builds the handler. A registry without an installed switch (an agent
// without a WebSocket channel) answers not_supported: the stream only exists on
// the socket, and pretending otherwise would let the panel believe it is
// collecting.
func auditCtl(reg *Registry) Handler {
	return func(_ context.Context, req Request, _ Completion) (Result, error) {
		ctl := reg.auditControl()
		if ctl == nil {
			return Result{}, coded("not_supported", errors.New("the access-log audit stream is not wired on this agent"))
		}
		var a auditCtlArgs
		if err := decodeArgs(req.Args, &a); err != nil {
			return Result{}, err
		}
		if !ctl.AuditSupported() {
			return Result{}, coded("not_supported", errors.New("this Xray kernel does not serve the access-log collector"))
		}
		enabled := ctl.SetAuditEnabled(a.Enabled)
		return done(auditCtlResult{Enabled: enabled}), nil
	}
}
