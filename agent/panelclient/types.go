// Package panelclient talks to the panel (W1nCBoard/Xboard) on behalf of the
// agent: it pulls the desired state, reports the outcome and the runtime
// status, and executes the small whitelist of panel commands.
//
// The wire contract is docs/PLAN-v7-panel-control.md (sections 2 and 3). This
// file holds the contract types only; the Client (HTTP) and the Runner (loops)
// live in their own files. Field names are snake_case on the wire.
package panelclient

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/W1nCwC/W1nCray/agent/reconcile"
	"github.com/W1nCwC/W1nCray/agent/spec"
)

// Schema is the version of the wire contract spoken by this package.
const Schema = 1

// Command types the agent executes (contract section 3.5). Anything else is
// answered with a "failed" result and never executed.
const (
	CmdRefresh   = "refresh"
	CmdDumpState = "dump_state"
)

// Command result statuses.
const (
	ResultDone    = "done"
	ResultFailed  = "failed"
	ResultExpired = "expired"
)

// Platform identifies the machine for the panel's capability greying.
type Platform struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
	Libc string `json:"libc,omitempty"`
}

// ConfigRequest is the body of POST /config.
type ConfigRequest struct {
	Schema       int               `json:"schema"`
	InstanceID   string            `json:"instance_id"`
	AgentVersion string            `json:"agent_version"`
	HaveRevision int64             `json:"have_revision"`
	HaveHash     string            `json:"have_hash"`
	Platform     Platform          `json:"platform"`
	Engines      []string          `json:"engines"`
	Kernels      map[string]string `json:"kernels,omitempty"`
}

// Command is a whitelisted panel command.
type Command struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Args      json.RawMessage `json:"args,omitempty"`
	ExpiresAt int64           `json:"expires_at,omitempty"` // unix seconds; 0 = no expiry
}

// ConfigResponse is the answer of POST /config. When Unchanged is true only
// Revision is meaningful. DesiredRaw is decoded strictly by Desired().
type ConfigResponse struct {
	Schema     int             `json:"schema"`
	Unchanged  bool            `json:"unchanged,omitempty"`
	Revision   int64           `json:"revision"`
	Hash       string          `json:"hash,omitempty"`
	IssuedAt   int64           `json:"issued_at,omitempty"`
	DesiredRaw json.RawMessage `json:"desired,omitempty"`
	Commands   []Command       `json:"commands,omitempty"`
}

// ErrBadDesired is returned by ConfigResponse.Desired when the desired state
// does not strictly match spec.Desired (unknown field, wrong type, trailing
// data, missing or mismatching revision).
type ErrBadDesired struct{ Err error }

func (e *ErrBadDesired) Error() string {
	return "panel sent an invalid desired state: " + e.Err.Error()
}
func (e *ErrBadDesired) Unwrap() error { return e.Err }

// Desired decodes the desired state strictly (unknown fields are an error) and
// checks that its revision equals the envelope revision.
func (r ConfigResponse) Desired() (spec.Desired, error) {
	var d spec.Desired
	if len(r.DesiredRaw) == 0 {
		return d, &ErrBadDesired{Err: fmt.Errorf("desired is missing")}
	}
	dec := json.NewDecoder(bytes.NewReader(r.DesiredRaw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return d, &ErrBadDesired{Err: err}
	}
	if dec.More() {
		return d, &ErrBadDesired{Err: fmt.Errorf("trailing data after the desired state")}
	}
	if d.Revision != r.Revision {
		return d, &ErrBadDesired{Err: fmt.Errorf("desired.revision %d does not match revision %d", d.Revision, r.Revision)}
	}
	return d, nil
}

// AckRequest is the body of POST /ack, sent after every apply attempt.
type AckRequest struct {
	Schema     int              `json:"schema"`
	InstanceID string           `json:"instance_id"`
	Revision   int64            `json:"revision"`
	Hash       string           `json:"hash"`
	Report     reconcile.Report `json:"report"`
}

// InstanceStat is one instance in a status report. The counters are
// cumulative within one InstanceID of the agent process and are nil when the
// engine cannot count (for example realm).
type InstanceStat struct {
	ID          string  `json:"id"`
	State       string  `json:"state"`
	Engine      string  `json:"engine,omitempty"`
	BytesUp     *uint64 `json:"bytes_up,omitempty"`
	BytesDown   *uint64 `json:"bytes_down,omitempty"`
	ConnsActive *uint64 `json:"conns_active,omitempty"`
	ConnsTotal  *uint64 `json:"conns_total,omitempty"`
}

// HostStat is the optional machine load; unavailable fields are nil.
type HostStat struct {
	CPU         *float64 `json:"cpu,omitempty"`
	MemTotal    *uint64  `json:"mem_total,omitempty"`
	MemUsed     *uint64  `json:"mem_used,omitempty"`
	SwapTotal   *uint64  `json:"swap_total,omitempty"`
	SwapUsed    *uint64  `json:"swap_used,omitempty"`
	DiskTotal   *uint64  `json:"disk_total,omitempty"`
	DiskUsed    *uint64  `json:"disk_used,omitempty"`
	NetInSpeed  *float64 `json:"net_in_speed,omitempty"`
	NetOutSpeed *float64 `json:"net_out_speed,omitempty"`
	UptimeS     *uint64  `json:"uptime_s,omitempty"`
}

// ReportRequest is the body of POST /report (every ReportInterval).
type ReportRequest struct {
	Schema          int                    `json:"schema"`
	InstanceID      string                 `json:"instance_id"`
	Seq             uint64                 `json:"seq"`
	TS              int64                  `json:"ts"`
	AppliedRevision int64                  `json:"applied_revision"`
	AppliedHash     string                 `json:"applied_hash"`
	Health          reconcile.HealthReport `json:"health"`
	Instances       []InstanceStat         `json:"instances"`
	Kernels         map[string]string      `json:"kernels,omitempty"`
	Host            *HostStat              `json:"host,omitempty"`
}

// ReportResponse is the answer of POST /report. Commands is the fast channel
// for panel commands.
type ReportResponse struct {
	OK       bool      `json:"ok"`
	AckSeq   uint64    `json:"ack_seq,omitempty"`
	Commands []Command `json:"commands,omitempty"`
}

// CommandResultRequest is the body of POST /command-result.
type CommandResultRequest struct {
	Schema     int             `json:"schema"`
	InstanceID string          `json:"instance_id"`
	ID         string          `json:"id"`
	Status     string          `json:"status"`
	Result     json.RawMessage `json:"result,omitempty"`
}

// ManifestRequest is the query of GET /manifest. ETag is the entity tag of the
// manifest the agent already accepted ("" for the first fetch); it is sent as
// If-None-Match so an unchanged manifest answers 304.
type ManifestRequest struct {
	ETag string
}

// ManifestResponse is the answer of GET /manifest. NotModified is true for 304:
// Raw and ETag are then empty and the stored manifest is still current.
type ManifestResponse struct {
	NotModified bool
	Raw         []byte // the signed manifest document (200 only)
	ETag        string // entity tag of Raw (200 only; may be empty)
}

// APIError is a non-2xx answer of the panel ({"error","message"} body).
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("panel answered HTTP %d: %s", e.Status, e.Message)
	}
	return fmt.Sprintf("panel answered HTTP %d (%s): %s", e.Status, e.Code, e.Message)
}
