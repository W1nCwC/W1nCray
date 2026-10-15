// Package xrayapi holds the wire types of the W1nCray-xray kernel's local
// status interface and the interface the agent uses to reach it.
//
// It has no dependency on the Xray kernel, so the agent can link it: the agent
// program must never pull in Xray-core, while it still has to read the kernel's
// JSON status, ask it to pre-check staged files and wait for a reload.
package xrayapi

import "context"

// The manifest kernel name of the Xray kernel and the names of its local
// status endpoint. The kernel program (package xraynode) serves them; the
// agent reads them without linking Xray-core, so they live here, next to the
// wire types both sides share.
const (
	// KernelName is the kernel name in the signed manifest and in the kernel_*
	// commands.
	KernelName = "xray"
	// StatusSocketName is the Unix socket next to config.yml on Unix systems.
	StatusSocketName = "xray.sock"
	// StatusAddrName is the file holding the loopback address on Windows.
	StatusAddrName = "xray.addr"
	// StatusPath is the HTTP path the status document is served on.
	StatusPath = "/status"
	// NodesSyncPath is the HTTP path that asks the kernel to re-fetch this
	// machine's node list from the panel right now instead of waiting for its
	// 60 s poll. It is served on the same local endpoint as StatusPath (the
	// Unix socket, or the loopback address on Windows) and takes no parameter:
	// no path, no command, no node data. A kernel older than this route answers
	// HTTP 404, which the caller degrades to the poll.
	NodesSyncPath = "/nodes/sync"
	// AuditPath is the HTTP path that returns one bounded page of the kernel's
	// access-log collector. It is served on the same local endpoint as
	// StatusPath and takes two optional query parameters: after=<seq> (the
	// first sequence number the caller has not seen; 0 or absent means "from
	// the oldest entry kept") and max=<n> (the page size, default and cap
	// MaxAuditItems). A kernel older than this route answers HTTP 404, which
	// the caller degrades to "no audit log".
	AuditPath = "/audit"
	// AuditCtlPath is the HTTP path that turns access-log collection on or
	// off. It takes a POST with an AuditCtlRequest body and is served on the
	// same local endpoint as StatusPath.
	AuditCtlPath = "/audit/ctl"
	// MaxAuditItems is the largest page a single AuditPath request returns and
	// the cap on its max parameter. It is the same bound wsproto.MaxAuditItems
	// puts on one audit.log frame, so a page always fits one frame.
	MaxAuditItems = 400
	// RuntimeDirName is the directory under /run that holds the kernel's
	// runtime files. The systemd unit asks systemd to create it
	// (RuntimeDirectory=W1nCray); the kernel creates it itself when it is not
	// there (OpenRC, procd, the agent's fallback supervisor).
	RuntimeDirName = "W1nCray"
	// RuntimeDirEnv overrides the runtime directory. Tests and unprivileged
	// development runs use it; production never sets it.
	RuntimeDirEnv = "W1NCRAY_RUNTIME_DIR"
)

// Status is the JSON body of GET /status on the kernel's local endpoint (a
// Unix socket, or a loopback TCP port on Windows).
type Status struct {
	// Version is the kernel program's own version ("0.6.0").
	Version string `json:"version"`
	// XrayCore is the Xray-core version the kernel was built with.
	XrayCore string `json:"xray_core"`
	// StartedAt is when the kernel started, as a Unix timestamp.
	StartedAt int64 `json:"started_at"`
	// Running reports whether the Xray instance is up.
	Running bool `json:"running"`
	// Nodes describes every node controller of the running instance.
	Nodes []NodeStatus `json:"nodes"`
	// ConfigFingerprint is the content fingerprint of the watched files at the
	// last successful reload.
	ConfigFingerprint string `json:"config_fingerprint"`
	// LastReloadAt is the Unix timestamp of the last successful reload (0 when
	// the instance was only built at start-up).
	LastReloadAt int64 `json:"last_reload_at"`
	// LastError is the last reload error, "" when there is none.
	LastError string `json:"last_error,omitempty"`
	// Audit reports whether this kernel supports the access-log collector
	// (AuditPath and AuditCtlPath). It is independent of whether collection is
	// switched on right now, so an old agent that ignores it is unaffected.
	Audit bool `json:"audit,omitempty"`
}

// AuditBatch is the JSON body of GET AuditPath: one bounded page of the
// kernel's access-log entries, oldest first.
//
// Epoch is the kernel process start (unix seconds) the sequence numbers belong
// to; a change of Epoch means the kernel restarted and a caller that had a
// cursor must start again at the kernel's current position. FromSeq/ToSeq are
// the sequence numbers of Items[0] and Items[len-1] (both 0 for an empty
// page). Dropped counts the entries the kernel discarded between the caller's
// previous cursor and FromSeq (the bounded buffer overflowed, or an off switch
// emptied it), so it is the loss this page reports and never repeats on the
// next one. More reports that entries beyond ToSeq are already buffered, so the
// caller should ask again immediately.
//
// It carries no dependency on agent/wsproto: the agent maps this document onto
// the panel's audit.log frame itself.
type AuditBatch struct {
	Epoch   int64       `json:"epoch"`
	FromSeq uint64      `json:"from_seq"`
	ToSeq   uint64      `json:"to_seq"`
	Dropped uint64      `json:"dropped"`
	Items   []AuditItem `json:"items"`
	More    bool        `json:"more"`
}

// AuditItem is one access-log line: T is when the kernel handled it (unix ms)
// and L is the line, at most MaxAuditLine bytes. The JSON keys are the ones
// wsproto.AuditItem uses, so the agent can copy the item as it is.
type AuditItem struct {
	T int64  `json:"t"`
	L string `json:"l"`
}

// MaxAuditLine is the longest access-log line the kernel keeps; a longer one is
// truncated on a UTF-8 boundary. It is the same bound wsproto.MaxAuditLine
// puts on one audit.log item.
const MaxAuditLine = 512

// AuditCtlRequest is the JSON body of POST AuditCtlPath. Disabling collection
// discards the kernel's buffer, so a later enable starts a fresh page.
type AuditCtlRequest struct {
	Enabled bool `json:"enabled"`
}

// NodeStatus is one entry of Status.Nodes.
type NodeStatus struct {
	Tag    string `json:"tag"`
	ID     int    `json:"id"`
	Type   string `json:"type"`
	Users  int    `json:"users"`
	Online int    `json:"online"`
	Error  string `json:"error,omitempty"`
}

// NodesSyncResult is the JSON body of NodesSyncPath. A request that could not
// reach the panel is answered with a non-2xx status instead, so the caller can
// tell "the list is unchanged" (changed=false) from "the kernel could not ask".
type NodesSyncResult struct {
	// Changed reports whether the panel's node-list version differed from the
	// one the running instance was built from. When it is true the kernel has
	// requested a reload; when it is false the running list is current and
	// nothing was reloaded.
	Changed bool `json:"changed"`
	// Version is the version the panel reported, for logs. It is empty when
	// machine mode is off (there is no list to refresh).
	Version string `json:"version,omitempty"`
}

// StagedError is one problem `check-staged` found in a staged file.
type StagedError struct {
	File    string `json:"file"`
	Message string `json:"message"`
}

// StagedResult is the JSON document `check-staged` prints.
type StagedResult struct {
	OK     bool          `json:"ok"`
	Errors []StagedError `json:"errors"`
}

// Service is the agent's view of the locally installed Xray kernel. The agent
// holds it as an interface so that a machine without the kernel (the default)
// degrades safely instead of failing to start; the implementation (X2) talks
// to the kernel's local endpoint.
//
// A nil Service means "the Xray kernel is not installed": managed Xray files
// are refused with "Xray 内核未安装" instead of being half-applied.
type Service interface {
	// Status returns the kernel's current status document.
	Status(ctx context.Context) (Status, error)
	// CheckStaged pre-checks a staged managed-file set with the kernel's own
	// configuration loader. files are the managed-file names in dir.
	CheckStaged(ctx context.Context, dir string, files []string) (StagedResult, error)
	// WaitReloaded waits until the kernel reports fingerprint as its loaded
	// configuration fingerprint (or ctx ends).
	WaitReloaded(ctx context.Context, fingerprint string) error
	// SyncMachineNodes asks the kernel to re-fetch this machine's node list
	// from the panel now instead of waiting for its 60 s poll. changed reports
	// whether the list differed from the running instance's one (the kernel
	// then requested a reload); an idle list is (false, nil). An error means
	// the kernel could not be reached or answered with a failure — including a
	// kernel that predates the route (HTTP 404) — and the caller falls back to
	// the poll instead of failing.
	SyncMachineNodes(ctx context.Context) (changed bool, err error)
}
