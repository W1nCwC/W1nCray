// Package opscmd is the agent's operations command framework: one registry
// that owns the command whitelist, one execution entry point shared by the HTTP
// Runner and the WebSocket channel, and one place where a long command answers
// "accepted" and then delivers its final result (docs/WS-PROTOCOL.md section 7
// rulings 7 and 11).
//
// It is plugin shaped on purpose: a later feature package (self-update, managed
// files, terminal, file operations) only adds a file with a
// func Register(*opscmd.Registry) that calls Register(type, handler); it never
// edits this package or the channels.
//
// The built-in command types (refresh, dump_state) stay in agent/panelclient:
// they need the pull loop and the last report, which only the Runner has. Every
// other type is served here; an unregistered type is answered with exactly the
// same "unsupported command" failure as before this package existed.

package opscmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/panelclient"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/kernel"
	"github.com/W1nCwC/W1nCray/kernel/install"
)

// Result statuses a handler returns. StatusAccepted is only valid together
// with a Completion that will be called later.
const (
	StatusDone     = panelclient.ResultDone
	StatusFailed   = panelclient.ResultFailed
	StatusAccepted = panelclient.ResultAccepted
)

// errUnsupported is the answer for a command type no handler is registered for
// (contract section 3.5: never executed).
var errUnsupported = errors.New("unsupported command")

// Request is one command handed to a handler.
type Request struct {
	ID   string
	Type string
	Args json.RawMessage
}

// Result is a handler's outcome. Status is one of the Status* constants; Data
// is the JSON result body (nil means no result).
type Result struct {
	Status string
	Data   json.RawMessage
}

// Completion delivers the final outcome of a long command. It is called
// exactly once, from the handler's own goroutine, after the handler returned
// StatusAccepted. status is StatusDone or StatusFailed; a non-nil err turns the
// result into a failed one whatever status says.
type Completion func(status string, data json.RawMessage, err error)

// Handler runs one command type.
//
// A handler that finishes immediately returns a Result with Status done or
// failed and never calls complete. A long handler returns
// Result{Status: StatusAccepted} *before* starting its work and calls complete
// exactly once when that work is finished, so the panel gets its "accepted"
// answer within the command's ttl (ruling 7).
type Handler func(ctx context.Context, req Request, complete Completion) (Result, error)

// Sink delivers the final result of a long command to the panel. The channels
// provide it: the HTTP link posts /command-result, the WebSocket sends a
// cmd.result frame. A nil sink means a long command's final result cannot be
// delivered and is logged.
type Sink interface {
	Deliver(id, status string, data json.RawMessage)
}

// SinkFunc adapts a function to Sink.
type SinkFunc func(id, status string, data json.RawMessage)

// Deliver implements Sink.
func (f SinkFunc) Deliver(id, status string, data json.RawMessage) { f(id, status, data) }

// EventSink reports a local event to the panel (event frames, audit). It is
// best effort: events are live data and are never replayed.
type EventSink interface {
	Event(kind, level, message string)
}

// EventFunc adapts a function to EventSink.
type EventFunc func(kind, level, message string)

// Event implements EventSink.
func (f EventFunc) Event(kind, level, message string) { f(kind, level, message) }

// KernelOps is the kernel manager surface the kernel_* commands need. It is
// declared here so this package does not depend on kernelx (which imports the
// agent runtime) and so tests can substitute a fake.
type KernelOps interface {
	// List returns every installed kernel version.
	List() ([]install.Entry, error)
	// Catalog lists the signed manifest's versions with availability.
	Catalog() ([]install.CatalogEntry, error)
	// Ensure installs the pin if needed and makes it current (empty version =
	// newest the manifest offers).
	Ensure(ctx context.Context, pin spec.KernelPin) (driver.Installed, error)
	// Remove deletes one installed version.
	Remove(name, version string) error
	// Rollback makes the previous version current again.
	Rollback(name string) (driver.Installed, error)
	// RunningVersion returns the version a live managed process executes;
	// exact=false means the platform cannot tell and the caller must fall back
	// to the current pointer.
	RunningVersion(name string) (version string, exact bool)
}

// ComponentOps restarts the running process(es) of one kernel component.
// The agent itself is never a component here: it is not supervised.
type ComponentOps interface {
	// Restart restarts the named component's process(es) and returns how many
	// were restarted.
	Restart(ctx context.Context, name string) (int, error)
}

// Deps configures the registry.
type Deps struct {
	// Kernels is required: without a kernel manager the kernel_* commands
	// cannot exist.
	Kernels KernelOps
	// Comp serves component_restart. Nil answers it with not_supported.
	Comp ComponentOps
	// Files serves files_apply / files_validate / files_rollback, the MANAGED
	// xray files (D4/D5). Nil answers them with not_supported (protocol ruling
	// 5: never silently ignored).
	Files FilesOps
	// FileCmds serves the file_* commands (WP-G6): file_list, file_read,
	// file_write, file_delete, the confined file manager. It is a separate
	// field from Files because the two features are different: Files replaces
	// the managed xray files from the panel's revision, FileCmds browses and
	// edits single files inside the local roots. RegisterFileCmds installs
	// them, because a machine without a configured root must not expose the
	// commands at all.
	FileCmds FileCmdOps
	// Events reports kernel.installed / kernel.removed / files.applied /
	// files.rolled_back (ruling 10). Nil drops them.
	Events EventSink
	// Sink delivers the final result of long commands. It may be set later
	// with SetSink, once the channels exist.
	Sink Sink
	// Log receives the registry's events; never an argument payload.
	Log driver.Logger
}

// Registry is the command registry and the panelclient.CommandRunner
// implementation. It is safe for concurrent use: the HTTP pull loop and the
// WebSocket reader both execute through it.
type Registry struct {
	mu       sync.RWMutex
	handlers map[string]Handler
	sink     Sink
	events   EventSink
	// files is the managed-file implementation. It can be installed after the
	// registry exists (SetFiles), because the blob fetcher only appears once
	// the panel link is built; until then the file commands answer
	// "not_supported" instead of running half-wired.
	files FilesOps
	log   driver.Logger
}

var _ panelclient.CommandRunner = (*Registry)(nil)

type nopLog struct{}

func (nopLog) Debugf(string, ...any) {}
func (nopLog) Infof(string, ...any)  {}
func (nopLog) Warnf(string, ...any)  {}
func (nopLog) Errorf(string, ...any) {}

// New builds the registry with the built-in operation commands registered.
func New(d Deps) (*Registry, error) {
	if d.Kernels == nil {
		return nil, errors.New("opscmd: a kernel manager is required")
	}
	r := &Registry{
		handlers: map[string]Handler{},
		sink:     d.Sink,
		events:   d.Events,
		files:    d.Files,
		log:      d.Log,
	}
	if r.log == nil {
		r.log = nopLog{}
	}
	if err := registerKernel(r, d); err != nil {
		return nil, err
	}
	if err := registerFiles(r, d); err != nil {
		return nil, err
	}
	return r, nil
}

// Register adds one command type. It is the only thing a feature package needs
// to plug in (design section 4).
func (r *Registry) Register(typ string, h Handler) error {
	if typ == "" {
		return errors.New("opscmd: empty command type")
	}
	if h == nil {
		return fmt.Errorf("opscmd: command %q has a nil handler", typ)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.handlers[typ]; dup {
		return fmt.Errorf("opscmd: command %q is already registered", typ)
	}
	r.handlers[typ] = h
	return nil
}

// Has reports whether a type is registered (the whitelist).
func (r *Registry) Has(typ string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.handlers[typ]
	return ok
}

// Types returns the registered command types, sorted. It is the whitelist the
// panel may send.
func (r *Registry) Types() []string {
	r.mu.RLock()
	out := make([]string, 0, len(r.handlers))
	for t := range r.handlers {
		out = append(out, t)
	}
	r.mu.RUnlock()
	sort.Strings(out)
	return out
}

// SetSink installs the late-result sink. bootstrap calls it once the HTTP link
// and the WebSocket channel exist.
func (r *Registry) SetSink(s Sink) {
	r.mu.Lock()
	r.sink = s
	r.mu.Unlock()
}

// SetEvents installs the event sink.
func (r *Registry) SetEvents(e EventSink) {
	r.mu.Lock()
	r.events = e
	r.mu.Unlock()
}

// SetFiles installs the managed-file implementation. bootstrap calls it once
// the panel link exists, because the blob fetcher is the panel HTTP client. It
// replaces a previously installed one (idempotent), so a re-link after a
// reconnect cannot register twice.
func (r *Registry) SetFiles(f FilesOps) {
	r.mu.Lock()
	r.files = f
	r.mu.Unlock()
}

// filesOps returns the installed managed-file implementation (nil when none).
func (r *Registry) filesOps() FilesOps {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.files
}

// Execute runs one command. It implements panelclient.CommandRunner, so the
// Runner's whitelist, expiry check and id de-duplication stay exactly where
// they were and only the unregistered types are delegated here.
func (r *Registry) Execute(ctx context.Context, c panelclient.Command) (string, json.RawMessage) {
	h, ok := r.handler(c.Type)
	if !ok {
		r.logf().Warnf("opscmd: refusing unsupported command type %q", c.Type)
		return panelclient.ResultFailed, mustJSON(failure{Error: errUnsupported.Error()})
	}
	req := Request{ID: c.ID, Type: c.Type, Args: c.Args}
	var once sync.Once
	complete := func(status string, data json.RawMessage, err error) {
		once.Do(func() {
			st, out := finalize(status, data, err)
			r.deliver(req.ID, st, out)
		})
	}
	res, err := h(ctx, req, complete)
	if err != nil {
		return finalize(res.Status, res.Data, err)
	}
	if res.Status == "" {
		res.Status = panelclient.ResultDone
	}
	return res.Status, res.Data
}

func (r *Registry) handler(typ string) (Handler, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.handlers[typ]
	return h, ok
}

func (r *Registry) deliver(id, status string, data json.RawMessage) {
	r.mu.RLock()
	s := r.sink
	r.mu.RUnlock()
	if s == nil {
		r.logf().Warnf("opscmd: no result sink wired; the final %s result of command %q cannot be delivered", status, id)
		return
	}
	s.Deliver(id, status, data)
}

func (r *Registry) event(kind, level, message string) {
	r.mu.RLock()
	e := r.events
	r.mu.RUnlock()
	if e == nil {
		return
	}
	e.Event(kind, level, message)
}

func (r *Registry) logf() driver.Logger {
	if r.log == nil {
		return nopLog{}
	}
	return r.log
}

// ---- results ---------------------------------------------------------------

// failure is the result body of a failed command. code is a stable
// machine-readable reason when one is known (kernel.Code for kernel errors, or
// one of the codes this package defines).
type failure struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

// codedError attaches a stable code to an error so the panel can branch on it
// instead of parsing prose.
type codedError struct {
	code string
	err  error
}

func (e *codedError) Error() string { return e.err.Error() }
func (e *codedError) Unwrap() error { return e.err }

func coded(code string, err error) error { return &codedError{code: code, err: err} }

// codeOf extracts the machine-readable code of an error, if it has one.
func codeOf(err error) string {
	var ce *codedError
	if errors.As(err, &ce) {
		return ce.code
	}
	if c := kernel.Code(err); c != "error" {
		return c
	}
	return ""
}

// finalize turns a handler outcome into the status and JSON body the channels
// deliver.
func finalize(status string, data json.RawMessage, err error) (string, json.RawMessage) {
	if err != nil {
		return panelclient.ResultFailed, mustJSON(failure{Error: err.Error(), Code: codeOf(err)})
	}
	if status == "" {
		status = panelclient.ResultDone
	}
	if len(data) == 0 {
		return status, nil
	}
	return status, data
}

func done(v any) Result { return Result{Status: StatusDone, Data: mustJSON(v)} }
func accepted() Result  { return Result{Status: StatusAccepted} }

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{"error":"encode failed"}`)
	}
	return b
}

// decodeArgs decodes a command's args strictly: an unknown field or trailing
// data is an error, so a panel/protocol drift is caught instead of silently
// ignored.
func decodeArgs(raw json.RawMessage, v any) error {
	if len(raw) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return coded("invalid_args", fmt.Errorf("invalid args: %w", err))
	}
	if dec.More() {
		return coded("invalid_args", errors.New("invalid args: trailing data"))
	}
	return nil
}
