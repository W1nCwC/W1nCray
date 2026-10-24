// Package prismapi is the agent's client of the W1nCray-prism kernel's local
// control API (HTTP/1.1 + JSON over a Unix socket, docs/IPC.md of the kernel).
//
// The kernel is a separate GPL-3.0 program; the agent never links it. The wire
// types below are defined here on their own and are not shared with the kernel.
package prismapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// KernelName is the kernel name in kernel_* commands and in the components list.
	KernelName = "prism"
	// APIVersion is the control API version this client speaks.
	APIVersion = 1
	// RuntimeDirName is the directory under /run the kernel's socket lives in.
	RuntimeDirName = "W1nCray-prism"
	// SocketName is the control socket inside the runtime directory.
	SocketName = "prism.sock"
	// StateDirName is the kernel's state directory under /var/lib.
	StateDirName = "W1nCray-prism"
)

// Status is the answer of GET /v1/status.
type Status struct {
	API          int             `json:"api"`
	Version      string          `json:"version"`
	Core         string          `json:"core"`
	BootID       string          `json:"boot_id"`
	State        string          `json:"state"` // running | idle | failed
	ConfigHash   *string         `json:"config_hash"`
	RejectedHash *string         `json:"rejected_hash"`
	LastError    string          `json:"last_error"`
	Inbounds     []InboundStatus `json:"inbounds"`
	StartedAt    int64           `json:"started_at"`
}

// InboundStatus describes one running inbound.
type InboundStatus struct {
	Tag   string `json:"tag"`
	Type  string `json:"type"`
	Users int    `json:"users"`
	Conns int    `json:"conns"`
}

// User is one panel user of an inbound.
type User struct {
	ID          int    `json:"id"`
	UUID        string `json:"uuid"`
	SpeedBps    int64  `json:"speed_bps"`
	DeviceLimit int    `json:"device_limit"`
}

// Traffic is the unreported usage of one user.
type Traffic struct {
	ID   int   `json:"id"`
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

// Alive is the set of client addresses of one user.
type Alive struct {
	ID  int      `json:"id"`
	IPs []string `json:"ips"`
}

// Stats is the answer of GET /v1/stats.
type Stats struct {
	BootID   string    `json:"boot_id"`
	Snapshot uint64    `json:"snapshot"`
	Traffic  []Traffic `json:"traffic"`
	Alive    []Alive   `json:"alive"`
}

// ApplyResult is the answer of PUT /v1/config.
type ApplyResult struct {
	Applied string `json:"applied"`
	Noop    bool   `json:"noop"`
}

// UsersResult is the answer of PUT /v1/users/{tag}.
type UsersResult struct {
	Applied bool `json:"applied"`
	Users   int  `json:"users"`
	Added   int  `json:"added"`
	Removed int  `json:"removed"`
	Kicked  int  `json:"kicked"`
}

// Error is an HTTP answer other than 2xx.
type Error struct {
	Code    int
	Kind    string // the "error" field of the body
	Message string
	Kept    string // the config hash the kernel kept (config errors)
}

func (e *Error) Error() string {
	return fmt.Sprintf("prism kernel: HTTP %d %s: %s", e.Code, e.Kind, e.Message)
}

// IsInvalid reports a 422 (the kernel refused the content).
func (e *Error) IsInvalid() bool { return e.Code == http.StatusUnprocessableEntity }

// IsNotFound reports a 404 (unknown inbound).
func (e *Error) IsNotFound() bool { return e.Code == http.StatusNotFound }

// IsStale reports a 409 (a stale statistics snapshot).
func (e *Error) IsStale() bool { return e.Code == http.StatusConflict }

// Client talks to one kernel.
type Client struct {
	hc   *http.Client
	base string
}

// New returns a client of the kernel listening at address: "unix:<path>" or
// "tcp:<host:port>" (tests).
func New(address string) (*Client, error) {
	kind, addr, ok := strings.Cut(address, ":")
	if !ok || addr == "" {
		return nil, fmt.Errorf("prismapi: address %q must be unix:<path> or tcp:<host:port>", address)
	}
	var dial func(ctx context.Context, _, _ string) (net.Conn, error)
	switch kind {
	case "unix":
		dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", addr)
		}
	case "tcp":
		dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		}
	default:
		return nil, fmt.Errorf("prismapi: unknown address kind %q", kind)
	}
	return &Client{
		base: "http://prism",
		hc: &http.Client{
			Timeout:   60 * time.Second,
			Transport: &http.Transport{DialContext: dial, DisableKeepAlives: true},
		},
	}, nil
}

// Status reads GET /v1/status.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var s Status
	err := c.do(ctx, http.MethodGet, "/v1/status", nil, &s)
	return s, err
}

// Apply installs the config identified by hash (PUT /v1/config).
func (c *Client) Apply(ctx context.Context, hash string, config json.RawMessage) (ApplyResult, error) {
	var r ApplyResult
	err := c.do(ctx, http.MethodPut, "/v1/config", map[string]any{"hash": hash, "config": config}, &r)
	return r, err
}

// Check builds a config without keeping it (POST /v1/check).
func (c *Client) Check(ctx context.Context, config json.RawMessage) error {
	return c.do(ctx, http.MethodPost, "/v1/check", map[string]any{"config": config}, nil)
}

// SetUsers replaces the user set of an inbound (PUT /v1/users/{tag}).
func (c *Client) SetUsers(ctx context.Context, tag string, seq int64, users []User) (UsersResult, error) {
	if users == nil {
		users = []User{}
	}
	var r UsersResult
	err := c.do(ctx, http.MethodPut, "/v1/users/"+url.PathEscape(tag), map[string]any{"seq": seq, "users": users}, &r)
	return r, err
}

// SetDevices stores the panel-wide alive device count per user.
func (c *Client) SetDevices(ctx context.Context, tag string, alive map[int]int) error {
	m := make(map[string]int, len(alive))
	for id, n := range alive {
		m[strconv.Itoa(id)] = n
	}
	return c.do(ctx, http.MethodPut, "/v1/devices/"+url.PathEscape(tag), map[string]any{"alive": m}, nil)
}

// Stats records and returns a statistics snapshot (GET /v1/stats).
func (c *Client) Stats(ctx context.Context, tag string) (Stats, error) {
	var s Stats
	err := c.do(ctx, http.MethodGet, "/v1/stats?tag="+url.QueryEscape(tag), nil, &s)
	return s, err
}

// Commit subtracts the usage a snapshot reported (POST /v1/stats/commit).
func (c *Client) Commit(ctx context.Context, tag string, snapshot uint64, bootID string) error {
	return c.do(ctx, http.MethodPost, "/v1/stats/commit", map[string]any{"tag": tag, "snapshot": snapshot, "boot_id": bootID}, nil)
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("X-Prism-Api", strconv.Itoa(APIVersion))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		e := &Error{Code: resp.StatusCode}
		var raw struct {
			Error   string `json:"error"`
			Message string `json:"message"`
			Kept    string `json:"kept"`
		}
		if json.Unmarshal(data, &raw) == nil {
			e.Kind, e.Message, e.Kept = raw.Error, raw.Message, raw.Kept
		}
		return e
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		// The kernel answered, so it is reachable: IsUnavailable must not say
		// otherwise.
		return &Error{Code: resp.StatusCode, Kind: "bad_answer", Message: err.Error()}
	}
	return nil
}

// IsUnavailable reports an error from a kernel that is not reachable (not
// running yet, socket missing) as opposed to one that answered.
func IsUnavailable(err error) bool {
	if err == nil {
		return false
	}
	var pe *Error
	return !errors.As(err, &pe)
}
