// This file is the agent's client of the Xray kernel's access-log collector:
// the local /audit and /audit/ctl routes the kernel serves next to /status.
//
// It deliberately does NOT extend xrayapi.Service (the D1 contract): the
// collector is an optional capability of a kernel version, so it is reached
// through its own small client. Every method reports an old kernel (HTTP 404)
// as "not supported" instead of an error, which is what lets the agent leave
// the audit capability out of hello and degrade without a single warning on a
// machine whose kernel predates the route.
//
// Nothing here ever links Xray-core, and nothing here logs or stores a line:
// the access lines travel from the kernel's bounded buffer to the panel frame
// and are never written anywhere else.
package xraysvc

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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/W1nCwC/W1nCray/agent/xrayapi"
)

// Defaults of the audit client. They are per-request bounds, not a cadence: the
// pull loop's cadence belongs to agent/ws.
const (
	// DefaultAuditTimeout bounds one audit request.
	DefaultAuditTimeout = 5 * time.Second
	// DefaultAuditStatusTimeout bounds the status read that answers "does this
	// kernel serve /audit at all?".
	DefaultAuditStatusTimeout = 2 * time.Second
	// maxAuditBody bounds what is read from one audit response. A page is at
	// most xrayapi.MaxAuditItems lines of at most xrayapi.MaxAuditLine bytes
	// plus the JSON overhead, so 1 MiB is generous and still a hard bound.
	maxAuditBody = 1 << 20
)

// AuditOptions configures an AuditClient. Exactly one of BaseURL and
// ConfigPath must be set: BaseURL is the test hook (an httptest server),
// ConfigPath is production (the kernel's local endpoint lives next to
// config.yml).
type AuditOptions struct {
	// BaseURL is the kernel endpoint's base URL, for example
	// "http://127.0.0.1:1234". Empty means "resolve it from ConfigPath".
	BaseURL string
	// ConfigPath is the absolute path of the kernel's config.yml.
	ConfigPath string
	// Status reads the kernel's status document, which is where the kernel's
	// own "I serve /audit" bit comes from (xrayapi.Status.Audit). Nil means the
	// capability can only be discovered by asking the route itself, which the
	// caller does through Supported.
	Status xrayapi.Service
	// HTTP replaces the HTTP client (tests).
	HTTP *http.Client
	// Timeout bounds one audit request (default DefaultAuditTimeout).
	Timeout time.Duration
	// StatusTimeout bounds the status read of Supported
	// (default DefaultAuditStatusTimeout).
	StatusTimeout time.Duration
}

// AuditClient talks to the kernel's access-log collector. It is safe for
// concurrent use.
type AuditClient struct {
	opts AuditOptions
}

// Page is one answer of AuditClient.Batch. Supported is false when the kernel
// does not serve /audit (an old kernel): the batch is then the zero value and
// the caller must not advertise the audit capability.
type Page struct {
	Batch     xrayapi.AuditBatch
	Supported bool
}

// NewAuditClient builds the client.
func NewAuditClient(o AuditOptions) (*AuditClient, error) {
	if o.BaseURL == "" && o.ConfigPath == "" {
		return nil, errors.New("xraysvc: an audit BaseURL or ConfigPath is required")
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultAuditTimeout
	}
	if o.StatusTimeout <= 0 {
		o.StatusTimeout = DefaultAuditStatusTimeout
	}
	return &AuditClient{opts: o}, nil
}

// Supported reports whether the kernel serves the access-log collector. It asks
// the kernel's own status document first (Status.Audit), because that is the
// kernel telling the truth about itself, and falls back to the route itself
// when no status reader is wired. An unreachable kernel is (false, err): the
// caller must not advertise a capability it cannot serve.
func (c *AuditClient) Supported(ctx context.Context) (bool, error) {
	if c.opts.Status != nil {
		sctx, cancel := context.WithTimeout(ctx, c.opts.StatusTimeout)
		defer cancel()
		st, err := c.opts.Status.Status(sctx)
		if err != nil {
			return false, fmt.Errorf("读取 Xray 内核状态以判断审计支持: %w", err)
		}
		return st.Audit, nil
	}
	return c.probeSupported(ctx)
}

// probeSupported asks the route itself. A kernel that predates it answers 404
// (and 405 for a route that exists for another method); both mean "not
// supported", which is a fact and not a failure.
func (c *AuditClient) probeSupported(ctx context.Context) (bool, error) {
	status, err := c.do(ctx, http.MethodGet, xrayapi.AuditPath+"?max=1", nil, nil)
	switch {
	case err == nil:
		return true, nil
	case isNotFound(status):
		return false, nil
	default:
		return false, err
	}
}

// Enabled asks the kernel whether access-log collection is on right now. It
// returns false when the kernel does not serve the collector at all.
func (c *AuditClient) Enabled(ctx context.Context) (bool, error) {
	if c.opts.Status != nil {
		sctx, cancel := context.WithTimeout(ctx, c.opts.StatusTimeout)
		defer cancel()
		st, err := c.opts.Status.Status(sctx)
		if err != nil {
			return false, fmt.Errorf("读取 Xray 内核状态以判断审计开关: %w", err)
		}
		return st.Audit, nil
	}
	supported, err := c.probeSupported(ctx)
	if err != nil || !supported {
		return false, err
	}
	return true, nil
}

// SetEnabled turns the kernel's access-log collection on or off. Turning it off
// discards the kernel's buffer, so a later enable starts a fresh page; a kernel
// that does not serve the route answers "not supported".
func (c *AuditClient) SetEnabled(ctx context.Context, enabled bool) error {
	body, err := json.Marshal(xrayapi.AuditCtlRequest{Enabled: enabled})
	if err != nil {
		return fmt.Errorf("xraysvc: encode audit control: %w", err)
	}
	status, err := c.do(ctx, http.MethodPost, xrayapi.AuditCtlPath, body, nil)
	if err == nil {
		return nil
	}
	if isNotFound(status) {
		return errAuditUnsupported
	}
	return err
}

// Batch pulls one bounded page of access-log entries with a sequence number
// greater than after. max is clamped by the kernel to xrayapi.MaxAuditItems. A
// kernel that does not serve the route answers Supported=false and no error.
func (c *AuditClient) Batch(ctx context.Context, after uint64, max int) (Page, error) {
	if max <= 0 || max > xrayapi.MaxAuditItems {
		max = xrayapi.MaxAuditItems
	}
	q := url.Values{}
	q.Set("after", strconv.FormatUint(after, 10))
	q.Set("max", strconv.Itoa(max))
	var batch xrayapi.AuditBatch
	status, err := c.do(ctx, http.MethodGet, xrayapi.AuditPath+"?"+q.Encode(), nil, &batch)
	switch {
	case err == nil:
		return Page{Batch: batch, Supported: true}, nil
	case isNotFound(status):
		return Page{}, nil
	default:
		return Page{}, err
	}
}

// errAuditUnsupported is returned by SetEnabled when the kernel predates the
// collector. The caller disables the feature and logs it once.
var errAuditUnsupported = errors.New("Xray 内核不支持访问日志采集（/audit 路由不存在）")

// IsAuditUnsupported reports whether err means "this kernel has no collector".
func IsAuditUnsupported(err error) bool { return errors.Is(err, errAuditUnsupported) }

// httpStatusError carries the HTTP status of a failed audit request, so the
// caller can tell "this kernel predates the route" (404/405) from a real
// failure.
type httpStatusError struct {
	path   string
	status int
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("Xray 内核 %s 返回 HTTP %d", e.path, e.status)
}

// isNotFound reports whether an HTTP status means the route does not exist.
func isNotFound(status int) bool {
	return status == http.StatusNotFound || status == http.StatusMethodNotAllowed
}

// do performs one request against the kernel endpoint and decodes a JSON
// response into out when out is not nil. It returns the HTTP status even on
// failure (0 for a transport error), so a caller can distinguish 404 from a
// real failure.
func (c *AuditClient) do(ctx context.Context, method, path string, body []byte, out any) (int, error) {
	client, base, err := c.endpoint()
	if err != nil {
		return 0, err
	}
	defer client.CloseIdleConnections()

	ctx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()

	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, rdr)
	if err != nil {
		return 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("请求 Xray 内核审计接口: %w", err)
	}
	defer resp.Body.Close()

	status := resp.StatusCode
	if status != http.StatusOK {
		// Drain a bounded amount so the connection can be reused.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return status, &httpStatusError{path: path, status: status}
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return status, nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAuditBody)).Decode(out); err != nil {
		return status, fmt.Errorf("解析 Xray 内核审计接口响应: %w", err)
	}
	return status, nil
}

// endpoint returns the HTTP client and base URL of the kernel's local
// endpoint. A test can pin BaseURL (an httptest server); production resolves
// the Unix socket (or, on Windows, the loopback address file) the way
// agent/xraykern does, so both clients always reach the same kernel.
func (c *AuditClient) endpoint() (*http.Client, string, error) {
	if c.opts.BaseURL != "" {
		cl := c.opts.HTTP
		if cl == nil {
			cl = &http.Client{}
		}
		return cl, strings.TrimRight(c.opts.BaseURL, "/"), nil
	}
	cl, base, err := auditEndpoint(c.opts.ConfigPath)
	if err != nil {
		return nil, "", err
	}
	if c.opts.HTTP != nil {
		// A caller-supplied client (tests) still governs the transport.
		cl = c.opts.HTTP
	}
	return cl, base, nil
}

// auditEndpoint builds the HTTP client and base URL of the kernel's local
// endpoint on this platform. It mirrors agent/xraykern's statusEndpoint (which
// is unexported and cannot be imported), including the legacy socket next to
// config.yml that a kernel up to v0.6.0 left behind.
func auditEndpoint(configPath string) (*http.Client, string, error) {
	if configPath == "" {
		return nil, "", errors.New("xraysvc: an audit ConfigPath is required")
	}
	if socket := auditSocketPath(filepath.Dir(configPath)); socket != "" {
		tr := &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		}
		return &http.Client{Transport: tr}, "http://unix", nil
	}
	addrPath := xrayapi.AddrPath(filepath.Dir(configPath))
	b, err := os.ReadFile(addrPath)
	if err != nil {
		return nil, "", fmt.Errorf("Xray 内核状态接口不可用（读取 %s: %v）", addrPath, err)
	}
	addr := strings.TrimSpace(string(b))
	if addr == "" {
		return nil, "", fmt.Errorf("Xray 内核状态接口不可用（%s 是空的）", addrPath)
	}
	return &http.Client{}, "http://" + addr, nil
}

// auditSocketPath returns the kernel's Unix socket when this platform has one
// and it exists: the runtime directory first, then the legacy location next to
// config.yml. An empty result means "no socket here" (Windows, or a kernel that
// has not started yet), and the caller falls back to the address file.
func auditSocketPath(configDir string) string {
	first := xrayapi.SocketPath(configDir)
	if !strings.HasSuffix(first, xrayapi.StatusSocketName) {
		// Windows: SocketPath is the address file, not a socket.
		return ""
	}
	for _, candidate := range []string{first, filepath.Join(configDir, xrayapi.StatusSocketName)} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}
