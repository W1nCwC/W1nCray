// This file implements the HTTP client the agent uses to talk to the panel
// (contract sections 2 and 3). It performs no retries: every failure is handed
// back to the caller, which owns the scheduling and backoff policy.

package panelclient

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
	// endpointPrefix is the common path prefix of all panel agent endpoints.
	endpointPrefix = "/api/v2/server/machine/agent/"

	// maxResponseBytes is the largest response body the client is willing to
	// read. Anything bigger is rejected instead of being buffered.
	maxResponseBytes = 4 << 20 // 4 MiB

	// maxManifestBytes is the largest signed manifest the client accepts. It
	// matches the transport limit the task sets (1 MiB); a bigger body is
	// rejected before it is buffered in full.
	maxManifestBytes = 1 << 20 // 1 MiB

	// maxRedirects is how many redirects the client follows before giving up.
	maxRedirects = 3

	// defaultTimeout bounds a single request made through the default client.
	defaultTimeout = 30 * time.Second

	// redacted replaces the token inside every message shown to callers.
	redacted = "***"
)

// Options configures New.
type Options struct {
	// BaseURL is the panel origin, for example "https://panel.example.com".
	BaseURL string
	// MachineID identifies this machine on the panel; it must be positive.
	MachineID int
	// Token authenticates the machine; it must not be empty.
	Token string
	// AgentVersion is reported in the User-Agent header ("dev" when empty).
	AgentVersion string
	// AllowInsecureHTTP permits plain http:// to a non-loopback host.
	AllowInsecureHTTP bool
	// HTTP, when non-nil, is copied and used as the underlying client.
	HTTP *http.Client
}

// Client is a small HTTP client for the panel agent API. It is safe for
// concurrent use.
type Client struct {
	baseURL   string
	machineID int
	token     string
	userAgent string
	http      *http.Client
}

// New validates the options and builds a Client. The base URL must be https
// unless it points at a loopback host or AllowInsecureHTTP is set.
func New(o Options) (*Client, error) {
	if o.MachineID <= 0 {
		return nil, fmt.Errorf("panelclient: machine id must be positive, got %d", o.MachineID)
	}
	if o.Token == "" {
		return nil, errors.New("panelclient: token must not be empty")
	}

	u, err := url.Parse(o.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("panelclient: invalid base URL %q: %w", o.BaseURL, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("panelclient: base URL %q has no host", o.BaseURL)
	}
	if u.User != nil {
		// Credentials belong in Options.Token; a URL with user info would also
		// end up in error messages and logs.
		return nil, errors.New("panelclient: base URL must not contain user info")
	}
	switch u.Scheme {
	case "https":
		// Always acceptable.
	case "http":
		if !o.AllowInsecureHTTP && !isLoopbackHost(u.Hostname()) {
			return nil, fmt.Errorf("panelclient: base URL %q must use https (or set AllowInsecureHTTP)", o.BaseURL)
		}
	default:
		return nil, fmt.Errorf("panelclient: base URL %q has unsupported scheme %q", o.BaseURL, u.Scheme)
	}

	httpClient := &http.Client{
		Timeout: defaultTimeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
		},
	}
	if o.HTTP != nil {
		// Work on a copy so the caller's client is never mutated.
		cp := *o.HTTP
		httpClient = &cp
	}
	httpClient.CheckRedirect = redirectPolicy

	version := o.AgentVersion
	if version == "" {
		version = "dev"
	}

	return &Client{
		baseURL:   strings.TrimRight(o.BaseURL, "/"),
		machineID: o.MachineID,
		token:     o.Token,
		userAgent: "W1nCray-agent/" + version,
		http:      httpClient,
	}, nil
}

// isLoopbackHost reports whether host names the local machine.
func isLoopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// redirectPolicy bounds redirects: at most maxRedirects, same host only, and
// never a downgrade from https to plain http.
func redirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) > maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	if len(via) == 0 {
		return nil
	}
	prev := via[len(via)-1]
	if !strings.EqualFold(req.URL.Host, prev.URL.Host) {
		return fmt.Errorf("refusing redirect to a different host %q", req.URL.Host)
	}
	if prev.URL.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("refusing redirect from https to %q", req.URL.Scheme)
	}
	return nil
}

// Config pulls the desired state from POST /config.
func (c *Client) Config(ctx context.Context, req ConfigRequest) (ConfigResponse, error) {
	if req.Schema == 0 {
		req.Schema = Schema
	}
	var out ConfigResponse
	err := c.post(ctx, "config", req, &out)
	return out, err
}

// Ack acknowledges an apply attempt through POST /ack. The response body is
// ignored.
func (c *Client) Ack(ctx context.Context, req AckRequest) error {
	if req.Schema == 0 {
		req.Schema = Schema
	}
	return c.post(ctx, "ack", req, nil)
}

// Report sends a runtime status update through POST /report.
func (c *Client) Report(ctx context.Context, req ReportRequest) (ReportResponse, error) {
	if req.Schema == 0 {
		req.Schema = Schema
	}
	var out ReportResponse
	err := c.post(ctx, "report", req, &out)
	return out, err
}

// CommandResult reports the outcome of a panel command through
// POST /command-result. The response body is ignored.
func (c *Client) CommandResult(ctx context.Context, req CommandResultRequest) error {
	if req.Schema == 0 {
		req.Schema = Schema
	}
	return c.post(ctx, "command-result", req, nil)
}

// Manifest fetches the signed kernel manifest through GET /manifest. The body
// is limited to maxManifestBytes and is returned unparsed: the agent verifies
// it locally against the keys compiled into the binary, never here.
//
// The answers are:
//   - 200: Raw and ETag are set;
//   - 304 (If-None-Match matched): NotModified is true;
//   - 404: ErrNoManifest, the panel has not published a manifest yet;
//   - anything else: a redacted *APIError or a transport error.
//
// The token is never part of the URL and every error text is redacted.
func (c *Client) Manifest(ctx context.Context, req ManifestRequest) (ManifestResponse, error) {
	httpReq, err := c.newRequest(ctx, http.MethodGet, "manifest", nil)
	if err != nil {
		return ManifestResponse{}, c.wrap("manifest", fmt.Errorf("build request: %w", err))
	}
	if req.ETag != "" {
		httpReq.Header.Set("If-None-Match", req.ETag)
	}

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return ManifestResponse{}, c.wrap("manifest", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		return ManifestResponse{NotModified: true}, nil
	case http.StatusNotFound:
		return ManifestResponse{}, ErrNoManifest
	}

	// Read one byte past the limit so a too-large body can be detected.
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes+1))
	if err != nil {
		return ManifestResponse{}, c.wrap("manifest", fmt.Errorf("read response: %w", err))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ManifestResponse{}, c.apiError(resp.StatusCode, data)
	}
	if len(data) > maxManifestBytes {
		return ManifestResponse{}, c.wrap("manifest", fmt.Errorf("response body exceeds %d bytes", maxManifestBytes))
	}
	return ManifestResponse{Raw: data, ETag: resp.Header.Get("ETag")}, nil
}

// newRequest builds a request to an agent endpoint with the four headers every
// call carries. The body is optional (nil for GET).
func (c *Client) newRequest(ctx context.Context, method, endpoint string, body io.Reader) (*http.Request, error) {
	httpReq, err := http.NewRequestWithContext(ctx, method, c.baseURL+endpointPrefix+endpoint, body)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("X-Machine-Id", strconv.Itoa(c.machineID))
	httpReq.Header.Set("Authorization", "Bearer "+c.token)
	httpReq.Header.Set("User-Agent", c.userAgent)
	return httpReq, nil
}

// post performs one JSON POST. A nil out means the response body is ignored.
func (c *Client) post(ctx context.Context, endpoint string, req any, out any) error {
	body, err := json.Marshal(req)
	if err != nil {
		return c.wrap(endpoint, fmt.Errorf("encode request: %w", err))
	}

	httpReq, err := c.newRequest(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return c.wrap(endpoint, fmt.Errorf("build request: %w", err))
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return c.wrap(endpoint, err)
	}
	defer resp.Body.Close()

	// Read one byte past the limit so a too-large body can be detected.
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return c.wrap(endpoint, fmt.Errorf("read response: %w", err))
	}
	if len(data) > maxResponseBytes {
		return c.wrap(endpoint, fmt.Errorf("response body exceeds %d bytes", maxResponseBytes))
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return c.apiError(resp.StatusCode, data)
	}

	if out == nil {
		// Ack and CommandResult accept an empty body.
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return c.wrap(endpoint, fmt.Errorf("decode response: %w", err))
	}
	return nil
}

// apiError turns a non-2xx answer into a redacted *APIError.
func (c *Client) apiError(status int, body []byte) error {
	e := &APIError{Status: status}
	var payload struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &payload); err == nil {
		e.Code = payload.Error
		e.Message = payload.Message
	} else {
		msg := body
		if len(msg) > 200 {
			msg = msg[:200]
		}
		e.Message = string(msg)
	}
	e.Code = c.redact(e.Code)
	e.Message = c.redact(e.Message)
	return e
}

// requestError carries a redacted message while keeping the original error
// reachable through Unwrap.
type requestError struct {
	endpoint string
	msg      string
	err      error
}

func (e *requestError) Error() string {
	return "panel request " + e.endpoint + ": " + e.msg
}

func (e *requestError) Unwrap() error { return e.err }

// wrap redacts err and tags it with the endpoint it came from.
func (c *Client) wrap(endpoint string, err error) error {
	if err == nil {
		return nil
	}
	return &requestError{
		endpoint: endpoint,
		msg:      c.redact(err.Error()),
		err:      err,
	}
}

// redact replaces every occurrence of the token with "***".
func (c *Client) redact(s string) string {
	if c.token == "" {
		return s
	}
	return strings.ReplaceAll(s, c.token, redacted)
}
