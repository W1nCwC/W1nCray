// Package xboard is the client of the Xboard node API (UniProxy).
//
// Contract (Xboard app/Http/Routes/V1/ServerRoute.php, UniProxyController):
//
//	GET  /api/v1/server/UniProxy/config     node config, ETag
//	GET  /api/v1/server/UniProxy/user       {"users":[...]}, ETag
//	POST /api/v1/server/UniProxy/push       {uid:[upload,download]}
//	POST /api/v1/server/UniProxy/alive      {uid:[ip,...]}
//	GET  /api/v1/server/UniProxy/alivelist  {"alive":{uid:count}}
//	POST /api/v1/server/UniProxy/status     {cpu,mem,swap,disk}
//
// Authentication is token + node_id (+ optional node_type) on every request.
package xboard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const basePath = "/api/v1/server/UniProxy/"

// ErrNotModified is returned when the panel answers 304.
var ErrNotModified = errors.New("not modified")

// StatusError is a non-2xx answer of the panel.
type StatusError struct {
	Path string
	Code int
	Body string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("request %s: status %d: %s", e.Path, e.Code, e.Body)
}

// Config configures a Client.
type Config struct {
	APIHost  string
	Key      string
	NodeID   int
	NodeType string // optional, Xboard node type (vmess, vless, ...)
	Timeout  time.Duration
}

// Client talks to one Xboard node.
type Client struct {
	cfg   Config
	base  string
	query url.Values
	http  *http.Client

	mu        sync.Mutex
	configTag string
	userTag   string
}

// New creates a client.
func New(cfg Config) *Client {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	q := url.Values{}
	q.Set("token", cfg.Key)
	q.Set("node_id", strconv.Itoa(cfg.NodeID))
	if cfg.NodeType != "" {
		q.Set("node_type", cfg.NodeType)
	}
	return &Client{
		cfg:   cfg,
		base:  strings.TrimRight(cfg.APIHost, "/"),
		query: q,
		http:  &http.Client{Timeout: cfg.Timeout},
	}
}

// Host returns the configured API host.
func (c *Client) Host() string { return c.cfg.APIHost }

// NodeID returns the configured node id.
func (c *Client) NodeID() int { return c.cfg.NodeID }

// ResetETags forces the next config/user requests to return full bodies.
func (c *Client) ResetETags() {
	c.mu.Lock()
	c.configTag, c.userTag = "", ""
	c.mu.Unlock()
}

// retryDelay is the base backoff between GET attempts (variable for tests).
var retryDelay = time.Second

// do sends a request. GET requests are idempotent and are retried up to three
// times on network errors and 5xx answers, like XrayR's resty client; POST
// requests (traffic reports) are sent once so traffic cannot be counted twice.
func (c *Client) do(ctx context.Context, method, name string, body any, etag string) (*http.Response, error) {
	attempts := 1
	if method == http.MethodGet {
		attempts = 3
	}
	var resp *http.Response
	var err error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return nil, err
			case <-time.After(retryDelay * time.Duration(i)):
			}
		}
		resp, err = c.attempt(ctx, method, name, body, etag)
		if !retryable(err) {
			break
		}
	}
	return resp, err
}

func retryable(err error) bool {
	if err == nil || errors.Is(err, ErrNotModified) || errors.Is(err, context.Canceled) {
		return false
	}
	var se *StatusError
	if errors.As(err, &se) {
		return se.Code >= 500
	}
	return true
}

func (c *Client) attempt(ctx context.Context, method, name string, body any, etag string) (*http.Response, error) {
	u := c.base + basePath + name + "?" + c.query.Encode()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, c.redact(err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "W1nCray")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request %s: %w", name, c.redact(err))
	}
	if resp.StatusCode == http.StatusNotModified {
		resp.Body.Close()
		return nil, ErrNotModified
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		return nil, &StatusError{Path: name, Code: resp.StatusCode, Body: c.redactString(strings.TrimSpace(string(b)))}
	}
	return resp, nil
}

// redact removes the node token from errors: *url.Error embeds the full
// request URL, whose query carries the token, and errors end up in logs.
func (c *Client) redact(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		ue.URL = c.redactString(ue.URL)
	}
	return err
}

func (c *Client) redactString(s string) string {
	if c.cfg.Key == "" {
		return s
	}
	s = strings.ReplaceAll(s, url.QueryEscape(c.cfg.Key), "***")
	return strings.ReplaceAll(s, c.cfg.Key, "***")
}

// GetNodeConfig fetches the node config. It returns ErrNotModified when the
// panel reports the cached ETag is still current.
func (c *Client) GetNodeConfig(ctx context.Context) (*NodeConfig, error) {
	c.mu.Lock()
	etag := c.configTag
	c.mu.Unlock()
	resp, err := c.do(ctx, http.MethodGet, "config", nil, etag)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	nc := new(NodeConfig)
	if err := json.Unmarshal(raw, nc); err != nil {
		return nil, fmt.Errorf("decode node config: %w", err)
	}
	if nc.Protocol == "" {
		return nil, fmt.Errorf("decode node config: missing protocol: %.200s", raw)
	}
	nc.Raw = raw
	c.mu.Lock()
	c.configTag = resp.Header.Get("ETag")
	c.mu.Unlock()
	return nc, nil
}

// GetUsers fetches the users of the node. It returns ErrNotModified when the
// list did not change.
func (c *Client) GetUsers(ctx context.Context) ([]User, error) {
	c.mu.Lock()
	etag := c.userTag
	c.mu.Unlock()
	resp, err := c.do(ctx, http.MethodGet, "user", nil, etag)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var body struct {
		Users []User `json:"users"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode users: %w", err)
	}
	c.mu.Lock()
	c.userTag = resp.Header.Get("ETag")
	c.mu.Unlock()
	return body.Users, nil
}

// PushTraffic reports traffic as {uid: [upload, download]}.
func (c *Client) PushTraffic(ctx context.Context, traffic map[int][2]int64) error {
	if len(traffic) == 0 {
		return nil
	}
	body := make(map[string][2]int64, len(traffic))
	for uid, t := range traffic {
		body[strconv.Itoa(uid)] = t
	}
	return c.post(ctx, "push", body)
}

// PushAlive reports online IPs as {uid: [ip, ...]}.
func (c *Client) PushAlive(ctx context.Context, alive map[int][]string) error {
	body := make(map[string][]string, len(alive))
	for uid, ips := range alive {
		body[strconv.Itoa(uid)] = ips
	}
	return c.post(ctx, "alive", body)
}

// GetAliveList returns the panel-wide device count of users with a device
// limit, {uid: count}.
func (c *Client) GetAliveList(ctx context.Context) (map[int]int, error) {
	resp, err := c.do(ctx, http.MethodGet, "alivelist", nil, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var body struct {
		Alive json.RawMessage `json:"alive"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode alivelist: %w", err)
	}
	out := make(map[int]int)
	if t := bytes.TrimSpace(body.Alive); len(t) > 0 && t[0] == '{' {
		var m map[string]Int
		if err := json.Unmarshal(t, &m); err != nil {
			return nil, fmt.Errorf("decode alivelist: %w", err)
		}
		for k, v := range m {
			if uid, err := strconv.Atoi(k); err == nil {
				out[uid] = int(v)
			}
		}
	}
	return out, nil
}

// PushStatus reports the machine load.
func (c *Client) PushStatus(ctx context.Context, s *Status) error {
	return c.post(ctx, "status", s)
}

func (c *Client) post(ctx context.Context, name string, body any) error {
	resp, err := c.do(ctx, http.MethodPost, name, body, "")
	if err != nil {
		return err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	return nil
}
