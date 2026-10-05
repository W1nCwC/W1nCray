package gost

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Object kinds of gost's REST API (path segment under /config).
const (
	kindAdmission = "admissions"
	kindLimiter   = "limiters"
	kindCLimiter  = "climiters"
	kindChain     = "chains"
	kindService   = "services"
)

// apiClient talks to the gost API on 127.0.0.1 with basic auth.
type apiClient struct {
	base string
	user string
	pass string
	hc   *http.Client
}

func newAPIClient(ep endpoint, timeout time.Duration) *apiClient {
	return &apiClient{
		base: "http://" + ep.Addr,
		user: ep.User,
		pass: ep.Pass,
		hc: &http.Client{
			Timeout: timeout,
			// The API is on loopback; never follow redirects or use a proxy.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true},
		},
	}
}

// apiError is an error response of the gost API.
type apiError struct {
	Status int
	Code   int
	Msg    string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("gost api: http %d code %d: %s", e.Status, e.Code, e.Msg)
}

func (c *apiClient) do(ctx context.Context, method, path string, body []byte, out any) error {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.user, c.pass)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		// The URL has no credentials; the error is safe to return.
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		ae := &apiError{Status: resp.StatusCode}
		var e struct {
			Code int    `json:"code"`
			Msg  string `json:"msg"`
		}
		if json.Unmarshal(b, &e) == nil {
			ae.Code, ae.Msg = e.Code, e.Msg
		} else {
			ae.Msg = strings.TrimSpace(string(b))
			if len(ae.Msg) > 200 {
				ae.Msg = ae.Msg[:200]
			}
		}
		return ae
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

func itemPath(kind, name string) string {
	return "/config/" + kind + "/" + url.PathEscape(name)
}

func (c *apiClient) create(ctx context.Context, kind string, body []byte) error {
	return c.do(ctx, http.MethodPost, "/config/"+kind, body, nil)
}

func (c *apiClient) update(ctx context.Context, kind, name string, body []byte) error {
	return c.do(ctx, http.MethodPut, itemPath(kind, name), body, nil)
}

func (c *apiClient) remove(ctx context.Context, kind, name string) error {
	return c.do(ctx, http.MethodDelete, itemPath(kind, name), nil, nil)
}

// svcInfo is the part of a service entry of GET /config/services the driver
// reads.
type svcInfo struct {
	Name   string `json:"name"`
	Status *struct {
		CreateTime int64  `json:"createTime"`
		State      string `json:"state"`
		Events     []struct {
			Time int64  `json:"time"`
			Msg  string `json:"msg"`
		} `json:"events"`
		Stats *struct {
			TotalConns   uint64 `json:"totalConns"`
			CurrentConns uint64 `json:"currentConns"`
			TotalErrs    uint64 `json:"totalErrs"`
			InputBytes   uint64 `json:"inputBytes"`
			OutputBytes  uint64 `json:"outputBytes"`
		} `json:"stats"`
	} `json:"status"`
}

func (c *apiClient) services(ctx context.Context) (map[string]svcInfo, error) {
	var resp struct {
		Data struct {
			List []svcInfo `json:"list"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/config/services", nil, &resp); err != nil {
		return nil, err
	}
	m := make(map[string]svcInfo, len(resp.Data.List))
	for _, s := range resp.Data.List {
		m[s.Name] = s
	}
	return m, nil
}

// ping reports whether the API answers with valid credentials.
func (c *apiClient) ping(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/config/services", nil, nil)
}

// lastEvent returns the newest status event message, for error reports.
func (s svcInfo) lastEvent() string {
	if s.Status == nil || len(s.Status.Events) == 0 {
		return ""
	}
	return s.Status.Events[len(s.Status.Events)-1].Msg
}
