package frp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

// adminSection is appended to the rendered config at apply time. The values
// are random per process start, so they cannot be part of the deterministic
// artifact.
func adminSection(a adminInfo) string {
	return fmt.Sprintf("\n[webServer]\naddr = \"127.0.0.1\"\nport = %d\nuser = %q\npassword = %q\n", a.Port, a.User, a.Pass)
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// newAdmin picks a free loopback port and random credentials. The port is
// probed by binding and releasing it, so a race with another process remains
// possible; Apply retries a start that fails.
func newAdmin() (adminInfo, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return adminInfo{}, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	user, err := randHex(8)
	if err != nil {
		return adminInfo{}, err
	}
	pass, err := randHex(24)
	if err != nil {
		return adminInfo{}, err
	}
	return adminInfo{Port: port, User: "w1nc-" + user, Pass: pass}, nil
}

var adminClient = &http.Client{
	Timeout: 3 * time.Second,
	// Never follow redirects or use proxy settings: this is loopback only.
	Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func (a adminInfo) do(ctx context.Context, method, path string, auth bool, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, "http://127.0.0.1:"+strconv.Itoa(a.Port)+path, nil)
	if err != nil {
		return err
	}
	if auth {
		req.SetBasicAuth(a.User, a.Pass)
	}
	resp, err := adminClient.Do(req)
	if err != nil {
		// The URL carries no secret, but keep errors terse anyway.
		return errors.New("admin api unreachable")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		msg := string(body)
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return fmt.Errorf("admin api %s: status %d: %s", path, resp.StatusCode, msg)
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("admin api %s: bad json", path)
		}
	}
	return nil
}

func (a adminInfo) healthy(ctx context.Context) bool {
	return a.do(ctx, http.MethodGet, "/healthz", false, nil) == nil
}

// frps API.

type frpsProxy struct {
	Name            string `json:"name"`
	TodayTrafficIn  int64  `json:"todayTrafficIn"`
	TodayTrafficOut int64  `json:"todayTrafficOut"`
	CurConns        int64  `json:"curConns"`
	Status          string `json:"status"`
	ClientID        string `json:"clientID"`
	Conf            struct {
		RemotePort int `json:"remotePort"`
	} `json:"conf"`
}

func (a adminInfo) proxies(ctx context.Context, typ string) ([]frpsProxy, error) {
	var r struct {
		Proxies []frpsProxy `json:"proxies"`
	}
	if err := a.do(ctx, http.MethodGet, "/api/proxy/"+typ, true, &r); err != nil {
		return nil, err
	}
	return r.Proxies, nil
}

// traffic returns the per-day counters of a proxy, newest day first.
func (a adminInfo) traffic(ctx context.Context, name string) (in, out []int64, err error) {
	var r struct {
		TrafficIn  []int64 `json:"trafficIn"`
		TrafficOut []int64 `json:"trafficOut"`
	}
	if err = a.do(ctx, http.MethodGet, "/api/traffic/"+name, true, &r); err != nil {
		return nil, nil, err
	}
	return r.TrafficIn, r.TrafficOut, nil
}

// frpc API.

type frpcProxyStatus struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Status     string `json:"status"`
	Err        string `json:"err"`
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
}

func (a adminInfo) status(ctx context.Context) ([]frpcProxyStatus, error) {
	var r map[string][]frpcProxyStatus
	if err := a.do(ctx, http.MethodGet, "/api/status", true, &r); err != nil {
		return nil, err
	}
	var out []frpcProxyStatus
	for _, v := range r {
		out = append(out, v...)
	}
	return out, nil
}

func (a adminInfo) reload(ctx context.Context) error {
	return a.do(ctx, http.MethodGet, "/api/reload?strictConfig=true", true, nil)
}
