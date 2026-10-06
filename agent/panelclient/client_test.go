package panelclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/reconcile"
)

const (
	testToken     = "tok-SECRET-0123456789"
	testMachineID = 7
	testPrefix    = "/api/v2/server/machine/agent/"
)

// newClient builds a Client against a TLS test server.
func newClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c, err := New(Options{
		BaseURL:      srv.URL,
		MachineID:    testMachineID,
		Token:        testToken,
		AgentVersion: "1.2.3",
		HTTP:         srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func tlsServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	io.WriteString(w, body)
}

func noTokenIn(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected an error", what)
	}
	if strings.Contains(err.Error(), testToken) {
		t.Fatalf("%s: error text leaks the token: %q", what, err.Error())
	}
	var api *APIError
	if errors.As(err, &api) && (strings.Contains(api.Code, testToken) || strings.Contains(api.Message, testToken)) {
		t.Fatalf("%s: APIError fields leak the token: %+v", what, api)
	}
}

func TestEveryRequestCarriesTheFourHeadersPathsAndBodies(t *testing.T) {
	type seen struct {
		path string
		body map[string]any
	}
	var got []seen
	srv := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		for h, want := range map[string]string{
			"X-Machine-Id":  strconv.Itoa(testMachineID),
			"Authorization": "Bearer " + testToken,
			"Content-Type":  "application/json",
			"User-Agent":    "W1nCray-agent/1.2.3",
		} {
			if v := r.Header.Get(h); v != want {
				t.Errorf("%s: header %s = %q, want %q", r.URL.Path, h, v, want)
			}
		}
		if r.URL.RawQuery != "" {
			t.Errorf("query string must stay empty, got %q", r.URL.RawQuery)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("%s: body is not JSON: %v", r.URL.Path, err)
		}
		got = append(got, seen{r.URL.Path, body})
		switch strings.TrimPrefix(r.URL.Path, testPrefix) {
		case "config":
			writeJSON(w, 200, `{"schema":1,"unchanged":true,"revision":3}`)
		case "report":
			writeJSON(w, 200, `{"ok":true,"ack_seq":9}`)
		default:
			writeJSON(w, 200, `{"ok":true}`)
		}
	})
	c := newClient(t, srv)
	ctx := context.Background()

	if _, err := c.Config(ctx, ConfigRequest{InstanceID: "9f2c1a7e", AgentVersion: "1.2.3", HaveRevision: 41, HaveHash: "sha256:ab", Platform: Platform{OS: "linux", Arch: "mipsle"}, Engines: []string{"gost"}, Kernels: map[string]string{"gost": "3.3.0"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.Ack(ctx, AckRequest{InstanceID: "9f2c1a7e", Revision: 42, Hash: "sha256:cd", Report: reconcile.Report{Revision: 42, Status: reconcile.StatusRejected, Instances: []reconcile.InstanceReport{}}}); err != nil {
		t.Fatal(err)
	}
	rr, err := c.Report(ctx, ReportRequest{InstanceID: "9f2c1a7e", Seq: 9, TS: 1790000030, AppliedRevision: 42, AppliedHash: "sha256:cd"})
	if err != nil {
		t.Fatal(err)
	}
	if !rr.OK || rr.AckSeq != 9 {
		t.Errorf("report response = %+v", rr)
	}
	if err := c.CommandResult(ctx, CommandResultRequest{InstanceID: "9f2c1a7e", ID: "01JAB", Status: ResultDone, Result: json.RawMessage(`{"revision":42}`)}); err != nil {
		t.Fatal(err)
	}

	wantPaths := []string{"config", "ack", "report", "command-result"}
	if len(got) != len(wantPaths) {
		t.Fatalf("server saw %d requests, want %d", len(got), len(wantPaths))
	}
	for i, p := range wantPaths {
		if got[i].path != testPrefix+p {
			t.Errorf("request %d path = %q, want %q", i, got[i].path, testPrefix+p)
		}
		if got[i].body["schema"] != float64(1) {
			t.Errorf("request %d: schema = %v, want 1 (filled in by the client)", i, got[i].body["schema"])
		}
		if got[i].body["instance_id"] != "9f2c1a7e" {
			t.Errorf("request %d: instance_id = %v", i, got[i].body["instance_id"])
		}
	}
	// Config body
	cfg := got[0].body
	if cfg["have_revision"] != float64(41) || cfg["have_hash"] != "sha256:ab" || cfg["agent_version"] != "1.2.3" {
		t.Errorf("config body = %v", cfg)
	}
	if p, _ := cfg["platform"].(map[string]any); p["os"] != "linux" || p["arch"] != "mipsle" {
		t.Errorf("config platform = %v", cfg["platform"])
	}
	// Ack body
	ack := got[1].body
	if ack["revision"] != float64(42) || ack["hash"] != "sha256:cd" {
		t.Errorf("ack body = %v", ack)
	}
	if rep, _ := ack["report"].(map[string]any); rep["status"] != "rejected" {
		t.Errorf("ack report = %v", ack["report"])
	}
	// Report body
	rep := got[2].body
	if rep["seq"] != float64(9) || rep["ts"] != float64(1790000030) || rep["applied_revision"] != float64(42) || rep["applied_hash"] != "sha256:cd" {
		t.Errorf("report body = %v", rep)
	}
	// Command result body
	cr := got[3].body
	if cr["id"] != "01JAB" || cr["status"] != "done" {
		t.Errorf("command-result body = %v", cr)
	}
	if res, _ := cr["result"].(map[string]any); res["revision"] != float64(42) {
		t.Errorf("command-result result = %v", cr["result"])
	}
}

func TestDefaultUserAgentIsDev(t *testing.T) {
	srv := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		if ua := r.Header.Get("User-Agent"); ua != "W1nCray-agent/dev" {
			t.Errorf("User-Agent = %q", ua)
		}
		writeJSON(w, 200, `{"ok":true}`)
	})
	c, err := New(Options{BaseURL: srv.URL, MachineID: 1, Token: testToken, HTTP: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Ack(context.Background(), AckRequest{}); err != nil {
		t.Fatal(err)
	}
}

func TestConfigUnchangedAndChanged(t *testing.T) {
	var n atomic.Int32
	srv := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			writeJSON(w, 200, `{"schema":1,"unchanged":true,"revision":41}`)
			return
		}
		writeJSON(w, 200, `{"schema":1,"revision":42,"hash":"sha256:cd34","issued_at":1790000000,
			"desired":{"version":1,"revision":42,"instances":[]},
			"commands":[{"id":"01JAB","type":"refresh","args":{},"expires_at":1790000060}]}`)
	})
	c := newClient(t, srv)

	resp, err := c.Config(context.Background(), ConfigRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Unchanged || resp.Revision != 41 || len(resp.DesiredRaw) != 0 {
		t.Fatalf("unchanged response = %+v", resp)
	}

	resp, err = c.Config(context.Background(), ConfigRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Unchanged || resp.Revision != 42 || resp.Hash != "sha256:cd34" || resp.IssuedAt != 1790000000 {
		t.Fatalf("changed response = %+v", resp)
	}
	d, err := resp.Desired()
	if err != nil {
		t.Fatalf("Desired: %v", err)
	}
	if d.Revision != 42 || d.Version != 1 {
		t.Errorf("desired = %+v", d)
	}
	if len(resp.Commands) != 1 || resp.Commands[0].ID != "01JAB" || resp.Commands[0].Type != CmdRefresh || resp.Commands[0].ExpiresAt != 1790000060 {
		t.Errorf("commands = %+v", resp.Commands)
	}
}

func TestDesiredIsStrict(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		rev  int64
	}{
		{"unknown top-level field", `{"version":1,"revision":5,"instances":[],"bogus":1}`, 5},
		{"unknown instance field", `{"version":1,"revision":5,"instances":[{"id":"a","surprise":true}]}`, 5},
		{"revision mismatch", `{"version":1,"revision":6,"instances":[]}`, 5},
		{"trailing data", `{"version":1,"revision":5,"instances":[]} {"x":1}`, 5},
		{"trailing garbage", `{"version":1,"revision":5,"instances":[]} x`, 5},
		{"wrong type", `{"version":1,"revision":"5","instances":[]}`, 5},
		{"not an object", `[1,2]`, 5},
		{"missing", ``, 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ConfigResponse{Revision: tc.rev, DesiredRaw: json.RawMessage(tc.raw)}.Desired()
			var bad *ErrBadDesired
			if !errors.As(err, &bad) {
				t.Fatalf("err = %v (%T), want *ErrBadDesired", err, err)
			}
			if !strings.Contains(err.Error(), "invalid desired state") {
				t.Errorf("error text = %q", err.Error())
			}
		})
	}

	// The same through the wire: unknown fields survive the HTTP decode and are
	// caught by Desired.
	srv := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"schema":1,"revision":5,"hash":"h","desired":{"version":1,"revision":5,"instances":[],"extra":1}}`)
	})
	resp, err := newClient(t, srv).Config(context.Background(), ConfigRequest{})
	if err != nil {
		t.Fatalf("the envelope itself is fine: %v", err)
	}
	var bad *ErrBadDesired
	if _, err := resp.Desired(); !errors.As(err, &bad) {
		t.Fatalf("Desired err = %v, want *ErrBadDesired", err)
	}
}

func TestNon2xxJSONErrorBecomesAPIError(t *testing.T) {
	for _, status := range []int{401, 403, 404, 409, 422, 429, 500, 503} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			srv := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, status, `{"error":"machine.bad","message":"something is wrong"}`)
			})
			c := newClient(t, srv)
			ctx := context.Background()
			_, err := c.Config(ctx, ConfigRequest{})
			var api *APIError
			if !errors.As(err, &api) {
				t.Fatalf("Config err = %v (%T), want *APIError", err, err)
			}
			if api.Status != status || api.Code != "machine.bad" || api.Message != "something is wrong" {
				t.Errorf("APIError = %+v", api)
			}
			// Every endpoint maps errors the same way.
			if err := c.Ack(ctx, AckRequest{}); !errors.As(err, &api) {
				t.Errorf("Ack err = %v", err)
			}
			if _, err := c.Report(ctx, ReportRequest{}); !errors.As(err, &api) {
				t.Errorf("Report err = %v", err)
			}
			if err := c.CommandResult(ctx, CommandResultRequest{}); !errors.As(err, &api) {
				t.Errorf("CommandResult err = %v", err)
			}
		})
	}
}

func TestNonJSONErrorBodyStillGivesAPIError(t *testing.T) {
	srv := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(502)
		io.WriteString(w, "<html>Bad Gateway "+strings.Repeat("x", 500)+"</html>")
	})
	_, err := newClient(t, srv).Config(context.Background(), ConfigRequest{})
	var api *APIError
	if !errors.As(err, &api) {
		t.Fatalf("err = %v (%T), want *APIError", err, err)
	}
	if api.Status != 502 || api.Code != "" || !strings.Contains(api.Message, "Bad Gateway") {
		t.Errorf("APIError = %+v", api)
	}
	if len(api.Message) > 200 {
		t.Errorf("non-JSON message is %d bytes, want it truncated to 200", len(api.Message))
	}
}

func TestTokenNeverAppearsInErrors(t *testing.T) {
	t.Run("echoed in a JSON error body", func(t *testing.T) {
		srv := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
			// A broken panel that reflects the credential it was given.
			auth := r.Header.Get("Authorization")
			writeJSON(w, 401, `{"error":"bad token `+testToken+`","message":"`+auth+` is invalid"}`)
		})
		_, err := newClient(t, srv).Config(context.Background(), ConfigRequest{})
		noTokenIn(t, "json body", err)
		var api *APIError
		if !errors.As(err, &api) || !strings.Contains(api.Message, "***") || !strings.Contains(api.Code, "***") {
			t.Fatalf("the token should be replaced by ***: %+v", api)
		}
	})

	t.Run("echoed in a plain text error body", func(t *testing.T) {
		srv := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(500)
			io.WriteString(w, "token was "+testToken)
		})
		_, err := newClient(t, srv).Report(context.Background(), ReportRequest{})
		noTokenIn(t, "text body", err)
	})

	t.Run("echoed in the status line", func(t *testing.T) {
		srv := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
			conn, buf, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			io.WriteString(buf, "HTTP/1.1 500 "+testToken+"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			buf.Flush()
		})
		err := newClient(t, srv).Ack(context.Background(), AckRequest{})
		noTokenIn(t, "status line", err)
	})

	t.Run("echoed in an undecodable success body", func(t *testing.T) {
		srv := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "not json "+testToken)
		})
		_, err := newClient(t, srv).Config(context.Background(), ConfigRequest{})
		noTokenIn(t, "decode error", err)
	})

	t.Run("network failure", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.NotFoundHandler())
		c := newClient(t, srv)
		srv.Close() // connection refused from now on
		for name, call := range map[string]func() error{
			"config":         func() error { _, err := c.Config(context.Background(), ConfigRequest{}); return err },
			"ack":            func() error { return c.Ack(context.Background(), AckRequest{}) },
			"report":         func() error { _, err := c.Report(context.Background(), ReportRequest{}); return err },
			"command-result": func() error { return c.CommandResult(context.Background(), CommandResultRequest{}) },
		} {
			noTokenIn(t, name, call())
		}
	})

	t.Run("wrap redacts whatever the underlying error says", func(t *testing.T) {
		c := &Client{token: testToken}
		err := c.wrap("config", errors.New("dial failed for "+testToken))
		noTokenIn(t, "wrap", err)
		if !strings.Contains(err.Error(), "config") {
			t.Errorf("the endpoint should be named: %q", err.Error())
		}
	})
}

func TestResponseLimit(t *testing.T) {
	// A valid JSON object padded to exactly n bytes.
	pad := func(n int) string {
		const head = `{"schema":1,"unchanged":true,"revision":1,"pad":"`
		const tail = `"}`
		return head + strings.Repeat("a", n-len(head)-len(tail)) + tail
	}
	t.Run("exactly the limit is accepted", func(t *testing.T) {
		srv := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, pad(maxResponseBytes))
		})
		resp, err := newClient(t, srv).Config(context.Background(), ConfigRequest{})
		if err != nil {
			t.Fatalf("a body of exactly %d bytes must be accepted: %v", maxResponseBytes, err)
		}
		if !resp.Unchanged {
			t.Errorf("resp = %+v", resp)
		}
	})
	t.Run("one byte over is refused", func(t *testing.T) {
		srv := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, pad(maxResponseBytes+1))
		})
		_, err := newClient(t, srv).Config(context.Background(), ConfigRequest{})
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("err = %v, want a size error", err)
		}
	})
	t.Run("an oversized error body is refused too", func(t *testing.T) {
		srv := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 500, pad(maxResponseBytes+10))
		})
		_, err := newClient(t, srv).Config(context.Background(), ConfigRequest{})
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("err = %v, want a size error", err)
		}
	})
}

func TestSchemeRules(t *testing.T) {
	base := Options{MachineID: 1, Token: testToken}
	cases := []struct {
		name     string
		url      string
		insecure bool
		wantErr  string // "" = accepted
	}{
		{"https", "https://panel.example.com", false, ""},
		{"https with port and trailing slash", "https://panel.example.com:8443/", false, ""},
		{"http to a remote host is refused", "http://panel.example.com", false, "must use https"},
		{"http to a remote IP is refused", "http://203.0.113.5", false, "must use https"},
		{"http to a remote host with AllowInsecureHTTP", "http://panel.example.com", true, ""},
		{"http to localhost", "http://localhost:8080", false, ""},
		{"http to 127.0.0.1", "http://127.0.0.1:8080", false, ""},
		{"http to ::1", "http://[::1]:8080", false, ""},
		{"ftp", "ftp://panel.example.com", false, "unsupported scheme"},
		{"no host", "https://", false, "no host"},
		{"user info", "https://user:pass@panel.example.com", false, "user info"},
		{"user without password", "https://user@panel.example.com", false, "user info"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := base
			o.BaseURL, o.AllowInsecureHTTP = tc.url, tc.insecure
			_, err := New(o)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("accepted %q", tc.url)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
			}
			if err != nil && (strings.Contains(err.Error(), "pass") || strings.Contains(err.Error(), testToken)) {
				t.Errorf("error leaks a credential: %v", err)
			}
		})
	}

	t.Run("a scheme-less URL is refused", func(t *testing.T) {
		o := base
		o.BaseURL = "panel.example.com/path"
		if _, err := New(o); err == nil {
			t.Fatal("accepted a URL without scheme")
		}
	})
}

func TestNewValidatesIdentity(t *testing.T) {
	for _, id := range []int{0, -1} {
		if _, err := New(Options{BaseURL: "https://p.example.com", MachineID: id, Token: testToken}); err == nil {
			t.Errorf("machine id %d accepted", id)
		}
	}
	if _, err := New(Options{BaseURL: "https://p.example.com", MachineID: 1, Token: ""}); err == nil {
		t.Error("empty token accepted")
	}
}

func TestLoopbackHTTPServerWorks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"ok":true}`)
	}))
	defer srv.Close()
	c, err := New(Options{BaseURL: srv.URL, MachineID: 1, Token: testToken})
	if err != nil {
		t.Fatalf("a loopback http URL must be accepted: %v", err)
	}
	if err := c.Ack(context.Background(), AckRequest{}); err != nil {
		t.Fatal(err)
	}
}

func TestCallerHTTPClientIsNotMutated(t *testing.T) {
	srv := tlsServer(t, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, `{}`) })
	hc := srv.Client()
	if hc.CheckRedirect != nil {
		t.Fatal("test setup: the client already has a redirect policy")
	}
	if _, err := New(Options{BaseURL: srv.URL, MachineID: 1, Token: testToken, HTTP: hc}); err != nil {
		t.Fatal(err)
	}
	if hc.CheckRedirect != nil {
		t.Error("New installed its redirect policy on the caller's client")
	}
}

func TestRedirects(t *testing.T) {
	t.Run("same host redirect keeps method, body and credentials", func(t *testing.T) {
		var final atomic.Int32
		srv := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == testPrefix+"config" {
				http.Redirect(w, r, testPrefix+"config2", http.StatusTemporaryRedirect)
				return
			}
			final.Add(1)
			if r.Method != http.MethodPost {
				t.Errorf("method after redirect = %s", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer "+testToken || r.Header.Get("X-Machine-Id") != "7" {
				t.Errorf("credentials lost on a same-host redirect: %v", r.Header)
			}
			var req ConfigRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.HaveRevision != 11 {
				t.Errorf("body lost on redirect: %+v %v", req, err)
			}
			writeJSON(w, 200, `{"schema":1,"unchanged":true,"revision":11}`)
		})
		resp, err := newClient(t, srv).Config(context.Background(), ConfigRequest{HaveRevision: 11})
		if err != nil {
			t.Fatal(err)
		}
		if final.Load() != 1 || !resp.Unchanged {
			t.Errorf("final hits = %d, resp = %+v", final.Load(), resp)
		}
	})

	t.Run("cross-host redirect is refused", func(t *testing.T) {
		var other atomic.Int32
		target := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
			other.Add(1)
			writeJSON(w, 200, `{"ok":true}`)
		})
		srv := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
		})
		err := newClient(t, srv).Ack(context.Background(), AckRequest{})
		if err == nil || !strings.Contains(err.Error(), "different host") {
			t.Fatalf("err = %v, want a different-host refusal", err)
		}
		noTokenIn(t, "cross-host", err)
		if other.Load() != 0 {
			t.Fatalf("the other host received %d request(s) (credentials would have gone with them)", other.Load())
		}
	})

	t.Run("https to http redirect is refused", func(t *testing.T) {
		srv := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://"+r.Host+r.URL.Path, http.StatusTemporaryRedirect)
		})
		err := newClient(t, srv).Ack(context.Background(), AckRequest{})
		if err == nil || !strings.Contains(err.Error(), "refusing redirect from https") {
			t.Fatalf("err = %v, want a downgrade refusal", err)
		}
	})

	t.Run("redirect loops stop", func(t *testing.T) {
		var hits atomic.Int32
		srv := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			http.Redirect(w, r, r.URL.Path, http.StatusTemporaryRedirect)
		})
		err := newClient(t, srv).Ack(context.Background(), AckRequest{})
		if err == nil || !strings.Contains(err.Error(), "redirects") {
			t.Fatalf("err = %v, want a redirect-limit error", err)
		}
		if hits.Load() > maxRedirects+2 {
			t.Errorf("followed %d hops", hits.Load())
		}
	})
}

func TestContextCancellationInterruptsARequest(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	srv := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	defer close(release)
	c := newClient(t, srv)

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := c.Config(ctx, ConfigRequest{})
		errc <- err
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the request never reached the server")
	}
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
		noTokenIn(t, "canceled", err)
	case <-time.After(10 * time.Second):
		t.Fatal("cancellation did not interrupt the request")
	}

	// A context that is already done never reaches the network.
	var hits atomic.Int32
	srv2 := tlsServer(t, func(w http.ResponseWriter, r *http.Request) { hits.Add(1); writeJSON(w, 200, `{}`) })
	done, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if err := newClient(t, srv2).Ack(done, AckRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if hits.Load() != 0 {
		t.Errorf("the server was contacted with a cancelled context")
	}
}

func TestAPIErrorText(t *testing.T) {
	e := &APIError{Status: 422, Code: "bad", Message: "nope"}
	if got := e.Error(); got != "panel answered HTTP 422 (bad): nope" {
		t.Errorf("Error() = %q", got)
	}
	e = &APIError{Status: 502, Message: "gateway"}
	if got := e.Error(); got != "panel answered HTTP 502: gateway" {
		t.Errorf("Error() = %q", got)
	}
}
