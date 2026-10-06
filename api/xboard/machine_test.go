package xboard

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const machineTestToken = "machine-tok-0123456789"

// machineReq is what the fake panel saw, including the auth headers.
type machineReq struct {
	method, path, rawQuery string
	machineID, auth        string
	ifNoneMatch            string
}

func newMachineServer(t *testing.T, nodeID int, handler func(r *machineReq, w http.ResponseWriter)) (*Client, *[]machineReq) {
	t.Helper()
	var reqs []machineReq
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := machineReq{
			method:      r.Method,
			path:        r.URL.Path,
			rawQuery:    r.URL.RawQuery,
			machineID:   r.Header.Get("X-Machine-Id"),
			auth:        r.Header.Get("Authorization"),
			ifNoneMatch: r.Header.Get("If-None-Match"),
		}
		reqs = append(reqs, rec)
		handler(&rec, w)
	}))
	t.Cleanup(srv.Close)
	return New(Config{APIHost: srv.URL + "/", MachineID: 9, MachineToken: machineTestToken, NodeID: nodeID}), &reqs
}

// checkMachineAuth asserts the machine credentials and that the token never
// reached the URL.
func checkMachineAuth(t *testing.T, reqs []machineReq) {
	t.Helper()
	for _, r := range reqs {
		if r.machineID != "9" || r.auth != "Bearer "+machineTestToken {
			t.Errorf("%s %s: headers X-Machine-Id=%q Authorization=%q", r.method, r.path, r.machineID, r.auth)
		}
		if strings.Contains(r.rawQuery, "token") || strings.Contains(r.rawQuery, machineTestToken) {
			t.Errorf("%s %s: token leaked into the query %q", r.method, r.path, r.rawQuery)
		}
	}
}

func TestMachineRequestShape(t *testing.T) {
	c, reqs := newMachineServer(t, 7, func(r *machineReq, w http.ResponseWriter) {
		switch r.path {
		case "/api/v2/server/machine/agent/node/config":
			io.WriteString(w, `{"protocol":"vless","server_port":443,"tls":0}`)
		case "/api/v2/server/machine/agent/node/user":
			io.WriteString(w, `{"users":[]}`)
		default:
			io.WriteString(w, `{"data":true}`)
		}
	})
	ctx := context.Background()
	if _, err := c.GetNodeConfig(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetUsers(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.PushTraffic(ctx, map[int][2]int64{1: {10, 20}}); err != nil {
		t.Fatal(err)
	}
	if err := c.PushStatus(ctx, &Status{CPU: 1}); err != nil {
		t.Fatal(err)
	}
	if !c.MachineMode() {
		t.Fatal("MachineMode() = false")
	}
	if got := len(*reqs); got != 4 {
		t.Fatalf("%d requests, want 4", got)
	}
	for _, r := range *reqs {
		if r.rawQuery != "node_id=7" {
			t.Errorf("%s %s: query %q, want only node_id=7", r.method, r.path, r.rawQuery)
		}
	}
	if p := (*reqs)[0].path; p != "/api/v2/server/machine/agent/node/config" {
		t.Errorf("config path %q", p)
	}
	if p := (*reqs)[1].path; p != "/api/v2/server/machine/agent/node/user" {
		t.Errorf("user path %q", p)
	}
	checkMachineAuth(t, *reqs)
}

func TestMachineETagUnchanged(t *testing.T) {
	c, reqs := newMachineServer(t, 3, func(r *machineReq, w http.ResponseWriter) {
		if r.ifNoneMatch == `"abc"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"abc"`)
		io.WriteString(w, `{"users":[{"id":1,"uuid":"u"}]}`)
	})
	if _, err := c.GetUsers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetUsers(context.Background()); !errors.Is(err, ErrNotModified) {
		t.Fatalf("second request: %v, want ErrNotModified", err)
	}
	if (*reqs)[1].ifNoneMatch != `"abc"` {
		t.Fatal("ETag not sent in machine mode")
	}
	checkMachineAuth(t, *reqs)
}

func TestListMachineNodes(t *testing.T) {
	c, reqs := newMachineServer(t, 0, func(r *machineReq, w http.ResponseWriter) {
		// Values typed the way PHP may emit them.
		io.WriteString(w, `{"nodes":[{"id":"1","type":"vless","name":"a","updated_at":"1700000000"},{"id":2,"type":"vmess","name":"b","updated_at":1700000001}],"version":"sha1-abc"}`)
	})
	nodes, version, err := c.ListMachineNodes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if version != "sha1-abc" {
		t.Errorf("version %q", version)
	}
	want := []MachineNode{
		{ID: 1, Type: "vless", Name: "a", UpdatedAt: 1700000000},
		{ID: 2, Type: "vmess", Name: "b", UpdatedAt: 1700000001},
	}
	if len(nodes) != len(want) {
		t.Fatalf("nodes %+v", nodes)
	}
	for i := range want {
		if nodes[i] != want[i] {
			t.Errorf("node %d = %+v, want %+v", i, nodes[i], want[i])
		}
	}
	r := (*reqs)[0]
	if r.path != "/api/v2/server/machine/agent/nodes" {
		t.Errorf("path %q", r.path)
	}
	if r.rawQuery != "" {
		t.Errorf("list query %q, want empty (node_id 0)", r.rawQuery)
	}
	checkMachineAuth(t, *reqs)
}

func TestListMachineNodesEmptyAndMalformed(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		c, _ := newMachineServer(t, 0, func(r *machineReq, w http.ResponseWriter) {
			io.WriteString(w, `{"nodes":[],"version":""}`)
		})
		nodes, version, err := c.ListMachineNodes(context.Background())
		if err != nil || len(nodes) != 0 || version != "" {
			t.Fatalf("nodes=%v version=%q err=%v", nodes, version, err)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		c, _ := newMachineServer(t, 0, func(r *machineReq, w http.ResponseWriter) {
			io.WriteString(w, `not json`)
		})
		if _, _, err := c.ListMachineNodes(context.Background()); err == nil || !strings.Contains(err.Error(), "decode machine nodes") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestMachineStatusErrors(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   error
	}{
		{http.StatusUnauthorized, `{"error":"bad_credentials"}`, ErrBadCredentials},
		{http.StatusForbidden, `{"error":"machine_disabled"}`, ErrMachineDisabled},
		{http.StatusNotFound, `{"error":"unknown_node"}`, ErrUnknownNode},
	}
	for _, tc := range cases {
		t.Run(tc.body, func(t *testing.T) {
			c, _ := newMachineServer(t, 4, func(r *machineReq, w http.ResponseWriter) {
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			})
			_, err := c.GetNodeConfig(context.Background())
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			// The status code stays reachable for callers that branch on it.
			var se *StatusError
			if !errors.As(err, &se) || se.Code != tc.status {
				t.Fatalf("StatusError not preserved: %v", err)
			}
			if err := c.PushTraffic(context.Background(), map[int][2]int64{1: {1, 1}}); !errors.Is(err, tc.want) {
				t.Fatalf("POST err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestMachineTokenRedacted(t *testing.T) {
	retryDelay = time.Millisecond
	t.Run("transport error", func(t *testing.T) {
		c := New(Config{APIHost: "http://127.0.0.1:1", MachineID: 9, MachineToken: "mach-s3cr3t+tok/en", NodeID: 1, Timeout: time.Second})
		_, err := c.GetUsers(context.Background())
		if err == nil {
			t.Fatal("expected error")
		}
		if strings.Contains(err.Error(), "mach-s3cr3t") || strings.Contains(err.Error(), "tok%2Fen") {
			t.Fatalf("machine token leaked: %v", err)
		}
	})
	t.Run("panel echoes the token", func(t *testing.T) {
		c, _ := newMachineServer(t, 1, func(r *machineReq, w http.ResponseWriter) {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"error":"bad_credentials","debug":"`+machineTestToken+`"}`)
		})
		_, err := c.GetNodeConfig(context.Background())
		if err == nil {
			t.Fatal("expected error")
		}
		if strings.Contains(err.Error(), machineTestToken) {
			t.Fatalf("machine token leaked: %v", err)
		}
		if !strings.Contains(err.Error(), "***") {
			t.Fatalf("redaction marker missing: %v", err)
		}
	})
}

// A plain (non-machine) client must keep the V1 path and query auth.
func TestMachineModeOff(t *testing.T) {
	c, reqs := newServer(t, func(r *recorded, w http.ResponseWriter) {
		io.WriteString(w, `{"users":[]}`)
	})
	if c.MachineMode() {
		t.Fatal("MachineMode() = true without a machine id/token")
	}
	if _, err := c.GetUsers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if (*reqs)[0].path != "/api/v1/server/UniProxy/user" || (*reqs)[0].query["token"] != "tok" {
		t.Fatalf("legacy request shape changed: %s %v", (*reqs)[0].path, (*reqs)[0].query)
	}
}
