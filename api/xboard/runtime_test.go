package xboard

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMachineRequestsAnnounceRuntime(t *testing.T) {
	c, reqs := newMachineServer(t, 0, func(r *machineReq, w http.ResponseWriter) {
		io.WriteString(w, `{"nodes":[],"version":"v"}`)
	})
	if _, _, err := c.ListMachineNodes(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := (*reqs)[0].runtime; got != "1" {
		t.Fatalf("%s header = %q, want 1", RuntimeHeader, got)
	}
	checkMachineAuth(t, *reqs)
}

func TestNodeModeDoesNotAnnounceRuntime(t *testing.T) {
	got := "unset"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get(RuntimeHeader)
		io.WriteString(w, `{"users":[]}`)
	}))
	t.Cleanup(srv.Close)
	c := New(Config{APIHost: srv.URL + "/", Key: "tok", NodeID: 5, NodeType: "vless"})
	if _, err := c.GetUsers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("node-mode request carried %s=%q", RuntimeHeader, got)
	}
}

func TestGetMachineRuntime(t *testing.T) {
	for _, tc := range []struct {
		name          string
		status        int
		body          string
		wantNil       bool
		wantNoProfile bool
		wantErr       string
	}{
		{name: "on", status: 200, body: `{"version":"abc","outbounds":[{"tag":"direct4","protocol":"freedom"}],"routing":{"domainStrategy":"AsIs","rules":[]},"dns":null}`},
		{name: "off", status: 204, wantNil: true, wantNoProfile: true},
		{name: "panel predates runtime", status: 404, body: `{"message":"not found"}`, wantNil: true},
		{name: "missing version", status: 200, body: `{"outbounds":[]}`, wantErr: "missing version"},
		{name: "bad json", status: 200, body: `{`, wantErr: "decode runtime"},
		{name: "bad token", status: 401, body: `{"error":"bad_credentials"}`, wantErr: "bad credentials"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, reqs := newMachineServer(t, 0, func(r *machineReq, w http.ResponseWriter) {
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			})
			rt, err := c.GetMachineRuntime(context.Background())
			if tc.wantNoProfile {
				if !errors.Is(err, ErrNoRuntimeProfile) || rt != nil {
					t.Fatalf("GetMachineRuntime = %+v, %v; want ErrNoRuntimeProfile", rt, err)
				}
				return
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				if strings.Contains(err.Error(), machineTestToken) {
					t.Fatalf("token leaked into %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantNil != (rt == nil) {
				t.Fatalf("runtime = %+v, want nil=%v", rt, tc.wantNil)
			}
			if rt != nil && (rt.Version != "abc" || !strings.Contains(string(rt.Outbounds), "direct4") || string(rt.DNS) != "null") {
				t.Fatalf("decoded %+v", rt)
			}
			if p := (*reqs)[0].path; p != machineRuntimePath {
				t.Fatalf("path = %s", p)
			}
			checkMachineAuth(t, *reqs)
		})
	}
}

func TestGetMachineRuntimeTooLarge(t *testing.T) {
	c, _ := newMachineServer(t, 0, func(r *machineReq, w http.ResponseWriter) {
		io.WriteString(w, `{"version":"v","outbounds":"`+strings.Repeat("x", maxRuntimeBytes)+`"}`)
	})
	_, err := c.GetMachineRuntime(context.Background())
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("err = %v", err)
	}
	if errors.Is(err, ErrUnknownNode) {
		t.Fatal("size error must not look like a 404")
	}
}
