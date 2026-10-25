package xboard

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
)

func TestGetMachinePortHop(t *testing.T) {
	const body = `{"version":"abc","rules":[{"node_id":12,"proto":"udp","ports":"20000-20100","to":443}]}`
	c, reqs := newMachineServer(t, 0, func(r *machineReq, w http.ResponseWriter) {
		if r.ifNoneMatch == `"abc"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		io.WriteString(w, body)
	})
	ctx := context.Background()

	doc, err := c.GetMachinePortHop(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if doc.Version != "abc" || len(doc.Rules) != 1 || doc.Rules[0] != (PortHopRule{NodeID: 12, Proto: "udp", Ports: "20000-20100", To: 443}) {
		t.Fatalf("doc = %+v", doc)
	}
	if _, err := c.GetMachinePortHop(ctx, "abc"); !errors.Is(err, ErrNotModified) {
		t.Fatalf("an unchanged version: err = %v, want ErrNotModified", err)
	}
	r := *reqs
	if r[0].path != "/api/v2/server/machine/agent/porthop" || r[0].ifNoneMatch != "" || r[1].ifNoneMatch != `"abc"` {
		t.Fatalf("requests = %+v", r)
	}
	checkMachineAuth(t, r)
}

func TestGetMachinePortHopStatuses(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		empty   bool
		wantErr string
	}{
		{name: "empty rule set", status: 200, body: `{"version":"v","rules":[]}`, empty: true},
		{name: "null rules", status: 200, body: `{"version":"v","rules":null}`, empty: true},
		{name: "panel predates port hopping", status: 404, body: `{"message":"not found"}`, empty: true},
		{name: "missing version", status: 200, body: `{"rules":[]}`, wantErr: "missing version"},
		{name: "bad json", status: 200, body: `{`, wantErr: "decode port-hop"},
		{name: "bad token", status: 401, body: `{"error":"bad_credentials"}`, wantErr: "bad credentials"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newMachineServer(t, 0, func(r *machineReq, w http.ResponseWriter) {
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			})
			doc, err := c.GetMachinePortHop(context.Background(), "")
			if tc.wantErr != "" {
				if err == nil || !contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || doc == nil || len(doc.Rules) != 0 {
				t.Fatalf("doc = %+v, err = %v; want an empty rule set", doc, err)
			}
		})
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
