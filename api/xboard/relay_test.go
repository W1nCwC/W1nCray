package xboard

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// relayFixture is a panel (HTTPS stand-in) and a relay on a Unix socket, each
// counting the requests it got.
type relayFixture struct {
	panel, relay atomic.Int32
	socket       string
	client       *Client
}

func newRelayFixture(t *testing.T, relay http.HandlerFunc) *relayFixture {
	t.Helper()
	f := &relayFixture{}
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.panel.Add(1)
		w.Header().Set("ETag", `"panel"`)
		_, _ = w.Write([]byte(`{"users":[{"id":1,"uuid":"u"}]}`))
	}))
	t.Cleanup(panel.Close)

	dir, err := os.MkdirTemp("", "relay")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	f.socket = filepath.Join(dir, "r.sock")
	if relay != nil {
		ln, err := net.Listen("unix", f.socket)
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			f.relay.Add(1)
			if r.Header.Get("X-Machine-Id") != "7" || r.Header.Get("Authorization") != "Bearer tok" || r.URL.Query().Get("node_id") != "3" {
				t.Errorf("relay request without the machine credentials: %v", r.Header)
			}
			relay(w, r)
		})}
		go func() { _ = srv.Serve(ln) }()
		t.Cleanup(func() { srv.Close() })
	}
	f.client = New(Config{APIHost: panel.URL, NodeID: 3, MachineID: 7, MachineToken: "tok", RelaySocket: f.socket, Timeout: 2 * time.Second})
	return f
}

func unavailableRelay(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set(RelayHeader, "unavailable")
	w.WriteHeader(http.StatusServiceUnavailable)
}

func TestRequestsGoThroughTheRelayWhenItAnswers(t *testing.T) {
	f := newRelayFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"relay"`)
		_, _ = w.Write([]byte(`{"users":[{"id":2,"uuid":"r"}]}`))
	})

	users, err := f.client.GetUsers(context.Background())
	if err != nil || len(users) != 1 || users[0].ID != 2 {
		t.Fatalf("users = %+v, %v", users, err)
	}
	if f.relay.Load() != 1 || f.panel.Load() != 0 {
		t.Fatalf("relay %d, panel %d", f.relay.Load(), f.panel.Load())
	}
}

func TestAnUnavailableRelayFallsBackToThePanel(t *testing.T) {
	f := newRelayFixture(t, unavailableRelay)

	if err := f.client.PushTraffic(context.Background(), map[int][2]int64{1: {1, 2}}); err != nil {
		t.Fatal(err)
	}
	users, err := f.client.GetUsers(context.Background())
	if err != nil || len(users) != 1 || users[0].ID != 1 {
		t.Fatalf("users = %+v, %v", users, err)
	}
	if f.relay.Load() != 2 || f.panel.Load() != 2 {
		t.Fatalf("relay %d, panel %d", f.relay.Load(), f.panel.Load())
	}
}

func TestNoSocketMeansThePanel(t *testing.T) {
	f := newRelayFixture(t, nil)

	if err := f.client.PushTraffic(context.Background(), map[int][2]int64{1: {1, 2}}); err != nil {
		t.Fatal(err)
	}
	if f.panel.Load() != 1 {
		t.Fatalf("panel %d", f.panel.Load())
	}
}

func TestAStaleSocketFileMeansThePanel(t *testing.T) {
	f := newRelayFixture(t, nil)
	if err := os.WriteFile(f.socket, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := f.client.PushTraffic(context.Background(), map[int][2]int64{1: {1, 2}}); err != nil {
		t.Fatal(err)
	}
	if f.panel.Load() != 1 {
		t.Fatalf("panel %d", f.panel.Load())
	}
}

func TestAForwardedPushThatFailedIsNotSentAgain(t *testing.T) {
	f := newRelayFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(RelayHeader, "lost")
		w.WriteHeader(http.StatusBadGateway)
	})

	err := f.client.PushTraffic(context.Background(), map[int][2]int64{1: {1, 2}})
	if err == nil {
		t.Fatal("the push must fail")
	}
	if f.relay.Load() != 1 || f.panel.Load() != 0 {
		t.Fatalf("relay %d, panel %d: a push the panel may have counted was sent again", f.relay.Load(), f.panel.Load())
	}
}

func TestTheRelayIsNeverUsedOutsideMachineMode(t *testing.T) {
	c := New(Config{APIHost: "http://127.0.0.1:1", Key: "k", NodeID: 3, RelaySocket: "/nonexistent"})
	if c.relay != nil {
		t.Fatal("a node-token client must not use the relay")
	}
}
