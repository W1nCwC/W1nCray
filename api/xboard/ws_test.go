package xboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type recHandler struct {
	mu        sync.Mutex
	connected int
	discon    []error
	configs   []*NodeConfig
	users     [][]User
	deltas    []*UserDelta
	devices   []map[int][]string
}

func (h *recHandler) OnConnected() { h.mu.Lock(); h.connected++; h.mu.Unlock() }
func (h *recHandler) OnDisconnected(err error) {
	h.mu.Lock()
	h.discon = append(h.discon, err)
	h.mu.Unlock()
}
func (h *recHandler) OnConfig(c *NodeConfig) {
	h.mu.Lock()
	h.configs = append(h.configs, c)
	h.mu.Unlock()
}
func (h *recHandler) OnUsers(u []User) { h.mu.Lock(); h.users = append(h.users, u); h.mu.Unlock() }
func (h *recHandler) OnUserDelta(d *UserDelta) {
	h.mu.Lock()
	h.deltas = append(h.deltas, d)
	h.mu.Unlock()
}
func (h *recHandler) OnDevices(m map[int][]string) {
	h.mu.Lock()
	h.devices = append(h.devices, m)
	h.mu.Unlock()
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// fakeWS speaks the Xboard node WebSocket protocol (NodeWorker.php).
type fakeWS struct {
	t       *testing.T
	mu      sync.Mutex
	conns   []*websocket.Conn
	queries []string
	got     []WSMessage
	// inject carries extra server->client messages. Only the handler
	// goroutine writes to the connection (gorilla allows one concurrent
	// writer), so tests push events here instead of calling WriteMessage
	// themselves.
	inject chan WSMessage
}

func (f *fakeWS) handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f.mu.Lock()
	f.queries = append(f.queries, r.URL.RawQuery)
	f.mu.Unlock()
	if q.Get("token") != "tok" || q.Get("node_id") != "5" {
		// The panel closes during the handshake for bad credentials.
		hj, _ := w.(http.Hijacker)
		c, _, _ := hj.Hijack()
		c.Close()
		return
	}
	up := websocket.Upgrader{}
	c, err := up.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	f.mu.Lock()
	f.conns = append(f.conns, c)
	f.mu.Unlock()
	// One writer goroutine per connection (gorilla allows a single
	// concurrent writer); the feeder forwards the test's inject channel into
	// it and exits with the connection.
	wch := make(chan WSMessage, 32)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for m := range wch {
			body := `{"event":"` + m.Event + `"`
			if len(m.Data) > 0 {
				body += `,"data":` + string(m.Data)
			}
			body += `}`
			if c.WriteMessage(websocket.TextMessage, []byte(body)) != nil {
				return
			}
		}
	}()
	go func() {
		for {
			select {
			case m, ok := <-f.inject:
				if !ok {
					return
				}
				select {
				case wch <- m:
				case <-done:
					return
				}
			case <-done:
				return
			}
		}
	}()
	send := func(event string, data string) {
		wch <- WSMessage{Event: event, Data: []byte(data)}
	}
	defer close(wch)
	send("auth.success", `{"node_id":5}`)
	// Full sync, as NodeEventHandlers::pushFullSync does (no base_config).
	send("sync.config", `{"config":{"protocol":"vmess","listen_ip":"0.0.0.0","server_port":443,"network":"tcp","tls":0}}`)
	send("sync.users", `{"users":[{"id":1,"uuid":"a","speed_limit":null,"device_limit":null}]}`)
	for {
		var m WSMessage
		if err := c.ReadJSON(&m); err != nil {
			return
		}
		f.mu.Lock()
		f.got = append(f.got, m)
		f.mu.Unlock()
	}
}

func (f *fakeWS) last() *websocket.Conn {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.conns[len(f.conns)-1]
}

// closeLast closes the most recent server-side connection. net.Conn.Close is
// safe against a concurrent Read.
func (f *fakeWS) closeLast() {
	f.mu.Lock()
	c := f.conns[len(f.conns)-1]
	f.mu.Unlock()
	c.Close()
}

func (f *fakeWS) received(event string) []WSMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []WSMessage
	for _, m := range f.got {
		if m.Event == event {
			out = append(out, m)
		}
	}
	return out
}

func TestHandshake(t *testing.T) {
	var gotPath, gotQuery, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery, gotMethod = r.URL.Path, r.URL.RawQuery, r.Method
		w.Write([]byte(`{"websocket":{"enabled":true,"ws_url":"wss:\/\/panel.example\/ws"}}`))
	}))
	defer srv.Close()
	c := New(Config{APIHost: srv.URL, Key: "tok", NodeID: 5})
	hs, err := c.Handshake(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost || gotPath != "/api/v2/server/handshake" || !strings.Contains(gotQuery, "token=tok") || !strings.Contains(gotQuery, "node_id=5") {
		t.Fatalf("request %s %s?%s", gotMethod, gotPath, gotQuery)
	}
	if !hs.WebSocket.Enabled || hs.WebSocket.URL != "wss://panel.example/ws" {
		t.Fatalf("handshake %+v", hs)
	}
}

func TestWSClientProtocol(t *testing.T) {
	f := &fakeWS{t: t, inject: make(chan WSMessage, 16)}
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	defer srv.Close()
	c := New(Config{APIHost: srv.URL, Key: "tok", NodeID: 5})
	h := &recHandler{}
	wc, err := c.NewWSClient("ws"+strings.TrimPrefix(srv.URL, "http")+"/ws", h)
	if err != nil {
		t.Fatal(err)
	}
	wc.BackoffInitial = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go wc.Run(ctx)

	waitFor(t, "auth + full sync", func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.connected == 1 && len(h.configs) == 1 && len(h.users) == 1
	})
	if !wc.Connected() {
		t.Fatal("not connected after auth.success")
	}
	h.mu.Lock()
	if h.configs[0].Protocol != "vmess" || h.configs[0].ServerPort != 443 || h.configs[0].BaseConfig != nil || len(h.configs[0].Raw) == 0 {
		t.Fatalf("config %+v", h.configs[0])
	}
	if h.users[0][0].ID != 1 || h.users[0][0].UUID != "a" {
		t.Fatalf("users %+v", h.users[0])
	}
	h.mu.Unlock()

	// Server->client messages go through the handler goroutine only: a
	// direct WriteMessage here would race with the client's pong writer on
	// the same gorilla connection.
	f.inject <- WSMessage{Event: "ping"}
	waitFor(t, "pong", func() bool { return len(f.received(EventPong)) == 1 })

	f.inject <- WSMessage{Event: "sync.user.delta", Data: []byte(`{"action":"remove","users":[{"id":1}]}`)}
	f.inject <- WSMessage{Event: "sync.user.delta", Data: []byte(`{"action":"add","users":[{"id":"2","uuid":"b","speed_limit":"10","device_limit":2}]}`)}
	// Sparse PHP array: the IP list arrives as an object.
	f.inject <- WSMessage{Event: "sync.devices", Data: []byte(`{"users":{"2":{"0":"1.1.1.1","2":"2.2.2.2"},"3":["3.3.3.3"]}}`)}
	waitFor(t, "deltas and devices", func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return len(h.deltas) == 2 && len(h.devices) == 1
	})
	h.mu.Lock()
	if h.deltas[0].Action != "remove" || h.deltas[0].Users[0].ID != 1 {
		t.Fatalf("remove delta %+v", h.deltas[0])
	}
	if d := h.deltas[1]; d.Action != "add" || d.Users[0].ID != 2 || d.Users[0].SpeedLimit != 10 || d.Users[0].DeviceLimit != 2 {
		t.Fatalf("add delta %+v", d)
	}
	if ips := h.devices[0][2]; len(ips) != 2 {
		t.Fatalf("object-encoded IPs: %v", h.devices[0])
	}
	if ips := h.devices[0][3]; len(ips) != 1 || ips[0] != "3.3.3.3" {
		t.Fatalf("array-encoded IPs: %v", h.devices[0])
	}
	h.mu.Unlock()

	if !wc.Send(EventReportDevices, DevicesPayload(map[int][]string{2: {"1.1.1.1"}})) {
		t.Fatal("send refused while connected")
	}
	waitFor(t, "report.devices", func() bool { return len(f.received(EventReportDevices)) == 1 })
	var rep map[string][]string
	json.Unmarshal(f.received(EventReportDevices)[0].Data, &rep)
	if rep["2"][0] != "1.1.1.1" {
		t.Fatalf("report payload %v", rep)
	}

	// The server drops the connection: the client reconnects and gets a
	// new full sync. Closing via the handler's own connection object would
	// race with nothing, but the test never kept a reference: ask the fake
	// to close its last conn (Close is safe to call from any goroutine).
	f.closeLast()
	waitFor(t, "reconnect", func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.connected == 2 && len(h.discon) >= 1
	})

	f.mu.Lock()
	q := f.queries[0]
	f.mu.Unlock()
	if !strings.Contains(q, "token=tok") || !strings.Contains(q, "node_id=5") {
		t.Fatalf("auth query %s", q)
	}
}

func TestWSBadTokenRedacted(t *testing.T) {
	f := &fakeWS{t: t, inject: make(chan WSMessage, 16)}
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	defer srv.Close()
	c := New(Config{APIHost: srv.URL, Key: "wrong-s3cret", NodeID: 5})
	h := &recHandler{}
	wc, _ := c.NewWSClient("ws"+strings.TrimPrefix(srv.URL, "http")+"/ws", h)
	wc.BackoffInitial = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go wc.Run(ctx)
	waitFor(t, "dial failure", func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return len(h.discon) == 1
	})
	h.mu.Lock()
	err := h.discon[0]
	h.mu.Unlock()
	if err == nil || strings.Contains(err.Error(), "wrong-s3cret") {
		t.Fatalf("error %v", err)
	}
	if wc.Connected() || h.connected != 0 {
		t.Fatal("connected with a bad token")
	}
}
