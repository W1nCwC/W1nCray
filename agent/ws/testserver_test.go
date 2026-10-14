package ws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// The tests run against a real WebSocket server (httptest + gorilla), never
// against a mocked transport: the handshake, the framing and the close codes
// are exactly what the panel will do.

// testServer is one httptest server that authenticates upgrades like the panel
// does and records what it saw.
type testServer struct {
	t   *testing.T
	srv *httptest.Server

	// wantMachineID and wantToken are the credentials the server accepts.
	wantMachineID string
	wantToken     string
	// silentPings models a peer that never answers a ping: the client must
	// then hit its silence timeout and reconnect.
	silentPings atomic.Bool

	mu      sync.Mutex
	headers []http.Header
	queries []string
	paths   []string
	closes  []int
	conns   chan *testConn
}

// testConn is a server side connection.
type testConn struct {
	ws  *websocket.Conn
	mu  sync.Mutex
	raw [][]byte
	// wmu serialises server writes: the read loop answers pings while the test
	// writes frames, and gorilla forbids concurrent writers.
	wmu sync.Mutex
	// paused stops the read loop, so the client's writer fills its socket
	// buffer and its outbound queue: that is how the ErrQueueFull path is
	// reached deterministically.
	paused atomic.Bool
}

func newTestServer(t *testing.T, machineID, token string) *testServer {
	t.Helper()
	ts := &testServer{
		t:             t,
		wantMachineID: machineID,
		wantToken:     token,
		conns:         make(chan *testConn, 16),
	}
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	ts.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.mu.Lock()
		ts.headers = append(ts.headers, r.Header.Clone())
		ts.queries = append(ts.queries, r.URL.RawQuery)
		ts.paths = append(ts.paths, r.URL.Path)
		ts.mu.Unlock()

		id := r.Header.Get("X-Machine-Id")
		auth := r.Header.Get("Authorization")
		switch {
		case id == "":
			http.Error(w, "no machine", http.StatusForbidden)
			return
		case id != ts.wantMachineID:
			http.Error(w, "machine disabled", http.StatusForbidden)
			return
		case auth != "Bearer "+ts.wantToken:
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		if ts.silentPings.Load() {
			// gorilla answers a ping inside ReadMessage, so the read loop never
			// sees one; a peer that ignores pings needs its own handler.
			conn.SetPingHandler(func(string) error { return nil })
		}
		tc := &testConn{ws: conn}
		select {
		case ts.conns <- tc:
		default:
		}
		go func() {
			for {
				mt, raw, err := conn.ReadMessage()
				if err != nil {
					ts.mu.Lock()
					if ce, ok := err.(*websocket.CloseError); ok {
						ts.closes = append(ts.closes, ce.Code)
					}
					ts.mu.Unlock()
					conn.Close()
					return
				}
				for tc.paused.Load() {
					time.Sleep(10 * time.Millisecond)
				}
				// A real panel answers a ping with a pong (gorilla does it
				// inside ReadMessage); without it the client would see nothing
				// at all on a quiet connection and would (correctly) drop it
				// on the silence timeout.
				if mt == websocket.TextMessage {
					tc.mu.Lock()
					tc.raw = append(tc.raw, raw)
					tc.mu.Unlock()
				}
			}
		}()
	}))
	t.Cleanup(ts.srv.Close)
	return ts
}

func (ts *testServer) url() string {
	return "ws" + strings.TrimPrefix(ts.srv.URL, "http")
}

func (ts *testServer) waitConn(t *testing.T) *testConn {
	t.Helper()
	select {
	case c := <-ts.conns:
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("server never saw a connection")
		return nil
	}
}

func (ts *testServer) maybeConn() *testConn {
	select {
	case c := <-ts.conns:
		return c
	case <-time.After(500 * time.Millisecond):
		return nil
	}
}

func (ts *testServer) lastHeader() http.Header {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if len(ts.headers) == 0 {
		return nil
	}
	return ts.headers[len(ts.headers)-1]
}

// attempts is how many upgrade requests the server has seen, including the
// ones it rejected.
func (ts *testServer) attempts() int {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return len(ts.headers)
}

func (ts *testServer) lastQuery() string {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if len(ts.queries) == 0 {
		return ""
	}
	return ts.queries[len(ts.queries)-1]
}

func (ts *testServer) lastPath() string {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if len(ts.paths) == 0 {
		return ""
	}
	return ts.paths[len(ts.paths)-1]
}

func (ts *testServer) closeCodes() []int {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return append([]int(nil), ts.closes...)
}

// send writes one frame from the server.
func (tc *testConn) send(t *testing.T, env wsproto.Envelope) {
	t.Helper()
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal frame: %v", err)
	}
	tc.sendRaw(t, raw)
}

// sendType writes a frame with an inline payload.
func (tc *testConn) sendType(t *testing.T, typ, id string, d any) {
	t.Helper()
	env, err := Encode(typ, id, d)
	if err != nil {
		t.Fatalf("encode %s: %v", typ, err)
	}
	tc.send(t, env)
}

// sendRaw writes raw bytes, used to push malformed and oversized frames.
func (tc *testConn) sendRaw(t *testing.T, raw []byte) {
	t.Helper()
	tc.wmu.Lock()
	defer tc.wmu.Unlock()
	_ = tc.ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := tc.ws.WriteMessage(websocket.TextMessage, raw); err != nil {
		t.Fatalf("server write: %v", err)
	}
}

// recv returns the next frame the client sent. The server's read loop stores
// every text frame, so a frame that arrived early is not lost.
func (tc *testConn) recv(t *testing.T) wsproto.Envelope {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		tc.mu.Lock()
		if len(tc.raw) > 0 {
			raw := tc.raw[0]
			tc.raw = tc.raw[1:]
			tc.mu.Unlock()
			return decodeFrame(t, raw)
		}
		tc.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("client never sent a frame")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// recvType waits for the first frame of the given type, skipping the others.
func (tc *testConn) recvType(t *testing.T, typ string) wsproto.Envelope {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		env := tc.recv(t)
		if env.T == typ {
			return env
		}
	}
	t.Fatalf("client never sent a %s frame", typ)
	return wsproto.Envelope{}
}

// decodeFrame parses one wire frame into an Envelope whose D holds the payload
// only, so a test can decode it with Decode exactly like the client does.
func decodeFrame(t *testing.T, raw []byte) wsproto.Envelope {
	t.Helper()
	var wire struct {
		T  string          `json:"t"`
		ID string          `json:"id"`
		D  json.RawMessage `json:"d"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("client frame is not an envelope: %v (%s)", err, raw)
	}
	return wsproto.Envelope{T: wire.T, ID: wire.ID, D: wire.D}
}

// closeNow drops the connection from the server side, as a restart would.
func (tc *testConn) closeNow() {
	_ = tc.ws.Close()
}

// pauseReading stops the server's read loop after the frame it just read, so
// the client's writer stalls and its outbound queue can be filled.
func (tc *testConn) pauseReading() { tc.paused.Store(true) }

// closeWith sends a close frame with an application code (4401, 4403, ...).
func (tc *testConn) closeWith(code int) {
	msg := websocket.FormatCloseMessage(code, "rejected")
	tc.wmu.Lock()
	defer tc.wmu.Unlock()
	_ = tc.ws.SetWriteDeadline(time.Now().Add(time.Second))
	_ = tc.ws.WriteMessage(websocket.CloseMessage, msg)
	_ = tc.ws.Close()
}

// decodeInto decodes a frame payload strictly.
func decodeInto(t *testing.T, env wsproto.Envelope, out any) {
	t.Helper()
	if err := Decode(env, out); err != nil {
		t.Fatalf("decode %s: %v (raw d=%s)", env.T, err, env.D)
	}
}

// helloOKEnv builds the panel's answer.
func helloOKEnv(t *testing.T, session string, telemetryS, componentsS int) wsproto.Envelope {
	t.Helper()
	env, err := Encode(wsproto.TypeHelloOK, "", wsproto.HelloOK{
		ServerTime: time.Now().Unix(),
		Intervals:  wsproto.Intervals{TelemetryS: telemetryS, ComponentsS: componentsS},
		Session:    session,
	})
	if err != nil {
		t.Fatalf("encode hello.ok: %v", err)
	}
	return env
}

// recordLogger captures every log line so a test can assert that the token is
// not in any of them.
type recordLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *recordLogger) add(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *recordLogger) Debugf(format string, args ...any) { l.add(format, args...) }
func (l *recordLogger) Infof(format string, args ...any)  { l.add(format, args...) }
func (l *recordLogger) Warnf(format string, args ...any)  { l.add(format, args...) }
func (l *recordLogger) Errorf(format string, args ...any) { l.add(format, args...) }

func (l *recordLogger) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}
