package node

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/W1nCwC/W1nCray/api/xboard"
)

// fakeWSPanel adds Xboard's handshake and node WebSocket (NodeWorker.php) to
// the fake panel.
type fakeWSPanel struct {
	fp       *fakePanel
	mu       sync.Mutex
	conn     *websocket.Conn
	connects int
	queries  []string
	got      []xboard.WSMessage
}

func newFakeWSPanel(t *testing.T, node string, users []map[string]any) *fakeWSPanel {
	fw := &fakeWSPanel{fp: newFakePanel(t, node, users)}
	fw.fp.hook = fw.serve
	return fw
}

func (fw *fakeWSPanel) serve(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/api/v2/server/handshake":
		fmt.Fprintf(w, `{"websocket":{"enabled":true,"ws_url":"ws://%s/ws"}}`, r.Host)
		return true
	case "/ws":
	default:
		return false
	}
	q := r.URL.Query()
	fw.mu.Lock()
	fw.queries = append(fw.queries, r.URL.RawQuery)
	fw.mu.Unlock()
	if q.Get("token") != "secret" || q.Get("node_id") != "1" {
		w.WriteHeader(http.StatusForbidden)
		return true
	}
	c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
	if err != nil {
		return true
	}
	fw.mu.Lock()
	fw.conn = c
	fw.connects++
	fw.mu.Unlock()

	fw.push("auth.success", `{"node_id":1}`)
	fw.push("sync.config", `{"config":`+fw.configWithoutBase()+`}`)
	fw.fp.mu.Lock()
	users, _ := json.Marshal(fw.fp.users)
	fw.fp.mu.Unlock()
	fw.push("sync.users", `{"users":`+string(users)+`}`)
	for {
		var m xboard.WSMessage
		if err := c.ReadJSON(&m); err != nil {
			return true
		}
		fw.mu.Lock()
		fw.got = append(fw.got, m)
		fw.mu.Unlock()
	}
}

// configWithoutBase mirrors buildNodeConfig(): pushes carry no base_config.
func (fw *fakeWSPanel) configWithoutBase() string {
	fw.fp.mu.Lock()
	defer fw.fp.mu.Unlock()
	var m map[string]json.RawMessage
	json.Unmarshal([]byte(fw.fp.node), &m)
	delete(m, "base_config")
	b, _ := json.Marshal(m)
	return string(b)
}

func (fw *fakeWSPanel) push(event, data string) {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	if fw.conn != nil {
		fw.conn.WriteMessage(websocket.TextMessage, []byte(`{"event":"`+event+`","data":`+data+`}`))
	}
}

func (fw *fakeWSPanel) count(event string) int {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	n := 0
	for _, m := range fw.got {
		if m.Event == event {
			n++
		}
	}
	return n
}

func eventually(t *testing.T, what string, timeout time.Duration, cond func() bool) time.Duration {
	t.Helper()
	start := time.Now()
	for !cond() {
		if time.Since(start) > timeout {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return time.Since(start)
}

func TestE2EWebSocket(t *testing.T) {
	tgt := target(t)
	port := freePort(t, "tcp")
	node := fmt.Sprintf(`{"protocol":"vmess","server_port":%d,"network":"tcp","tls":0,"base_config":{"push_interval":60,"pull_interval":60}}`, port)
	// Only user 2 exists at start.
	fw := newFakeWSPanel(t, node, []map[string]any{{"id": 2, "uuid": uuid2}})
	s := startServerOn(t, fw.fp, nil)

	eventually(t, "websocket connected", 10*time.Second, func() bool { return s.ctl.wsConnected() })
	// The panel clears the node's devices on connect: a snapshot follows.
	eventually(t, "report.devices on connect", 5*time.Second, func() bool { return fw.count(xboard.EventReportDevices) >= 1 })
	fw.mu.Lock()
	q := fw.queries[0]
	fw.mu.Unlock()
	if !strings.Contains(q, "token=secret") || !strings.Contains(q, "node_id=1") {
		t.Fatalf("ws auth query %q", q)
	}

	c1 := startClient(t, protoCases[0].client(port, uuid1))
	c2 := startClient(t, protoCases[0].client(port, uuid2))
	if _, err := c1.get(tgt.URL+"/bytes?n=10", 3*time.Second); err == nil {
		t.Fatal("user 1 accepted before being added")
	}

	// User 2 streams while user 1 is added and the config is re-pushed.
	stream := make(chan error, 1)
	go func() {
		n, err := c2.get(tgt.URL+"/slow", 15*time.Second)
		if err == nil && n != 10*1024 {
			err = fmt.Errorf("got %d bytes", n)
		}
		stream <- err
	}()
	time.Sleep(200 * time.Millisecond)

	fw.push("sync.user.delta", fmt.Sprintf(`{"action":"add","users":[{"id":1,"uuid":"%s","speed_limit":null,"device_limit":null}]}`, uuid1))
	took := eventually(t, "user 1 usable after push", 5*time.Second, func() bool {
		_, err := c1.get(tgt.URL+"/bytes?n=10", 2*time.Second)
		return err == nil
	})
	t.Logf("user added through WebSocket, usable after %v", took)

	// The same config without base_config must not rebuild the inbound
	// (that would cut user 2's stream) nor reset the intervals.
	fw.push("sync.config", `{"config":`+fw.configWithoutBase()+`}`)
	if err := <-stream; err != nil {
		t.Fatalf("re-pushed config disturbed an open connection: %v", err)
	}
	if got := s.ctl.interval(true); got != 60*time.Second {
		t.Fatalf("pull interval after push = %v", got)
	}

	fw.push("sync.user.delta", `{"action":"remove","users":[{"id":1}]}`)
	eventually(t, "user 1 rejected after removal push", 5*time.Second, func() bool {
		_, err := c1.get(tgt.URL+"/bytes?n=10", 2*time.Second)
		return err != nil
	})

	// sync.devices (object-encoded IP list) feeds the cross-node limit.
	fw.push("sync.user.delta", fmt.Sprintf(`{"action":"add","users":[{"id":1,"uuid":"%s","speed_limit":null,"device_limit":1}]}`, uuid1))
	fw.push("sync.devices", `{"users":{"1":{"0":"9.9.9.9"}}}`)
	eventually(t, "user 1 limited by a device on another node", 5*time.Second, func() bool {
		_, err := c1.get(tgt.URL+"/bytes?n=10", 2*time.Second)
		return err != nil
	})
	fw.push("sync.devices", `{"users":{}}`)
	eventually(t, "user 1 allowed once the other device is gone", 5*time.Second, func() bool {
		_, err := c1.get(tgt.URL+"/bytes?n=10", 2*time.Second)
		return err == nil
	})

	fw.push("ping", `{}`)
	eventually(t, "pong", 5*time.Second, func() bool { return fw.count(xboard.EventPong) >= 1 })

	// While connected, devices go over the WebSocket, not HTTP.
	s.ctl.push()
	fw.fp.mu.Lock()
	httpAlive := len(fw.fp.alive)
	fw.fp.mu.Unlock()
	if httpAlive != 0 {
		t.Fatalf("HTTP alive reported while the WebSocket is up: %d", httpAlive)
	}
	if up, down := fw.fp.totals(1); up <= 0 || down <= 0 {
		t.Fatalf("traffic must still go over HTTP: %d/%d", up, down)
	}

	// The panel drops the connection: devices are restored over HTTP and
	// the client reconnects.
	fw.mu.Lock()
	fw.conn.Close()
	fw.mu.Unlock()
	eventually(t, "HTTP alive after disconnect", 5*time.Second, func() bool {
		fw.fp.mu.Lock()
		defer fw.fp.mu.Unlock()
		return len(fw.fp.alive) >= 1
	})
	eventually(t, "reconnected", 10*time.Second, func() bool {
		fw.mu.Lock()
		n := fw.connects
		fw.mu.Unlock()
		return n >= 2 && s.ctl.wsConnected()
	})
}

func TestE2EWebSocketDisabled(t *testing.T) {
	port := freePort(t, "tcp")
	fp := newFakePanel(t, vmessNode(port, "[]"), panelUsers(0, 0))
	fp.hook = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/api/v2/server/handshake" {
			w.Write([]byte(`{"websocket":{"enabled":false}}`))
			return true
		}
		return false
	}
	s := startServerOn(t, fp, nil)
	time.Sleep(500 * time.Millisecond)
	if s.ctl.wsConnected() || s.ctl.ws.Load() != nil {
		t.Fatal("websocket used although the panel disabled it")
	}
	tgt := target(t)
	c := startClient(t, protoCases[0].client(port, uuid1))
	if _, err := c.get(tgt.URL+"/bytes?n=100", 10*time.Second); err != nil {
		t.Fatalf("HTTP-only node: %v", err)
	}
	s.ctl.push()
	if len(fp.aliveIPs(1)) == 0 {
		t.Fatal("HTTP alive not reported in HTTP-only mode")
	}
}
