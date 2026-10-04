package xboard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocket protocol of the Xboard node server (app/WebSocket/NodeWorker.php,
// NodeEventHandlers.php, Services/NodeSyncService.php).
const (
	EventPing          = "ping"
	EventPong          = "pong"
	EventAuthSuccess   = "auth.success"
	EventError         = "error"
	EventSyncConfig    = "sync.config"
	EventSyncUsers     = "sync.users"
	EventSyncUserDelta = "sync.user.delta"
	EventSyncDevices   = "sync.devices"
	EventReportDevices = "report.devices"
	EventNodeStatus    = "node.status"
)

// HandshakeResult is the answer of POST /api/v2/server/handshake.
type HandshakeResult struct {
	WebSocket struct {
		Enabled bool   `json:"enabled"`
		URL     string `json:"ws_url"`
	} `json:"websocket"`
}

// Handshake asks the panel whether nodes should use its WebSocket server.
func (c *Client) Handshake(ctx context.Context) (*HandshakeResult, error) {
	resp, err := c.do(ctx, http.MethodPost, "/api/v2/server/handshake", map[string]any{}, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	r := new(HandshakeResult)
	if err := json.NewDecoder(resp.Body).Decode(r); err != nil {
		return nil, fmt.Errorf("decode handshake: %w", err)
	}
	return r, nil
}

// WSMessage is the envelope of every WebSocket message.
type WSMessage struct {
	Event string          `json:"event"`
	Data  json.RawMessage `json:"data,omitempty"`
}

// IPList decodes a JSON array of IPs, or an object of IPs: PHP's
// array_unique keeps sparse keys, which json_encode turns into an object.
type IPList []string

// UnmarshalJSON implements json.Unmarshaler.
func (l *IPList) UnmarshalJSON(b []byte) error {
	t := bytes.TrimSpace(b)
	if len(t) > 0 && t[0] == '{' {
		var m map[string]String
		if err := json.Unmarshal(t, &m); err != nil {
			return err
		}
		out := make(IPList, 0, len(m))
		for _, v := range m {
			if v != "" {
				out = append(out, string(v))
			}
		}
		*l = out
		return nil
	}
	var s Strings
	if err := json.Unmarshal(t, &s); err != nil {
		return err
	}
	*l = IPList(s)
	return nil
}

// UserDelta is the payload of sync.user.delta.
type UserDelta struct {
	Action String `json:"action"` // add | remove
	Users  []User `json:"users"`
}

// WSHandler receives panel pushes. Calls come from the reader goroutine one
// at a time.
type WSHandler interface {
	OnConnected()
	OnDisconnected(err error)
	OnConfig(*NodeConfig)
	OnUsers([]User)
	OnUserDelta(*UserDelta)
	OnDevices(map[int][]string)
}

// WSClient keeps a WebSocket connection to the panel, reconnecting with
// exponential backoff.
type WSClient struct {
	url     string
	redact  func(string) string
	handler WSHandler
	dialer  *websocket.Dialer

	sendCh    chan WSMessage
	connected atomic.Bool
	panelErr  atomic.Pointer[string] // last "error" event from the panel

	// Tunables (tests shorten them).
	BackoffInitial time.Duration
	BackoffMax     time.Duration
	ReadTimeout    time.Duration
}

// NewWSClient prepares a client for ws_url from the handshake. Authentication
// uses the token and node_id query parameters (NodeWorker::authenticateNode).
func (c *Client) NewWSClient(wsURL string, h WSHandler) (*WSClient, error) {
	u, err := url.Parse(wsURL)
	if err != nil || (u.Scheme != "ws" && u.Scheme != "wss") {
		return nil, fmt.Errorf("invalid websocket url %q", wsURL)
	}
	q := u.Query()
	q.Set("token", c.cfg.Key)
	q.Set("node_id", strconv.Itoa(c.cfg.NodeID))
	u.RawQuery = q.Encode()
	return &WSClient{
		url:     u.String(),
		redact:  c.redactString,
		handler: h,
		dialer: &websocket.Dialer{
			Proxy:            http.ProxyFromEnvironment,
			HandshakeTimeout: 15 * time.Second,
		},
		sendCh:         make(chan WSMessage, 64),
		BackoffInitial: time.Second,
		BackoffMax:     time.Minute,
		// The server pings every 55 s (NodeWorker::PING_INTERVAL).
		ReadTimeout: 3 * 55 * time.Second,
	}, nil
}

// Connected reports whether the connection is up and authenticated.
func (w *WSClient) Connected() bool { return w.connected.Load() }

// Send queues a message; it is dropped when not connected or the queue is full.
func (w *WSClient) Send(event string, data any) bool {
	if !w.connected.Load() {
		return false
	}
	b, err := json.Marshal(data)
	if err != nil {
		return false
	}
	select {
	case w.sendCh <- WSMessage{Event: event, Data: b}:
		return true
	default:
		return false
	}
}

// Run connects and serves until ctx ends.
func (w *WSClient) Run(ctx context.Context) {
	backoff := w.BackoffInitial
	for ctx.Err() == nil {
		start := time.Now()
		err := w.serve(ctx)
		if w.connected.Swap(false) {
			w.handler.OnDisconnected(w.redactErr(err))
		} else if err != nil && ctx.Err() == nil {
			w.handler.OnDisconnected(w.redactErr(err))
		}
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > 2*time.Minute {
			backoff = w.BackoffInitial
		}
		wait := backoff
		if backoff > 4 {
			wait += time.Duration(rand.Int64N(int64(backoff / 4)))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		backoff = min(backoff*2, w.BackoffMax)
	}
}

func (w *WSClient) redactErr(err error) error {
	if p := w.panelErr.Swap(nil); p != nil {
		err = fmt.Errorf("panel error %q: %v", *p, err)
	}
	if err == nil {
		return nil
	}
	return errors.New(w.redact(err.Error()))
}

func (w *WSClient) serve(ctx context.Context) error {
	conn, resp, err := w.dialer.DialContext(ctx, w.url, nil)
	if resp != nil && resp.Body != nil {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
	}
	if err != nil {
		return fmt.Errorf("websocket dial: %w", err)
	}
	defer conn.Close()

	// Drop messages queued while disconnected.
	for len(w.sendCh) > 0 {
		<-w.sendCh
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	writeErr := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
				return
			case m := <-w.sendCh:
				conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := conn.WriteJSON(m); err != nil {
					writeErr <- err
					conn.Close()
					return
				}
			}
		}
	}()
	defer wg.Wait()
	defer cancel()

	for {
		conn.SetReadDeadline(time.Now().Add(w.ReadTimeout))
		var m WSMessage
		if err := conn.ReadJSON(&m); err != nil {
			select {
			case werr := <-writeErr:
				return fmt.Errorf("websocket write: %w", werr)
			default:
			}
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("websocket read: %w", err)
		}
		w.dispatch(m)
	}
}

func (w *WSClient) dispatch(m WSMessage) {
	switch m.Event {
	case EventPing:
		// Not gated on Connected: pong keeps node_ws_alive fresh.
		b, _ := json.Marshal(struct{}{})
		select {
		case w.sendCh <- WSMessage{Event: EventPong, Data: b}:
		default:
		}
	case EventAuthSuccess:
		w.connected.Store(true)
		w.handler.OnConnected()
	case EventError:
		var e struct {
			Message String `json:"message"`
		}
		json.Unmarshal(m.Data, &e)
		msg := string(e.Message)
		w.panelErr.Store(&msg)
	case EventSyncConfig:
		var p struct {
			Config json.RawMessage `json:"config"`
		}
		if json.Unmarshal(m.Data, &p) != nil || len(p.Config) == 0 {
			return
		}
		nc := new(NodeConfig)
		if json.Unmarshal(p.Config, nc) != nil || nc.Protocol == "" {
			return
		}
		nc.Raw = p.Config
		w.handler.OnConfig(nc)
	case EventSyncUsers:
		var p struct {
			Users []User `json:"users"`
		}
		if json.Unmarshal(m.Data, &p) != nil || p.Users == nil {
			return
		}
		w.handler.OnUsers(p.Users)
	case EventSyncUserDelta:
		d := new(UserDelta)
		if json.Unmarshal(m.Data, d) != nil || len(d.Users) == 0 {
			return
		}
		w.handler.OnUserDelta(d)
	case EventSyncDevices:
		var p struct {
			Users map[string]IPList `json:"users"`
		}
		if json.Unmarshal(m.Data, &p) != nil {
			return
		}
		out := make(map[int][]string, len(p.Users))
		for k, ips := range p.Users {
			if uid, err := strconv.Atoi(k); err == nil {
				out[uid] = ips
			}
		}
		w.handler.OnDevices(out)
	}
}

// DevicesPayload builds a report.devices payload: {uid: [ip, ...]}. It must be
// the node's complete snapshot (the panel removes users missing from it).
func DevicesPayload(alive map[int][]string) map[string][]string {
	out := make(map[string][]string, len(alive))
	for uid, ips := range alive {
		out[strconv.Itoa(uid)] = ips
	}
	return out
}
