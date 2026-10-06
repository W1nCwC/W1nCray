// This file implements the connection lifecycle of the WebSocket client:
// dialing with header authentication, the hello handshake, keepalive, the
// single-writer send queue and the forever-reconnect loop.

package ws

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/panelclient"
	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// WSPath is the panel endpoint of the agent WebSocket. It is a path of its own
// because the legacy /ws is served by a different process and must not be
// touched (docs/PLAN-v9-agent-platform.md, D2).
const WSPath = "/w1ncray-ws"

// Protocol defaults. Every one of them can be overridden in Options so tests
// do not have to sleep for real.
const (
	DefaultDialTimeout    = 10 * time.Second
	DefaultPingEvery      = 25 * time.Second
	DefaultSilenceTimeout = 70 * time.Second
	DefaultHelloTimeout   = 10 * time.Second
	DefaultBackoffMin     = time.Second
	DefaultBackoffMax     = 60 * time.Second
	DefaultQueueSize      = 64
	// DefaultWriteTimeout bounds one frame write so a stalled TCP connection
	// cannot park the writer goroutine forever.
	DefaultWriteTimeout = 10 * time.Second
	// stableConnection is how long a connection must have survived before the
	// reconnect backoff is reset to its minimum (same rule as the panel's own
	// node client, api/xboard/ws.go).
	stableConnection = 2 * time.Minute
	// jitterFraction is the +/- randomisation of every reconnect delay.
	jitterFraction = 0.2
)

// Close codes of the agent protocol (docs/WS-PROTOCOL.md section 1).
const (
	CloseNoRole      = 4400 // neither X-Machine-Id nor a browser ticket
	CloseBadCreds    = 4401 // bad machine id / token
	CloseMachineDown = 4403 // machine disabled on the panel
)

// ErrOffline is returned by Send when no connection is up.
var ErrOffline = errors.New("ws: not connected")

// ErrQueueFull is returned by Send when the writer is behind.
var ErrQueueFull = errors.New("ws: outbound queue full")

// ErrFrameTooLarge is returned when a frame would exceed wsproto.MaxFrame
// (256 KiB): the contract's limit applies in both directions.
var ErrFrameTooLarge = errors.New("ws: frame exceeds 256 KiB")

// rejectedError marks a connection the panel refused: an upgrade answered with
// an HTTP error status, or a close frame carrying an application code (4400 /
// 4401 / 4403). Those are configuration problems an operator must see in the
// log, unlike a network outage, which is expected to heal on its own.
type rejectedError struct{ err error }

func (e *rejectedError) Error() string { return e.err.Error() }
func (e *rejectedError) Unwrap() error { return e.err }

// asRejected reports whether err is an upgrade rejection.
func asRejected(err error) bool {
	var rej *rejectedError
	return errors.As(err, &rej)
}

// Options configures New. The zero value is NOT usable: URL, MachineID and
// Token are required (it mirrors panelclient.Options).
type Options struct {
	// URL is the panel origin, for example "https://panel.example.com" or the
	// full "wss://panel.example.com/w1ncray-ws". The machine token must never
	// be part of it.
	URL string
	// MachineID and Token are the agent's credentials; both are sent in the
	// upgrade request headers and nowhere else.
	MachineID int
	Token     string
	// AgentVersion is reported in the User-Agent header ("dev" when empty).
	AgentVersion string
	// AllowInsecureHTTP permits plain http:// / ws:// to a non-loopback host.
	AllowInsecureHTTP bool
	// HTTP, when non-nil, is copied and used as the underlying client (test
	// hook). A nil value builds a private one.
	HTTP *http.Client
	// TLSClientConfig, when non-nil, is used for the wss upgrade. It exists so
	// a test can trust the certificate of an httptest TLS server; production
	// leaves it nil and uses the system roots.
	TLSClientConfig *tls.Config
	// Log receives the client's events. It never receives the token.
	Log driver.Logger

	// DialTimeout / PingEvery / SilenceTimeout / HelloTimeout override the
	// protocol defaults (10s / 25s / 70s / 10s). Zero = default.
	DialTimeout    time.Duration
	PingEvery      time.Duration
	SilenceTimeout time.Duration
	HelloTimeout   time.Duration
	// WriteTimeout bounds a single frame write (default 10s).
	WriteTimeout time.Duration
	// BackoffMin / BackoffMax bound the reconnect delay (default 1s / 60s).
	BackoffMin time.Duration
	BackoffMax time.Duration
	// Rand returns [0,1) for the +/-20% jitter; nil uses math/rand/v2.
	Rand func() float64
	// QueueSize is the outbound queue length (default 64).
	QueueSize int
}

// Handler is the caller side of the connection. Every method is called from a
// single goroutine at a time (the reader), so implementations need no locking
// for their own protocol state. A Handler must not block indefinitely: the
// reader is not reading while a callback runs.
type Handler interface {
	// Hello is called right after the upgrade; the returned message is sent as
	// the first frame. A zero-value result is still sent (the panel answers
	// hello.ok, and a missing field is better than no hello at all).
	Hello() wsproto.Hello
	// HelloOK is called when the panel answers. The intervals are passed
	// through unchanged; the Agent clamps them (clampIntervals).
	HelloOK(ok wsproto.HelloOK)
	// Frame is called for every non-control frame.
	Frame(env wsproto.Envelope)
	// Disconnected is called when a connection ends, before the next dial.
	// err is nil for a clean local close.
	Disconnected(err error)
}

// Client owns the connection and the reconnect loop. It is safe for concurrent
// use.
type Client struct {
	url       string
	machineID int
	token     string
	userAgent string
	log       driver.Logger
	handler   Handler
	dialer    *websocket.Dialer

	pingEvery      time.Duration
	silenceTimeout time.Duration
	helloTimeout   time.Duration
	writeTimeout   time.Duration
	backoffMin     time.Duration
	backoffMax     time.Duration
	rand           func() float64
	queueSize      int

	mu      sync.Mutex
	conn    *websocket.Conn
	queue   chan []byte
	online  bool
	session string
	// connCancel ends the serve loop of the current connection; it is nil while
	// offline. RequestReconnect uses it to close the connection cleanly.
	connCancel context.CancelFunc
	// reconnectReq is set by RequestReconnect and consumed by Run, so a
	// deliberate reconnect waits only the minimum backoff instead of inheriting
	// one that had grown.
	reconnectReq bool
	// closeReason is what the close frame says when this connection ends. It is
	// reset for every connection and set by RequestReconnect, so a capability
	// reconnect is not reported to the panel as a shutdown.
	closeReason string

	// runMu serialises Run: two reconnect loops would fight over one machine
	// identity on the panel.
	runMu sync.Mutex

	// sessionSeq numbers the hello frames of this process (wsproto.Hello.Seq):
	// it identifies "the n-th hello of this process", not a telemetry index.
	sessionSeq int64
}

// New validates the options and builds a Client. The base URL must be https
// (or wss) unless it points at a loopback host or AllowInsecureHTTP is set.
func New(o Options, h Handler) (*Client, error) {
	if o.MachineID <= 0 {
		return nil, fmt.Errorf("ws: machine id must be positive, got %d", o.MachineID)
	}
	if o.Token == "" {
		return nil, errors.New("ws: token must not be empty")
	}
	if h == nil {
		return nil, errors.New("ws: handler must not be nil")
	}
	raw, err := validateURL(o.URL, o.AllowInsecureHTTP)
	if err != nil {
		return nil, err
	}
	target, err := wsURL(raw, WSPath)
	if err != nil {
		return nil, err
	}

	dialTimeout := o.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = DefaultDialTimeout
	}
	// gorilla owns the HTTP transport of the upgrade, so the caller's client
	// cannot be used as-is; its TLS configuration is the part that matters and
	// is carried over below. The dial timeout is enforced by the dialer.
	httpClient := &http.Client{
		Timeout: dialTimeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
		},
	}
	if o.HTTP != nil {
		// Work on a copy so the caller's client is never mutated.
		cp := *o.HTTP
		httpClient = &cp
	}
	// A caller-supplied client that trusts a private CA must also govern the
	// upgrade, otherwise its TLS configuration would be silently ignored.
	tlsConf := o.TLSClientConfig
	if tlsConf == nil {
		if tr, ok := httpClient.Transport.(*http.Transport); ok {
			tlsConf = tr.TLSClientConfig
		}
	}
	pingEvery := o.PingEvery
	if pingEvery <= 0 {
		pingEvery = DefaultPingEvery
	}
	silence := o.SilenceTimeout
	if silence <= 0 {
		silence = DefaultSilenceTimeout
	}
	hello := o.HelloTimeout
	if hello <= 0 {
		hello = DefaultHelloTimeout
	}
	write := o.WriteTimeout
	if write <= 0 {
		write = DefaultWriteTimeout
	}
	bmin := o.BackoffMin
	if bmin <= 0 {
		bmin = DefaultBackoffMin
	}
	bmax := o.BackoffMax
	if bmax <= 0 {
		bmax = DefaultBackoffMax
	}
	if bmax < bmin {
		bmax = bmin
	}
	size := o.QueueSize
	if size <= 0 {
		size = DefaultQueueSize
	}
	randf := o.Rand
	if randf == nil {
		randf = rand.Float64
	}

	version := o.AgentVersion
	if version == "" {
		version = "dev"
	}

	return &Client{
		url:            target,
		machineID:      o.MachineID,
		token:          o.Token,
		userAgent:      "W1nCray-agent/" + version,
		log:            o.Log,
		handler:        h,
		pingEvery:      pingEvery,
		silenceTimeout: silence,
		helloTimeout:   hello,
		writeTimeout:   write,
		backoffMin:     bmin,
		backoffMax:     bmax,
		rand:           randf,
		queueSize:      size,
		queue:          make(chan []byte, size),
		dialer: &websocket.Dialer{
			Proxy:            http.ProxyFromEnvironment,
			HandshakeTimeout: dialTimeout,
			// A caller-supplied client (tests: a self-signed TLS server) also
			// governs the upgrade.
			TLSClientConfig: tlsConf,
		},
	}, nil
}

// URL returns the endpoint the client dials. It never contains the token.
func (c *Client) URL() string { return c.url }

// Run blocks until ctx is cancelled, reconnecting forever with exponential
// backoff 1s -> 60s (+/-20% jitter). It never returns a transport error: a
// panel that is down, unreachable or answering garbage only delays the next
// attempt, because a panel fixed later must heal without an agent restart.
//
// A connection ended by RequestReconnect is the exception to the growth: its
// next dial waits the minimum backoff, because the caller asked for a fresh
// hello now, not for a retry after a failure.
func (c *Client) Run(ctx context.Context) error {
	c.runMu.Lock()
	defer c.runMu.Unlock()

	// A request that raced the previous Run must not shorten this Run's first
	// backoff.
	c.takeReconnectRequest()
	backoff := c.backoffMin
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		start := time.Now()
		err := c.connect(ctx)
		alive := time.Since(start)

		if ctx.Err() != nil {
			return ctx.Err()
		}
		// The handler is told before the next dial, and always exactly once per
		// connection: a callback that runs only on failure would hide a clean
		// server-side close from the runtime.
		c.handler.Disconnected(err)
		switch {
		case err == nil:
			// A clean local close.
		case asRejected(err):
			// The panel refused us: a warn, with the close code and never the
			// token, so a wrong machine id or a disabled machine is visible.
			c.logf().Warnf("ws: panel rejected the connection: %v", err)
		default:
			c.logf().Debugf("ws: connection ended: %v", err)
		}
		switch {
		case c.takeReconnectRequest():
			// A deliberate local close (RequestReconnect): the caller wants a
			// fresh connection now, so the first retry is the minimum interval
			// and the grown backoff is discarded.
			backoff = c.backoffMin
		case alive >= stableConnection:
			backoff = c.backoffMin
		}
		if !c.sleep(ctx, c.wait(backoff)) {
			return ctx.Err()
		}
		backoff = min(backoff*2, c.backoffMax)
	}
}

// RequestReconnect ends the current connection cleanly so the next dial sends a
// fresh hello, and makes that next dial wait only the minimum backoff. It is a
// no-op while offline: the next connection builds its hello from the current
// state anyway. The reason, when non-empty, is carried in the close frame.
func (c *Client) RequestReconnect(reason string) {
	c.mu.Lock()
	cancel := c.connCancel
	if cancel != nil {
		c.reconnectReq = true
		if reason != "" {
			c.closeReason = reason
		}
	}
	c.mu.Unlock()
	if cancel != nil {
		// Cancelling the connection context is the same clean end the
		// transport uses on shutdown: the serve loop returns nil, the reader
		// and the writer are joined, and Run reconnects.
		cancel()
	}
}

// takeReconnectRequest consumes the flag set by RequestReconnect.
func (c *Client) takeReconnectRequest() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	req := c.reconnectReq
	c.reconnectReq = false
	return req
}

// Send queues one frame. It never blocks on the network: it fails with
// ErrOffline when no connection is up (nothing is buffered while offline) and
// with ErrQueueFull when the writer is behind. The caller decides whether a
// dropped frame is acceptable.
func (c *Client) Send(env wsproto.Envelope) error {
	raw, err := marshalEnvelope(env)
	if err != nil {
		return err
	}
	c.mu.Lock()
	q := c.queue
	online := c.online
	c.mu.Unlock()
	if !online {
		return ErrOffline
	}
	select {
	case q <- raw:
		return nil
	default:
		return ErrQueueFull
	}
}

// SendWait queues one frame, waiting up to timeout for room in the queue. It is
// what the command path uses: a cmd.result must not be dropped silently, so it
// is worth blocking briefly instead of losing the answer.
func (c *Client) SendWait(ctx context.Context, env wsproto.Envelope, timeout time.Duration) error {
	err := c.Send(env)
	if err != ErrQueueFull {
		return err
	}
	raw, mErr := marshalEnvelope(env)
	if mErr != nil {
		return mErr
	}
	c.mu.Lock()
	q := c.queue
	online := c.online
	c.mu.Unlock()
	if !online {
		return ErrOffline
	}
	if timeout <= 0 {
		return ErrQueueFull
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case q <- raw:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ErrQueueFull
	}
}

// Connected reports whether a connection is up AND hello.ok was received. The
// HTTP report loop uses it to decide whether to omit the host payload.
func (c *Client) Connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.online
}

// Session returns the session id of the current connection ("" when offline).
func (c *Client) Session() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.online {
		return ""
	}
	return c.session
}

// NextHelloSeq returns the sequence number of the next hello frame and
// increments the counter. The Agent fills wsproto.Hello.Seq from it.
func (c *Client) NextHelloSeq() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessionSeq++
	return c.sessionSeq
}

// connect dials once and serves the connection until it ends.
func (c *Client) connect(ctx context.Context) error {
	header := http.Header{}
	header.Set("X-Machine-Id", fmt.Sprintf("%d", c.machineID))
	// The token lives in this header and in nothing else.
	header.Set("Authorization", "Bearer "+c.token)
	header.Set("User-Agent", c.userAgent)

	conn, resp, err := c.dialer.DialContext(ctx, c.url, header)
	if err != nil {
		if resp != nil {
			if resp.Body != nil {
				// Drain a bounded amount so the connection can be reused.
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
				resp.Body.Close()
			}
			return &rejectedError{fmt.Errorf("dial %s: %w (http %d)", c.url, err, resp.StatusCode)}
		}
		return fmt.Errorf("dial %s: %w", c.url, err)
	}
	defer conn.Close()

	// The token is not a frame, so no frame can exceed this: gorilla closes
	// the connection itself when the panel sends more than the contract's
	// 256 KiB, which sends us through the reconnect path.
	conn.SetReadLimit(wsproto.MaxFrame)

	// Keepalive. Control frames are consumed inside ReadMessage and never
	// surface to the reader, so the handlers are the only place that can renew
	// the silence deadline for a peer that only sends ping/pong. WriteControl
	// is documented as safe to call concurrently with the writer goroutine.
	renew := func() error { return conn.SetReadDeadline(time.Now().Add(c.silenceTimeout)) }
	conn.SetPongHandler(func(string) error { return renew() })
	conn.SetPingHandler(func(appData string) error {
		if err := renew(); err != nil {
			return err
		}
		return conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(c.writeTimeout))
	})

	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// This connection owns its queue: frames queued for the previous one are
	// dropped, and frames queued here are dropped when it ends. Live data is
	// never replayed (docs/WS-PROTOCOL.md section 7 ruling 3).
	queue := make(chan []byte, c.queueSize)
	c.mu.Lock()
	c.queue = queue
	c.conn = conn
	c.connCancel = cancel
	c.online = false
	c.session = ""
	// A close reason belongs to one connection: the previous one must not leak
	// into this connection's close frame.
	c.closeReason = ""
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.conn = nil
		c.connCancel = nil
		c.online = false
		c.session = ""
		c.mu.Unlock()
		drainQueue(queue)
	}()

	frameCh := make(chan []byte, 1)
	frameErr := make(chan error, 1)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		c.writeLoop(connCtx, conn, queue)
	}()
	go func() {
		defer wg.Done()
		c.readPump(connCtx, conn, frameCh, frameErr)
	}()
	// The order matters on the way out: stop the reader and the writer, wait
	// for both, and only then let the deferred conn.Close() run. Closing first
	// would hide a clean shutdown behind a "use of closed connection" error.
	defer func() {
		cancel()
		wg.Wait()
	}()

	// 1. Say hello.
	helloEnv, err := Encode(wsproto.TypeHello, "", c.handler.Hello())
	if err != nil {
		return err
	}
	hello, err := marshalEnvelope(helloEnv)
	if err != nil {
		return err
	}
	select {
	case queue <- hello:
	case <-connCtx.Done():
		return nil
	}

	// 2. Wait for hello.ok. Until it arrives nothing else is sent: the panel
	// owns the cadence, so telemetry before the handshake would race with a
	// configured interval. Silence extends the deadline, so a slow panel that
	// keeps the socket alive (pong) is not dropped, while a dead peer is.
	handshake := time.NewTimer(c.helloTimeout)
	defer handshake.Stop()
	for !c.handshaken() {
		conn.SetReadDeadline(time.Now().Add(c.silenceTimeout))
		select {
		case raw := <-frameCh:
			if err := c.handleFrame(conn, raw); err != nil {
				return err
			}
		case err := <-frameErr:
			if err == nil {
				return nil
			}
			return err
		case <-handshake.C:
			return errors.New("ws: timed out waiting for hello.ok")
		case <-connCtx.Done():
			return nil
		}
	}

	// 3. Serve until the reader, the writer or ctx ends it.
	for {
		conn.SetReadDeadline(time.Now().Add(c.silenceTimeout))
		select {
		case raw := <-frameCh:
			if err := c.handleFrame(conn, raw); err != nil {
				return err
			}
		case err := <-frameErr:
			if err == nil {
				return nil
			}
			return err
		case <-connCtx.Done():
			return nil
		}
	}
}

// handshaken reports whether hello.ok was accepted on the current connection.
func (c *Client) handshaken() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.online
}

// handleFrame dispatches one inbound frame. Only the reader goroutine calls it,
// which is what lets a Handler keep protocol state without locking. The lock is
// released before the callback: a Handler that answers with Send must not
// deadlock against the reader.
func (c *Client) handleFrame(conn *websocket.Conn, raw []byte) error {
	var env wsproto.Envelope
	if err := strictUnmarshal(raw, &env); err != nil {
		// A frame we cannot even parse is not worth closing the connection
		// over: the panel may be mid-deploy with a newer envelope. Answer and
		// keep going.
		c.logf().Warnf("ws: ignoring undecodable frame: %v", err)
		c.reply(ErrorFrame("", wsproto.ErrCodeBadPayload, "malformed envelope"))
		return nil
	}
	if env.T == "" {
		c.logf().Warnf("ws: ignoring frame without type")
		c.reply(ErrorFrame(env.ID, wsproto.ErrCodeBadPayload, "missing type"))
		return nil
	}
	if env.T == wsproto.TypeHelloOK {
		var ok wsproto.HelloOK
		if err := Decode(env, &ok); err != nil {
			return fmt.Errorf("hello.ok: %w", err)
		}
		c.mu.Lock()
		c.online = true
		c.session = ok.Session
		c.mu.Unlock()
	}
	c.handler.Frame(env)
	return nil
}

// reply is the best-effort answer used by the transport itself (bad payload).
func (c *Client) reply(env wsproto.Envelope) {
	if err := c.Send(env); err != nil {
		c.logf().Debugf("ws: cannot answer %s: %v", env.T, err)
	}
}

// readPump is the only goroutine that reads the connection.
func (c *Client) readPump(ctx context.Context, conn *websocket.Conn, frames chan<- []byte, errs chan<- error) {
	report := func(err error) {
		// The serve loop may already have returned (ctx cancelled, handshake
		// timeout): the send must never block, or the wait group would hang.
		select {
		case errs <- err:
		case <-ctx.Done():
		default:
		}
	}
	for {
		typ, raw, err := conn.ReadMessage()
		if err != nil {
			// A closed connection is the normal end of a connection; report
			// it as such so the caller does not log a spurious failure.
			if ctx.Err() != nil || websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				report(nil)
				return
			}
			// An application close code (4400/4401/4403) is the panel refusing
			// this machine, not a network failure: it must reach the operator.
			var ce *websocket.CloseError
			if errors.As(err, &ce) && ce.Code >= 4000 {
				report(&rejectedError{fmt.Errorf("read: %w", err)})
				return
			}
			report(fmt.Errorf("read: %w", err))
			return
		}
		if typ != websocket.TextMessage {
			// Binary frames are not part of the contract: terminal bytes are
			// base64 inside d (docs/WS-PROTOCOL.md section 1). Ignore and
			// keep the connection, which is more useful than a reconnect.
			c.logf().Warnf("ws: ignoring binary frame (%d bytes)", len(raw))
			continue
		}
		select {
		case frames <- raw:
		case <-ctx.Done():
			return
		}
	}
}

// writeLoop is the only goroutine that writes the connection (gorilla forbids
// concurrent writers). It also owns the keepalive ticker, so a connection has
// exactly one writer and one reader.
func (c *Client) writeLoop(ctx context.Context, conn *websocket.Conn, queue <-chan []byte) {
	ticker := time.NewTicker(c.pingEvery)
	defer ticker.Stop()
	for {
		select {
		case raw := <-queue:
			if err := c.writeRaw(conn, raw); err != nil {
				c.logf().Debugf("ws: write failed: %v", err)
				return
			}
		case <-ticker.C:
			if err := c.writePing(conn); err != nil {
				c.logf().Debugf("ws: ping failed: %v", err)
				return
			}
		case <-ctx.Done():
			c.writeClose(conn)
			return
		}
	}
}

// writeClose ends the connection with a normal closure. The reason is the one
// RequestReconnect recorded for this connection (a deliberate reconnect), or
// the transport's shutdown wording otherwise.
func (c *Client) writeClose(conn *websocket.Conn) {
	c.mu.Lock()
	reason := c.closeReason
	c.mu.Unlock()
	if reason == "" {
		reason = "agent shutting down"
	}
	msg := websocket.FormatCloseMessage(websocket.CloseNormalClosure, reason)
	_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	_ = conn.WriteMessage(websocket.CloseMessage, msg)
}

// writeRaw writes one already-encoded frame. Encoding happens in Send (and once
// for hello), so a frame cannot be wrapped twice on its way out.
func (c *Client) writeRaw(conn *websocket.Conn, raw []byte) error {
	if err := conn.SetWriteDeadline(time.Now().Add(c.writeTimeout)); err != nil {
		return err
	}
	return conn.WriteMessage(websocket.TextMessage, raw)
}

func (c *Client) writePing(conn *websocket.Conn) error {
	if err := conn.SetWriteDeadline(time.Now().Add(c.writeTimeout)); err != nil {
		return err
	}
	return conn.WriteMessage(websocket.PingMessage, nil)
}

// sleep waits for d, returning false when ctx ended first.
func (c *Client) sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// wait applies the +/-20% jitter and clamps the result to [BackoffMin,
// BackoffMax] so a small BackoffMin in a test cannot produce a negative delay.
func (c *Client) wait(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	r := c.rand()
	if r < 0 {
		r = 0
	} else if r >= 1 {
		r = 1 - 1e-9
	}
	d := time.Duration(float64(base) * (1 + jitterFraction*(2*r-1)))
	if d < c.backoffMin {
		d = c.backoffMin
	}
	if d > c.backoffMax {
		d = c.backoffMax
	}
	return d
}

func (c *Client) logf() driver.Logger {
	if c.log == nil {
		return nopLog{}
	}
	return c.log
}

type nopLog struct{}

func (nopLog) Debugf(string, ...any) {}
func (nopLog) Infof(string, ...any)  {}
func (nopLog) Warnf(string, ...any)  {}
func (nopLog) Errorf(string, ...any) {}

// drainQueue empties a connection's queue so its frames cannot leak into the
// next connection.
func drainQueue(q chan []byte) {
	for {
		select {
		case <-q:
		default:
			return
		}
	}
}

// validateURL normalises a panel base URL and enforces the same rules as the
// HTTP client: https (or wss) unless the host is loopback or AllowInsecureHTTP
// is set, and never a URL that carries credentials. The rules themselves come
// from panelclient.ValidateBaseURL, so HTTP and WS can never accept different
// panels (design R9).
//
// The shared validator only knows http/https; the ws/wss spellings are mapped
// onto them for the check and restored afterwards. Its error text echoes the
// URL it was given, so only the scheme://host probe (never a path, a query or
// user info) is handed to it: an operator who pasted the token into the URL
// must not have it repeated into a log line.
func validateURL(raw string, allowInsecureHTTP bool) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", errors.New("ws: base URL must not be empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		// url.Error carries the raw URL; never echo it.
		return "", errors.New("ws: invalid base URL")
	}
	if u.Host == "" {
		return "", errors.New("ws: base URL has no host")
	}
	if u.User != nil {
		// Credentials belong in Options.Token; a URL with user info would end
		// up in error messages and logs.
		return "", errors.New("ws: base URL must not contain user info")
	}
	probe := ""
	switch u.Scheme {
	case "https", "wss":
		probe = "https://" + u.Host
	case "http", "ws":
		probe = "http://" + u.Host
	default:
		return "", fmt.Errorf("ws: base URL has unsupported scheme %q", u.Scheme)
	}
	if _, err := panelclient.ValidateBaseURL(probe, allowInsecureHTTP); err != nil {
		return "", fmt.Errorf("ws: %w", err)
	}
	// The scheme is kept as the operator wrote it; wsURL does the http -> ws
	// conversion. A query string is dropped: the token travels in a header and
	// a query would end up in the panel's access log.
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

// wsURL turns a normalised base URL into the WebSocket endpoint. The token is
// never part of the result.
func wsURL(base, path string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		reason := err
		if inner := errors.Unwrap(err); inner != nil {
			reason = inner
		}
		return "", fmt.Errorf("ws: invalid base URL: %w", reason)
	}
	switch u.Scheme {
	case "https", "wss":
		u.Scheme = "wss"
	case "http", "ws":
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("ws: base URL %s://%s has unsupported scheme %q", u.Scheme, u.Host, u.Scheme)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = path
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}
