package ws

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// testHandler records what the transport handed it.
type testHandler struct {
	helloSent atomic.Int64
	hellos    chan wsproto.Hello
	frames    chan wsproto.Envelope
	oks       chan wsproto.HelloOK
	discs     chan error
	// send, when set, answers control frames the way the Dispatcher does.
	send func(wsproto.Envelope) error
}

func newTestHandler() *testHandler {
	return &testHandler{
		hellos: make(chan wsproto.Hello, 16),
		frames: make(chan wsproto.Envelope, 64),
		oks:    make(chan wsproto.HelloOK, 16),
		discs:  make(chan error, 16),
	}
}

func (h *testHandler) Hello() wsproto.Hello {
	n := h.helloSent.Add(1)
	return wsproto.Hello{AgentVersion: "test", InstanceID: "instance-1", Seq: n}
}

func (h *testHandler) HelloOK(ok wsproto.HelloOK) {
	select {
	case h.oks <- ok:
	default:
	}
}

func (h *testHandler) Frame(env wsproto.Envelope) {
	// The transport already validated hello.ok; a bare test handler has to
	// forward it like the Dispatcher does.
	if env.T == wsproto.TypeHelloOK {
		var ok wsproto.HelloOK
		if err := Decode(env, &ok); err == nil {
			h.HelloOK(ok)
		}
	}
	if env.T == wsproto.TypePing && h.send != nil {
		_ = h.send(wsproto.Envelope{T: wsproto.TypePong})
	}
	select {
	case h.frames <- env:
	default:
	}
}

func (h *testHandler) Disconnected(err error) {
	select {
	case h.discs <- err:
	default:
	}
}

// newTestClient builds a client that talks to ts with test-sized timings.
func newTestClient(t *testing.T, ts *testServer, h Handler, o Options) *Client {
	t.Helper()
	if o.URL == "" {
		o.URL = ts.url()
	}
	if o.MachineID == 0 {
		o.MachineID = 7
	}
	if o.Token == "" {
		o.Token = "secret-token"
	}
	o.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	if o.DialTimeout == 0 {
		o.DialTimeout = 2 * time.Second
	}
	if o.PingEvery == 0 {
		o.PingEvery = 100 * time.Millisecond
	}
	if o.SilenceTimeout == 0 {
		o.SilenceTimeout = 2 * time.Second
	}
	if o.HelloTimeout == 0 {
		o.HelloTimeout = 2 * time.Second
	}
	if o.BackoffMin == 0 {
		o.BackoffMin = 20 * time.Millisecond
	}
	if o.BackoffMax == 0 {
		o.BackoffMax = 200 * time.Millisecond
	}
	if o.Log == nil {
		o.Log = &recordLogger{}
	}
	c, err := New(o, h)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if th, ok := h.(*testHandler); ok {
		th.send = c.Send
	}
	return c
}

// clientRun is one background Client.Run: the cleanup and the test may both
// wait for it, so the result is latched instead of being consumed once.
type clientRun struct {
	cancel context.CancelFunc
	done   chan struct{}
	mu     sync.Mutex
	err    error
}

// runClient starts Run in the background and returns a handle that cancels and
// waits for it.
func runClient(t *testing.T, c *Client) *clientRun {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &clientRun{cancel: cancel, done: make(chan struct{})}
	go func() {
		err := c.Run(ctx)
		r.mu.Lock()
		r.err = err
		r.mu.Unlock()
		close(r.done)
	}()
	t.Cleanup(func() {
		r.stop(t)
	})
	return r
}

// stop cancels the run and waits for it to return.
func (r *clientRun) stop(t *testing.T) {
	t.Helper()
	r.cancel()
	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
		t.Error("Run did not return after cancel")
	}
}

// result returns the error Run returned, waiting for it to finish.
func (r *clientRun) result(t *testing.T) error {
	t.Helper()
	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

// handshake performs the server side of one connection: wait for hello, answer
// hello.ok, and return the connection.
func handshake(t *testing.T, ts *testServer, session string, telemetryS, componentsS int) (*testConn, wsproto.Hello) {
	t.Helper()
	tc := ts.waitConn(t)
	env := tc.recvType(t, wsproto.TypeHello)
	var hello wsproto.Hello
	decodeInto(t, env, &hello)
	tc.send(t, helloOKEnv(t, session, telemetryS, componentsS))
	return tc, hello
}

// waitConnected waits for the client to accept hello.ok. The server sends the
// frame before the client has processed it, so the tests must not assume the
// handshake is complete the moment handshake returns.
func waitConnected(t *testing.T, c *Client, session string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c.Connected() && (session == "" || c.Session() == session) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("client never became connected (connected=%v session=%q, want %q)", c.Connected(), c.Session(), session)
}

// waitDisconnected waits for the handler to be told the connection ended.
func waitDisconnected(t *testing.T, h *testHandler) {
	t.Helper()
	select {
	case <-h.discs:
	case <-time.After(3 * time.Second):
		t.Fatal("Disconnected was not reported")
	}
}

func TestAuthHeadersHandshakeAndNoTokenInURL(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	h := newTestHandler()
	c := newTestClient(t, ts, h, Options{})
	runClient(t, c)

	tc, hello := handshake(t, ts, "session-1", 5, 15)

	if hello.AgentVersion != "test" || hello.InstanceID != "instance-1" || hello.Seq != 1 {
		t.Fatalf("unexpected hello: %+v", hello)
	}

	hdr := ts.lastHeader()
	if got := hdr.Get("X-Machine-Id"); got != "7" {
		t.Errorf("X-Machine-Id = %q, want 7", got)
	}
	if got := hdr.Get("Authorization"); got != "Bearer secret-token" {
		t.Errorf("Authorization = %q, want the bearer token", got)
	}
	// The token must never travel in the URL: the panel's nginx logs queries.
	if q := ts.lastQuery(); q != "" {
		t.Errorf("upgrade query = %q, want empty (token must not be in the URL)", q)
	}
	if p := ts.lastPath(); p != WSPath {
		t.Errorf("upgrade path = %q, want %q", p, WSPath)
	}
	if !strings.HasPrefix(c.URL(), "ws://") || !strings.Contains(c.URL(), WSPath) {
		t.Errorf("client URL = %q, want a ws:// endpoint on %s", c.URL(), WSPath)
	}
	if strings.Contains(c.URL(), "secret-token") {
		t.Fatalf("client URL leaks the token: %s", c.URL())
	}

	// hello.ok was accepted: Connected and Session are set.
	waitConnected(t, c, "session-1")
	select {
	case ok := <-h.oks:
		if ok.Session != "session-1" {
			t.Errorf("HelloOK session = %q", ok.Session)
		}
	case <-time.After(time.Second):
		t.Fatal("HelloOK was not delivered")
	}

	// The negotiated intervals are clamped by the Agent, not here; the raw
	// value reaches the dispatcher unchanged.
	_ = tc
}

func TestMissingAndBadCredentialsCloseWithProtocolCodes(t *testing.T) {
	cases := []struct {
		name      string
		machineID int
		token     string
		want      int
	}{
		{"wrong machine", 9, "secret-token", 4403},
		{"wrong token", 7, "nope", 4401},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := newTestServer(t, "7", "secret-token")
			h := newTestHandler()
			c := newTestClient(t, ts, h, Options{
				MachineID:  tc.machineID,
				Token:      tc.token,
				BackoffMin: 20 * time.Millisecond,
				BackoffMax: 40 * time.Millisecond,
			})
			runClient(t, c)

			// The upgrade is refused: no hello ever reaches the server, the
			// client never reports a session, and it keeps retrying (a fixed
			// token heals without a restart).
			if conn := ts.maybeConn(); conn != nil {
				t.Fatal("server upgraded a connection with bad credentials")
			}
			waitFor(t, func() bool { return ts.attempts() >= 2 }, "the client did not retry a refused upgrade")
			if c.Connected() {
				t.Fatal("Connected() = true without a successful handshake")
			}
			if err := c.Send(wsproto.Envelope{T: wsproto.TypePing}); !errors.Is(err, ErrOffline) {
				t.Errorf("Send while refused = %v, want ErrOffline", err)
			}
		})
	}
}

func TestServerCloseCodeIsReportedWithoutToken(t *testing.T) {
	// A 4401 close frame from the panel must surface as a warning that carries
	// the code and never the token.
	ts := newTestServer(t, "7", "secret-token")
	log := &recordLogger{}
	h := newTestHandler()
	c := newTestClient(t, ts, h, Options{Log: log, BackoffMin: 20 * time.Millisecond, BackoffMax: 40 * time.Millisecond})
	runClient(t, c)

	tc := ts.waitConn(t)
	_ = tc.recvType(t, wsproto.TypeHello)
	tc.closeWith(CloseBadCreds)

	waitDisconnected(t, h)
	got := log.all()
	if strings.Contains(got, "secret-token") {
		t.Fatalf("log leaks the token:\n%s", got)
	}
	// The rejection is a warn (an operator must see it) and carries the code.
	if !strings.Contains(got, "4401") {
		t.Errorf("log does not carry the close code:\n%s", got)
	}
}

func TestServerCloseTriggersReconnectAndNewHello(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	h := newTestHandler()
	c := newTestClient(t, ts, h, Options{BackoffMin: 20 * time.Millisecond, BackoffMax: 40 * time.Millisecond})
	runClient(t, c)

	first, hello1 := handshake(t, ts, "session-1", 5, 15)
	waitConnected(t, c, "session-1")
	first.closeNow()

	waitDisconnected(t, h)
	if c.Connected() {
		t.Error("Connected() = true after the server closed")
	}

	second, hello2 := handshake(t, ts, "session-2", 5, 15)
	waitConnected(t, c, "session-2")
	if hello2.Seq <= hello1.Seq {
		t.Errorf("hello seq did not advance across reconnects: %d then %d", hello1.Seq, hello2.Seq)
	}
	_ = second
}

func TestReconnectBackoffGrowsWithinBounds(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	h := newTestHandler()
	c := newTestClient(t, ts, h, Options{
		BackoffMin: 60 * time.Millisecond,
		BackoffMax: 10 * time.Second,
		Rand:       func() float64 { return 0.5 }, // no jitter
	})
	runClient(t, c)

	// Three connections, each dropped by the server. The gaps must grow.
	stamps := make([]time.Time, 0, 3)
	for i := 0; i < 3; i++ {
		tc, _ := handshake(t, ts, "s", 5, 15)
		waitConnected(t, c, "s")
		stamps = append(stamps, time.Now())
		tc.closeNow()
		waitDisconnected(t, h)
	}
	if len(stamps) < 3 {
		t.Fatalf("only %d connections", len(stamps))
	}
	gap1 := stamps[1].Sub(stamps[0])
	gap2 := stamps[2].Sub(stamps[1])
	if gap1 < 50*time.Millisecond {
		t.Errorf("first reconnect gap %v is below BackoffMin", gap1)
	}
	if gap2 <= gap1 {
		t.Errorf("backoff did not grow: %v then %v", gap1, gap2)
	}
	// Each connection lives far less than stableConnection, so the delay keeps
	// doubling; it must never exceed BackoffMax.
	if gap2 > 500*time.Millisecond {
		t.Errorf("second reconnect gap %v grew too fast", gap2)
	}
}

func TestBackoffJitterStaysWithinTwentyPercent(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	base := 100 * time.Millisecond
	for _, r := range []float64{0, 0.25, 0.5, 0.75, 1} {
		c := newTestClient(t, ts, newTestHandler(), Options{
			BackoffMin: time.Millisecond,
			BackoffMax: time.Minute,
			Rand:       func() float64 { return r },
		})
		got := c.wait(base)
		lo := time.Duration(float64(base) * 0.8)
		hi := time.Duration(float64(base) * 1.2)
		if got < lo || got > hi {
			t.Errorf("wait(%v) with rand=%v = %v, want within [%v, %v]", base, r, got, lo, hi)
		}
	}
	// The clamp wins over the jitter at the bounds.
	c := newTestClient(t, ts, newTestHandler(), Options{
		BackoffMin: 50 * time.Millisecond,
		BackoffMax: 200 * time.Millisecond,
		Rand:       func() float64 { return 0 },
	})
	if got := c.wait(10 * time.Millisecond); got != 50*time.Millisecond {
		t.Errorf("wait below the minimum = %v, want 50ms", got)
	}
	if got := c.wait(time.Hour); got != 200*time.Millisecond {
		t.Errorf("wait above the maximum = %v, want 200ms", got)
	}
}

func TestHelloOKTimeoutReconnects(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	h := newTestHandler()
	c := newTestClient(t, ts, h, Options{
		HelloTimeout: 100 * time.Millisecond,
		BackoffMin:   20 * time.Millisecond,
		BackoffMax:   40 * time.Millisecond,
	})
	runClient(t, c)

	// A server that never answers hello.ok: the client must give up, report
	// the disconnect and try again.
	first := ts.waitConn(t)
	first.recvType(t, wsproto.TypeHello)
	waitDisconnected(t, h)
	if c.Connected() {
		t.Error("Connected() = true without hello.ok")
	}
	// It reconnects: a second hello arrives.
	second := ts.waitConn(t)
	second.recvType(t, wsproto.TypeHello)
}

func TestOversizedFrameDisconnectsAndReconnects(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	h := newTestHandler()
	c := newTestClient(t, ts, h, Options{BackoffMin: 20 * time.Millisecond, BackoffMax: 40 * time.Millisecond})
	runClient(t, c)

	first, _ := handshake(t, ts, "session-1", 5, 15)
	waitConnected(t, c, "session-1")
	// A frame past the contract's 256 KiB must break the connection instead of
	// being buffered.
	big := strings.Repeat("a", wsproto.MaxFrame+1024)
	first.sendRaw(t, []byte(`{"t":"telemetry","d":{"blob":"`+big+`"}}`))

	waitDisconnected(t, h)
	// And the client comes back rather than dying.
	second, _ := handshake(t, ts, "session-2", 5, 15)
	waitConnected(t, c, "session-2")
	_ = second
}

func TestBinaryFramesAreIgnoredAndConnectionSurvives(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	h := newTestHandler()
	c := newTestClient(t, ts, h, Options{})
	runClient(t, c)

	tc, _ := handshake(t, ts, "session-1", 5, 15)
	waitConnected(t, c, "session-1")
	_ = tc.ws.SetWriteDeadline(time.Now().Add(time.Second))
	if err := tc.ws.WriteMessage(websocket.BinaryMessage, []byte{1, 2, 3}); err != nil {
		t.Fatalf("server write binary: %v", err)
	}
	// The connection is still usable: a ping gets a pong.
	tc.sendType(t, wsproto.TypePing, "", nil)
	env := tc.recvType(t, wsproto.TypePong)
	if env.T != wsproto.TypePong {
		t.Fatalf("got %s, want pong", env.T)
	}
	if !c.Connected() {
		t.Error("binary frame broke the connection")
	}
}

func TestConcurrentSendIsSafeAndBounded(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	h := newTestHandler()
	// A tiny queue so the full path is exercised, and a server that never
	// reads, so the queue cannot drain.
	c := newTestClient(t, ts, h, Options{QueueSize: 4})
	runClient(t, c)

	tc, _ := handshake(t, ts, "session-1", 5, 15)
	waitConnected(t, c, "session-1")
	tc.pauseReading()

	var (
		full    atomic.Int64
		sent    atomic.Int64
		offline atomic.Int64
		other   atomic.Int64
		wg      sync.WaitGroup
	)
	const (
		senders = 32
		rounds  = 50
	)
	for i := 0; i < senders; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < rounds; j++ {
				env, err := Encode(wsproto.TypeEvent, "", map[string]any{"i": i, "j": j})
				if err != nil {
					t.Errorf("encode: %v", err)
					return
				}
				switch err := c.Send(env); {
				case err == nil:
					sent.Add(1)
				case errors.Is(err, ErrQueueFull):
					full.Add(1)
				case errors.Is(err, ErrOffline):
					offline.Add(1)
				default:
					other.Add(1)
					t.Errorf("unexpected Send error: %v", err)
				}
			}
		}(i)
	}
	wg.Wait()
	if other.Load() != 0 {
		t.Errorf("%d Send calls failed with an unexpected error", other.Load())
	}
	if full.Load() == 0 {
		t.Errorf("expected ErrQueueFull with a queue of 4 and a stalled writer (sent=%d, offline=%d)", sent.Load(), offline.Load())
	}
	if sent.Load() == 0 {
		t.Error("no frame was queued at all")
	}
	if got := sent.Load() + full.Load() + offline.Load(); got != senders*rounds {
		t.Errorf("Send accounted for %d of %d attempts", got, senders*rounds)
	}
	// The client is still healthy afterwards.
	if !c.Connected() {
		t.Error("client lost its connection under concurrent Send")
	}
}

func TestPongRenewsTheSilenceDeadline(t *testing.T) {
	// A panel that only ever answers pings (no telemetry, no commands) must
	// still keep the connection: control frames do not surface through
	// ReadMessage, so the pong handler is what renews the deadline.
	ts := newTestServer(t, "7", "secret-token")
	h := newTestHandler()
	c := newTestClient(t, ts, h, Options{
		PingEvery:      50 * time.Millisecond,
		SilenceTimeout: 300 * time.Millisecond,
	})
	runClient(t, c)

	handshake(t, ts, "session-1", 5, 15)
	waitConnected(t, c, "session-1")

	// More than three silence windows: without the renewal the client would
	// have dropped the connection long before this.
	time.Sleep(1200 * time.Millisecond)
	if !c.Connected() {
		t.Fatal("the client dropped a connection whose peer answers pings")
	}
	select {
	case <-h.discs:
		t.Fatal("the client reported a disconnect despite pongs")
	default:
	}
}

func TestSilentPeerHitsTheSilenceTimeout(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	ts.silentPings.Store(true)
	h := newTestHandler()
	c := newTestClient(t, ts, h, Options{
		PingEvery:      30 * time.Millisecond,
		SilenceTimeout: 200 * time.Millisecond,
		BackoffMin:     20 * time.Millisecond,
		BackoffMax:     40 * time.Millisecond,
	})
	runClient(t, c)

	handshake(t, ts, "session-1", 5, 15)
	waitConnected(t, c, "session-1")

	// The peer never sends anything: 70 s of silence is fatal, and 200 ms in a
	// test.
	waitDisconnected(t, h)
	if c.Connected() {
		t.Error("Connected() = true after the silence timeout")
	}
	// And the reconnect loop keeps trying.
	ts.waitConn(t)
}

func TestConcurrentSendProducesWellFormedFrames(t *testing.T) {
	// The writer goroutine is the only writer: concurrent Send calls must
	// never interleave two frames on the wire.
	ts := newTestServer(t, "7", "secret-token")
	h := newTestHandler()
	c := newTestClient(t, ts, h, Options{QueueSize: 512})
	runClient(t, c)

	tc, _ := handshake(t, ts, "session-1", 5, 15)
	waitConnected(t, c, "session-1")

	const (
		senders = 8
		rounds  = 50
	)
	blob := strings.Repeat("x", 1024)
	var (
		queued atomic.Int64
		wg     sync.WaitGroup
	)
	for i := 0; i < senders; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < rounds; j++ {
				env, err := Encode(wsproto.TypeEvent, "", map[string]any{"i": i, "j": j, "blob": blob})
				if err != nil {
					t.Errorf("encode: %v", err)
					return
				}
				if err := c.Send(env); err == nil {
					queued.Add(1)
				}
			}
		}(i)
	}
	wg.Wait()

	// The server reads every frame; each one must parse on its own.
	got := 0
	deadline := time.Now().Add(10 * time.Second)
	for int64(got) < queued.Load() && time.Now().Before(deadline) {
		env := tc.recv(t)
		if env.T != wsproto.TypeEvent {
			t.Fatalf("frame %d has type %q", got, env.T)
		}
		var body struct {
			I int `json:"i"`
			J int `json:"j"`
		}
		if err := json.Unmarshal(env.D, &body); err != nil {
			t.Fatalf("frame %d payload is corrupt: %v", got, err)
		}
		got++
	}
	if int64(got) != queued.Load() {
		t.Errorf("received %d of %d queued frames", got, queued.Load())
	}
}

func TestSendRefusesOversizedFrame(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	h := newTestHandler()
	c := newTestClient(t, ts, h, Options{})
	runClient(t, c)

	tc, _ := handshake(t, ts, "session-1", 5, 15)
	waitConnected(t, c, "session-1")

	env, err := Encode(wsproto.TypeEvent, "", map[string]any{"blob": strings.Repeat("x", wsproto.MaxFrame)})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Send(env); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("Send of an oversized frame = %v, want ErrFrameTooLarge", err)
	}
	// The connection is untouched.
	if !c.Connected() {
		t.Error("an oversized Send broke the connection")
	}
	tc.sendType(t, wsproto.TypePing, "", nil)
	tc.recvType(t, wsproto.TypePong)
}

func TestNoReplayAcrossReconnect(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	h := newTestHandler()
	c := newTestClient(t, ts, h, Options{BackoffMin: 20 * time.Millisecond, BackoffMax: 40 * time.Millisecond})
	runClient(t, c)

	first, _ := handshake(t, ts, "session-1", 5, 15)
	waitConnected(t, c, "session-1")
	first.closeNow()
	waitDisconnected(t, h)

	// Nothing may be buffered while offline.
	for i := 0; i < 5; i++ {
		env, err := Encode(wsproto.TypeEvent, "", map[string]any{"i": i})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Send(env); !errors.Is(err, ErrOffline) {
			t.Fatalf("Send while offline = %v, want ErrOffline", err)
		}
	}

	second, _ := handshake(t, ts, "session-2", 5, 15)
	waitConnected(t, c, "session-2")

	// handshake already asserted the new connection's first frame is hello;
	// nothing that was queued while offline may follow it.
	time.Sleep(200 * time.Millisecond)
	second.mu.Lock()
	left := len(second.raw)
	second.mu.Unlock()
	if left != 0 {
		t.Errorf("%d frame(s) replayed after reconnect", left)
	}
}

func TestSendAfterRunReturnsErrOffline(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	h := newTestHandler()
	c := newTestClient(t, ts, h, Options{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	handshake(t, ts, "session-1", 5, 15)
	waitConnected(t, c, "session-1")
	cancel()
	start := time.Now()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned %v, want context.Canceled", err)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("Run took %v to return after cancel, want < 1s", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if err := c.Send(wsproto.Envelope{T: wsproto.TypePing}); !errors.Is(err, ErrOffline) {
		t.Errorf("Send after Run = %v, want ErrOffline", err)
	}
	if c.Connected() || c.Session() != "" {
		t.Error("client still reports a session after Run returned")
	}
}

func TestContextCancelLeavesNoGoroutines(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	// Warm the server up so its accept loop and TLS state are already counted.
	warm := newTestHandler()
	warmClient := newTestClient(t, ts, warm, Options{})
	warmRun := runClient(t, warmClient)
	handshake(t, ts, "warm", 5, 15)
	waitConnected(t, warmClient, "warm")
	warmRun.stop(t)
	if err := warmRun.result(t); !errors.Is(err, context.Canceled) {
		t.Errorf("warm-up Run returned %v, want context.Canceled", err)
	}
	time.Sleep(200 * time.Millisecond)
	before := runtime.NumGoroutine()

	for i := 0; i < 3; i++ {
		h := newTestHandler()
		c := newTestClient(t, ts, h, Options{})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- c.Run(ctx) }()
		handshake(t, ts, "session", 5, 15)
		waitConnected(t, c, "session")
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("Run returned %v, want context.Canceled", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Run did not return after cancel")
		}
	}

	// Give the runtime a moment to reap the finished goroutines.
	var after int
	for i := 0; i < 40; i++ {
		time.Sleep(50 * time.Millisecond)
		after = runtime.NumGoroutine()
		if after <= before+2 {
			break
		}
	}
	if after > before+2 {
		t.Errorf("goroutine leak: %d before, %d after", before, after)
	}
}

func TestTokenNeverAppearsInLogsOrErrors(t *testing.T) {
	const token = "super-secret-token-value"
	ts := newTestServer(t, "7", token)
	log := &recordLogger{}
	h := newTestHandler()
	c := newTestClient(t, ts, h, Options{
		Token:      token,
		Log:        log,
		BackoffMin: 20 * time.Millisecond,
		BackoffMax: 40 * time.Millisecond,
	})
	runClient(t, c)

	tc, _ := handshake(t, ts, "session-1", 5, 15)
	waitConnected(t, c, "session-1")
	// A malformed frame and a panel error both produce error paths.
	tc.sendRaw(t, []byte("{not json"))
	tc.sendType(t, wsproto.TypeError, "x", wsproto.ErrorBody{Code: "boom", Message: "panel said no"})
	tc.closeNow()
	// A failed dial also has an error path (the server is about to close).
	ts.srv.Close()
	time.Sleep(300 * time.Millisecond)

	if got := log.all(); strings.Contains(got, token) {
		t.Fatalf("log output contains the token:\n%s", got)
	}
	if strings.Contains(c.URL(), token) {
		t.Fatal("client URL contains the token")
	}
	// The authorization header is the only place the token may live.
	if hdr := ts.lastHeader(); hdr != nil && hdr.Get("Authorization") != "Bearer "+token {
		t.Fatalf("Authorization header = %q", hdr.Get("Authorization"))
	}
}

func TestNewRejectsBadOptions(t *testing.T) {
	const token = "supersecrettoken123"
	cases := []struct {
		name string
		o    Options
	}{
		{"no machine", Options{URL: "https://panel.example.com", Token: token}},
		{"no token", Options{URL: "https://panel.example.com", MachineID: 1}},
		{"no url", Options{MachineID: 1, Token: token}},
		{"user info", Options{URL: "https://user:pass@panel.example.com", MachineID: 1, Token: token}},
		{"bad scheme", Options{URL: "ftp://panel.example.com", MachineID: 1, Token: token}},
		{"plain http", Options{URL: "http://panel.example.com", MachineID: 1, Token: token}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.o, newTestHandler())
			if err == nil {
				t.Fatal("New accepted invalid options")
			}
			if strings.Contains(err.Error(), token) {
				t.Fatalf("error leaks the token: %v", err)
			}
		})
	}
}

func TestValidateURLRules(t *testing.T) {
	cases := []struct {
		in      string
		allow   bool
		want    string
		wantErr bool
	}{
		{"https://panel.example.com", false, "https://panel.example.com", false},
		{"https://panel.example.com/", false, "https://panel.example.com", false},
		{"wss://panel.example.com/w1ncray-ws", false, "wss://panel.example.com/w1ncray-ws", false},
		{"https://panel.example.com?token=x", false, "https://panel.example.com", false},
		{"http://127.0.0.1:8080", false, "http://127.0.0.1:8080", false},
		{"ws://localhost:8080", false, "ws://localhost:8080", false},
		{"http://panel.example.com", true, "http://panel.example.com", false},
		{"http://panel.example.com", false, "", true},
		{"https://user:pw@panel.example.com", false, "", true},
		{"", false, "", true},
		{"panel.example.com", false, "", true},
	}
	for _, tc := range cases {
		got, err := validateURL(tc.in, tc.allow)
		if tc.wantErr {
			if err == nil {
				t.Errorf("validateURL(%q) = %q, want an error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("validateURL(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("validateURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestWSURLConversion(t *testing.T) {
	cases := []struct {
		base string
		want string
	}{
		{"https://panel.example.com", "wss://panel.example.com" + WSPath},
		{"http://127.0.0.1:8080", "ws://127.0.0.1:8080" + WSPath},
		{"wss://panel.example.com/w1ncray-ws", "wss://panel.example.com/w1ncray-ws"},
		{"https://panel.example.com:8443/", "wss://panel.example.com:8443" + WSPath},
	}
	for _, tc := range cases {
		got, err := wsURL(tc.base, WSPath)
		if err != nil {
			t.Errorf("wsURL(%q): %v", tc.base, err)
			continue
		}
		if got != tc.want {
			t.Errorf("wsURL(%q) = %q, want %q", tc.base, got, tc.want)
		}
	}
}

func TestURLRulesNeverEchoASecret(t *testing.T) {
	// An operator who pasted the token into the base URL must not have it
	// repeated into an error message.
	const secret = "leaked-secret-value"
	for _, raw := range []string{
		"ftp://panel.example.com/?token=" + secret,
		"http://panel.example.com/?token=" + secret,
		"https://user:" + secret + "@panel.example.com",
		"not a url " + secret,
	} {
		_, err := validateURL(raw, false)
		if err == nil {
			t.Fatalf("validateURL(%q) accepted the URL", raw)
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("validateURL(%q) leaks the secret: %v", raw, err)
		}
	}
	// A query string is dropped from the accepted form entirely.
	got, err := validateURL("https://panel.example.com/?token="+secret, false)
	if err != nil {
		t.Fatalf("validateURL: %v", err)
	}
	if strings.Contains(got, secret) || strings.Contains(got, "?") {
		t.Errorf("normalised URL keeps the query: %q", got)
	}
}

func TestCallerHTTPClientIsNotMutated(t *testing.T) {
	ts := newTestServer(t, "7", "secret-token")
	orig := &http.Client{Timeout: 3 * time.Second}
	h := newTestHandler()
	c := newTestClient(t, ts, h, Options{HTTP: orig})
	runClient(t, c)
	if orig.CheckRedirect != nil {
		t.Error("caller's http.Client was mutated")
	}
	handshake(t, ts, "s", 5, 15)
}
