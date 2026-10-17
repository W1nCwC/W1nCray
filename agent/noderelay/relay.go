// Package noderelay is the agent's local node API relay.
//
// The kernel's node controllers talk to the panel's machine-node endpoints
// (/api/v2/server/machine/agent/node/{config,user,push,alive,alivelist,status})
// once a minute each. When the panel offers it (hello.ok.node_relay), those
// requests go to this relay over a local Unix socket instead, and the relay
// forwards each one as node.req frames on the agent's panel WebSocket; the
// panel runs the same endpoint code and answers node.res. The kernel gets the
// very same status, ETag and body it would have got over HTTPS, without one
// HTTPS request per node and minute.
//
// The relay never guesses: a request it does not forward (no session, the
// panel said no, not a node endpoint, wrong credentials) is answered 503 with
// X-W1nCray-Relay: unavailable, and the kernel's client then sends it to the
// panel directly. Once a request is forwarded, whatever happens is the
// answer — a lost session is a 502, a timeout a 504 — so a traffic report is
// never sent twice.
package noderelay

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// Header values of api/xboard.RelayHeader.
const (
	header      = "X-W1nCray-Relay"
	unavailable = "unavailable"
)

// pathPrefix is the panel path of the node endpoints.
const pathPrefix = "/api/v2/server/machine/agent/node/"

// names are the endpoints the panel relays.
var names = map[string]bool{"config": true, "user": true, "push": true, "alive": true, "alivelist": true, "status": true}

// Limits.
const (
	// MaxBody is the largest request body forwarded (a push of every user).
	MaxBody = 8 << 20
	// MaxAnswer is the largest answer accepted (a user list of a big node).
	MaxAnswer = 64 << 20
	// DefaultTimeout bounds the wait for an answer.
	DefaultTimeout = 60 * time.Second
)

var (
	errLost     = errors.New("noderelay: the panel session ended before the answer")
	errTooLarge = errors.New("noderelay: the answer is too large")
)

// Options configures a Relay.
type Options struct {
	// MachineID and Token are this machine's: a request must carry them,
	// exactly like the panel would require, before it is forwarded.
	MachineID int
	Token     string
	// Timeout bounds the wait for an answer (DefaultTimeout when zero).
	Timeout time.Duration
	Log     driver.Logger
}

// Relay forwards node API requests over the panel WebSocket.
type Relay struct {
	opts Options

	mu      sync.Mutex
	send    func(wsproto.Envelope) error
	enabled bool
	chunk   int
	pending map[string]*call

	seq    atomic.Uint64
	prefix string

	srv  *http.Server
	ln   net.Listener
	path string
	stop chan struct{}
}

// call is one forwarded request waiting for its answer.
type call struct {
	head    bool // the first answer frame arrived
	status  int
	etag    string
	ctype   string
	body    bytes.Buffer
	err     error
	done    chan struct{}
	settled bool
}

// New creates a relay. It forwards nothing until SetSend and SetPanel say a
// session is up and the panel takes node requests.
func New(o Options) *Relay {
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	return &Relay{
		opts:    o,
		chunk:   wsproto.NodeRelayChunk,
		pending: make(map[string]*call),
		prefix:  "nr" + strconv.FormatInt(time.Now().UnixNano()%1e9, 36) + "-",
	}
}

// SetSend wires the WebSocket's send queue.
func (r *Relay) SetSend(send func(wsproto.Envelope) error) {
	r.mu.Lock()
	r.send = send
	r.mu.Unlock()
}

// SetPanel applies hello.ok.node_relay of a new session (nil: not offered).
func (r *Relay) SetPanel(ctl *wsproto.NodeRelayCtl) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enabled = ctl != nil && ctl.Enabled
	r.chunk = wsproto.NodeRelayChunk
	if ctl != nil && ctl.Chunk > 0 && ctl.Chunk < r.chunk {
		r.chunk = max(ctl.Chunk, 1024)
	}
}

// Enabled reports whether requests are forwarded right now.
func (r *Relay) Enabled() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.enabled && r.send != nil
}

// Disconnected ends the session: nothing is forwarded until the next
// hello.ok, and every request still waiting is answered 502.
func (r *Relay) Disconnected() {
	r.mu.Lock()
	r.enabled = false
	waiting := r.pending
	r.pending = make(map[string]*call)
	for _, c := range waiting {
		c.finish(errLost)
	}
	r.mu.Unlock()
}

// OnResponse takes one node.res frame.
func (r *Relay) OnResponse(id string, res wsproto.NodeRes) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.pending[id]
	if c == nil {
		return // timed out, or a session that already ended
	}
	if !c.head {
		c.head = true
		c.status, c.etag, c.ctype = res.Status, res.ETag, res.ContentType
	}
	if res.Body != "" {
		b, err := base64.StdEncoding.DecodeString(res.Body)
		if err != nil {
			delete(r.pending, id)
			c.finish(fmt.Errorf("noderelay: bad answer body: %w", err))
			return
		}
		if c.body.Len()+len(b) > MaxAnswer {
			delete(r.pending, id)
			c.finish(errTooLarge)
			return
		}
		c.body.Write(b)
	}
	if !res.More {
		delete(r.pending, id)
		c.finish(nil)
	}
}

// finish settles a call once. The caller holds r.mu.
func (c *call) finish(err error) {
	if c.settled {
		return
	}
	c.settled = true
	c.err = err
	close(c.done)
}

// Listen serves the relay on a Unix socket only this user can open.
func (r *Relay) Listen(path string) error {
	if path == "" {
		return errors.New("noderelay: no socket path on this platform")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("noderelay: %w", err)
	}
	_ = os.Remove(path) // left behind by a crashed process
	ln, err := listenSocket(path)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.ln, r.path = ln, path
	r.stop = make(chan struct{})
	stop := r.stop
	r.mu.Unlock()
	r.srv = &http.Server{Handler: r, ReadHeaderTimeout: 10 * time.Second}
	r.serve(ln)
	go r.watch(path, stop)
	return nil
}

// listenSocket binds the 0600 socket.
func listenSocket(path string) (net.Listener, error) {
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("noderelay: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("noderelay: %w", err)
	}
	return ln, nil
}

func (r *Relay) serve(ln net.Listener) {
	go func() {
		if err := r.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) && r.opts.Log != nil && !r.isOld(ln) {
			r.opts.Log.Warnf("noderelay: %v", err)
		}
	}()
}

func (r *Relay) isOld(ln net.Listener) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ln != ln
}

// WatchInterval is how often the socket file is checked.
var WatchInterval = 2 * time.Second

// watch binds the socket again when its file disappears. systemd removes the
// whole /run/W1nCray directory (RuntimeDirectory=) when the kernel's service is
// stopped or restarted, e.g. by a kernel upgrade, which leaves the listener
// open on an unlinked path that no kernel can reach: it would stay on HTTPS
// until the agent restarts.
func (r *Relay) watch(path string, stop chan struct{}) {
	t := time.NewTicker(WatchInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		if _, err := os.Lstat(path); err == nil {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			continue
		}
		ln, err := listenSocket(path)
		if err != nil {
			if r.opts.Log != nil {
				r.opts.Log.Warnf("noderelay: cannot bind %s again: %v", path, err)
			}
			continue
		}
		r.mu.Lock()
		old := r.ln
		r.ln = ln
		r.mu.Unlock()
		if u, ok := old.(*net.UnixListener); ok {
			u.SetUnlinkOnClose(false) // the path now belongs to the new listener
		}
		_ = old.Close()
		r.serve(ln)
		if r.opts.Log != nil {
			r.opts.Log.Infof("noderelay: socket %s was removed; bound again", path)
		}
	}
}

// Close stops the listener and removes the socket, so the kernel goes back to
// HTTPS at once.
func (r *Relay) Close() {
	r.mu.Lock()
	if r.stop != nil {
		close(r.stop)
		r.stop = nil
	}
	r.mu.Unlock()
	if r.srv != nil {
		_ = r.srv.Close()
	}
	if r.path != "" {
		_ = os.Remove(r.path)
	}
	r.Disconnected()
}

// ServeHTTP is the kernel's side.
func (r *Relay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	name, nodeID, ok := r.accept(req)
	if !ok {
		refuse(w)
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, MaxBody+1))
	if err != nil || len(body) > MaxBody {
		refuse(w)
		return
	}

	id := r.prefix + strconv.FormatUint(r.seq.Add(1), 36)
	c := &call{done: make(chan struct{})}
	if !r.forward(id, c, req.Method, name, nodeID, req.Header.Get("If-None-Match"), body) {
		refuse(w)
		return
	}

	timer := time.NewTimer(r.opts.Timeout)
	defer timer.Stop()
	select {
	case <-c.done:
	case <-timer.C:
		r.abandon(id, c, context.DeadlineExceeded)
	case <-req.Context().Done():
		r.abandon(id, c, req.Context().Err())
	}

	r.mu.Lock()
	err, status, etag, ctype := c.err, c.status, c.etag, c.ctype
	r.mu.Unlock()
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		w.Header().Set(header, "timeout")
		http.Error(w, "the panel did not answer in time", http.StatusGatewayTimeout)
		return
	case err != nil:
		w.Header().Set(header, "lost")
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if etag != "" {
		w.Header().Set("ETag", etag)
	}
	if ctype != "" {
		w.Header().Set("Content-Type", ctype)
	}
	if status < 100 || status > 999 {
		status = http.StatusBadGateway
	}
	w.WriteHeader(status)
	_, _ = w.Write(c.body.Bytes())
}

// accept checks that the request is a node endpoint call of this machine.
func (r *Relay) accept(req *http.Request) (name string, nodeID int, ok bool) {
	if !r.Enabled() {
		return "", 0, false
	}
	name, found := strings.CutPrefix(req.URL.Path, pathPrefix)
	if !found || !names[name] {
		return "", 0, false
	}
	if req.Header.Get("X-Machine-Id") != strconv.Itoa(r.opts.MachineID) {
		return "", 0, false
	}
	token, _ := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
	if r.opts.Token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(r.opts.Token)) != 1 {
		return "", 0, false
	}
	nodeID, err := strconv.Atoi(req.URL.Query().Get("node_id"))
	if err != nil || nodeID <= 0 {
		return "", 0, false
	}
	return name, nodeID, true
}

// forward registers the call and sends its frames. False means nothing reached
// the panel in a form it would run: the request may go to HTTPS.
func (r *Relay) forward(id string, c *call, method, name string, nodeID int, etag string, body []byte) bool {
	r.mu.Lock()
	send, enabled, chunk := r.send, r.enabled, r.chunk
	if !enabled || send == nil {
		r.mu.Unlock()
		return false
	}
	r.pending[id] = c
	r.mu.Unlock()

	for first := true; first || len(body) > 0; first = false {
		part := body[:min(len(body), chunk)]
		body = body[len(part):]
		req := wsproto.NodeReq{More: len(body) > 0}
		if first {
			req.Method, req.Name, req.NodeID, req.IfNoneMatch = method, name, nodeID, etag
		}
		if len(part) > 0 {
			req.Body = base64.StdEncoding.EncodeToString(part)
		}
		env, err := encode(id, req)
		if err == nil {
			err = send(env)
		}
		if err != nil {
			// The panel runs a request only on its last frame, and this one
			// (or an earlier one) never left: nothing ran.
			r.mu.Lock()
			delete(r.pending, id)
			r.mu.Unlock()
			if r.opts.Log != nil {
				r.opts.Log.Debugf("noderelay: %s not forwarded: %v", name, err)
			}
			return false
		}
	}
	return true
}

// abandon stops waiting for a call.
func (r *Relay) abandon(id string, c *call, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending[id] == c {
		delete(r.pending, id)
	}
	c.finish(err)
}

// Waiting reports how many forwarded requests wait for an answer (tests).
func (r *Relay) Waiting() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending)
}

func refuse(w http.ResponseWriter) {
	w.Header().Set(header, unavailable)
	http.Error(w, "the relay cannot forward this request", http.StatusServiceUnavailable)
}

func encode(id string, req wsproto.NodeReq) (wsproto.Envelope, error) {
	d, err := json.Marshal(req)
	if err != nil {
		return wsproto.Envelope{}, err
	}
	return wsproto.Envelope{T: wsproto.TypeNodeReq, ID: id, D: d}, nil
}
