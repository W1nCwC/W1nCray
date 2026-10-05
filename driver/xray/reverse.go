package xray

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/xtls/xray-core/app/reverse"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
	"google.golang.org/protobuf/proto"
)

// Self-managed reverse proxy.
//
// The classic Xray reverse proxy (app/reverse) is configured once at start-up
// and cannot be torn down cleanly: Bridge.Close only stops its monitor timer
// and leaves the bridge workers (and their tunnel connections) running, and a
// closed Portal leaves its picker's 30 s timer behind. The driver therefore
// builds the same mechanism from the exported parts of Xray (mux workers,
// reverse.BridgeWorker, the Control message) and owns every goroutine and
// connection, so adding and removing reverse instances at run time is
// leak-free. The wire protocol is unchanged: a bridge of this package works
// with an Xray portal and vice versa.

// internalDomain is the destination of the control stream inside the mux
// session (fixed by the reverse protocol).
const internalDomain = "reverse"

// reverseHandle is a running portal or bridge.
type reverseHandle interface {
	Close() error
}

// ------------------------------------------------------------------ portal

// portal is the public side: it is an outbound handler that, depending on the
// request, either accepts a bridge's control link (target = rendezvous domain)
// or relays user traffic through one of the registered bridge links.
type portal struct {
	om     outbound.Manager
	tag    string
	domain string

	mu      sync.Mutex
	workers []*portalWorker
	closed  bool

	client *mux.ClientManager
	once   sync.Once
}

func startPortal(om outbound.Manager, tag, domain string) (*portal, error) {
	if om == nil {
		return nil, errors.New("no outbound manager")
	}
	p := &portal{om: om, tag: tag, domain: domain}
	p.client = &mux.ClientManager{Picker: p}
	if err := om.AddHandler(context.Background(), p); err != nil {
		return nil, err
	}
	return p, nil
}

// Close closes every bridge link and is idempotent. It must NOT touch the
// outbound manager: Xray's outbound.Manager.Close holds its write lock while
// calling Handler.Close on every registered handler, so a RemoveHandler call
// here would re-acquire the same (non-reentrant) RWMutex on the same goroutine
// and deadlock the whole process on shutdown. Removal from the manager is the
// driver's job (see teardown in apply.go); this method only tears down the
// workers this portal owns.
func (p *portal) Close() error {
	p.once.Do(p.shutdown)
	return nil
}

// shutdown closes the workers; it is also reached when the outbound manager
// closes the handler itself.
func (p *portal) shutdown() {
	p.mu.Lock()
	p.closed = true
	ws := p.workers
	p.workers = nil
	p.mu.Unlock()
	for _, w := range ws {
		w.close()
	}
}

// outbound.Handler implementation.

func (p *portal) Tag() string  { return p.tag }
func (p *portal) Start() error { return nil }

func (p *portal) SenderSettings() *serial.TypedMessage { return nil }
func (p *portal) ProxySettings() *serial.TypedMessage  { return nil }

func (p *portal) Dispatch(ctx context.Context, link *transport.Link) {
	if err := p.handle(ctx, link); err != nil {
		common.Interrupt(link.Writer)
		common.Interrupt(link.Reader)
	}
}

func (p *portal) handle(ctx context.Context, link *transport.Link) error {
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 || outbounds[len(outbounds)-1] == nil {
		return errors.New("outbound metadata not found")
	}
	ob := outbounds[len(outbounds)-1]
	if ob.Target.Address != nil && ob.Target.Address.Family().IsDomain() && ob.Target.Address.Domain() == p.domain {
		return p.acceptBridge(ctx, link)
	}
	if ob.Target.Network == net.Network_UDP && ob.OriginalTarget.Address != nil && ob.OriginalTarget.Address != ob.Target.Address {
		link.Reader = &buf.EndpointOverrideReader{Reader: link.Reader, Dest: ob.Target.Address, OriginalDest: ob.OriginalTarget.Address}
		link.Writer = &buf.EndpointOverrideWriter{Writer: link.Writer, Dest: ob.Target.Address, OriginalDest: ob.OriginalTarget.Address}
	}
	return p.client.Dispatch(ctx, link)
}

func (p *portal) acceptBridge(ctx context.Context, link *transport.Link) error {
	mc, err := mux.NewClientWorker(*link, mux.ClientStrategy{})
	if err != nil {
		return err
	}
	w, err := newPortalWorker(mc)
	if err != nil {
		mc.Close()
		return err
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		w.close()
		return errors.New("portal closed")
	}
	// Drop workers that have ended.
	live := p.workers[:0]
	for _, o := range p.workers {
		if o.client.Closed() {
			o.close()
		} else {
			live = append(live, o)
		}
	}
	p.workers = append(live, w)
	p.mu.Unlock()
	if _, ok := link.Reader.(*pipe.Reader); !ok {
		select {
		case <-ctx.Done():
		case <-mc.WaitClosed():
		}
	}
	return nil
}

// PickAvailable implements mux.WorkerPicker.
func (p *portal) PickAvailable() (*mux.ClientWorker, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.workers) == 0 {
		return nil, errors.New("no bridge connected")
	}
	live := p.workers[:0]
	for _, w := range p.workers {
		if w.client.Closed() {
			w.close()
			continue
		}
		live = append(live, w)
	}
	p.workers = live
	best := -1
	var bestConn uint32 = 1 << 30
	for pass := 0; pass < 2 && best < 0; pass++ {
		for i, w := range p.workers {
			if pass == 0 && w.draining {
				continue
			}
			if w.client.IsFull() {
				continue
			}
			if c := w.client.ActiveConnections(); c < bestConn {
				bestConn, best = c, i
			}
		}
	}
	if best < 0 {
		return nil, errors.New("no bridge link available")
	}
	return p.workers[best].client, nil
}

// portalWorker is the portal end of one bridge link: a mux client plus the
// control stream that keeps the bridge worker alive (its 60 s inactivity
// timer is refreshed by every control message).
type portalWorker struct {
	client   *mux.ClientWorker
	writer   buf.Writer
	reader   buf.Reader
	stop     chan struct{}
	once     sync.Once
	draining bool
}

func newPortalWorker(client *mux.ClientWorker) (*portalWorker, error) {
	opt := []pipe.Option{pipe.WithSizeLimit(16 * 1024)}
	upR, upW := pipe.New(opt...)
	downR, downW := pipe.New(opt...)
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.UDPDestination(net.DomainAddress(internalDomain), 0),
	}})
	if !client.Dispatch(ctx, &transport.Link{Reader: upR, Writer: downW}) {
		return nil, errors.New("unable to open the control stream")
	}
	w := &portalWorker{client: client, writer: upW, reader: downR, stop: make(chan struct{})}
	go w.heartbeat()
	return w, nil
}

// heartbeat sends a control message every 10 s (Xray: every fifth 2 s tick)
// and starts draining the link after 256 sessions.
func (w *portalWorker) heartbeat() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	n := 0
	send := func(draining bool) error {
		msg := &reverse.Control{}
		msg.FillInRandom()
		if draining {
			msg.State = reverse.Control_DRAIN
		}
		b, err := proto.Marshal(msg)
		if err != nil {
			return err
		}
		return w.writer.WriteMultiBuffer(buf.MergeBytes(nil, b))
	}
	_ = send(false)
	for {
		select {
		case <-w.stop:
			return
		case <-w.client.WaitClosed():
			w.close()
			return
		case <-t.C:
		}
		if w.client.TotalConnections() > 256 {
			w.draining = true
			_ = send(true)
			common.Close(w.writer)
			common.Interrupt(w.reader)
			return
		}
		n = (n + 1) % 5
		if n == 1 {
			if err := send(false); err != nil {
				return
			}
		}
	}
}

func (w *portalWorker) close() {
	w.once.Do(func() {
		close(w.stop)
		w.client.Close()
		common.Interrupt(w.reader)
		common.Close(w.writer)
	})
}

// ------------------------------------------------------------------ bridge

// bridge keeps at least one control link to the portal. It reproduces the
// monitor of app/reverse.Bridge (2 s period, one worker per 16 sessions) but
// can be stopped completely.
type bridge struct {
	d      routing.Dispatcher
	tag    string
	domain string

	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once

	log func(format string, args ...any)
}

func startBridge(d routing.Dispatcher, tag, domain string, logf func(string, ...any)) (*bridge, error) {
	if d == nil {
		return nil, errors.New("no dispatcher")
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := &bridge{d: d, tag: tag, domain: domain, cancel: cancel, done: make(chan struct{}), log: logf}
	go b.run(ctx)
	return b, nil
}

func (b *bridge) run(ctx context.Context) {
	defer close(b.done)
	var workers []*reverse.BridgeWorker
	defer func() {
		for _, w := range workers {
			closeBridgeWorker(w)
		}
	}()
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		workers = b.monitor(workers)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (b *bridge) monitor(workers []*reverse.BridgeWorker) []*reverse.BridgeWorker {
	active := workers[:0]
	for _, w := range workers {
		if w.IsActive() {
			active = append(active, w)
		} else if w.Closed() {
			closeBridgeWorker(w)
		} else {
			// Draining worker: keep it until its sessions end.
			active = append(active, w)
			continue
		}
	}
	workers = active
	var conns, n uint32
	for _, w := range workers {
		if w.IsActive() {
			conns += w.Connections()
			n++
		}
	}
	if n == 0 || conns/n > 16 {
		w, err := reverse.NewBridgeWorker(b.domain, b.tag, b.d)
		if err != nil {
			if b.log != nil {
				b.log("reverse bridge %s: cannot create a worker: %v", b.tag, err)
			}
			return workers
		}
		workers = append(workers, w)
	}
	return workers
}

func closeBridgeWorker(w *reverse.BridgeWorker) {
	if w.Worker != nil {
		w.Worker.Close()
	}
	if w.Timer != nil {
		w.Timer.SetTimeout(0)
	}
}

// Close stops the monitor and closes every worker, then waits until the
// goroutine is gone.
func (b *bridge) Close() error {
	b.once.Do(func() { b.cancel() })
	<-b.done
	return nil
}
