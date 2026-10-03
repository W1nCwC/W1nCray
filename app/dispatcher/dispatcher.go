// Package dispatcher provides the W1nCray dispatcher: Xray's own
// DefaultDispatcher, created through its official config creator, wrapped with
// per-user device limiting and rate limiting.
//
// Wrapping instead of forking keeps routing, sniffing, stats and FakeDNS
// behaviour identical to the upstream kernel across Xray upgrades.
package dispatcher

import (
	"context"
	"sync/atomic"

	xdispatcher "github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"

	"w1ncray/common/limiter"
)

// spliceForbidden is session.Inbound.CanSpliceCopy's "cannot" value. Splice
// copies bytes in the kernel and would bypass the token buckets.
const spliceForbidden = 3

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		inner, err := common.CreateObject(ctx, &xdispatcher.Config{})
		if err != nil {
			return nil, err
		}
		d, ok := inner.(routing.Dispatcher)
		if !ok {
			return nil, errors.New("upstream dispatcher does not implement routing.Dispatcher")
		}
		return &Dispatcher{inner: d}, nil
	}))
}

// Dispatcher implements routing.Dispatcher.
type Dispatcher struct {
	inner   routing.Dispatcher
	limiter atomic.Pointer[limiter.Limiter]
}

// SetLimiter attaches the limiter. Until it is set, connections pass through.
func (d *Dispatcher) SetLimiter(l *limiter.Limiter) {
	d.limiter.Store(l)
}

// Type implements common.HasType.
func (*Dispatcher) Type() interface{} {
	return routing.DispatcherType()
}

// Start implements common.Runnable.
func (d *Dispatcher) Start() error {
	return d.inner.Start()
}

// Close implements common.Closable.
func (d *Dispatcher) Close() error {
	return d.inner.Close()
}

// admit runs the device limit check for the user of this connection. A nil
// session means the connection is not managed by W1nCray.
func (d *Dispatcher) admit(ctx context.Context) (*limiter.Session, error) {
	l := d.limiter.Load()
	if l == nil {
		return nil, nil
	}
	in := session.InboundFromContext(ctx)
	if in == nil || in.User == nil || in.User.Email == "" || in.Source.Address == nil {
		return nil, nil
	}
	ip := in.Source.Address.String()
	if in.Source.Address.Family().IsIP() {
		ip = in.Source.Address.IP().String()
	}
	sess, err := l.Acquire(in.Tag, in.User.Email, ip)
	if err != nil {
		errors.LogInfo(ctx, "rejected ", in.User.Email, " from ", ip, ": ", err)
		return nil, err
	}
	if sess.Limited() {
		in.CanSpliceCopy = spliceForbidden
	}
	return sess, nil
}

// Dispatch implements routing.Dispatcher.
//
// The returned link.Reader must stay the *pipe.Reader created by the upstream
// dispatcher (common/mux asserts it for XUDP), so downlink throttling relays
// through a fresh pipe instead of wrapping that reader.
func (d *Dispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	sess, err := d.admit(ctx)
	if err != nil {
		return nil, err
	}
	link, err := d.inner.Dispatch(ctx, dest)
	if err != nil {
		sess.Release()
		return nil, err
	}
	if sess == nil {
		return link, nil
	}
	context.AfterFunc(ctx, sess.Release)
	if !sess.Limited() {
		return link, nil
	}

	upstreamReader := link.Reader
	reader, writer := pipe.New(pipe.OptionsFromContext(ctx)...)
	go relay(ctx, limiter.NewReader(ctx, upstreamReader, sess.Down), upstreamReader, writer)
	context.AfterFunc(ctx, func() { common.Interrupt(upstreamReader) })

	return &transport.Link{
		Reader: reader,
		Writer: limiter.NewWriter(ctx, link.Writer, sess.Up),
	}, nil
}

// relay copies the throttled downlink into the pipe handed to the inbound.
func relay(ctx context.Context, from buf.Reader, upstream buf.Reader, to *pipe.Writer) {
	if err := buf.Copy(from, to); err != nil {
		errors.LogDebugInner(ctx, err, "downlink relay ended")
		common.Interrupt(upstream)
		common.Interrupt(to)
		return
	}
	common.Close(to)
}

// DispatchLink implements routing.Dispatcher.
func (d *Dispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	sess, err := d.admit(ctx)
	if err != nil {
		return err
	}
	if sess != nil {
		context.AfterFunc(ctx, sess.Release)
		if sess.Limited() {
			link = &transport.Link{
				Reader: limiter.NewReader(ctx, link.Reader, sess.Up),
				Writer: limiter.NewWriter(ctx, link.Writer, sess.Down),
			}
		}
	}
	return d.inner.DispatchLink(ctx, dest, link)
}
