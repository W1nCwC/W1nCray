// Package dispatcher provides the W1nCray dispatcher: Xray's own
// DefaultDispatcher, created through its official config creator, wrapped with
// per-user device limiting and rate limiting.
//
// Wrapping instead of forking keeps routing, sniffing and stats behaviour
// identical to the upstream kernel across Xray upgrades. The one change is
// that route selection runs under routeguard's lock (see that package).
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
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"

	"github.com/W1nCwC/W1nCray/app/routeguard"
	"github.com/W1nCwC/W1nCray/common/limiter"
)

// spliceForbidden is session.Inbound.CanSpliceCopy's "cannot" value. Splice
// copies bytes in the kernel and would bypass the token buckets.
const spliceForbidden = 3

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		// This is the creator of xdispatcher.Config (app/dispatcher/default.go
		// in Xray) with one difference: the router handed to the default
		// dispatcher is wrapped by routeguard, so that route selection cannot
		// observe a routing table that is being reloaded. Everything else is
		// the upstream wiring. The upstream creator also looks up an optional
		// FakeDNS engine into an unexported field; W1nCray never configures
		// FakeDNS (it only generates the "dns" section), so none exists.
		d := new(xdispatcher.DefaultDispatcher)
		if err := core.RequireFeatures(ctx, func(om outbound.Manager, router routing.Router, pm policy.Manager, sm stats.Manager, dc dns.Client) error {
			return d.Init(&xdispatcher.Config{}, om, routeguard.Router(router), pm, sm)
		}); err != nil {
			return nil, err
		}
		return &Dispatcher{inner: d}, nil
	}))
}

// Dispatcher implements routing.Dispatcher.
type Dispatcher struct {
	inner   routing.Dispatcher
	limiter atomic.Pointer[limiter.Limiter]
	tracker ConnTracker
}

// Tracker returns the connection tracker of this dispatcher. Nothing is
// tracked until a tag prefix is passed to its Watch method.
func (d *Dispatcher) Tracker() *ConnTracker {
	return &d.tracker
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
	ctx, untrack := d.tracker.track(ctx)
	link, err := d.inner.Dispatch(ctx, dest)
	if err != nil {
		sess.Release()
		if untrack != nil {
			untrack()
		}
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
	// DispatchLink returns when the session is over.
	ctx, untrack := d.tracker.track(ctx)
	if untrack != nil {
		defer untrack()
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
