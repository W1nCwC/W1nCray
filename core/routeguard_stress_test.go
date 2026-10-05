package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	routingsession "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// stressNodeRules is a node whose Head is a long list of unrelated rules
// followed by the one rule under test, which blocks 127.0.0.1:port for the
// inbound "stress". The long list makes a rule reload slow, so the window in
// which an unprotected reload leaves the table without the blocking rule is
// wide. The Tail routes inbound "lb" through a balancer, which reads the
// outbound manager (Select) during route selection.
func stressNodeRules(port int, fillers int) *NodeRules {
	var head []json.RawMessage
	// Fillers are cheap rules (about 6 microseconds each to build; ip and
	// domain rules cost about 1 ms each), so a reload takes a few
	// milliseconds and thousands of reloads fit into the test.
	for i := 0; i < fillers; i++ {
		head = append(head, json.RawMessage(fmt.Sprintf(
			`{"inboundTag":["filler"],"port":"%d","outboundTag":"direct"}`, 1000+i)))
	}
	head = append(head, json.RawMessage(fmt.Sprintf(
		`{"inboundTag":["stress"],"ip":["127.0.0.1"],"port":"%d","outboundTag":"%s"}`, port, BlockTag)))
	return &NodeRules{
		Head:      head,
		Tail:      []json.RawMessage{json.RawMessage(`{"inboundTag":["lb"],"balancerTag":"stress-lb"}`)},
		Balancers: json.RawMessage(`[{"tag":"stress-lb","selector":["extra-"],"fallbackTag":"direct"}]`),
	}
}

func freedomConfig(t *testing.T, tag string) *conf.OutboundDetourConfig {
	t.Helper()
	var oc conf.OutboundDetourConfig
	if err := json.Unmarshal([]byte(`{"protocol":"freedom","tag":"`+tag+`"}`), &oc); err != nil {
		t.Fatal(err)
	}
	return &oc
}

// TestRouteSelectionNeverSeesPartialRules hammers route selection while the
// rule table is reloaded and outbounds come and go, and requires that a
// destination blocked by a rule that is present in every version of the
// table is never routed anywhere else.
//
// Xray's Router.ReloadRules empties the table and rebuilds it rule by rule,
// and PickRoute reads it without a lock, so without routeguard a selection
// that overlaps a reload sees a prefix of the new table: the blocking rule is
// missing and the connection falls through to the default outbound. Under
// "go test -race" the same overlap is reported as a data race on the rule
// slice and on the outbound manager's tag cache.
func TestRouteSelectionNeverSeesPartialRules(t *testing.T) {
	c := newTestCore(t)
	dur := 5 * time.Second
	if testing.Short() {
		dur = 1500 * time.Millisecond
	}

	// A connection that is not blocked reaches this listener through the
	// default outbound; any accept is a leak past the blocking rule.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	var accepted atomic.Int64
	go func() {
		for {
			cn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			cn.Close()
		}
	}()

	rules := stressNodeRules(port, 40)
	if err := c.Rules.SetNode("stress", rules); err != nil {
		t.Fatal(err)
	}
	router := guardedRouter(c)
	blocked := func() (string, error) {
		r, err := router.PickRoute(&routingsession.Context{
			Inbound:  &session.Inbound{Tag: "stress"},
			Outbound: &session.Outbound{Target: xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(port))},
			Content:  &session.Content{},
		})
		if err != nil {
			return "", err
		}
		return r.GetOutboundTag(), nil
	}
	if tag, err := blocked(); err != nil || tag != BlockTag {
		t.Fatalf("precondition: blocked destination routes to %q (%v), want %s", tag, err, BlockTag)
	}

	var (
		stop     = make(chan struct{})
		wg       sync.WaitGroup
		picks    atomic.Int64
		bad      atomic.Int64
		firstBad atomic.Value // string
		dispatch atomic.Int64
		lbPicks  atomic.Int64
		reloads  atomic.Int64
		outAdds  atomic.Int64
		mutErr   atomic.Value // error
	)
	fail := func(format string, a ...any) {
		bad.Add(1)
		firstBad.CompareAndSwap(nil, fmt.Sprintf(format, a...))
	}
	running := func() bool {
		select {
		case <-stop:
			return false
		default:
			return true
		}
	}

	// Readers 1: route selection for the blocked destination.
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for running() {
				tag, err := blocked()
				picks.Add(1)
				if err != nil {
					fail("blocked destination: PickRoute error %v (table was empty or partial)", err)
				} else if tag != BlockTag {
					fail("blocked destination routed to %q, want %s", tag, BlockTag)
				}
			}
		}()
	}

	// Readers 2: the same through the real dispatcher, so the path under test
	// is the one connections take (DispatchLink -> router -> outbound).
	d := c.Instance.GetFeature(routing.DispatcherType()).(routing.Dispatcher)
	dest := xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(port))
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for running() {
				ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
					Tag:    "stress",
					Source: xnet.TCPDestination(xnet.LocalHostIP, 40000),
				})
				ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
				up, upW := pipe.New()
				down, downW := pipe.New()
				common.Close(upW) // the client sends nothing and half-closes
				if err := d.DispatchLink(ctx, dest, &transport.Link{Reader: up, Writer: downW}); err != nil {
					fail("DispatchLink: %v", err)
				}
				common.Interrupt(down)
				dispatch.Add(1)
			}
		}()
	}

	// Readers 3: a balancer rule, whose selection reads the outbound manager
	// while outbounds are added and removed. Any answer is fine; it must not
	// crash or race.
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for running() {
				_, _ = router.PickRoute(&routingsession.Context{
					Inbound:  &session.Inbound{Tag: "lb"},
					Outbound: &session.Outbound{Target: xnet.TCPDestination(xnet.ParseAddress("8.8.8.8"), 80)},
					Content:  &session.Content{},
				})
				lbPicks.Add(1)
			}
		}()
	}

	// Writer 1: reload the whole table over and over, with a second node that
	// comes and goes, always carrying the blocking rule.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for running() {
			if err := c.Rules.SetNode("stress", rules); err != nil {
				mutErr.CompareAndSwap(nil, fmt.Errorf("SetNode stress: %w", err))
				return
			}
			reloads.Add(1)
			if reloads.Load()%4 == 0 {
				if err := c.Rules.SetNode("other", &NodeRules{Head: []json.RawMessage{json.RawMessage(`{"inboundTag":["other"],"outboundTag":"direct"}`)}}); err != nil {
					mutErr.CompareAndSwap(nil, fmt.Errorf("SetNode other: %w", err))
					return
				}
				if err := c.Rules.RemoveNode("other"); err != nil {
					mutErr.CompareAndSwap(nil, fmt.Errorf("RemoveNode other: %w", err))
					return
				}
				reloads.Add(2)
			}
		}
	}()

	// Writer 2: add and remove outbounds that the balancer selects from.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; running(); i++ {
			tag := fmt.Sprintf("extra-%d", i%5)
			hc, err := freedomConfig(t, tag).Build()
			if err != nil {
				mutErr.CompareAndSwap(nil, err)
				return
			}
			if err := c.AddOutbound(hc); err != nil {
				mutErr.CompareAndSwap(nil, fmt.Errorf("AddOutbound %s: %w", tag, err))
				return
			}
			outAdds.Add(1)
			if err := c.RemoveOutbound(tag); err != nil {
				mutErr.CompareAndSwap(nil, fmt.Errorf("RemoveOutbound %s: %w", tag, err))
				return
			}
		}
	}()

	// Run for at least dur and for at least minReloads reloads (capped, so a
	// regression that stalls reloading fails instead of hanging).
	minReloads := int64(2000)
	if testing.Short() {
		minReloads = 0
	}
	start := time.Now()
	for el := time.Duration(0); el < dur || (reloads.Load() < minReloads && el < 8*dur); el = time.Since(start) {
		time.Sleep(20 * time.Millisecond)
	}
	dur = time.Since(start).Round(time.Millisecond)
	close(stop)
	wg.Wait()
	time.Sleep(300 * time.Millisecond) // let in-flight dispatches finish

	t.Logf("duration %s: %d reloads, %d outbound add/remove, %d blocked picks, %d dispatches, %d balancer picks; %d violations, %d leaked connections",
		dur, reloads.Load(), outAdds.Load(), picks.Load(), dispatch.Load(), lbPicks.Load(), bad.Load(), accepted.Load())

	if err, _ := mutErr.Load().(error); err != nil {
		t.Fatalf("mutator failed: %v", err)
	}
	if reloads.Load() < 100 && !testing.Short() {
		t.Fatalf("only %d reloads in %s: the test did not exercise reloading", reloads.Load(), dur)
	}
	if n := bad.Load(); n > 0 {
		t.Errorf("%d route selections escaped the blocking rule during reloads; first: %v", n, firstBad.Load())
	}
	if n := accepted.Load(); n > 0 {
		t.Errorf("%d connections to the blocked destination were let through to the default outbound", n)
	}
}
