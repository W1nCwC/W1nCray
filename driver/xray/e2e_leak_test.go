package xray

// Goroutine-stability under churn: adding and removing instances must not
// grow the goroutine count. This is the regression test for the BridgeWorker
// leak found in the plan's experiment E7 (+3 goroutines per portal/bridge
// pair with the official Bridge.Close) and for handler teardown in general.
// Forward churn exercises inbound/outbound/rule teardown; the reverse churn
// exercises the self-managed bridge workers and portals.

import (
	"fmt"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/spec"
)

func TestE2EGoroutinesStableUnderForwardChurn(t *testing.T) {
	n := newNode(t, testOpts())
	echo := echoServer(t, "")
	h, p := splitHP(t, echo)
	base := fwdInst("base", freePort(t), h, p)
	n.apply(base)
	time.Sleep(500 * time.Millisecond) // let lazily created helpers settle
	before := goroutineCount()

	for i := 0; i < 100; i++ {
		inst := fwdInst(fmt.Sprintf("churn-%d", i), freePort(t), h, p)
		n.apply(base, inst)
		n.apply(base)
	}

	// Worker teardown is asynchronous; allow a grace window before judging.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if goroutineCount() <= before+5 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if after := goroutineCount(); after > before+5 {
		t.Fatalf("goroutines grew after 100 add/remove cycles: before=%d after=%d", before, after)
	}
}

func TestE2EReverseChurnStopsAndDoesNotLeak(t *testing.T) {
	host, port := dualEcho(t)
	pn, bn := newNode(t, testOpts()), newNode(t, testOpts())
	tp, user := freePort(t), freePort(t)
	tunnelAddr := fmt.Sprintf("127.0.0.1:%d", tp)

	// Keep one plain instance on each node as the "desired state" while the
	// reverse pair of the cycle is removed; apply() is full-set semantics.
	warmP := fwdInst("warm-portal", freePort(t), host, port)
	warmB := fwdInst("warm-bridge", freePort(t), host, port)
	pn.apply(warmP)
	bn.apply(warmB)
	time.Sleep(500 * time.Millisecond)
	pBefore, bBefore := goroutineCount(), goroutineCount()

	pair := func(id string) (spec.Instance, spec.Instance) {
		po := spec.Instance{ID: "rp-" + id, Enabled: true, Engine: "xray", Kind: spec.KindReversePortal,
			Listen:  &spec.Listen{Addr: "127.0.0.1", Ports: fmt.Sprint(user)},
			Network: []string{"tcp"},
			Secret:  testSecret,
			Tunnel:  &spec.Tunnel{Type: "tcp", Security: "vless_enc", Listen: tunnelAddr},
			Reverse: &spec.Reverse{Domain: testDomain}}
		br := spec.Instance{ID: "rb-" + id, Enabled: true, Engine: "xray", Kind: spec.KindReverseBridge,
			Network: []string{"tcp"},
			Targets: []spec.Target{{Host: host, Ports: fmt.Sprint(port)}},
			Secret:  testSecret,
			Tunnel:  &spec.Tunnel{Type: "tcp", Security: "vless_enc", Server: tunnelAddr},
			Reverse: &spec.Reverse{Domain: testDomain}}
		return po, br
	}

	for i := 0; i < 20; i++ {
		po, br := pair(fmt.Sprint(i))
		pn.apply(warmP, po)
		bn.apply(warmB, br)
		if i == 0 || i == 19 {
			eventually(t, 15*time.Second, fmt.Sprintf("reverse link cycle %d", i), func() error {
				_, err := tcpEcho(fmt.Sprintf("127.0.0.1:%d", user), []byte("ping"), false)
				return err
			})
		}
		pn.apply(warmP) // removes the portal of this cycle
		bn.apply(warmB) // removes the bridge of this cycle
	}

	// After removal the bridge must not reconnect (D-A regression): the
	// portal's public port stays closed.
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := tcpEcho(fmt.Sprintf("127.0.0.1:%d", user), []byte("x"), false)
		if err != nil {
			break // refused: good
		}
		if time.Now().After(deadline) {
			t.Fatal("bridge still serves the public port after removal")
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Worker teardown is asynchronous; allow a grace window before judging.
	pDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(pDeadline) {
		if goroutineCount() <= pBefore+5 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if a := goroutineCount(); a > pBefore+5 {
		t.Fatalf("portal node goroutines grew over 20 reverse cycles: before=%d after=%d", pBefore, a)
	}
	bDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(bDeadline) {
		if goroutineCount() <= bBefore+5 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if a := goroutineCount(); a > bBefore+5 {
		t.Fatalf("bridge node goroutines grew over 20 reverse cycles: before=%d after=%d", bBefore, a)
	}
}
