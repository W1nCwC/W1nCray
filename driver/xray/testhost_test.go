package xray

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/serial"
	xcore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/infra/conf"

	// All Xray protocols and transports, as in core.
	_ "github.com/xtls/xray-core/main/distro/all"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/app/dispatcher"
	"github.com/W1nCwC/W1nCray/app/routeguard"
)

// testHost is a minimal real Host over an in-process Xray instance (the
// W1nCray dispatcher for its route guard, but no limiter or tracker watch):
// what core.Core + RuleManager provide once WP0 is merged. Kill is recorded
// but cannot close connections (no tracker prefix is watched).
type testHost struct {
	t     testing.TB
	inst  *xcore.Instance
	ibm   inbound.Manager
	obm   outbound.Manager
	rt    routing.Router
	stats stats.Manager

	mu     sync.Mutex
	rules  map[string][]json.RawMessage
	bals   map[string]json.RawMessage
	kills  []string
	setErr error
}

const testPolicyJSON = `{
  "levels": {
    "0":   {"handshake": 4, "connIdle": 300, "uplinkOnly": 2, "downlinkOnly": 5},
    "100": {"handshake": 4, "connIdle": 3600, "uplinkOnly": 5, "downlinkOnly": 5, "bufferSize": 64},
    "101": {"handshake": 4, "connIdle": 30, "uplinkOnly": 5, "downlinkOnly": 5, "bufferSize": 64},
    "102": {"handshake": 4, "connIdle": 120, "uplinkOnly": 5, "downlinkOnly": 5, "bufferSize": 64},
    "103": {"handshake": 4, "connIdle": 300, "uplinkOnly": 5, "downlinkOnly": 5, "bufferSize": 64}
  },
  "system": {"statsInboundUplink": true, "statsInboundDownlink": true, "statsOutboundUplink": true, "statsOutboundDownlink": true}
}`

func newTestHost(t testing.TB) *testHost {
	t.Helper()
	cfg := `{
	  "log": {"loglevel": "` + testLogLevel() + `", "access": "none"},
	  "stats": {},
	  "policy": ` + testPolicyJSON + `,
	  "routing": {"rules": []},
	  "outbounds": [{"protocol": "blackhole", "tag": "test-default"}]
	}`
	var c conf.Config
	if err := json.Unmarshal([]byte(cfg), &c); err != nil {
		t.Fatal(err)
	}
	pb, err := c.Build()
	if err != nil {
		t.Fatal(err)
	}
	// Use the W1nCray dispatcher, as core.New does: its route selection runs
	// under the routeguard lock, which the run-time mutators below take.
	swapped := false
	for i, app := range pb.App {
		if app.Type == "xray.app.dispatcher.Config" {
			pb.App[i] = serial.ToTypedMessage(&dispatcher.Config{})
			swapped = true
		}
	}
	if !swapped {
		t.Fatal("upstream dispatcher config not found in app list")
	}
	inst, err := xcore.New(pb)
	if err != nil {
		t.Fatal(err)
	}
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	h := &testHost{
		t: t, inst: inst, rules: map[string][]json.RawMessage{}, bals: map[string]json.RawMessage{},
		ibm:   inst.GetFeature(inbound.ManagerType()).(inbound.Manager),
		obm:   routeguard.OutboundManager(inst.GetFeature(outbound.ManagerType()).(outbound.Manager)),
		rt:    routeguard.Router(inst.GetFeature(routing.RouterType()).(routing.Router)),
		stats: inst.GetFeature(stats.ManagerType()).(stats.Manager),
	}
	t.Cleanup(func() { h.Close() })
	return h
}

func testLogLevel() string {
	if v := os.Getenv("W1N_TEST_LOG"); v != "" {
		return v
	}
	return "warning"
}

func (h *testHost) Close() { h.inst.Close() }

func (h *testHost) AddInbound(cfg *xcore.InboundHandlerConfig) error {
	return xcore.AddInboundHandler(h.inst, cfg)
}

func (h *testHost) RemoveInbound(tag string) error {
	if _, err := h.ibm.GetHandler(context.Background(), tag); err != nil {
		return nil
	}
	return h.ibm.RemoveHandler(context.Background(), tag)
}

// AddOutbound builds the handler and registers it under the routeguard write
// lock (what core.Core.AddOutbound does).
func (h *testHost) AddOutbound(cfg *xcore.OutboundHandlerConfig) error {
	raw, err := xcore.CreateObject(h.inst, cfg)
	if err != nil {
		return err
	}
	oh, ok := raw.(outbound.Handler)
	if !ok {
		return fmt.Errorf("not an OutboundHandler")
	}
	return h.obm.AddHandler(context.Background(), oh)
}

// RemoveOutbound closes the handler first (WP0 D-A), outside the lock that
// the guarded manager takes for the removal.
func (h *testHost) RemoveOutbound(tag string) error {
	o := h.obm.GetHandler(tag)
	if o == nil {
		return nil
	}
	common.Close(o)
	return h.obm.RemoveHandler(context.Background(), tag)
}

func (h *testHost) SetRules(tag string, head []json.RawMessage, balancers json.RawMessage) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.setErr != nil {
		return h.setErr
	}
	prevH, prevB, had := h.rules[tag], h.bals[tag], false
	_, had = h.rules[tag]
	h.rules[tag], h.bals[tag] = head, balancers
	if err := h.applyLocked(); err != nil {
		if had {
			h.rules[tag], h.bals[tag] = prevH, prevB
		} else {
			delete(h.rules, tag)
			delete(h.bals, tag)
		}
		_ = h.applyLocked()
		return err
	}
	return nil
}

func (h *testHost) applyLocked() error {
	tags := make([]string, 0, len(h.rules))
	for k := range h.rules {
		tags = append(tags, k)
	}
	sort.Strings(tags)
	rc := &conf.RouterConfig{}
	for _, tg := range tags {
		rc.RuleList = append(rc.RuleList, h.rules[tg]...)
		if len(h.bals[tg]) > 0 {
			var bs []*conf.BalancingRule
			if err := json.Unmarshal(h.bals[tg], &bs); err != nil {
				return err
			}
			rc.Balancers = append(rc.Balancers, bs...)
		}
	}
	cfg, err := rc.Build()
	if err != nil {
		return err
	}
	return h.rt.AddRule(serial.ToTypedMessage(cfg), false)
}

func (h *testHost) Kill(tag string) int {
	h.mu.Lock()
	h.kills = append(h.kills, tag)
	h.mu.Unlock()
	return 0
}

func (h *testHost) Conns(string) (uint64, uint64) { return 0, 0 }

func (h *testHost) Counter(name string) (uint64, bool) {
	c := h.stats.GetCounter(name)
	if c == nil {
		return 0, false
	}
	return uint64(c.Value()), true
}

func (h *testHost) DropCounter(name string) { _ = h.stats.UnregisterCounter(name) }

func (h *testHost) Dispatcher() routing.Dispatcher {
	return h.inst.GetFeature(routing.DispatcherType()).(routing.Dispatcher)
}

func (h *testHost) OutboundManager() outbound.Manager { return h.obm }

// ---------------------------------------------------------------- helpers

type testLog struct{ t testing.TB }

func (l testLog) Debugf(f string, a ...any) {}
func (l testLog) Infof(f string, a ...any)  {}
func (l testLog) Warnf(f string, a ...any)  { l.t.Logf("WARN "+f, a...) }
func (l testLog) Errorf(f string, a ...any) { l.t.Logf("ERROR "+f, a...) }

func testRuntime(t testing.TB) driver.Runtime {
	return driver.Runtime{StateDir: t.TempDir(), Log: testLog{t}}
}

// node is one "machine": an Xray instance and its driver.
type node struct {
	t    testing.TB
	host *testHost
	drv  *Driver
	rt   driver.Runtime
}

func newNode(t testing.TB, opts Options) *node {
	h := newTestHost(t)
	return &node{t: t, host: h, drv: New(h, opts), rt: testRuntime(t)}
}

func (n *node) render(ins ...spec.Instance) []driver.Rendered {
	n.t.Helper()
	var set []driver.Rendered
	for _, in := range ins {
		a, err := n.drv.Render(in)
		if err != nil {
			n.t.Fatalf("render %s: %v", in.ID, err)
		}
		set = append(set, driver.Rendered{Instance: in, Artifact: a})
	}
	return set
}

func (n *node) apply(ins ...spec.Instance) driver.ApplyResult {
	n.t.Helper()
	res, err := n.drv.Apply(context.Background(), n.rt, n.render(ins...))
	if err != nil {
		n.t.Fatalf("apply: %v (%+v)", err, res)
	}
	return res
}

// kill simulates a node crash. Closing the Xray instance alone does not drop
// established connections (Xray's dispatcher Close is a no-op and the outbound
// handlers do not close in-flight links), and the self-managed reverse bridge
// keeps dialing, so the driver is stopped first: that closes the reverse
// workers and with them the tunnel connections, exactly as a process exit
// would, and then the instance is closed.
func (n *node) kill() {
	n.t.Helper()
	if err := n.drv.Stop(context.Background(), n.rt); err != nil {
		n.t.Fatalf("kill: %v", err)
	}
	n.host.Close()
}

// freePort returns a port that is free for TCP and UDP on loopback.
func freePort(t testing.TB) int {
	t.Helper()
	for i := 0; i < 100; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
		l.Close()
		if err != nil {
			continue
		}
		pc.Close()
		return port
	}
	t.Fatal("no free port")
	return 0
}

// freeRange returns the first port of n consecutive free ports.
func freeRange(t testing.TB, n int) int {
	t.Helper()
	for i := 0; i < 200; i++ {
		base := freePort(t)
		if base+n > 65000 {
			continue
		}
		ok := true
		var ls []io.Closer
		for p := base; p < base+n && ok; p++ {
			l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
			if err != nil {
				ok = false
				break
			}
			ls = append(ls, l)
			pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", p))
			if err != nil {
				ok = false
				break
			}
			ls = append(ls, pc)
		}
		for _, l := range ls {
			l.Close()
		}
		if ok {
			return base
		}
	}
	t.Fatal("no free port range")
	return 0
}

// tcpServer runs handle for every accepted connection.
func tcpServer(t testing.TB, handle func(net.Conn)) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				handle(c)
			}()
		}
	}()
	return l.Addr().String()
}

// echoServer echoes everything; if tag is set it first sends "tag\n".
func echoServer(t testing.TB, tag string) string {
	return tcpServer(t, func(c net.Conn) {
		if tag != "" {
			fmt.Fprintf(c, "%s\n", tag)
		}
		io.Copy(c, c)
	})
}

func udpEchoServer(t testing.TB) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			pc.WriteTo(b[:n], a)
		}
	}()
	return pc.LocalAddr().String()
}

func splitHP(t testing.TB, addr string) (string, int) {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	fmt.Sscan(p, &n)
	return h, n
}

// tcpEcho dials addr, sends payload and expects it back (after skipping the
// "tag\n" line when skipTag is set); it returns the tag.
func tcpEcho(addr string, payload []byte, skipTag bool) (string, error) {
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	tag := ""
	r := make([]byte, 0, len(payload))
	if skipTag {
		var line []byte
		one := make([]byte, 1)
		for {
			if _, err := io.ReadFull(c, one); err != nil {
				return "", fmt.Errorf("reading tag: %w", err)
			}
			if one[0] == '\n' {
				break
			}
			line = append(line, one[0])
		}
		tag = string(line)
	}
	werr := make(chan error, 1)
	go func() { _, err := c.Write(payload); werr <- err }()
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(c, buf); err != nil {
		return tag, fmt.Errorf("read echo: %w", err)
	}
	r = append(r, buf...)
	if err := <-werr; err != nil {
		return tag, err
	}
	if !bytes.Equal(r, payload) {
		return tag, fmt.Errorf("echo mismatch (%d bytes)", len(r))
	}
	return tag, nil
}

func udpEcho(addr string, payload []byte) error {
	c, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(payload); err != nil {
		return err
	}
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil {
		return err
	}
	if !bytes.Equal(buf[:n], payload) {
		return fmt.Errorf("udp echo mismatch")
	}
	return nil
}

// eventually retries f until it succeeds or the timeout expires.
func eventually(t testing.TB, d time.Duration, what string, f func() error) time.Duration {
	t.Helper()
	start := time.Now()
	var err error
	for time.Since(start) < d {
		if err = f(); err == nil {
			return time.Since(start)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s: still failing after %s: %v", what, d, err)
	return 0
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	var x uint32 = 12345
	for i := range b {
		x = x*1664525 + 1013904223
		b[i] = byte(x >> 24)
	}
	return b
}

// goroutineCount waits briefly for goroutines that are shutting down.
func goroutineCount() int {
	for i := 0; i < 30; i++ {
		runtime.GC()
		time.Sleep(50 * time.Millisecond)
	}
	return runtime.NumGoroutine()
}

func stacks() string {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	return string(buf[:n])
}

func countStack(substr string) int { return strings.Count(stacks(), substr) }

var bg = context.Background()
