package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/W1nCwC/W1nCray/agent/agentcfg"
	"github.com/W1nCwC/W1nCray/agent/panelclient"
	"github.com/W1nCwC/W1nCray/agent/ws"
	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// orderLog records every line in order, so the close-order test can compare
// positions instead of wall-clock timestamps.
type orderLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *orderLog) add(format string, args ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
	l.mu.Unlock()
}

func (l *orderLog) Debugf(format string, args ...any) { l.add(format, args...) }
func (l *orderLog) Infof(format string, args ...any)  { l.add(format, args...) }
func (l *orderLog) Warnf(format string, args ...any)  { l.add(format, args...) }
func (l *orderLog) Errorf(format string, args ...any) { l.add(format, args...) }

func (l *orderLog) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

// index returns the position of the first line containing sub (-1 when absent).
func (l *orderLog) index(sub string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, line := range l.lines {
		if strings.Contains(line, sub) {
			return i
		}
	}
	return -1
}

// wsPanel is one loopback panel that serves both the HTTP agent API and the
// agent WebSocket, exactly like the real panel does.
type wsPanel struct {
	t   *testing.T
	srv *httptest.Server

	mu      sync.Mutex
	paths   []string
	configs []panelclient.ConfigRequest
	results []panelclient.CommandResultRequest

	// configCommands, when set, returns the "commands" JSON array of the n-th
	// /config answer (1-based); "" answers unchanged.
	configCommands func(n int) string

	conns chan *wsConn
}

type wsConn struct {
	ws     *websocket.Conn
	mu     sync.Mutex
	raw    [][]byte
	counts map[string]int
	wmu    sync.Mutex
}

func newWSPanel(t *testing.T) *wsPanel {
	t.Helper()
	p := &wsPanel{t: t, conns: make(chan *wsConn, 8)}
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	p.srv = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.paths = append(p.paths, r.URL.Path)
		p.mu.Unlock()
		if r.URL.Path == ws.WSPath {
			conn, err := up.Upgrade(rw, r, nil)
			if err != nil {
				return
			}
			wc := &wsConn{ws: conn, counts: map[string]int{}}
			select {
			case p.conns <- wc:
			default:
			}
			go func() {
				for {
					mt, raw, err := conn.ReadMessage()
					if err != nil {
						conn.Close()
						return
					}
					if mt == websocket.TextMessage {
						var wire struct {
							T string `json:"t"`
						}
						_ = json.Unmarshal(raw, &wire)
						wc.mu.Lock()
						wc.raw = append(wc.raw, raw)
						wc.counts[wire.T]++
						wc.mu.Unlock()
					}
				}
			}()
			return
		}

		raw, _ := io.ReadAll(r.Body)
		ep := strings.TrimPrefix(r.URL.Path, "/api/v2/server/machine/agent/")
		switch ep {
		case "config":
			var req panelclient.ConfigRequest
			json.Unmarshal(raw, &req)
			p.mu.Lock()
			p.configs = append(p.configs, req)
			n := len(p.configs)
			fn := p.configCommands
			p.mu.Unlock()
			cmds := ""
			if fn != nil {
				cmds = fn(n)
			}
			if cmds == "" {
				io.WriteString(rw, `{"schema":1,"unchanged":true,"revision":0}`)
				return
			}
			fmt.Fprintf(rw, `{"schema":1,"revision":0,"commands":%s}`, cmds)
		case "command-result":
			var req panelclient.CommandResultRequest
			json.Unmarshal(raw, &req)
			p.mu.Lock()
			p.results = append(p.results, req)
			p.mu.Unlock()
			io.WriteString(rw, `{"ok":true}`)
		default:
			io.WriteString(rw, `{"ok":true}`)
		}
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *wsPanel) count(path string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, got := range p.paths {
		if got == path {
			n++
		}
	}
	return n
}

func (p *wsPanel) configsSeen() []panelclient.ConfigRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]panelclient.ConfigRequest(nil), p.configs...)
}

func (p *wsPanel) commandResults() []panelclient.CommandResultRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]panelclient.CommandResultRequest(nil), p.results...)
}

func (p *wsPanel) waitConfigs(t *testing.T, n int) {
	t.Helper()
	waitFor(t, fmt.Sprintf("%d /config request(s)", n), func() bool {
		p.mu.Lock()
		defer p.mu.Unlock()
		return len(p.configs) >= n
	})
}

func (p *wsPanel) waitConn(t *testing.T) *wsConn {
	t.Helper()
	select {
	case c := <-p.conns:
		return c
	case <-time.After(10 * time.Second):
		t.Fatal("the agent never opened the WebSocket")
		return nil
	}
}

// recvType returns the next frame of the given type, skipping the others.
func (c *wsConn) recvType(t *testing.T, typ string) wsproto.Envelope {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		if len(c.raw) > 0 {
			raw := c.raw[0]
			c.raw = c.raw[1:]
			c.mu.Unlock()
			var wire struct {
				T  string          `json:"t"`
				ID string          `json:"id"`
				D  json.RawMessage `json:"d"`
			}
			if err := json.Unmarshal(raw, &wire); err != nil {
				t.Fatalf("frame is not an envelope: %v (%s)", err, raw)
			}
			if wire.T == typ {
				return wsproto.Envelope{T: wire.T, ID: wire.ID, D: wire.D}
			}
			continue
		}
		c.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("the agent never sent a %s frame", typ)
	return wsproto.Envelope{}
}

// countType counts every frame of one type the connection received, including
// the ones a recvType already consumed.
func (c *wsConn) countType(t *testing.T, typ string) int {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[typ]
}

func (c *wsConn) sendType(t *testing.T, typ, id string, d any) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"t": typ, "id": id, "d": d})
	if err != nil {
		t.Fatal(err)
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = c.ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := c.ws.WriteMessage(websocket.TextMessage, body); err != nil {
		t.Fatalf("server write: %v", err)
	}
}

func (c *wsConn) sendHelloOK(t *testing.T, session string, telemetryS, componentsS int) {
	t.Helper()
	c.sendType(t, wsproto.TypeHelloOK, "", wsproto.HelloOK{
		ServerTime: time.Now().Unix(),
		Intervals:  wsproto.Intervals{TelemetryS: telemetryS, ComponentsS: componentsS},
		Session:    session,
	})
}

// remoteWS starts a panel link with the WebSocket channel enabled and a slow
// HTTP cadence, so only an explicit hint pulls again.
func remoteWS(t *testing.T, rt *Runtime, p *wsPanel, log *orderLog, cfg *agentcfg.Config) func() {
	t.Helper()
	stop, err := rt.StartRemote(context.Background(), RemoteOptions{
		URL:            p.srv.URL,
		MachineID:      7,
		Token:          remoteToken,
		AgentVersion:   "1.2.3",
		Log:            log,
		WS:             true,
		AgentConfig:    cfg,
		PullInterval:   300 * time.Second,
		ReportInterval: 300 * time.Second,
	})
	if err != nil {
		t.Fatalf("StartRemote: %v", err)
	}
	t.Cleanup(stop)
	return stop
}

// TestStartRemoteWebSocketHelloCapabilitiesAndFeatures covers the wiring: the
// hello carries the contract's fields, and the HTTP config request carries the
// same capability list (ruling 1) and the same instance id.
func TestStartRemoteWebSocketHelloCapabilitiesAndFeatures(t *testing.T) {
	rt, _ := bootCycle(t, t.TempDir(), false, nil)
	p := newWSPanel(t)
	log := &orderLog{}
	remoteWS(t, rt, p, log, &agentcfg.Config{})

	wc := p.waitConn(t)
	helloEnv := wc.recvType(t, wsproto.TypeHello)
	var hello wsproto.Hello
	if err := json.Unmarshal(helloEnv.D, &hello); err != nil {
		t.Fatalf("hello payload: %v", err)
	}
	if hello.AgentVersion != "1.2.3" {
		t.Errorf("hello.agent_version = %q", hello.AgentVersion)
	}
	if hello.InstanceID == "" || hello.Seq != 1 {
		t.Errorf("hello = %+v", hello)
	}
	if hello.Platform.OS != runtime.GOOS || hello.Platform.Arch != runtime.GOARCH {
		t.Errorf("hello.platform = %+v", hello.Platform)
	}
	want := []string{wsproto.CapTelemetry, wsproto.CapXrayNodes}
	if len(hello.Capabilities) != len(want) || hello.Capabilities[0] != want[0] || hello.Capabilities[1] != want[1] {
		t.Errorf("hello.capabilities = %v, want %v", hello.Capabilities, want)
	}
	if !hello.Policy.Terminal || !hello.Policy.Modules.XrayNodes {
		t.Errorf("hello.policy = %+v", hello.Policy)
	}
	if len(hello.HostInfo.IPs.Private) == 0 && hello.HostInfo.Hostname == "" {
		t.Errorf("hello.host_info looks empty: %+v", hello.HostInfo)
	}

	// The HTTP link must declare exactly the same capabilities and identify the
	// same agent run.
	p.waitConfigs(t, 1)
	req := p.configsSeen()[0]
	if len(req.Features) != len(hello.Capabilities) {
		t.Fatalf("config.features = %v, hello.capabilities = %v", req.Features, hello.Capabilities)
	}
	for i := range req.Features {
		if req.Features[i] != hello.Capabilities[i] {
			t.Fatalf("config.features = %v, hello.capabilities = %v", req.Features, hello.Capabilities)
		}
	}
	if req.InstanceID != hello.InstanceID {
		t.Errorf("config.instance_id = %q, hello.instance_id = %q", req.InstanceID, hello.InstanceID)
	}

	// hello.ok starts the cadence; the first telemetry frame arrives at once.
	wc.sendHelloOK(t, "session-1", 1, 1)
	wc.recvType(t, wsproto.TypeTelemetry)
	wc.recvType(t, wsproto.TypeComponents)
}

// TestStartRemoteStopEndsTheWebSocketBeforeTheRunner covers the shutdown order
// of design section 3.6: the WS commands run through the same Runner the HTTP
// link owns, so the socket must be gone before the Runner is cancelled.
func TestStartRemoteStopEndsTheWebSocketBeforeTheRunner(t *testing.T) {
	rt, _ := bootCycle(t, t.TempDir(), false, nil)
	p := newWSPanel(t)
	log := &orderLog{}
	stop := remoteWS(t, rt, p, log, &agentcfg.Config{})

	wc := p.waitConn(t)
	wc.recvType(t, wsproto.TypeHello)
	p.waitConfigs(t, 1)

	stop()
	stop() // idempotent

	wsAt := log.index("websocket channel stopped")
	httpAt := log.index("panel: link stopped")
	if wsAt < 0 || httpAt < 0 {
		t.Fatalf("missing shutdown log lines:\n%s", log.text())
	}
	if wsAt > httpAt {
		t.Errorf("the HTTP link stopped before the WebSocket:\n%s", log.text())
	}
	// Both loops are gone: a cancelled socket does not reconnect.
	before := p.count(ws.WSPath)
	time.Sleep(150 * time.Millisecond)
	if after := p.count(ws.WSPath); after != before {
		t.Errorf("the WebSocket reconnected after stop (%d -> %d)", before, after)
	}
}

// TestStartRemoteNodesHintSyncsTheKernel covers the wiring of ruling 6: the
// hook the WebSocket channel gets is the runtime's kernel client, so a "nodes"
// hint makes the kernel re-fetch this machine's node list now. The hint is
// about the kernel's node list, not the agent's desired state, so the HTTP pull
// must not run again.
func TestStartRemoteNodesHintSyncsTheKernel(t *testing.T) {
	rt, _ := bootCycle(t, t.TempDir(), false, nil)
	k := &fakeXray{syncChanged: true}
	rt.Xray = k
	p := newWSPanel(t)
	log := &orderLog{}
	remoteWS(t, rt, p, log, &agentcfg.Config{})
	wc := p.waitConn(t)
	wc.recvType(t, wsproto.TypeHello)
	p.waitConfigs(t, 1)

	wc.sendType(t, wsproto.TypeHint, "h1", wsproto.Hint{What: "nodes"})
	waitFor(t, "the kernel sync", func() bool { return k.syncCallCount() == 1 })
	if !strings.Contains(log.text(), "xray nodes hint") {
		t.Errorf("the nodes hint was not logged:\n%s", log.text())
	}
	// The nodes hint must not pull the desired state any more.
	time.Sleep(150 * time.Millisecond)
	if n := len(p.configsSeen()); n != 1 {
		t.Errorf("the nodes hint pulled the desired state %d time(s)", n-1)
	}
}

// TestStartRemoteNodesHintDegradesWithoutTheKernel: on a machine without the
// Xray kernel (rt.Xray is nil) the hint is logged and degraded to the kernel's
// 60 s poll; it never fails the command path and it does not pull the desired
// state.
func TestStartRemoteNodesHintDegradesWithoutTheKernel(t *testing.T) {
	rt, _ := bootCycle(t, t.TempDir(), false, nil) // no XrayConfigPath: rt.Xray is nil
	p := newWSPanel(t)
	log := &orderLog{}
	remoteWS(t, rt, p, log, &agentcfg.Config{})
	wc := p.waitConn(t)
	wc.recvType(t, wsproto.TypeHello)
	p.waitConfigs(t, 1)

	wc.sendType(t, wsproto.TypeHint, "h1", wsproto.Hint{What: "nodes"})
	waitFor(t, "the degradation to be logged", func() bool {
		return strings.Contains(log.text(), "xray nodes hint")
	})
	time.Sleep(150 * time.Millisecond)
	if n := len(p.configsSeen()); n != 1 {
		t.Errorf("the nodes hint pulled the desired state %d time(s)", n-1)
	}
}

// TestStartRemoteNodesHintRefusedLocally covers the local gate: with
// Modules.XrayNodes false the hint is refused and nothing is pulled, so a
// remote hint can never turn the module on (ruling 13).
func TestStartRemoteNodesHintRefusedLocally(t *testing.T) {
	rt, _ := bootCycle(t, t.TempDir(), false, nil)
	p := newWSPanel(t)
	log := &orderLog{}
	off := &agentcfg.Config{Modules: &agentcfg.ModuleConfig{XrayNodes: boolPtr(false)}}
	remoteWS(t, rt, p, log, off)
	wc := p.waitConn(t)
	wc.recvType(t, wsproto.TypeHello)
	p.waitConfigs(t, 1)

	wc.sendType(t, wsproto.TypeHint, "h1", wsproto.Hint{What: "nodes"})
	waitFor(t, "the refusal to be logged", func() bool {
		return strings.Contains(log.text(), "refused")
	})
	time.Sleep(150 * time.Millisecond)
	if n := len(p.configsSeen()); n != 1 {
		t.Errorf("a refused nodes hint pulled the desired state %d time(s)", n-1)
	}
}

// TestCommandDeduplicationAcrossHTTPAndWebSocket covers ruling 7 end to end:
// the same command id delivered on both channels runs once and is answered once.
func TestCommandDeduplicationAcrossHTTPAndWebSocket(t *testing.T) {
	rt, _ := bootCycle(t, t.TempDir(), false, nil)
	p := newWSPanel(t)
	// The first pull carries no command; every later one carries the duplicate.
	p.configCommands = func(n int) string {
		if n < 2 {
			return ""
		}
		return `[{"id":"dup-1","type":"dump_state"}]`
	}
	log := &orderLog{}
	remoteWS(t, rt, p, log, &agentcfg.Config{})
	wc := p.waitConn(t)
	wc.recvType(t, wsproto.TypeHello)
	wc.sendHelloOK(t, "session-1", 300, 300)
	p.waitConfigs(t, 1)

	// Channel one: the WebSocket.
	wc.sendType(t, wsproto.TypeCmd, "dup-1", wsproto.Cmd{Type: "dump_state", TTLS: 60})
	res := wc.recvType(t, wsproto.TypeCmdResult)
	if res.ID != "dup-1" {
		t.Errorf("cmd.result id = %q", res.ID)
	}
	var body wsproto.CmdResult
	if err := json.Unmarshal(res.D, &body); err != nil {
		t.Fatalf("cmd.result payload: %v", err)
	}
	if body.Status != "done" {
		t.Errorf("cmd.result = %+v", body)
	}
	if n := len(p.commandResults()); n != 0 {
		t.Fatalf("the WebSocket command was also answered over HTTP: %+v", p.commandResults())
	}

	// Channel two: the same id in a /config answer.
	wc.sendType(t, wsproto.TypeHint, "h1", wsproto.Hint{What: "desired"})
	p.waitConfigs(t, 2)
	time.Sleep(200 * time.Millisecond)
	if n := len(p.commandResults()); n != 0 {
		t.Fatalf("the duplicate was executed over HTTP: %+v", p.commandResults())
	}
	if n := wc.countType(t, wsproto.TypeCmdResult); n != 1 {
		t.Errorf("cmd.result frames = %d, want exactly 1", n)
	}
}

// TestStartRemoteWithoutWSNeverOpensTheSocket is the compatibility guard: the
// HTTP-only link (the legacy node mode and every caller that does not ask for
// the channel) must behave exactly as before.
func TestStartRemoteWithoutWSNeverOpensTheSocket(t *testing.T) {
	rt, _ := bootCycle(t, t.TempDir(), false, nil)
	p := newWSPanel(t)
	stop, err := rt.StartRemote(context.Background(), RemoteOptions{
		URL:          p.srv.URL,
		MachineID:    7,
		Token:        remoteToken,
		AgentVersion: "1.2.3",
		PullInterval: 300 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	p.waitConfigs(t, 1)
	time.Sleep(200 * time.Millisecond)
	if n := p.count(ws.WSPath); n != 0 {
		t.Fatalf("a WS-less link opened %d WebSocket connection(s)", n)
	}
	// And the HTTP report still carries the host: nothing suppresses it.
	if body := p.configsSeen()[0]; len(body.Features) != 0 {
		t.Errorf("a WS-less link declared features %v", body.Features)
	}
}
