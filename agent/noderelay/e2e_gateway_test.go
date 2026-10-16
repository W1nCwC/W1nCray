package noderelay_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/noderelay"
	"github.com/W1nCwC/W1nCray/agent/ws"
	"github.com/W1nCwC/W1nCray/agent/wsproto"
	"github.com/W1nCwC/W1nCray/api/xboard"
)

type streams struct{}

func (streams) HostInfo(context.Context) wsproto.HostInfo {
	return wsproto.HostInfo{Hostname: "e2e", OS: "linux", Arch: "amd64"}
}
func (streams) Telemetry(context.Context) wsproto.Telemetry   { return wsproto.Telemetry{} }
func (streams) Components(context.Context) wsproto.Components { return wsproto.Components{} }
func (streams) Kernels() []wsproto.KernelEntry                { return nil }
func (streams) Policy() wsproto.Policy                        { return wsproto.Policy{} }
func (streams) Capabilities() []string {
	return []string{wsproto.CapTelemetry, wsproto.CapNodeRelay}
}
func (streams) TerminalSupported() bool { return false }

// TestE2ERelayAgainstTheRealGateway drives a real panel gateway (manual; skipped
// unless E2E_RELAY_URL is set): the agent WebSocket client with the relay, and
// a machine-mode xboard client whose panel origin is unreachable, so every call
// must travel through the relay. Example:
//
//	E2E_RELAY_URL=http://127.0.0.1:8077 E2E_MACHINE=<id> E2E_TOKEN=<token> E2E_NODE=<node id> \
//		go test ./agent/noderelay -run E2E -v
func TestE2ERelayAgainstTheRealGateway(t *testing.T) {
	url := os.Getenv("E2E_RELAY_URL")
	if url == "" {
		t.Skip("set E2E_RELAY_URL")
	}
	machine, _ := strconv.Atoi(os.Getenv("E2E_MACHINE"))
	node, _ := strconv.Atoi(os.Getenv("E2E_NODE"))
	token := os.Getenv("E2E_TOKEN")
	socket := filepath.Join(t.TempDir(), "relay.sock")

	relay := noderelay.New(noderelay.Options{MachineID: machine, Token: token})
	if err := relay.Listen(socket); err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	agent, err := ws.NewAgent(ws.Options{URL: url, MachineID: machine, Token: token, AllowInsecureHTTP: true},
		ws.AgentOptions{Streams: streams{}, NodeRelay: relay})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = agent.Run(ctx) }()
	deadline := time.Now().Add(10 * time.Second)
	for !relay.Enabled() {
		if time.Now().After(deadline) {
			t.Fatal("the panel never enabled the relay")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// The panel origin is unreachable on purpose: everything must go through the relay.
	c := xboard.New(xboard.Config{APIHost: "http://127.0.0.1:1", NodeID: node, MachineID: machine, MachineToken: token, RelaySocket: socket, Timeout: 10 * time.Second})

	start := time.Now()
	nc, err := c.GetNodeConfig(ctx)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	t.Logf("config: protocol=%s port=%d (%s)", nc.Protocol, nc.ServerPort, time.Since(start))

	start = time.Now()
	users, err := c.GetUsers(ctx)
	if err != nil {
		t.Fatalf("users: %v", err)
	}
	t.Logf("users: %d (%s)", len(users), time.Since(start))
	if len(users) == 0 {
		t.Fatal("no users")
	}
	if _, err := c.GetUsers(ctx); !errors.Is(err, xboard.ErrNotModified) {
		t.Fatalf("second users pull: %v, want not modified", err)
	}

	uid := int(users[0].ID)
	if err := c.PushTraffic(ctx, map[int][2]int64{uid: {1000, 2000}}); err != nil {
		t.Fatalf("push: %v", err)
	}
	if err := c.PushAlive(ctx, map[int][]string{uid: {"203.0.113.7"}}); err != nil {
		t.Fatalf("alive: %v", err)
	}
	alive, err := c.GetAliveList(ctx)
	if err != nil {
		t.Fatalf("alivelist: %v", err)
	}
	t.Logf("alivelist: %d users with a limit online", len(alive))

	// 60 pulls in a row, to see the per-request cost on the relay path.
	c.ResetETags()
	start = time.Now()
	for i := 0; i < 60; i++ {
		if _, err := c.GetNodeConfig(ctx); err != nil && !errors.Is(err, xboard.ErrNotModified) {
			t.Fatal(err)
		}
	}
	t.Logf("60 config pulls: %s", time.Since(start))
	if relay.Waiting() != 0 {
		t.Fatal("calls left waiting")
	}
}
