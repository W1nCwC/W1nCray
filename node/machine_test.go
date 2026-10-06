package node

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/api/xboard"
	"github.com/W1nCwC/W1nCray/common/cert"
)

// machineNodeToken is the machine token the fake panel expects in machine mode.
const machineNodeToken = "machine-node-secret"

// newMachineFakePanel is a fake panel in machine mode: the credentials travel
// in headers and node_id selects the node.
func newMachineFakePanel(t *testing.T, nodeJSON string, users []map[string]any) *fakePanel {
	t.Helper()
	fp := newFakePanel(t, nodeJSON, users)
	fp.machine, fp.machineID, fp.machineToken = true, 9, machineNodeToken
	return fp
}

// startMachineServer runs a full controller against a machine-mode fake panel.
func startMachineServer(t *testing.T, nodeJSON string, users []map[string]any, mutate func(*Config)) (*server, *fakePanel) {
	t.Helper()
	fp := newMachineFakePanel(t, nodeJSON, users)
	s := startServerAPI(t, fp, &APIConfig{
		APIHost: fp.srv.URL, NodeID: 1, MachineID: 9, MachineToken: machineNodeToken, Timeout: 10,
	}, mutate, nil)
	return s, fp
}

func machineController(t *testing.T, fp *fakePanel, token string) *Controller {
	t.Helper()
	return New(Options{
		API: &APIConfig{
			APIHost: fp.srv.URL, NodeID: 1, MachineID: 9, MachineToken: token, Timeout: 10,
		},
		Config: DefaultConfig(),
		Certs:  cert.NewManager(t.TempDir()),
		Reload: func(string) {},
	})
}

// TestMachinePrefetch covers the parts of a machine node that need no kernel:
// the tag identifies the machine, config and users are pulled over the V2
// machine endpoints, and the token never reaches the URL.
func TestMachinePrefetch(t *testing.T) {
	fp := newMachineFakePanel(t, vmessNode(1234, "[]"), panelUsers(0, 0))
	ctl := machineController(t, fp, machineNodeToken)
	if got := ctl.Tag(); got != "node1@machine9" {
		t.Fatalf("tag = %q, want node1@machine9", got)
	}
	if !ctl.api.MachineMode() {
		t.Fatal("controller is not in machine mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := ctl.Prefetch(ctx); err != nil {
		t.Fatal(err)
	}
	if p := ctl.PendingPort(); p != 1234 {
		t.Fatalf("pending port = %d, want 1234", p)
	}
	ctl.mu.Lock()
	users := len(ctl.pendingUsers)
	ctl.mu.Unlock()
	if users != 2 {
		t.Fatalf("pending users = %d, want 2", users)
	}
	for _, ep := range []string{
		"/api/v2/server/machine/agent/node/config",
		"/api/v2/server/machine/agent/node/user",
	} {
		if !fp.sawPath(ep) {
			t.Errorf("panel never saw %s", ep)
		}
	}
}

// TestMachinePrefetchBadToken maps a 401 onto xboard.ErrBadCredentials and
// never leaks the token into the error.
func TestMachinePrefetchBadToken(t *testing.T) {
	fp := newMachineFakePanel(t, vmessNode(1234, "[]"), panelUsers(0, 0))
	ctl := machineController(t, fp, "wrong-machine-token")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := ctl.Prefetch(ctx)
	if err == nil {
		t.Fatal("Prefetch accepted a bad machine token")
	}
	if !errors.Is(err, xboard.ErrBadCredentials) {
		t.Fatalf("err = %v, want ErrBadCredentials", err)
	}
	if strings.Contains(err.Error(), "wrong-machine-token") {
		t.Fatalf("token leaked: %v", err)
	}
}

// TestMachineControllerE2E runs one proxied request through a machine-mode
// controller and checks that config, users, traffic and status all travelled
// over the V2 machine endpoints, and that the WebSocket was never attempted
// (its handshake would put the token in the URL).
func TestMachineControllerE2E(t *testing.T) {
	tgt := target(t)
	port := freePort(t, "tcp")
	s, fp := startMachineServer(t, vmessNode(port, "[]"), panelUsers(0, 0), nil)

	if got := s.ctl.Tag(); got != "node1@machine9" {
		t.Fatalf("tag = %q", got)
	}
	if s.ctl.wsConnected() {
		t.Fatal("websocket must stay off in machine mode")
	}

	c := startClient(t, protoCases[0].client(port, uuid1))
	const size = 128 * 1024
	n, err := c.get(tgt.URL+"/bytes?n="+strconv.Itoa(size), 15*time.Second)
	if err != nil {
		t.Fatalf("request through the machine node: %v", err)
	}
	if n != size {
		t.Fatalf("got %d bytes, want %d", n, size)
	}

	s.ctl.push()
	up, down := fp.totals(1)
	if up <= 0 || down < size {
		t.Fatalf("reported traffic up=%d down=%d, want up>0 down>=%d", up, down, size)
	}
	if fp.status == 0 {
		t.Fatal("status not reported")
	}
	for _, ep := range []string{
		"/api/v2/server/machine/agent/node/config",
		"/api/v2/server/machine/agent/node/user",
		"/api/v2/server/machine/agent/node/push",
		"/api/v2/server/machine/agent/node/status",
	} {
		if !fp.sawPath(ep) {
			t.Errorf("panel never saw %s", ep)
		}
	}
	if fp.sawPath("handshake") {
		t.Error("machine mode attempted the websocket handshake")
	}
}
