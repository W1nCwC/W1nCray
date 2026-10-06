package bootstrap

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/panelclient"
	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// writeFakeKernel fabricates one installed kernel version on disk (the
// installer's <KernelsDir>/kernels/<name>/<version> layout), so the command
// channel can be exercised end to end without downloading anything.
func writeFakeKernel(t *testing.T, kernelsDir, name, version string, size int64) {
	t.Helper()
	dir := filepath.Join(kernelsDir, "kernels", name, version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	mk := map[string]any{
		"name": name, "version": version, "target": "linux/amd64",
		"binary": name, "archive_sha256": strings.Repeat("0", 64),
		"installed_at": time.Now().UTC(),
		"files":        []map[string]any{{"to": name, "size": size, "mode": "0755"}},
	}
	b, err := json.Marshal(mk)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".installed.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte("fake kernel"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestWebSocketKernelCommandsAndEvents is the end-to-end wiring test: a cmd
// frame on the socket reaches the operations registry through the shared
// Runner, the result goes back on the same socket, and kernel.removed is
// pushed as an event frame.
func TestWebSocketKernelCommandsAndEvents(t *testing.T) {
	dir := t.TempDir()
	kernelsDir := filepath.Join(dir, "kernels")
	writeFakeKernel(t, kernelsDir, "gost", "1.0.0", 4096)

	useFake(t, newFakeDriver())
	rt, err := Boot(Options{StateDir: filepath.Join(dir, "state"), KernelsDir: kernelsDir}, nil)
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	t.Cleanup(func() { _ = rt.Shutdown(context.Background()) })
	if rt.Ops == nil {
		t.Fatal("Boot did not build the operations registry")
	}

	p := newWSPanel(t)
	remoteWS(t, rt, p, &orderLog{}, nil)
	wc := p.waitConn(t)
	helloEnv := wc.recvType(t, wsproto.TypeHello)
	var hello wsproto.Hello
	if err := json.Unmarshal(helloEnv.D, &hello); err != nil {
		t.Fatalf("hello payload: %v", err)
	}
	// No signed manifest is loaded, so kernel_install cannot resolve a version
	// and the capability is not promised (ruling 1)...
	if hasCapability(hello.Capabilities, wsproto.CapKernel) {
		t.Errorf("hello.capabilities = %v, want no kernel without a manifest", hello.Capabilities)
	}
	// ...but the installed versions are still reported (they are a fact).
	if len(hello.Kernels) != 1 || hello.Kernels[0].Name != "gost" || hello.Kernels[0].Version != "1.0.0" {
		t.Fatalf("hello.kernels = %+v", hello.Kernels)
	}
	if hello.Kernels[0].SizeBytes != 4096 || hello.Kernels[0].InstalledAt == 0 || hello.Kernels[0].Path == "" {
		t.Errorf("hello.kernels lost size/installed_at/path: %+v", hello.Kernels[0])
	}
	wc.sendHelloOK(t, "session-1", 300, 300)

	// kernel_list over the socket.
	wc.sendType(t, wsproto.TypeCmd, "k1", wsproto.Cmd{Type: panelclient.CmdKernelList, TTLS: 60})
	var body wsproto.CmdResult
	if err := json.Unmarshal(wc.recvType(t, wsproto.TypeCmdResult).D, &body); err != nil {
		t.Fatalf("kernel_list result: %v", err)
	}
	if body.Status != "done" {
		t.Fatalf("kernel_list = %+v", body)
	}
	var list panelclient.KernelListResult
	raw, err := json.Marshal(body.Result)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatalf("kernel_list result %s: %v", raw, err)
	}
	if len(list.Kernels) != 1 || list.Kernels[0].Version != "1.0.0" || list.Kernels[0].Current {
		t.Errorf("kernel_list = %+v", list.Kernels)
	}
	if list.Catalog == nil || len(list.Catalog) != 0 {
		t.Errorf("catalog without a manifest = %+v, want an empty list", list.Catalog)
	}

	// kernel_remove over the socket: a done result plus a kernel.removed event.
	wc.sendType(t, wsproto.TypeCmd, "k2", wsproto.Cmd{
		Type: panelclient.CmdKernelRemove,
		Args: json.RawMessage(`{"name":"gost","version":"1.0.0"}`),
		TTLS: 60,
	})
	if err := json.Unmarshal(wc.recvType(t, wsproto.TypeCmdResult).D, &body); err != nil {
		t.Fatalf("kernel_remove result: %v", err)
	}
	if body.Status != "done" {
		t.Fatalf("kernel_remove = %+v", body)
	}
	raw, err = json.Marshal(body.Result)
	if err != nil {
		t.Fatal(err)
	}
	var removed panelclient.KernelRemoveResult
	if err := json.Unmarshal(raw, &removed); err != nil {
		t.Fatalf("kernel_remove result %s: %v", raw, err)
	}
	if removed.FreedBytes <= 0 {
		t.Errorf("freed_bytes = %d, want > 0", removed.FreedBytes)
	}

	eventEnv := wc.recvType(t, wsproto.TypeEvent)
	var event struct {
		Kind    string `json:"kind"`
		Level   string `json:"level"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(eventEnv.D, &event); err != nil {
		t.Fatalf("event payload: %v", err)
	}
	if event.Kind != "kernel.removed" {
		t.Errorf("event = %+v, want kernel.removed", event)
	}

	if _, err := os.Stat(filepath.Join(kernelsDir, "kernels", "gost", "1.0.0")); !os.IsNotExist(err) {
		t.Errorf("the version is still on disk after kernel_remove (%v)", err)
	}
}
