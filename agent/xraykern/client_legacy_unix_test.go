//go:build !windows

package xraykern

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/xrayapi"
)

// TestStatusFallsBackToTheLegacySocket covers an in-place upgrade: a kernel up
// to v0.6.0 publishes its status socket next to config.yml, and the agent must
// keep reading it until that kernel is restarted with the new layout.
func TestStatusFallsBackToTheLegacySocket(t *testing.T) {
	c, dir := newClient(t, fakeKernels{err: ErrNotInstalled}, nil)
	t.Setenv(xrayapi.RuntimeDirEnv, t.TempDir()) // an empty runtime directory
	sock := xrayapi.LegacySocketPath(dir)
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("unix socket: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(xrayapi.Status{Version: "0.6.0", Running: true})
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
	})
	st, err := c.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !st.Running || st.Version != "0.6.0" {
		t.Fatalf("status = %+v", st)
	}
}
