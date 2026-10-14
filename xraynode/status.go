package xraynode

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/W1nCwC/W1nCray/agent/xrayapi"
)

// Names of the local status endpoint. They live in agent/xrayapi (the wire
// package the agent also links); the aliases keep the names this package used
// before the split.
const (
	StatusSocketName = xrayapi.StatusSocketName
	StatusAddrName   = xrayapi.StatusAddrName
	// StatusPath is the HTTP path the status document is served on.
	StatusPath = xrayapi.StatusPath
	// NodesSyncPath is the HTTP path that asks the kernel to re-fetch the
	// machine's node list now (the agent's hint{what:"nodes"}). It shares the
	// status endpoint and takes no parameter.
	NodesSyncPath = xrayapi.NodesSyncPath
)

// StatusServer serves GET /status on the kernel's local endpoint.
type StatusServer struct {
	svc  *Service
	ln   net.Listener
	srv  *http.Server
	addr string
	// endpointPath is the socket file (Unix) or the address file (Windows) the
	// endpoint owns and removes on Close.
	endpointPath string
}

// NewStatusServer starts the local status endpoint for a service. configDir is
// the directory of config.yml; on Unix the socket is created in the runtime
// directory (/run/W1nCray, see agent/xrayapi.SocketPath) and falls back to
// configDir when that directory cannot be created.
func NewStatusServer(svc *Service, configDir string) (*StatusServer, error) {
	ln, addr, path, err := listenStatus(configDir)
	if err != nil {
		return nil, err
	}
	s := &StatusServer{svc: svc, ln: ln, addr: addr, endpointPath: path}
	mux := http.NewServeMux()
	mux.HandleFunc(StatusPath, s.handleStatus)
	mux.HandleFunc(NodesSyncPath, s.handleNodesSync)
	s.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := s.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Warnf("status endpoint: %v", err)
		}
	}()
	return s, nil
}

// Addr returns where the endpoint is reachable (a socket path or host:port).
func (s *StatusServer) Addr() string { return s.addr }

// Close stops the endpoint and removes the socket file.
func (s *StatusServer) Close() {
	if s == nil || s.srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = s.srv.Shutdown(ctx)
	_ = s.ln.Close()
	cleanupStatus(s.endpointPath)
}

// handleStatus answers GET /status with the current status document.
func (s *StatusServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(s.svc.Status())
}

// handleNodesSync answers GET /nodes/sync: the kernel re-fetches this machine's
// node list from the panel now instead of waiting for its 60 s poll, and asks
// for a reload only when the version changed. The request carries no parameter
// (no path, no command, no node data) and the route exists only on the local
// status endpoint, so it adds no listener and no remote surface.
//
// A panel that could not be reached is answered with 502 and the running node
// list is left untouched: the caller (the agent) then falls back to the poll.
func (s *StatusServer) handleNodesSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	changed, version, err := s.svc.SyncMachineNodes(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(xrayapi.NodesSyncResult{Changed: changed, Version: version})
}

// StatusSocketPath returns the path of the Unix socket (the runtime directory,
// or the configuration directory when the runtime directory is unusable).
func StatusSocketPath(configPath string) string {
	return xrayapi.SocketPath(filepath.Dir(configPath))
}

// StatusAddrPath returns the path of the address file next to config.yml.
func StatusAddrPath(configPath string) string {
	return xrayapi.AddrPath(filepath.Dir(configPath))
}
