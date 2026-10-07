package xraynode

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
)

// Names of the local status endpoint. On Unix-like systems it is a Unix socket
// called StatusSocketName next to config.yml; on Windows (and anywhere a Unix
// socket is unavailable) it is a loopback TCP listener whose address is written
// to StatusAddrName.
const (
	StatusSocketName = "xray.sock"
	StatusAddrName   = "xray.addr"
	// StatusPath is the HTTP path the status document is served on.
	StatusPath = "/status"
)

// StatusServer serves GET /status on the kernel's local endpoint.
type StatusServer struct {
	svc       *Service
	ln        net.Listener
	srv       *http.Server
	addr      string
	configDir string
}

// NewStatusServer starts the local status endpoint for a service. configDir is
// the directory of config.yml; the socket (or the address file) is created
// there.
func NewStatusServer(svc *Service, configDir string) (*StatusServer, error) {
	ln, addr, err := listenStatus(configDir)
	if err != nil {
		return nil, err
	}
	s := &StatusServer{svc: svc, ln: ln, addr: addr, configDir: configDir}
	mux := http.NewServeMux()
	mux.HandleFunc(StatusPath, s.handleStatus)
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
	cleanupStatus(s.configDir)
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

// StatusSocketPath returns the path of the Unix socket next to config.yml.
func StatusSocketPath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), StatusSocketName)
}

// StatusAddrPath returns the path of the address file next to config.yml.
func StatusAddrPath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), StatusAddrName)
}
