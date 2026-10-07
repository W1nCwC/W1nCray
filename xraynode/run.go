package xraynode

import (
	"context"
	"path/filepath"
)

// Run starts the kernel service for configPath and its local status endpoint,
// then blocks until ctx is cancelled. It is what `W1nCray-xray run` calls.
func Run(ctx context.Context, path string, cfg *Config) error {
	svc := New(path, cfg)
	if err := svc.Start(); err != nil {
		return err
	}
	status, err := NewStatusServer(svc, filepath.Dir(path))
	if err != nil {
		svc.Close()
		return err
	}
	<-ctx.Done()
	status.Close()
	svc.Close()
	return nil
}
