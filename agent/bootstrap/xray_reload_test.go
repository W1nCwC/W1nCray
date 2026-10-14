package bootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/xrayapi"
	"github.com/W1nCwC/W1nCray/config"
)

// recordingXray is a stand-in for the kernel service that records the
// fingerprint the reloader waits for.
type recordingXray struct {
	fp  string
	err error
}

func (r *recordingXray) Status(context.Context) (xrayapi.Status, error) {
	return xrayapi.Status{}, errors.New("not used")
}
func (r *recordingXray) CheckStaged(context.Context, string, []string) (xrayapi.StagedResult, error) {
	return xrayapi.StagedResult{}, errors.New("not used")
}
func (r *recordingXray) WaitReloaded(_ context.Context, fingerprint string) error {
	r.fp = fingerprint
	return r.err
}
func (r *recordingXray) SyncMachineNodes(context.Context) (bool, error) {
	return false, errors.New("not used")
}

// TestXrayReloaderWaitsForTheWrittenFingerprint is PLAN v11 §C: after a
// managed-file apply the agent waits for the kernel to report the fingerprint
// of the files on disk, computed with exactly the kernel's own code
// (config.Fingerprint over config.WatchedFiles).
func TestXrayReloaderWaitsForTheWrittenFingerprint(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yml")
	route := filepath.Join(dir, "route.json")
	if err := os.WriteFile(configPath, []byte("RouteConfigPath: "+route+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(route, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfigFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	want := config.Fingerprint(cfg.WatchedFiles(configPath))

	rec := &recordingXray{}
	if err := filesReloader(rec, configPath, nil).Reload(context.Background(), "test"); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if rec.fp != want {
		t.Fatalf("waited for %q, want the written files' fingerprint %q", rec.fp, want)
	}

	// A reload timeout is the reloader's error; filesync turns it into the
	// existing rollback path.
	rec2 := &recordingXray{err: errors.New("等待 Xray 内核重载配置超时")}
	if err := filesReloader(rec2, configPath, nil).Reload(context.Background(), "test"); err == nil {
		t.Fatal("a failed wait must be reported")
	}

	// Without a kernel service there is no reloader: filesync refuses a reload
	// instead of writing files no instance would read.
	if r := filesReloader(nil, configPath, nil); r != nil {
		t.Fatalf("reloader without a kernel = %v, want nil", r)
	}
	if r := filesReloader(rec, "", nil); r != nil {
		t.Fatalf("reloader without a config path = %v, want nil", r)
	}
}
