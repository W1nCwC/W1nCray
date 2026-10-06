package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/agentcfg"
	"github.com/W1nCwC/W1nCray/agent/filesync"
	"github.com/W1nCwC/W1nCray/agent/opscmd"
	"github.com/W1nCwC/W1nCray/agent/panelclient"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// TestFileCapabilityRequiresTheSeparatedLayoutAndRoots covers ruling 1 and 2:
// the "files" capability is a promise, so it is only declared when the
// managed-file layer is wired, the local Files policy has a root, and the
// machine uses the agent.yml layout (otherwise the panel would be handed a
// write path to the agent's own configuration).
func TestFileCapabilityRequiresTheSeparatedLayoutAndRoots(t *testing.T) {
	dir := t.TempDir()
	rt := &Runtime{log: nopLog{}}

	// No file layer at all.
	if rt.fileCapable() {
		t.Error("a runtime without a managed-file layer claims the capability")
	}
	if got := capabilities(&agentcfg.Config{}, false, false, false); hasCapability(got, wsproto.CapFiles) {
		t.Errorf("capabilities = %v, want no files", got)
	}
	if got := capabilities(&agentcfg.Config{}, false, false, true); !hasCapability(got, wsproto.CapFiles) {
		t.Errorf("capabilities = %v, want files", got)
	}

	// A file layer with the single-file layout: config.yml is the agent's own
	// configuration, so the capability must not be promised.
	rt.Files = newFilesRuntime(Options{
		StateDir: dir,
		Files: &FilesOptions{
			ConfigDir:       filepath.Join(dir, "xray"),
			ConfigPath:      filepath.Join(dir, "config.yml"),
			LayoutSeparated: false,
		},
	})
	if rt.Files == nil {
		t.Fatal("the file layer was not built")
	}
	rt.cfg = &agentcfg.Config{Files: &agentcfg.FilesConfig{Roots: []string{filepath.Join(dir, "xray")}}}
	if rt.fileCapable() {
		t.Error("the capability was promised with the single-file layout")
	}

	// The separated layout with a root: the capability is promised.
	rt.Files = newFilesRuntime(Options{
		StateDir: dir,
		Files: &FilesOptions{
			ConfigDir:       filepath.Join(dir, "xray"),
			ConfigPath:      filepath.Join(dir, "config.yml"),
			LayoutSeparated: true,
		},
	})
	if !rt.fileCapable() {
		t.Error("the capability was not promised with the separated layout and a root")
	}
	// The single contract name "files" is the conjunction of both file
	// features: the managed layer alone is not enough, because the panel gates
	// desired.files on this one capability and the file_* commands must be
	// servable under it too (see filesCapable).
	if rt.filesCapable() {
		t.Error("filesCapable was promised although the file_* commands are not registered")
	}
	if rt.fileCmdsCapable() {
		t.Error("a runtime without a confined file manager claims the file_* commands")
	}

	// No local root: the panel may not manage anything.
	rt.cfg = &agentcfg.Config{Files: &agentcfg.FilesConfig{}}
	if rt.fileCapable() {
		t.Error("the capability was promised without a Files.Roots entry")
	}
}

// TestFilesRuntimeApplyThroughTheRegistry is the wiring test: a
// bootstrap.FilesRuntime installed on the ops registry applies a blob fetched
// over real HTTP and reports applied_pending through the late-result sink.
func TestFilesRuntimeApplyThroughTheRegistry(t *testing.T) {
	content := []byte(`{"rules":[{"type":"field","outboundTag":"direct","domain":["example.com"]}]}`)
	sha := filesync.Digest(content)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/server/machine/agent/file/"+sha {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	client, err := panelclient.New(panelclient.Options{BaseURL: srv.URL, MachineID: 1, Token: "t"})
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	configDir := filepath.Join(dir, "xray")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	rt := &Runtime{log: nopLog{}}
	rt.Files = newFilesRuntime(Options{
		StateDir: filepath.Join(dir, "state"),
		Files: &FilesOptions{
			ConfigDir:       configDir,
			ConfigPath:      filepath.Join(dir, "config.yml"),
			LayoutSeparated: true,
		},
	})
	if rt.Files == nil {
		t.Fatal("the file layer was not built")
	}
	rt.Files.applier.SetFetch(blobFetcher{api: client})
	rt.Files.applier.SetSource(filesync.SourceFunc(func() []filesync.FileRef {
		return []filesync.FileRef{{Name: filesync.NameRoute, SHA256: sha, Size: int64(len(content))}}
	}))
	rt.Files.applier.SetValidator(filesync.ValidatorFunc(func(context.Context, string, []filesync.FileRef) []error {
		return nil
	}))
	var reloads []string
	rt.Files.applier.SetReload(filesync.ReloaderFunc(func(_ context.Context, reason string) error {
		reloads = append(reloads, reason)
		return nil
	}))

	reg, err := opscmd.New(opscmd.Deps{Kernels: rt.Kernels, Log: rt.log})
	if err != nil {
		t.Fatal(err)
	}
	sink := &captureSink{}
	reg.SetSink(sink)
	reg.SetFiles(rt.Files)

	status, _ := reg.Execute(context.Background(), panelclient.Command{ID: "c1", Type: panelclient.CmdFilesApply})
	if status != panelclient.ResultAccepted {
		t.Fatalf("status = %q, want accepted", status)
	}
	got := sink.wait(t, 1)
	var body struct {
		Status         string `json:"status"`
		Reload         string `json:"reload"`
		AppliedPending bool   `json:"applied_pending"`
	}
	if err := json.Unmarshal(got[0].data, &body); err != nil {
		t.Fatalf("late body %s: %v", got[0].data, err)
	}
	if body.Status != filesync.StatusDone || body.Reload != filesync.ReloadReloaded || !body.AppliedPending {
		t.Errorf("late body = %s", got[0].data)
	}
	if len(reloads) != 1 {
		t.Errorf("reloads = %v, want one", reloads)
	}
	onDisk, err := os.ReadFile(filepath.Join(configDir, filesync.NameRoute))
	if err != nil {
		t.Fatalf("route.json: %v", err)
	}
	if string(onDisk) != string(content) {
		t.Errorf("route.json = %q", onDisk)
	}
}

// TestFilesHintUsesTheSameApplier: SyncFiles (the "files" hint) applies the
// desired files, so the hint and the command cannot drift apart.
func TestFilesHintUsesTheSameApplier(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "xray")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := []byte("geo bytes")
	sha := filesync.Digest(content)
	rt := &Runtime{log: nopLog{}}
	rt.Files = newFilesRuntime(Options{
		StateDir: filepath.Join(dir, "state"),
		Files:    &FilesOptions{ConfigDir: configDir, ConfigPath: filepath.Join(dir, "config.yml"), LayoutSeparated: true},
	})
	rt.Files.applier.SetFetch(filesync.BlobFetcherFunc(func(context.Context, string) ([]byte, bool, error) {
		return content, false, nil
	}))
	rt.Files.applier.SetSource(filesync.SourceFunc(func() []filesync.FileRef {
		return []filesync.FileRef{{Name: filesync.NameGeoIP, SHA256: sha, Size: int64(len(content))}}
	}))
	rt.Files.applier.SetValidator(filesync.ValidatorFunc(func(context.Context, string, []filesync.FileRef) []error { return nil }))

	if err := rt.Files.SyncFiles(context.Background()); err != nil {
		t.Fatalf("SyncFiles: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(configDir, filesync.NameGeoIP)); err != nil || string(got) != string(content) {
		t.Fatalf("geoip.dat = %q, %v", got, err)
	}

	// A refusal must surface as an error, never as silence (ruling 5).
	rt.Files.applier.SetValidator(filesync.ValidatorFunc(func(context.Context, string, []filesync.FileRef) []error {
		return []error{errors.New("route.json: rules[0] bad")}
	}))
	rt.Files.applier.SetSource(filesync.SourceFunc(func() []filesync.FileRef {
		return []filesync.FileRef{{Name: filesync.NameRoute, SHA256: filesync.Digest([]byte(`{"rules":[]}`)), Size: 12}}
	}))
	rt.Files.applier.SetFetch(filesync.BlobFetcherFunc(func(context.Context, string) ([]byte, bool, error) {
		return []byte(`{"rules":[]}`), false, nil
	}))
	if err := rt.Files.SyncFiles(context.Background()); err == nil {
		t.Error("a refused hint apply returned nil")
	} else if !strings.Contains(err.Error(), "rules[0]") {
		t.Errorf("hint error = %v, want the validator error", err)
	}
}

// TestFilesRuntimeWithoutADirectoryIsOff: no xray directory means no file
// commands, and the registry answers them explicitly.
func TestFilesRuntimeWithoutADirectoryIsOff(t *testing.T) {
	rt := &Runtime{log: nopLog{}}
	rt.Files = newFilesRuntime(Options{StateDir: t.TempDir()})
	if rt.Files != nil {
		t.Fatal("a file layer was built without a ConfigDir")
	}
	reg, err := opscmd.New(opscmd.Deps{Kernels: rt.Kernels, Log: rt.log})
	if err != nil {
		t.Fatal(err)
	}
	status, res := reg.Execute(context.Background(), panelclient.Command{ID: "c1", Type: panelclient.CmdFilesApply})
	if status != panelclient.ResultFailed || !strings.Contains(string(res), "not_supported") {
		t.Fatalf("status=%q res=%s", status, res)
	}
}

// TestFilesSourceReadsTheLastDesiredState: the source the applier reads is the
// reconciler's last desired state, files included.
func TestFilesSourceReadsTheLastDesiredState(t *testing.T) {
	src := filesSource{rt: &Runtime{}}
	if got := src.DesiredFiles(); got != nil {
		t.Errorf("DesiredFiles on an empty runtime = %v", got)
	}
}

// captureSink records the late results.
type captureSink struct {
	mu      sync.Mutex
	results []struct {
		id, status string
		data       json.RawMessage
	}
}

func (s *captureSink) Deliver(id, status string, data json.RawMessage) {
	s.mu.Lock()
	s.results = append(s.results, struct {
		id, status string
		data       json.RawMessage
	}{id, status, data})
	s.mu.Unlock()
}

func (s *captureSink) wait(t *testing.T, n int) []struct {
	id, status string
	data       json.RawMessage
} {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		got := append([]struct {
			id, status string
			data       json.RawMessage
		}(nil), s.results...)
		s.mu.Unlock()
		if len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d late result(s)", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestDesiredFilesRoundTripThroughSpec pins the wire shape: the files section
// of a desired state decodes into spec.FileRef.
func TestDesiredFilesRoundTripThroughSpec(t *testing.T) {
	raw := []byte(`{"version":1,"revision":7,"instances":[],"files":[{"name":"route.json","sha256":"` +
		strings.Repeat("a", 64) + `","size":12,"kernel":"xray"}]}`)
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var d spec.Desired
	if err := dec.Decode(&d); err != nil {
		t.Fatalf("a desired state with files was rejected: %v", err)
	}
	if len(d.Files) != 1 || d.Files[0].Name != "route.json" || d.Files[0].Kernel != "xray" {
		t.Fatalf("files = %+v", d.Files)
	}
}
