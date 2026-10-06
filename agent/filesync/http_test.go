package filesync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/panelclient"
)

// blobClient adapts the real panel HTTP client to filesync.BlobFetcher.
type blobClient struct{ c *panelclient.Client }

func (b blobClient) Fetch(ctx context.Context, sha string) ([]byte, bool, error) {
	res, err := b.c.Blob(ctx, panelclient.BlobRequest{SHA256: sha})
	if err != nil {
		return nil, false, err
	}
	if res.NotModified {
		return nil, true, nil
	}
	return res.Raw, false, nil
}

// TestLargeGeoBlobOverRealHTTP covers acceptance 9: a 30 MB geoip.dat is
// downloaded over a real HTTP server (no mock fetcher), verified and written in
// well under ten seconds.
func TestLargeGeoBlobOverRealHTTP(t *testing.T) {
	if testing.Short() {
		t.Skip("30 MB download")
	}
	const size = 30 << 20 // 30 MiB
	// Deterministic, incompressible-enough content: a repeating 4 KiB pattern
	// with a counter, so a truncated or misaligned body fails the hash.
	payload := make([]byte, size)
	pattern := make([]byte, 4096)
	for i := range pattern {
		pattern[i] = byte(i*7 + 3)
	}
	for off := 0; off < size; off += len(pattern) {
		n := copy(payload[off:], pattern)
		if n < len(pattern) {
			break
		}
	}
	sum := sha256.Sum256(payload)
	sha := hex.EncodeToString(sum[:])

	var served, notModified int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/server/machine/agent/file/"+sha {
			http.NotFound(w, r)
			return
		}
		etag := `"` + sha + `"`
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") == etag {
			atomic.AddInt64(&notModified, 1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		atomic.AddInt64(&served, 1)
		w.Header().Set("Content-Length", fmt.Sprint(size))
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	client, err := panelclient.New(panelclient.Options{
		BaseURL:   srv.URL,
		MachineID: 7,
		Token:     "test-token",
	})
	if err != nil {
		t.Fatalf("panelclient.New: %v", err)
	}

	dir := t.TempDir()
	configDir := filepath.Join(dir, "xray")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	validate := &stubValidator{}
	applier, err := New(Options{
		ConfigDir:       configDir,
		StateDir:        filepath.Join(dir, "state"),
		Fetch:           blobClient{c: client},
		Validate:        validate,
		Reload:          &stubReloader{},
		LayoutSeparated: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	start := time.Now()
	res, err := applier.Apply(context.Background(), []FileRef{{Name: NameGeoIP, SHA256: sha, Size: size}})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Status != StatusDone || res.Reload != ReloadNotNeeded {
		t.Fatalf("res = %+v, want done/not_needed", res)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("the 30 MB download and verification took %s, want under 10s", elapsed)
	}
	if atomic.LoadInt64(&served) != 1 {
		t.Errorf("HTTP 200 answers = %d, want 1", served)
	}
	onDisk, err := os.ReadFile(filepath.Join(configDir, NameGeoIP))
	if err != nil {
		t.Fatalf("read geoip.dat: %v", err)
	}
	if len(onDisk) != size {
		t.Fatalf("geoip.dat is %d bytes, want %d", len(onDisk), size)
	}
	got := sha256.Sum256(onDisk)
	if hex.EncodeToString(got[:]) != sha {
		t.Fatal("the written geoip.dat does not hash back to the desired sha256")
	}
	if res.Files[0].Bytes != size {
		t.Errorf("reported bytes = %d, want %d", res.Files[0].Bytes, size)
	}
	// The second apply is served from the blob cache: no HTTP request at all.
	before := atomic.LoadInt64(&served)
	res2, err := applier.Apply(context.Background(), []FileRef{{Name: NameGeoIP, SHA256: sha, Size: size}})
	if err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if res2.Reload != ReloadNotNeeded {
		t.Fatalf("second res = %+v", res2)
	}
	if atomic.LoadInt64(&served) != before {
		t.Error("the second apply fetched the blob over HTTP again")
	}
	t.Logf("30 MB geoip.dat applied in %s", elapsed)
}

// TestBlobOverRealHTTPWithETag covers the 304 path end to end: the client sends
// If-None-Match, and the applier refetches without it when its cache lost the
// blob.
func TestBlobOverRealHTTPWithETag(t *testing.T) {
	body := []byte(`{"rules":[{"outboundTag":"direct"}]}`)
	sum := sha256.Sum256(body)
	sha := hex.EncodeToString(sum[:])

	var noMatch, withMatch int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		etag := `"` + sha + `"`
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") != "" {
			atomic.AddInt64(&withMatch, 1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		atomic.AddInt64(&noMatch, 1)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	client, err := panelclient.New(panelclient.Options{BaseURL: srv.URL, MachineID: 7, Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	applier, err := New(Options{
		ConfigDir: dir, StateDir: filepath.Join(dir, "state"),
		Fetch: blobClient{c: client}, Validate: &stubValidator{}, Reload: &stubReloader{},
		LayoutSeparated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The first fetch has no ETag and gets the body.
	res, err := applier.Apply(context.Background(), []FileRef{{Name: NameRoute, SHA256: sha, Size: int64(len(body))}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Status != StatusDone {
		t.Fatalf("res = %+v", res)
	}
	if atomic.LoadInt64(&noMatch) != 1 || atomic.LoadInt64(&withMatch) != 0 {
		t.Errorf("first fetch: noMatch=%d withMatch=%d", noMatch, withMatch)
	}
	if got, err := os.ReadFile(filepath.Join(dir, NameRoute)); err != nil || string(got) != string(body) {
		t.Fatalf("route.json = %q, %v", got, err)
	}
	if !strings.Contains(string(body), "direct") {
		t.Fatal("unreachable")
	}
}
