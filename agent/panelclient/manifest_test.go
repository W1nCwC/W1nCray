package panelclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/kernelx"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
)

// ---- helpers ----------------------------------------------------------------

// writeTrustedKey writes the hex public key of a fresh ed25519 pair to path and
// returns the private key. The Ensurer trusts only this key.
func writeTrustedKey(t *testing.T, path string) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(pub)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return priv
}

// testManifest builds and signs a minimal valid manifest (one gost entry) with
// the given sequence.
func testManifest(t *testing.T, seq int64, priv ed25519.PrivateKey) []byte {
	t.Helper()
	arch := sha256.Sum256([]byte("archive"))
	bin := sha256.Sum256([]byte("binary"))
	now := time.Now()
	m := &manifest.Manifest{
		Schema: manifest.SchemaVersion, Sequence: seq,
		IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(24 * time.Hour),
		Kernels: []manifest.Kernel{{
			Name: "gost", Version: "3.3.0",
			License: manifest.License{SPDX: "MIT"},
			Run:     manifest.Run{Binary: "gost", VersionCmd: []string{"-V"}},
			Targets: map[string]*manifest.Target{
				"linux/amd64": {
					URLs: []string{"https://example.invalid/gost.tar.gz"}, Archive: manifest.ArchiveTarGz,
					ArchiveSHA256: hex.EncodeToString(arch[:]), ArchiveSize: 10,
					Extract:       []manifest.Extract{{From: "gost", To: "gost", SHA256: hex.EncodeToString(bin[:]), Size: 3, Mode: "0755"}},
					InstalledSize: 3,
				},
			},
		}},
	}
	raw, err := manifest.Sign(m, priv)
	if err != nil {
		t.Fatalf("sign manifest: %v", err)
	}
	return raw
}

// newTestEnsurer builds the production sink: an Ensurer trusting only the key
// in keysPath.
func newTestEnsurer(t *testing.T, dir, keysPath string) *kernelx.Ensurer {
	t.Helper()
	e, err := kernelx.New(kernelx.Options{Dir: dir, KeysPath: keysPath})
	if err != nil {
		t.Fatalf("kernelx.New: %v", err)
	}
	return e
}

// manifestEnv is the fixed layout every manifest test uses.
type manifestEnv struct {
	dir      string
	keysPath string
	persist  string
	kernels  string
	trusted  ed25519.PrivateKey
	ensurer  *kernelx.Ensurer
}

func newManifestEnv(t *testing.T) *manifestEnv {
	t.Helper()
	dir := t.TempDir()
	e := &manifestEnv{
		dir:      dir,
		keysPath: filepath.Join(dir, "keys.txt"),
		persist:  filepath.Join(dir, "state", "manifest.json"),
		kernels:  filepath.Join(dir, "kernels"),
	}
	e.trusted = writeTrustedKey(t, e.keysPath)
	e.ensurer = newTestEnsurer(t, e.kernels, e.keysPath)
	return e
}

func (e *manifestEnv) persisted() ([]byte, bool) {
	b, err := os.ReadFile(e.persist)
	return b, err == nil
}

// ---- sync loop ---------------------------------------------------------------

func TestManifestSyncFirstFetchLoadsPersistsThenUsesETag(t *testing.T) {
	e := newManifestEnv(t)
	raw := testManifest(t, 7, e.trusted)

	var mu sync.Mutex
	var etags []string
	h := newHarness(t, hopts{
		manifest:         e.ensurer,
		manifestPath:     e.persist,
		manifestInterval: 10 * time.Minute,
		manifestAnswer: func(n int, r *http.Request) (int, string, string) {
			if n == 1 {
				return 200, string(raw), `"seq7"`
			}
			mu.Lock()
			etags = append(etags, r.Header.Get("If-None-Match"))
			mu.Unlock()
			return 304, "", ""
		},
	})
	h.panel.waitCount("manifest", 1)

	eventually(t, "the manifest to be in force", func() bool {
		seq, ok := e.ensurer.ManifestSequence()
		return ok && seq == 7
	})
	eventually(t, "the manifest to be persisted", func() bool {
		got, ok := e.persisted()
		return ok && bytes.Equal(got, raw)
	})
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(e.persist)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("persisted manifest mode = %04o, want 0600", perm)
		}
	}
	if h.log.count("sequence 7") == 0 {
		t.Errorf("the accepted sequence was not logged: %s", h.log.text())
	}

	// The next round happens one interval later and is conditional.
	h.clock.fire(t, 10*time.Minute)
	h.panel.waitCount("manifest", 2)
	eventually(t, "the conditional request", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(etags) == 1 && etags[0] == `"seq7"`
	})
	// A 304 changes nothing.
	if seq, _ := e.ensurer.ManifestSequence(); seq != 7 {
		t.Errorf("sequence after 304 = %d, want 7", seq)
	}
}

func TestManifestSyncMissingManifestIsNotPersisted(t *testing.T) {
	e := newManifestEnv(t)
	h := newHarness(t, hopts{
		manifest:         e.ensurer,
		manifestPath:     e.persist,
		manifestInterval: 10 * time.Minute,
		// No manifestAnswer: the server answers 404 no_manifest.
	})
	h.panel.waitCount("manifest", 1)
	eventually(t, "the 404 to be logged at debug level", func() bool {
		return h.log.count("DEBUG panel: no kernel manifest published yet") >= 1
	})
	if _, ok := e.persisted(); ok {
		t.Error("a 404 must not create the persisted manifest")
	}
	if _, ok := e.ensurer.ManifestSequence(); ok {
		t.Error("a 404 must not load a manifest")
	}
	// The loop keeps its normal cadence.
	h.clock.fire(t, 10*time.Minute)
	h.panel.waitCount("manifest", 2)
}

// manifestRejection covers the two ways the sink refuses a document: a
// signature the local keys do not vouch for, and a sequence that goes
// backwards. In both cases the manifest in force must survive untouched.
func TestManifestSyncRejectedDocumentIsDropped(t *testing.T) {
	cases := []struct {
		name string
		// serve builds the document the panel sends.
		serve func(t *testing.T, e *manifestEnv) []byte
		want  string
	}{
		{
			name: "untrusted signature",
			serve: func(t *testing.T, e *manifestEnv) []byte {
				_, other, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				// A compromised panel can sign anything; it just does not
				// hold the private key the agent trusts.
				return testManifest(t, 8, other)
			},
			want: "unknown key",
		},
		{
			name: "sequence rollback",
			serve: func(t *testing.T, e *manifestEnv) []byte {
				return testManifest(t, 5, e.trusted)
			},
			want: "sequence 5 < accepted 9",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newManifestEnv(t)
			// Pre-load a newer, trusted manifest: this is what a rejected
			// document must not disturb.
			if err := e.ensurer.LoadManifest(testManifest(t, 9, e.trusted)); err != nil {
				t.Fatal(err)
			}
			bad := tc.serve(t, e)
			h := newHarness(t, hopts{
				manifest:         e.ensurer,
				manifestPath:     e.persist,
				manifestInterval: 10 * time.Minute,
				manifestAnswer: func(int, *http.Request) (int, string, string) {
					return 200, string(bad), `"bad"`
				},
			})
			h.panel.waitCount("manifest", 1)
			eventually(t, "the rejection to be logged", func() bool {
				return h.log.count("rejected the kernel manifest") >= 1
			})
			if !strings.Contains(h.log.text(), tc.want) {
				t.Errorf("the warning does not say %q: %s", tc.want, h.log.text())
			}
			if seq, ok := e.ensurer.ManifestSequence(); !ok || seq != 9 {
				t.Errorf("sequence = %d (ok=%v), want the pre-loaded 9", seq, ok)
			}
			if _, ok := e.persisted(); ok {
				t.Error("a rejected manifest must never be persisted")
			}
			// It is retried at the normal cadence, not in a tight loop.
			h.clock.fire(t, 10*time.Minute)
			h.panel.waitCount("manifest", 2)
			if seq, _ := e.ensurer.ManifestSequence(); seq != 9 {
				t.Errorf("sequence after the retry = %d, want 9", seq)
			}
		})
	}
}

func TestManifestSyncNetworkFailureBacksOffAndKeepsRunning(t *testing.T) {
	e := newManifestEnv(t)
	h := newHarness(t, hopts{
		manifest:         e.ensurer,
		manifestPath:     e.persist,
		manifestInterval: 10 * time.Minute,
		manifestAnswer: func(int, *http.Request) (int, string, string) {
			return 503, `{"error":"unavailable","message":"try later"}`, ""
		},
	})
	h.panel.waitCount("manifest", 1)
	eventually(t, "the failure to be logged", func() bool {
		return h.log.count("kernel manifest sync failed") >= 1
	})
	if _, ok := e.persisted(); ok {
		t.Error("a failed fetch must not persist anything")
	}
	// The first back-off is 30s (jitter is neutral: rand returns 0.5).
	h.clock.fire(t, 30*time.Second)
	h.panel.waitCount("manifest", 2)
	h.clock.fire(t, time.Minute)
	h.panel.waitCount("manifest", 3)
	// Still running, still backing off.
	eventually(t, "another failure", func() bool {
		return h.log.count("kernel manifest sync failed") >= 3
	})
}

func TestManifestSyncTokenNeverLeaks(t *testing.T) {
	cases := []struct {
		name   string
		answer func(int, *http.Request) (int, string, string)
	}{
		{"500 body", func(int, *http.Request) (int, string, string) {
			return 500, fmt.Sprintf(`{"error":"boom","message":%q}`, testToken), ""
		}},
		{"401 body", func(int, *http.Request) (int, string, string) {
			return 401, fmt.Sprintf(`{"error":"bad_token","message":"token %s refused"}`, testToken), ""
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newManifestEnv(t)
			h := newHarness(t, hopts{
				manifest:         e.ensurer,
				manifestPath:     e.persist,
				manifestInterval: 10 * time.Minute,
				manifestAnswer:   tc.answer,
			})
			h.panel.waitCount("manifest", 1)
			eventually(t, "the failure to be logged", func() bool {
				return h.log.count("kernel manifest sync failed") >= 1
			})
			if strings.Contains(h.log.text(), testToken) {
				t.Errorf("the token is in the log: %s", h.log.text())
			}
		})
	}
}

func TestManifestSyncStopsPromptlyWhileTheRequestHangs(t *testing.T) {
	e := newManifestEnv(t)
	h := newHarness(t, hopts{
		manifest:         e.ensurer,
		manifestInterval: 10 * time.Minute,
		manifestAnswer: func(_ int, r *http.Request) (int, string, string) {
			<-r.Context().Done() // the client must abort this on cancellation
			return 200, "", ""
		},
	})
	h.panel.waitCount("manifest", 1) // the request is stuck inside the server
	h.stop()                         // must return, and without Runner goroutines left
}

func TestManifestSyncDisabledWithoutASink(t *testing.T) {
	h := newHarness(t, hopts{})
	h.panel.waitCount("config", 1)
	time.Sleep(20 * time.Millisecond)
	if n := h.panel.count("manifest"); n != 0 {
		t.Errorf("the manifest endpoint was called %d time(s) without a sink", n)
	}
}

// ---- client ------------------------------------------------------------------

func TestClientManifestGet(t *testing.T) {
	var got struct {
		method, path, machine, auth, etag string
		body                              []byte
	}
	srv := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		got.body, _ = io.ReadAll(r.Body)
		got.method, got.path = r.Method, r.URL.Path
		got.machine = r.Header.Get("X-Machine-Id")
		got.auth = r.Header.Get("Authorization")
		got.etag = r.Header.Get("If-None-Match")
		w.Header().Set("ETag", `"abc"`)
		writeJSON(w, 200, `{"sequence":3}`)
	})
	c := newClient(t, srv)
	res, err := c.Manifest(context.Background(), ManifestRequest{ETag: `"old"`})
	if err != nil {
		t.Fatal(err)
	}
	if got.method != http.MethodGet || got.path != testPrefix+"manifest" {
		t.Errorf("request = %s %s", got.method, got.path)
	}
	if got.machine != strconv.Itoa(testMachineID) || got.auth != "Bearer "+testToken {
		t.Errorf("machine=%q auth=%q", got.machine, got.auth)
	}
	if got.etag != `"old"` {
		t.Errorf("If-None-Match = %q", got.etag)
	}
	if len(got.body) != 0 {
		t.Errorf("GET body = %q", got.body)
	}
	if res.NotModified || res.ETag != `"abc"` || string(res.Raw) != `{"sequence":3}` {
		t.Errorf("response = %+v", res)
	}
}

func TestClientManifestAnswers(t *testing.T) {
	t.Run("304", func(t *testing.T) {
		srv := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("If-None-Match") != `"same"` {
				t.Errorf("If-None-Match = %q", r.Header.Get("If-None-Match"))
			}
			w.WriteHeader(http.StatusNotModified)
		})
		res, err := newClient(t, srv).Manifest(context.Background(), ManifestRequest{ETag: `"same"`})
		if err != nil || !res.NotModified || res.Raw != nil {
			t.Fatalf("res=%+v err=%v", res, err)
		}
	})
	t.Run("404", func(t *testing.T) {
		srv := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusNotFound, `{"error":"no_manifest"}`)
		})
		_, err := newClient(t, srv).Manifest(context.Background(), ManifestRequest{})
		if err != ErrNoManifest {
			t.Fatalf("err = %v, want ErrNoManifest", err)
		}
		noTokenIn(t, "404", err)
	})
	t.Run("oversized body", func(t *testing.T) {
		srv := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			io.WriteString(w, strings.Repeat("x", maxManifestBytes+1))
		})
		_, err := newClient(t, srv).Manifest(context.Background(), ManifestRequest{})
		if err == nil {
			t.Fatal("a body over the limit was accepted")
		}
		if !strings.Contains(err.Error(), "exceeds") {
			t.Errorf("err = %v", err)
		}
		noTokenIn(t, "oversized", err)
	})
	t.Run("server error body is redacted", func(t *testing.T) {
		srv := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusInternalServerError, fmt.Sprintf(`{"error":"boom","message":%q}`, testToken))
		})
		_, err := newClient(t, srv).Manifest(context.Background(), ManifestRequest{})
		noTokenIn(t, "500", err)
	})
}

// ---- intervals ---------------------------------------------------------------

func TestClampManifestInterval(t *testing.T) {
	for in, want := range map[time.Duration]time.Duration{
		0: time.Hour, -5: time.Hour, time.Second: 5 * time.Minute, 5 * time.Minute: 5 * time.Minute,
		10 * time.Minute: 10 * time.Minute, time.Hour: time.Hour, 48 * time.Hour: 24 * time.Hour,
	} {
		if got := ClampManifestInterval(in); got != want {
			t.Errorf("ClampManifestInterval(%v) = %v, want %v", in, got, want)
		}
	}
}

func TestManifestWaitIsJitteredByTenPercent(t *testing.T) {
	const base = time.Hour
	for _, tc := range []struct {
		rand float64
		want time.Duration
	}{{0, 54 * time.Minute}, {0.5, time.Hour}, {0.999999, 66 * time.Minute}} {
		r, err := NewRunner(&Client{}, &fakeApp{}, RunnerOptions{Rand: func() float64 { return tc.rand }})
		if err != nil {
			t.Fatal(err)
		}
		got := r.jitterBy(base, manifestJitterFraction)
		if diff := got - tc.want; diff < -time.Millisecond || diff > time.Millisecond {
			t.Errorf("jitter(rand=%v) = %v, want about %v", tc.rand, got, tc.want)
		}
	}
	// The generic jitter is untouched: still +/-20%.
	r, _ := NewRunner(&Client{}, &fakeApp{}, RunnerOptions{Rand: func() float64 { return 0 }})
	if got := r.jitter(time.Hour); got != 48*time.Minute {
		t.Errorf("jitter(1h, rand=0) = %v, want 48m", got)
	}
}
