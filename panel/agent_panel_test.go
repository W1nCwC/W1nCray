package panel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/bootstrap"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
)

const testPanelToken = "tok-panel-0123456789"

// writeAgentConfig writes a config with an Agent.Panel section; panelYAML is
// the indented body of that section.
func writeAgentConfig(t *testing.T, dir, panelYAML string) string {
	t.Helper()
	path := filepath.Join(dir, "config.yml")
	body := fmt.Sprintf("Log: {Level: warning}\nAgent:\n  Enabled: true\n  StateDir: %q\n  Panel:\n%s", filepath.Join(dir, "state"), panelYAML)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAgentPanelConfigParses(t *testing.T) {
	dir := t.TempDir()
	path := writeAgentConfig(t, dir, `    Enabled: true
    URL: https://panel.example.com
    MachineID: 7
    TokenFile: panel.token
    PullIntervalSec: 45
    ReportIntervalSec: 5
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	pc := cfg.Agent.Panel
	if pc == nil || !pc.Enabled || pc.URL != "https://panel.example.com" || pc.MachineID != 7 {
		t.Fatalf("panel section = %+v", pc)
	}
	// A relative token file is relative to the config file.
	if pc.TokenFile != filepath.Join(dir, "panel.token") {
		t.Errorf("TokenFile = %q", pc.TokenFile)
	}
	pull, report := pc.Intervals()
	if pull != 45*time.Second || report != 10*time.Second {
		t.Errorf("intervals = %v / %v, want 45s and the 10s minimum", pull, report)
	}
	if p0, r0 := (&AgentPanelConfig{}).Intervals(); p0 != 30*time.Second || r0 != 30*time.Second {
		t.Errorf("default intervals = %v / %v", p0, r0)
	}
}

func TestAgentPanelConfigValidation(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string // error substring; "" = valid
	}{
		{"token", "    Enabled: true\n    URL: https://p.example.com\n    MachineID: 1\n    Token: abc\n", ""},
		{"token file", "    Enabled: true\n    URL: https://p.example.com\n    MachineID: 1\n    TokenFile: /x/tok\n", ""},
		{"disabled sections are not validated", "    Enabled: false\n    URL: not a url\n", ""},
		{"both token and file", "    Enabled: true\n    URL: https://p.example.com\n    MachineID: 1\n    Token: abc\n    TokenFile: /x\n", "both set"},
		{"neither token nor file", "    Enabled: true\n    URL: https://p.example.com\n    MachineID: 1\n", "needs Token or TokenFile"},
		{"no machine id", "    Enabled: true\n    URL: https://p.example.com\n    Token: abc\n", "MachineID"},
		{"negative machine id", "    Enabled: true\n    URL: https://p.example.com\n    MachineID: -3\n    Token: abc\n", "MachineID"},
		{"no url", "    Enabled: true\n    MachineID: 1\n    Token: abc\n", "Agent.Panel.URL"},
		{"plain http", "    Enabled: true\n    URL: http://panel.example.com\n    MachineID: 1\n    Token: abc\n", "https"},
		{"plain http, explicitly allowed", "    Enabled: true\n    URL: http://panel.example.com\n    MachineID: 1\n    Token: abc\n    AllowInsecureHTTP: true\n", ""},
		{"plain http to loopback", "    Enabled: true\n    URL: http://127.0.0.1:8080\n    MachineID: 1\n    Token: abc\n", ""},
		{"user info in the url", "    Enabled: true\n    URL: https://u:p@panel.example.com\n    MachineID: 1\n    Token: abc\n", "user info"},
		{"negative interval", "    Enabled: true\n    URL: https://p.example.com\n    MachineID: 1\n    Token: abc\n    PullIntervalSec: -1\n", "negative"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeAgentConfig(t, t.TempDir(), tc.yaml)
			_, err := LoadConfig(path)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.want != "" && err == nil:
				t.Fatal("accepted")
			case tc.want != "" && !strings.Contains(err.Error(), tc.want):
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
			if err != nil && strings.Contains(err.Error(), ":p@") {
				t.Errorf("error leaks URL credentials: %v", err)
			}
		})
	}
}

func TestAgentPanelRequiresTheAgent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	body := `Log: {Level: warning}
Nodes:
  - ApiConfig: {ApiHost: "https://p.example.com", ApiKey: k, NodeID: 1}
Agent:
  Enabled: false
  Panel: {Enabled: true, URL: "https://p.example.com", MachineID: 1, Token: abc}
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "requires Agent.Enabled") {
		t.Fatalf("err = %v", err)
	}
}

func TestCheckTokenFileMode(t *testing.T) {
	cases := []struct {
		mode    fs.FileMode
		goos    string
		wantErr bool
	}{
		{0o600, "linux", false},
		{0o400, "linux", false},
		{0o700, "linux", false},
		{0o640, "linux", true},
		{0o604, "linux", true},
		{0o644, "linux", true},
		{0o660, "darwin", true},
		{0o777, "freebsd", true},
		{0o644, "windows", false}, // permission bits are meaningless there
		{0o777, "windows", false},
	}
	for _, tc := range cases {
		err := checkTokenFileMode("/etc/W1nCray/panel.token", tc.mode, tc.goos)
		if (err != nil) != tc.wantErr {
			t.Errorf("mode %04o on %s: err = %v, wantErr %v", tc.mode, tc.goos, err, tc.wantErr)
		}
		if err != nil && !strings.Contains(err.Error(), "chmod 600") {
			t.Errorf("the error should say how to fix it: %v", err)
		}
	}
}

func TestReadTokenFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string, mode fs.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("trims surrounding whitespace", func(t *testing.T) {
		got, err := readTokenFile(write("a", "  "+testPanelToken+" \r\n\n", 0o600))
		if err != nil || got != testPanelToken {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	t.Run("empty", func(t *testing.T) {
		if _, err := readTokenFile(write("empty", " \n", 0o600)); err == nil || !strings.Contains(err.Error(), "empty") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("more than a token", func(t *testing.T) {
		if _, err := readTokenFile(write("two", "tok en\n", 0o600)); err == nil {
			t.Fatal("accepted a file with whitespace inside")
		}
	})
	t.Run("too large", func(t *testing.T) {
		if _, err := readTokenFile(write("big", strings.Repeat("a", maxTokenFileBytes+1), 0o600)); err == nil || !strings.Contains(err.Error(), "larger") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("missing", func(t *testing.T) {
		if _, err := readTokenFile(filepath.Join(dir, "nope")); err == nil {
			t.Fatal("accepted a missing file")
		}
	})
	t.Run("directory", func(t *testing.T) {
		if _, err := readTokenFile(dir); err == nil {
			t.Fatal("accepted a directory")
		}
	})
	t.Run("group/other readable is refused on Unix", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("permission bits are not enforced on Windows")
		}
		p := write("loose", testPanelToken, 0o640)
		_, err := readTokenFile(p)
		if err == nil || !strings.Contains(err.Error(), "group or other") {
			t.Fatalf("err = %v", err)
		}
		if strings.Contains(err.Error(), testPanelToken) {
			t.Errorf("the error leaks the token: %v", err)
		}
		if err := os.Chmod(p, 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := readTokenFile(p); err != nil || got != testPanelToken {
			t.Fatalf("after chmod 600: %q, %v", got, err)
		}
	})
}

func TestResolveToken(t *testing.T) {
	if tok, err := (&AgentPanelConfig{Token: "inline"}).ResolveToken(); err != nil || tok != "inline" {
		t.Errorf("inline: %q %v", tok, err)
	}
	if _, err := (&AgentPanelConfig{}).ResolveToken(); err == nil {
		t.Error("no token source accepted")
	}
	p := filepath.Join(t.TempDir(), "tok")
	os.WriteFile(p, []byte(testPanelToken+"\n"), 0o600)
	if tok, err := (&AgentPanelConfig{TokenFile: p}).ResolveToken(); err != nil || tok != testPanelToken {
		t.Errorf("file: %q %v", tok, err)
	}
}

func TestCheckAgentPanelReport(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.token")
	os.WriteFile(good, []byte(testPanelToken), 0o600)
	pc := func() *AgentPanelConfig {
		return &AgentPanelConfig{Enabled: true, URL: "https://panel.example.com", MachineID: 7}
	}

	t.Run("token file", func(t *testing.T) {
		c := pc()
		c.TokenFile = good
		var w bytes.Buffer
		if err := checkAgentPanel(&w, c); err != nil {
			t.Fatalf("%v\n%s", err, w.String())
		}
		out := w.String()
		if !strings.Contains(out, "panel.example.com") || !strings.Contains(out, "机器 ID 7") || !strings.Contains(out, "TokenFile") {
			t.Errorf("report:\n%s", out)
		}
		if strings.Contains(out, testPanelToken) {
			t.Errorf("the report prints the token:\n%s", out)
		}
	})
	t.Run("inline token is flagged but never printed", func(t *testing.T) {
		c := pc()
		c.Token = testPanelToken
		var w bytes.Buffer
		if err := checkAgentPanel(&w, c); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(w.String(), testPanelToken) || !strings.Contains(w.String(), "建议改用") {
			t.Errorf("report:\n%s", w.String())
		}
	})
	t.Run("unreadable token file fails the check", func(t *testing.T) {
		c := pc()
		c.TokenFile = filepath.Join(dir, "missing.token")
		var w bytes.Buffer
		if err := checkAgentPanel(&w, c); err == nil || !strings.Contains(w.String(), "✗") {
			t.Fatalf("err = %v\n%s", err, w.String())
		}
	})
	t.Run("clamped intervals and insecure http are called out", func(t *testing.T) {
		c := pc()
		c.Token, c.PullIntervalSec, c.AllowInsecureHTTP = "t", 1, true
		var w bytes.Buffer
		if err := checkAgentPanel(&w, c); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(w.String(), "10–300") || !strings.Contains(w.String(), "AllowInsecureHTTP") {
			t.Errorf("report:\n%s", w.String())
		}
	})
	t.Run("disabled prints nothing", func(t *testing.T) {
		var w bytes.Buffer
		if err := checkAgentPanel(&w, &AgentPanelConfig{}); err != nil || w.Len() != 0 {
			t.Errorf("err=%v out=%q", err, w.String())
		}
		if err := checkAgentPanel(&w, nil); err != nil || w.Len() != 0 {
			t.Errorf("nil: err=%v out=%q", err, w.String())
		}
	})
	t.Run("loose file mode fails the check on Unix", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("permission bits are not enforced on Windows")
		}
		loose := filepath.Join(dir, "loose.token")
		os.WriteFile(loose, []byte(testPanelToken), 0o644)
		os.Chmod(loose, 0o644)
		c := pc()
		c.TokenFile = loose
		var w bytes.Buffer
		if err := checkAgentPanel(&w, c); err == nil {
			t.Fatalf("accepted a world-readable token file\n%s", w.String())
		}
	})
}

// fakePanelServer is a loopback panel: it hands out one desired state and
// records what the agent sends. Loopback http is accepted by the client.
type fakePanelServer struct {
	srv *httptest.Server

	mu       sync.Mutex
	desired  string // the "desired" JSON; "" answers unchanged
	down     bool   // answer 503 to everything
	manifest string // the signed manifest body; "" answers 404 no_manifest
	etag     string
	counts   map[string]int
	ack      map[string]any
	auth     string
	headers  http.Header
}

func newFakePanelServer(t *testing.T) *fakePanelServer {
	f := &fakePanelServer{counts: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		ep := strings.TrimPrefix(r.URL.Path, "/api/v2/server/machine/agent/")
		f.mu.Lock()
		defer f.mu.Unlock()
		f.counts[ep]++
		f.auth, f.headers = r.Header.Get("Authorization"), r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		if f.down {
			w.WriteHeader(503)
			io.WriteString(w, `{"error":"down","message":"maintenance"}`)
			return
		}
		switch ep {
		case "config":
			if f.desired == "" {
				io.WriteString(w, `{"schema":1,"unchanged":true,"revision":0}`)
				return
			}
			fmt.Fprintf(w, `{"schema":1,"revision":1,"hash":"sha256:one","desired":%s}`, f.desired)
		case "ack":
			var m map[string]any
			json.Unmarshal(raw, &m)
			f.ack = m
			io.WriteString(w, `{"ok":true}`)
		case "manifest":
			if f.manifest == "" {
				w.WriteHeader(404)
				io.WriteString(w, `{"error":"no_manifest"}`)
				return
			}
			if f.etag != "" {
				w.Header().Set("ETag", f.etag)
			}
			io.WriteString(w, f.manifest)
		default:
			io.WriteString(w, `{"ok":true}`)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakePanelServer) count(ep string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.counts[ep]
}

// TestPanelLinkEndToEnd runs the whole panel with an agent linked to a (fake)
// panel: the pushed state is applied and acknowledged with the token file's
// token; after a restart the last good state comes back without the panel, and
// stopping the panel ends the link.
func TestPanelLinkEndToEnd(t *testing.T) {
	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "panel.token")
	if err := os.WriteFile(tokenFile, []byte(testPanelToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fp := newFakePanelServer(t)
	fp.desired = fmt.Sprintf(`{"version":1,"revision":1,"instances":[{"id":"fwd1","enabled":true,"engine":"xray","kind":"forward","listen":{"addr":"127.0.0.1","ports":"%d"},"targets":[{"host":"1.1.1.1","ports":"80"}]}]}`, port)

	configPath := writeAgentConfig(t, dir, fmt.Sprintf(`    Enabled: true
    URL: %s
    MachineID: 7
    TokenFile: %q
`, fp.srv.URL, tokenFile))

	// Lifetime 1: the panel pushes the state.
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	p := New(configPath, cfg)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	waitDial(t, addr, true, 20*time.Second, "port open after the panel pushed the state")
	deadline := time.Now().Add(10 * time.Second)
	for fp.count("ack") == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no ack reached the panel")
		}
		time.Sleep(10 * time.Millisecond)
	}
	fp.mu.Lock()
	ack, auth, hdr := fp.ack, fp.auth, fp.headers
	fp.mu.Unlock()
	rep, _ := ack["report"].(map[string]any)
	if ack["revision"] != float64(1) || ack["hash"] != "sha256:one" || rep["status"] != "applied" {
		t.Errorf("ack = %v", ack)
	}
	if auth != "Bearer "+testPanelToken || hdr.Get("X-Machine-Id") != "7" {
		t.Errorf("credentials sent: %q / machine %q", auth, hdr.Get("X-Machine-Id"))
	}
	p.Close()
	waitDial(t, addr, false, 20*time.Second, "port closed after Close")
	// Close ended the link: no more requests.
	n := fp.count("config")
	time.Sleep(100 * time.Millisecond)
	if fp.count("config") != n {
		t.Error("the link kept talking to the panel after Close")
	}

	// Lifetime 2: the panel is down. The last good state still comes back.
	fp.mu.Lock()
	fp.down = true
	fp.mu.Unlock()
	cfg2, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	p2 := New(configPath, cfg2)
	if err := p2.Start(); err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	waitDial(t, addr, true, 20*time.Second, "port open after restart with the panel down (Resume)")
	deadline = time.Now().Add(10 * time.Second)
	for fp.count("config") <= n {
		if time.Now().After(deadline) {
			t.Fatal("the restarted agent never tried the panel")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !dialOK(addr) {
		t.Error("a panel outage took the resumed forwarding down")
	}
}

func dialOK(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// ---- kernel manifest sync ----------------------------------------------------

// TestAgentPanelManifestSyncConfig covers the two new knobs: the default (on,
// 1h) and the explicit opt-out, plus the [300, 86400] clamp.
func TestAgentPanelManifestSyncConfig(t *testing.T) {
	load := func(t *testing.T, extra string) *AgentPanelConfig {
		t.Helper()
		dir := t.TempDir()
		path := writeAgentConfig(t, dir, `    Enabled: true
    URL: https://panel.example.com
    MachineID: 7
    Token: t
`+extra)
		cfg, err := LoadConfig(path)
		if err != nil {
			t.Fatal(err)
		}
		return cfg.Agent.Panel
	}

	pc := load(t, "")
	if !pc.ManifestSyncEnabled() {
		t.Error("manifest sync must default to enabled")
	}
	if pc.ManifestSync != nil {
		t.Errorf("ManifestSync default = %v, want unset (nil)", *pc.ManifestSync)
	}
	if got := pc.ManifestInterval(); got != time.Hour {
		t.Errorf("default interval = %v, want 1h", got)
	}

	off := load(t, "    ManifestSync: false\n")
	if off.ManifestSync == nil || *off.ManifestSync {
		t.Fatalf("ManifestSync = %v, want false", off.ManifestSync)
	}
	if off.ManifestSyncEnabled() {
		t.Error("ManifestSync: false must disable the sync")
	}

	for _, tc := range []struct {
		sec  string
		want time.Duration
	}{
		{"1", 5 * time.Minute},
		{"300", 5 * time.Minute},
		{"7200", 2 * time.Hour},
		{"86400", 24 * time.Hour},
		{"100000", 24 * time.Hour},
	} {
		if got := load(t, "    ManifestIntervalSec: "+tc.sec+"\n").ManifestInterval(); got != tc.want {
			t.Errorf("ManifestIntervalSec %s = %v, want %v", tc.sec, got, tc.want)
		}
	}

	// A negative interval is a config error, not silently clamped.
	dir := t.TempDir()
	path := writeAgentConfig(t, dir, `    Enabled: true
    URL: https://panel.example.com
    MachineID: 7
    Token: t
    ManifestIntervalSec: -1
`)
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "ManifestIntervalSec") {
		t.Errorf("negative interval: err = %v", err)
	}
}

// TestCheckAgentPanelManifestSync checks the "check" report line.
func TestCheckAgentPanelManifestSync(t *testing.T) {
	pc := &AgentPanelConfig{Enabled: true, URL: "https://panel.example.com", MachineID: 7, Token: "t"}
	var w bytes.Buffer
	if err := checkAgentPanel(&w, pc); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(w.String(), "内核清单同步: 已启用") || !strings.Contains(w.String(), "1h0m0s") {
		t.Errorf("report:\n%s", w.String())
	}

	off := false
	pc.ManifestSync = &off
	w.Reset()
	if err := checkAgentPanel(&w, pc); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(w.String(), "已关闭") {
		t.Errorf("report:\n%s", w.String())
	}

	pc.ManifestSync = nil
	pc.ManifestIntervalSec = 60
	w.Reset()
	if err := checkAgentPanel(&w, pc); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(w.String(), "300–86400") {
		t.Errorf("the clamp is not reported:\n%s", w.String())
	}
}

// TestPanelLinkSyncsSignedManifest is the whole-stack proof: a panel serves a
// signed manifest, the agent verifies it locally and persists the accepted
// bytes under the state directory.
func TestPanelLinkSyncsSignedManifest(t *testing.T) {
	dir := t.TempDir()
	keysPath := filepath.Join(dir, "keys.txt")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keysPath, []byte(hex.EncodeToString(pub)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	arch := sha256.Sum256([]byte("archive"))
	bin := sha256.Sum256([]byte("binary"))
	now := time.Now()
	raw, err := manifest.Sign(&manifest.Manifest{
		Schema: manifest.SchemaVersion, Sequence: 3,
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
	}, priv)
	if err != nil {
		t.Fatal(err)
	}

	fp := newFakePanelServer(t)
	fp.mu.Lock()
	fp.manifest, fp.etag = string(raw), `"seq3"`
	fp.mu.Unlock()

	stateDir := filepath.Join(dir, "state")
	configPath := filepath.Join(dir, "config.yml")
	body := fmt.Sprintf(`Log: {Level: warning}
Agent:
  Enabled: true
  StateDir: %q
  ManifestKeysPath: %q
  Panel:
    Enabled: true
    URL: %s
    MachineID: 7
    Token: t
    ManifestIntervalSec: 300
`, stateDir, keysPath, fp.srv.URL)
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	p := New(configPath, cfg)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	persist := bootstrap.PersistedManifestPath(stateDir)
	deadline := time.Now().Add(30 * time.Second)
	for {
		got, err := os.ReadFile(persist)
		if err == nil {
			if !bytes.Equal(got, raw) {
				t.Fatalf("persisted manifest differs from what the panel served")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the signed manifest was not persisted: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if fp.count("manifest") == 0 {
		t.Error("the panel never served a manifest")
	}
}
