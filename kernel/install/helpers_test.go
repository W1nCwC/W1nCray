package install

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/kernel/manifest"
	"github.com/W1nCwC/W1nCray/kernel/platform"
)

// ---- archives ---------------------------------------------------------------

type tarEntry struct {
	Name string
	Data []byte
	Type byte // 0 = regular
	Link string
}

func mkTarGz(t testing.TB, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		typ := e.Type
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{Name: e.Name, Typeflag: typ, Mode: 0o644, Linkname: e.Link}
		if typ == tar.TypeReg {
			hdr.Size = int64(len(e.Data))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write(e.Data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func mkZip(t testing.TB, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		hdr := &zip.FileHeader{Name: e.Name, Method: zip.Deflate}
		if e.Type == tar.TypeSymlink {
			hdr.SetMode(os.ModeSymlink | 0o777)
		} else {
			hdr.SetMode(0o644)
		}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatal(err)
		}
		data := e.Data
		if e.Type == tar.TypeSymlink {
			data = []byte(e.Link)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// mkGz is a raw gzip stream: exactly one file, no member name. It is the shape
// release/build.sh produces (dist/W1nCray-linux-<arch>.gz).
func mkGz(t testing.TB, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// fakeBin is a stand-in executable whose "version" the test Check reads.
func fakeBin(version string, pad int) []byte {
	return append([]byte("#!/bin/sh\n# FAKEKERNEL version="+version+"\n"), bytes.Repeat([]byte("x"), pad)...)
}

var reFake = regexp.MustCompile(`FAKEKERNEL version=(\S+)`)

func fakeCheck(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	m := reFake.FindSubmatch(b)
	if m == nil {
		return "", io.ErrUnexpectedEOF
	}
	return string(m[1]), nil
}

// ---- manifest fixture ----------------------------------------------------------

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type fixture struct {
	t     *testing.T
	pub   ed25519.PublicKey
	priv  ed25519.PrivateKey
	keys  []manifest.Key
	clk   *clock
	plat  platform.Info
	seq   int64
	space uint64
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	return &fixture{
		t: t, pub: pub, priv: priv,
		keys:  []manifest.Key{manifest.NewKey(pub2), manifest.NewKey(pub)},
		clk:   &clock{t: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)},
		plat:  platform.Info{GOOS: "linux", GOARCH: "amd64", Libc: "glibc"},
		seq:   1,
		space: 1 << 40,
	}
}

func (f *fixture) installer(dir string, mod ...func(*Config)) *Installer {
	f.t.Helper()
	cfg := Config{
		Dir: dir, Keys: f.keys, Platform: &f.plat, AllowHTTP: true, Check: fakeCheck,
		FreeSpace:  func(string) (uint64, bool) { return f.space, true },
		Now:        f.clk.Now,
		RetryDelay: time.Millisecond, StallTimeout: 5 * time.Second,
	}
	for _, m := range mod {
		m(&cfg)
	}
	in, err := New(cfg)
	if err != nil {
		f.t.Fatal(err)
	}
	return in
}

// kern describes one kernel entry to put in a manifest.
type kern struct {
	Name, Version string
	Format        string // tar.gz (default) | zip
	Archive       []byte // the archive served
	Members       map[string][]byte
	Extract       map[string]string // member -> to
	RunBinary     string            // manifest run.binary; "gost" when empty
	URLs          []string
	Variant       string
	Null          bool // target null for the fixture platform
	MinAgent      string
	Revoked       []manifest.Revocation
	BadExtractSHA bool
	Mode          string
}

// build creates the archive (if Archive is nil) and the manifest entry.
func (f *fixture) build(k kern) (manifest.Kernel, []byte) {
	f.t.Helper()
	if k.Format == "" {
		k.Format = manifest.ArchiveTarGz
	}
	if k.Members == nil {
		k.Members = map[string][]byte{"gost": fakeBin(k.Version, 4096), "README": []byte("hi")}
	}
	if k.Extract == nil {
		k.Extract = map[string]string{"gost": "gost"}
	}
	if k.Mode == "" {
		k.Mode = "0755"
	}
	if k.RunBinary == "" {
		k.RunBinary = "gost"
	}
	archive := k.Archive
	if archive == nil {
		if k.Format == manifest.ArchiveGz {
			// A raw gzip stream holds one file; the single extract member names it.
			var data []byte
			for member := range k.Extract {
				data = k.Members[member]
			}
			archive = mkGz(f.t, data)
		} else {
			var es []tarEntry
			for n, d := range k.Members {
				es = append(es, tarEntry{Name: n, Data: d})
			}
			if k.Format == manifest.ArchiveZip {
				archive = mkZip(f.t, es...)
			} else {
				archive = mkTarGz(f.t, es...)
			}
		}
	}
	mk := manifest.Kernel{
		Name: k.Name, Version: k.Version, Channel: "stable", MinAgent: k.MinAgent,
		License: manifest.License{SPDX: "MIT", SourceURL: "https://example.com/src"},
		Run:     manifest.Run{Binary: k.RunBinary, VersionCmd: []string{"-V"}},
		Targets: map[string]*manifest.Target{},
		Revoked: k.Revoked,
	}
	key := f.plat.Key()
	if k.Null {
		mk.Targets[key] = nil
		mk.Targets["linux/arm64"] = f.target(k, archive) // some other target exists
		return mk, archive
	}
	mk.Targets[key] = f.target(k, archive)
	return mk, archive
}

func (f *fixture) target(k kern, archive []byte) *manifest.Target {
	t := &manifest.Target{
		Variant: k.Variant, URLs: k.URLs, Archive: k.Format,
		ArchiveSHA256: sum(archive), ArchiveSize: int64(len(archive)),
	}
	if len(t.URLs) == 0 {
		t.URLs = []string{"http://127.0.0.1:1/unused"}
	}
	for member, to := range k.Extract {
		data := k.Members[member]
		s := sum(data)
		if k.BadExtractSHA {
			s = sum([]byte("not it"))
		}
		t.Extract = append(t.Extract, manifest.Extract{From: member, To: to, SHA256: s, Size: int64(len(data)), Mode: k.Mode})
	}
	return t
}

// sign makes a signed manifest document with the next sequence number.
func (f *fixture) sign(kernels ...manifest.Kernel) []byte {
	f.t.Helper()
	raw := f.signSeq(f.seq, f.clk.Now().Add(-time.Hour), f.clk.Now().Add(30*24*time.Hour), kernels...)
	f.seq++
	return raw
}

func (f *fixture) signSeq(seq int64, issued, expires time.Time, kernels ...manifest.Kernel) []byte {
	f.t.Helper()
	m := &manifest.Manifest{Schema: manifest.SchemaVersion, Sequence: seq, IssuedAt: issued, ExpiresAt: expires, Kernels: kernels}
	raw, err := manifest.Sign(m, f.priv)
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

// ---- HTTP server -----------------------------------------------------------------

type fileServer struct {
	*httptest.Server
	mu          sync.Mutex
	blobs       map[string][]byte
	hits        map[string]int
	ranges      map[string][]string
	cutAfter    map[string]int  // first request is cut after N bytes
	ignoreRange map[string]bool // answer 200 + full body even to Range
	status      map[string]int  // forced status
}

func newFileServer(t *testing.T) *fileServer {
	fs := &fileServer{blobs: map[string][]byte{}, hits: map[string]int{}, ranges: map[string][]string{},
		cutAfter: map[string]int{}, ignoreRange: map[string]bool{}, status: map[string]int{}}
	fs.Server = httptest.NewUnstartedServer(http.HandlerFunc(fs.handle))
	fs.Config.ErrorLog = log.New(io.Discard, "", 0)
	fs.Start()
	t.Cleanup(fs.Close)
	return fs
}

func (fs *fileServer) handle(w http.ResponseWriter, r *http.Request) {
	fs.mu.Lock()
	p := r.URL.Path
	fs.hits[p]++
	n := fs.hits[p]
	if rg := r.Header.Get("Range"); rg != "" {
		fs.ranges[p] = append(fs.ranges[p], rg)
	}
	blob, ok := fs.blobs[p]
	cut := fs.cutAfter[p]
	ign := fs.ignoreRange[p]
	st := fs.status[p]
	fs.mu.Unlock()
	if st != 0 {
		http.Error(w, "forced", st)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	if cut > 0 && n == 1 {
		w.Header().Set("Content-Length", strconv.Itoa(len(blob)))
		w.WriteHeader(200)
		_, _ = w.Write(blob[:cut])
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}
	if ign {
		r.Header.Del("Range")
	}
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(blob))
}

func (fs *fileServer) put(path string, b []byte) string {
	fs.mu.Lock()
	fs.blobs[path] = b
	fs.mu.Unlock()
	return fs.URL + path
}

func (fs *fileServer) hitCount(path string) int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.hits[path]
}

func (fs *fileServer) rangesOf(path string) []string {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return append([]string(nil), fs.ranges[path]...)
}
