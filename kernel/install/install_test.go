package install

import (
	"archive/tar"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/kernel"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
)

func pin(name, ver string) spec.KernelPin { return spec.KernelPin{Name: name, Version: ver} }

// publish builds a kernel entry, serves its archive and returns the entry.
func publish(t *testing.T, f *fixture, fs *fileServer, k kern) manifest.Kernel {
	t.Helper()
	path := "/" + k.Name + "-" + k.Version + ".bin"
	if k.URLs == nil {
		k.URLs = []string{fs.URL + path}
	}
	mk, archive := f.build(k)
	fs.put(path, archive)
	return mk
}

func mustEnsure(t *testing.T, in *Installer, name, ver string) string {
	t.Helper()
	got, err := in.Ensure(context.Background(), pin(name, ver))
	if err != nil {
		t.Fatalf("Ensure(%s@%s): %v", name, ver, err)
	}
	if got.Version != manifest.NormalizeVersion(ver) {
		t.Fatalf("version %q want %q", got.Version, ver)
	}
	if _, err := os.Stat(got.Path); err != nil {
		t.Fatalf("binary missing: %v", err)
	}
	return got.Path
}

func currentOf(t *testing.T, in *Installer, name string) string {
	t.Helper()
	v, err := readPointer(in.curPath(name))
	if err != nil {
		return ""
	}
	return v
}

func TestEnsureTarGzAndZip(t *testing.T) {
	for _, format := range []string{manifest.ArchiveTarGz, manifest.ArchiveZip} {
		t.Run(format, func(t *testing.T) {
			f := newFixture(t)
			fs := newFileServer(t)
			k := publish(t, f, fs, kern{Name: "gost", Version: "3.3.0", Format: format})
			in := f.installer(t.TempDir())
			if err := in.LoadManifest(f.sign(k)); err != nil {
				t.Fatal(err)
			}
			path := mustEnsure(t, in, "gost", "v3.3.0") // "v" prefix from the panel is normalised
			if runtime.GOOS != "windows" {
				fi, _ := os.Stat(path)
				if fi.Mode().Perm() != 0o755 {
					t.Errorf("mode %v want 0755", fi.Mode().Perm())
				}
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(path), "README")); err == nil {
				t.Error("unlisted member README must not be extracted")
			}
			if cur := currentOf(t, in, "gost"); cur != "3.3.0" {
				t.Errorf("current=%q", cur)
			}
			if ents, _ := os.ReadDir(in.partialDir("gost")); len(ents) != 0 {
				t.Errorf(".partial not clean: %v", ents)
			}
			// Detect (offline)
			inst, err := in.Current("gost")
			if err != nil || inst.Path != path {
				t.Errorf("Current=%v,%v", inst, err)
			}
			// idempotent: no second download
			hits := fs.hitCount("/gost-3.3.0.bin")
			mustEnsure(t, in, "gost", "3.3.0")
			if fs.hitCount("/gost-3.3.0.bin") != hits {
				t.Error("second Ensure hit the network")
			}
		})
	}
}

func TestSecondInstallerSeesState(t *testing.T) {
	f := newFixture(t)
	fs := newFileServer(t)
	k := publish(t, f, fs, kern{Name: "gost", Version: "3.3.0"})
	dir := t.TempDir()
	in := f.installer(dir)
	if err := in.LoadManifest(f.sign(k)); err != nil {
		t.Fatal(err)
	}
	mustEnsure(t, in, "gost", "3.3.0")
	in2 := f.installer(dir) // restart: manifest and state are reloaded
	if in2.Manifest() == nil || in2.Manifest().Sequence != 1 {
		t.Fatalf("manifest not reloaded: %+v", in2.Manifest())
	}
	hits := fs.hitCount("/gost-3.3.0.bin")
	mustEnsure(t, in2, "gost", "3.3.0")
	if fs.hitCount("/gost-3.3.0.bin") != hits {
		t.Error("restart caused a re-download")
	}
}

func TestManifestAntiRollbackPersisted(t *testing.T) {
	f := newFixture(t)
	fs := newFileServer(t)
	k := publish(t, f, fs, kern{Name: "gost", Version: "3.3.0"})
	dir := t.TempDir()
	in := f.installer(dir)
	old := f.signSeq(4, f.clk.Now().Add(-time.Hour), f.clk.Now().Add(time.Hour*24), k)
	newer := f.signSeq(5, f.clk.Now().Add(-time.Hour), f.clk.Now().Add(time.Hour*24), k)
	if err := in.LoadManifest(newer); err != nil {
		t.Fatal(err)
	}
	if err := in.LoadManifest(old); !errors.Is(err, kernel.ErrStaleManifest) {
		t.Fatalf("want ErrStaleManifest, got %v", err)
	}
	// still enforced after a restart
	in2 := f.installer(dir)
	if err := in2.LoadManifest(old); !errors.Is(err, kernel.ErrStaleManifest) {
		t.Fatalf("after restart: want ErrStaleManifest, got %v", err)
	}
	if err := in2.LoadManifest(newer); err != nil { // same sequence again is fine
		t.Fatal(err)
	}
}

func TestExpiredManifest(t *testing.T) {
	f := newFixture(t)
	fs := newFileServer(t)
	k := publish(t, f, fs, kern{Name: "gost", Version: "3.3.0"})
	in := f.installer(t.TempDir())
	raw := f.signSeq(1, f.clk.Now().Add(-time.Hour), f.clk.Now().Add(time.Hour), k)
	if err := in.LoadManifest(raw); err != nil {
		t.Fatal(err)
	}
	f.clk.Add(2 * time.Hour) // manifest now stale
	if _, err := in.Ensure(context.Background(), pin("gost", "3.3.0")); !errors.Is(err, kernel.ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
	if err := in.LoadManifest(raw); !errors.Is(err, kernel.ErrExpired) {
		t.Fatalf("LoadManifest of expired: %v", err)
	}
}

func TestNoManifest(t *testing.T) {
	f := newFixture(t)
	in := f.installer(t.TempDir())
	if _, err := in.Ensure(context.Background(), pin("gost", "3.3.0")); !errors.Is(err, kernel.ErrNoManifest) {
		t.Fatalf("got %v", err)
	}
}

func TestTargetNullVsUnknown(t *testing.T) {
	f := newFixture(t)
	fs := newFileServer(t)
	k := publish(t, f, fs, kern{Name: "realm", Version: "2.9.6", Null: true})
	in := f.installer(t.TempDir())
	if err := in.LoadManifest(f.sign(k)); err != nil {
		t.Fatal(err)
	}
	_, err := in.Ensure(context.Background(), pin("realm", "2.9.6"))
	if !errors.Is(err, kernel.ErrUnavailable) || errors.Is(err, kernel.ErrUnknownKernel) {
		t.Fatalf("null target: want ErrUnavailable only, got %v", err)
	}
	if kernel.Code(err) != "unavailable" || !strings.Contains(err.Error(), "null") {
		t.Errorf("code=%s err=%v", kernel.Code(err), err)
	}
	_, err = in.Ensure(context.Background(), pin("realm", "9.9.9"))
	if !errors.Is(err, kernel.ErrUnknownKernel) || errors.Is(err, kernel.ErrUnavailable) {
		t.Fatalf("unknown version: want ErrUnknownKernel only, got %v", err)
	}
	_, err = in.Ensure(context.Background(), pin("nosuch", "1.0.0"))
	if !errors.Is(err, kernel.ErrUnknownKernel) {
		t.Fatalf("unknown kernel: %v", err)
	}
	cat, err := in.Catalog()
	if err != nil || len(cat) != 1 || cat[0].Available || cat[0].Code != "unavailable" {
		t.Fatalf("catalog=%+v err=%v", cat, err)
	}
}

func TestIncompatibleVariant(t *testing.T) {
	f := newFixture(t)
	f.plat.GOARCH, f.plat.Float = "mipsle", "softfloat"
	fs := newFileServer(t)
	k := publish(t, f, fs, kern{Name: "gost", Version: "3.3.0", Variant: "hardfloat"})
	in := f.installer(t.TempDir())
	if err := in.LoadManifest(f.sign(k)); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Ensure(context.Background(), pin("gost", "3.3.0")); !errors.Is(err, kernel.ErrUnavailable) {
		t.Fatalf("hardfloat on softfloat host: %v", err)
	}
}

func TestRevokedAndMinAgent(t *testing.T) {
	f := newFixture(t)
	fs := newFileServer(t)
	good := publish(t, f, fs, kern{Name: "gost", Version: "3.3.0"})
	bad := publish(t, f, fs, kern{Name: "gost", Version: "3.2.0"})
	// the newer entry revokes the older version
	good.Revoked = []manifest.Revocation{{Version: "3.2.0", Reason: "CVE-test"}}
	in := f.installer(t.TempDir(), func(c *Config) { c.AgentVersion = "0.3.0" })
	if err := in.LoadManifest(f.sign(good, bad)); err != nil {
		t.Fatal(err)
	}
	_, err := in.Ensure(context.Background(), pin("gost", "3.2.0"))
	if !errors.Is(err, kernel.ErrRevoked) || !strings.Contains(err.Error(), "CVE-test") {
		t.Fatalf("version revoke: %v", err)
	}
	mustEnsure(t, in, "gost", "3.3.0")

	// revoked by hash, even though already installed
	hash := good.Targets[f.plat.Key()].ArchiveSHA256
	good2 := good
	good2.Revoked = []manifest.Revocation{{SHA256: hash}}
	if err := in.LoadManifest(f.sign(good2, bad)); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Ensure(context.Background(), pin("gost", "3.3.0")); !errors.Is(err, kernel.ErrRevoked) {
		t.Fatalf("hash revoke of installed version: %v", err)
	}

	// min_agent
	newer := publish(t, f, fs, kern{Name: "gost", Version: "3.4.0", MinAgent: "0.5.0"})
	if err := in.LoadManifest(f.sign(newer)); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Ensure(context.Background(), pin("gost", "3.4.0")); !errors.Is(err, kernel.ErrAgentTooOld) {
		t.Fatalf("min_agent: %v", err)
	}
}

func TestHashMismatchRejectedAndBackoff(t *testing.T) {
	f := newFixture(t)
	fs := newFileServer(t)
	k := publish(t, f, fs, kern{Name: "gost", Version: "3.3.0"})
	// the server now serves different bytes of the very same length
	goodBlob := append([]byte(nil), fs.blobs["/gost-3.3.0.bin"]...)
	blob := append([]byte(nil), goodBlob...)
	blob[len(blob)/2] ^= 0xff
	fs.put("/gost-3.3.0.bin", blob)

	in := f.installer(t.TempDir(), func(c *Config) { c.BackoffBase = time.Minute; c.BackoffMax = 5 * time.Minute })
	if err := in.LoadManifest(f.sign(k)); err != nil {
		t.Fatal(err)
	}
	_, err := in.Ensure(context.Background(), pin("gost", "3.3.0"))
	if !errors.Is(err, kernel.ErrVerify) {
		t.Fatalf("want ErrVerify, got %v", err)
	}
	if currentOf(t, in, "gost") != "" {
		t.Error("must not be installed")
	}
	if _, err := os.Stat(filepath.Join(in.partialDir("gost"), k.Targets[f.plat.Key()].ArchiveSHA256+".part")); err == nil {
		t.Error("tampered partial file must be discarded")
	}
	hits := fs.hitCount("/gost-3.3.0.bin")
	// back-off: no further network access
	if _, err := in.Ensure(context.Background(), pin("gost", "3.3.0")); !errors.Is(err, kernel.ErrBackoff) {
		t.Fatalf("want ErrBackoff, got %v", err)
	}
	if fs.hitCount("/gost-3.3.0.bin") != hits {
		t.Error("back-off still hit the network")
	}
	// exponential: 1m, 2m, 4m, then capped at 5m
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	for i, w := range want {
		b := in.st.Bad["gost@3.3.0"]
		if b == nil || b.Fails != i+1 || b.Until.Sub(b.LastAt) != w {
			t.Fatalf("step %d: %+v want delay %v", i, b, w)
		}
		f.clk.Add(w + time.Second)
		if i < len(want)-1 {
			if _, err := in.Ensure(context.Background(), pin("gost", "3.3.0")); !errors.Is(err, kernel.ErrVerify) {
				t.Fatalf("retry %d: %v", i, err)
			}
		}
	}
	// the operator fixes the mirror; once the back-off passed, it installs
	fs.put("/gost-3.3.0.bin", goodBlob)
	mustEnsure(t, in, "gost", "3.3.0")
	if in.st.Bad["gost@3.3.0"] != nil {
		t.Error("failure record must be cleared after success")
	}
}

func TestBackoffClearedOnSuccess(t *testing.T) {
	f := newFixture(t)
	fs := newFileServer(t)
	k, archive := f.build(kern{Name: "gost", Version: "3.3.0", URLs: []string{fs.URL + "/a"}})
	fs.status["/a"] = 503
	in := f.installer(t.TempDir(), func(c *Config) { c.Retries = 1 })
	if err := in.LoadManifest(f.sign(k)); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Ensure(context.Background(), pin("gost", "3.3.0")); !errors.Is(err, kernel.ErrDownload) {
		t.Fatalf("want ErrDownload, got %v", err)
	}
	if _, err := in.Ensure(context.Background(), pin("gost", "3.3.0")); !errors.Is(err, kernel.ErrBackoff) {
		t.Fatalf("want ErrBackoff, got %v", err)
	}
	fs.mu.Lock()
	delete(fs.status, "/a")
	fs.mu.Unlock()
	fs.put("/a", archive)
	f.clk.Add(2 * time.Minute)
	mustEnsure(t, in, "gost", "3.3.0")
	if in.st.Bad["gost@3.3.0"] != nil {
		t.Error("failure record must be cleared after success")
	}
}

func TestMirrorFallback(t *testing.T) {
	f := newFixture(t)
	fs := newFileServer(t)
	k, archive := f.build(kern{Name: "gost", Version: "3.3.0"})
	tampered := append([]byte(nil), archive...)
	tampered[len(tampered)-5] ^= 0x55
	fs.put("/tampered", tampered)
	fs.put("/good", archive)
	fs.status["/down"] = 500
	k.Targets[f.plat.Key()].URLs = []string{fs.URL + "/missing", fs.URL + "/down", fs.URL + "/tampered", fs.URL + "/good"}
	in := f.installer(t.TempDir(), func(c *Config) { c.Retries = 2 })
	if err := in.LoadManifest(f.sign(k)); err != nil {
		t.Fatal(err)
	}
	mustEnsure(t, in, "gost", "3.3.0")
	if fs.hitCount("/tampered") != 1 || fs.hitCount("/good") != 1 {
		t.Errorf("tampered=%d good=%d", fs.hitCount("/tampered"), fs.hitCount("/good"))
	}
}

func TestAllMirrorsTampered(t *testing.T) {
	f := newFixture(t)
	fs := newFileServer(t)
	k, archive := f.build(kern{Name: "gost", Version: "3.3.0"})
	for _, p := range []string{"/m1", "/m2"} {
		bad := append([]byte(nil), archive...)
		bad[10] ^= 1
		fs.put(p, bad)
	}
	k.Targets[f.plat.Key()].URLs = []string{fs.URL + "/m1", fs.URL + "/m2"}
	in := f.installer(t.TempDir())
	if err := in.LoadManifest(f.sign(k)); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Ensure(context.Background(), pin("gost", "3.3.0")); !errors.Is(err, kernel.ErrVerify) {
		t.Fatalf("want ErrVerify, got %v", err)
	}
}

func TestPlainHTTPRefusedByDefault(t *testing.T) {
	f := newFixture(t)
	fs := newFileServer(t)
	k := publish(t, f, fs, kern{Name: "gost", Version: "3.3.0"})
	in := f.installer(t.TempDir(), func(c *Config) { c.AllowHTTP = false })
	if err := in.LoadManifest(f.sign(k)); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Ensure(context.Background(), pin("gost", "3.3.0")); !errors.Is(err, kernel.ErrDownload) {
		t.Fatalf("got %v", err)
	}
	if fs.hitCount("/gost-3.3.0.bin") != 0 {
		t.Error("http source was contacted")
	}
}

func TestRangeResumeAfterInterruption(t *testing.T) {
	f := newFixture(t)
	fs := newFileServer(t)
	k := publish(t, f, fs, kern{Name: "gost", Version: "3.3.0"})
	size := len(fs.blobs["/gost-3.3.0.bin"])
	fs.cutAfter["/gost-3.3.0.bin"] = size / 3
	in := f.installer(t.TempDir())
	if err := in.LoadManifest(f.sign(k)); err != nil {
		t.Fatal(err)
	}
	mustEnsure(t, in, "gost", "3.3.0")
	rs := fs.rangesOf("/gost-3.3.0.bin")
	if len(rs) != 1 || rs[0] != "bytes="+strconv.Itoa(size/3)+"-" {
		t.Fatalf("expected one resume request from %d, got %v (hits=%d)", size/3, rs, fs.hitCount("/gost-3.3.0.bin"))
	}
}

func TestResumeFromLeftoverPartialAndRangeIgnoredByServer(t *testing.T) {
	f := newFixture(t)
	fs := newFileServer(t)
	k := publish(t, f, fs, kern{Name: "gost", Version: "3.3.0"})
	blob := fs.blobs["/gost-3.3.0.bin"]
	in := f.installer(t.TempDir())
	if err := in.LoadManifest(f.sign(k)); err != nil {
		t.Fatal(err)
	}
	part := filepath.Join(in.partialDir("gost"), k.Targets[f.plat.Key()].ArchiveSHA256+".part")
	if err := os.MkdirAll(filepath.Dir(part), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(part, blob[:len(blob)/2], 0o600); err != nil { // crash leftovers
		t.Fatal(err)
	}
	mustEnsure(t, in, "gost", "3.3.0")
	if rs := fs.rangesOf("/gost-3.3.0.bin"); len(rs) != 1 || rs[0] != "bytes="+strconv.Itoa(len(blob)/2)+"-" {
		t.Fatalf("ranges=%v", rs)
	}

	// A server that ignores Range (answers 200 + full body) must also work.
	f2 := newFixture(t)
	fs2 := newFileServer(t)
	k2 := publish(t, f2, fs2, kern{Name: "gost", Version: "3.3.0"})
	fs2.ignoreRange["/gost-3.3.0.bin"] = true
	in2 := f2.installer(t.TempDir())
	if err := in2.LoadManifest(f2.sign(k2)); err != nil {
		t.Fatal(err)
	}
	part2 := filepath.Join(in2.partialDir("gost"), k2.Targets[f2.plat.Key()].ArchiveSHA256+".part")
	_ = os.MkdirAll(filepath.Dir(part2), 0o700)
	_ = os.WriteFile(part2, fs2.blobs["/gost-3.3.0.bin"][:100], 0o600)
	mustEnsure(t, in2, "gost", "3.3.0")
}

func TestNoSpaceKeepsOldVersion(t *testing.T) {
	f := newFixture(t)
	fs := newFileServer(t)
	v1 := publish(t, f, fs, kern{Name: "gost", Version: "3.2.0"})
	v2 := publish(t, f, fs, kern{Name: "gost", Version: "3.3.0"})
	in := f.installer(t.TempDir())
	if err := in.LoadManifest(f.sign(v1, v2)); err != nil {
		t.Fatal(err)
	}
	p1 := mustEnsure(t, in, "gost", "3.2.0")

	f.space = spaceMargin + 1024 // far less than archive + installed size
	_, err := in.Ensure(context.Background(), pin("gost", "3.3.0"))
	if !errors.Is(err, kernel.ErrNoSpace) {
		t.Fatalf("want ErrNoSpace, got %v", err)
	}
	for _, want := range []string{"--prefix", "extroot", "kept"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message lacks %q: %v", want, err)
		}
	}
	if fs.hitCount("/gost-3.3.0.bin") != 0 {
		t.Error("must not download when it cannot fit")
	}
	if _, err := os.Stat(p1); err != nil {
		t.Errorf("old version deleted: %v", err)
	}
	if currentOf(t, in, "gost") != "3.2.0" {
		t.Errorf("current changed to %q", currentOf(t, in, "gost"))
	}
	if in.st.Bad["gost@3.3.0"] != nil {
		t.Error("no-space must not be recorded as a bad version")
	}
	// after space is freed it just works
	f.space = 1 << 40
	mustEnsure(t, in, "gost", "3.3.0")
}

func TestArchiveHostility(t *testing.T) {
	bin := fakeBin("3.3.0", 2048)
	good := tarEntry{Name: "gost", Data: bin}
	big := make([]byte, 6<<20) // 6 MiB of zeros: tiny once gzipped
	cases := []struct {
		name    string
		format  string
		entries []tarEntry
		cfg     func(*Config)
		members map[string][]byte
		badSHA  bool
	}{
		{name: "dotdot-member", entries: []tarEntry{{Name: "../../evil", Data: []byte("x")}, good}},
		{name: "absolute-member", entries: []tarEntry{{Name: "/etc/passwd", Data: []byte("x")}, good}},
		{name: "listed-file-is-symlink", entries: []tarEntry{{Name: "gost", Type: tar.TypeSymlink, Link: "/bin/sh"}}},
		{name: "listed-file-is-hardlink", entries: []tarEntry{{Name: "gost", Type: tar.TypeLink, Link: "other"}}},
		{name: "duplicate-member", entries: []tarEntry{good, good}},
		{name: "decompression-bomb", entries: []tarEntry{{Name: "junk.bin", Data: big}, good}, cfg: func(c *Config) { c.MaxExtractBytes = 1 << 20 }},
		{name: "too-many-entries", entries: append(manyEntries(50), good), cfg: func(c *Config) { c.MaxEntries = 10 }},
		{name: "missing-listed-file", entries: []tarEntry{{Name: "README", Data: []byte("x")}}},
		{name: "content-differs-from-manifest", entries: []tarEntry{good}, badSHA: true},
		{name: "zip-dotdot", format: manifest.ArchiveZip, entries: []tarEntry{{Name: "../evil", Data: []byte("x")}, good}},
		{name: "zip-symlink", format: manifest.ArchiveZip, entries: []tarEntry{{Name: "gost", Type: tar.TypeSymlink, Link: "/bin/sh"}}},
		{name: "zip-bomb", format: manifest.ArchiveZip, entries: []tarEntry{{Name: "junk.bin", Data: big}, good}, cfg: func(c *Config) { c.MaxExtractBytes = 1 << 20 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			fs := newFileServer(t)
			var archive []byte
			if tc.format == manifest.ArchiveZip {
				archive = mkZip(t, tc.entries...)
			} else {
				archive = mkTarGz(t, tc.entries...)
			}
			k, _ := f.build(kern{Name: "gost", Version: "3.3.0", Format: orDefault(tc.format), Archive: archive,
				Members: map[string][]byte{"gost": bin}, URLs: []string{fs.URL + "/a"}, BadExtractSHA: tc.badSHA})
			fs.put("/a", archive)
			var mods []func(*Config)
			if tc.cfg != nil {
				mods = append(mods, tc.cfg)
			}
			in := f.installer(t.TempDir(), mods...)
			if err := in.LoadManifest(f.sign(k)); err != nil {
				t.Fatal(err)
			}
			_, err := in.Ensure(context.Background(), pin("gost", "3.3.0"))
			if !errors.Is(err, kernel.ErrVerify) {
				t.Fatalf("want ErrVerify, got %v", err)
			}
			t.Logf("rejected: %v", err)
			if want := hostileReasons[tc.name]; !strings.Contains(err.Error(), want) {
				t.Errorf("rejected for the wrong reason, want %q in: %v", want, err)
			}
			if currentOf(t, in, "gost") != "" {
				t.Error("installed despite rejection")
			}
			if _, err := os.Stat(in.verDir("gost", "3.3.0")); err == nil {
				t.Error("version directory exists after rejection")
			}
			// nothing may have been written outside the kernels tree
			if _, err := os.Stat(filepath.Join(filepath.Dir(in.cfg.Dir), "evil")); err == nil {
				t.Error("path traversal wrote a file")
			}
		})
	}
}

// hostileReasons pins each hostile archive to the check that must catch it.
var hostileReasons = map[string]string{
	"dotdot-member":                 "unsafe path",
	"absolute-member":               "unsafe path",
	"listed-file-is-symlink":        "links and special files are refused",
	"listed-file-is-hardlink":       "links and special files are refused",
	"duplicate-member":              "appears twice",
	"decompression-bomb":            "decompression bomb",
	"too-many-entries":              "more than 10 entries",
	"missing-listed-file":           "missing from archive",
	"content-differs-from-manifest": "does not match manifest",
	"zip-dotdot":                    "unsafe path",
	"zip-symlink":                   "links and special files are refused",
	"zip-bomb":                      "decompression bomb",
}

func orDefault(f string) string {
	if f == "" {
		return manifest.ArchiveTarGz
	}
	return f
}

func manyEntries(n int) []tarEntry {
	var es []tarEntry
	for i := 0; i < n; i++ {
		es = append(es, tarEntry{Name: "f" + strconv.Itoa(i), Data: []byte("x")})
	}
	return es
}

func TestSelfCheckFailureRollsBack(t *testing.T) {
	f := newFixture(t)
	fs := newFileServer(t)
	v1 := publish(t, f, fs, kern{Name: "gost", Version: "3.2.0"})
	// v2's binary claims to be 9.9.9
	liar := publish(t, f, fs, kern{Name: "gost", Version: "3.3.0",
		Members: map[string][]byte{"gost": fakeBin("9.9.9", 1024)}})
	in := f.installer(t.TempDir(), func(c *Config) { c.BackoffBase = time.Minute })
	if err := in.LoadManifest(f.sign(v1, liar)); err != nil {
		t.Fatal(err)
	}
	p1 := mustEnsure(t, in, "gost", "3.2.0")
	_, err := in.Ensure(context.Background(), pin("gost", "3.3.0"))
	if !errors.Is(err, kernel.ErrCheck) {
		t.Fatalf("want ErrCheck, got %v", err)
	}
	if currentOf(t, in, "gost") != "3.2.0" {
		t.Errorf("current=%q, old version must stay", currentOf(t, in, "gost"))
	}
	if _, err := os.Stat(p1); err != nil {
		t.Error("old binary gone")
	}
	if _, err := os.Stat(in.verDir("gost", "3.3.0")); err == nil {
		t.Error("failed version left on disk")
	}
	if b := in.st.Bad["gost@3.3.0"]; b == nil || b.Code != "check_failed" {
		t.Errorf("bad record: %+v", b)
	}
	if _, err := in.Ensure(context.Background(), pin("gost", "3.3.0")); !errors.Is(err, kernel.ErrBackoff) {
		t.Fatalf("want ErrBackoff, got %v", err)
	}
}

func TestPostSwitchCheckFailureReverts(t *testing.T) {
	f := newFixture(t)
	fs := newFileServer(t)
	v1 := publish(t, f, fs, kern{Name: "gost", Version: "3.2.0"})
	v2 := publish(t, f, fs, kern{Name: "gost", Version: "3.3.0"})
	// passes from the staging dir, fails from the final location
	check := func(p string) (string, error) {
		if !strings.Contains(p, ".partial") && strings.Contains(p, "3.3.0") {
			return "", errors.New("exec format error")
		}
		return fakeCheck(p)
	}
	in := f.installer(t.TempDir(), func(c *Config) { c.Check = check })
	if err := in.LoadManifest(f.sign(v1, v2)); err != nil {
		t.Fatal(err)
	}
	mustEnsure(t, in, "gost", "3.2.0")
	if _, err := in.Ensure(context.Background(), pin("gost", "3.3.0")); !errors.Is(err, kernel.ErrCheck) {
		t.Fatalf("want ErrCheck, got %v", err)
	}
	if currentOf(t, in, "gost") != "3.2.0" {
		t.Errorf("current=%q", currentOf(t, in, "gost"))
	}
	if _, err := os.Stat(in.verDir("gost", "3.3.0")); err == nil {
		t.Error("reverted version still on disk")
	}
	if p, _ := readPointer(in.prevPath("gost")); p != "" {
		t.Errorf("previous pointer = %q, want unset", p)
	}
}

func TestUpgradeKeepsPreviousAndPrunes(t *testing.T) {
	f := newFixture(t)
	fs := newFileServer(t)
	var ks []manifest.Kernel
	for _, v := range []string{"1.0.0", "1.1.0", "1.2.0"} {
		ks = append(ks, publish(t, f, fs, kern{Name: "gost", Version: v}))
	}
	in := f.installer(t.TempDir()) // Keep defaults to 2
	if err := in.LoadManifest(f.sign(ks...)); err != nil {
		t.Fatal(err)
	}
	mustEnsure(t, in, "gost", "1.0.0")
	f.clk.Add(time.Hour)
	mustEnsure(t, in, "gost", "1.1.0")
	if p, _ := readPointer(in.prevPath("gost")); p != "1.0.0" {
		t.Fatalf("previous=%q", p)
	}
	f.clk.Add(time.Hour)
	mustEnsure(t, in, "gost", "1.2.0")
	list, err := in.List()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range list {
		got = append(got, e.Version)
	}
	if strings.Join(got, ",") != "1.2.0,1.1.0" {
		t.Fatalf("after prune: %v (Keep=2 keeps current+previous)", got)
	}
	if !list[0].Current || !list[1].Previous {
		t.Errorf("flags: %+v", list)
	}

	// Keep=3 keeps all three
	in3 := f.installer(t.TempDir(), func(c *Config) { c.Keep = 3 })
	if err := in3.LoadManifest(f.sign(ks...)); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"1.0.0", "1.1.0", "1.2.0"} {
		f.clk.Add(time.Hour)
		mustEnsure(t, in3, "gost", v)
	}
	if l, _ := in3.List(); len(l) != 3 {
		t.Fatalf("Keep=3 kept %d versions", len(l))
	}
}

func TestRollbackRemove(t *testing.T) {
	f := newFixture(t)
	fs := newFileServer(t)
	v1 := publish(t, f, fs, kern{Name: "gost", Version: "3.2.0"})
	v2 := publish(t, f, fs, kern{Name: "gost", Version: "3.3.0"})
	in := f.installer(t.TempDir())
	if err := in.LoadManifest(f.sign(v1, v2)); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Rollback("gost"); !errors.Is(err, kernel.ErrNotInstalled) {
		t.Fatalf("rollback with nothing: %v", err)
	}
	mustEnsure(t, in, "gost", "3.2.0")
	mustEnsure(t, in, "gost", "3.3.0")
	got, err := in.Rollback("gost")
	if err != nil || got.Version != "3.2.0" {
		t.Fatalf("rollback: %+v %v", got, err)
	}
	if currentOf(t, in, "gost") != "3.2.0" {
		t.Fatal("current not switched")
	}
	// the version we left is bad: the same pin does not flip straight back
	if _, err := in.Ensure(context.Background(), pin("gost", "3.3.0")); !errors.Is(err, kernel.ErrBackoff) && currentOf(t, in, "gost") != "3.3.0" {
		t.Fatalf("unexpected: %v", err)
	}
	if err := in.Remove("gost", currentOf(t, in, "gost")); !errors.Is(err, kernel.ErrInUse) {
		t.Fatalf("remove current: %v", err)
	}
	if err := in.Remove("gost", "9.9.9"); !errors.Is(err, kernel.ErrNotInstalled) {
		t.Fatalf("remove unknown: %v", err)
	}
	other := "3.3.0"
	if currentOf(t, in, "gost") == "3.3.0" {
		other = "3.2.0"
	}
	if err := in.Remove("gost", other); err != nil {
		t.Fatalf("remove other: %v", err)
	}
	if err := in.Remove("gost", ""); err != nil {
		t.Fatalf("remove all: %v", err)
	}
	if _, err := in.Current("gost"); !errors.Is(err, kernel.ErrNotInstalled) {
		t.Fatalf("after remove: %v", err)
	}
	if err := in.Remove("../x", ""); err == nil {
		t.Fatal("path-like names must be refused")
	}
}

func TestImportOffline(t *testing.T) {
	f := newFixture(t)
	k, archive := f.build(kern{Name: "gost", Version: "3.3.0", URLs: []string{"http://127.0.0.1:1/never"}})
	in := f.installer(t.TempDir())
	apath := filepath.Join(t.TempDir(), "gost_3.3.0.tar.gz")
	if err := os.WriteFile(apath, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Import(context.Background(), apath); !errors.Is(err, kernel.ErrNoManifest) {
		t.Fatalf("without manifest: %v", err)
	}
	if err := in.LoadManifest(f.sign(k)); err != nil {
		t.Fatal(err)
	}
	got, err := in.Import(context.Background(), apath)
	if err != nil || got.Version != "3.3.0" {
		t.Fatalf("import: %+v %v", got, err)
	}
	if currentOf(t, in, "gost") != "3.3.0" {
		t.Error("not current")
	}
	if _, err := os.Stat(apath); err != nil {
		t.Error("imported archive must be left in place")
	}
	// a tampered copy (same name) matches no manifest hash
	bad := append([]byte(nil), archive...)
	bad[20] ^= 1
	bpath := filepath.Join(t.TempDir(), "evil.tar.gz")
	_ = os.WriteFile(bpath, bad, 0o600)
	if _, err := in.Import(context.Background(), bpath); !errors.Is(err, kernel.ErrVerify) {
		t.Fatalf("tampered import: %v", err)
	}
	// an archive for another platform's target is not accepted either
	other := mkTarGz(t, tarEntry{Name: "gost", Data: fakeBin("3.3.0", 10)})
	opath := filepath.Join(t.TempDir(), "other.tar.gz")
	_ = os.WriteFile(opath, other, 0o600)
	if _, err := in.Import(context.Background(), opath); !errors.Is(err, kernel.ErrVerify) {
		t.Fatalf("foreign import: %v", err)
	}
}

func TestVerifyInstalledDetectsTamper(t *testing.T) {
	f := newFixture(t)
	fs := newFileServer(t)
	k := publish(t, f, fs, kern{Name: "gost", Version: "3.3.0"})
	in := f.installer(t.TempDir())
	if err := in.LoadManifest(f.sign(k)); err != nil {
		t.Fatal(err)
	}
	p := mustEnsure(t, in, "gost", "3.3.0")
	if err := in.VerifyInstalled("gost", "3.3.0"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	b[len(b)-1] ^= 1 // same size, different content
	if err := os.WriteFile(p, b, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := in.VerifyInstalled("gost", "3.3.0"); !errors.Is(err, kernel.ErrVerify) {
		t.Fatalf("got %v", err)
	}
}

func TestContextCancelNotRecordedAsFailure(t *testing.T) {
	f := newFixture(t)
	fs := newFileServer(t)
	k := publish(t, f, fs, kern{Name: "gost", Version: "3.3.0"})
	in := f.installer(t.TempDir())
	if err := in.LoadManifest(f.sign(k)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := in.Ensure(ctx, pin("gost", "3.3.0")); err == nil {
		t.Fatal("expected error")
	}
	if len(in.st.Bad) != 0 {
		t.Errorf("cancellation recorded as bad: %+v", in.st.Bad)
	}
}

func TestPointerRoundTripAndValidation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "current")
	if err := writePointer(p, "1.2.3"); err != nil {
		t.Fatal(err)
	}
	if v, err := readPointer(p); err != nil || v != "1.2.3" {
		t.Fatalf("%q %v", v, err)
	}
	if err := writePointer(p, "1.2.4"); err != nil { // replaces atomically
		t.Fatal(err)
	}
	if v, _ := readPointer(p); v != "1.2.4" {
		t.Fatalf("not replaced: %q", v)
	}
	// text-file form (Windows / vfat) is understood on every OS
	tp := filepath.Join(dir, "textptr")
	_ = os.WriteFile(tp, []byte("2.0.0\n"), 0o600)
	if v, err := readPointer(tp); err != nil || v != "2.0.0" {
		t.Fatalf("%q %v", v, err)
	}
	for _, evil := range []string{"../../etc", "a/b", "", ".hidden", "x\x00y"} {
		_ = os.WriteFile(tp, []byte(evil), 0o600)
		if _, err := readPointer(tp); err == nil {
			t.Errorf("pointer content %q accepted", evil)
		}
	}
}

func TestLayoutModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	f := newFixture(t)
	fs := newFileServer(t)
	k := publish(t, f, fs, kern{Name: "gost", Version: "3.3.0"})
	in := f.installer(t.TempDir())
	if err := in.LoadManifest(f.sign(k)); err != nil {
		t.Fatal(err)
	}
	mustEnsure(t, in, "gost", "3.3.0")
	check := func(p string, want os.FileMode) {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s: %v want %v", p, fi.Mode().Perm(), want)
		}
	}
	check(in.root, 0o755)
	check(in.statePath(), 0o600)
	check(in.manifestPath(), 0o600)
	check(filepath.Join(in.verDir("gost", "3.3.0"), ".installed.json"), 0o600)
	check(in.partialDir("gost"), 0o700)
}
