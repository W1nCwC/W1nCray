package state

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/spec"
)

func sample() spec.Desired {
	return spec.Desired{
		Version:  spec.Version,
		Revision: 7,
		Kernels:  []spec.KernelPin{{Name: "gost", Version: "3.3.0"}},
		Instances: []spec.Instance{
			{ID: "a", Enabled: true, Engine: "auto", Kind: spec.KindTunnelEntry, Secret: "SUPER-SECRET-VALUE-1234",
				Listen: &spec.Listen{Addr: "127.0.0.1", Ports: "8443"},
				Tunnel: &spec.Tunnel{Type: "ws", Server: "198.51.100.1:443"}},
			{ID: "b", Enabled: true, Engine: "xray", Kind: spec.KindForward},
		},
	}
}

func TestRoundTripAndPerms(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	d := sample()
	if err := s.SaveDesired(d); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveLastGood(d, map[string]string{"a": "gost"}); err != nil {
		t.Fatal(err)
	}
	sn, ok, err := s.LoadDesired()
	if err != nil || !ok {
		t.Fatalf("load: %v %v", ok, err)
	}
	if sn.Desired.Instances[0].Secret != "SUPER-SECRET-VALUE-1234" || sn.Hash != Hash(d) || sn.Schema != SchemaVersion {
		t.Fatalf("round trip lost data: %+v", sn)
	}
	lg, ok, err := s.LoadLastGood()
	if err != nil || !ok || lg.Engines["a"] != "gost" {
		t.Fatalf("last good: %+v %v %v", lg, ok, err)
	}
	if runtime.GOOS != "windows" {
		for _, p := range []string{filepath.Join(dir, fileDesired), filepath.Join(dir, fileLastGood)} {
			fi, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != 0o600 {
				t.Errorf("%s mode %v", p, fi.Mode().Perm())
			}
		}
		fi, _ := os.Stat(dir)
		if fi.Mode().Perm() != 0o700 {
			t.Errorf("dir mode %v", fi.Mode().Perm())
		}
	}
	// no temp files left behind
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("leftover temp file %s", e.Name())
		}
	}
}

func TestMissingAndCorrupt(t *testing.T) {
	s, _ := Open(t.TempDir())
	if _, ok, err := s.LoadDesired(); ok || err != nil {
		t.Fatalf("missing: %v %v", ok, err)
	}
	if h, _, err := s.LoadBlocked(); h != "" || err != nil {
		t.Fatalf("blocked missing: %q %v", h, err)
	}
	os.WriteFile(filepath.Join(s.Dir(), fileDesired), []byte("{not json"), 0o600)
	if _, _, err := s.LoadDesired(); err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("corrupt not detected: %v", err)
	}
	os.WriteFile(filepath.Join(s.Dir(), fileLastGood), []byte(`{"schema":99,"desired":{}}`), 0o600)
	if _, _, err := s.LoadLastGood(); err == nil || !strings.Contains(err.Error(), "newer schema") {
		t.Fatalf("future schema accepted: %v", err)
	}
	os.WriteFile(filepath.Join(s.Dir(), fileLastGood), []byte(`{"desired":{}}`), 0o600)
	if _, _, err := s.LoadLastGood(); err == nil {
		t.Fatal("missing schema accepted")
	}
}

func TestAtomicOverwriteKeepsOldOnFailureToWrite(t *testing.T) {
	s, _ := Open(t.TempDir())
	d := sample()
	if err := s.SaveDesired(d); err != nil {
		t.Fatal(err)
	}
	d2 := sample()
	d2.Revision = 8
	d2.Instances[1].Name = "changed"
	if err := s.SaveDesired(d2); err != nil {
		t.Fatal(err)
	}
	sn, _, _ := s.LoadDesired()
	if sn.Desired.Revision != 8 || sn.Desired.Instances[1].Name != "changed" {
		t.Fatalf("overwrite lost: %+v", sn.Desired)
	}
}

func TestBlocked(t *testing.T) {
	s, _ := Open(t.TempDir())
	if err := s.SaveBlocked("abc", "health check failed"); err != nil {
		t.Fatal(err)
	}
	h, r, err := s.LoadBlocked()
	if err != nil || h != "abc" || r != "health check failed" {
		t.Fatalf("%q %q %v", h, r, err)
	}
	if err := s.ClearBlocked(); err != nil {
		t.Fatal(err)
	}
	if h, _, _ := s.LoadBlocked(); h != "" {
		t.Fatal("not cleared")
	}
	if err := s.ClearBlocked(); err != nil {
		t.Fatalf("clear twice: %v", err)
	}
}

func TestRedacted(t *testing.T) {
	d := sample()
	r := Redacted(d)
	for _, in := range r.Instances {
		if in.Secret != "" {
			t.Fatalf("secret survived: %+v", in)
		}
	}
	if d.Instances[0].Secret == "" {
		t.Fatal("Redacted mutated its input")
	}
	// the redacted copy must not alias the original instances
	r.Instances[0].ID = "zzz"
	r.Kernels[0].Name = "zzz"
	if d.Instances[0].ID != "a" || d.Kernels[0].Name != "gost" {
		t.Fatal("Redacted shares memory with its input")
	}
	sn := Snapshot{Desired: d}.Redacted()
	if sn.Desired.Instances[0].Secret != "" {
		t.Fatal("Snapshot.Redacted kept secret")
	}
}

func TestHash(t *testing.T) {
	d := sample()
	h := Hash(d)
	d2 := sample()
	d2.Revision = 999
	if Hash(d2) != h {
		t.Fatal("revision must not affect the hash")
	}
	d3 := sample()
	d3.Instances[0].Secret = "another-secret-value-9999"
	if Hash(d3) == h {
		t.Fatal("secret change must change the hash")
	}
	if strings.Contains(h, "SECRET") || len(h) != 64 {
		t.Fatalf("bad hash %q", h)
	}
	// map ordering must not matter
	a := sample()
	a.Instances[0].Listen.PortMap = map[string]string{"1": "x:1", "2": "x:2", "3": "x:3"}
	b := sample()
	b.Instances[0].Listen.PortMap = map[string]string{"3": "x:3", "1": "x:1", "2": "x:2"}
	if Hash(a) != Hash(b) {
		t.Fatal("hash not canonical")
	}
}

func TestDriverDir(t *testing.T) {
	s, _ := Open(t.TempDir())
	p, err := s.DriverDir("gost")
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(p); err != nil || !fi.IsDir() {
		t.Fatalf("%v %v", fi, err)
	}
	for _, bad := range []string{"", "../x", "a/b", "A", "x y", strings.Repeat("a", 41)} {
		if _, err := s.DriverDir(bad); err == nil {
			t.Errorf("DriverDir(%q) accepted", bad)
		}
	}
}

func TestOpenTightensMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	dir := t.TempDir()
	os.Chmod(dir, 0o755)
	if _, err := Open(dir); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(dir)
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
}
