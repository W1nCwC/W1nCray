package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/kernel"
	"github.com/W1nCwC/W1nCray/kernel/install"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
	"github.com/W1nCwC/W1nCray/kernel/netutil"
	"github.com/W1nCwC/W1nCray/kernel/platform"
)

func hsum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func tgz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for n, d := range files {
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(d)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write(d)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func zipOf(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for n, d := range files {
		w, _ := zw.Create(n)
		w.Write(d)
	}
	zw.Close()
	return buf.Bytes()
}

// fakeGH serves one release "o/r" tag v1.0.0 and its assets.
type fakeGH struct {
	*httptest.Server
	assets   map[string][]byte
	digest   map[string]string // overrides (to inject lies)
	noDigest bool
	extra    map[string][]byte // served but listed without digest handling
}

func newFakeGH(t *testing.T, assets map[string][]byte) *fakeGH {
	g := &fakeGH{assets: assets, digest: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r/releases/tags/v1.0.0", func(w http.ResponseWriter, r *http.Request) {
		type a struct {
			Name   string `json:"name"`
			Size   int64  `json:"size"`
			Digest string `json:"digest,omitempty"`
			URL    string `json:"browser_download_url"`
		}
		var list []a
		for n, b := range g.assets {
			d := "sha256:" + hsum(b)
			if v, ok := g.digest[n]; ok {
				d = v
			}
			if g.noDigest {
				d = ""
			}
			list = append(list, a{Name: n, Size: int64(len(b)), Digest: d, URL: g.URL + "/dl/" + n})
		}
		json.NewEncoder(w).Encode(map[string]any{"tag_name": "v1.0.0", "assets": list})
	})
	mux.HandleFunc("/dl/", func(w http.ResponseWriter, r *http.Request) {
		b, ok := g.assets[strings.TrimPrefix(r.URL.Path, "/dl/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	})
	g.Server = httptest.NewServer(mux)
	t.Cleanup(g.Close)
	return g
}

func (g *fakeGH) build(t *testing.T, cfgYAML string) (*manifest.Manifest, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(p, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	return Build(context.Background(), buildOptions{
		Cfg: cfg, GH: &github{api: g.URL, client: netutil.NewClient()}, Cache: t.TempDir(),
		Now: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC), Log: func(string, ...any) {},
	})
}

const gostCfg = `
sequence: 3
valid_days: 30
mirrors: ["https://mirror.example/kernels/{name}/{version}/{asset}"]
kernels:
  - name: gost
    version: "1.0.0"
    repo: o/r
    license: {spdx: MIT}
    run: {binary: gost, version_cmd: ["-V"]}
    %s
    extract: [{from: gost, to: gost}]
    targets:
      linux/amd64: {asset: gost_1.0.0_linux_amd64.tar.gz}
      linux/riscv64: null
      linux/mipsle: {asset: gost_1.0.0_linux_mipsle.tar.gz, variant: softfloat}
`

func gostAssets(t *testing.T) map[string][]byte {
	bin := []byte("#!fake\n# FAKEKERNEL version=1.0.0\n")
	arch := tgz(t, map[string][]byte{"gost": bin, "README.md": []byte("readme")})
	mips := tgz(t, map[string][]byte{"gost": append(bin, 'm')})
	sums := fmt.Sprintf("%s  gost_1.0.0_linux_amd64.tar.gz\n%s  gost_1.0.0_linux_mipsle.tar.gz\n", hsum(arch), hsum(mips))
	return map[string][]byte{
		"gost_1.0.0_linux_amd64.tar.gz":  arch,
		"gost_1.0.0_linux_mipsle.tar.gz": mips,
		"checksums.txt":                  []byte(sums),
	}
}

func TestBuildCrossChecksAndExtractHashes(t *testing.T) {
	assets := gostAssets(t)
	g := newFakeGH(t, assets)
	m, err := g.build(t, fmt.Sprintf(gostCfg, "checksums: {asset: checksums.txt}"))
	if err != nil {
		t.Fatal(err)
	}
	k := m.Kernels[0]
	amd := k.Targets["linux/amd64"]
	if amd == nil || amd.ArchiveSHA256 != hsum(assets["gost_1.0.0_linux_amd64.tar.gz"]) || amd.ArchiveSize != int64(len(assets["gost_1.0.0_linux_amd64.tar.gz"])) {
		t.Fatalf("archive fields: %+v", amd)
	}
	if len(amd.Extract) != 1 || amd.Extract[0].SHA256 != hsum([]byte("#!fake\n# FAKEKERNEL version=1.0.0\n")) || amd.Extract[0].Mode != "0755" {
		t.Fatalf("extract: %+v", amd.Extract)
	}
	if amd.URLs[0] != "https://mirror.example/kernels/gost/1.0.0/gost_1.0.0_linux_amd64.tar.gz" || !strings.HasSuffix(amd.URLs[1], "/dl/gost_1.0.0_linux_amd64.tar.gz") {
		t.Fatalf("urls (mirror first, upstream last): %v", amd.URLs)
	}
	if tg, st := k.Lookup("linux/riscv64"); tg != nil || st != manifest.TargetNull {
		t.Fatalf("riscv64 must be an explicit null")
	}
	if k.Targets["linux/mipsle"].Variant != "softfloat" {
		t.Error("variant lost")
	}
	if m.Sequence != 3 || m.ExpiresAt.Sub(m.IssuedAt) != 30*24*time.Hour {
		t.Errorf("seq/validity: %d %v", m.Sequence, m.ExpiresAt.Sub(m.IssuedAt))
	}
}

func TestBuildRefusesDisagreement(t *testing.T) {
	cases := map[string]func(*fakeGH){
		"digest lies": func(g *fakeGH) {
			g.digest["gost_1.0.0_linux_amd64.tar.gz"] = "sha256:" + strings.Repeat("0", 64)
		},
		"checksums file lies": func(g *fakeGH) {
			g.assets["checksums.txt"] = []byte(strings.Repeat("a", 64) + "  gost_1.0.0_linux_amd64.tar.gz\n" +
				strings.Repeat("b", 64) + "  gost_1.0.0_linux_mipsle.tar.gz\n")
			delete(g.digest, "checksums.txt")
		},
		"checksum entry missing": func(g *fakeGH) {
			g.assets["checksums.txt"] = []byte(strings.Repeat("a", 64) + "  other.tar.gz\n")
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			g := newFakeGH(t, gostAssets(t))
			mut(g)
			_, err := g.build(t, fmt.Sprintf(gostCfg, "checksums: {asset: checksums.txt}"))
			if err == nil {
				t.Fatal("build accepted inconsistent hashes")
			}
			t.Logf("refused: %v", err)
		})
	}
}

func TestBuildMismatchMessageNamesSources(t *testing.T) {
	g := newFakeGH(t, gostAssets(t))
	g.digest["gost_1.0.0_linux_amd64.tar.gz"] = "sha256:" + strings.Repeat("0", 64)
	_, err := g.build(t, fmt.Sprintf(gostCfg, "checksums: {asset: checksums.txt}"))
	if err == nil || !strings.Contains(err.Error(), "HASH MISMATCH") || !strings.Contains(err.Error(), "asset.digest") {
		t.Fatalf("%v", err)
	}
}

func TestBuildNeedsAnUpstreamHash(t *testing.T) {
	g := newFakeGH(t, gostAssets(t))
	g.noDigest = true
	if _, err := g.build(t, fmt.Sprintf(gostCfg, "")); err == nil || !strings.Contains(err.Error(), "no upstream hash") {
		t.Fatalf("a bare download must not be trusted: %v", err)
	}
	// with the checksum file as the only upstream source it is fine
	if _, err := g.build(t, fmt.Sprintf(gostCfg, "checksums: {asset: checksums.txt}")); err != nil {
		t.Fatal(err)
	}
}

func TestBuildMissingAssetOrMember(t *testing.T) {
	g := newFakeGH(t, gostAssets(t))
	cfg := strings.Replace(fmt.Sprintf(gostCfg, "checksums: {asset: checksums.txt}"), "gost_1.0.0_linux_amd64.tar.gz", "nope.tar.gz", 1)
	if _, err := g.build(t, cfg); err == nil || !strings.Contains(err.Error(), "not in release") {
		t.Fatalf("missing asset: %v", err)
	}
	cfg = strings.Replace(fmt.Sprintf(gostCfg, "checksums: {asset: checksums.txt}"), "from: gost,", "from: gostx,", 1)
	if _, err := g.build(t, cfg); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing member: %v", err)
	}
}

func TestBuildXrayStyleDgstZipSoftfloatMember(t *testing.T) {
	zipB := zipOf(t, map[string][]byte{"xray": []byte("hard"), "xray_softfloat": []byte("soft"), "geoip.dat": []byte("geo")})
	g := newFakeGH(t, map[string][]byte{
		"Xray-linux-mips32.zip":      zipB,
		"Xray-linux-mips32.zip.dgst": []byte("MD5= 00\nSHA2-256= " + hsum(zipB) + "\nSHA2-512= 00\n"),
	})
	cfg := `
sequence: 1
kernels:
  - name: xray
    version: "1.0.0"
    repo: o/r
    license: {spdx: MPL-2.0}
    run: {binary: xray, version_cmd: [version]}
    checksums: {dgst: true}
    extract: [{from: xray, to: xray}]
    targets:
      linux/mips: {asset: Xray-linux-mips32.zip, variant: softfloat, extract: [{from: xray_softfloat, to: xray}]}
`
	m, err := g.build(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	e := m.Kernels[0].Targets["linux/mips"].Extract[0]
	if e.From != "xray_softfloat" || e.To != "xray" || e.SHA256 != hsum([]byte("soft")) {
		t.Fatalf("must pick the softfloat binary: %+v", e)
	}
	// a lying .dgst is caught
	g.assets["Xray-linux-mips32.zip.dgst"] = []byte("SHA2-256= " + strings.Repeat("1", 64) + "\n")
	if _, err := g.build(t, cfg); err == nil {
		t.Fatal(".dgst mismatch accepted")
	}
}

func TestBuildAssetBaseTemplate(t *testing.T) {
	arch := tgz(t, map[string][]byte{"frp_1.0.0_linux_amd64/frpc": []byte("c"), "frp_1.0.0_linux_amd64/frps": []byte("s")})
	g := newFakeGH(t, map[string][]byte{"frp_1.0.0_linux_amd64.tar.gz": arch})
	m, err := g.build(t, `
sequence: 1
kernels:
  - name: frp
    version: "1.0.0"
    repo: o/r
    license: {spdx: Apache-2.0}
    run: {binary: frpc, version_cmd: ["-v"]}
    extract: [{from: "{asset_base}/frpc", to: frpc}, {from: "{asset_base}/frps", to: frps}]
    targets:
      linux/amd64: {asset: frp_1.0.0_linux_amd64.tar.gz}
`)
	if err != nil {
		t.Fatal(err)
	}
	ex := m.Kernels[0].Targets["linux/amd64"].Extract
	if len(ex) != 2 || ex[0].To != "frpc" || ex[1].To != "frps" || ex[1].SHA256 != hsum([]byte("s")) {
		t.Fatalf("%+v", ex)
	}
}

// The whole chain: build -> sign -> verify -> agent installer imports the
// very archive manifestgen hashed. Proves the two halves agree.
func TestEndToEndBuildSignVerifyImport(t *testing.T) {
	assets := gostAssets(t)
	g := newFakeGH(t, assets)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.yaml")
	os.WriteFile(cfgPath, []byte(fmt.Sprintf(gostCfg, "checksums: {asset: checksums.txt}")), 0o600)
	unsigned, signed := filepath.Join(dir, "unsigned.json"), filepath.Join(dir, "manifest.json")
	key := filepath.Join(dir, "m.key")

	var out, errb bytes.Buffer
	step := func(args ...string) string {
		out.Reset()
		errb.Reset()
		if err := run(args, &out, &errb); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, errb.String())
		}
		return out.String()
	}
	step("keygen", "-out", key)
	pubHex := strings.TrimSpace(readFile(t, key+".pub"))
	step("build", "-config", cfgPath, "-out", unsigned, "-cache", filepath.Join(dir, "cache"), "-api-base", g.URL, "-now", "2026-10-05T12:00:00Z")
	step("sign", "-key", key, "-in", unsigned, "-out", signed)
	vout := step("verify", "-in", signed, "-pub", pubHex, "-now", "2026-10-06T00:00:00Z")
	if !strings.Contains(vout, "OK  signature valid") || !strings.Contains(vout, "gost") {
		t.Fatalf("verify output:\n%s", vout)
	}

	// wrong key, expired, tampered all fail
	otherPub := strings.TrimSpace(readFile(t, key+".pub"))
	step("keygen", "-out", filepath.Join(dir, "other.key"))
	otherPub = strings.TrimSpace(readFile(t, filepath.Join(dir, "other.key.pub")))
	if err := run([]string{"verify", "-in", signed, "-pub", otherPub}, &out, &errb); !errors.Is(err, kernel.ErrSignature) {
		t.Errorf("wrong key: %v", err)
	}
	if err := run([]string{"verify", "-in", signed, "-pub", pubHex, "-now", "2027-01-01T00:00:00Z"}, &out, &errb); !errors.Is(err, kernel.ErrExpired) {
		t.Errorf("expired: %v", err)
	}
	if err := run([]string{"verify", "-in", signed, "-pub", pubHex, "-now", "2026-10-06T00:00:00Z", "-min-sequence", "4"}, &out, &errb); !errors.Is(err, kernel.ErrStaleManifest) {
		t.Errorf("sequence: %v", err)
	}
	raw := readFile(t, signed)
	os.WriteFile(filepath.Join(dir, "evil.json"), []byte(strings.Replace(raw, "mirror.example", "evil.example", 1)), 0o644)
	if err := run([]string{"verify", "-in", filepath.Join(dir, "evil.json"), "-pub", pubHex, "-now", "2026-10-06T00:00:00Z"}, &out, &errb); !errors.Is(err, kernel.ErrSignature) {
		t.Errorf("tampered: %v", err)
	}

	// Agent side: install from the downloaded archive with the generated manifest.
	keys, _ := manifest.ParseKeys(pubHex)
	plat := platform.Info{GOOS: "linux", GOARCH: "amd64"}
	in, err := install.New(install.Config{
		Dir: filepath.Join(dir, "agent"), Keys: keys, Platform: &plat,
		Now:       func() time.Time { return time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC) },
		Check:     func(string) (string, error) { return "1.0.0", nil }, // cannot exec ELF files here
		FreeSpace: func(string) (uint64, bool) { return 1 << 40, true },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := in.LoadManifest([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "cache", "o_r", "v1.0.0", "gost_1.0.0_linux_amd64.tar.gz")
	got, err := in.Import(context.Background(), archive)
	if err != nil || got.Version != "1.0.0" {
		t.Fatalf("Import: %+v %v", got, err)
	}
	// mipsle target is also reachable through the same manifest, and null is "unavailable" not "unknown"
	plat2 := platform.Info{GOOS: "linux", GOARCH: "riscv64"}
	in2, _ := install.New(install.Config{Dir: filepath.Join(dir, "agent2"), Keys: keys, Platform: &plat2,
		Now: func() time.Time { return time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC) }})
	if err := in2.LoadManifest([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	if _, err := in2.Ensure(context.Background(), spec.KernelPin{Name: "gost", Version: "1.0.0"}); !errors.Is(err, kernel.ErrUnavailable) {
		t.Fatalf("riscv64: %v", err)
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestKeygenModeAndNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "k")
	var out bytes.Buffer
	if err := run([]string{"keygen", "-out", key}, &out, &out); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(key)
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("private key mode %v", fi.Mode().Perm())
		}
	}
	if !strings.Contains(out.String(), "public key: ") || strings.Contains(out.String(), readFile(t, key)[:64]) {
		t.Errorf("output must show the public key and never the private one:\n%s", out.String())
	}
	if err := run([]string{"keygen", "-out", key}, &out, &out); err == nil {
		t.Fatal("keygen overwrote an existing key")
	}
	if runtime.GOOS != "windows" {
		os.Chmod(key, 0o644)
		if err := run([]string{"sign", "-key", key, "-in", "x", "-out", "y"}, &out, &out); err == nil || !strings.Contains(err.Error(), "chmod 600") {
			t.Errorf("group-readable key accepted: %v", err)
		}
	}
}

// The shipped example describes exactly the 12 W1nCray targets for every kernel.
func TestExampleConfigCoversTwelveTargets(t *testing.T) {
	cfg, err := loadConfig("kernels.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"386", "amd64", "arm64", "armv5", "armv6", "armv7", "loong64", "mips", "mipsle", "mips64", "mips64le", "riscv64"}
	nulls := map[string][]string{
		"gost": nil, "xray": nil,
		"realm": {"386", "armv5", "loong64", "riscv64"},
		"frp":   {"386", "armv6"},
	}
	names := map[string]bool{}
	for _, k := range cfg.Kernels {
		names[k.Name] = true
		if len(k.Targets) != 12 {
			t.Errorf("%s: %d targets", k.Name, len(k.Targets))
		}
		isNull := map[string]bool{}
		for _, n := range nulls[k.Name] {
			isNull[n] = true
		}
		for _, a := range want {
			tc, ok := k.Targets["linux/"+a]
			if !ok {
				t.Errorf("%s: linux/%s missing", k.Name, a)
				continue
			}
			if (tc == nil) != isNull[a] {
				t.Errorf("%s linux/%s: null=%v want %v", k.Name, a, tc == nil, isNull[a])
			}
			if tc != nil && strings.Contains(tc.Asset, "slim") {
				t.Errorf("%s linux/%s: slim realm build selected", k.Name, a)
			}
		}
	}
	for _, n := range []string{"gost", "realm", "frp", "xray"} {
		if !names[n] {
			t.Errorf("kernel %s missing", n)
		}
	}
	// mips softfloat specifics
	for _, k := range cfg.Kernels {
		switch k.Name {
		case "gost":
			if !strings.Contains(k.Targets["linux/mipsle"].Asset, "softfloat") || !strings.Contains(k.Targets["linux/mips64"].Asset, "hardfloat") {
				t.Error("gost mips float selection wrong")
			}
		case "xray":
			if k.Targets["linux/mipsle"].Extract[0].From != "xray_softfloat" {
				t.Error("xray mips must extract xray_softfloat")
			}
		}
	}
}
