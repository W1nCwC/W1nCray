package kernelx

import (
	"bytes"
	"compress/gzip"
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

	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/kernel/install"
	"github.com/W1nCwC/W1nCray/kernel/platform"
)

func gzBytes(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func sumHex(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// ghFake is a fake GitHub release host. assets maps a file name to its bytes;
// sums maps a file name to the hash listed in SHA256SUMS (default: the real one).
type ghFake struct {
	srv    *httptest.Server
	tag    string
	assets map[string][]byte
	sums   map[string]string
	hits   atomic.Int32
}

func newGHFake(t *testing.T, tag string, assets map[string][]byte) *ghFake {
	f := &ghFake{tag: tag, assets: assets, sums: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/releases/tag/"+f.tag, http.StatusFound)
	})
	mux.HandleFunc("/releases/download/"+tag+"/SHA256SUMS", func(w http.ResponseWriter, r *http.Request) {
		var sb strings.Builder
		for name, b := range f.assets {
			h := sumHex(b)
			if o, ok := f.sums[name]; ok {
				h = o
			}
			fmt.Fprintf(&sb, "%s  %s\n", h, name)
		}
		_, _ = w.Write([]byte(sb.String()))
	})
	mux.HandleFunc("/releases/download/"+tag+"/", func(w http.ResponseWriter, r *http.Request) {
		name := filepath.Base(r.URL.Path)
		if b, ok := f.assets[name]; ok {
			f.hits.Add(1)
			_, _ = w.Write(b)
			return
		}
		http.NotFound(w, r)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func ghEnsurer(t *testing.T, plat platform.Info, base string) *Ensurer {
	t.Helper()
	in, err := install.New(install.Config{
		Dir:       t.TempDir(),
		Platform:  &plat,
		AllowHTTP: true,
		Check:     func(string) (string, error) { return "0.9.2", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return &Ensurer{in: in, ghBase: base, ghClient: http.DefaultClient, allowHTTP: true}
}

// 成功：默认装 GitHub 最新 release 的 xray（full 变体），且不需要签名清单。
func TestXrayDefaultInstallsGitHubLatest(t *testing.T) {
	full, lite := gzBytes(t, "full-bin"), gzBytes(t, "lite-bin")
	f := newGHFake(t, "v0.9.2", map[string][]byte{
		"W1nCray-xray-linux-amd64.gz":      full,
		"W1nCray-xray-linux-amd64-lite.gz": lite,
	})
	e := ghEnsurer(t, ghAmd64, f.srv.URL)
	inst, err := e.Ensure(context.Background(), spec.KernelPin{Name: "xray"})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if inst.Version != "0.9.2" {
		t.Fatalf("version = %q, want 0.9.2", inst.Version)
	}
	if got, err := e.in.Current("xray"); err != nil || got.Version != "0.9.2" {
		t.Fatalf("Current = %+v, %v", got, err)
	}
}

// lite 变体：OpenWrt 机器优先 -lite；只有 full 时回到 full。
func TestXrayDefaultPicksLiteOnOpenWrt(t *testing.T) {
	full, lite := gzBytes(t, "full-bin"), gzBytes(t, "lite-bin")
	f := newGHFake(t, "v0.9.2", map[string][]byte{
		"W1nCray-xray-linux-amd64.gz":      full,
		"W1nCray-xray-linux-amd64-lite.gz": lite,
	})
	owrt := ghAmd64
	owrt.OpenWrt = true
	e := ghEnsurer(t, owrt, f.srv.URL)
	if _, err := e.installXrayLatest(context.Background()); err != nil {
		t.Fatalf("lite: %v", err)
	}
	if got := f.hits.Load(); got != 1 {
		t.Fatalf("asset downloads = %d, want 1", got)
	}
	// 装到的是 lite 字节：检查版本目录里的文件内容。
	inst, _ := e.in.Current("xray")
	b := readFile(t, inst.Path)
	if string(b) != "lite-bin" {
		t.Fatalf("installed %q, want the lite build", b)
	}

	f2 := newGHFake(t, "v0.9.2", map[string][]byte{"W1nCray-xray-linux-amd64.gz": full})
	e2 := ghEnsurer(t, owrt, f2.srv.URL)
	if _, err := e2.installXrayLatest(context.Background()); err != nil {
		t.Fatalf("lite missing, full fallback: %v", err)
	}
	inst2, _ := e2.in.Current("xray")
	if string(readFile(t, inst2.Path)) != "full-bin" {
		t.Fatal("expected the full build when no lite asset exists")
	}
}

// sha 不符：SHA256SUMS 与实际资产不一致 → 拒绝安装；Ensure 回落后因无清单报错并带上 GitHub 失败原因。
func TestXrayDefaultRejectsSHAMismatch(t *testing.T) {
	f := newGHFake(t, "v0.9.2", map[string][]byte{"W1nCray-xray-linux-amd64.gz": gzBytes(t, "x")})
	f.sums["W1nCray-xray-linux-amd64.gz"] = strings.Repeat("0", 64)
	e := ghEnsurer(t, ghAmd64, f.srv.URL)
	if _, err := e.installXrayLatest(context.Background()); err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("want sha256 mismatch error, got %v", err)
	}
	if _, err := e.in.Current("xray"); err == nil {
		t.Fatal("a rejected download must leave nothing installed")
	}
	_, err := e.Ensure(context.Background(), spec.KernelPin{Name: "xray"})
	if err == nil || !strings.Contains(err.Error(), "no signed manifest") || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("want fallback error mentioning both causes, got %v", err)
	}
}

// 网络失败：回落到签名清单路径（旧行为）。无清单时报旧的错误并附带 GitHub 原因。
func TestXrayDefaultFallsBackToManifestOnNetworkFailure(t *testing.T) {
	f := newGHFake(t, "v0.9.2", nil)
	base := f.srv.URL
	f.srv.Close() // 连接被拒绝
	e := ghEnsurer(t, ghAmd64, base)
	_, err := e.Ensure(context.Background(), spec.KernelPin{Name: "xray"})
	if err == nil || !strings.Contains(err.Error(), "no signed manifest") {
		t.Fatalf("want the legacy manifest error after fallback, got %v", err)
	}
	if !strings.Contains(err.Error(), "GitHub") {
		t.Fatalf("error should also name the GitHub failure: %v", err)
	}
}

// release 里没有本平台的 xray 资产 → 回落。
func TestXrayDefaultNoAssetForPlatform(t *testing.T) {
	f := newGHFake(t, "v0.9.2", map[string][]byte{"W1nCray-xray-linux-arm64.gz": gzBytes(t, "x")})
	e := ghEnsurer(t, ghAmd64, f.srv.URL)
	if _, err := e.installXrayLatest(context.Background()); err == nil || !strings.Contains(err.Error(), "no Xray kernel") {
		t.Fatalf("got %v", err)
	}
}

// 显式版本、非 xray 内核不走 GitHub 路径。
func TestGitHubPathOnlyForUnpinnedXray(t *testing.T) {
	f := newGHFake(t, "v0.9.2", map[string][]byte{"W1nCray-xray-linux-amd64.gz": gzBytes(t, "x")})
	e := ghEnsurer(t, ghAmd64, f.srv.URL)
	if _, err := e.Ensure(context.Background(), spec.KernelPin{Name: "xray", Version: "0.8.2"}); err == nil {
		t.Fatal("pinned version without a manifest must fail, not use GitHub")
	}
	if f.hits.Load() != 0 {
		t.Fatal("pinned version must not touch the GitHub release")
	}
}

// AllowHTTP 关闭时拒绝 http 源。
func TestXrayDefaultRespectsAllowHTTP(t *testing.T) {
	f := newGHFake(t, "v0.9.2", map[string][]byte{"W1nCray-xray-linux-amd64.gz": gzBytes(t, "x")})
	e := ghEnsurer(t, ghAmd64, f.srv.URL)
	e.allowHTTP = false
	if _, err := e.installXrayLatest(context.Background()); err == nil || !strings.Contains(err.Error(), "scheme") {
		t.Fatalf("got %v", err)
	}
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var ghAmd64 = platform.Info{GOOS: "linux", GOARCH: "amd64"}
