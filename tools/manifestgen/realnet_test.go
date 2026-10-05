//go:build realnet

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/kernel/install"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
	"github.com/W1nCwC/W1nCray/kernel/platform"
)

// Run with:  ALL_PROXY=socks5h://127.0.0.1:7890 go test -tags realnet -run RealGost -v ./tools/manifestgen/
//
// It talks to the real GitHub API and downloads the real gost v3.3.0
// linux_amd64 asset (~17 MB), builds a manifest with the real digest and
// checksums.txt cross-check, signs and verifies it, then lets the agent-side
// installer import the real archive (extraction + per-file sha256; the
// version self-check is stubbed because an ELF binary cannot run on Windows).
const realGostCfg = `
sequence: 1
valid_days: 30
kernels:
  - name: gost
    version: "3.3.0"
    repo: go-gost/gost
    license: {spdx: MIT, file: LICENSE}
    run: {binary: gost, version_cmd: ["-V"]}
    checksums: {asset: checksums.txt}
    extract: [{from: gost, to: gost}]
    targets:
      linux/amd64: {asset: gost_3.3.0_linux_amd64.tar.gz}
      linux/riscv64: null
`

// digest published by GitHub for the asset on 2026-10-05 (asset.digest).
const realGostAMD64SHA = "676fb7f78d267b6ae73df719c0c7f2b565dde7147da935cfafbc1e1da558b6d5"

func TestRealGostV330(t *testing.T) {
	dir := t.TempDir()
	cache := os.Getenv("W1NC_REALNET_CACHE")
	if cache == "" {
		cache = filepath.Join(dir, "cache")
	}
	cfg := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(cfg, []byte(realGostCfg), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	do := func(args ...string) string {
		out.Reset()
		if err := run(args, &out, &errb); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, errb.String())
		}
		return out.String()
	}
	key := filepath.Join(dir, "k")
	do("keygen", "-out", key)
	pub := strings.TrimSpace(readFile(t, key+".pub"))
	do("build", "-config", cfg, "-out", filepath.Join(dir, "u.json"), "-cache", cache)
	t.Logf("build log:\n%s", errb.String())
	do("sign", "-key", key, "-in", filepath.Join(dir, "u.json"), "-out", filepath.Join(dir, "m.json"))
	t.Logf("verify:\n%s", do("verify", "-in", filepath.Join(dir, "m.json"), "-pub", pub))
	raw := readFile(t, filepath.Join(dir, "m.json"))
	t.Logf("manifest:\n%s", raw)

	keys, _ := manifest.ParseKeys(pub)
	m, err := manifest.Verify([]byte(raw), manifest.VerifyOptions{Keys: keys, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	tg := m.Kernels[0].Targets["linux/amd64"]
	if tg.ArchiveSHA256 != realGostAMD64SHA {
		t.Fatalf("archive sha256 %s, GitHub published %s", tg.ArchiveSHA256, realGostAMD64SHA)
	}

	plat := platform.Info{GOOS: "linux", GOARCH: "amd64", Libc: "glibc"}
	in, err := install.New(install.Config{Dir: filepath.Join(dir, "agent"), Keys: keys, Platform: &plat,
		Check:     func(string) (string, error) { return "3.3.0", nil },
		FreeSpace: func(string) (uint64, bool) { return 1 << 40, true }})
	if err != nil {
		t.Fatal(err)
	}
	if err := in.LoadManifest([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	got, err := in.Import(context.Background(), filepath.Join(cache, "go-gost_gost", "v3.3.0", "gost_3.3.0_linux_amd64.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(got.Path)
	if err != nil || fi.Size() != tg.Extract[0].Size {
		t.Fatalf("installed %s: %v %v", got.Path, fi, err)
	}
	if err := in.VerifyInstalled("gost", "3.3.0"); err != nil {
		t.Fatal(err)
	}
	// and Ensure resolves from the manifest without network once installed
	if _, err := in.Ensure(context.Background(), spec.KernelPin{Name: "gost", Version: "v3.3.0"}); err != nil {
		t.Fatal(err)
	}
	t.Logf("installed gost %s (%d bytes) at %s", got.Version, fi.Size(), got.Path)
}
