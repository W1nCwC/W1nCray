package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/kernel/manifest"
)

// localAgentCfg describes the agent's own signed entry, built from a local
// dist/W1nCray-linux-<arch>.gz the way release/build.sh produces it. The path
// is single-quoted so Windows backslashes stay literal.
const localAgentCfg = `
sequence: 11
valid_days: 30
mirrors: ["https://mirror.example/agent/{version}/{asset}"]
kernels:
  - name: agent
    version: "0.5.0"
    license: {spdx: MIT}
    capabilities: {self_update: true}
    run: {binary: W1nCray, version_cmd: ["version"], version_regex: "W1nCray ([0-9][0-9.]*)"}
    local:
      - file: '%s'
        target: linux/amd64
        to: W1nCray
`

func gzipFile(t *testing.T, path string, data []byte) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func buildLocal(t *testing.T, cfgYAML string) (*manifest.Manifest, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(p, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(p)
	if err != nil {
		return nil, err
	}
	return Build(context.Background(), buildOptions{
		Cfg: cfg, Cache: t.TempDir(), Now: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC),
		Log: func(string, ...any) {},
	})
}

// TestLocalGzBuildProducesTheAgentEntry covers acceptance item 1: manifestgen
// turns a local raw gzip build into an unsigned manifest whose agent entry has
// archive "gz" and whose extract hash/size describe the decompressed binary.
func TestLocalGzBuildProducesTheAgentEntry(t *testing.T) {
	dist := t.TempDir()
	bin := []byte("#!/bin/sh\n# W1nCray 0.5.0\n" + strings.Repeat("x", 4096))
	archive := filepath.Join(dist, "W1nCray-linux-amd64.gz")
	gzipFile(t, archive, bin)

	m, err := buildLocal(t, fmt.Sprintf(localAgentCfg, archive))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	k, err := m.Find("agent", "0.5.0")
	if err != nil {
		t.Fatal(err)
	}
	tg, st := k.Lookup("linux/amd64")
	if st != manifest.TargetPresent {
		t.Fatalf("agent/linux-amd64 state = %v", st)
	}
	if tg.Archive != manifest.ArchiveGz {
		t.Fatalf("archive = %q, want %q", tg.Archive, manifest.ArchiveGz)
	}
	if len(tg.Extract) != 1 {
		t.Fatalf("extract = %+v", tg.Extract)
	}
	ex := tg.Extract[0]
	if ex.From != "W1nCray-linux-amd64.gz" {
		t.Errorf("extract.from = %q, want the archive's base name", ex.From)
	}
	if ex.To != "W1nCray" {
		t.Errorf("extract.to = %q", ex.To)
	}
	if ex.SHA256 != hsum(bin) || ex.Size != int64(len(bin)) {
		t.Errorf("extract = %s/%d, want the decompressed %s/%d", ex.SHA256, ex.Size, hsum(bin), len(bin))
	}
	if tg.InstalledSize != int64(len(bin)) {
		t.Errorf("installed_size = %d, want %d", tg.InstalledSize, len(bin))
	}
	raw, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if tg.ArchiveSHA256 != hsum(raw) || tg.ArchiveSize != int64(len(raw)) {
		t.Errorf("archive hash/size = %s/%d, want the file's", tg.ArchiveSHA256, tg.ArchiveSize)
	}
	if len(tg.URLs) != 1 || tg.URLs[0] != "https://mirror.example/agent/0.5.0/W1nCray-linux-amd64.gz" {
		t.Errorf("urls = %v", tg.URLs)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("generated manifest is invalid: %v", err)
	}
}

// TestTarGzLocalBuildIsNotReadAsRawGz covers the ordering rule: a .tar.gz must
// be treated as a tar archive (and therefore needs a member name), never as a
// raw gzip stream.
func TestTarGzLocalBuildIsNotReadAsRawGz(t *testing.T) {
	dist := t.TempDir()
	archive := filepath.Join(dist, "gost_1.0.0_linux_amd64.tar.gz")
	if err := os.WriteFile(archive, tgz(t, map[string][]byte{"gost": []byte("bin")}), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := fmt.Sprintf(localAgentCfg, archive)
	cfg = strings.Replace(cfg, "to: W1nCray", "to: gost\n        from: gost", 1)
	cfg = strings.Replace(cfg, "binary: W1nCray", "binary: gost", 1)
	m, err := buildLocal(t, cfg)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	tg, _ := m.Kernels[0].Lookup("linux/amd64")
	if tg.Archive != manifest.ArchiveTarGz {
		t.Fatalf("archive = %q, want %q", tg.Archive, manifest.ArchiveTarGz)
	}
	if tg.Extract[0].From != "gost" {
		t.Errorf("extract.from = %q", tg.Extract[0].From)
	}

	// Without an explicit member name a tar.gz local build must be refused:
	// there is no single-member default for a tarball.
	noFrom := fmt.Sprintf(localAgentCfg, archive)
	noFrom = strings.Replace(noFrom, "to: W1nCray", "to: gost", 1)
	noFrom = strings.Replace(noFrom, "binary: W1nCray", "binary: gost", 1)
	if _, err := buildLocal(t, noFrom); err == nil || !strings.Contains(err.Error(), "explicit extract list") {
		t.Fatalf("err = %v, want a refusal to guess the tar member", err)
	}
}

// TestLocalBuildNeedsAMirror keeps the generated manifest distributable: a
// local file has no upstream URL, so without a mirror the target would have no
// url at all and the manifest would be invalid.
func TestLocalBuildNeedsAMirror(t *testing.T) {
	dist := t.TempDir()
	archive := filepath.Join(dist, "W1nCray-linux-amd64.gz")
	gzipFile(t, archive, []byte("bin"))
	cfg := strings.Replace(fmt.Sprintf(localAgentCfg, archive),
		`mirrors: ["https://mirror.example/agent/{version}/{asset}"]`, "mirrors: []", 1)
	if _, err := buildLocal(t, cfg); err == nil || !strings.Contains(err.Error(), "at least one mirror") {
		t.Fatalf("err = %v, want a mirror requirement", err)
	}
}

// TestAgentExampleConfigLoads keeps the shipped self-update example honest: it
// must describe the agent's reserved manifest entry for all 12 platforms from
// local files, so a release owner can copy it and run one build.
func TestAgentExampleConfigLoads(t *testing.T) {
	cfg, err := loadConfig("kernels.agent.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Kernels) != 1 || cfg.Kernels[0].Name != "agent" {
		t.Fatalf("kernels = %+v", cfg.Kernels)
	}
	k := cfg.Kernels[0]
	if len(k.Targets) != 0 {
		t.Errorf("the agent entry is local-only, but targets = %v", k.Targets)
	}
	want := []string{"386", "amd64", "arm64", "armv5", "armv6", "armv7", "loong64", "mips", "mipsle", "mips64", "mips64le", "riscv64"}
	if len(k.Local) != len(want) {
		t.Fatalf("local entries = %d, want %d", len(k.Local), len(want))
	}
	got := map[string]bool{}
	for _, la := range k.Local {
		if !strings.HasSuffix(la.File, ".gz") {
			t.Errorf("%s: %q is not a raw gz build", la.Target, la.File)
		}
		if !strings.HasSuffix(la.Target, "/") {
			got[strings.TrimPrefix(la.Target, "linux/")] = true
		}
	}
	for _, a := range want {
		if !got[a] {
			t.Errorf("linux/%s missing from the example", a)
		}
	}
	if k.Run.Binary != "W1nCray" || len(k.Run.VersionCmd) == 0 {
		t.Errorf("run = %+v", k.Run)
	}
}

// TestLocalOpenWrtEntryGoesToOpenWrtTargets covers the release-blocker rule in
// the generator: a local build marked openwrt: true lands in openwrt_targets
// under a plain os/arch key, never under a "+openwrt" key in targets.
func TestLocalOpenWrtEntryGoesToOpenWrtTargets(t *testing.T) {
	dist := t.TempDir()
	full := filepath.Join(dist, "W1nCray-xray-linux-amd64.gz")
	lite := filepath.Join(dist, "W1nCray-xray-linux-amd64-lite.gz")
	gzipFile(t, full, []byte("full"))
	gzipFile(t, lite, []byte("lite"))
	cfg := fmt.Sprintf(`
sequence: 21
mirrors: ["https://mirror.example/xray/{version}/{asset}"]
kernels:
  - name: xray
    version: "0.6.0"
    license: {spdx: MIT}
    run: {binary: W1nCray-xray, version_cmd: ["version"]}
    local:
      - {file: '%s', target: linux/amd64, to: W1nCray-xray}
      - {file: '%s', target: linux/amd64, to: W1nCray-xray, variant: fallbackroots, openwrt: true}
`, full, lite)
	m, err := buildLocal(t, cfg)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	k := m.Kernels[0]
	tg, st := k.Lookup("linux/amd64")
	if st != manifest.TargetPresent || strings.Contains(tg.URLs[0], "-lite.gz") {
		t.Fatalf("targets[linux/amd64] = %+v (%v)", tg, st)
	}
	ow, st := k.LookupOpenWrt("linux/amd64")
	if st != manifest.TargetPresent || !strings.Contains(ow.URLs[0], "-lite.gz") {
		t.Fatalf("openwrt_targets[linux/amd64] = %+v (%v)", ow, st)
	}
	if ow.Variant != "fallbackroots" {
		t.Errorf("openwrt variant = %q", ow.Variant)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("generated manifest is invalid: %v", err)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "+openwrt") {
		t.Error("the generated manifest carries a +openwrt key")
	}
}

// TestSuffixedTargetKeysAreRefused keeps the build description from
// reintroducing the legacy "+openwrt" key, which is exactly what made a
// v0.5.2 agent reject the whole manifest.
func TestSuffixedTargetKeysAreRefused(t *testing.T) {
	for _, field := range []string{"targets", "openwrt_targets"} {
		cfg := fmt.Sprintf(`
sequence: 22
kernels:
  - name: gost
    version: "1.0.0"
    repo: o/r
    license: {spdx: MIT}
    run: {binary: gost, version_cmd: ["-V"]}
    extract: [{from: gost, to: gost}]
    %s:
      linux/amd64+openwrt: {asset: gost_1.0.0_linux_amd64.tar.gz}
`, field)
		p := filepath.Join(t.TempDir(), "cfg.yaml")
		if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfig(p); err == nil || !strings.Contains(err.Error(), "must not carry a suffix") {
			t.Errorf("%s: err = %v, want a suffix refusal", field, err)
		}
	}
	cfg := `
sequence: 23
kernels:
  - name: agent
    version: "0.5.0"
    license: {spdx: MIT}
    run: {binary: W1nCray, version_cmd: ["version"]}
    local:
      - {file: /nonexistent.gz, target: linux/amd64+openwrt, to: W1nCray}
`
	p := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(p); err == nil || !strings.Contains(err.Error(), "must not carry a suffix") {
		t.Errorf("local: err = %v, want a suffix refusal", err)
	}
}

// TestLocalAndRemoteTargetsCanCoexist guards the kernel-level wiring: a kernel
// may list GitHub targets and local ones side by side, and a duplicate platform
// key is refused at config load.
func TestLocalAndRemoteTargetsCanCoexist(t *testing.T) {
	g := newFakeGH(t, gostAssets(t))
	dist := t.TempDir()
	archive := filepath.Join(dist, "W1nCray-linux-arm64.gz")
	gzipFile(t, archive, []byte("armbin"))
	cfg := fmt.Sprintf(`
sequence: 12
mirrors: ["https://mirror.example/{name}/{version}/{asset}"]
kernels:
  - name: gost
    version: "1.0.0"
    repo: o/r
    license: {spdx: MIT}
    run: {binary: gost, version_cmd: ["-V"]}
    extract: [{from: gost, to: gost}]
    targets:
      linux/amd64: {asset: gost_1.0.0_linux_amd64.tar.gz}
    local:
      - file: '%s'
        target: linux/arm64
        to: gost
        from: gost
        archive: gz
`, archive)
	m, err := g.build(t, cfg)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	k := m.Kernels[0]
	if _, st := k.Lookup("linux/amd64"); st != manifest.TargetPresent {
		t.Errorf("amd64 state = %v", st)
	}
	if tg, st := k.Lookup("linux/arm64"); st != manifest.TargetPresent || tg.Archive != manifest.ArchiveGz {
		t.Errorf("arm64 = %+v (%v)", tg, st)
	}

	dup := strings.Replace(cfg, "target: linux/arm64", "target: linux/amd64", 1)
	p := filepath.Join(t.TempDir(), "dup.yaml")
	if err := os.WriteFile(p, []byte(dup), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(p); err == nil || !strings.Contains(err.Error(), "both in targets and local") {
		t.Fatalf("err = %v, want a duplicate-key refusal", err)
	}
}

func TestKernelMirrorsOverrideTheTopLevelOnes(t *testing.T) {
	cfg := &Config{Mirrors: []string{"https://top/{name}/{asset}"}}
	own := &KernelCfg{Name: "agent", Mirrors: []string{"https://own/v{version}/{asset}"}}
	other := &KernelCfg{Name: "gost"}
	if got := mirrorsFor(cfg, own); len(got) != 1 || got[0] != "https://own/v{version}/{asset}" {
		t.Errorf("own mirrors = %v", got)
	}
	if got := mirrorsFor(cfg, other); len(got) != 1 || got[0] != "https://top/{name}/{asset}" {
		t.Errorf("fallback mirrors = %v", got)
	}
}
