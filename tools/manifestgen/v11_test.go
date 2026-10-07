package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/kernel/manifest"
)

// v11Archs is the release matrix every kernel entry must cover.
var v11Archs = []string{"386", "amd64", "arm64", "armv5", "armv6", "armv7", "loong64", "mips", "mipsle", "mips64", "mips64le", "riscv64"}

// TestV11ExampleConfigLoads keeps examples/v11.yaml honest: the agent and the
// Xray kernel are local-only entries, the Xray kernel carries the full and the
// +openwrt (lite) target for every architecture, and the four upstream kernels
// carry two versions each.
func TestV11ExampleConfigLoads(t *testing.T) {
	cfg, err := loadConfig("examples/v11.yaml")
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string][]KernelCfg{}
	for _, k := range cfg.Kernels {
		byName[k.Name] = append(byName[k.Name], k)
	}
	for name, want := range map[string]int{"agent": 1, "xray": 1, "gost": 2, "realm": 2, "frp": 2} {
		if len(byName[name]) != want {
			t.Errorf("%s: %d entries, want %d", name, len(byName[name]), want)
		}
	}

	// ---- agent ----
	agent := byName["agent"][0]
	if agent.Version != "0.6.0" || agent.Run.Binary != "W1nCray" {
		t.Errorf("agent entry = %+v", agent.Run)
	}
	if len(agent.Targets) != 0 {
		t.Errorf("the agent entry is local-only, but targets = %v", agent.Targets)
	}
	if len(agent.Local) != len(v11Archs) {
		t.Errorf("agent local entries = %d, want %d", len(agent.Local), len(v11Archs))
	}

	// ---- xray ----
	xray := byName["xray"][0]
	if xray.Version != "0.6.0" {
		t.Errorf("xray version = %q", xray.Version)
	}
	if xray.Run.Binary != "W1nCray-xray" || len(xray.Run.VersionCmd) != 1 || xray.Run.VersionCmd[0] != "version" {
		t.Errorf("xray run = %+v", xray.Run)
	}
	re, err := regexp.Compile(xray.Run.VersionRegex)
	if err != nil {
		t.Fatalf("xray version_regex %q: %v", xray.Run.VersionRegex, err)
	}
	if m := re.FindStringSubmatch("W1nCray-xray v0.6.0 (Xray-core 26.3.27)"); len(m) < 2 || m[1] != "0.6.0" {
		t.Errorf("xray version_regex on the banner = %v", m)
	}
	// Every architecture must be listed twice: the full build under linux/<arch>
	// and the lite build under linux/<arch>+openwrt.
	keys := map[string]LocalAssetCfg{}
	for _, la := range xray.Local {
		if _, dup := keys[la.Target]; dup {
			t.Errorf("xray: target %s listed twice", la.Target)
		}
		keys[la.Target] = la
	}
	if len(xray.Local) != 2*len(v11Archs) {
		t.Errorf("xray local entries = %d, want %d", len(xray.Local), 2*len(v11Archs))
	}
	for _, a := range v11Archs {
		full, ok := keys["linux/"+a]
		if !ok {
			t.Errorf("xray: linux/%s missing", a)
		} else if !strings.HasSuffix(full.File, ".gz") || strings.Contains(full.File, "-lite") {
			t.Errorf("xray linux/%s: %q is not the full build", a, full.File)
		}
		ow, ok := keys["linux/"+a+"+openwrt"]
		if !ok {
			t.Errorf("xray: linux/%s+openwrt missing", a)
			continue
		}
		if !strings.HasSuffix(ow.File, "-lite.gz") {
			t.Errorf("xray linux/%s+openwrt: %q is not the lite build", a, ow.File)
		}
		if !strings.Contains(ow.Variant, "fallbackroots") {
			t.Errorf("xray linux/%s+openwrt: variant %q lacks fallbackroots", a, ow.Variant)
		}
		if ow.To != "W1nCray-xray" {
			t.Errorf("xray linux/%s+openwrt: to = %q", a, ow.To)
		}
	}

	// ---- upstream kernels ----
	for _, name := range []string{"gost", "realm", "frp"} {
		for _, k := range byName[name] {
			if len(k.Targets) != len(v11Archs) {
				t.Errorf("%s %s: %d targets, want %d", name, k.Version, len(k.Targets), len(v11Archs))
			}
			for _, a := range v11Archs {
				tc, ok := k.Targets["linux/"+a]
				if !ok {
					t.Errorf("%s %s: linux/%s missing", name, k.Version, a)
					continue
				}
				// gost and frp put the version in the asset name; realm does
				// not (realm-<target>-unknown-linux-musl.tar.gz).
				if tc != nil && name != "realm" && !strings.Contains(tc.Asset, k.Version) {
					t.Errorf("%s %s linux/%s: asset %q lacks the version", name, k.Version, a, tc.Asset)
				}
			}
		}
	}
}

// TestV11XrayEntryBuildsFullAndOpenWrtTargets builds the shipped xray entry
// (with the local dist paths redirected to temporary real gz files) and checks
// the manifest it produces: a gz target for linux/<arch> and one for
// linux/<arch>+openwrt pointing at the -lite asset.
func TestV11XrayEntryBuildsFullAndOpenWrtTargets(t *testing.T) {
	raw, err := os.ReadFile("examples/v11.yaml")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	text := strings.ReplaceAll(string(raw), "dist/", filepath.ToSlash(dir)+"/")
	// Give every file the example names real bytes: a raw gz stream whose
	// content is the file's base name, so no two entries hash alike. Only the
	// active entries match (the placeholder block is commented out).
	for _, m := range regexp.MustCompile(`(?m)^\s*-\s*\{file:\s*(\S+\.gz)`).FindAllStringSubmatch(text, -1) {
		p := filepath.FromSlash(m[1])
		if _, err := os.Stat(p); err == nil {
			continue
		}
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if _, err := gz.Write([]byte(filepath.Base(p))); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfgPath := filepath.Join(t.TempDir(), "v11.yaml")
	if err := os.WriteFile(cfgPath, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := filterKernels(cfg, "xray"); err != nil {
		t.Fatal(err)
	}
	// The xray entry is local-only, so no GitHub client is needed.
	m, err := Build(context.Background(), buildOptions{
		Cfg: cfg, Cache: t.TempDir(), Now: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC),
		Log: func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(m.Kernels) != 1 || m.Kernels[0].Name != "xray" {
		t.Fatalf("kernels = %+v", m.Kernels)
	}
	k := m.Kernels[0]
	if k.Version != "0.6.0" || k.Run.Binary != "W1nCray-xray" {
		t.Fatalf("xray entry = %s %+v", k.Version, k.Run)
	}
	for _, a := range v11Archs {
		for _, key := range []string{"linux/" + a, "linux/" + a + "+openwrt"} {
			tg, st := k.Lookup(key)
			if st != manifest.TargetPresent || tg == nil {
				t.Errorf("%s: state = %v", key, st)
				continue
			}
			if tg.Archive != manifest.ArchiveGz {
				t.Errorf("%s: archive = %q, want %q", key, tg.Archive, manifest.ArchiveGz)
			}
			if len(tg.Extract) != 1 || tg.Extract[0].To != "W1nCray-xray" || tg.Extract[0].Mode != "0755" {
				t.Errorf("%s: extract = %+v", key, tg.Extract)
			}
			if tg.InstalledSize <= 0 || tg.ArchiveSHA256 == "" {
				t.Errorf("%s: size/hash = %d/%q", key, tg.InstalledSize, tg.ArchiveSHA256)
			}
			if len(tg.URLs) != 1 || !strings.Contains(tg.URLs[0], "W1nCray-xray") {
				t.Errorf("%s: urls = %v", key, tg.URLs)
			}
			lite := strings.HasSuffix(key, "+openwrt")
			if lite && !strings.HasSuffix(tg.URLs[0], "-lite.gz") {
				t.Errorf("%s: url %q does not name the lite asset", key, tg.URLs[0])
			}
			if !lite && strings.Contains(tg.URLs[0], "-lite.gz") {
				t.Errorf("%s: url %q names the lite asset", key, tg.URLs[0])
			}
		}
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("generated manifest is invalid: %v", err)
	}
}

// TestFilterKernels covers the -kernels selector used to re-publish one entry
// from the full example.
func TestFilterKernels(t *testing.T) {
	cfg, err := loadConfig("examples/v11.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := filterKernels(cfg, " xray , "); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Kernels) != 1 || cfg.Kernels[0].Name != "xray" {
		t.Fatalf("kernels = %+v", cfg.Kernels)
	}

	cfg2, err := loadConfig("examples/v11.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := filterKernels(cfg2, "gost,xray"); err != nil {
		t.Fatal(err)
	}
	names := map[string]int{}
	for _, k := range cfg2.Kernels {
		names[k.Name]++
	}
	if len(cfg2.Kernels) != 3 || names["gost"] != 2 || names["xray"] != 1 {
		t.Fatalf("kernels = %+v", names)
	}

	cfg3, err := loadConfig("examples/v11.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := filterKernels(cfg3, "xray,nope"); err == nil || !strings.Contains(err.Error(), "not in the config") {
		t.Fatalf("unknown name: %v", err)
	}
}
