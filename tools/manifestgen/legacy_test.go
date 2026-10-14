package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/W1nCwC/W1nCray/kernel/manifest"
)

// openwrtOnlyCfg is a build description that v11 accepts but v0.5.2 does not:
// the only kernel carries a single OpenWrt (lite) local build, so the generated
// manifest has no "targets" key at all. v0.5.2's Kernel.validate() rejects the
// whole document with "no targets" as soon as one kernel has an empty targets
// object, so a 0.5.x agent would load nothing and report no_manifest on every
// command. This is the REG3-1 failure in a new shape.
func openwrtOnlyCfg(t *testing.T) string {
	t.Helper()
	lite := filepath.Join(t.TempDir(), "W1nCray-xray-linux-amd64-lite.gz")
	gzipFile(t, lite, []byte("lite"))
	return fmt.Sprintf(`
sequence: 31
mirrors: ["https://mirror.example/xray/{version}/{asset}"]
kernels:
  - name: xray
    version: "0.6.0"
    license: {spdx: MIT}
    run: {binary: W1nCray-xray, version_cmd: ["version"]}
    local:
      - {file: '%s', target: linux/amd64, to: W1nCray-xray, variant: fallbackroots, openwrt: true}
`, lite)
}

// writeOpenWrtOnlyConfig writes openwrtOnlyCfg to a temporary file and returns
// its path (the CLI tests need a path, the Build-level tests do not).
func writeOpenWrtOnlyConfig(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "openwrt-only.yaml")
	if err := os.WriteFile(p, []byte(openwrtOnlyCfg(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestLegacyGateRefusesOpenWrtOnlyKernel is the F10b regression test: the
// generator must refuse to produce (and therefore to sign) a manifest that a
// v0.5.2 agent rejects outright, and the error must name the kernel and explain
// why the whole document dies.
func TestLegacyGateRefusesOpenWrtOnlyKernel(t *testing.T) {
	_, err := buildLocal(t, openwrtOnlyCfg(t))
	if err == nil {
		t.Fatal("an openwrt_targets-only kernel was generated without the 0.5.x gate failing")
	}
	for _, want := range []string{"xray", "0.6.0", "0.5.x", "targets", "openwrt_targets", "no targets"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// TestLegacyGateAcceptsTheShippedV11Example is the other half: the manifest the
// shipped examples/v11.yaml produces (every targets key plain, the OpenWrt lite
// builds under openwrt_targets) must pass the gate. buildV11Xray builds it
// through Build, so the test also proves the default path does not reject it.
func TestLegacyGateAcceptsTheShippedV11Example(t *testing.T) {
	m := buildV11Xray(t)
	if err := checkLegacyV052(m); err != nil {
		t.Fatalf("the gate rejected the shipped examples/v11.yaml manifest: %v", err)
	}
	if len(m.Kernels[0].Targets) == 0 || len(m.Kernels[0].OpenWrtTargets) == 0 {
		t.Fatalf("xray entry = %d targets, %d openwrt_targets", len(m.Kernels[0].Targets), len(m.Kernels[0].OpenWrtTargets))
	}
}

// TestNoLegacyGateFlagAllowsGeneration covers the only supported opt-out: the
// default build refuses the openwrt-only kernel, --no-legacy-gate writes it.
func TestNoLegacyGateFlagAllowsGeneration(t *testing.T) {
	cfgPath := writeOpenWrtOnlyConfig(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "unsigned.json")
	var stdout, stderr bytes.Buffer

	err := run([]string{"build", "-config", cfgPath, "-out", out, "-cache", filepath.Join(dir, "cache")}, &stdout, &stderr)
	if err == nil {
		t.Fatal("build without --no-legacy-gate generated a 0.5.x-incompatible manifest")
	}
	if !strings.Contains(err.Error(), "0.5.x gate") {
		t.Fatalf("err = %v, want the 0.5.x gate error", err)
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Error("a refused build still wrote the manifest")
	}

	stdout.Reset()
	stderr.Reset()
	if err := run([]string{"build", "-config", cfgPath, "-out", out, "-cache", filepath.Join(dir, "cache"), "-no-legacy-gate"}, &stdout, &stderr); err != nil {
		t.Fatalf("build --no-legacy-gate: %v\n%s", err, stderr.String())
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var m manifest.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	// The document really is the one a v0.5.2 agent rejects: no targets at all.
	if len(m.Kernels) != 1 || len(m.Kernels[0].Targets) != 0 || len(m.Kernels[0].OpenWrtTargets) != 1 {
		t.Fatalf("kernels = %+v", m.Kernels)
	}
	if err := checkLegacyV052(&m); err == nil {
		t.Fatal("the generated document unexpectedly passes the gate")
	}
}

// TestNoLegacyGateFlagCoversSign proves the gate also sits in front of the
// private key: an unsigned manifest that carries an openwrt-only kernel cannot
// be signed unless the same explicit opt-out is passed.
func TestNoLegacyGateFlagCoversSign(t *testing.T) {
	cfgPath := writeOpenWrtOnlyConfig(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "m.key")
	unsigned := filepath.Join(dir, "unsigned.json")
	var stdout, stderr bytes.Buffer
	if err := run([]string{"keygen", "-out", key}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"build", "-config", cfgPath, "-out", unsigned, "-cache", filepath.Join(dir, "cache"), "-no-legacy-gate"}, &stdout, &stderr); err != nil {
		t.Fatalf("build --no-legacy-gate: %v\n%s", err, stderr.String())
	}

	if err := run([]string{"sign", "-key", key, "-in", unsigned, "-out", filepath.Join(dir, "bad.json")}, &stdout, &stderr); err == nil {
		t.Fatal("sign accepted a 0.5.x-incompatible manifest")
	} else if !strings.Contains(err.Error(), "0.5.x gate") {
		t.Fatalf("sign err = %v, want the 0.5.x gate error", err)
	}
	if err := run([]string{"sign", "-key", key, "-in", unsigned, "-out", filepath.Join(dir, "ok.json"), "-no-legacy-gate"}, &stdout, &stderr); err != nil {
		t.Fatalf("sign --no-legacy-gate: %v\n%s", err, stderr.String())
	}
}

// TestLegacyGateRules pins the gate's rules to v0.5.2's validate, including the
// "+suffix" spelling of the REG3-1 blocker and the empty-kernel/empty-targets
// cases of legacyV052Validate.
func TestLegacyGateRules(t *testing.T) {
	// The gate and the v11 test's copy of the v0.5.2 rule must not drift.
	if v052TargetKey.String() != reTargetV052.String() {
		t.Fatalf("gate regex %q != test copy %q", reTargetV052, v052TargetKey)
	}

	// A plain os/arch key passes; a null (unavailable) value is irrelevant.
	ok := &manifest.Manifest{Kernels: []manifest.Kernel{{
		Name: "gost", Version: "1.0.0",
		Targets: map[string]*manifest.Target{"linux/amd64": nil},
	}}}
	if err := checkLegacyV052(ok); err != nil {
		t.Fatalf("plain os/arch key refused: %v", err)
	}

	// A document with no kernels is rejected by v0.5.2 ("no kernels").
	err := checkLegacyV052(&manifest.Manifest{})
	if err == nil || !strings.Contains(err.Error(), "no kernels") {
		t.Fatalf("empty manifest: %v", err)
	}

	// An empty targets object is rejected by v0.5.2 ("no targets"), even when
	// the kernel has OpenWrt builds.
	err = checkLegacyV052(&manifest.Manifest{Kernels: []manifest.Kernel{{
		Name: "xray", Version: "0.6.0",
		OpenWrtTargets: map[string]*manifest.Target{"linux/amd64": nil},
	}}})
	if err == nil || !strings.Contains(err.Error(), "xray 0.6.0") || !strings.Contains(err.Error(), "no targets") {
		t.Fatalf("openwrt-only kernel: %v", err)
	}

	// The legacy "+openwrt" key is the REG3-1 blocker: the gate must name the
	// key and explain that the whole document dies.
	err = checkLegacyV052(&manifest.Manifest{Kernels: []manifest.Kernel{{
		Name: "xray", Version: "0.6.0",
		Targets: map[string]*manifest.Target{"linux/amd64+openwrt": nil},
	}}})
	if err == nil || !strings.Contains(err.Error(), "linux/amd64+openwrt") || !strings.Contains(err.Error(), "suffix") {
		t.Fatalf("suffixed key: %v", err)
	}

	// Any other key outside the regex is refused too (case, missing slash,
	// too short/long segments).
	for _, key := range []string{"linux/amd64 ", "Linux/amd64", "linux", "l/amd64", "linux/amd64/x", "linux/thisarchiswaytoolong"} {
		err := checkLegacyV052(&manifest.Manifest{Kernels: []manifest.Kernel{{
			Name: "gost", Version: "1.0.0",
			Targets: map[string]*manifest.Target{key: nil},
		}}})
		if err == nil || !strings.Contains(err.Error(), key) {
			t.Errorf("key %q: err = %v, want a refusal naming the key", key, err)
		}
	}
}
