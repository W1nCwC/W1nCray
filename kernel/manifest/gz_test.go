package manifest

import (
	"strings"
	"testing"
)

// gzManifest is sample() with an extra raw-gzip kernel entry, the shape the
// agent's own self_update entry uses (protocol ruling 11).
func gzManifest(extract []Extract) *Manifest {
	m := sample()
	m.Kernels = append(m.Kernels, Kernel{
		Name: "agent", Version: "0.5.0", Channel: "stable",
		License: License{SPDX: "MIT", SourceURL: "https://example.com/agent"},
		Run:     Run{Binary: "W1nCray", VersionCmd: []string{"version"}},
		Targets: map[string]*Target{
			"linux/amd64": {
				URLs:          []string{"https://m.example/W1nCray-linux-amd64.gz"},
				Archive:       ArchiveGz,
				ArchiveSHA256: hexsha("agent-archive"),
				ArchiveSize:   20,
				Extract:       extract,
			},
		},
	})
	return m
}

// TestValidateAcceptsRawGzTarget covers the acceptance rule that a gz target is
// legal when it lists exactly one plain-named member.
func TestValidateAcceptsRawGzTarget(t *testing.T) {
	ex := Extract{From: "W1nCray-linux-amd64", To: "W1nCray", SHA256: hexsha("bin"), Size: 3, Mode: "0755"}
	if err := gzManifest([]Extract{ex}).Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// TestValidateRefusesGzWithMultipleExtract covers the second half of acceptance
// item 2: a raw gzip stream cannot carry more than one file, so a gz target
// with several extract entries is refused before anything is downloaded.
func TestValidateRefusesGzWithMultipleExtract(t *testing.T) {
	a := Extract{From: "W1nCray-linux-amd64", To: "W1nCray", SHA256: hexsha("bin"), Size: 3, Mode: "0755"}
	b := Extract{From: "extra", To: "extra", SHA256: hexsha("extra"), Size: 3, Mode: "0644"}
	err := gzManifest([]Extract{a, b}).Validate()
	if err == nil {
		t.Fatal("a gz target with two extract entries must be refused")
	}
	if !strings.Contains(err.Error(), "exactly one extract entry") {
		t.Fatalf("error = %v", err)
	}
}

// TestValidateRefusesGzWithDirectoryMember covers the "no directory semantics"
// rule: a gz member has no name, so the manifest may not pretend it has a path.
func TestValidateRefusesGzWithDirectoryMember(t *testing.T) {
	ex := Extract{From: "dist/W1nCray-linux-amd64", To: "W1nCray", SHA256: hexsha("bin"), Size: 3, Mode: "0755"}
	err := gzManifest([]Extract{ex}).Validate()
	if err == nil {
		t.Fatal("a gz member with a directory must be refused")
	}
	if !strings.Contains(err.Error(), "plain file name") {
		t.Fatalf("error = %v", err)
	}
}

// TestTarGzRulesAreUnchanged is the regression guard for the format dispatch:
// adding gz must not loosen or tighten tar.gz targets.
func TestTarGzRulesAreUnchanged(t *testing.T) {
	if err := sample().Validate(); err != nil {
		t.Fatalf("the tar.gz sample must stay valid: %v", err)
	}
	// A tar.gz target may keep a directory member; only gz is restricted.
	m := sample()
	m.Kernels[0].Targets["linux/amd64"].Extract = []Extract{
		{From: "pkg/gost", To: "gost", SHA256: hexsha("bin"), Size: 3, Mode: "0755"},
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("a tar.gz member inside a directory must stay legal: %v", err)
	}
	// An unknown archive format is still refused.
	bad := sample()
	bad.Kernels[0].Targets["linux/amd64"].Archive = "rar"
	if err := bad.Validate(); err == nil {
		t.Fatal("an unknown archive format must be refused")
	}
}

// TestArchiveGzSurvivesSignVerify makes sure a gz target round-trips through
// the signed document (the signature covers the whole tree).
func TestArchiveGzSurvivesSignVerify(t *testing.T) {
	pub, priv := keypair(t)
	ex := Extract{From: "W1nCray-linux-amd64", To: "W1nCray", SHA256: hexsha("bin"), Size: 3, Mode: "0755"}
	raw := signed(t, gzManifest([]Extract{ex}), priv)
	m, err := Verify(raw, VerifyOptions{Keys: []Key{NewKey(pub)}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	k, err := m.Find("agent", "0.5.0")
	if err != nil {
		t.Fatal(err)
	}
	tg, st := k.Lookup("linux/amd64")
	if st != TargetPresent || tg.Archive != ArchiveGz {
		t.Fatalf("agent target = %+v (%v)", tg, st)
	}
}
