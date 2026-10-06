package manifest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/kernel"
)

var now = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

func hexsha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func sample() *Manifest {
	ex := Extract{From: "gost", To: "gost", SHA256: hexsha("bin"), Size: 3, Mode: "0755"}
	return &Manifest{
		Schema: SchemaVersion, Sequence: 7,
		IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(24 * time.Hour),
		Kernels: []Kernel{{
			Name: "gost", Version: "3.3.0", Channel: "stable", MinAgent: "0.4.0",
			License:      License{SPDX: "MIT", File: "LICENSE", SourceURL: "https://example.com/gost"},
			Capabilities: map[string]any{"reload": "api", "udp": true},
			Run:          Run{Binary: "gost", VersionCmd: []string{"-V"}},
			Targets: map[string]*Target{
				"linux/amd64": {Variant: "glibc", URLs: []string{"https://m.example/gost.tgz"}, Archive: ArchiveTarGz,
					ArchiveSHA256: hexsha("archive"), ArchiveSize: 10, Extract: []Extract{ex}, InstalledSize: 3},
				"linux/riscv64": nil,
			},
			Revoked: []Revocation{{Version: "3.1.0", Reason: "bad"}},
		}},
	}
}

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func signed(t *testing.T, m *Manifest, priv ed25519.PrivateKey) []byte {
	t.Helper()
	raw, err := Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv := keypair(t)
	raw := signed(t, sample(), priv)
	m, err := Verify(raw, VerifyOptions{Keys: []Key{NewKey(pub)}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if m.Sequence != 7 || m.Kernels[0].Name != "gost" {
		t.Fatalf("%+v", m)
	}
	// null target survives the round trip as "present key, nil target"
	if tg, st := m.Kernels[0].Lookup("linux/riscv64"); tg != nil || st != TargetNull {
		t.Errorf("riscv64: %v %v", tg, st)
	}
	if tg, st := m.Kernels[0].Lookup("linux/mips"); tg != nil || st != TargetAbsent {
		t.Errorf("mips: %v %v", tg, st)
	}
	if tg, st := m.Kernels[0].Lookup("linux/amd64"); tg == nil || st != TargetPresent {
		t.Errorf("amd64: %v %v", tg, st)
	}
	if !strings.Contains(string(raw), `"linux/riscv64": null`) {
		t.Errorf("null target not written as JSON null:\n%s", raw)
	}
}

func TestKeyRotation(t *testing.T) {
	pub1, _ := keypair(t)
	pub2, priv2 := keypair(t)
	raw := signed(t, sample(), priv2)
	if _, err := Verify(raw, VerifyOptions{Keys: []Key{NewKey(pub1), NewKey(pub2)}, Now: now}); err != nil {
		t.Fatalf("second key must verify: %v", err)
	}
	if _, err := Verify(raw, VerifyOptions{Keys: []Key{NewKey(pub1)}, Now: now}); !errors.Is(err, kernel.ErrSignature) {
		t.Fatalf("unknown key: %v", err)
	}
}

func TestSignatureTamper(t *testing.T) {
	pub, priv := keypair(t)
	keys := []Key{NewKey(pub)}
	raw := string(signed(t, sample(), priv))
	tamper := map[string]string{
		"archive hash":      strings.Replace(raw, hexsha("archive"), hexsha("evil"), 1),
		"url":               strings.Replace(raw, "https://m.example/gost.tgz", "https://evil.example/gost.tgz", 1),
		"sequence":          strings.Replace(raw, `"sequence": 7`, `"sequence": 8`, 1),
		"expiry":            strings.Replace(raw, `"expires_at": "2026-10-06`, `"expires_at": "2036-10-06`, 1),
		"mode":              strings.Replace(raw, `"0755"`, `"0777"`, 1),
		"revocation":        strings.Replace(raw, `"3.1.0"`, `"3.0.0"`, 1),
		"added member":      strings.Replace(raw, `"schema": 1,`, `"schema": 1, "extra": "x",`, 1),
		"swapped null":      strings.Replace(raw, `"linux/riscv64": null`, `"linux/riscv64": {}`, 1),
		"sig bytes":         strings.Replace(raw, `"sig": "`, `"sig": "AAAA`, 1),
		"key id":            strings.Replace(raw, `"key_id": "`, `"key_id": "0`, 1),
		"algorithm":         strings.Replace(raw, `"alg": "ed25519"`, `"alg": "none"`, 1),
		"signature removed": removeSignature(raw),
	}
	for name, doc := range tamper {
		if doc == raw {
			t.Fatalf("%s: tamper did not change the document", name)
		}
		_, err := Verify([]byte(doc), VerifyOptions{Keys: keys, Now: now})
		if !errors.Is(err, kernel.ErrSignature) {
			t.Errorf("%s: want ErrSignature, got %v", name, err)
		}
	}
	// whitespace/formatting changes do NOT matter (canonical form is signed)
	compact := strings.NewReplacer("\n", "", "  ", "").Replace(raw)
	if _, err := Verify([]byte(compact), VerifyOptions{Keys: keys, Now: now}); err != nil {
		t.Errorf("reformatted but equal document rejected: %v", err)
	}
}

func removeSignature(raw string) string {
	i := strings.Index(raw, ",\n  \"signature\"")
	return raw[:i] + "\n}\n"
}

func TestExpiryAndClock(t *testing.T) {
	pub, priv := keypair(t)
	keys := []Key{NewKey(pub)}
	raw := signed(t, sample(), priv)
	if _, err := Verify(raw, VerifyOptions{Keys: keys, Now: now.Add(25 * time.Hour)}); !errors.Is(err, kernel.ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
	if _, err := Verify(raw, VerifyOptions{Keys: keys, Now: now.Add(25 * time.Hour), AllowExpired: true}); err != nil {
		t.Fatalf("AllowExpired: %v", err)
	}
	if _, err := Verify(raw, VerifyOptions{Keys: keys, Now: time.Unix(0, 0)}); !errors.Is(err, kernel.ErrClock) {
		t.Fatalf("1970 clock: %v", err)
	}
	m, _ := Verify(raw, VerifyOptions{Keys: keys, Now: now})
	if err := m.CheckFresh(now.Add(48 * time.Hour)); !errors.Is(err, kernel.ErrExpired) {
		t.Fatalf("CheckFresh: %v", err)
	}
}

func TestSequenceRollback(t *testing.T) {
	pub, priv := keypair(t)
	keys := []Key{NewKey(pub)}
	raw := signed(t, sample(), priv) // sequence 7
	if _, err := Verify(raw, VerifyOptions{Keys: keys, Now: now, MinSequence: 8}); !errors.Is(err, kernel.ErrStaleManifest) {
		t.Fatalf("lower sequence: %v", err)
	}
	if _, err := Verify(raw, VerifyOptions{Keys: keys, Now: now, MinSequence: 7}); err != nil {
		t.Fatalf("equal sequence must be accepted: %v", err)
	}
}

func TestNoKeys(t *testing.T) {
	_, priv := keypair(t)
	raw := signed(t, sample(), priv)
	if _, err := Verify(raw, VerifyOptions{Now: now}); !errors.Is(err, kernel.ErrNoTrustedKeys) {
		t.Fatalf("got %v", err)
	}
	// an empty trust list is fail-closed (independent of what this build ships)
	withTrustedKeysFile(t, "# no keys\n")
	if _, err := DefaultKeys(); !errors.Is(err, kernel.ErrNoTrustedKeys) {
		t.Fatalf("DefaultKeys on an empty list: %v", err)
	}
}

// withTrustedKeysFile swaps the embedded trust list for the duration of a test.
func withTrustedKeysFile(t *testing.T, content string) {
	t.Helper()
	old := trustedKeysFile
	trustedKeysFile = content
	t.Cleanup(func() { trustedKeysFile = old })
}

// The shipped trust root is exactly the two production keys (primary + spare).
// Changing it is a deliberate release decision, so a change must touch this test.
func TestShippedTrustRoot(t *testing.T) {
	keys, err := DefaultKeys()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"280f5d33adf21274": true, "cb1ce38570e6a8b9": true}
	if len(keys) != len(want) {
		t.Fatalf("shipped trust root has %d keys, want %d", len(keys), len(want))
	}
	for _, k := range keys {
		if !want[k.ID] {
			t.Fatalf("unexpected trusted key id %s", k.ID)
		}
	}
}

func TestParseKeys(t *testing.T) {
	pub, _ := keypair(t)
	ks, err := ParseKeys("# c\n\n" + hex.EncodeToString(pub) + " # primary\n")
	if err != nil || len(ks) != 1 || ks[0].ID != KeyID(pub) {
		t.Fatalf("%v %v", ks, err)
	}
	if _, err := ParseKeys("zz"); err == nil {
		t.Fatal("bad key accepted")
	}
	old := ExtraKeys
	defer func() { ExtraKeys = old }()
	withTrustedKeysFile(t, "# no embedded keys here\n")
	ExtraKeys = hex.EncodeToString(pub)
	if ks, err := DefaultKeys(); err != nil || len(ks) != 1 {
		t.Fatalf("ExtraKeys: %v %v", ks, err)
	}
}

func TestStrictParsing(t *testing.T) {
	_, priv := keypair(t)
	raw := string(signed(t, sample(), priv))
	for name, doc := range map[string]string{
		"duplicate key": strings.Replace(raw, `"schema": 1,`, `"schema": 1, "schema": 2,`, 1),
		"float number":  strings.Replace(raw, `"sequence": 7`, `"sequence": 7.0`, 1),
		"exponent":      strings.Replace(raw, `"sequence": 7`, `"sequence": 7e0`, 1),
		"trailing data": raw + `{}`,
		"not an object": `[1]`,
	} {
		if _, err := Canonicalize([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	deep := strings.Repeat("[", 100) + strings.Repeat("]", 100)
	if _, err := Canonicalize([]byte(deep)); err == nil {
		t.Error("deep nesting accepted")
	}
}

func TestCanonicalVector(t *testing.T) {
	in := `{ "b": [1, 2, {"z": null, "a": true}], "a": "x<>&é", "signature": {"alg":"ed25519"}, "n": -0 }`
	_, err := Canonicalize([]byte(in))
	if err == nil {
		// "-0" matches the integer pattern; it is passed through verbatim
		t.Log("note: -0 is accepted verbatim")
	}
	in = `{ "b": [1, 2, {"z": null, "a": true}], "a": "x<>&é", "signature": {"alg":"ed25519"} }`
	got, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":"x<>&é","b":[1,2,{"a":true,"z":null}]}`
	if string(got) != want {
		t.Fatalf("canonical form\n got  %s\n want %s", got, want)
	}
}

func TestFindRevokedAgent(t *testing.T) {
	m := sample()
	if _, err := m.Find("gost", "v3.3.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Find("gost", "9.9.9"); !errors.Is(err, kernel.ErrUnknownKernel) {
		t.Fatal(err)
	}
	if why, bad := m.RevokedReason("gost", "3.1.0"); !bad || why != "bad" {
		t.Errorf("version revoke: %q %v", why, bad)
	}
	if _, bad := m.RevokedReason("realm", "3.1.0"); bad {
		t.Error("revocation must be scoped to the kernel name")
	}
	m.Kernels[0].Revoked = append(m.Kernels[0].Revoked, Revocation{SHA256: hexsha("archive")})
	if _, bad := m.RevokedReason("realm", "1.0.0", hexsha("archive")); !bad {
		t.Error("hash revocation applies to any kernel")
	}
	k := &m.Kernels[0]
	if err := k.CheckAgent("0.3.9"); !errors.Is(err, kernel.ErrAgentTooOld) {
		t.Error(err)
	}
	for _, v := range []string{"0.4.0", "0.10.0", "1.0.0", "dev", ""} {
		if err := k.CheckAgent(v); err != nil {
			t.Errorf("agent %q: %v", v, err)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.10.0", "1.9.9", 1}, {"1.0.0", "1.0.0", 0}, {"v2.0.0", "1.99.99", 1},
		{"1.0.0-rc1", "1.0.0", -1}, {"1.0", "1.0.0", 0}, {"26.3.27", "26.7.1", -1},
	} {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("%s vs %s = %d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestValidateRejects(t *testing.T) {
	bad := map[string]func(*Manifest){
		"schema":               func(m *Manifest) { m.Schema = 2 },
		"sequence zero":        func(m *Manifest) { m.Sequence = 0 },
		"expiry before issue":  func(m *Manifest) { m.ExpiresAt = m.IssuedAt },
		"no kernels":           func(m *Manifest) { m.Kernels = nil },
		"v prefix":             func(m *Manifest) { m.Kernels[0].Version = "v3.3.0" },
		"bad name":             func(m *Manifest) { m.Kernels[0].Name = "../x" },
		"no license":           func(m *Manifest) { m.Kernels[0].License.SPDX = "" },
		"dup entry":            func(m *Manifest) { m.Kernels = append(m.Kernels, m.Kernels[0]) },
		"target key":           func(m *Manifest) { m.Kernels[0].Targets["Linux AMD"] = nil },
		"archive type":         func(m *Manifest) { m.Kernels[0].Targets["linux/amd64"].Archive = "rar" },
		"short hash":           func(m *Manifest) { m.Kernels[0].Targets["linux/amd64"].ArchiveSHA256 = "abc" },
		"upper hash":           func(m *Manifest) { m.Kernels[0].Targets["linux/amd64"].ArchiveSHA256 = strings.ToUpper(hexsha("a")) },
		"size":                 func(m *Manifest) { m.Kernels[0].Targets["linux/amd64"].ArchiveSize = 0 },
		"no urls":              func(m *Manifest) { m.Kernels[0].Targets["linux/amd64"].URLs = nil },
		"ftp url":              func(m *Manifest) { m.Kernels[0].Targets["linux/amd64"].URLs = []string{"ftp://x/y"} },
		"userinfo url":         func(m *Manifest) { m.Kernels[0].Targets["linux/amd64"].URLs = []string{"https://u:p@x/y"} },
		"from traversal":       func(m *Manifest) { m.Kernels[0].Targets["linux/amd64"].Extract[0].From = "../gost" },
		"from absolute":        func(m *Manifest) { m.Kernels[0].Targets["linux/amd64"].Extract[0].From = "/gost" },
		"to with slash":        func(m *Manifest) { m.Kernels[0].Targets["linux/amd64"].Extract[0].To = "bin/gost" },
		"to dotdot":            func(m *Manifest) { m.Kernels[0].Targets["linux/amd64"].Extract[0].To = ".." },
		"to reserved":          func(m *Manifest) { m.Kernels[0].Targets["linux/amd64"].Extract[0].To = ".installed.json" },
		"setuid mode":          func(m *Manifest) { m.Kernels[0].Targets["linux/amd64"].Extract[0].Mode = "4755" },
		"non-octal mode":       func(m *Manifest) { m.Kernels[0].Targets["linux/amd64"].Extract[0].Mode = "rwx" },
		"binary not extracted": func(m *Manifest) { m.Kernels[0].Run.Binary = "other" },
		"no version cmd":       func(m *Manifest) { m.Kernels[0].Run.VersionCmd = nil },
		"bad regex":            func(m *Manifest) { m.Kernels[0].Run.VersionRegex = "(" },
		"regex no group":       func(m *Manifest) { m.Kernels[0].Run.VersionRegex = "abc" },
		"empty revocation":     func(m *Manifest) { m.Kernels[0].Revoked = []Revocation{{}} },
	}
	if err := sample().Validate(); err != nil {
		t.Fatalf("sample invalid: %v", err)
	}
	for name, mut := range bad {
		m := sample()
		mut(m)
		err := m.Validate()
		if !errors.Is(err, kernel.ErrManifestInvalid) {
			t.Errorf("%s: want ErrManifestInvalid, got %v", name, err)
		}
	}
}

func TestSignRefusesInvalid(t *testing.T) {
	_, priv := keypair(t)
	m := sample()
	m.Kernels[0].Targets["linux/amd64"].Extract[0].Mode = "6755"
	if _, err := Sign(m, priv); err == nil {
		t.Fatal("signed an invalid manifest")
	}
}
