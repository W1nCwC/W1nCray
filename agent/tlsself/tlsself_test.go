package tlsself

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// The expected values below were recorded from driver/xray's SelfCert BEFORE it
// was moved here (the baseline run is quoted in the commit message). They are
// the contract of the move: the derivation must stay byte-for-byte identical,
// because every deployed pin and every certificate an agent already serves
// depends on it.
var frozen = []struct {
	secret, sni string
	pin         string // SHA-256 (hex) of the certificate DER
	certPEMSha  string // SHA-256 (hex) of the PEM text
}{
	{
		secret: "baseline-secret-0123456789abcdef", sni: "a.example",
		pin:        "1116d39be389c166b21b6d674e85d0cb34fae41b7fd3dc2fe15b864aed0b0676",
		certPEMSha: "28781b2bb4b1571878ee3ca0f20ed08c9bf460a4e387efa41f56965980aaf39f",
	},
	{
		secret: "baseline-secret-0123456789abcdef", sni: "",
		pin:        "397264448e5279fb172981d51ed92711036c1da3874851e7f3285c5abae1ef4f",
		certPEMSha: "6924555f4bef2c2cb319393059190bfa93508e9daaea723547cdcaa296f3b4f5",
	},
	{
		secret: "another-secret-0123456789abc", sni: "tun.example.net",
		pin:        "5961eb5ba8a4f55700aa6ddb2d1774d4f5d5a2441956c0a387a07c89e81b6ba8",
		certPEMSha: "3cec09a76877e74bd22d02d7a28f4e83d4be38c8e4a9db8610a1a961c6437e63",
	},
}

func TestDerivationIsFrozen(t *testing.T) {
	for _, c := range frozen {
		certPEM, keyPEM, pin, err := SelfCert(c.secret, c.sni)
		if err != nil {
			t.Fatalf("SelfCert(%q, %q): %v", c.secret, c.sni, err)
		}
		if pin != c.pin {
			t.Errorf("SelfCert(%q, %q) pin = %s, want %s", c.secret, c.sni, pin, c.pin)
		}
		sum := sha256.Sum256([]byte(certPEM))
		if got := hex.EncodeToString(sum[:]); got != c.certPEMSha {
			t.Errorf("SelfCert(%q, %q) certificate PEM sha256 = %s, want %s", c.secret, c.sni, got, c.certPEMSha)
		}
		if !strings.HasPrefix(certPEM, "-----BEGIN CERTIFICATE-----") || !strings.Contains(keyPEM, "BEGIN PRIVATE KEY") {
			t.Errorf("SelfCert returned something that is not PEM: %q / %q", certPEM[:32], keyPEM[:32])
		}
	}
}

func TestSelfCertIsDeterministicAndInputDependent(t *testing.T) {
	_, _, p1, err := SelfCert("secret-a-0123456789abcdef", "a.example")
	if err != nil {
		t.Fatal(err)
	}
	_, _, p2, _ := SelfCert("secret-a-0123456789abcdef", "a.example")
	if p1 != p2 {
		t.Errorf("the same inputs gave different pins: %s vs %s", p1, p2)
	}
	_, _, p3, _ := SelfCert("secret-a-0123456789abcdef", "b.example")
	_, _, p4, _ := SelfCert("secret-b-0123456789abcdef", "a.example")
	if p1 == p3 || p1 == p4 {
		t.Error("a different SNI or secret must give a different certificate")
	}
	pin, err := SelfCertPin("secret-a-0123456789abcdef", "a.example")
	if err != nil || pin != p1 {
		t.Errorf("SelfCertPin = %s, %v; want %s", pin, err, p1)
	}
}

func TestNameUsesTheDefaultWhenSNIIsEmpty(t *testing.T) {
	if Name("") != DefaultName {
		t.Errorf("Name(\"\") = %q, want %q", Name(""), DefaultName)
	}
	if Name("x.example") != "x.example" {
		t.Errorf("Name(x.example) = %q", Name("x.example"))
	}
	// An empty SNI and the explicit default name must derive the same bytes:
	// that is what lets a client with no SNI trust a server that has one.
	_, _, a, err := SelfCert("s-0123456789abcdef", "")
	if err != nil {
		t.Fatal(err)
	}
	_, _, b, _ := SelfCert("s-0123456789abcdef", DefaultName)
	if a != b {
		t.Errorf("empty SNI and the default name gave different pins: %s vs %s", a, b)
	}
}
