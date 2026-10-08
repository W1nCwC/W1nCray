// Package tlsself derives the deterministic self-signed certificate of a
// tunnel's shared secret. It is the one implementation the drivers use for
// security "tls_self": the two ends of a tunnel (possibly on different
// machines, configured from the same panel record) derive the SAME certificate
// without exchanging anything but the secret, which is what lets a panel that
// cannot run x509 itself still pin or trust the peer.
//
// The package was moved out of the (since deleted) driver/xray unchanged: the
// KDF salt and every label are frozen, so a certificate computed before the
// move is byte-for-byte the one computed now. tlsself.TestDerivationIsFrozen
// pins that with values recorded from the pre-move implementation.
//
// It lives in agent/tlsself rather than under driver/: the gost driver needs
// it, and the derivation is an engine-independent, frozen contract (the removed
// xray driver derived the same certificate).
package tlsself

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"time"
)

// DefaultName is the certificate's DNS name when no SNI is configured. It is
// part of the derived certificate, so it must never change.
const DefaultName = "w1n-fwd.invalid"

// kdfSalt is mixed into every derivation. It was named after the xray driver
// because the credentials of a tunnel (UUID, VLESS encryption) were the first
// users; the certificate shares it on purpose, and changing it would change
// every certificate and pin already deployed.
const kdfSalt = "w1ncray/xray-driver/v1"

// Derive expands the shared secret into n bytes for one label. It is the only
// KDF of a tunnel: the certificate, the UUID and the VLESS encryption keys are
// all labels of it, so both ends agree on everything from the secret alone.
func Derive(secret, label string, n int) ([]byte, error) {
	return hkdf.Key(sha256.New, []byte(secret), []byte(kdfSalt), label, n)
}

// Name returns the certificate's DNS name for a configured SNI: the SNI when
// one is set, DefaultName otherwise. A client that pins the certificate does
// not verify the name, but the name is part of the certificate, so both ends
// must use the same rule to derive the same bytes.
func Name(sni string) string {
	if sni == "" {
		return DefaultName
	}
	return sni
}

// zeroReader makes x509.CreateCertificate independent of any entropy source
// (Ed25519 signatures are deterministic and ignore it).
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// SelfCert returns the deterministic self-signed server certificate of a
// secret and server name, and the SHA-256 (hex) of its DER encoding, which is
// the value a client pins (Tunnel.PinSHA256). The same inputs always give the
// same certificate, so Render stays a pure function and the pin can be
// computed by whoever knows the secret.
func SelfCert(secret, sni string) (certPEM, keyPEM, pin string, err error) {
	seed, err := Derive(secret, "cert-ed25519", ed25519.SeedSize)
	if err != nil {
		return "", "", "", err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	name := Name(sni)
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "w1n-fwd"},
		NotBefore:             time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2124, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{name},
	}
	der, err := x509.CreateCertificate(zeroReader{}, tpl, tpl, priv.Public(), priv)
	if err != nil {
		return "", "", "", err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", "", err
	}
	sum := sha256.Sum256(der)
	var cb, kb bytes.Buffer
	if err := pem.Encode(&cb, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return "", "", "", err
	}
	if err := pem.Encode(&kb, &pem.Block{Type: "PRIVATE KEY", Bytes: kder}); err != nil {
		return "", "", "", err
	}
	return cb.String(), kb.String(), hex.EncodeToString(sum[:]), nil
}

// SelfCertPin returns only the pin of SelfCert.
func SelfCertPin(secret, sni string) (string, error) {
	_, _, pin, err := SelfCert(secret, sni)
	return pin, err
}
