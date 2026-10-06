package xray

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// All credentials of a tunnel are derived from the shared Secret, so that the
// two ends of a tunnel (possibly on different machines, configured from the
// same panel record) agree without exchanging anything else. The Secret itself
// never appears in the Xray configuration.
const kdfSalt = "w1ncray/xray-driver/v1"

func derive(secret, label string, n int) ([]byte, error) {
	return hkdf.Key(sha256.New, []byte(secret), []byte(kdfSalt), label, n)
}

// credentials are the tunnel credentials derived from a Secret.
type credentials struct {
	UUID string
	// VLESS Encryption strings (mlkem768x25519plus, X25519 authentication,
	// "0s"/"1rtt": no session tickets, which also avoids the ticket-cleaning
	// goroutine of the Xray server instance).
	Decryption string // server side
	Encryption string // client side
}

func deriveCreds(secret string) (*credentials, error) {
	u, err := derive(secret, "uuid", 16)
	if err != nil {
		return nil, err
	}
	// Format as a version-4 style UUID so every parser accepts it.
	u[6] = (u[6] & 0x0f) | 0x40
	u[8] = (u[8] & 0x3f) | 0x80
	id := fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])

	priv, err := derive(secret, "vlessenc-x25519", 32)
	if err != nil {
		return nil, err
	}
	key, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	enc := base64.RawURLEncoding
	return &credentials{
		UUID:       id,
		Decryption: "mlkem768x25519plus.native.0s." + enc.EncodeToString(priv),
		Encryption: "mlkem768x25519plus.native.1rtt." + enc.EncodeToString(key.PublicKey().Bytes()),
	}, nil
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
// the value a client pins (Tunnel.PinSHA256). The same inputs always give
// the same certificate, so Render stays a pure function and the pin can be
// computed by whoever knows the secret.
func SelfCert(secret, sni string) (certPEM, keyPEM, pin string, err error) {
	seed, err := derive(secret, "cert-ed25519", ed25519.SeedSize)
	if err != nil {
		return "", "", "", err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	name := sni
	if name == "" {
		name = "w1n-fwd.invalid"
	}
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
