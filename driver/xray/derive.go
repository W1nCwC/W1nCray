package xray

import (
	"crypto/ecdh"
	"encoding/base64"
	"fmt"

	"github.com/W1nCwC/W1nCray/agent/tlsself"
)

// All credentials of a tunnel are derived from the shared Secret, so that the
// two ends of a tunnel (possibly on different machines, configured from the
// same panel record) agree without exchanging anything else. The Secret itself
// never appears in the Xray configuration.
//
// The derivation (and its salt) lives in agent/tlsself, which the
// gost driver uses too: the certificate of security "tls_self" is a label of
// the same KDF, and one implementation keeps the two engines byte-compatible.

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
	u, err := tlsself.Derive(secret, "uuid", 16)
	if err != nil {
		return nil, err
	}
	// Format as a version-4 style UUID so every parser accepts it.
	u[6] = (u[6] & 0x0f) | 0x40
	u[8] = (u[8] & 0x3f) | 0x80
	id := fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])

	priv, err := tlsself.Derive(secret, "vlessenc-x25519", 32)
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
