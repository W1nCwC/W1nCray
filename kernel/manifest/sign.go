package manifest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/W1nCwC/W1nCray/kernel"
)

// AlgEd25519 is the only signature algorithm.
const AlgEd25519 = "ed25519"

// maxClockSkew: a manifest cannot have been issued in the future of a
// correct clock; beyond this tolerance the local clock is considered wrong.
const maxClockSkew = 24 * time.Hour

// Key is a trusted manifest verification key.
type Key struct {
	ID  string
	Pub ed25519.PublicKey
}

// KeyID derives the key identifier: first 8 bytes of SHA-256(pub), hex.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// NewKey builds a Key from a raw public key.
func NewKey(pub ed25519.PublicKey) Key { return Key{ID: KeyID(pub), Pub: pub} }

// ParseKeys parses a key list: one hex public key per line, '#' comments and
// blank lines ignored, anything after the first field is a comment.
func ParseKeys(text string) ([]Key, error) {
	var keys []Key
	for i, line := range strings.Split(text, "\n") {
		if j := strings.IndexByte(line, '#'); j >= 0 {
			line = line[:j]
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		b, err := hex.DecodeString(f[0])
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("key list line %d: not a 32-byte hex ed25519 public key", i+1)
		}
		keys = append(keys, NewKey(ed25519.PublicKey(b)))
	}
	return keys, nil
}

// Sign signs m (any existing signature is replaced) and returns the final
// pretty-printed document. The key id is derived from the private key.
func Sign(m *Manifest, priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("bad ed25519 private key")
	}
	cp := *m
	cp.Signature = nil
	if err := cp.Validate(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(&cp)
	if err != nil {
		return nil, err
	}
	canon, err := Canonicalize(body)
	if err != nil {
		return nil, fmt.Errorf("canonicalise: %w", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	cp.Signature = &Signature{
		Alg:   AlgEd25519,
		KeyID: KeyID(pub),
		Sig:   base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canon)),
	}
	out, err := json.MarshalIndent(&cp, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// VerifyOptions controls Verify.
type VerifyOptions struct {
	// Keys are the trusted public keys; empty means kernel.ErrNoTrustedKeys.
	Keys []Key
	// Now is the clock; zero means time.Now().
	Now time.Time
	// MinSequence is the highest sequence accepted so far; a lower sequence
	// is a rollback. Equal is allowed (re-fetching the same manifest).
	MinSequence int64
	// AllowExpired skips only the expiry check (used when re-loading the
	// stored manifest; Ensure re-checks expiry on every call).
	AllowExpired bool
}

// Verify authenticates raw and returns the parsed manifest. Order matters
// and is fail-closed: nothing of the document is interpreted before the
// signature over its canonical form has been verified.
func Verify(raw []byte, opt VerifyOptions) (*Manifest, error) {
	if len(opt.Keys) == 0 {
		return nil, kernel.Newf(kernel.ErrNoTrustedKeys, "", "", "this agent build carries no manifest keys")
	}
	tree, err := parseStrict(raw)
	if err != nil {
		return nil, kernel.Wrap(kernel.ErrManifestInvalid, "", "", err, "parse")
	}
	obj, _ := tree.(map[string]any)
	sigObj, _ := obj["signature"].(map[string]any)
	if sigObj == nil {
		return nil, kernel.Newf(kernel.ErrSignature, "", "", "no signature")
	}
	alg, _ := sigObj["alg"].(string)
	keyID, _ := sigObj["key_id"].(string)
	sigB64, _ := sigObj["sig"].(string)
	if alg != AlgEd25519 {
		return nil, kernel.Newf(kernel.ErrSignature, "", "", "unsupported algorithm %q", alg)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, kernel.Newf(kernel.ErrSignature, "", "", "malformed signature")
	}
	var key *Key
	for i := range opt.Keys {
		if opt.Keys[i].ID == keyID {
			key = &opt.Keys[i]
			break
		}
	}
	if key == nil {
		return nil, kernel.Newf(kernel.ErrSignature, "", "", "signed by unknown key %q", keyID)
	}
	canon, err := canonicalOfTree(tree)
	if err != nil {
		return nil, kernel.Wrap(kernel.ErrManifestInvalid, "", "", err, "canonicalise")
	}
	if !ed25519.Verify(key.Pub, canon, sig) {
		return nil, kernel.Newf(kernel.ErrSignature, "", "", "signature does not match content (key %s)", keyID)
	}

	// Authentic from here on.
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, kernel.Wrap(kernel.ErrManifestInvalid, "", "", err, "decode")
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	now := opt.Now
	if now.IsZero() {
		now = time.Now()
	}
	if now.Add(maxClockSkew).Before(m.IssuedAt) {
		return nil, kernel.Newf(kernel.ErrClock, "", "", "now %s is before issued_at %s", now.UTC().Format(time.RFC3339), m.IssuedAt.UTC().Format(time.RFC3339))
	}
	if !opt.AllowExpired && !now.Before(m.ExpiresAt) {
		return nil, kernel.Newf(kernel.ErrExpired, "", "", "expired at %s", m.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if m.Sequence < opt.MinSequence {
		return nil, kernel.Newf(kernel.ErrStaleManifest, "", "", "sequence %d < accepted %d", m.Sequence, opt.MinSequence)
	}
	return &m, nil
}

// CheckFresh re-evaluates expiry (and clock sanity) of an already accepted
// manifest at time now.
func (m *Manifest) CheckFresh(now time.Time) error {
	if now.Add(maxClockSkew).Before(m.IssuedAt) {
		return kernel.Newf(kernel.ErrClock, "", "", "now %s is before issued_at %s", now.UTC().Format(time.RFC3339), m.IssuedAt.UTC().Format(time.RFC3339))
	}
	if !now.Before(m.ExpiresAt) {
		return kernel.Newf(kernel.ErrExpired, "", "", "expired at %s", m.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return nil
}
