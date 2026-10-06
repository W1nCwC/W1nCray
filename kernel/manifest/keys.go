package manifest

import (
	_ "embed"
	"strings"

	"github.com/W1nCwC/W1nCray/kernel"
)

// trustedKeysFile is the embedded public key list. It is edited by the
// release owner (the private halves never enter this repository). Keep at
// least two keys listed so one can be rotated out without bricking agents.
//
//go:embed trusted_keys.txt
var trustedKeysFile string

// ExtraKeys lets a release build add keys without editing the file:
//
//	go build -ldflags "-X github.com/W1nCwC/W1nCray/kernel/manifest.ExtraKeys=<hex>,<hex>"
//
// Keys are comma separated hex ed25519 public keys.
var ExtraKeys string

// DefaultKeys returns the keys compiled into this binary: the embedded list
// plus ExtraKeys. Tests and tools pass their own Keys to Verify instead.
func DefaultKeys() ([]Key, error) {
	keys, err := ParseKeys(trustedKeysFile)
	if err != nil {
		return nil, err
	}
	if ExtraKeys != "" {
		extra, err := ParseKeys(strings.ReplaceAll(ExtraKeys, ",", "\n"))
		if err != nil {
			return nil, err
		}
		keys = append(keys, extra...)
	}
	if len(keys) == 0 {
		return nil, kernel.Newf(kernel.ErrNoTrustedKeys, "", "", "no keys in trusted_keys.txt or ExtraKeys")
	}
	return keys, nil
}
