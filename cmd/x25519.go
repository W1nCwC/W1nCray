package cmd

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/spf13/cobra"
)

var x25519Input string

func init() {
	c := &cobra.Command{
		Use:   "x25519",
		Short: "Generate a REALITY key pair (same format as `xray x25519`)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return x25519()
		},
	}
	c.Flags().StringVarP(&x25519Input, "input", "i", "", "derive from this base64 private key")
	rootCmd.AddCommand(c)
}

func x25519() error {
	var priv *ecdh.PrivateKey
	var err error
	if x25519Input != "" {
		b, derr := base64.RawURLEncoding.DecodeString(x25519Input)
		if derr != nil {
			return fmt.Errorf("decode private key: %w", derr)
		}
		priv, err = ecdh.X25519().NewPrivateKey(b)
	} else {
		priv, err = ecdh.X25519().GenerateKey(rand.Reader)
	}
	if err != nil {
		return err
	}
	fmt.Printf("Private key: %s\n", base64.RawURLEncoding.EncodeToString(priv.Bytes()))
	fmt.Printf("Public key: %s\n", base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()))
	return nil
}
