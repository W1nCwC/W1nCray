// Package certcfg holds the *configuration* half of the node-certificate
// support: the certificate mode constants, the certificate source Config, the
// paths a certificate is stored at, whether a certificate on disk is still
// usable, and which DNS-01 providers the running build knows.
//
// It deliberately has no ACME/lego dependency. The agent program links this
// package (through nodecfg and the configuration loader) and must not carry
// go-acme/lego plus the dozens of cloud DNS SDKs it registers. Issuing a
// certificate — ACME, self-signed generation, writing pushed content — lives in
// common/cert, which only the W1nCray-xray kernel program links.
package certcfg

import (
	"crypto/tls"
	"crypto/x509"
	"path/filepath"
	"regexp"
	"time"
)

// Modes.
const (
	ModeNone    = "none"
	ModeFile    = "file"
	ModeContent = "content"
	ModeSelf    = "self"
	ModeHTTP    = "http"
	ModeTLS     = "tls"
	ModeDNS     = "dns"
)

// renewBefore is how long before expiry a certificate is considered stale.
const renewBefore = 30 * 24 * time.Hour

// Config describes where a certificate comes from. The mapstructure names are
// those of XrayR's CertConfig.
type Config struct {
	CertMode   string            `mapstructure:"CertMode"`
	CertDomain string            `mapstructure:"CertDomain"`
	CertFile   string            `mapstructure:"CertFile"`
	KeyFile    string            `mapstructure:"KeyFile"`
	Provider   string            `mapstructure:"Provider"`
	Email      string            `mapstructure:"Email"`
	DNSEnv     map[string]string `mapstructure:"DNSEnv"`
	HTTPPort   int               `mapstructure:"HTTPPort"`

	RejectUnknownSni bool `mapstructure:"RejectUnknownSni"`

	// Content mode (panel cert push).
	CertContent string `mapstructure:"-"`
	KeyContent  string `mapstructure:"-"`
}

// Enabled reports whether the config yields a certificate.
func (c *Config) Enabled() bool {
	return c != nil && c.CertMode != "" && c.CertMode != ModeNone
}

var unsafeChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// CertName is the file-name stem a certificate of domain is stored under: every
// character outside [A-Za-z0-9._-] becomes "_", and an empty domain becomes
// "default".
func CertName(domain string) string {
	name := unsafeChars.ReplaceAllString(domain, "_")
	if name == "" {
		name = "default"
	}
	return name
}

// TargetPaths returns where a certificate of cfg is stored: CertFile and
// KeyFile when both are set, otherwise <dir>/<domain>.crt|.key.
func TargetPaths(dir string, cfg *Config) (certFile, keyFile string) {
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		return cfg.CertFile, cfg.KeyFile
	}
	name := CertName(cfg.CertDomain)
	return filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
}

// Valid reports whether the pair exists, covers domain and does not expire
// within the renewal window.
func Valid(certFile, keyFile, domain string) bool {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil || len(pair.Certificate) == 0 {
		return false
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return false
	}
	if time.Until(leaf.NotAfter) < renewBefore {
		return false
	}
	return leaf.VerifyHostname(domain) == nil
}
