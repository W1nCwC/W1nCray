// Package cert provides TLS certificates for node inbounds: existing files,
// certificates pushed by the panel, self-signed certificates and ACME
// (HTTP-01, TLS-ALPN-01, DNS-01) certificates issued with lego.
package cert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
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

// renewBefore is how long before expiry a certificate is replaced.
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

// Manager obtains certificates into a storage directory.
type Manager struct {
	Dir string

	mu sync.Mutex // serializes ACME runs (they bind ports 80/443)
}

// NewManager creates a manager storing files under dir.
func NewManager(dir string) *Manager {
	return &Manager{Dir: dir}
}

var unsafeChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)

func (m *Manager) paths(domain string) (string, string) {
	name := unsafeChars.ReplaceAllString(domain, "_")
	if name == "" {
		name = "default"
	}
	return filepath.Join(m.Dir, name+".crt"), filepath.Join(m.Dir, name+".key")
}

// Ensure returns the certificate and key file paths for cfg, creating,
// writing or renewing them when needed. renewed reports whether new files
// were written.
func (m *Manager) Ensure(cfg *Config) (certFile, keyFile string, renewed bool, err error) {
	if !cfg.Enabled() {
		return "", "", false, errors.New("certificate mode is none")
	}
	switch cfg.CertMode {
	case ModeFile:
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return "", "", false, errors.New("file mode requires CertFile and KeyFile")
		}
		if _, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile); err != nil {
			return "", "", false, fmt.Errorf("load certificate: %w", err)
		}
		return cfg.CertFile, cfg.KeyFile, false, nil
	case ModeContent:
		return m.ensureContent(cfg)
	case ModeSelf:
		return m.ensureSelf(cfg)
	case ModeHTTP, ModeTLS, ModeDNS:
		return m.ensureACME(cfg)
	default:
		return "", "", false, fmt.Errorf("unsupported certificate mode %q", cfg.CertMode)
	}
}

func (m *Manager) target(cfg *Config) (string, string, error) {
	if cfg.CertDomain == "" {
		return "", "", fmt.Errorf("%s mode requires a domain", cfg.CertMode)
	}
	certFile, keyFile := m.paths(cfg.CertDomain)
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		certFile, keyFile = cfg.CertFile, cfg.KeyFile
	}
	if err := os.MkdirAll(filepath.Dir(certFile), 0o700); err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
		return "", "", err
	}
	return certFile, keyFile, nil
}

func (m *Manager) ensureContent(cfg *Config) (string, string, bool, error) {
	if cfg.CertContent == "" || cfg.KeyContent == "" {
		return "", "", false, errors.New("content mode requires certificate and key content")
	}
	if _, err := tls.X509KeyPair([]byte(cfg.CertContent), []byte(cfg.KeyContent)); err != nil {
		return "", "", false, fmt.Errorf("parse pushed certificate: %w", err)
	}
	if cfg.CertDomain == "" {
		cfg.CertDomain = "panel"
	}
	certFile, keyFile, err := m.target(cfg)
	if err != nil {
		return "", "", false, err
	}
	oldCert, _ := os.ReadFile(certFile)
	oldKey, _ := os.ReadFile(keyFile)
	if bytes.Equal(oldCert, []byte(cfg.CertContent)) && bytes.Equal(oldKey, []byte(cfg.KeyContent)) {
		return certFile, keyFile, false, nil
	}
	if err := writePair(certFile, keyFile, []byte(cfg.CertContent), []byte(cfg.KeyContent)); err != nil {
		return "", "", false, err
	}
	return certFile, keyFile, true, nil
}

func (m *Manager) ensureSelf(cfg *Config) (string, string, bool, error) {
	certFile, keyFile, err := m.target(cfg)
	if err != nil {
		return "", "", false, err
	}
	if valid(certFile, keyFile, cfg.CertDomain) {
		return certFile, keyFile, false, nil
	}
	certPEM, keyPEM, err := SelfSigned(cfg.CertDomain, 10*365*24*time.Hour)
	if err != nil {
		return "", "", false, err
	}
	if err := writePair(certFile, keyFile, certPEM, keyPEM); err != nil {
		return "", "", false, err
	}
	return certFile, keyFile, true, nil
}

func (m *Manager) ensureACME(cfg *Config) (string, string, bool, error) {
	certFile, keyFile, err := m.target(cfg)
	if err != nil {
		return "", "", false, err
	}
	if valid(certFile, keyFile, cfg.CertDomain) {
		return certFile, keyFile, false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	certPEM, keyPEM, err := m.obtain(cfg)
	if err != nil {
		return "", "", false, err
	}
	if err := writePair(certFile, keyFile, certPEM, keyPEM); err != nil {
		return "", "", false, err
	}
	return certFile, keyFile, true, nil
}

// valid reports whether the pair exists, covers domain and is not about to
// expire.
func valid(certFile, keyFile, domain string) bool {
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

func writePair(certFile, keyFile string, certPEM, keyPEM []byte) error {
	if err := writeAtomic(keyFile, keyPEM, 0o600); err != nil {
		return err
	}
	return writeAtomic(certFile, certPEM, 0o644)
}

func writeAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// SelfSigned creates a self-signed ECDSA certificate for domain.
func SelfSigned(domain string, validity time.Duration) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: domain},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := parseIP(domain); ip != nil {
		tpl.IPAddresses = append(tpl.IPAddresses, ip)
	} else {
		tpl.DNSNames = []string{domain}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

func parseIP(s string) net.IP {
	return net.ParseIP(strings.Trim(s, "[]"))
}
